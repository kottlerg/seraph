// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/hotplug-check/src/disk.rs

//! The disk mode (`hotplug-check disk`): vfsd's handling of a disk removed
//! and added again behind a PCI Express root port, and of the loss of its
//! root filesystem's driver.
//!
//! `cargo xtask test-hotplug` boots the split-data layout with the data disk
//! behind the root port, so vfsd mounts its data partition at `/data` at
//! startup. The fixture finds the root mount's driver by its name
//! (`fatfs:/`, `LIST_PROCESSES`), writes a file under `/data` and keeps it
//! open, and logs [`REMOVE_MARKER`]. The host removes the disk while the
//! mount's driver is idle: the fixture makes no call that reaches it, so
//! only vfsd's watch on the block class can see the loss. The fixture checks
//! that vfsd marks the disk removed (`MOUNT` answers `NO_MOUNT` where it
//! answered `TABLE_FULL`, `/data` taken), that the mount is torn down
//! (`/data` falls through to the root filesystem, which has no `data`
//! entry), and that the open file fails with `StaleNetworkFileHandle`; logs
//! [`READD_MARKER`]; and, once the host has added the disk again, mounts it
//! through a fresh `MOUNT`, which vfsd answers `NO_MOUNT` until devmgr
//! serves the disk and then finds it by querying devmgr again, and reads its
//! file back.
//!
//! It then stops every thread of the root mount's driver through an attach
//! with the debug authority it holds: a lookup at `/` that falls through
//! to the stopped driver ends in an error within vfsd's bound, and a read
//! under `/data` still answers. It logs its verdict and, on a pass, kills
//! the root mount's driver: it points the main thread's instruction pointer
//! at an unmapped address and starts the threads again. vfsd exits on the
//! loss of its root, and svcmgr shuts the system down; the host checks both.

use std::io::Read;
use std::time::{Duration, Instant};

use ipc::{IpcMessage, procmgr_errors, procmgr_labels, vfsd_errors, vfsd_labels};

use crate::arch::current::{IP_OFFSET, REGS_SIZE};
use crate::{FAIL_MARKER, PASS_MARKER};

/// Logged once the fixture knows the root mount's driver and holds a file
/// open under `/data`: the host removes the disk behind the port on seeing
/// it. Kept in sync with `xtask/src/commands/test_hotplug.rs`.
const REMOVE_MARKER: &str = "HOLDING a file open on /data; READY for the removal of its disk";

/// Logged once vfsd marked the removed disk removed and tore its mount
/// down: the host adds the disk again on seeing it. Kept in sync with
/// `xtask/src/commands/test_hotplug.rs`.
const READD_MARKER: &str = "TORN DOWN /data, its disk removed; READY for the re-added disk";

/// The process name vfsd gives the root mount's driver: `fatfs:` and the
/// mount path.
const ROOT_DRIVER_NAME: &[u8] = b"fatfs:/";

/// `MountRole::Data` (`services/vfsd/docs/vfs-ipc-interface.md` § Label 10).
const ROLE_DATA: u64 = 1;

/// Where the fixture mounts the data partition.
const MOUNT_PATH: &[u8] = b"/data";

/// The file the fixture writes on the data disk and reads back.
const FILE_PATH: &str = "/data/hotplug-check.txt";

/// What [`FILE_PATH`] holds.
const FILE_BYTES: &[u8] = b"hotplug-check: written before the removal\n";

/// A path at `/` that names no mount, so its lookup falls through to the
/// root filesystem's driver.
const FALLTHROUGH_PATH: &str = "/hotplug-check-absent";

/// How long the fixture waits for vfsd to mount the re-added disk: past the
/// host's hot-add, devmgr's poller period, the link wait, and the driver's
/// settle.
const DISK_WAIT: Duration = Duration::from_mins(2);

/// How long the fixture waits for vfsd to mark the removed disk removed and
/// tear its mount down: past the poller's period and the attention button's
/// five-second abort window.
const TEARDOWN_WAIT: Duration = Duration::from_mins(1);

/// How long a lookup that falls through to the stopped root driver may take:
/// vfsd's bound on the call (`FALLTHROUGH_TIMEOUT_MS`, 10 s) with room for a
/// loaded host.
const FALLTHROUGH_LIMIT: Duration = Duration::from_secs(30);

/// The interval at which the fixture polls.
const POLL: Duration = Duration::from_millis(200);

/// An address no process maps (the first page), which the root driver's
/// main thread is pointed at.
const UNMAPPED_IP: u64 = 0;

/// Run the disk mode and log its verdict; on a pass, kill the root mount's
/// driver.
pub fn run(info: &std::os::seraph::StartupInfo, ipc_buf: *mut u64)
{
    match check(info, ipc_buf)
    {
        Ok(stopped) =>
        {
            std::os::seraph::log!(
                "{PASS_MARKER}: /data torn down at its disk's removal with its driver idle and \
                 its disk marked removed, its open file stale; mounted again on the re-added \
                 disk through MOUNT; with the root driver stopped a \
                 lookup at / ended in {:?} after {} ms and /data answered; killing the root \
                 driver",
                stopped.fallthrough,
                stopped.took.as_millis()
            );
            if let Err(why) = kill(&stopped.threads)
            {
                std::os::seraph::log!("{FAIL_MARKER}: killing the root driver: {why}");
            }
            release(&stopped.threads);
        }
        Err(why) => std::os::seraph::log!("{FAIL_MARKER}: {why}"),
    }
}

/// The root mount's driver, stopped, and what the fall-through lookup did.
struct Stopped
{
    /// The thread caps the attach returned, the main thread first, each
    /// stopped.
    threads: Vec<u64>,
    /// The error the fall-through lookup ended in.
    fallthrough: std::io::ErrorKind,
    /// How long it took.
    took: Duration,
}

/// The checks of the module documentation, up to and including the stopped
/// root driver; the stopped driver, or why a check failed.
fn check(info: &std::os::seraph::StartupInfo, ipc_buf: *mut u64) -> Result<Stopped, String>
{
    declare_no_debug(info.procmgr_endpoint, ipc_buf)?;
    let (mount, authority) = bootstrap_seeds(info.creator_endpoint, ipc_buf)
        .ok_or("no vfsd.mount seed and debug authority")?;
    let root = find_named(authority, ROOT_DRIVER_NAME, ipc_buf)?
        .ok_or("LIST_PROCESSES lists no fatfs:/, the root mount's driver")?;

    std::fs::write(FILE_PATH, FILE_BYTES).map_err(|e| format!("writing {FILE_PATH}: {e}"))?;
    read_back("after its write")?;
    // Opened and not read, so the read after the removal starts at offset 0
    // and must reach the driver.
    let mut open =
        std::fs::File::open(FILE_PATH).map_err(|e| format!("opening {FILE_PATH}: {e}"))?;
    std::os::seraph::log!("{REMOVE_MARKER}");

    await_removed(mount, ipc_buf)?;
    match open.read(&mut [0u8; 8])
    {
        Err(e) if e.kind() == std::io::ErrorKind::StaleNetworkFileHandle =>
        {}
        other =>
        {
            return Err(format!(
                "a read of the file open on the removed disk gave {other:?}, not \
                 StaleNetworkFileHandle"
            ));
        }
    }
    drop(open);
    std::os::seraph::log!("{READD_MARKER}");

    mount_when_served(mount, ipc_buf, "the re-added disk")?;
    read_back("after the re-add")?;
    let _ = syscall::cap_delete(mount);

    let threads = attach(authority, root, ipc_buf)?;
    let stopped = stop_and_look_up(&threads);
    if stopped.is_err()
    {
        for &thread in &threads
        {
            let _ = syscall::thread_start(thread);
        }
        release(&threads);
    }
    let (fallthrough, took) = stopped?;
    Ok(Stopped {
        threads,
        fallthrough,
        took,
    })
}

/// Declare the fixture undebuggable, as every holder of the debug authority
/// does (`procmgr_labels::DECLARE_NO_DEBUG`), before it spawns a thread.
fn declare_no_debug(procmgr: u64, ipc_buf: *mut u64) -> Result<(), String>
{
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe {
        ipc::ipc_call(
            procmgr,
            &IpcMessage::new(procmgr_labels::DECLARE_NO_DEBUG),
            ipc_buf,
        )
    }
    .map_err(|e| format!("DECLARE_NO_DEBUG failed ({e})"))?;
    if reply.label == procmgr_errors::SUCCESS
    {
        Ok(())
    }
    else
    {
        Err(format!("DECLARE_NO_DEBUG refused ({:#x})", reply.label))
    }
}

/// Pull the bootstrap round: slot 0 is the recipe's `seed = vfsd.mount`,
/// slot 1 the debug authority `debug_authority = yes` delivers after it.
fn bootstrap_seeds(creator_ep: u64, ipc_buf: *mut u64) -> Option<(u64, u64)>
{
    if creator_ep == 0
    {
        return None;
    }
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let [mount, authority] =
        unsafe { ipc::bootstrap::request_slots::<2>(creator_ep, ipc_buf) }.ok()?;
    (mount != 0 && authority != 0).then_some((mount, authority))
}

/// Walk `LIST_PROCESSES` for the first live process named `name`; its
/// badge.
fn find_named(authority: u64, name: &[u8], ipc_buf: *mut u64) -> Result<Option<u64>, String>
{
    let mut cursor = None;
    loop
    {
        let request = IpcMessage::builder(procmgr_labels::LIST_PROCESSES)
            .word(0, u64::from(cursor.is_some()))
            .word(1, cursor.unwrap_or(0))
            .build();
        // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(authority, &request, ipc_buf) }
            .map_err(|e| format!("LIST_PROCESSES failed ({e})"))?;
        if reply.label != procmgr_errors::SUCCESS
        {
            return Err(format!("LIST_PROCESSES refused ({:#x})", reply.label));
        }
        let words = reply.words();
        let count = usize::try_from(words.first().copied().unwrap_or(0)).unwrap_or(0);
        let mut listed = [0u8; ipc::svcmgr_labels::NAME_MAX];
        for i in 0..count
        {
            let (badge, len) = procmgr_labels::unpack_list_entry(words, i, &mut listed)
                .ok_or("a malformed LIST_PROCESSES entry")?;
            if listed.get(..len) == Some(name)
            {
                return Ok(Some(badge));
            }
            cursor = Some(badge);
        }
        if count < procmgr_labels::LIST_PROCESSES_PAGE
        {
            return Ok(None);
        }
    }
}

/// Send `MOUNT` of the data partition at [`MOUNT_PATH`] on `mount`; the
/// reply's label. A cap the reply carries is deleted.
fn mount_data(mount: u64, ipc_buf: *mut u64) -> Result<u64, String>
{
    let request = IpcMessage::builder(vfsd_labels::MOUNT)
        .word(0, ROLE_DATA)
        .word(1, MOUNT_PATH.len() as u64)
        .bytes(2, MOUNT_PATH)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(mount, &request, ipc_buf) }
        .map_err(|e| format!("MOUNT failed ({e})"))?;
    for &cap in reply.caps()
    {
        let _ = syscall::cap_delete(cap);
    }
    Ok(reply.label)
}

/// Mount the data partition at `/data` once devmgr serves the disk that
/// holds it, `what`: `NO_MOUNT` until then, within [`DISK_WAIT`]. Each
/// `NO_MOUNT` has vfsd query devmgr for the disks served since its last
/// query.
fn mount_when_served(mount: u64, ipc_buf: *mut u64, what: &str) -> Result<(), String>
{
    let start = Instant::now();
    loop
    {
        match mount_data(mount, ipc_buf)?
        {
            vfsd_errors::SUCCESS => return Ok(()),
            vfsd_errors::NO_MOUNT if start.elapsed() < DISK_WAIT => std::thread::sleep(POLL),
            vfsd_errors::NO_MOUNT =>
            {
                return Err(format!(
                    "MOUNT at /data found no data partition within {DISK_WAIT:?} of waiting for \
                     {what}"
                ));
            }
            label => return Err(format!("MOUNT at /data on {what} answered {label:#x}")),
        }
    }
}

/// Wait for vfsd to mark the removed disk removed and tear its mount down:
/// `MOUNT` at `/data` answers `TABLE_FULL` while the mount stands on a
/// disk vfsd holds as present, and `NO_MOUNT` once vfsd holds the disk
/// removed, with no other disk holding the partition; then `/data` falls
/// through to the root filesystem, which has no `data` entry. Neither
/// reaches the mount's driver.
fn await_removed(mount: u64, ipc_buf: *mut u64) -> Result<(), String>
{
    let start = Instant::now();
    let in_time = || {
        if start.elapsed() < TEARDOWN_WAIT
        {
            std::thread::sleep(POLL);
            Ok(())
        }
        else
        {
            Err(format!(
                "the removal was not handled within {TEARDOWN_WAIT:?}"
            ))
        }
    };
    loop
    {
        match mount_data(mount, ipc_buf)?
        {
            vfsd_errors::NO_MOUNT => break,
            vfsd_errors::TABLE_FULL => in_time().map_err(|e| {
                format!(
                    "{e}: MOUNT at /data \
                                                                  answers TABLE_FULL"
                )
            })?,
            label =>
            {
                return Err(format!(
                    "MOUNT at /data after the removal answered {label:#x}, not TABLE_FULL or \
                     NO_MOUNT"
                ));
            }
        }
    }
    loop
    {
        match std::fs::metadata("/data")
        {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            _ => in_time().map_err(|e| format!("{e}: /data still resolves"))?,
        }
    }
}

/// Read [`FILE_PATH`] back, `when` naming the step in a failure.
fn read_back(when: &str) -> Result<(), String>
{
    let bytes = std::fs::read(FILE_PATH).map_err(|e| format!("reading {FILE_PATH} {when}: {e}"))?;
    if bytes == FILE_BYTES
    {
        Ok(())
    }
    else
    {
        Err(format!(
            "{FILE_PATH} {when} holds {} other bytes",
            bytes.len()
        ))
    }
}

/// Attach to the process `process` (`ATTACH_PROCESS`); the caps of its
/// threads, the main thread first.
fn attach(authority: u64, process: u64, ipc_buf: *mut u64) -> Result<Vec<u64>, String>
{
    let request = IpcMessage::builder(procmgr_labels::ATTACH_PROCESS)
        .word(0, process)
        .word(1, 0)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(authority, &request, ipc_buf) }
        .map_err(|e| format!("ATTACH_PROCESS of the root driver failed ({e})"))?;
    let threads = reply.caps().to_vec();
    if reply.label != procmgr_errors::SUCCESS || threads.is_empty()
    {
        release(&threads);
        return Err(format!(
            "ATTACH_PROCESS of the root driver answered {:#x} with {} thread(s)",
            reply.label,
            threads.len()
        ));
    }
    Ok(threads)
}

/// Stop each of `threads`, then look up [`FALLTHROUGH_PATH`], which falls
/// through to the stopped root driver, and read [`FILE_PATH`] under the
/// healthy mount; the error the lookup ended in and how long it took.
fn stop_and_look_up(threads: &[u64]) -> Result<(std::io::ErrorKind, Duration), String>
{
    for &thread in threads
    {
        syscall::thread_stop(thread)
            .map_err(|e| format!("stopping a thread of the root driver ({e})"))?;
    }
    let start = Instant::now();
    let looked_up = std::fs::metadata(FALLTHROUGH_PATH);
    let took = start.elapsed();
    let kind = match looked_up
    {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => e.kind(),
        other =>
        {
            return Err(format!(
                "a lookup of {FALLTHROUGH_PATH} with the root driver stopped gave {other:?}, \
                 not an error of the call"
            ));
        }
    };
    if took > FALLTHROUGH_LIMIT
    {
        return Err(format!(
            "a lookup of {FALLTHROUGH_PATH} with the root driver stopped took {took:?}, past \
             {FALLTHROUGH_LIMIT:?}"
        ));
    }
    read_back("with the root driver stopped")?;
    Ok((kind, took))
}

/// Kill the stopped root driver: point its main thread, the first of
/// `threads`, at [`UNMAPPED_IP`] and start every thread, so it takes a
/// fault no handler resolves.
fn kill(threads: &[u64]) -> Result<(), String>
{
    let &main = threads.first().ok_or("no main thread")?;
    let mut regs = [0u8; REGS_SIZE];
    syscall::thread_read_regs(main, &mut regs)
        .map_err(|e| format!("reading its main thread's registers ({e})"))?;
    regs.get_mut(IP_OFFSET..IP_OFFSET + 8)
        .ok_or("the instruction pointer lies outside the register file")?
        .copy_from_slice(&UNMAPPED_IP.to_ne_bytes());
    // SAFETY: the thread is the attached driver's, bound to its address
    // space, so the frame it resumes on touches none of this process's
    // memory; the write only makes it fault.
    unsafe { syscall::thread_write_regs(main, &regs) }
        .map_err(|e| format!("writing its instruction pointer ({e})"))?;
    for &thread in threads
    {
        syscall::thread_start(thread).map_err(|e| format!("starting a thread ({e})"))?;
    }
    Ok(())
}

/// Delete the thread caps `threads`.
fn release(threads: &[u64])
{
    for &thread in threads
    {
        let _ = syscall::cap_delete(thread);
    }
}
