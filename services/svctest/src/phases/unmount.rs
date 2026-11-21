// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/unmount.rs

//! vfsd's `UNMOUNT` (services/vfsd/docs/vfs-ipc-interface.md § Label 11) on
//! the data partition: its refusals, `BUSY` with a file open and success with
//! `FORCE`, the `StaleNetworkFileHandle` std reports on every cap the unmount
//! killed, the fall-through to the root filesystem while unmounted, a remount,
//! and what a client that mapped a cache page reads across a forced unmount;
//! then vfsd's restart of the mount's fs driver when it dies, and the
//! teardown of the mount once its restart budget is spent
//! (services/vfsd/docs/namespace-composition.md § Driver restart).
//!
//! The phases run in order and leave `/data` mounted again, with svctest's
//! cwd set to it, as the phases before them found it.

use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::os::seraph::{current_ipc_buf, startup_info};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::bootstrap::Caps;
use crate::ipc_util::fs::{fs_open, fs_read_memory};
use crate::ipc_util::ns::ns_lookup;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "vfsd_unmount_refusals",
            run: unmount_refusals_phase,
        },
        Phase {
            name: "vfsd_unmount_busy_then_forced",
            run: unmount_busy_then_forced_phase,
        },
        Phase {
            name: "vfsd_unmount_falls_through",
            run: unmount_falls_through_phase,
        },
        Phase {
            name: "vfsd_unmount_remount",
            run: unmount_remount_phase,
        },
        Phase {
            name: "vfsd_unmount_stale_mapping",
            run: unmount_stale_mapping_phase,
        },
        Phase {
            name: "vfsd_driver_death",
            run: driver_death_phase,
        },
    ]
}

/// The process name vfsd gives the fs driver it starts for a mount at
/// `/data`: `fatfs:` and the mount path.
const DATA_DRIVER_NAME: &[u8] = b"fatfs:/data";

/// How long [`driver_death_phase`] waits, at most, for vfsd to restart the
/// driver it killed, or to tear down its mount: a restart creates the driver
/// from the root filesystem.
const DEATH_TIMEOUT: Duration = Duration::from_secs(30);

/// The interval at which [`driver_death_phase`] looks for the restart or the
/// teardown.
const DEATH_POLL: Duration = Duration::from_millis(10);

/// `MountRole::Data` (vfs-ipc-interface.md § Label 10).
const ROLE_DATA: u64 = 1;

/// A directory of the root filesystem that svcmgr does not scan (its recipes
/// are staged from it at build time), over which the data partition is
/// mounted to show the fall-through to a directory that exists.
const SHADOWED_DIR: &str = "/config/svcmgr/tests";

/// A file of [`SHADOWED_DIR`] on the root filesystem.
const SHADOWED_FILE: &str = "/config/svcmgr/tests/svctest.svc";

/// Child role of [`unmount_stale_mapping_phase`].
const STALE_MAP_CHILD_ROLE: &str = "stale-map-child";

/// Bytes of the mapped page the stale-mapping child compares.
const MAPPED_BYTES: usize = 16;

/// The label flags of a forced `UNMOUNT`.
const FORCED: u64 = ipc::vfsd_labels::UNMOUNT_FORCE;

/// The label flags of an unforced `UNMOUNT`.
const UNFORCED: u64 = 0;

/// An `UNMOUNT` request for `path` with the label flags `flags`
/// ([`FORCED`] or [`UNFORCED`]), carrying `version` and `path_len` as stated.
fn unmount_request(path: &[u8], path_len: u64, version: u64, flags: u64) -> ipc::IpcMessage
{
    ipc::IpcMessage::builder(ipc::vfsd_labels::UNMOUNT | flags)
        .word(0, version)
        .word(1, path_len)
        .bytes(2, path)
        .build()
}

/// Send `UNMOUNT` of `path` on `cap` and return the reply.
fn unmount(cap: u64, path: &str, flags: u64) -> ipc::IpcMessage
{
    let msg = unmount_request(
        path.as_bytes(),
        path.len() as u64,
        u64::from(ipc::VFSD_LABELS_VERSION),
        flags,
    );
    call(cap, &msg, "UNMOUNT")
}

/// Send `msg` on `cap`, asserting the call goes through and the reply
/// carries no cap.
fn call(cap: u64, msg: &ipc::IpcMessage, what: &str) -> ipc::IpcMessage
{
    let ipc_buf = current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(cap, msg, ipc_buf) }
        .unwrap_or_else(|_| panic!("{what}: ipc_call failed"));
    assert!(reply.caps().is_empty(), "{what}: reply carried a cap");
    reply
}

/// Mount the data partition at `path` through `caps.vfsd_mount`, asserting
/// `SUCCESS`, and drop the namespace SEND the reply carries.
fn mount_data(caps: &Caps, path: &str)
{
    let msg = ipc::IpcMessage::builder(ipc::vfsd_labels::MOUNT)
        .word(0, ROLE_DATA)
        .word(1, path.len() as u64)
        .bytes(2, path.as_bytes())
        .build();
    let ipc_buf = current_ipc_buf();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(caps.vfsd_mount, &msg, ipc_buf) }
        .unwrap_or_else(|_| panic!("MOUNT of the data partition at {path}: ipc_call failed"));
    for &cap in reply.caps()
    {
        let _ = syscall::cap_delete(cap);
    }
    assert_eq!(
        reply.label,
        ipc::vfsd_errors::SUCCESS,
        "MOUNT of the data partition at {path} must succeed (got {:#x})",
        reply.label
    );
}

/// Force-unmount `/data`, asserting `SUCCESS`.
fn force_unmount_data(caps: &Caps)
{
    let reply = unmount(caps.vfsd_mount, "/data", FORCED);
    assert_eq!(
        reply.label,
        ipc::vfsd_errors::SUCCESS,
        "forced UNMOUNT of /data must succeed (got {:#x})",
        reply.label
    );
}

/// Assert `result` failed with `StaleNetworkFileHandle`.
fn assert_stale<T: std::fmt::Debug>(result: std::io::Result<T>, what: &str)
{
    match result
    {
        Err(e) => assert_eq!(
            e.kind(),
            std::io::ErrorKind::StaleNetworkFileHandle,
            "{what} after the forced unmount: want StaleNetworkFileHandle, got {e:?}"
        ),
        Ok(v) => panic!("{what} after the forced unmount succeeded: {v:?}"),
    }
}

/// `UNMOUNT` refusals, none of which unmounts anything: on `vfsd.deny`
/// (`UNAUTHORIZED`), of `/` (`UNAUTHORIZED`: the root is never unmounted), of
/// a path no mount is at (`NO_MOUNT`), with another label version
/// (`LABEL_VERSION_MISMATCH`), and with a path length past the bytes the
/// request carries (`NOT_FOUND`).
fn unmount_refusals_phase(caps: &Caps)
{
    assert_ne!(
        caps.vfsd_mount, 0,
        "vfsd_unmount_refusals: no vfsd.mount seed"
    );
    assert_ne!(
        caps.vfsd_deny, 0,
        "vfsd_unmount_refusals: no vfsd.deny seed"
    );
    let expected = std::fs::read("/data/test.txt").expect("read /data/test.txt");

    let label = unmount(caps.vfsd_deny, "/data", UNFORCED).label;
    assert_eq!(
        label,
        ipc::vfsd_errors::UNAUTHORIZED,
        "UNMOUNT without MOUNT_AUTHORITY must reply UNAUTHORIZED (got {label:#x})"
    );
    let label = unmount(caps.vfsd_deny, "/data", FORCED).label;
    assert_eq!(
        label,
        ipc::vfsd_errors::UNAUTHORIZED,
        "forced UNMOUNT without MOUNT_AUTHORITY must reply UNAUTHORIZED (got {label:#x})"
    );
    let label = unmount(caps.vfsd_mount, "/", FORCED).label;
    assert_eq!(
        label,
        ipc::vfsd_errors::UNAUTHORIZED,
        "UNMOUNT of / must reply UNAUTHORIZED (got {label:#x})"
    );
    for path in ["/svctest-no-mount", "/config"]
    {
        let label = unmount(caps.vfsd_mount, path, FORCED).label;
        assert_eq!(
            label,
            ipc::vfsd_errors::NO_MOUNT,
            "UNMOUNT of {path}, no mount point, must reply NO_MOUNT (got {label:#x})"
        );
    }
    let wrong = unmount_request(
        b"/data",
        5,
        u64::from(ipc::VFSD_LABELS_VERSION).wrapping_add(1),
        FORCED,
    );
    let label = call(caps.vfsd_mount, &wrong, "UNMOUNT (version)").label;
    assert_eq!(
        label,
        ipc::vfsd_errors::LABEL_VERSION_MISMATCH,
        "UNMOUNT with another VFSD_LABELS_VERSION must be refused (got {label:#x})"
    );
    // One data word of path bytes (8), against a stated length of 20.
    let short = unmount_request(b"/data", 20, u64::from(ipc::VFSD_LABELS_VERSION), FORCED);
    let label = call(caps.vfsd_mount, &short, "UNMOUNT (short path)").label;
    assert_eq!(
        label,
        ipc::vfsd_errors::NOT_FOUND,
        "UNMOUNT with path_len past its data must reply NOT_FOUND (got {label:#x})"
    );

    assert_eq!(
        std::fs::read("/data/test.txt").expect("read /data/test.txt after the refusals"),
        expected,
        "/data/test.txt changed across refused UNMOUNTs"
    );
    std::os::seraph::log!("vfsd unmount refusals passed (nothing unmounted)");
}

/// With files open on `/data`, an unforced `UNMOUNT` replies `BUSY` with the
/// open count and keeps the mount; a forced one succeeds, and every cap the
/// unmount killed then fails in std with `StaleNetworkFileHandle`: an open
/// `File` on the inline and the memory-cap read paths, a `ReadDir` made
/// before, and a relative path through the cwd svctest set to `/data`.
fn unmount_busy_then_forced_phase(caps: &Caps)
{
    let expected = std::fs::read("/data/test.txt").expect("read /data/test.txt");
    let mut small = std::fs::File::open("/data/test.txt").expect("open /data/test.txt");
    let mut large =
        std::fs::File::open("/data/svctest/large.bin").expect("open /data/svctest/large.bin");
    let mut listing = std::fs::read_dir("/data").expect("read_dir /data");

    let reply = unmount(caps.vfsd_mount, "/data", UNFORCED);
    assert_eq!(
        reply.label,
        ipc::vfsd_errors::BUSY,
        "UNMOUNT of /data with files open must reply BUSY (got {:#x})",
        reply.label
    );
    assert!(
        reply.word(0) >= 2,
        "BUSY must count svctest's two open files (counted {})",
        reply.word(0)
    );
    let mut text = Vec::new();
    small
        .read_to_end(&mut text)
        .expect("read /data/test.txt through the open File after BUSY");
    assert_eq!(
        text, expected,
        "/data/test.txt changed across a BUSY UNMOUNT"
    );
    assert!(
        std::fs::metadata("test.txt").is_ok_and(|m| m.is_file()),
        "the relative path test.txt no longer resolves after BUSY"
    );

    force_unmount_data(caps);
    small.seek(SeekFrom::Start(0)).expect("seek /data/test.txt");
    let mut inline = [0u8; 8];
    assert_stale(
        small.read(&mut inline),
        "an inline read of the open /data/test.txt",
    );
    let mut page = vec![0u8; 4096];
    assert_stale(large.read(&mut page), "a frame read of the open large.bin");
    assert_stale(
        listing.next().expect("a ReadDir reports its failure"),
        "the next entry of a ReadDir made before",
    );
    assert_stale(
        std::fs::metadata("test.txt"),
        "metadata of a path relative to the cwd",
    );
    assert_stale(
        std::fs::File::create("svctest-unmount-create"),
        "a create relative to the cwd",
    );
    drop(small);
    drop(large);
    drop(listing);
    std::os::seraph::log!(
        "vfsd unmount busy-then-forced passed (BUSY with {} open, then stale handles)",
        reply.word(0)
    );
}

/// With `/data` unmounted its path falls through to the root filesystem,
/// which has no `data` directory: the path is not found and `/` does not list
/// it. The data partition mounted over [`SHADOWED_DIR`], a directory the
/// root filesystem has, shadows it while mounted, the tree around it still
/// resolving, and the directory's own entries come back through the
/// fall-through once it is unmounted.
fn unmount_falls_through_phase(caps: &Caps)
{
    let root_names = || -> Vec<String> {
        std::fs::read_dir("/")
            .expect("read_dir /")
            .map(|e| {
                e.expect("a / entry")
                    .file_name()
                    .into_string()
                    .expect("UTF-8 name")
            })
            .collect()
    };
    let missing = std::fs::metadata("/data").map(|m| m.is_dir());
    assert_eq!(
        missing.as_ref().map_err(std::io::Error::kind),
        Err(std::io::ErrorKind::NotFound),
        "unmounted /data must fall through to the root fs, which has no data directory"
    );
    assert!(
        !root_names().iter().any(|n| n == "data"),
        "/ lists data while /data is unmounted"
    );

    let svc = std::fs::read(SHADOWED_FILE).expect("read the shadowed file before the mount");
    mount_data(caps, SHADOWED_DIR);
    let shadowed_test = format!("{SHADOWED_DIR}/test.txt");
    let data_text = std::fs::read(&shadowed_test).expect("read test.txt of the data partition");
    assert!(
        !data_text.is_empty(),
        "the data partition's test.txt is empty"
    );
    assert_eq!(
        std::fs::metadata(SHADOWED_FILE).map_err(|e| e.kind()).err(),
        Some(std::io::ErrorKind::NotFound),
        "{SHADOWED_FILE} still resolves with a mount over its directory"
    );
    assert!(
        std::fs::metadata("/config/svcmgr/services").is_ok_and(|m| m.is_dir()),
        "/config/svcmgr/services no longer resolves beside the mount"
    );
    assert!(
        root_names().iter().any(|n| n == "config"),
        "/ does not list config with a mount below it"
    );

    let reply = unmount(caps.vfsd_mount, SHADOWED_DIR, UNFORCED);
    assert_eq!(
        reply.label,
        ipc::vfsd_errors::SUCCESS,
        "UNMOUNT of {SHADOWED_DIR} with nothing open must succeed (got {:#x})",
        reply.label
    );
    assert_eq!(
        std::fs::read(SHADOWED_FILE).expect("read the shadowed file after the unmount"),
        svc,
        "{SHADOWED_FILE} differs after the unmount"
    );
    assert_eq!(
        std::fs::metadata(&shadowed_test)
            .map_err(|e| e.kind())
            .err(),
        Some(std::io::ErrorKind::NotFound),
        "{shadowed_test} still resolves after the unmount"
    );
    std::os::seraph::log!("vfsd unmount fall-through passed (/data absent, {SHADOWED_DIR} back)");
}

/// The data partition mounts at `/data` again: its files read as before the
/// unmount, `/` lists `data`, and svctest's cwd is set to it again.
fn unmount_remount_phase(caps: &Caps)
{
    mount_data(caps, "/data");
    let text = std::fs::read("/data/test.txt").expect("read /data/test.txt after the remount");
    assert!(
        !text.is_empty(),
        "/data/test.txt is empty after the remount"
    );
    std::env::set_current_dir("/data").expect("set_current_dir(/data) after the remount");
    assert_eq!(
        std::fs::read("test.txt").expect("read test.txt relative to the restored cwd"),
        text,
        "test.txt differs relative to the restored cwd"
    );
    assert!(
        std::fs::metadata("/data/svctest/large.bin").is_ok_and(|m| m.is_file()),
        "/data/svctest/large.bin missing after the remount"
    );
    std::os::seraph::log!("vfsd unmount remount passed (/data mounted again, cwd restored)");
}

/// A child maps a cache page of `/data/test.txt` read-only and records its
/// bytes; `/data` is force-unmounted under it, which revokes the page's caps
/// and ends the driver; the child then reads the page again. An established
/// mapping outlives the revoke of the cap it was made through
/// (docs/capability-model.md § Revocation), so the child must read the same
/// stale bytes and exit 0; a fault would kill it. `/data` is mounted again
/// afterwards.
fn unmount_stale_mapping_phase(caps: &Caps)
{
    let mut child = Command::new("/tests/svctest")
        .arg(STALE_MAP_CHILD_ROLE)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn the stale-map child");
    let mut stdin = child.stdin.take().expect("the child's stdin");
    let mut stdout = std::io::BufReader::new(child.stdout.take().expect("the child's stdout"));
    let mut line = String::new();
    stdout
        .read_line(&mut line)
        .expect("read the child's ready line");
    assert_eq!(
        line.trim(),
        "mapped",
        "the stale-map child did not map its page (its line: {line:?})"
    );

    force_unmount_data(caps);
    stdin
        .write_all(b"go\n")
        .expect("tell the child to read again");
    drop(stdin);
    let status = child.wait().expect("wait for the stale-map child");
    let outcome = match status.code()
    {
        Some(0) => "stale bytes readable",
        Some(3) => "bytes changed",
        _ => "no voluntary exit (fault or kill)",
    };
    std::os::seraph::log!("stale mapping across a forced unmount: {outcome} ({status})");
    assert!(
        status.success(),
        "the child must read its mapped page's stale bytes after the forced unmount: {outcome} \
         ({status})"
    );

    mount_data(caps, "/data");
    std::env::set_current_dir("/data").expect("set_current_dir(/data) after the remount");
    std::os::seraph::log!("vfsd unmount stale-mapping passed ({outcome})");
}

/// vfsd restarts the fs driver of a mount below `/` that dies, as long as
/// the mount's restart budget allows, then tears the mount down and keeps its
/// disk.
///
/// `/data` is mounted again, which gives it a whole budget, and its driver is
/// found by name (`LIST_PROCESSES`): the one process named `fatfs:/data`
/// not listed before. `RESTART_BURST` times, with a file open on the mount,
/// svctest kills the driver through an attach (`logd_restart::kill`), the
/// first time by a worker thread's exit and then its main thread's, with
/// another code (`thread_exits::end_two`), after which vfsd's line about the
/// death must carry the worker's code, the driver's one exit reason; and
/// vfsd starts another: a new `fatfs:/data` is listed and
/// `/data/test.txt` reads again by its path, while `/data` is never
/// resolved through the root filesystem meanwhile (it is never not found),
/// and the file open on the dead driver fails with
/// `StaleNetworkFileHandle`. The next death, within the budget's window,
/// finds the budget spent: vfsd tears the mount down without the driver,
/// `/data` falls through to the root filesystem and is not found, and a
/// `MOUNT` at `/data`, which vfsd refuses until the teardown ends, then
/// succeeds on the same disk, which vfsd still holds. svctest's cwd is set to
/// `/data` again.
fn driver_death_phase(caps: &Caps)
{
    let authority = caps.debug_authority;
    assert_ne!(authority, 0, "vfsd_driver_death: no debug authority");
    force_unmount_data(caps);
    let mut seen = data_drivers(authority);
    mount_data(caps, "/data");
    let mut driver = new_data_driver(authority, &seen)
        .expect("vfsd_driver_death: LIST_PROCESSES lists no new fatfs after the MOUNT");
    let first_kill = Instant::now();
    for restart in 1..=restart_budget::RESTART_BURST
    {
        let mut open = std::fs::File::open("/data/test.txt").expect("open /data/test.txt");
        seen.push(driver);
        if restart == 1
        {
            end_from_a_worker(authority, driver);
        }
        else
        {
            super::logd_restart::kill(authority, driver, "vfsd_driver_death: the /data fatfs");
        }
        driver = await_restart(authority, &seen, restart);
        if restart == 1
        {
            require_worker_reason(caps.logd_query);
        }
        let mut bytes = [0u8; 8];
        assert_stale(
            open.read(&mut bytes),
            "a read of a file open on the dead driver's mount",
        );
    }
    let restarted_in = first_kill.elapsed().as_millis();

    let mut open = std::fs::File::open("/data/test.txt").expect("open /data/test.txt");
    seen.push(driver);
    super::logd_restart::kill(authority, driver, "vfsd_driver_death: the /data fatfs");
    let fell_through = await_teardown(authority, &seen, first_kill);
    remount_data_after_teardown(caps);
    let mut bytes = [0u8; 8];
    assert_stale(
        open.read(&mut bytes),
        "a read of a file open on the dead driver's mount",
    );
    drop(open);
    let text = std::fs::read("/data/test.txt").expect("read /data/test.txt after the remount");
    assert!(
        !text.is_empty(),
        "/data/test.txt is empty after the remount"
    );
    std::env::set_current_dir("/data").expect("set_current_dir(/data) after the remount");
    std::os::seraph::log!(
        "vfsd driver death passed ({} restarts in {restarted_in} ms, then the budget spent: /data \
         fell through in {fell_through} ms, the disk held, mounted again)",
        restart_budget::RESTART_BURST
    );
}

/// The exit code the first death's worker thread ends the driver with.
const WORKER_EXIT_CODE: u32 = 43;

/// The exit code the first death's main thread exits with after the worker
/// ended the driver.
const MAIN_EXIT_CODE: u32 = 44;

/// End the `/data` driver `driver` from a worker thread, with
/// `SYS_ASPACE_EXIT` of [`WORKER_EXIT_CODE`], and then have its main thread
/// exit with [`MAIN_EXIT_CODE`] (`thread_exits::end_two`): the driver's end
/// is the worker's, and the main thread's own end, which posts to its
/// thread's observers, carries the other code.
fn end_from_a_worker(authority: u64, driver: u64)
{
    use super::thread_exits::{End, First, end_two};
    end_two(
        authority,
        driver,
        End::Process(MAIN_EXIT_CODE),
        End::Process(WORKER_EXIT_CODE),
        First::Other,
        "vfsd_driver_death: the /data fatfs",
    );
}

/// Require vfsd's newest line about a mount's driver's death in logd's history,
/// through `query`, to carry the reason of the worker's end,
/// [`WORKER_EXIT_CODE`]: the driver's one exit reason, which procmgr posts
/// to the relay, and not its main thread's.
fn require_worker_reason(query: u64)
{
    const DIED: &[u8] = b"fs driver of the mount on disk index";
    let history = super::procmgr::logd_history(query, None);
    let line = history
        .iter()
        .map(|(_, bytes)| bytes)
        .find(|bytes| bytes.windows(DIED.len()).any(|w| w == DIED))
        .expect("vfsd_driver_death: no vfsd line about the driver's death in logd's history");
    let want = format!(
        "died (reason={:#x})",
        syscall_abi::encode_exit_code(WORKER_EXIT_CODE)
    );
    assert!(
        line.windows(want.len()).any(|w| w == want.as_bytes()),
        "vfsd_driver_death: vfsd logged {:?} for a driver a worker ended with exit code \
         {WORKER_EXIT_CODE}, before its main thread exited with {MAIN_EXIT_CODE}",
        String::from_utf8_lossy(line)
    );
}

/// The badges of the processes `LIST_PROCESSES` lists as the `/data`
/// mount's fs driver.
fn data_drivers(authority: u64) -> Vec<u64>
{
    let listed = core::cell::RefCell::new(Vec::new());
    let _ = super::crash::find_listed(authority, |badge, name| {
        if name == DATA_DRIVER_NAME
        {
            listed.borrow_mut().push(badge);
        }
        false
    });
    listed.into_inner()
}

/// The badge of a process listed as the `/data` mount's fs driver that is
/// not in `seen`.
fn new_data_driver(authority: u64, seen: &[u64]) -> Option<u64>
{
    super::crash::find_listed(authority, |badge, name| {
        name == DATA_DRIVER_NAME && !seen.contains(&badge)
    })
    .map(|(badge, _)| badge)
}

/// Wait for vfsd's `restart`-th restart of the `/data` driver, whose
/// earlier instances are `seen`, and return the new driver's badge: once a
/// driver not in `seen` is listed and `/data/test.txt` reads by its path.
/// Until then `/data` must not be not found, which would be its fall-through
/// to the root filesystem.
fn await_restart(authority: u64, seen: &[u64], restart: u32) -> u64
{
    let start = Instant::now();
    loop
    {
        match std::fs::read("/data/test.txt")
        {
            Ok(text) =>
            {
                assert!(
                    !text.is_empty(),
                    "vfsd_driver_death: /data/test.txt is empty after restart {restart}"
                );
                if let Some(driver) = new_data_driver(authority, seen)
                {
                    return driver;
                }
            }
            Err(e) => assert_ne!(
                e.kind(),
                std::io::ErrorKind::NotFound,
                "vfsd_driver_death: /data fell through to the root fs during restart {restart}"
            ),
        }
        assert!(
            start.elapsed() < DEATH_TIMEOUT,
            "vfsd_driver_death: restart {restart} of the /data driver did not end within \
             {DEATH_TIMEOUT:?}"
        );
        std::thread::sleep(DEATH_POLL);
    }
}

/// Wait for vfsd to tear `/data` down after a death that finds its restart
/// budget spent, the budget's window having opened at `first_kill` or
/// later: once `/data` is not found, its fall-through to the root
/// filesystem. A new driver listed instead, beside the earlier ones `seen`,
/// is a restart past the budget while the window since `first_kill` has not
/// passed, and a phase that missed its precondition once it has. Returns how
/// long the teardown took, in milliseconds.
fn await_teardown(authority: u64, seen: &[u64], first_kill: Instant) -> u128
{
    let start = Instant::now();
    let window = Duration::from_nanos(restart_budget::RESTART_WINDOW_NS);
    while !matches!(
        std::fs::metadata("/data").map_err(|e| e.kind()),
        Err(std::io::ErrorKind::NotFound)
    )
    {
        if new_data_driver(authority, seen).is_some()
        {
            // vfsd charged each restart after its kill, so every charge fell
            // within the time since the first kill: inside the window, this
            // restart is past the budget; past it, the window may have
            // refilled, and the phase did not test the budget.
            let since = first_kill.elapsed();
            assert!(
                since >= window,
                "vfsd_driver_death: vfsd restarted the /data driver past its budget, {since:?} \
                 after the first kill, within the {window:?} window"
            );
            panic!(
                "vfsd_driver_death: the kills spanned {since:?}, past the budget's {window:?} \
                 window, so the budget was not tested"
            );
        }
        assert!(
            start.elapsed() < DEATH_TIMEOUT,
            "vfsd_driver_death: /data still resolves {DEATH_TIMEOUT:?} after its driver died \
             with the budget spent"
        );
        std::thread::sleep(DEATH_POLL);
    }
    start.elapsed().as_millis()
}

/// Mount the data partition at `/data` once vfsd has ended the teardown of
/// the mount there: `TABLE_FULL` while the removal is under way, then
/// `SUCCESS`, within [`DEATH_TIMEOUT`].
fn remount_data_after_teardown(caps: &Caps)
{
    let msg = ipc::IpcMessage::builder(ipc::vfsd_labels::MOUNT)
        .word(0, ROLE_DATA)
        .word(1, 5)
        .bytes(2, b"/data")
        .build();
    let ipc_buf = current_ipc_buf();
    let start = Instant::now();
    loop
    {
        // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(caps.vfsd_mount, &msg, ipc_buf) }
            .unwrap_or_else(|_| panic!("vfsd_driver_death: MOUNT ipc_call failed"));
        for &cap in reply.caps()
        {
            let _ = syscall::cap_delete(cap);
        }
        if reply.label == ipc::vfsd_errors::SUCCESS
        {
            return;
        }
        assert_eq!(
            reply.label,
            ipc::vfsd_errors::TABLE_FULL,
            "vfsd_driver_death: MOUNT at /data after the death must succeed once the teardown \
             ends (got {:#x}; NO_MOUNT: the disk was taken as removed)",
            reply.label
        );
        assert!(
            start.elapsed() < DEATH_TIMEOUT,
            "vfsd_driver_death: the teardown of /data did not end within {DEATH_TIMEOUT:?}"
        );
        std::thread::sleep(DEATH_POLL);
    }
}

/// Run the child mode for `role` if this module owns it.
pub fn reentry_main(role: &str)
{
    if role == STALE_MAP_CHILD_ROLE
    {
        stale_map_child_main();
    }
}

/// The `stale-map-child`: open `/data/test.txt` (no release SEND), take its
/// first cache page with `FS_READ_MEMORY`, map it read-only, record its first
/// [`MAPPED_BYTES`] bytes, and print `mapped`; then, once stdin gives a line,
/// read the page again. Exit codes: 0 = the same bytes, 3 = other bytes, 2 =
/// the setup failed. A fault on the read kills it.
fn stale_map_child_main() -> !
{
    let ipc_buf = current_ipc_buf();
    let Some((va, before)) = map_test_page(ipc_buf)
    else
    {
        std::process::exit(2)
    };
    println!("mapped");
    let _ = std::io::stdout().flush();
    let mut go = String::new();
    let _ = std::io::stdin().lock().read_line(&mut go);
    let after = read_mapped(va);
    std::process::exit(if after == before { 0 } else { 3 })
}

/// Map the first cache page of `/data/test.txt` read-only and return the
/// page's address with its first [`MAPPED_BYTES`] bytes.
fn map_test_page(ipc_buf: *mut u64) -> Option<(u64, [u8; MAPPED_BYTES])>
{
    let root = std::os::seraph::root_dir_cap();
    let (data, _, _) = ns_lookup(root, b"data", 0xFFFF, ipc_buf).ok()?;
    let (node, _, _) = ns_lookup(data, b"test.txt", 0xFFFF, ipc_buf).ok()?;
    let open = fs_open(node, 0, ipc_buf).ok()?;
    let (page, valid) = fs_read_memory(open, 0, 1, ipc_buf).ok()?;
    if page == 0 || valid < MAPPED_BYTES as u64
    {
        return None;
    }
    let range = std::os::seraph::reserve_pages(1).ok()?;
    // SAFETY: `range` is a fresh page reservation from the per-process arena,
    // owned here: VA no Rust object or IPC page occupies.
    unsafe {
        std::os::seraph::mem_map_funded(
            page,
            startup_info().self_aspace,
            range.va_start(),
            0,
            1,
            syscall::MAP_READ,
        )
    }
    .ok()?;
    // The mapping and its reservation stay for the process's life: the page
    // is read again after the unmount.
    let va = range.va_start();
    Some((va, read_mapped(va)))
}

/// The first [`MAPPED_BYTES`] bytes of the page mapped at `va`.
fn read_mapped(va: u64) -> [u8; MAPPED_BYTES]
{
    let mut bytes = [0u8; MAPPED_BYTES];
    for (i, b) in bytes.iter_mut().enumerate()
    {
        // `va` maps one readable page, and `i` is below MAPPED_BYTES, within
        // it, so the address is in that page.
        let at = (va as *const u8).wrapping_add(i);
        // SAFETY: `at` is in the readable page mapped at `va`.
        *b = unsafe { core::ptr::read_volatile(at) };
    }
    bytes
}
