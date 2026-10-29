// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/fs_faults/mod.rs

//! fatfs under block-device faults: a fatfs svctest spawns itself, on a RAM
//! volume whose device drops or fails chosen block requests.
//!
//! A write the device refuses leaves fatfs's cache as it was before the
//! write (`PageCache::write_sector`), and a removal whose last write failed
//! is settled by what the device holds in the entry's 8.3 slot
//! (services/fs/docs/fs-driver-protocol.md § Label 14: `FS_REMOVE` and
//! § Label 16: `FS_RENAME`). Each case lives in its own directory, whose
//! single sector the faults are armed on.

mod ramdisk;

use std::sync::Arc;

use ipc::{IpcMessage, fs_errors, procmgr_errors, procmgr_labels};
use namespace_protocol::{NamespaceRights, NodeId, NsError};

use crate::bootstrap::Caps;
use crate::ipc_util::fs::{
    fs_create, fs_mkdir, fs_read_bytes, fs_remove, fs_rename, fs_write_inline,
};
use crate::ipc_util::ns::ns_lookup;
use crate::runner::Phase;
use ramdisk::{Fault, RamDisk, SharedDisk, lock};

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "fs_block_faults",
        run: fs_block_faults_phase,
    }]
}

/// Badge of fatfs's SEND on the block endpoint.
const BLOCK_CLIENT_BADGE: u64 = 0xB10C;
/// Badge of fatfs's creator SEND, matched by the bootstrap round.
const CREATOR_BADGE: u64 = 0xC4EA;
/// Bytes each case's file holds before its faulted operation.
const CONTENT: &[u8] = b"fs_block_faults content";
/// Slots in one directory sector; one sector is one cluster on the volume.
const SLOTS_PER_SECTOR: usize = 16;
/// Characters one LFN slot holds.
const LFN_CHARS: usize = 13;

/// Every case of the module docs, against one svctest-owned fatfs.
pub fn fs_block_faults_phase(_: &Caps)
{
    let disk = RamDisk::formatted();
    let fs = OwnFatfs::start(&disk);

    rename_undone_when_sfn_write_dropped(&fs, &disk);
    rename_undone_when_lfn_write_dropped(&fs, &disk);
    rename_done_when_failed_sfn_write_landed(&fs, &disk);
    rename_unsettled_when_device_unreadable(&fs, &disk);
    remove_kept_when_sfn_write_dropped(&fs, &disk);
    remove_done_when_failed_sfn_write_landed(&fs, &disk);
    remove_unsettled_when_device_unreadable(&fs, &disk);
    write_dropped_leaves_cache_unchanged(&fs, &disk);

    fs.stop();
    std::os::seraph::log!("fs_block_faults phase passed");
}

/// The source's 8.3 write is dropped after its LFN slot was marked: the
/// rename is undone, the source's slots are as they were on disk, and its
/// node and long name survive.
fn rename_undone_when_sfn_write_dropped(fs: &OwnFatfs, disk: &SharedDisk)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let src_name: &[u8] = b"r1_source.txt";
    let (dir, lba) = fs.case_dir(disk, b"R1");
    let src = create_with_content(dir, src_name);
    fill_rest_of_sector(dir, 2 + lfn_slots(src_name) + 1);
    let before = lock(disk).sector(lba).to_vec();

    // The removal writes the LFN slot, then the 8.3 slot.
    lock(disk).arm(lba, 1, Fault::DropWrite);
    let got = fs_rename(dir, src_name, b"R1DST.TXT", ipc_buf);
    assert_fired(disk, "R1");
    assert_eq!(
        got,
        Err(fs_errors::IO_ERROR),
        "R1: a rename whose 8.3 write was dropped"
    );
    assert_eq!(
        lock(disk).sector(lba),
        &before[..],
        "R1: the undone rename left the source's slots changed on disk"
    );
    expect_present(dir, src_name, "R1: source");
    expect_missing(dir, b"R1DST.TXT", "R1: undone destination");
    assert_eq!(
        fs_read_bytes(src, 0, CONTENT.len() as u64, ipc_buf).as_deref(),
        Ok(CONTENT),
        "R1: a read through the source cap after the undone rename"
    );
    let _ = syscall::cap_delete(src);
    let _ = syscall::cap_delete(dir);
}

/// The second of the source's two LFN writes is dropped, after the first
/// landed: the rename is undone and the partly cleared run restored.
fn rename_undone_when_lfn_write_dropped(fs: &OwnFatfs, disk: &SharedDisk)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let src_name: &[u8] = b"r2_long_source.txt";
    assert_eq!(lfn_slots(src_name), 2);
    let (dir, lba) = fs.case_dir(disk, b"R2");
    let src = create_with_content(dir, src_name);
    fill_rest_of_sector(dir, 2 + lfn_slots(src_name) + 1);
    let before = lock(disk).sector(lba).to_vec();

    lock(disk).arm(lba, 1, Fault::DropWrite);
    let got = fs_rename(dir, src_name, b"R2DST.TXT", ipc_buf);
    assert_fired(disk, "R2");
    assert_eq!(
        got,
        Err(fs_errors::IO_ERROR),
        "R2: a rename whose second LFN write was dropped"
    );
    assert_eq!(
        lock(disk).sector(lba),
        &before[..],
        "R2: the undone rename left the source's LFN run changed on disk"
    );
    expect_present(dir, src_name, "R2: source by its long name");
    expect_missing(dir, b"R2DST.TXT", "R2: undone destination");
    let _ = syscall::cap_delete(src);
    let _ = syscall::cap_delete(dir);
}

/// The source's 8.3 write lands and is reported failed: the rename took
/// effect, so it succeeds and the source's node is dropped.
fn rename_done_when_failed_sfn_write_landed(fs: &OwnFatfs, disk: &SharedDisk)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let (dir, lba) = fs.case_dir(disk, b"R3");
    let src = create_with_content(dir, b"R3SRC.TXT");
    fill_rest_of_sector(dir, 2 + 1);

    lock(disk).arm(lba, 0, Fault::FailAfterWrite);
    let got = fs_rename(dir, b"R3SRC.TXT", b"R3DST.TXT", ipc_buf);
    assert_fired(disk, "R3");
    assert_eq!(
        got,
        Ok(()),
        "R3: a rename whose failed 8.3 write reached the disk"
    );
    expect_missing(dir, b"R3SRC.TXT", "R3: renamed source");
    expect_dropped(src, "R3: the renamed source's cap");
    let (dst, _, _) =
        ns_lookup(dir, b"R3DST.TXT", 0xFFFF, ipc_buf).expect("R3: destination lookup");
    assert_eq!(
        fs_read_bytes(dst, 0, CONTENT.len() as u64, ipc_buf).as_deref(),
        Ok(CONTENT),
        "R3: the destination's content"
    );
    let _ = syscall::cap_delete(dst);
    let _ = syscall::cap_delete(src);
    let _ = syscall::cap_delete(dir);
}

/// The source's 8.3 write is dropped and the device cannot be read back:
/// the rename replies `IO_ERROR` undone nothing, and drops the source's node.
fn rename_unsettled_when_device_unreadable(fs: &OwnFatfs, disk: &SharedDisk)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let (dir, lba) = fs.case_dir(disk, b"R4");
    let src = create_with_content(dir, b"R4SRC.TXT");
    fill_rest_of_sector(dir, 2 + 1);

    {
        let mut disk = lock(disk);
        disk.arm(lba, 0, Fault::DropWrite);
        disk.arm(lba, 0, Fault::FailRead);
    }
    let got = fs_rename(dir, b"R4SRC.TXT", b"R4DST.TXT", ipc_buf);
    assert_fired(disk, "R4");
    assert_eq!(
        got,
        Err(fs_errors::IO_ERROR),
        "R4: a rename whose outcome the device could not show"
    );
    expect_dropped(src, "R4: the unsettled source's cap");
    expect_present(dir, b"R4SRC.TXT", "R4: source, not undone");
    expect_present(dir, b"R4DST.TXT", "R4: destination, not undone");
    let _ = syscall::cap_delete(src);
    let _ = syscall::cap_delete(dir);
}

/// The 8.3 write of a removal is dropped after the LFN slot was marked: the
/// entry stays, with its long name and its node.
fn remove_kept_when_sfn_write_dropped(fs: &OwnFatfs, disk: &SharedDisk)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let name: &[u8] = b"m1_source.txt";
    let (dir, lba) = fs.case_dir(disk, b"M1");
    let file = create_with_content(dir, name);
    let before = lock(disk).sector(lba).to_vec();

    lock(disk).arm(lba, 1, Fault::DropWrite);
    let got = fs_remove(dir, name, ipc_buf);
    assert_fired(disk, "M1");
    assert_eq!(
        got,
        Err(fs_errors::IO_ERROR),
        "M1: a removal whose 8.3 write was dropped"
    );
    assert_eq!(
        lock(disk).sector(lba),
        &before[..],
        "M1: the kept entry's slots changed on disk"
    );
    expect_present(dir, name, "M1: kept entry by its long name");
    assert_eq!(
        fs_read_bytes(file, 0, CONTENT.len() as u64, ipc_buf).as_deref(),
        Ok(CONTENT),
        "M1: a read through the kept entry's cap"
    );
    let _ = syscall::cap_delete(file);
    let _ = syscall::cap_delete(dir);
}

/// The 8.3 write of a removal lands and is reported failed: the removal
/// took effect, so it frees the chain, drops the node, and succeeds.
fn remove_done_when_failed_sfn_write_landed(fs: &OwnFatfs, disk: &SharedDisk)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let (dir, lba) = fs.case_dir(disk, b"M2");
    let file = create_with_content(dir, b"M2SRC.TXT");
    let cluster = first_entry_cluster(disk, lba);
    assert_ne!(lock(disk).fat_entry(cluster), 0, "M2: the file's chain");

    lock(disk).arm(lba, 0, Fault::FailAfterWrite);
    let got = fs_remove(dir, b"M2SRC.TXT", ipc_buf);
    assert_fired(disk, "M2");
    assert_eq!(
        got,
        Ok(()),
        "M2: a removal whose failed 8.3 write reached the disk"
    );
    expect_missing(dir, b"M2SRC.TXT", "M2: removed entry");
    expect_dropped(file, "M2: the removed entry's cap");
    assert_eq!(
        lock(disk).fat_entry(cluster),
        0,
        "M2: the removed entry's chain was not freed"
    );
    let _ = syscall::cap_delete(file);
    let _ = syscall::cap_delete(dir);
}

/// The 8.3 write of a removal is dropped and the device cannot be read back:
/// the removal replies `IO_ERROR` and drops the node of the entry it may
/// have removed.
fn remove_unsettled_when_device_unreadable(fs: &OwnFatfs, disk: &SharedDisk)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let (dir, lba) = fs.case_dir(disk, b"M3");
    let file = create_with_content(dir, b"M3SRC.TXT");

    {
        let mut disk = lock(disk);
        disk.arm(lba, 0, Fault::DropWrite);
        disk.arm(lba, 0, Fault::FailRead);
    }
    let got = fs_remove(dir, b"M3SRC.TXT", ipc_buf);
    assert_fired(disk, "M3");
    assert_eq!(
        got,
        Err(fs_errors::IO_ERROR),
        "M3: a removal whose outcome the device could not show"
    );
    expect_dropped(file, "M3: the unsettled entry's cap");
    expect_present(dir, b"M3SRC.TXT", "M3: entry the device still holds");
    let _ = syscall::cap_delete(file);
    let _ = syscall::cap_delete(dir);
}

/// An in-place `FS_WRITE` whose data write is dropped fails, and a read
/// afterwards returns the bytes from before it, not the cached new ones.
fn write_dropped_leaves_cache_unchanged(fs: &OwnFatfs, disk: &SharedDisk)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let (dir, lba) = fs.case_dir(disk, b"W1");
    let file = create_with_content(dir, b"W1.BIN");
    let data_lba = RamDisk::cluster_lba(first_entry_cluster(disk, lba));
    let new: Vec<u8> = CONTENT.iter().map(u8::to_ascii_uppercase).collect();

    lock(disk).arm(data_lba, 0, Fault::DropWrite);
    let got = fs_write_inline(file, 0, &new, ipc_buf);
    assert_fired(disk, "W1");
    assert_eq!(
        got,
        Err(fs_errors::IO_ERROR),
        "W1: a write the device dropped"
    );
    assert_eq!(
        fs_read_bytes(file, 0, CONTENT.len() as u64, ipc_buf).as_deref(),
        Ok(CONTENT),
        "W1: a read after a dropped write must return the bytes before it"
    );
    let _ = syscall::cap_delete(file);
    let _ = syscall::cap_delete(dir);
}

// ── Case helpers ───────────────────────────────────────────────────────────

/// LFN slots fatfs writes for `name`, which is not a strict 8.3 name.
fn lfn_slots(name: &[u8]) -> usize
{
    name.len().div_ceil(LFN_CHARS)
}

/// Create `name` in `dir` and write [`CONTENT`] to it; returns its cap.
fn create_with_content(dir: u32, name: &[u8]) -> u32
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let (cap, _) = fs_create(dir, name, ipc_buf).expect("fs_block_faults: FS_CREATE failed");
    fs_write_inline(cap, 0, CONTENT, ipc_buf).expect("fs_block_faults: FS_WRITE failed");
    cap
}

/// Fill a fresh directory's first sector, whose first `used` slots hold
/// entries, with one entry whose LFN run takes every remaining slot, so a
/// rename's destination lands in another sector and the faults armed on
/// this one count only the source's writes.
fn fill_rest_of_sector(dir: u32, used: usize)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let lfn = SLOTS_PER_SECTOR - used - 1;
    let filler = vec![b'f'; lfn * LFN_CHARS];
    let (cap, _) = fs_create(dir, &filler, ipc_buf).expect("fs_block_faults: filler FS_CREATE");
    let _ = syscall::cap_delete(cap);
}

/// First cluster of the entry in slot 2 (after `.` and `..`) of the
/// directory sector `lba`.
fn first_entry_cluster(disk: &SharedDisk, lba: usize) -> u16
{
    let disk = lock(disk);
    let slot = &disk.sector(lba)[2 * 32..3 * 32];
    u16::from_le_bytes([slot[26], slot[27]])
}

/// Every fault the case armed fired: the operation reached the write it
/// meant to fault.
fn assert_fired(disk: &SharedDisk, case: &str)
{
    assert_eq!(
        lock(disk).unfired(),
        0,
        "{case}: an armed block fault never fired"
    );
}

fn expect_present(dir: u32, name: &[u8], what: &str)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let (cap, _, _) =
        ns_lookup(dir, name, 0xFFFF, ipc_buf).unwrap_or_else(|e| panic!("{what}: lookup {e}"));
    let _ = syscall::cap_delete(cap);
}

fn expect_missing(dir: u32, name: &[u8], what: &str)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let got = ns_lookup(dir, name, 0xFFFF, ipc_buf).map(|(cap, _, _)| {
        let _ = syscall::cap_delete(cap);
    });
    assert_eq!(
        got,
        Err(NsError::NotFound.as_label()),
        "{what}: lookup must find nothing"
    );
}

/// A cap whose node fatfs dropped names nothing: `FS_READ` replies
/// `INVALID_BADGE`.
fn expect_dropped(cap: u32, what: &str)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    assert_eq!(
        fs_read_bytes(cap, 0, 1, ipc_buf),
        Err(fs_errors::INVALID_BADGE),
        "{what}"
    );
}

// ── The svctest-owned fatfs ────────────────────────────────────────────────

/// A fatfs svctest spawned from `/services/fs/fatfs`, as vfsd spawns one
/// (services/fs/docs/fs-driver-protocol.md § Bootstrap caps), mounted on a
/// [`RamDisk`] its own thread serves.
struct OwnFatfs
{
    /// procmgr process handle.
    process: u32,
    /// The driver's service endpoint; every node cap derives from it.
    service: u32,
    /// Full-rights cap on the volume's root directory.
    root: u32,
    block_ep: u32,
    block_stop: u32,
    server: std::thread::JoinHandle<()>,
}

impl OwnFatfs
{
    fn start(disk: &SharedDisk) -> Self
    {
        let ipc_buf = std::os::seraph::current_ipc_buf();
        let block_ep = new_endpoint();
        let block_client =
            syscall::cap_derive_badge(block_ep, syscall::RIGHTS_EP_SEND, BLOCK_CLIENT_BADGE)
                .expect("fs_block_faults: block SEND derive failed");
        let block_stop =
            syscall::cap_derive_badge(block_ep, syscall::RIGHTS_EP_SEND, ramdisk::STOP_BADGE)
                .expect("fs_block_faults: block stop SEND derive failed");
        let server_disk = Arc::clone(disk);
        let server = std::thread::Builder::new()
            .name("fs_faults_blk".into())
            .spawn(move || ramdisk::serve(block_ep, &server_disk))
            .expect("fs_block_faults: block server thread spawn failed");

        let service = new_endpoint();
        let child_service = syscall::cap_derive(service, syscall::RIGHTS_ALL)
            .expect("fs_block_faults: service endpoint derive failed");
        let creator_ep = new_endpoint();
        let creator = syscall::cap_derive_badge(creator_ep, syscall::RIGHTS_EP_SEND, CREATOR_BADGE)
            .expect("fs_block_faults: creator SEND derive failed");
        let process = spawn_fatfs(creator);
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        unsafe {
            ipc::bootstrap::serve_round(
                creator_ep,
                CREATOR_BADGE,
                ipc_buf,
                true,
                &[block_client, child_service],
                &[],
            )
        }
        .expect("fs_block_faults: fatfs bootstrap round failed");
        let _ = syscall::cap_delete(creator_ep);

        let send = syscall::cap_derive(service, syscall::RIGHTS_EP_SEND)
            .expect("fs_block_faults: service SEND derive failed");
        let mount = IpcMessage::builder(ipc::fs_labels::FS_MOUNT)
            .word(0, u64::from(ipc::FS_LABELS_VERSION))
            .build();
        // SAFETY: as above.
        let reply = unsafe { ipc::ipc_call(send, &mount, ipc_buf) }
            .expect("fs_block_faults: FS_MOUNT ipc_call failed");
        assert_eq!(
            reply.label,
            fs_errors::SUCCESS,
            "fs_block_faults: FS_MOUNT of the RAM volume"
        );
        let _ = syscall::cap_delete(send);
        let root_badge = namespace_protocol::pack(NodeId::ROOT, NamespaceRights::ALL);
        let root = syscall::cap_derive_badge(service, syscall::RIGHTS_EP_SEND, root_badge)
            .expect("fs_block_faults: root cap derive failed");
        Self {
            process,
            service,
            root,
            block_ep,
            block_stop,
            server,
        }
    }

    /// `FS_MKDIR` `name` in the root; returns the directory's cap and the
    /// sector of its single cluster.
    fn case_dir(&self, disk: &SharedDisk, name: &[u8]) -> (u32, usize)
    {
        let ipc_buf = std::os::seraph::current_ipc_buf();
        let (cap, _) =
            fs_mkdir(self.root, name, ipc_buf).expect("fs_block_faults: FS_MKDIR failed");
        let mut sfn = [b' '; 11];
        sfn[..name.len()].copy_from_slice(name);
        let disk = lock(disk);
        let (lba, off) = disk
            .find_root_sfn(&sfn)
            .expect("fs_block_faults: case directory entry not on disk");
        let entry = &disk.sector(lba)[off..off + 32];
        let cluster = u16::from_le_bytes([entry[26], entry[27]]);
        (cap, RamDisk::cluster_lba(cluster))
    }

    /// Destroy the driver, then stop and join the block server.
    fn stop(self)
    {
        let ipc_buf = std::os::seraph::current_ipc_buf();
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        let destroyed = unsafe {
            ipc::ipc_call(
                self.process,
                &IpcMessage::new(procmgr_labels::DESTROY_PROCESS),
                ipc_buf,
            )
        };
        assert!(
            matches!(destroyed, Ok(ref r) if r.label == procmgr_errors::SUCCESS),
            "fs_block_faults: DESTROY_PROCESS of the driver failed"
        );
        // SAFETY: as above.
        unsafe { ipc::ipc_call(self.block_stop, &IpcMessage::new(0), ipc_buf) }
            .expect("fs_block_faults: stopping the block server failed");
        self.server
            .join()
            .expect("fs_block_faults: block server thread panicked");
        for cap in [
            self.process,
            self.root,
            self.service,
            self.block_stop,
            self.block_ep,
        ]
        {
            let _ = syscall::cap_delete(cap);
        }
    }
}

fn new_endpoint() -> u32
{
    std::os::seraph::object_slab_retype(88, |slab| syscall::cap_create_endpoint(slab).ok())
        .expect("fs_block_faults: endpoint creation failed")
}

/// Create and start a fatfs process with `creator` as its creator endpoint
/// (`CREATE_FROM_FILE`, services/procmgr/docs/ipc-interface.md); returns
/// its process handle.
fn spawn_fatfs(creator: u32) -> u32
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let (file, size) = std::os::seraph::namespace_lookup_file(
        std::os::seraph::root_dir_cap(),
        "/services/fs/fatfs",
    )
    .expect("fs_block_faults: lookup of /services/fs/fatfs failed");
    let create = IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE)
        .word(0, size)
        .cap(file)
        .cap(creator)
        .build();
    let procmgr = std::os::seraph::startup_info().procmgr_endpoint;
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(procmgr, &create, ipc_buf) }
        .expect("fs_block_faults: CREATE_FROM_FILE ipc_call failed");
    assert_eq!(
        reply.label,
        procmgr_errors::SUCCESS,
        "fs_block_faults: CREATE_FROM_FILE of fatfs"
    );
    let (process, thread) = match reply.caps()
    {
        &[process, thread] => (process, thread),
        other => panic!(
            "fs_block_faults: CREATE_FROM_FILE replied {} caps",
            other.len()
        ),
    };
    let _ = syscall::cap_delete(thread);
    // SAFETY: as above.
    let started = unsafe {
        ipc::ipc_call(
            process,
            &IpcMessage::new(procmgr_labels::START_PROCESS),
            ipc_buf,
        )
    };
    assert!(
        matches!(started, Ok(ref r) if r.label == procmgr_errors::SUCCESS),
        "fs_block_faults: START_PROCESS of fatfs failed"
    );
    process
}
