// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/fs_faults/run_write.rs

//! fatfs writes a run of contiguous sectors in one block request
//! (`PageCache::write_run`, services/fs/fat/docs/storage-layout.md): a 4 KiB
//! `FS_WRITE_MEMORY` over a file region on consecutive clusters is one
//! `BLK_WRITE_FROM_MEMORY` of its 8 sectors, read from the RAM device's log of
//! writes, and a run write the device drops fails the write and leaves every
//! cached sector of the run as it was.

use ipc::fs_errors;
use syscall::MAP_WRITABLE;

use super::ramdisk::{Fault, RamDisk, SharedDisk, lock};
use super::{CHUNK, OwnFatfs, assert_fired, first_entry_cluster};
use crate::ipc_util::fs::{fs_create, fs_read_bytes};

/// Bytes of one page, the payload of one `FS_WRITE_MEMORY`.
const PAGE: usize = 4096;
/// One-sector clusters the page covers on the RAM volume.
const RUN_SECTORS: usize = PAGE / super::ramdisk::SECTOR;
/// Links of the FAT chain between the run's clusters.
const RUN_LINKS: usize = RUN_SECTORS - 1;

/// The case: run first on the fresh volume, so the file's clusters are the
/// consecutive free ones past the case directory's.
pub fn run_write_is_one_request_and_rolls_back(fs: &OwnFatfs, disk: &SharedDisk)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let (dir, lba) = fs.case_dir(disk, b"W2");
    let (file, _) = fs_create(dir, b"W2.BIN", ipc_buf).expect("W2: FS_CREATE");
    let old = page_of(0x11);
    assert_eq!(
        fs_write_page(file, &old),
        Ok(PAGE as u64),
        "W2: the first write"
    );

    let first = first_entry_cluster(disk, lba);
    {
        let disk = lock(disk);
        for cluster in (first..).take(RUN_LINKS)
        {
            assert_eq!(
                cluster.checked_add(1),
                Some(disk.fat_entry(cluster)),
                "W2: the file's clusters are not consecutive"
            );
        }
    }
    let data_lba = RamDisk::cluster_lba(first);

    let new = page_of(0x22);
    let _ = lock(disk).take_writes();
    assert_eq!(
        fs_write_page(file, &new),
        Ok(PAGE as u64),
        "W2: the rewrite"
    );
    assert_eq!(
        lock(disk).take_writes(),
        vec![(data_lba, RUN_SECTORS)],
        "W2: a 4 KiB rewrite over consecutive clusters is one write of its sectors"
    );

    lock(disk).arm(data_lba, 0, Fault::DropWrite);
    let got = fs_write_page(file, &old);
    assert_fired(disk, "W2");
    assert_eq!(
        got,
        Err(fs_errors::IO_ERROR),
        "W2: a rewrite whose run the device dropped"
    );
    let mut read = Vec::with_capacity(PAGE);
    while read.len() < PAGE
    {
        let len = CHUNK.min(PAGE.saturating_sub(read.len()));
        let bytes = fs_read_bytes(file, read.len() as u64, len as u64, ipc_buf)
            .expect("W2: FS_READ after the dropped run");
        assert!(
            !bytes.is_empty(),
            "W2: a read short of the page returned nothing"
        );
        read.extend_from_slice(&bytes);
    }
    assert!(
        read == new,
        "W2: a read after a dropped run write must return every sector of the run as it was"
    );
    let _ = syscall::cap_delete(file);
    let _ = syscall::cap_delete(dir);
}

/// A page whose byte `i` is `seed` plus `i`, wrapping.
fn page_of(seed: u8) -> Vec<u8>
{
    (0..=u8::MAX)
        .cycle()
        .take(PAGE)
        .map(|i| seed.wrapping_add(i))
        .collect()
}

/// `FS_WRITE_MEMORY` of `data`, one page, at offset 0 of `file`, from a
/// page svctest takes from memmgr and gives back after the reply: the byte
/// count written, or the error label.
fn fs_write_page(file: u64, data: &[u8]) -> Result<u64, u64>
{
    let info = std::os::seraph::startup_info();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let page = request_page();
    let va = std::os::seraph::reserve_pages(1)
        .expect("W2: reserve_pages")
        .va_start();
    // SAFETY: `va` is a fresh page reservation from the per-process arena,
    // owned here: VA no Rust object or IPC page occupies.
    unsafe { std::os::seraph::mem_map_funded(page, info.self_aspace, va, 0, 1, MAP_WRITABLE) }
        .expect("W2: mem_map of the source page");
    // SAFETY: `va` was just mapped writable for one page, and `data` is one
    // page long at most (the slice below bounds it).
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), va as *mut u8, data.len().min(PAGE));
    }
    let msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_WRITE_MEMORY)
        .word(0, 0)
        .word(1, data.len().min(PAGE) as u64)
        .word(2, 0)
        .cap(page)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply =
        unsafe { ipc::ipc_call(file, &msg, ipc_buf) }.expect("W2: FS_WRITE_MEMORY ipc_call");
    // SAFETY: `va` is this case's reserved page, written only through a raw
    // copy above; no Rust reference into it is live.
    let _ = unsafe { syscall::mem_unmap(info.self_aspace, va, 1) };
    for &cap in reply.caps()
    {
        let _ = syscall::cap_delete(cap);
    }
    if reply.label == fs_errors::SUCCESS
    {
        Ok(reply.word(0))
    }
    else
    {
        Err(reply.label)
    }
}

/// One page from memmgr, as a Memory cap svctest owns.
fn request_page() -> u64
{
    let info = std::os::seraph::startup_info();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let req = ipc::IpcMessage::builder(ipc::memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, 1)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(info.memmgr_endpoint, &req, ipc_buf) }
        .expect("W2: memmgr REQUEST_MEMORY_CAPS");
    assert_eq!(
        reply.label,
        ipc::memmgr_errors::SUCCESS,
        "W2: REQUEST_MEMORY_CAPS status"
    );
    *reply
        .caps()
        .first()
        .expect("W2: REQUEST_MEMORY_CAPS returned no cap")
}
