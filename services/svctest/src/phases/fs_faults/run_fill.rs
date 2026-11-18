// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/fs_faults/run_fill.rs

//! fatfs's run fills and per-open chain cursors: a fatfs svctest spawns itself
//! fills a sequential `FS_READ_MEMORY` scan in runs of up to
//! `fat_parse::RUN_PAGES` contiguous pages, fills a read off the sequence one
//! page at a time, and does not resume an open's chain walk from a cursor a
//! FAT change retired (services/fs/fat/docs/storage-layout.md, Page cache and
//! Open table).

use ipc::fs_errors;

use super::ramdisk::{self, DATA_LBA, RUN_PAGES, RamDisk, SharedDisk, lock};
use super::{CHUNK, OwnFatfs, slot_cluster};
use crate::bootstrap::Caps;
use crate::ipc_util::fs::{fs_close, fs_create, fs_open_live, fs_release_memory, fs_write_inline};
use crate::ipc_util::ns::ns_lookup;

/// The scanned file's name, and its 8.3 entry as the root directory holds it.
const NAME: &[u8] = b"RUNFILL.BIN";
const SFN: &[u8; 11] = b"RUNFILL BIN";
/// The file the cursor case writes into the clusters the first file freed.
const OTHER: &[u8] = b"OTHER.BIN";
/// Pages of the scanned file.
const FILE_PAGES: usize = 40;
/// Bytes of one page, as fatfs caches it.
const PAGE: usize = 4096;
/// Sectors in one cache page.
const SECTORS_PER_PAGE: usize = PAGE / ramdisk::SECTOR;
/// The FAT16 values at and past which a chain ends.
const FAT16_EOC_MIN: u16 = 0xFFF8;
/// Shift of content B against content A.
const SHIFT_B: usize = 7;

/// The byte at file offset `at` of the content shifted by `shift`: content A
/// for 0 and content B for [`SHIFT_B`].
fn content_byte(at: usize, shift: usize) -> u8
{
    u8::try_from(at.checked_add(shift).expect("fs_run_fill: content offset") % 251)
        .expect("a residue of 251 fits a byte")
}

/// fatfs's run fills and chain cursors:
///
/// 1. A sequential `FS_READ_MEMORY` scan of a file whose clusters are
///    contiguous fills runs: the data-region reads include one of more than a
///    page's sectors, none of more than `RUN_PAGES` pages', and their number
///    is about the file's pages over `RUN_PAGES`; together they cover every
///    sector of the file.
/// 2. A read at an offset other than the open's next one fills one page.
/// 3. An open whose cursor stands deep in the chain reads the file's new
///    bytes after the volume's FAT entries changed under it: the cursor was
///    retired, not resumed.
pub fn fs_run_fill_phase(_: &Caps)
{
    let disk = RamDisk::formatted();
    write_scanned_file(&disk);
    let (reads, longest) = sequential_scan(&disk);
    off_sequence_read(&disk);
    cursor_retired_by_fat_change(&disk);
    std::os::seraph::log!(
        "fs_run_fill passed: {reads} data reads for a {FILE_PAGES}-page scan, the longest \
         {longest} sectors; a read off the sequence filled one page; a cursor did not \
         outlive a FAT change"
    );
}

/// A writer fatfs creates the file and writes `FILE_PAGES` pages of content A
/// to it; on the fresh volume its clusters are contiguous.
fn write_scanned_file(disk: &SharedDisk)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let writer = OwnFatfs::start(disk);
    let (file, _) = fs_create(writer.root, NAME, ipc_buf).expect("fs_run_fill: FS_CREATE");
    write_range(file, 0, FILE_PAGES * PAGE, 0);
    let _ = syscall::cap_delete(file);
    writer.stop();
}

/// Case 1: a fresh fatfs's sequential scan; returns the data-region reads and
/// the longest in sectors.
fn sequential_scan(disk: &SharedDisk) -> (usize, usize)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let _ = lock(disk).take_reads();
    let fs = OwnFatfs::start(disk);
    let (file, _, _) = ns_lookup(fs.root, NAME, 0xFFFF, ipc_buf)
        .unwrap_or_else(|e| panic!("fs_run_fill: lookup of the file: {e}"));
    let (open, liveness) = fs_open_live(file, 0, ipc_buf).expect("fs_run_fill: FS_OPEN");
    let mut cookie = 1;
    let end = scan(open, 0, FILE_PAGES * PAGE, 0, &mut cookie);
    assert_eq!(end, FILE_PAGES * PAGE, "fs_run_fill: the scan's end");

    let reads = data_reads(disk);
    let longest = reads
        .iter()
        .map(|&(_, count)| count)
        .max()
        .expect("fs_run_fill: the scan read no data sector");
    assert!(
        longest > SECTORS_PER_PAGE,
        "fs_run_fill: no data read of more than one page, longest {longest} sectors"
    );
    assert!(
        longest <= RUN_PAGES * SECTORS_PER_PAGE,
        "fs_run_fill: a data read of {longest} sectors, past a run"
    );
    let most = FILE_PAGES.div_ceil(RUN_PAGES).saturating_add(1);
    assert!(
        reads.len() <= most,
        "fs_run_fill: {} data reads for the scan, more than {most}: {reads:?}",
        reads.len()
    );
    for lba in file_sectors(disk)
    {
        assert!(
            reads
                .iter()
                .any(|&(first, count)| (first..first.saturating_add(count)).contains(&lba)),
            "fs_run_fill: file sector {lba} lies in no data read: {reads:?}"
        );
    }
    close_all(fs, open, &[liveness, file]);
    (reads.len(), longest)
}

/// Case 2: the read at page 10, not the open's next offset of 0, fills one
/// page.
fn off_sequence_read(disk: &SharedDisk)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let _ = lock(disk).take_reads();
    let fs = OwnFatfs::start(disk);
    let (file, _, _) = ns_lookup(fs.root, NAME, 0xFFFF, ipc_buf)
        .unwrap_or_else(|e| panic!("fs_run_fill: lookup of the file: {e}"));
    let (open, liveness) = fs_open_live(file, 0, ipc_buf).expect("fs_run_fill: FS_OPEN");
    let at = 10 * PAGE;
    let valid = read_check(open, at, 1, 0);
    assert!(
        valid > 0,
        "fs_run_fill: the off-sequence read returned no bytes"
    );

    let reads = data_reads(disk);
    assert!(
        !reads.is_empty(),
        "fs_run_fill: the off-sequence read read no data sector"
    );
    assert!(
        reads.iter().all(|&(_, count)| count <= SECTORS_PER_PAGE),
        "fs_run_fill: the off-sequence read filled more than a page: {reads:?}"
    );
    close_all(fs, open, &[liveness, file]);
}

/// Case 3: an open read to page 20 keeps its cursor there while the file is
/// truncated, rewritten with its first sector first, `OTHER.BIN` takes the
/// clusters after, and the rest of the file follows: the file's first cluster
/// is as before and its links past the first are not, so only the chain epoch
/// retires the cursor. The open then reads content B throughout.
fn cursor_retired_by_fat_change(disk: &SharedDisk)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let fs = OwnFatfs::start(disk);
    let (file, _, _) = ns_lookup(fs.root, NAME, 0xFFFF, ipc_buf)
        .unwrap_or_else(|e| panic!("fs_run_fill: lookup of the file: {e}"));
    let (open, liveness) = fs_open_live(file, 0, ipc_buf).expect("fs_run_fill: FS_OPEN");
    let mut cookie = 1;
    let at = scan(open, 0, 20 * PAGE, 0, &mut cookie);
    assert_eq!(at, 20 * PAGE, "fs_run_fill: the first scan's end");

    let truncate = ipc::IpcMessage::builder(ipc::fs_labels::FS_TRUNCATE)
        .word(0, 0)
        .build();
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(file, &truncate, ipc_buf) }
        .expect("fs_run_fill: FS_TRUNCATE ipc_call failed");
    assert_eq!(reply.label, fs_errors::SUCCESS, "fs_run_fill: FS_TRUNCATE");
    write_range(file, 0, ramdisk::SECTOR, SHIFT_B);
    let (other, _) = fs_create(fs.root, OTHER, ipc_buf).expect("fs_run_fill: FS_CREATE of OTHER");
    write_range(other, 0, 4 * PAGE, 0);
    write_range(file, ramdisk::SECTOR, FILE_PAGES * PAGE, SHIFT_B);

    let end = scan(open, at, FILE_PAGES * PAGE, SHIFT_B, &mut cookie);
    assert_eq!(end, FILE_PAGES * PAGE, "fs_run_fill: the second scan's end");
    let end = scan(open, 0, 20 * PAGE, SHIFT_B, &mut cookie);
    assert_eq!(end, 20 * PAGE, "fs_run_fill: the third scan's end");
    close_all(fs, open, &[liveness, file, other]);
}

/// Close `open`, delete it and `caps`, and stop `fs`.
fn close_all(fs: OwnFatfs, open: u64, caps: &[u64])
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    assert_eq!(
        fs_close(open, ipc_buf),
        fs_errors::SUCCESS,
        "fs_run_fill: FS_CLOSE"
    );
    let _ = syscall::cap_delete(open);
    for &cap in caps
    {
        let _ = syscall::cap_delete(cap);
    }
    fs.stop();
}

/// Read the file through `FS_READ_MEMORY` from `from` while the offset is
/// under `to`, checking each page against the content shifted by `shift`;
/// returns the offset the scan ends at. `cookie` numbers the reads.
fn scan(open: u64, from: usize, to: usize, shift: usize, cookie: &mut u64) -> usize
{
    let mut at = from;
    while at < to
    {
        let valid = read_check(open, at, *cookie, shift);
        *cookie = cookie.checked_add(1).expect("fs_run_fill: cookie");
        at = at.checked_add(valid).expect("fs_run_fill: scan offset");
    }
    at
}

/// `FS_READ_MEMORY` at `at` with `cookie`: map the page, check its bytes
/// against the content shifted by `shift`, unmap it, release the cookie and
/// delete the cap; returns the bytes valid.
fn read_check(open: u64, at: usize, cookie: u64, shift: usize) -> usize
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_READ_MEMORY)
        .word(0, at as u64)
        .word(1, cookie)
        .build();
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(open, &msg, ipc_buf) }
        .expect("fs_run_fill: FS_READ_MEMORY ipc_call failed");
    assert_eq!(
        reply.label,
        fs_errors::SUCCESS,
        "fs_run_fill: FS_READ_MEMORY at {at}"
    );
    let cap = *reply
        .caps()
        .first()
        .expect("fs_run_fill: FS_READ_MEMORY returned no page");
    let offset = usize::try_from(reply.word(2)).expect("fs_run_fill: page data offset");
    let valid = usize::try_from(reply.word(0)).expect("fs_run_fill: bytes valid");
    assert!(
        valid > 0 && offset.checked_add(valid).is_some_and(|end| end <= PAGE),
        "fs_run_fill: {valid} bytes at page data offset {offset} past the page"
    );
    let range = std::os::seraph::reserve_pages(1).expect("fs_run_fill: reserve_pages failed");
    let aspace = std::os::seraph::startup_info().self_aspace;
    // SAFETY: `range` is a fresh page reservation from the per-process
    // arena: VA no Rust object or IPC page occupies.
    unsafe {
        std::os::seraph::mem_map_funded(cap, aspace, range.va_start(), 0, 1, syscall::MAP_READ)
    }
    .expect("fs_run_fill: mapping the page failed");
    let base = usize::try_from(range.va_start())
        .ok()
        .and_then(|va| va.checked_add(offset))
        .expect("fs_run_fill: the page's data address");
    // SAFETY: the page is mapped readable at `range`, and `offset + valid`
    // was bounded by the page's size above.
    let got = unsafe { core::slice::from_raw_parts(base as *const u8, valid) };
    let matches = got.iter().enumerate().all(|(i, &byte)| {
        byte == content_byte(at.checked_add(i).expect("fs_run_fill: byte offset"), shift)
    });
    // SAFETY: the page was mapped at `range` above and `got` is not used
    // past this point.
    let _ = unsafe { syscall::mem_unmap(aspace, range.va_start(), 1) };
    assert!(
        matches,
        "fs_run_fill: the page at file offset {at} does not hold the expected content"
    );
    assert_eq!(
        fs_release_memory(open, cookie, ipc_buf),
        fs_errors::SUCCESS,
        "fs_run_fill: FS_RELEASE_MEMORY of cookie {cookie:#x}"
    );
    let _ = syscall::cap_delete(cap);
    valid
}

/// Write file offsets `from..to` of `file` with the content shifted by
/// `shift`, in [`CHUNK`] pieces.
fn write_range(file: u64, from: usize, to: usize, shift: usize)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let mut at = from;
    while at < to
    {
        let end = at.saturating_add(CHUNK).min(to);
        let part: Vec<u8> = (at..end).map(|i| content_byte(i, shift)).collect();
        fs_write_inline(file, at as u64, &part, ipc_buf).expect("fs_run_fill: FS_WRITE");
        at = end;
    }
}

/// The reads reaching the data region that the device served since the last
/// call, as `(first sector, sectors)`. A page-sized fill can start before the
/// region: the page holding the root directory's last sectors holds the first
/// data sectors too.
fn data_reads(disk: &SharedDisk) -> Vec<(usize, usize)>
{
    let mut reads = lock(disk).take_reads();
    reads.retain(|&(lba, count)| lba.saturating_add(count) > DATA_LBA);
    reads
}

/// The sector of every cluster of the scanned file, in file order.
fn file_sectors(disk: &SharedDisk) -> Vec<usize>
{
    let (lba, off) = lock(disk)
        .find_root_sfn(SFN)
        .expect("fs_run_fill: the file's entry is not on disk");
    let mut cluster = slot_cluster(disk, lba, off / 32);
    let mut sectors = Vec::new();
    while (2..FAT16_EOC_MIN).contains(&cluster)
    {
        sectors.push(RamDisk::cluster_lba(cluster));
        cluster = lock(disk).fat_entry(cluster);
    }
    sectors
}
