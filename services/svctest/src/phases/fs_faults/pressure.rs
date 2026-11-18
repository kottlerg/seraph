// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/fs_faults/pressure.rs

//! fatfs under memory pressure: a fatfs svctest spawns itself gives memmgr
//! back its idle cache pages when the level turns `Low`, the page whose cap a
//! failed fill lost among them, keeps the page a client still maps and its
//! most recently used idle pages, and goes on serving
//! (services/fs/fat/docs/storage-layout.md, Page cache).

use std::collections::BTreeSet;

use ipc::fs_errors;

use super::ramdisk::{self, Fault, RamDisk, lock};
use super::{CHUNK, OwnFatfs, slot_cluster};
use crate::bootstrap::Caps;
use crate::ipc_util::fs::{
    fs_close, fs_create, fs_open_live, fs_read_bytes, fs_release_memory, fs_write_inline,
};
use crate::ipc_util::ns::ns_lookup;
use crate::phases::memmgr::{memory_usage, pool_pressure_status, release_grant, take_pages};

/// The file's name, and its 8.3 entry as the root directory holds it.
const NAME: &[u8] = b"PRESSURE.BIN";
const SFN: &[u8; 11] = b"PRESSUREBIN";
/// Bytes of the file: eight pages, each cluster one sector, so the cache
/// fills more pages than fatfs keeps idle under pressure.
const FILE_BYTES: usize = 8 * PAGE;
/// Bytes of one page, as fatfs caches it.
const PAGE: usize = 4096;
/// Sectors in one fatfs cache page on the volume.
const SECTORS_PER_PAGE: usize = PAGE / ramdisk::SECTOR;
/// File offsets of the page svctest keeps mapped (A) and of the page it
/// releases and unmaps (B) before the level turns.
const MAPPED_AT: usize = 3 * PAGE;
const UNMAPPED_AT: usize = 5 * PAGE;
/// File offset of the page whose first fill the block server fails and
/// whose cap it keeps (C).
const LOST_AT: usize = PAGE;
/// Release cookies of the two `FS_READ_MEMORY` pages.
const MAPPED_COOKIE: u64 = 0xA;
const UNMAPPED_COOKIE: u64 = 0xB;
/// How long the phase waits for fatfs's release, and for the level to fall
/// back to `Normal`. A test wait bound.
const PRESSURE_WAIT: std::time::Duration = std::time::Duration::from_secs(30);
/// The FAT16 values at and past which a chain ends.
const FAT16_EOC_MIN: u16 = 0xFFF8;

/// The byte at file offset `at`.
fn content_byte(at: usize) -> u8
{
    u8::try_from(at % 251).expect("a residue of 251 fits a byte")
}

/// fatfs gives memmgr back its idle cache pages under memory pressure
/// (services/fs/fat/src/cache.rs, Release under memory pressure):
///
/// 1. svctest writes a file through a fatfs of its own, then starts another
///    on the volume, whose cache is empty. The block server fails the first
///    fill of page C of the file and keeps its cap, so the read fails and the
///    slot keeps a page it cannot refill. Two reads of the file follow.
/// 2. svctest takes page A of the file through `FS_READ_MEMORY` and maps it,
///    and page B, which it does not map; it releases both.
/// 3. svctest drives memmgr's level to `Low`, as `memmgr_pressure` does. The
///    pages charged to svctest's children, fatfs's among them, fall by at
///    least the pages fatfs's cache holds (each page it filled, and C's lost
///    one) less A, which a client still maps, and less the
///    `fat_parse::RELEASE_KEEP` idle pages fatfs keeps.
/// 4. A read of the file reads every page of it from the device again but A
///    and at most `RELEASE_KEEP` kept ones, and returns the file; A's mapping
///    still reads the file.
/// 5. svctest releases its grants: the level returns to `Normal`, and memmgr's
///    pool total is unchanged and accounts for all of RAM
///    (`system_ram == kernel_reserved + pool_total`).
pub fn fs_pressure_release_phase(_: &Caps)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let (_, _, pool_total) = pool_identity();
    let disk = RamDisk::formatted();

    // 1. The file, with page C's cap lost, then read twice.
    let want: Vec<u8> = (0..FILE_BYTES).map(content_byte).collect();
    let sectors = {
        let writer = OwnFatfs::start(&disk);
        let (file, sectors) = write_file(&writer, &disk, &want);
        let _ = syscall::cap_delete(file);
        writer.stop();
        sectors
    };
    let _ = lock(&disk).take_reads();
    let fs = OwnFatfs::start(&disk);
    let (file, _, _) = ns_lookup(fs.root, NAME, 0xFFFF, ipc_buf)
        .unwrap_or_else(|e| panic!("fs_pressure: lookup of the file: {e}"));
    let page_c = page_base(sector_at(&sectors, LOST_AT));
    lock(&disk).arm(page_c, 0, Fault::LoseCap);
    assert_eq!(
        fs_read_bytes(file, LOST_AT as u64, CHUNK as u64, ipc_buf),
        Err(fs_errors::IO_ERROR),
        "fs_pressure: the read whose fill lost page C's cap"
    );
    assert!(
        lock(&disk).unfired().is_empty(),
        "fs_pressure: the read of page C never filled it"
    );
    assert_eq!(read_file(file), want, "fs_pressure: the file's first read");
    assert_eq!(read_file(file), want, "fs_pressure: the file's second read");

    // 2. Page A mapped, page B not; both released to fatfs.
    let (open, liveness) = fs_open_live(file, 0, ipc_buf).expect("fs_pressure: FS_OPEN");
    let mapped = expose_pages(open);
    let page_a = page_base(sector_at(&sectors, MAPPED_AT));
    let page_b = page_base(sector_at(&sectors, UNMAPPED_AT));
    assert!(
        page_a != page_b && page_c != page_a && page_c != page_b,
        "fs_pressure: pages A, B and C share a cache page"
    );
    let filled = cache_fills(&lock(&disk).take_reads());
    assert!(
        filled.contains(&page_a) && filled.contains(&page_b) && filled.contains(&page_c),
        "fs_pressure: pages A, B and C are not among the cache's fills"
    );

    // 3. The level to Low; fatfs gives its idle pages back.
    let (own_before, _, subtree_before) = memory_usage();
    let children_before = subtree_before.saturating_sub(own_before);
    let held = drive_low();
    // The pages held: each filled one, and C's lost one. A stays, and so do
    // the kept ones.
    let floor = u64::try_from(filled.len().saturating_sub(fat_parse::RELEASE_KEEP))
        .expect("page count fits u64");
    let released = await_children_drop(children_before, floor);

    // 4. Every page but A and the kept ones comes from the device again.
    expect_reread(file, &disk, &want, &sectors, page_a);
    mapped.expect_content(&want, "fs_pressure: page A's mapping after the release");
    fs.expect_serving("fs_pressure: after the release");

    // 5. Back to Normal; the pool accounts for every page.
    for (cap, id) in held
    {
        release_grant(cap, id);
    }
    await_normal();
    expect_pool_identity(pool_total);

    drop(mapped);
    assert_eq!(
        fs_close(open, ipc_buf),
        fs_errors::SUCCESS,
        "fs_pressure: FS_CLOSE"
    );
    for cap in [open, liveness, file]
    {
        let _ = syscall::cap_delete(cap);
    }
    fs.stop();
    std::os::seraph::log!(
        "fs_pressure_release passed: {released} pages given back at Low of {} the cache \
         held, the mapped page and {} idle ones kept",
        filled.len().saturating_add(1),
        fat_parse::RELEASE_KEEP
    );
}

/// Create the file in the volume's root and write `want` to it; returns its
/// cap and the sector of each of its clusters.
fn write_file(fs: &OwnFatfs, disk: &ramdisk::SharedDisk, want: &[u8]) -> (u64, Vec<usize>)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let (file, _) = fs_create(fs.root, NAME, ipc_buf).expect("fs_pressure: FS_CREATE");
    let mut at = 0u64;
    for part in want.chunks(CHUNK)
    {
        fs_write_inline(file, at, part, ipc_buf).expect("fs_pressure: FS_WRITE");
        at = at
            .checked_add(part.len() as u64)
            .expect("fs_pressure: write offset");
    }
    let sectors = file_sectors(disk);
    assert_eq!(
        sectors.len(),
        FILE_BYTES / ramdisk::SECTOR,
        "fs_pressure: the file's clusters"
    );
    (file, sectors)
}

/// Take page A of the open's file mapped and page B unmapped through
/// `FS_READ_MEMORY`, and release both to fatfs; returns A's mapping.
fn expose_pages(open: u64) -> MappedPage
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let mapped = MappedPage::take(open, MAPPED_AT, MAPPED_COOKIE);
    let (unmapped, _, _) = read_memory(open, UNMAPPED_AT, UNMAPPED_COOKIE);
    for cookie in [MAPPED_COOKIE, UNMAPPED_COOKIE]
    {
        assert_eq!(
            fs_release_memory(open, cookie, ipc_buf),
            fs_errors::SUCCESS,
            "fs_pressure: FS_RELEASE_MEMORY of cookie {cookie:#x}"
        );
    }
    let _ = syscall::cap_delete(unmapped);
    mapped
}

/// A read of the file after the release returns `want` and reads every
/// cache page of it from the device again but `page_a` and at most
/// `fat_parse::RELEASE_KEEP` pages fatfs kept.
fn expect_reread(
    file: u64,
    disk: &ramdisk::SharedDisk,
    want: &[u8],
    sectors: &[usize],
    page_a: usize,
)
{
    assert_eq!(
        read_file(file),
        want,
        "fs_pressure: the file read after the release"
    );
    let reread = cache_fills(&lock(disk).take_reads());
    let missing: Vec<usize> = sectors
        .iter()
        .map(|&lba| page_base(lba))
        .collect::<BTreeSet<usize>>()
        .into_iter()
        .filter(|&page| page != page_a && !reread.contains(&page))
        .collect();
    assert!(
        missing.len() <= fat_parse::RELEASE_KEEP,
        "fs_pressure: file pages {missing:?} the read after the release found still cached, \
         more than the {} fatfs keeps",
        fat_parse::RELEASE_KEEP
    );
    assert!(
        !reread.contains(&page_a),
        "fs_pressure: the page svctest maps was given back and read again"
    );
}

/// memmgr's pool total is `pool_total` and, with the kernel's reservation,
/// accounts for all of RAM.
fn expect_pool_identity(pool_total: u64)
{
    let (system_ram, kernel_reserved, pool_total_after) = pool_identity();
    assert_eq!(
        pool_total_after, pool_total,
        "fs_pressure: memmgr's pool total across the release"
    );
    assert_eq!(
        system_ram,
        kernel_reserved.saturating_add(pool_total_after),
        "fs_pressure: system_ram == kernel_reserved + pool_total after the release"
    );
}

/// The sector of every cluster of the file, in file order, from the volume.
fn file_sectors(disk: &ramdisk::SharedDisk) -> Vec<usize>
{
    let (lba, off) = lock(disk)
        .find_root_sfn(SFN)
        .expect("fs_pressure: the file's entry is not on disk");
    let mut cluster = slot_cluster(disk, lba, off / 32);
    let mut sectors = Vec::new();
    while (2..FAT16_EOC_MIN).contains(&cluster)
    {
        sectors.push(RamDisk::cluster_lba(cluster));
        cluster = lock(disk).fat_entry(cluster);
    }
    sectors
}

/// The sector holding file offset `at`.
fn sector_at(sectors: &[usize], at: usize) -> usize
{
    *sectors
        .get(at / ramdisk::SECTOR)
        .expect("fs_pressure: offset past the file")
}

/// The first sector of the cache page holding sector `lba`.
fn page_base(lba: usize) -> usize
{
    (lba / SECTORS_PER_PAGE)
        .checked_mul(SECTORS_PER_PAGE)
        .expect("fs_pressure: page base")
}

/// The cache pages a read log shows fatfs filling: its page-sized reads.
/// A single-sector read goes to fatfs's transfer buffer, not to a slot, and
/// this phase makes no sequential `FS_READ_MEMORY` scan, so no run fill.
fn cache_fills(reads: &[(usize, usize)]) -> BTreeSet<usize>
{
    reads
        .iter()
        .filter(|&&(_, count)| count == SECTORS_PER_PAGE)
        .map(|&(lba, _)| lba)
        .collect()
}

/// The whole file, through inline `FS_READ`s.
fn read_file(file: u64) -> Vec<u8>
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let mut got = Vec::new();
    while got.len() < FILE_BYTES
    {
        let part = fs_read_bytes(file, got.len() as u64, CHUNK as u64, ipc_buf)
            .expect("fs_pressure: FS_READ");
        assert!(
            !part.is_empty(),
            "fs_pressure: FS_READ ended before the file's size"
        );
        got.extend_from_slice(&part);
    }
    got
}

/// `FS_READ_MEMORY` at file offset `at` with `cookie`: the page cap, the
/// offset of `at`'s byte within the page, and how many of the file's bytes
/// follow it there.
fn read_memory(open: u64, at: usize, cookie: u64) -> (u64, usize, usize)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = ipc::IpcMessage::builder(ipc::fs_labels::FS_READ_MEMORY)
        .word(0, at as u64)
        .word(1, cookie)
        .build();
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(open, &msg, ipc_buf) }
        .expect("fs_pressure: FS_READ_MEMORY ipc_call failed");
    assert_eq!(
        reply.label,
        fs_errors::SUCCESS,
        "fs_pressure: FS_READ_MEMORY"
    );
    let cap = *reply
        .caps()
        .first()
        .expect("fs_pressure: FS_READ_MEMORY returned no page");
    let offset = usize::try_from(reply.word(2)).expect("fs_pressure: page data offset");
    let valid = usize::try_from(reply.word(0)).expect("fs_pressure: bytes valid");
    assert!(
        valid > 0 && offset.checked_add(valid).is_some_and(|end| end <= PAGE),
        "fs_pressure: {valid} bytes at page data offset {offset} past the page"
    );
    (cap, offset, valid)
}

/// A page of the file svctest maps from an `FS_READ_MEMORY` cap.
struct MappedPage
{
    cap: u64,
    range: std::os::seraph::ReservedRange,
    /// File offset of the page's first byte of file content.
    file_at: usize,
    /// Where that byte sits in the page.
    data_offset: usize,
    /// The file's bytes that follow it in the page.
    valid: usize,
}

impl MappedPage
{
    fn take(open: u64, at: usize, cookie: u64) -> Self
    {
        let (cap, data_offset, valid) = read_memory(open, at, cookie);
        let range = std::os::seraph::reserve_pages(1).expect("fs_pressure: reserve_pages failed");
        let aspace = std::os::seraph::startup_info().self_aspace;
        // SAFETY: `range` is a fresh page reservation from the per-process
        // arena that this struct owns: VA no Rust object or IPC page occupies.
        unsafe {
            std::os::seraph::mem_map_funded(cap, aspace, range.va_start(), 0, 1, syscall::MAP_READ)
        }
        .expect("fs_pressure: mapping page A failed");
        Self {
            cap,
            range,
            file_at: at,
            data_offset,
            valid,
        }
    }

    /// The mapped page holds the file's bytes it held when it was taken.
    fn expect_content(&self, want: &[u8], what: &str)
    {
        let at = usize::try_from(self.range.va_start())
            .ok()
            .and_then(|va| va.checked_add(self.data_offset))
            .expect("fs_pressure: page A's data address");
        // SAFETY: the page is mapped readable at `range` for the life of
        // `self`, and `read_memory` bounded `data_offset + valid` by the
        // page's size.
        let got = unsafe { core::slice::from_raw_parts(at as *const u8, self.valid) };
        let want = self
            .file_at
            .checked_add(self.valid)
            .and_then(|end| want.get(self.file_at..end))
            .expect("fs_pressure: page A past the file");
        assert!(got == want, "{what}: the mapping no longer reads the file");
    }
}

impl Drop for MappedPage
{
    fn drop(&mut self)
    {
        let aspace = std::os::seraph::startup_info().self_aspace;
        // SAFETY: the page was mapped at `range` by `take` and no reference
        // into it outlives `expect_content`.
        let _ = unsafe { syscall::mem_unmap(aspace, self.range.va_start(), 1) };
        let _ = syscall::cap_delete(self.cap);
    }
}

/// Take grants until memmgr's free pages outside `promised`, which its level
/// reads, sit at 6/128 of the pool, below the low threshold (1/16) and above
/// the reserve (2/128), then wait for the level to read `Low`; returns the
/// grants.
fn drive_low() -> Vec<(u64, u64)>
{
    let (total, free, level) = pool_pressure_status();
    assert_eq!(
        level,
        ipc::memmgr_labels::PRESSURE_NORMAL,
        "fs_pressure: level before the drive"
    );
    let target = (total / 128).saturating_mul(6);
    let low_exit = (total / 16).saturating_add(total / 128);
    assert!(
        free > low_exit,
        "fs_pressure: free pool {free} of {total} pages too low to drive the level and back"
    );
    let held = take_pages(free.saturating_sub(target));
    let (_, low_free, level) = pool_pressure_status();
    assert_eq!(
        level,
        ipc::memmgr_labels::PRESSURE_LOW,
        "fs_pressure: level with {low_free} of {total} pages free"
    );
    held
}

/// Poll svctest's children's charge until it has fallen by at least `floor`
/// pages from `before`, within [`PRESSURE_WAIT`]; returns the fall.
fn await_children_drop(before: u64, floor: u64) -> u64
{
    let start = std::time::Instant::now();
    loop
    {
        let (own, _, subtree) = memory_usage();
        let fall = before.saturating_sub(subtree.saturating_sub(own));
        if fall >= floor
        {
            return fall;
        }
        assert!(
            start.elapsed() < PRESSURE_WAIT,
            "fs_pressure: the children's charge fell {fall} pages at Low, fewer than {floor}"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Poll memmgr's level until it reads `Normal`, within [`PRESSURE_WAIT`].
fn await_normal()
{
    let start = std::time::Instant::now();
    loop
    {
        let (total, free, level) = pool_pressure_status();
        if level == ipc::memmgr_labels::PRESSURE_NORMAL
        {
            return;
        }
        assert!(
            start.elapsed() < PRESSURE_WAIT,
            "fs_pressure: level {level} with {free} of {total} pages free after the release"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// memmgr's `QUERY_POOL_STATUS` `(system_ram, kernel_reserved, pool_total)`,
/// in bytes.
fn pool_identity() -> (u64, u64, u64)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let req = ipc::IpcMessage::builder(ipc::memmgr_labels::QUERY_POOL_STATUS).build();
    let memmgr = std::os::seraph::startup_info().memmgr_endpoint;
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(memmgr, &req, ipc_buf) }
        .expect("fs_pressure: QUERY_POOL_STATUS ipc_call failed");
    assert_eq!(
        reply.label,
        ipc::memmgr_errors::SUCCESS,
        "fs_pressure: QUERY_POOL_STATUS status"
    );
    (reply.word(0), reply.word(1), reply.word(2))
}
