// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/fs_faults/ramdisk.rs

//! RAM block device behind the `fs_faults` phase's own fatfs: a FAT16 volume
//! just past FAT12's cluster count, formatted at run time and held sparsely,
//! served over the `BLK_READ_INTO_MEMORY` / `BLK_WRITE_FROM_MEMORY` requests
//! fatfs issues, with block faults armed by sector and attempt.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use ipc::{IpcMessage, blk_errors, blk_labels};

/// Bytes per sector, the only size fatfs reads.
pub const SECTOR: usize = 512;
/// One reserved sector (the boot sector), then one FAT copy.
const FAT_LBA: usize = 1;
/// Sectors of the FAT copy: 17 sectors hold 4352 FAT16 entries, enough for
/// the 4098 the clusters need.
const FAT_SECTORS: usize = 17;
/// The fixed root directory: 64 entries, four sectors.
const ROOT_ENTRIES: u16 = 64;
const ROOT_LBA: usize = FAT_LBA + FAT_SECTORS;
const ROOT_SECTORS: usize = 4;
/// First sector of the data region, cluster 2.
const DATA_LBA: usize = ROOT_LBA + ROOT_SECTORS;
/// Data clusters, one sector each: past the 4085 below which a volume is
/// FAT12, which fatfs refuses.
const CLUSTERS: usize = 4096;
/// Sectors on the volume.
const TOTAL_SECTORS: usize = DATA_LBA + CLUSTERS;
/// What an unwritten sector reads as.
const ZERO_SECTOR: [u8; SECTOR] = [0; SECTOR];
/// Largest request fatfs issues: one cache page of sectors.
const MAX_SECTORS_PER_REQUEST: usize = 8;

/// Badge of the phase's stop SEND on the block endpoint.
pub const STOP_BADGE: u64 = 0x5_70B;

/// A fault the device applies to one request.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Fault
{
    /// A write reaches no sector and is reported failed.
    DropWrite,
    /// A write reaches its sectors and is still reported failed.
    FailAfterWrite,
    /// A read is reported failed and fills nothing.
    FailRead,
}

impl Fault
{
    fn direction(self) -> Direction
    {
        if self == Fault::FailRead
        {
            Direction::Read
        }
        else
        {
            Direction::Write
        }
    }
}

/// Which way a block request moves sectors.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Direction
{
    /// `BLK_READ_INTO_MEMORY`: disk to the caller's page.
    Read,
    /// `BLK_WRITE_FROM_MEMORY`: the caller's page to disk.
    Write,
}

/// An armed fault: it fires on the request of its direction starting at
/// `lba` after `skip` such requests have passed, then disarms.
struct Rule
{
    lba: usize,
    skip: u32,
    fault: Fault,
}

/// The volume's written sectors (every other one reads as zeros) and its
/// armed faults.
pub struct RamDisk
{
    sectors: BTreeMap<usize, Box<[u8; SECTOR]>>,
    rules: Vec<Rule>,
}

/// The disk the phase and the block server thread share.
pub type SharedDisk = Arc<Mutex<RamDisk>>;

/// A geometry count as the little-endian 16-bit BPB field that holds it.
fn bpb_u16(count: usize) -> [u8; 2]
{
    u16::try_from(count)
        .expect("fs_faults volume geometry fits a 16-bit BPB field")
        .to_le_bytes()
}

/// Lock the shared disk, ignoring poison: a panicking holder fails the run
/// anyway.
pub fn lock(disk: &SharedDisk) -> MutexGuard<'_, RamDisk>
{
    disk.lock().unwrap_or_else(PoisonError::into_inner)
}

impl RamDisk
{
    /// A zeroed volume with a FAT16 boot sector and the two reserved FAT
    /// entries: an empty root directory and every cluster free.
    pub fn formatted() -> SharedDisk
    {
        let mut boot = Box::new(ZERO_SECTOR);
        boot[..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        boot[3..11].copy_from_slice(b"SVCTEST ");
        boot[11..13].copy_from_slice(&512u16.to_le_bytes());
        boot[13] = 1; // sectors per cluster
        boot[14..16].copy_from_slice(&1u16.to_le_bytes()); // reserved sectors
        boot[16] = 1; // FAT copies
        boot[17..19].copy_from_slice(&ROOT_ENTRIES.to_le_bytes());
        boot[19..21].copy_from_slice(&bpb_u16(TOTAL_SECTORS));
        boot[21] = 0xF8; // media descriptor
        boot[22..24].copy_from_slice(&bpb_u16(FAT_SECTORS));
        boot[510] = 0x55;
        boot[511] = 0xAA;
        let mut fat = Box::new(ZERO_SECTOR);
        fat[..4].copy_from_slice(&[0xF8, 0xFF, 0xFF, 0xFF]);
        Arc::new(Mutex::new(Self {
            sectors: BTreeMap::from([(0, boot), (FAT_LBA, fat)]),
            rules: Vec::new(),
        }))
    }

    /// The bytes of sector `lba`.
    pub fn sector(&self, lba: usize) -> &[u8; SECTOR]
    {
        self.sectors.get(&lba).map_or(&ZERO_SECTOR, |sector| sector)
    }

    /// The FAT16 entry of `cluster`.
    pub fn fat_entry(&self, cluster: u16) -> u16
    {
        let at = usize::from(cluster) * 2;
        let sector = self.sector(FAT_LBA + at / SECTOR);
        u16::from_le_bytes([sector[at % SECTOR], sector[at % SECTOR + 1]])
    }

    /// The sector of `cluster` (one sector per cluster).
    pub fn cluster_lba(cluster: u16) -> usize
    {
        DATA_LBA + usize::from(cluster) - 2
    }

    /// The `(sector, byte offset)` of the root directory's 8.3 entry named
    /// `sfn` (space-padded, no dot), if there is one.
    pub fn find_root_sfn(&self, sfn: &[u8; 11]) -> Option<(usize, usize)>
    {
        (ROOT_LBA..ROOT_LBA + ROOT_SECTORS).find_map(|lba| {
            self.sector(lba)
                .chunks_exact(32)
                .position(|slot| slot[..11] == *sfn && slot[11] != 0x0F)
                .map(|i| (lba, i * 32))
        })
    }

    /// Arm `fault` for the request of its direction starting at `lba` once
    /// `skip` such requests have passed.
    pub fn arm(&mut self, lba: usize, skip: u32, fault: Fault)
    {
        self.rules.push(Rule { lba, skip, fault });
    }

    /// The armed faults that have not fired, in arming order.
    pub fn unfired(&self) -> Vec<Fault>
    {
        self.rules.iter().map(|rule| rule.fault).collect()
    }

    /// Disarm every fault that has not fired.
    pub fn disarm(&mut self)
    {
        self.rules.clear();
    }

    /// The fault that fires on a request starting at `lba`, counting the
    /// request against every armed rule of its direction there.
    fn take_fault(&mut self, lba: usize, direction: Direction) -> Option<Fault>
    {
        let mut fired = None;
        self.rules.retain_mut(|rule| {
            if rule.lba != lba || rule.fault.direction() != direction
            {
                return true;
            }
            if rule.skip > 0
            {
                rule.skip -= 1;
                return true;
            }
            fired = fired.or(Some(rule.fault));
            false
        });
        fired
    }
}

/// Serve the block requests fatfs sends on `ep` until a message carrying
/// [`STOP_BADGE`]. Each request's Memory cap is mapped at a scratch page for
/// the copy, unmapped, and moved back in the reply.
pub fn serve(ep: u32, disk: &SharedDisk)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let aspace = std::os::seraph::startup_info().self_aspace;
    let va = std::os::seraph::reserve_pages(1)
        .expect("fs_faults block server: reserve_pages failed")
        .va_start();
    loop
    {
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        let msg =
            unsafe { ipc::ipc_recv(ep, ipc_buf) }.expect("fs_faults block server: ipc_recv failed");
        if msg.badge == STOP_BADGE
        {
            // SAFETY: as above.
            let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(0), ipc_buf) };
            return;
        }
        let cap = msg.caps().first().copied().unwrap_or(0);
        for &extra in msg.caps().iter().skip(1)
        {
            let _ = syscall::cap_delete(extra);
        }
        let label = match msg.label & 0xFFFF
        {
            blk_labels::BLK_READ_INTO_MEMORY => transfer(
                disk,
                aspace,
                va,
                cap,
                msg.word(0),
                msg.word(1),
                Direction::Read,
            ),
            blk_labels::BLK_WRITE_FROM_MEMORY => transfer(
                disk,
                aspace,
                va,
                cap,
                msg.word(0),
                msg.word(1),
                Direction::Write,
            ),
            _ => blk_errors::DEVICE_STATUS_UNSUPP,
        };
        let mut reply = IpcMessage::builder(label);
        if cap != 0
        {
            reply = reply.cap(cap);
        }
        // SAFETY: as above.
        let _ = unsafe { ipc::ipc_reply(&reply.build(), ipc_buf) };
    }
}

/// Copy `count` sectors at `lba` between the disk and the page `cap` names,
/// in `direction`, unless an armed fault says otherwise. Returns the reply
/// label.
fn transfer(
    disk: &SharedDisk,
    aspace: u32,
    va: u64,
    cap: u32,
    lba: u64,
    count: u64,
    direction: Direction,
) -> u64
{
    let (Ok(lba), Ok(count)) = (usize::try_from(lba), usize::try_from(count))
    else
    {
        return blk_errors::OUT_OF_BOUNDS;
    };
    if cap == 0 || count == 0 || count > MAX_SECTORS_PER_REQUEST
    {
        return blk_errors::INVALID_MEMORY_CAP;
    }
    if lba.saturating_add(count) > TOTAL_SECTORS
    {
        return blk_errors::OUT_OF_BOUNDS;
    }
    let mut disk = lock(disk);
    let fault = disk.take_fault(lba, direction);
    if matches!(fault, Some(Fault::DropWrite | Fault::FailRead))
    {
        return blk_errors::DEVICE_STATUS_IOERR;
    }
    let prot = match direction
    {
        Direction::Read => syscall::MAP_WRITABLE,
        Direction::Write => syscall::MAP_READ,
    };
    // SAFETY: `va` is the block server's own page reservation from the
    // per-process arena, used only by this thread for one copy at a time: VA
    // no Rust object or IPC page occupies.
    if unsafe { syscall::mem_map(cap, aspace, va, 0, 1, prot) }.is_err()
    {
        return blk_errors::INVALID_MEMORY_CAP;
    }
    for i in 0..count
    {
        let page = (va + (i * SECTOR) as u64) as *mut u8;
        // SAFETY: `va` maps one page for this copy, and sector `i` of at
        // most `MAX_SECTORS_PER_REQUEST`, one page's worth, lies inside it.
        unsafe {
            match direction
            {
                Direction::Write =>
                {
                    let sector = disk
                        .sectors
                        .entry(lba + i)
                        .or_insert_with(|| Box::new(ZERO_SECTOR));
                    core::ptr::copy_nonoverlapping(page, sector.as_mut_ptr(), SECTOR);
                }
                Direction::Read =>
                {
                    core::ptr::copy_nonoverlapping(disk.sector(lba + i).as_ptr(), page, SECTOR);
                }
            }
        }
    }
    // SAFETY: the same reserved page, accessed above only through a raw
    // copy; no Rust reference into it is live.
    let _ = unsafe { syscall::mem_unmap(aspace, va, 1) };
    if fault.is_some()
    {
        blk_errors::DEVICE_STATUS_IOERR
    }
    else
    {
        blk_errors::SUCCESS
    }
}
