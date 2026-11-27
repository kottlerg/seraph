// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/fs_faults/ramdisk.rs

//! RAM block device behind the `fs_faults` phase's own fatfs: a FAT16 volume
//! just past FAT12's cluster count, formatted at run time and held sparsely,
//! served over the `BLK_GET_GEOMETRY`, `BLK_READ_INTO_MEMORY`, and
//! `BLK_WRITE_FROM_MEMORY` requests fatfs issues, and over the registered-region
//! labels (`BLK_REGISTER_REGION`, `BLK_READ_REGION`, `BLK_WRITE_REGION`,
//! `BLK_UNREGISTER_REGION`; [`Regions`]), with block faults armed by
//! sector and attempt, or every request failed at once ([`RamDisk::fail_all`]).
//! The device keeps a log of the reads and of the writes it served
//! ([`RamDisk::take_reads`], [`RamDisk::take_writes`]).
//!
//! A request carries up to [`RUN_PAGES`] pages of Memory cap, the run fill
//! fatfs issues for a sequential read, and the server maps and copies as many
//! pages as the request's sectors span; a region transfer moves as many sectors
//! at most, from any sector-aligned offset in its region.
//!
//! The device can also go away: a request carrying [`GONE_BADGE`] revokes
//! every capability derived from the block endpoint, fatfs's among them, and
//! stops the server, as a device whose partition capabilities its owner
//! revoked (services/fs/docs/fs-driver-protocol.md § Loss of the block
//! device).

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
pub const DATA_LBA: usize = ROOT_LBA + ROOT_SECTORS;
/// Data clusters, one sector each: past the 4085 below which a volume is
/// FAT12, which fatfs refuses.
const CLUSTERS: usize = 4096;
/// Sectors on the volume.
const TOTAL_SECTORS: usize = DATA_LBA + CLUSTERS;
/// What an unwritten sector reads as.
const ZERO_SECTOR: [u8; SECTOR] = [0; SECTOR];
/// Pages of the largest request fatfs issues, a run fill.
#[expect(
    clippy::cast_possible_truncation,
    reason = "RUN_PAGES is 16, far below usize::MAX on every target"
)]
pub const RUN_PAGES: usize = fat_parse::RUN_PAGES as usize;
/// Sectors in one page.
const SECTORS_PER_PAGE: usize = 4096 / SECTOR;
/// Largest request fatfs issues, a run fill: `RUN_PAGES` pages of sectors.
const MAX_SECTORS_PER_REQUEST: usize = RUN_PAGES * SECTORS_PER_PAGE;

/// Badge of the phase's stop SEND on the block endpoint.
pub const STOP_BADGE: u64 = 0x5_70B;
/// Badge of the phase's SEND that takes the device away.
pub const GONE_BADGE: u64 = 0x60E;
/// Badge bit of a region cap the device mints, as virtio-blk's region badges
/// carry it, with the region's slot below it.
const REGION_BADGE: u64 = 1 << 62;
/// Regions the device holds at once: virtio-blk's bound for one partition.
const MAX_REGIONS: usize = 4;

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
    /// A read is reported failed, fills nothing, and keeps the page cap it
    /// carried: the device deletes it, and the reply carries no cap. A region
    /// read is only reported failed: the region keeps its cap.
    LoseCap,
}

impl Fault
{
    fn direction(self) -> Direction
    {
        if matches!(self, Fault::FailRead | Fault::LoseCap)
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
    /// Every read and write is answered `DEVICE_STATUS_IOERR` and moves no
    /// sector.
    failing: bool,
    /// `(first sector, sectors)` of every read served since the last
    /// [`RamDisk::take_reads`].
    reads: Vec<(usize, usize)>,
    /// `(first sector, sectors)` of every write served since the last
    /// [`RamDisk::take_writes`].
    writes: Vec<(usize, usize)>,
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
        let mut boot = ZERO_SECTOR;
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
        let mut fat = ZERO_SECTOR;
        fat[..4].copy_from_slice(&[0xF8, 0xFF, 0xFF, 0xFF]);
        Arc::new(Mutex::new(Self {
            sectors: BTreeMap::from([(0, Box::new(boot)), (FAT_LBA, Box::new(fat))]),
            rules: Vec::new(),
            failing: false,
            reads: Vec::new(),
            writes: Vec::new(),
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
        let at = usize::from(cluster)
            .checked_mul(2)
            .expect("FAT entry byte offset overflowed");
        let sector = self.sector(
            FAT_LBA
                .checked_add(at / SECTOR)
                .expect("FAT entry sector overflowed"),
        );
        let entry = sector
            .get(at % SECTOR..)
            .and_then(<[u8]>::first_chunk::<2>)
            .expect("FAT entry straddles a sector");
        u16::from_le_bytes(*entry)
    }

    /// The sector of `cluster` (one sector per cluster).
    pub fn cluster_lba(cluster: u16) -> usize
    {
        DATA_LBA
            .checked_add(usize::from(cluster))
            .and_then(|lba| lba.checked_sub(2))
            .expect("cluster number outside the data area")
    }

    /// The `(sector, byte offset)` of the root directory's 8.3 entry named
    /// `sfn` (space-padded, no dot), if there is one.
    pub fn find_root_sfn(&self, sfn: &[u8; 11]) -> Option<(usize, usize)>
    {
        (ROOT_LBA..DATA_LBA).find_map(|lba| {
            self.sector(lba)
                .as_chunks::<32>()
                .0
                .iter()
                .position(|slot| slot[..11] == *sfn && slot[11] != 0x0F)
                .map(|i| (lba, i.checked_mul(32).expect("root slot offset overflowed")))
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

    /// Fail every read and write until [`RamDisk::serve_all`].
    pub fn fail_all(&mut self)
    {
        self.failing = true;
    }

    /// Serve reads and writes again after [`RamDisk::fail_all`].
    pub fn serve_all(&mut self)
    {
        self.failing = false;
    }

    /// `(first sector, sectors)` of every read the device served since the
    /// last call, in order, emptying the log.
    pub fn take_reads(&mut self) -> Vec<(usize, usize)>
    {
        core::mem::take(&mut self.reads)
    }

    /// `(first sector, sectors)` of every write the device served, the
    /// failed-after-landing ones included, since the last call, in order,
    /// emptying the log.
    pub fn take_writes(&mut self) -> Vec<(usize, usize)>
    {
        core::mem::take(&mut self.writes)
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
                rule.skip = rule.skip.checked_sub(1).expect("fault skip counter");
                return true;
            }
            fired = fired.or(Some(rule.fault));
            false
        });
        fired
    }
}

/// A region the device holds: the Memory cap it was registered with, its
/// length, whether the device may write it, the root of its region caps and
/// the parent of its liveness Notification.
struct Region
{
    memory: u64,
    len: u64,
    writable: bool,
    root: u64,
    liveness: u64,
}

/// The regions registered with the device, by slot, the slot being the low
/// bits of the region's badge. The fake keeps no sole-reference binding: a
/// region stands until it is unregistered or the server stops.
#[derive(Default)]
struct Regions
{
    slots: [Option<Region>; MAX_REGIONS],
}

impl Regions
{
    /// The region a request's badge names.
    fn get(&self, badge: u64) -> Option<&Region>
    {
        if badge & REGION_BADGE == 0
        {
            return None;
        }
        let slot = usize::try_from(badge & !REGION_BADGE).ok()?;
        self.slots.get(slot)?.as_ref()
    }

    /// `BLK_REGISTER_REGION` with `memory` and the access word `access`:
    /// the reply label and, on success, the region cap and the liveness cap.
    /// The device keeps `memory` on success; the caller deletes it otherwise.
    fn register(&mut self, ep: u64, memory: u64, access: u64) -> (u64, Option<(u64, u64)>)
    {
        let writable = match access
        {
            blk_labels::REGION_DEVICE_READS => false,
            blk_labels::REGION_DEVICE_READS_WRITES => true,
            _ => return (blk_errors::INVALID_MEMORY_CAP, None),
        };
        let len = syscall::cap_info(memory, syscall::CAP_INFO_MEMORY_SIZE).unwrap_or(0);
        if memory == 0 || len == 0
        {
            return (blk_errors::INVALID_MEMORY_CAP, None);
        }
        let Some(slot) = self.slots.iter().position(Option::is_none)
        else
        {
            return (blk_errors::REGION_LIMIT, None);
        };
        let badge = REGION_BADGE | slot as u64;
        let root = syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND, badge)
            .expect("fs_faults block server: region root derivation failed");
        let region_cap = syscall::cap_derive(root, syscall::RIGHTS_EP_SEND)
            .expect("fs_faults block server: region cap derivation failed");
        let liveness = std::os::seraph::object_slab_retype(
            std::os::seraph::NOTIFICATION_RETYPE_BYTES,
            |slab| syscall::cap_create_notification(slab).ok(),
        )
        .expect("fs_faults block server: liveness notification creation failed");
        let child = syscall::cap_derive(liveness, 0)
            .expect("fs_faults block server: liveness cap derivation failed");
        if let Some(free) = self.slots.get_mut(slot)
        {
            *free = Some(Region {
                memory,
                len,
                writable,
                root,
                liveness,
            });
        }
        (blk_errors::SUCCESS, Some((region_cap, child)))
    }

    /// `BLK_UNREGISTER_REGION` on `badge`: revoke every copy of the
    /// region's caps and delete the device's. The reply label.
    fn unregister(&mut self, badge: u64) -> u64
    {
        if self.get(badge).is_none()
        {
            return blk_errors::OUT_OF_BOUNDS;
        }
        let slot = usize::try_from(badge & !REGION_BADGE).expect("region slot checked by get");
        if let Some(region) = self.slots.get_mut(slot).and_then(Option::take)
        {
            Self::release(&region);
        }
        blk_errors::SUCCESS
    }

    /// Revoke and delete a region's caps.
    fn release(region: &Region)
    {
        let _ = syscall::cap_revoke_all(region.root);
        let _ = syscall::cap_delete(region.root);
        let _ = syscall::cap_revoke_all(region.liveness);
        let _ = syscall::cap_delete(region.liveness);
        let _ = syscall::cap_delete(region.memory);
    }

    /// Release every region, as the server stops.
    fn clear(&mut self)
    {
        for region in self.slots.iter_mut().filter_map(Option::take)
        {
            Self::release(&region);
        }
    }
}

/// Serve the block requests fatfs sends on `ep` until a message carrying
/// [`STOP_BADGE`] or [`GONE_BADGE`]; the latter first revokes every
/// capability derived from `ep`. Each request's Memory cap is mapped, for as
/// many pages as the request spans (at most [`RUN_PAGES`]), at a scratch
/// range for the copy, unmapped, and moved back in the reply; a region
/// transfer maps the pages of its region it spans the same way.
pub fn serve(ep: u64, disk: &SharedDisk)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let aspace = std::os::seraph::startup_info().self_aspace;
    // One page past a run, for a region transfer that starts inside a page.
    let va = std::os::seraph::reserve_pages(
        (RUN_PAGES as u64)
            .checked_add(1)
            .expect("a run's pages plus one fit"),
    )
    .expect("fs_faults block server: reserve_pages failed")
    .va_start();
    let mut regions = Regions::default();
    loop
    {
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        let msg =
            unsafe { ipc::ipc_recv(ep, ipc_buf) }.expect("fs_faults block server: ipc_recv failed");
        if msg.badge == STOP_BADGE || msg.badge == GONE_BADGE
        {
            // The revoke precedes the reply, so the device is gone once the
            // sender's call returns.
            if msg.badge == GONE_BADGE
            {
                syscall::cap_revoke_all(ep).expect("fs_faults block server: revoke of the device");
            }
            regions.clear();
            // SAFETY: as above.
            let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(0), ipc_buf) };
            return;
        }
        let mut cap = msg.caps().first().copied().unwrap_or(0);
        for &extra in msg.caps().iter().skip(1)
        {
            let _ = syscall::cap_delete(extra);
        }
        if region_request(ep, disk, aspace, va, &mut regions, &msg, cap)
        {
            continue;
        }
        let label = match msg.label & 0xFFFF
        {
            blk_labels::BLK_GET_GEOMETRY =>
            {
                let reply = if msg.word(0) == u64::from(ipc::BLK_LABELS_VERSION)
                {
                    IpcMessage::builder(blk_errors::SUCCESS)
                        .word(0, SECTOR as u64)
                        .word(1, TOTAL_SECTORS as u64)
                        .build()
                }
                else
                {
                    IpcMessage::new(blk_errors::LABEL_VERSION_MISMATCH)
                };
                if cap != 0
                {
                    let _ = syscall::cap_delete(cap);
                }
                // SAFETY: as above.
                let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                continue;
            }
            blk_labels::BLK_READ_INTO_MEMORY => transfer(
                disk,
                aspace,
                va,
                &mut cap,
                msg.word(0),
                msg.word(1),
                Direction::Read,
                None,
            ),
            blk_labels::BLK_WRITE_FROM_MEMORY => transfer(
                disk,
                aspace,
                va,
                &mut cap,
                msg.word(0),
                msg.word(1),
                Direction::Write,
                None,
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

/// Serve a registered-region request `msg` (`BLK_REGISTER_REGION`,
/// `BLK_READ_REGION`, `BLK_WRITE_REGION`, `BLK_UNREGISTER_REGION`), which
/// carried `cap` in `caps[0]` (`0` for none), and reply to it: the device
/// keeps a registered region's Memory cap and deletes every other. Returns
/// `false` for any other label, `cap` then left to the caller.
///
/// Kept out of line so its reply messages take no room in [`serve`]'s frame.
#[inline(never)]
fn region_request(
    ep: u64,
    disk: &SharedDisk,
    aspace: u64,
    va: u64,
    regions: &mut Regions,
    msg: &IpcMessage,
    cap: u64,
) -> bool
{
    let label = msg.label & 0xFFFF;
    let current = msg.word(0) == u64::from(ipc::BLK_LABELS_VERSION);
    if label == blk_labels::BLK_REGISTER_REGION
    {
        let (status, caps) = if current
        {
            regions.register(ep, cap, msg.word(1))
        }
        else
        {
            (blk_errors::LABEL_VERSION_MISMATCH, None)
        };
        let mut reply = IpcMessage::builder(status);
        if let Some((region_cap, liveness_cap)) = caps
        {
            reply = reply.cap(region_cap).cap(liveness_cap);
        }
        else if cap != 0
        {
            let _ = syscall::cap_delete(cap);
        }
        // SAFETY: `serve`'s thread, whose registered IPC buffer page this is.
        let _ = unsafe { ipc::ipc_reply(&reply.build(), std::os::seraph::current_ipc_buf()) };
        return true;
    }
    let status = match label
    {
        blk_labels::BLK_READ_REGION =>
        {
            region_transfer(disk, aspace, va, regions, msg, Direction::Read)
        }
        blk_labels::BLK_WRITE_REGION =>
        {
            region_transfer(disk, aspace, va, regions, msg, Direction::Write)
        }
        blk_labels::BLK_UNREGISTER_REGION if current => regions.unregister(msg.badge),
        blk_labels::BLK_UNREGISTER_REGION => blk_errors::LABEL_VERSION_MISMATCH,
        _ => return false,
    };
    if cap != 0
    {
        let _ = syscall::cap_delete(cap);
    }
    // SAFETY: as above.
    let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(status), std::os::seraph::current_ipc_buf()) };
    true
}

/// The reply label for a request whose Memory cap the block server's map
/// refused with `error`. A map that still finds the page-table pool exhausted
/// after the funded map's top-ups is the server's own failure, not the
/// caller's, and is answered `DEVICE_FAULT`, the code a block driver gives a
/// request whose cap could not be mapped for the device; any other refusal is
/// the cap's, answered `INVALID_MEMORY_CAP`.
fn map_refusal_label(error: i64) -> u64
{
    if error == syscall_abi::SyscallError::OutOfMemory as i64
    {
        blk_errors::DEVICE_FAULT
    }
    else
    {
        blk_errors::INVALID_MEMORY_CAP
    }
}

/// A `BLK_READ_REGION` or `BLK_WRITE_REGION` request `msg` on the region its
/// badge names: `data[1]` LBA, `data[2]` count, `data[3]` byte offset in the
/// region. Returns the reply label, with virtio-blk's checks: the offset a
/// sector multiple, the run inside the region, a read into a writable region.
fn region_transfer(
    disk: &SharedDisk,
    aspace: u64,
    va: u64,
    regions: &Regions,
    msg: &IpcMessage,
    direction: Direction,
) -> u64
{
    if msg.word(0) != u64::from(ipc::BLK_LABELS_VERSION)
    {
        return blk_errors::LABEL_VERSION_MISMATCH;
    }
    let Some(region) = regions.get(msg.badge)
    else
    {
        return blk_errors::OUT_OF_BOUNDS;
    };
    let (count, offset) = (msg.word(2), msg.word(3));
    let end = count
        .checked_mul(SECTOR as u64)
        .and_then(|bytes| bytes.checked_add(offset));
    if !offset.is_multiple_of(SECTOR as u64)
        || end.is_none_or(|end| end > region.len)
        || (direction == Direction::Read && !region.writable)
    {
        return blk_errors::INVALID_MEMORY_CAP;
    }
    let mut memory = region.memory;
    transfer(
        disk,
        aspace,
        va,
        &mut memory,
        msg.word(1),
        count,
        direction,
        Some(offset),
    )
}

/// Copy `count` sectors at `lba` between the disk and the pages `*cap` names,
/// from byte `at` of them for a region transfer and from the start
/// otherwise, in `direction`, unless an armed fault says otherwise. Returns
/// the reply label; `*cap` is 0 when the fault deleted the cap, so the reply
/// carries none, which a region transfer's fault never does.
#[expect(
    clippy::too_many_arguments,
    reason = "the server's scratch range, the cap and the request's words; a struct would only \
              rename them for this one private call"
)]
fn transfer(
    disk: &SharedDisk,
    aspace: u64,
    va: u64,
    cap: &mut u64,
    lba: u64,
    count: u64,
    direction: Direction,
    at: Option<u64>,
) -> u64
{
    let (Ok(lba), Ok(count)) = (usize::try_from(lba), usize::try_from(count))
    else
    {
        return blk_errors::OUT_OF_BOUNDS;
    };
    if *cap == 0 || count == 0 || count > MAX_SECTORS_PER_REQUEST
    {
        return blk_errors::INVALID_MEMORY_CAP;
    }
    if lba.saturating_add(count) > TOTAL_SECTORS
    {
        return blk_errors::OUT_OF_BOUNDS;
    }
    let mut disk = lock(disk);
    if disk.failing
    {
        return blk_errors::DEVICE_STATUS_IOERR;
    }
    let fault = disk.take_fault(lba, direction);
    if matches!(fault, Some(Fault::DropWrite | Fault::FailRead))
    {
        return blk_errors::DEVICE_STATUS_IOERR;
    }
    if fault == Some(Fault::LoseCap) && at.is_some()
    {
        return blk_errors::DEVICE_STATUS_IOERR;
    }
    if fault == Some(Fault::LoseCap)
    {
        let _ = syscall::cap_delete(*cap);
        *cap = 0;
        return blk_errors::DEVICE_STATUS_IOERR;
    }
    let prot = match direction
    {
        Direction::Read => syscall::MAP_WRITABLE,
        Direction::Write => syscall::MAP_READ,
    };
    let at = at.unwrap_or(0);
    let first_page = at / 4096;
    let Ok(in_page) = usize::try_from(at % 4096)
    else
    {
        return blk_errors::INVALID_MEMORY_CAP;
    };
    let pages = count
        .checked_mul(SECTOR)
        .and_then(|bytes| bytes.checked_add(in_page))
        .expect("fs_faults block server: transfer span overflowed")
        .div_ceil(4096);
    // SAFETY: `va` is the block server's own reservation of `RUN_PAGES + 1`
    // pages from the per-process arena, used only by this thread for one copy
    // at a time: VA no Rust object or IPC page occupies; `pages` of them,
    // at most `RUN_PAGES + 1` (a run of sectors from inside a page), are
    // mapped.
    let mapped = unsafe {
        std::os::seraph::mem_map_funded(*cap, aspace, va, first_page, pages as u64, prot)
    };
    if let Err(e) = mapped
    {
        // A map refused part-way can leave the pages before the failing one
        // mapped (docs/userspace-memory-model.md § Page Reservations), and the
        // reply moves the cap back to fatfs.
        // SAFETY: the same `pages` reserved pages, which no Rust reference
        // reaches.
        let _ = unsafe { syscall::mem_unmap(aspace, va, pages as u64) };
        return map_refusal_label(e);
    }
    match direction
    {
        Direction::Read => disk.reads.push((lba, count)),
        Direction::Write => disk.writes.push((lba, count)),
    }
    for i in 0..count
    {
        let offset = i
            .checked_mul(SECTOR)
            .and_then(|bytes| bytes.checked_add(in_page))
            .expect("sector copy offset overflowed");
        let page = va
            .checked_add(offset as u64)
            .expect("sector copy address overflowed") as *mut u8;
        let sector_lba = lba.checked_add(i).expect("sector copy LBA overflowed");
        match direction
        {
            Direction::Write =>
            {
                let sector = disk
                    .sectors
                    .entry(sector_lba)
                    .or_insert_with(|| Box::new(ZERO_SECTOR));
                // SAFETY: `va` maps `pages` pages for this copy, and sector `i`
                // of `count`, which `pages` holds, lies inside them;
                // `sector` is a distinct heap buffer.
                unsafe { core::ptr::copy_nonoverlapping(page, sector.as_mut_ptr(), SECTOR) };
            }
            Direction::Read =>
            {
                let sector = disk.sector(sector_lba);
                // SAFETY: `va` maps `pages` pages for this copy, and sector
                // `i` lies inside them, as for the write arm; `sector` is the
                // disk's own buffer or the static `ZERO_SECTOR`, either way
                // distinct from the mapped page.
                unsafe { core::ptr::copy_nonoverlapping(sector.as_ptr(), page, SECTOR) };
            }
        }
    }
    drop(disk);
    // SAFETY: the same `pages` reserved pages, accessed above only through
    // a raw copy; no Rust reference into them is live.
    let _ = unsafe { syscall::mem_unmap(aspace, va, pages as u64) };
    if fault.is_some()
    {
        blk_errors::DEVICE_STATUS_IOERR
    }
    else
    {
        blk_errors::SUCCESS
    }
}
