// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/virtio/blk/src/main.rs

//! Seraph `VirtIO` block device driver.
//!
//! Receives BAR MMIO cap, IRQ cap, and `VirtioPciStartupInfo` startup message
//! from devmgr. Initialises the `VirtIO` device via the modern PCI transport,
//! sets up a split virtqueue, and serves block read requests over IPC.

// cast_possible_truncation: userspace targets 64-bit only; u64/usize conversions
// are lossless. u32 casts on capability slot indices are bounded by CSpace capacity.
#![allow(clippy::cast_possible_truncation)]

mod io;

use ipc::{IpcMessage, blk_labels, devmgr_labels, memmgr_errors, memmgr_labels};
use std::os::seraph::{StartupInfo, reserve_pages, startup_info};
use syscall_abi::PAGE_SIZE;
use virtio_core::pci::PciTransport;
use virtio_core::virtqueue::{self, SplitVirtqueue};
use virtio_core::{
    STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FEATURES_OK, VirtioPciStartupInfo,
};

use crate::io::IoLayout;

// ── Constants ──────────────────────────────────────────────────────────────

/// Queue size we request (must be <= device max).
const QUEUE_SIZE: u16 = 128;

/// Maximum number of badged partitions this driver can serve concurrently.
///
/// Partition identity is the caller's cap badge. vfsd registers one entry
/// per mount; 16 is ample for early boot (typical disk has 1–2 partitions).
const PARTITION_TABLE_SIZE: usize = 16;

/// Per-badge partition bound: absolute LBA range the caller is permitted
/// to access. Badge 0 is reserved for the un-badged (whole-disk) endpoint
/// and is never stored here.
#[derive(Clone, Copy)]
struct PartitionBound
{
    badge: u64,
    base_lba: u64,
    length_lba: u64,
}

/// Fixed-capacity partition table. Open-addressed linear scan; expected
/// depth ≤ number of mounted partitions. Lookups and inserts are O(n) over
/// `PARTITION_TABLE_SIZE` but n is bounded and small.
struct PartitionTable
{
    entries: [Option<PartitionBound>; PARTITION_TABLE_SIZE],
}

impl PartitionTable
{
    const fn new() -> Self
    {
        Self {
            entries: [None; PARTITION_TABLE_SIZE],
        }
    }

    /// Return the bound for `badge`, or `None` if no entry is registered.
    fn lookup(&self, badge: u64) -> Option<PartitionBound>
    {
        if badge == 0
        {
            return None;
        }
        for b in self.entries.iter().flatten()
        {
            if b.badge == badge
            {
                return Some(*b);
            }
        }
        None
    }

    /// Insert a bound. Fails if `badge == 0`, a duplicate badge exists, or
    /// the table is full.
    fn insert(&mut self, bound: PartitionBound) -> Result<(), ()>
    {
        if bound.badge == 0 || bound.length_lba == 0
        {
            return Err(());
        }
        let mut empty_idx: Option<usize> = None;
        for (i, entry) in self.entries.iter().enumerate()
        {
            match entry
            {
                Some(b) if b.badge == bound.badge => return Err(()),
                None if empty_idx.is_none() => empty_idx = Some(i),
                _ =>
                {}
            }
        }
        match empty_idx
        {
            Some(i) =>
            {
                self.entries[i] = Some(bound);
                Ok(())
            }
            None => Err(()),
        }
    }

    /// Remove the entry matching `badge`, if any. Used to roll back an
    /// insert when downstream cap derivation fails.
    fn remove(&mut self, badge: u64)
    {
        for entry in &mut self.entries
        {
            if matches!(entry, Some(b) if b.badge == badge)
            {
                *entry = None;
                return;
            }
        }
    }
}

// ── Driver caps from bootstrap protocol ────────────────────────────────────
//
// devmgr → virtio-blk bootstrap plan:
// Round 1 (3 caps):
//   caps[0]: BAR MMIO region
//   caps[1]: IRQ line
//   caps[2]: service endpoint (virtio-blk receives on this)
// Round 2 (1 cap):
//   caps[0]: devmgr query endpoint (badged per-device — for QUERY_DEVICE_INFO)
//
// log_ep and procmgr_ep arrive via `ProcessInfo`/`StartupInfo`, not through
// this protocol.

struct DriverCaps
{
    bar_mmio_slot: u32,
    irq_slot: u32,
    memmgr_ep: u32,
    service_ep: u32,
    devmgr_ep: u32,
    self_aspace: u32,
}

fn bootstrap_caps(info: &StartupInfo, ipc_buf: *mut u64) -> Option<DriverCaps>
{
    let creator = info.creator_endpoint;
    if creator == 0
    {
        return None;
    }

    // SAFETY: `ipc_buf` is the registered IPC buffer for this thread.
    let round1 = unsafe { ipc::bootstrap::request_round(creator, ipc_buf) }.ok()?;
    if round1.cap_count < 3 || round1.done
    {
        return None;
    }

    // SAFETY: same invariant.
    let round2 = unsafe { ipc::bootstrap::request_round(creator, ipc_buf) }.ok()?;
    if round2.cap_count < 1 || !round2.done
    {
        return None;
    }

    Some(DriverCaps {
        bar_mmio_slot: round1.caps[0],
        irq_slot: round1.caps[1],
        service_ep: round1.caps[2],
        memmgr_ep: info.memmgr_endpoint,
        devmgr_ep: round2.caps[0],
        self_aspace: info.self_aspace,
    })
}

// ── Device info query via devmgr IPC ──────────────────────────────────────

/// Query devmgr for `VirtIO` PCI capability locations via IPC.
///
/// The driver's devmgr endpoint is badged — the badge identifies the
/// device. Devmgr replies in the generic `QUERY_DEVICE_INFO` schema:
/// `word[0]` = kind, `word[1]` = version, `word[2]` = `byte_len`,
/// payload bytes packed into the subsequent data words. The driver
/// verifies kind/version before deserialising.
fn query_device_info(devmgr_ep: u32, ipc_buf: *mut u64) -> VirtioPciStartupInfo
{
    let request = IpcMessage::builder(devmgr_labels::QUERY_DEVICE_INFO)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(devmgr_ep, &request, ipc_buf) })
    else
    {
        std::os::seraph::log!("QUERY_DEVICE_INFO ipc_call failed");
        syscall::thread_exit();
    };
    if reply.label != 0
    {
        std::os::seraph::log!("QUERY_DEVICE_INFO returned error");
        syscall::thread_exit();
    }
    let words = reply.words();
    if words.len() < 3
    {
        std::os::seraph::log!("QUERY_DEVICE_INFO reply truncated (header)");
        syscall::thread_exit();
    }
    let kind = words[0] as u32;
    let version = words[1] as u32;
    let byte_len = words[2] as usize;
    if kind != ipc::device_info_kind::VIRTIO_PCI || version != virtio_core::VIRTIO_PCI_INFO_VERSION
    {
        std::os::seraph::log!("QUERY_DEVICE_INFO reply kind/version mismatch");
        syscall::thread_exit();
    }
    if byte_len != VirtioPciStartupInfo::SIZE
    {
        std::os::seraph::log!("QUERY_DEVICE_INFO reply byte_len mismatch");
        syscall::thread_exit();
    }
    // Unpack payload words into a byte buffer, then deserialise.
    let mut buf = [0u8; VirtioPciStartupInfo::SIZE];
    let payload_words = byte_len.div_ceil(8);
    if words.len() < 3 + payload_words
    {
        std::os::seraph::log!("QUERY_DEVICE_INFO reply truncated (payload)");
        syscall::thread_exit();
    }
    for (i, chunk) in buf.chunks_mut(8).enumerate()
    {
        let bytes = words[3 + i].to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    let Some(info) = VirtioPciStartupInfo::from_bytes(&buf)
    else
    {
        std::os::seraph::log!("QUERY_DEVICE_INFO from_bytes failed");
        syscall::thread_exit();
    };
    info
}

// ── Memory-cap allocation via memmgr IPC ────────────────────────────────────────

/// Request a single contiguous Memory cap covering `page_count` pages from
/// memmgr. Returns `(cap_slot, phys_base)` on success — the physical base
/// address is needed for DMA programming on no-IOMMU systems and is
/// supplied by memmgr in the `REQUEST_MEMORY_CAPS` reply alongside the cap.
fn request_memory_caps(memmgr_ep: u32, page_count: u64, ipc_buf: *mut u64) -> Option<(u32, u64)>
{
    let arg = page_count | (u64::from(memmgr_labels::REQUIRE_CONTIGUOUS) << 32);
    let request = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, arg)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(memmgr_ep, &request, ipc_buf) }.ok()?;
    if reply.label != memmgr_errors::SUCCESS
    {
        return None;
    }

    // REQUIRE_CONTIGUOUS guarantees exactly one cap covering page_count pages.
    if reply.word(0) != 1
    {
        for &c in reply.caps()
        {
            let _ = syscall::cap_delete(c);
        }
        return None;
    }
    // Reply layout: data[0] = count, data[1..1+count] = page_counts,
    // data[1+count..1+2*count] = phys_bases. With count == 1, phys_base
    // sits at data[2].
    let cap = reply.caps().first().copied()?;
    let phys_base = reply.word(2);
    Some((cap, phys_base))
}

// ── Device initialisation ──────────────────────────────────────────────────

/// Initialise the `VirtIO` device through the standard sequence (`VirtIO` 1.2
/// section 3.1.1): reset, acknowledge, negotiate features, read capacity.
fn init_device(transport: &PciTransport) -> u64
{
    transport.reset();
    transport.set_status(STATUS_ACKNOWLEDGE);
    transport.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    let features = transport.negotiate_features(|device_features| {
        // Accept only VIRTIO_F_VERSION_1 (bit 32) — required for modern devices.
        device_features & (1 << 32)
    });
    if features.is_none()
    {
        std::os::seraph::log!("feature negotiation failed");
        syscall::thread_exit();
    }

    transport.config_read_u64(0)
}

/// Negotiate the virtqueue size against the device maximum and apply it.
fn configure_queue_size(transport: &PciTransport) -> u16
{
    transport.queue_select(0);
    let max_size = transport.queue_max_size();
    let queue_size = QUEUE_SIZE.min(max_size);
    transport.queue_set_size(queue_size);
    queue_size
}

/// Allocate the backing DMA memory for the virtqueue rings and map it into
/// the driver's address space. Returns `(ring_phys, ring_pages, ring_va)`.
fn allocate_and_map_rings(queue_size: u16, caps: &DriverCaps, ipc_buf: *mut u64)
-> (u64, u64, u64)
{
    let ring_pages = virtqueue::ring_pages(queue_size) as u64;
    let Some((ring_memory, ring_phys)) = request_memory_caps(caps.memmgr_ep, ring_pages, ipc_buf)
    else
    {
        std::os::seraph::log!("failed to allocate ring memory caps");
        syscall::thread_exit();
    };
    // The ring mapping lives for the driver process's lifetime; the
    // reservation is intentionally never returned to the arena (the
    // ReservedRange has no Drop impl, so falling out of scope is a no-op).
    let Ok(ring_range) = reserve_pages(ring_pages)
    else
    {
        std::os::seraph::log!("ring reserve_pages failed");
        syscall::thread_exit();
    };
    let ring_va = ring_range.va_start();
    if syscall::mem_map(
        ring_memory,
        caps.self_aspace,
        ring_va,
        0,
        ring_pages,
        syscall::MAP_READONLY | syscall::MAP_WRITABLE,
    )
    .is_err()
    {
        std::os::seraph::log!("ring mem_map failed");
        syscall::thread_exit();
    }
    // SAFETY: ring_va is mapped writable, ring_pages * PAGE_SIZE bytes.
    unsafe {
        core::ptr::write_bytes(ring_va as *mut u8, 0, (ring_pages * PAGE_SIZE) as usize);
    }
    (ring_phys, ring_pages, ring_va)
}

/// Write the descriptor/avail/used ring physical addresses into the PCI
/// transport and mark the queue ready.
fn program_transport_rings(transport: &PciTransport, queue_size: u16, ring_phys: u64)
{
    let desc_size = virtqueue::desc_table_size(queue_size);
    let used_off = virtqueue::used_ring_offset(queue_size);

    let desc_phys = ring_phys;
    let avail_phys = ring_phys + desc_size as u64;
    let used_phys = ring_phys + used_off as u64;

    transport.queue_set_desc_lo(desc_phys as u32);
    transport.queue_set_desc_hi((desc_phys >> 32) as u32);
    transport.queue_set_avail_lo(avail_phys as u32);
    transport.queue_set_avail_hi((avail_phys >> 32) as u32);
    transport.queue_set_used_lo(used_phys as u32);
    transport.queue_set_used_hi((used_phys >> 32) as u32);

    transport.queue_set_ready(1);
}

/// Set up virtqueue 0 (requestq): allocate ring DMA memory, map it, program
/// the device, and return a `SplitVirtqueue` + notification offset.
///
/// # Panics
///
/// Exits the thread on allocation or mapping failure (no recovery path).
fn setup_virtqueue(
    transport: &PciTransport,
    caps: &DriverCaps,
    ipc_buf: *mut u64,
) -> (SplitVirtqueue, u16)
{
    let queue_size = configure_queue_size(transport);
    let (ring_phys, _ring_pages, ring_va) = allocate_and_map_rings(queue_size, caps, ipc_buf);
    program_transport_rings(transport, queue_size, ring_phys);

    // Save notification offset for this queue before changing selection.
    let queue_notify_off = transport.queue_notify_off();

    let desc_size = virtqueue::desc_table_size(queue_size);
    let used_off = virtqueue::used_ring_offset(queue_size);
    let desc_va = ring_va;
    let avail_va = ring_va + desc_size as u64;
    let used_va = ring_va + used_off as u64;

    // SAFETY: ring memory is zeroed, properly sized, and exclusively owned.
    // Pointers are aligned: desc_va is page-aligned; avail_va is at desc_va +
    // queue_size*16 (always 2-byte aligned); used_va is at avail_va + 4 + 2*queue_size
    // (always 4-byte aligned for VirtqUsedElem).
    let vq = unsafe {
        SplitVirtqueue::new(
            desc_va as *mut virtqueue::VirtqDesc,
            avail_va as *mut virtqueue::VirtqAvail,
            used_va as *mut virtqueue::VirtqUsed,
            queue_size,
        )
    };

    (vq, queue_notify_off)
}

/// Allocate and map the data buffer page for block I/O, returning an `IoLayout`.
fn setup_io_buffer(caps: &DriverCaps, ipc_buf: *mut u64) -> IoLayout
{
    let Some((data_memory, data_phys)) = request_memory_caps(caps.memmgr_ep, 1, ipc_buf)
    else
    {
        std::os::seraph::log!("failed to allocate data memory cap");
        syscall::thread_exit();
    };
    // The data mapping lives for the driver process's lifetime; the
    // reservation falls out of scope as a no-op (ReservedRange has no
    // Drop impl).
    let Ok(data_range) = reserve_pages(1)
    else
    {
        std::os::seraph::log!("data reserve_pages failed");
        syscall::thread_exit();
    };
    let data_va = data_range.va_start();
    if syscall::mem_map(
        data_memory,
        caps.self_aspace,
        data_va,
        0,
        1,
        syscall::MAP_READONLY | syscall::MAP_WRITABLE,
    )
    .is_err()
    {
        std::os::seraph::log!("data mem_map failed");
        syscall::thread_exit();
    }

    // Fill data buffer with sentinel pattern (0xAA) to detect untouched regions.
    // SAFETY: data_va is mapped writable, one page.
    unsafe { core::ptr::write_bytes(data_va as *mut u8, 0xAA, PAGE_SIZE as usize) };

    IoLayout { data_va, data_phys }
}

// ── Service loop ───────────────────────────────────────────────────────────

/// Long-lived driver runtime state: the data-buffer layout, virtqueue, PCI
/// transport, IRQ plumbing, and partition table that every request needs.
pub struct BlkRuntime<'a>
{
    pub layout: &'a IoLayout,
    pub vq: &'a mut SplitVirtqueue,
    pub transport: &'a PciTransport,
    pub queue_notify_off: u16,
    pub irq_notification: u32,
    pub irq_cap: u32,
    /// Un-badged `SEND_GRANT` cap on this driver's service endpoint;
    /// kept so `handle_register_partition` can `cap_derive_badge` per-
    /// partition badged caps from it. The kernel rejects re-badging
    /// of a badged source, so partition cap derivation must happen
    /// here (server-side) and not at the caller (which holds a
    /// MOUNT_AUTHORITY-badged cap).
    pub service_ep: u32,
    partitions: PartitionTable,
    capacity: u64,
    /// Monotonic counter for partition-identity badges. The
    /// `MOUNT_AUTHORITY` bit lives at `1 << 63`; this counter stays in
    /// the low bits and so is bit-disjoint by construction.
    next_partition_badge: u64,
}

/// `RecvGuard` diagnostic hook: one line at the start of a failure streak,
/// one more before the fatal exit.
fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            std::os::seraph::log!("ipc_recv failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!("ipc_recv wedged (err={err}); exiting");
        }
    }
}

/// Handle incoming IPC requests on the service endpoint.
fn service_loop(service_ep: u32, ipc_buf: *mut u64, rt: &mut BlkRuntime) -> !
{
    std::os::seraph::log!("ready, entering service loop");
    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let msg = match unsafe { ipc::ipc_recv(service_ep, ipc_buf) }
        {
            Ok(msg) => msg,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();

        match msg.label
        {
            blk_labels::BLK_READ_INTO_MEMORY =>
            {
                handle_read_block_into_memory(&msg, ipc_buf, rt);
            }
            blk_labels::BLK_WRITE_FROM_MEMORY =>
            {
                handle_write_block_from_memory(&msg, ipc_buf, rt);
            }
            blk_labels::REGISTER_PARTITION =>
            {
                handle_register_partition(&msg, ipc_buf, rt);
            }
            _ =>
            {
                let reply = IpcMessage::new(ipc::blk_errors::UNKNOWN_OPCODE);
                // SAFETY: ipc_buf is the registered IPC buffer page.
                let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            }
        }
    }
}

/// Handle a `BLK_READ_INTO_MEMORY` request.
///
/// Reads `caps[0]` (target Memory cap) and DMAs `data[1]` consecutive sectors
/// (default 1) starting at LBA `data[0]` into the memory cap at offset 0,
/// packed contiguously. The memory cap must be at least `count * 512` bytes;
/// the driver rejects with `INVALID_MEMORY_CAP` otherwise.
///
/// `caps[1]` and `caps[2]` are reserved IPC-shape slots and remain null
/// pre-IOMMU; the driver does not inspect them. The target Memory cap is
/// moved back to the caller in `caps[0]` of the reply regardless of
/// success — leaving the cap in the driver's `CSpace` would leak it.
// too_many_lines: handle_read_block_into_memory folds nine validation
// gates (cap presence, sector count, descriptor-length bound, three
// cap_info lookups, partition resolution for start and end LBA) into
// one flat dispatch; each rejection path replies with the cap moved
// back so it never leaks. Extracting helpers would still leave the
// reply-with-cap pattern wired through main.
#[allow(clippy::too_many_lines)]
fn handle_read_block_into_memory(msg: &IpcMessage, ipc_buf: *mut u64, rt: &mut BlkRuntime)
{
    const SECTOR_SIZE: u64 = 512;

    let target_cap = msg.caps().first().copied().unwrap_or(0);

    let reply_with = |code: u64, ipc_buf: *mut u64| {
        let mut builder = IpcMessage::builder(code);
        if target_cap != 0
        {
            builder = builder.cap(target_cap);
        }
        let reply = builder.build();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    };

    if target_cap == 0
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, ipc_buf);
        return;
    }

    let sector_count = if msg.word_count() >= 2
    {
        msg.word(1)
    }
    else
    {
        1
    };
    if sector_count == 0
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, ipc_buf);
        return;
    }
    let data_len_bytes = sector_count * SECTOR_SIZE;
    // VirtIO descriptor length is u32; this also bounds total transfer
    // well below any plausible per-cap ask.
    if data_len_bytes > u64::from(u32::MAX)
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, ipc_buf);
        return;
    }

    // Validate the target cap: must be a Memory cap with MAP+WRITE rights and
    // at least `data_len_bytes` of capacity.
    let Ok(tag_rights) = syscall::cap_info(target_cap, syscall::CAP_INFO_TAG_RIGHTS)
    else
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, ipc_buf);
        return;
    };
    let tag = (tag_rights >> 32) as u8;
    let rights = tag_rights & 0xFFFF_FFFF;
    let required = syscall::RIGHTS_MAP_RW;
    if u64::from(tag) != u64::from(syscall::CAP_TAG_MEMORY) || (rights & required) != required
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, ipc_buf);
        return;
    }
    let Ok(size) = syscall::cap_info(target_cap, syscall::CAP_INFO_MEMORY_SIZE)
    else
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, ipc_buf);
        return;
    };
    if size < data_len_bytes
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, ipc_buf);
        return;
    }
    let Ok(phys_base) = syscall::cap_info(target_cap, syscall::CAP_INFO_MEMORY_PHYS_BASE)
    else
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, ipc_buf);
        return;
    };

    let sector = if msg.word_count() >= 1
    {
        msg.word(0)
    }
    else
    {
        0
    };
    let absolute_sector = match resolve_sector(msg.badge, sector, rt)
    {
        Ok(s) => s,
        Err(code) =>
        {
            reply_with(code, ipc_buf);
            return;
        }
    };
    // Validate the entire run lies within the partition / device bounds:
    // resolve_sector only checks the starting LBA. Re-check the inclusive
    // end LBA so a multi-sector ask doesn't walk past the partition.
    let last_relative = sector.saturating_add(sector_count - 1);
    if resolve_sector(msg.badge, last_relative, rt).is_err()
    {
        reply_with(ipc::blk_errors::OUT_OF_BOUNDS, ipc_buf);
        return;
    }

    // cast_possible_truncation: data_len_bytes <= u32::MAX checked above.
    #[allow(clippy::cast_possible_truncation)]
    if !io::submit_and_wait(
        rt.layout,
        io::IoDirection::Read,
        absolute_sector,
        phys_base,
        data_len_bytes as u32,
        rt.vq,
        rt.transport,
        rt.queue_notify_off,
        rt.irq_notification,
        rt.irq_cap,
    )
    {
        let status = rt.layout.read_status();
        reply_with(u64::from(status), ipc_buf);
        return;
    }

    reply_with(ipc::blk_errors::SUCCESS, ipc_buf);
}

/// Handle a `BLK_WRITE_FROM_MEMORY` request.
///
/// Mirror of [`handle_read_block_into_memory`] with the data direction
/// inverted. Reads `caps[0]` (source Memory cap, `MAP|READ`) and DMAs
/// `data[1]` consecutive sectors (default 1) starting at LBA `data[0]`
/// out of the memory cap at offset 0, packed contiguously. The source Memory cap
/// is moved back to the caller in `caps[0]` of the reply.
// too_many_lines: matches the read sibling — the same validation gates
// (cap presence, sector count, descriptor-length bound, three cap_info
// lookups, two partition resolutions for start and end LBA) all apply
// here, and the reply-with-cap pattern is unchanged.
#[allow(clippy::too_many_lines)]
fn handle_write_block_from_memory(msg: &IpcMessage, ipc_buf: *mut u64, rt: &mut BlkRuntime)
{
    const SECTOR_SIZE: u64 = 512;

    let source_cap = msg.caps().first().copied().unwrap_or(0);

    let reply_with = |code: u64, ipc_buf: *mut u64| {
        let mut builder = IpcMessage::builder(code);
        if source_cap != 0
        {
            builder = builder.cap(source_cap);
        }
        let reply = builder.build();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    };

    if source_cap == 0
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, ipc_buf);
        return;
    }

    let sector_count = if msg.word_count() >= 2
    {
        msg.word(1)
    }
    else
    {
        1
    };
    if sector_count == 0
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, ipc_buf);
        return;
    }
    let data_len_bytes = sector_count * SECTOR_SIZE;
    if data_len_bytes > u64::from(u32::MAX)
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, ipc_buf);
        return;
    }

    // Source memory cap must be a Memory cap with at least MAP+READ rights
    // (device reads sector data out of it) and large enough to cover the
    // requested run.
    let Ok(tag_rights) = syscall::cap_info(source_cap, syscall::CAP_INFO_TAG_RIGHTS)
    else
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, ipc_buf);
        return;
    };
    let tag = (tag_rights >> 32) as u8;
    let rights = tag_rights & 0xFFFF_FFFF;
    let required = syscall::RIGHTS_MAP_READ;
    if u64::from(tag) != u64::from(syscall::CAP_TAG_MEMORY) || (rights & required) != required
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, ipc_buf);
        return;
    }
    let Ok(size) = syscall::cap_info(source_cap, syscall::CAP_INFO_MEMORY_SIZE)
    else
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, ipc_buf);
        return;
    };
    if size < data_len_bytes
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, ipc_buf);
        return;
    }
    let Ok(phys_base) = syscall::cap_info(source_cap, syscall::CAP_INFO_MEMORY_PHYS_BASE)
    else
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, ipc_buf);
        return;
    };

    let sector = if msg.word_count() >= 1
    {
        msg.word(0)
    }
    else
    {
        0
    };
    let absolute_sector = match resolve_sector(msg.badge, sector, rt)
    {
        Ok(s) => s,
        Err(code) =>
        {
            reply_with(code, ipc_buf);
            return;
        }
    };
    let last_relative = sector.saturating_add(sector_count - 1);
    if resolve_sector(msg.badge, last_relative, rt).is_err()
    {
        reply_with(ipc::blk_errors::OUT_OF_BOUNDS, ipc_buf);
        return;
    }

    // cast_possible_truncation: data_len_bytes <= u32::MAX checked above.
    #[allow(clippy::cast_possible_truncation)]
    if !io::submit_and_wait(
        rt.layout,
        io::IoDirection::Write,
        absolute_sector,
        phys_base,
        data_len_bytes as u32,
        rt.vq,
        rt.transport,
        rt.queue_notify_off,
        rt.irq_notification,
        rt.irq_cap,
    )
    {
        let status = rt.layout.read_status();
        reply_with(u64::from(status), ipc_buf);
        return;
    }

    reply_with(ipc::blk_errors::SUCCESS, ipc_buf);
}

/// Translate a caller-supplied sector number into an absolute device LBA,
/// enforcing per-badge partition bounds. Returns a [`blk_errors`] code on
/// rejection.
///
/// Badge semantics:
/// * Badge bit [`MOUNT_AUTHORITY`] set → whole-disk read; bounded only
///   by device capacity. Held by callers (currently just vfsd) that
///   need to walk the partition table before partitioning is complete.
/// * Badge with [`MOUNT_AUTHORITY`] clear and non-zero low bits →
///   partition-identity badge issued by [`handle_register_partition`];
///   bounded by the registered partition.
/// * `badge == 0` → un-badged caller; rejected. Every consumer of
///   this endpoint holds a badged cap.
fn resolve_sector(badge: u64, sector: u64, rt: &BlkRuntime) -> Result<u64, u64>
{
    if badge == 0
    {
        return Err(ipc::blk_errors::OUT_OF_BOUNDS);
    }

    if badge & ipc::blk_labels::MOUNT_AUTHORITY != 0
    {
        // MOUNT_AUTHORITY holders read the whole disk directly,
        // bounded only by device capacity.
        if sector >= rt.capacity
        {
            return Err(ipc::blk_errors::OUT_OF_BOUNDS);
        }
        return Ok(sector);
    }

    let Some(bound) = rt.partitions.lookup(badge)
    else
    {
        return Err(ipc::blk_errors::OUT_OF_BOUNDS);
    };
    if sector >= bound.length_lba
    {
        return Err(ipc::blk_errors::OUT_OF_BOUNDS);
    }
    let absolute = bound.base_lba.saturating_add(sector);
    if absolute >= rt.capacity
    {
        return Err(ipc::blk_errors::OUT_OF_BOUNDS);
    }
    Ok(absolute)
}

/// Handle a `REGISTER_PARTITION` request.
///
/// Authority: caller's badge must have [`MOUNT_AUTHORITY`] set. Un-
/// badged callers and partition-badged callers are rejected — the
/// latter is already partition-scoped and has no authority to create
/// additional scopes.
///
/// Data words: `[base_lba, length_lba]`. The driver allocates a fresh
/// partition-identity badge from its monotonic counter, inserts the
/// bound, derives a badged `SEND_GRANT` cap on its own service endpoint
/// scoped to that badge, and returns the cap in `caps[0]` of the reply.
/// Server-side derivation is required because [`MOUNT_AUTHORITY`] caps
/// are badged and the kernel rejects re-badging of a badged source —
/// the caller cannot mint partition caps itself.
fn handle_register_partition(msg: &IpcMessage, ipc_buf: *mut u64, rt: &mut BlkRuntime)
{
    let reject = |ipc_buf: *mut u64| {
        let reply = IpcMessage::new(ipc::blk_errors::REGISTER_REJECTED);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    };

    if msg.badge & ipc::blk_labels::MOUNT_AUTHORITY == 0
    {
        reject(ipc_buf);
        return;
    }

    if msg.word_count() < 3
    {
        reject(ipc_buf);
        return;
    }
    if msg.word(0) != u64::from(ipc::BLK_LABELS_VERSION)
    {
        let reply = IpcMessage::new(ipc::blk_errors::LABEL_VERSION_MISMATCH);
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    }
    let base_lba = msg.word(1);
    let length_lba = msg.word(2);

    // Bound must fit inside device capacity.
    let end = base_lba.saturating_add(length_lba);
    if end > rt.capacity || length_lba == 0
    {
        reject(ipc_buf);
        return;
    }

    let new_badge = rt.next_partition_badge;
    // Saturating increment so a (theoretical) wrap collides with the
    // MOUNT_AUTHORITY bit instead of silently aliasing a live partition
    // badge to a verb-bit value.
    if new_badge & ipc::blk_labels::MOUNT_AUTHORITY != 0
    {
        reject(ipc_buf);
        return;
    }
    rt.next_partition_badge = new_badge.saturating_add(1);

    if rt
        .partitions
        .insert(PartitionBound {
            badge: new_badge,
            base_lba,
            length_lba,
        })
        .is_err()
    {
        reject(ipc_buf);
        return;
    }

    let Ok(partition_cap) =
        syscall::cap_derive_badge(rt.service_ep, syscall::RIGHTS_SEND_GRANT, new_badge)
    else
    {
        // Roll back the partition insert so the table doesn't grow a
        // bound the caller has no cap to address.
        rt.partitions.remove(new_badge);
        reject(ipc_buf);
        return;
    };

    let reply = IpcMessage::builder(ipc::blk_errors::SUCCESS)
        .cap(partition_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

// ── Entry point ────────────────────────────────────────────────────────────

fn main() -> !
{
    std::os::seraph::log::register_name(b"virtio-blk");
    let info = startup_info();

    // IPC buffer was registered by `std::os::seraph::_start`; no need to
    // re-register. `info.ipc_buffer` is page-aligned by the boot protocol,
    // so reinterpreting as `*mut u64` satisfies alignment.
    // cast_ptr_alignment: IPC buffer page is 4 KiB-aligned, stricter than u64.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // Bootstrap caps from devmgr. log + procmgr + stdio are wired by
    // `std::os::seraph::_start` from `ProcessInfo`.
    let Some(caps) = bootstrap_caps(info, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    std::os::seraph::log!("starting");
    if caps.bar_mmio_slot == 0
    {
        std::os::seraph::log!("no BAR MMIO cap");
        syscall::thread_exit();
    }
    if caps.memmgr_ep == 0
    {
        std::os::seraph::log!("no procmgr endpoint");
        syscall::thread_exit();
    }

    // Query devmgr for VirtIO PCI capability locations via IPC.
    if caps.devmgr_ep == 0
    {
        std::os::seraph::log!("no devmgr query endpoint");
        syscall::thread_exit();
    }
    let pci_info = query_device_info(caps.devmgr_ep, ipc_buf);

    // Map BAR MMIO. Reservation covers the highest reach across the four
    // VirtIO PCI capability regions (rounded up to whole pages); the BAR
    // mapping lives for the driver process's lifetime.
    let bar_pages = pci_info.bar_aperture_pages();
    let Ok(bar_range) = reserve_pages(bar_pages)
    else
    {
        std::os::seraph::log!("BAR reserve_pages failed");
        syscall::thread_exit();
    };
    let bar_va = bar_range.va_start();
    if !std::os::seraph::fund_aspace_pt_budget(caps.self_aspace, bar_pages)
    {
        std::os::seraph::log!("BAR PT-budget funding failed");
        syscall::thread_exit();
    }
    if syscall::mmio_map(caps.self_aspace, caps.bar_mmio_slot, bar_va, 0).is_err()
    {
        std::os::seraph::log!("BAR mmio_map failed");
        syscall::thread_exit();
    }

    // Create PCI transport and initialise device.
    let transport = PciTransport::new(bar_va, &pci_info);
    let capacity = init_device(&transport);
    std::os::seraph::log!("capacity (sectors)={capacity:#018x}");

    // Set up virtqueue and data buffer.
    let (mut vq, queue_notify_off) = setup_virtqueue(&transport, &caps, ipc_buf);

    // DRIVER_OK.
    transport
        .set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
    std::os::seraph::log!("device ready");

    // Set up IRQ-driven completion: create a notification and bind it to the IRQ.
    if caps.irq_slot == 0
    {
        std::os::seraph::log!("no IRQ cap, cannot operate");
        syscall::thread_exit();
    }
    let Some(irq_notification) = std::os::seraph::object_slab_acquire(120)
        .and_then(|slab| syscall::cap_create_notification(slab).ok())
    else
    {
        std::os::seraph::log!("failed to create IRQ notification");
        syscall::thread_exit();
    };
    if syscall::irq_register(caps.irq_slot, irq_notification).is_err()
    {
        std::os::seraph::log!("irq_register failed");
        syscall::thread_exit();
    }
    // Unmask the interrupt at the controller (IOAPIC/PLIC).
    // irq_register leaves the entry masked; the first irq_ack unmasks it.
    let _ = syscall::irq_ack(caps.irq_slot);
    let irq_cap = caps.irq_slot;

    // Set up I/O buffer (driver-owned page hosting request header at offset
    // 0 and status byte at offset 1024). Data segments live in caller-supplied
    // Memory caps per the BLK_READ_INTO_MEMORY contract, so no driver-side
    // smoke-read is possible without allocating a throwaway memory cap; the fs
    // driver's first BPB read serves as the real first-use sanity check.
    let layout = setup_io_buffer(&caps, ipc_buf);

    // Enter service loop.
    if caps.service_ep == 0
    {
        std::os::seraph::log!("no service endpoint, entering idle loop");
        loop
        {
            let _ = syscall::thread_yield();
        }
    }

    let mut rt = BlkRuntime {
        layout: &layout,
        vq: &mut vq,
        transport: &transport,
        queue_notify_off,
        irq_notification,
        irq_cap,
        service_ep: caps.service_ep,
        partitions: PartitionTable::new(),
        capacity,
        next_partition_badge: 1,
    };
    service_loop(caps.service_ep, ipc_buf, &mut rt);
}
