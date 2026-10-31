// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/blk/src/main.rs

//! Seraph `VirtIO` block device driver.
//!
//! Receives BAR MMIO cap, IRQ cap, and `VirtioPciStartupInfo` startup message
//! from devmgr. Initialises the `VirtIO` device via the modern PCI transport,
//! sets up a split virtqueue, and serves block reads
//! (`BLK_READ_INTO_MEMORY`), block writes (`BLK_WRITE_FROM_MEMORY`),
//! partition registration (`REGISTER_PARTITION`), and the device geometry
//! (`BLK_GET_GEOMETRY`) over IPC.

// cast_possible_truncation: userspace targets 64-bit only; u64/usize conversions
// are lossless. u32 casts on capability slot indices are bounded by CSpace capacity.
#![allow(clippy::cast_possible_truncation)]

mod io;

use ipc::{IpcMessage, blk_labels, devmgr_labels, memmgr_errors, memmgr_labels};
use std::os::seraph::{StartupInfo, reserve_pages, startup_info};
use std::time::Instant;
use syscall_abi::PAGE_SIZE;
use virtio_blk::{Geometry, IoOutcome, PartitionTable};
use virtio_core::pci::PciTransport;
use virtio_core::virtqueue::{self, SplitVirtqueue};
use virtio_core::{
    STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FEATURES_OK, VirtioPciStartupInfo,
};

use crate::io::IoLayout;

// ── Constants ──────────────────────────────────────────────────────────────

/// Queue size we request (capped to the device max, which a split ring
/// keeps a power of two).
///
/// The driver keeps one request in flight: the service loop receives one
/// IPC request, submits its three-descriptor chain, waits for that chain's
/// completion, and replies before it receives the next. The request depth is
/// 1 by design, so the queue is sized to one chain (three descriptors,
/// rounded up to the power of two four), and the rings fit one page. Deeper
/// queueing would need replies decoupled from the receive loop, which no
/// client's synchronous `ipc_call` would use.
const QUEUE_SIZE: u16 = 4;

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

/// Reset the device, waiting at most `virtio_core::pci::RESET_TIMEOUT` on
/// the monotonic clock for the reset to be acknowledged.
fn reset_device(transport: &PciTransport) -> bool
{
    let start = Instant::now();
    transport.try_reset(|| start.elapsed())
}

/// Initialise the `VirtIO` device through the standard sequence (`VirtIO` 1.2
/// section 3.1.1): reset, acknowledge, negotiate features, and read the
/// geometry: the capacity, and the logical block size when the device
/// offers `VIRTIO_BLK_F_BLK_SIZE`.
fn init_device(transport: &PciTransport) -> Geometry
{
    if !reset_device(transport)
    {
        std::os::seraph::log!("device reset unacknowledged");
        syscall::thread_exit();
    }
    transport.set_status(STATUS_ACKNOWLEDGE);
    transport.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    let features = transport.negotiate_features(|device_features| {
        // VIRTIO_F_VERSION_1 (bit 32), required for modern devices, and the
        // block-size report when the device offers it.
        device_features & ((1 << 32) | virtio_blk::VIRTIO_BLK_F_BLK_SIZE)
    });
    let Some(features) = features
    else
    {
        std::os::seraph::log!("feature negotiation failed");
        syscall::thread_exit();
    };

    let blk_size = (features & virtio_blk::VIRTIO_BLK_F_BLK_SIZE != 0)
        .then(|| transport.config_read_u32(virtio_blk::CONFIG_BLK_SIZE_OFFSET));
    let Some(geometry) = Geometry::new(transport.config_read_u64(0), blk_size)
    else
    {
        std::os::seraph::log!("unsupported logical block size {blk_size:?}");
        syscall::thread_exit();
    };
    geometry
}

/// Negotiate the virtqueue size against the device maximum and apply it.
/// Exits when the device's queue cannot hold one request's three-descriptor
/// chain, which every request needs.
fn configure_queue_size(transport: &PciTransport) -> u16
{
    transport.queue_select(0);
    let max_size = transport.queue_max_size();
    let queue_size = QUEUE_SIZE.min(max_size);
    if queue_size < 3
    {
        std::os::seraph::log!("device requestq of {queue_size} descriptors holds no request chain");
        syscall::thread_exit();
    }
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
    // SAFETY: `ring_range` is a fresh reservation from the per-process arena,
    // owned here for the mapping's life: VA no Rust object or IPC page
    // occupies.
    let mapped = unsafe {
        syscall::mem_map(
            ring_memory,
            caps.self_aspace,
            ring_va,
            0,
            ring_pages,
            syscall::MAP_WRITABLE,
        )
    };
    if mapped.is_err()
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
    let Some(vq) = vq
    else
    {
        std::os::seraph::log!("device offers no usable requestq (queue size {queue_size})");
        syscall::thread_exit();
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
    // SAFETY: `data_range` is a fresh reservation from the per-process arena,
    // owned here for the mapping's life: VA no Rust object or IPC page
    // occupies.
    let mapped = unsafe {
        syscall::mem_map(
            data_memory,
            caps.self_aspace,
            data_va,
            0,
            1,
            syscall::MAP_WRITABLE,
        )
    };
    if mapped.is_err()
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
    /// Logical block size and capacity; every wire LBA and count is in
    /// these blocks.
    geometry: Geometry,
    /// Set once [`quiesce_device`] has reset the device after a lost
    /// request; every later transfer is answered `DEVICE_FAULT`.
    device_faulted: bool,
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
                handle_transfer(&msg, ipc_buf, rt, io::IoDirection::Read);
            }
            blk_labels::BLK_WRITE_FROM_MEMORY =>
            {
                handle_transfer(&msg, ipc_buf, rt, io::IoDirection::Write);
            }
            blk_labels::REGISTER_PARTITION =>
            {
                handle_register_partition(&msg, ipc_buf, rt);
            }
            blk_labels::BLK_GET_GEOMETRY =>
            {
                handle_get_geometry(&msg, ipc_buf, rt);
            }
            _ =>
            {
                drop_caps(msg.caps());
                let reply = IpcMessage::new(ipc::blk_errors::UNKNOWN_OPCODE);
                // SAFETY: ipc_buf is the registered IPC buffer page.
                let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            }
        }
    }
}

/// Delete every cap in `caps` from the driver's `CSpace`: caps a request
/// carried that its handler neither uses nor returns, which would otherwise
/// accumulate there for the driver's lifetime.
fn drop_caps(caps: &[u32])
{
    for &cap in caps
    {
        let _ = syscall::cap_delete(cap);
    }
}

/// Handle a `BLK_READ_INTO_MEMORY` (`dir` = [`io::IoDirection::Read`]) or
/// `BLK_WRITE_FROM_MEMORY` (`dir` = [`io::IoDirection::Write`]) request.
///
/// `caps[0]` is the data-segment Memory cap: the read target, which needs
/// `MAP|WRITE` rights, or the write source, which needs `MAP`. The device
/// DMAs `data[1]` consecutive logical blocks (default 1) starting at LBA
/// `data[0]` into or out of the cap at offset 0, packed contiguously; the cap
/// must be at least `count * block_size` bytes or the driver rejects with
/// `INVALID_MEMORY_CAP`.
///
/// `caps[1]` and `caps[2]` are reserved IPC-shape slots and remain null
/// pre-IOMMU; the driver does not inspect them, and deletes any cap a
/// request carries past `caps[0]`. Every reply moves the
/// Memory cap back to the caller in `caps[0]`; leaving it in the driver's
/// `CSpace` would leak it. A request the device loses (see
/// [`io::submit_and_wait`]) is answered only after [`quiesce_device`] has
/// stopped the device, so the returned cap is free of device DMA.
fn handle_transfer(msg: &IpcMessage, ipc_buf: *mut u64, rt: &mut BlkRuntime, dir: io::IoDirection)
{
    let mem_cap = msg.caps().first().copied().unwrap_or(0);
    drop_caps(msg.caps().get(1..).unwrap_or(&[]));

    let reply_with = |code: u64, ipc_buf: *mut u64| {
        let mut builder = IpcMessage::builder(code);
        if mem_cap != 0
        {
            builder = builder.cap(mem_cap);
        }
        let reply = builder.build();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    };

    if rt.device_faulted
    {
        reply_with(ipc::blk_errors::DEVICE_FAULT, ipc_buf);
        return;
    }
    if mem_cap == 0
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, ipc_buf);
        return;
    }

    let lba = if msg.word_count() >= 1
    {
        msg.word(0)
    }
    else
    {
        0
    };
    let block_count = if msg.word_count() >= 2
    {
        msg.word(1)
    }
    else
    {
        1
    };
    // VirtIO descriptor length is u32; this also bounds total transfer well
    // below any plausible per-cap ask.
    let Some(data_len) = rt.geometry.transfer_len(block_count)
    else
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, ipc_buf);
        return;
    };
    let phys_base = match validate_memory_cap(mem_cap, dir, data_len)
    {
        Ok(phys_base) => phys_base,
        Err(code) =>
        {
            reply_with(code, ipc_buf);
            return;
        }
    };
    let absolute_lba = match resolve_run(msg.badge, lba, block_count, rt)
    {
        Ok(s) => s,
        Err(code) =>
        {
            reply_with(code, ipc_buf);
            return;
        }
    };

    let outcome = io::submit_and_wait(
        rt.layout,
        dir,
        rt.geometry.device_sector(absolute_lba),
        phys_base,
        data_len,
        rt.vq,
        rt.transport,
        rt.queue_notify_off,
        rt.irq_notification,
        rt.irq_cap,
    );
    if outcome == IoOutcome::Lost
    {
        quiesce_device(rt);
    }
    reply_with(outcome.reply_label(), ipc_buf);
}

/// Check the data-segment Memory cap of a transfer of `data_len` bytes and
/// return its physical base, or the `blk_errors` code to reply.
///
/// The cap must be a Memory cap of at least `data_len` bytes carrying
/// `MAP|WRITE` for a read (the device writes into it) or `MAP` for a write
/// (the device only reads it).
fn validate_memory_cap(mem_cap: u32, dir: io::IoDirection, data_len: u32) -> Result<u64, u64>
{
    let invalid = ipc::blk_errors::INVALID_MEMORY_CAP;
    let tag_rights =
        syscall::cap_info(mem_cap, syscall::CAP_INFO_TAG_RIGHTS).map_err(|_| invalid)?;
    let tag = (tag_rights >> 32) as u8;
    let rights = tag_rights & 0xFFFF_FFFF;
    let required = match dir
    {
        io::IoDirection::Read => syscall::RIGHTS_MEM_MAP_RW,
        io::IoDirection::Write => syscall::RIGHTS_MEM_MAP,
    };
    if u64::from(tag) != u64::from(syscall::CAP_TAG_MEMORY) || (rights & required) != required
    {
        return Err(invalid);
    }
    let size = syscall::cap_info(mem_cap, syscall::CAP_INFO_MEMORY_SIZE).map_err(|_| invalid)?;
    if size < u64::from(data_len)
    {
        return Err(invalid);
    }
    syscall::cap_info(mem_cap, syscall::CAP_INFO_MEMORY_PHYS_BASE).map_err(|_| invalid)
}

/// Resolve the run of `block_count` logical blocks starting at
/// caller-relative `lba` to its absolute starting LBA, checking that the
/// whole run lies within the caller badge's partition or the device:
/// [`resolve_lba`] checks one LBA, so the run's inclusive end is checked too.
fn resolve_run(badge: u64, lba: u64, block_count: u64, rt: &BlkRuntime) -> Result<u64, u64>
{
    let absolute = resolve_lba(badge, lba, rt)?;
    let last_relative = lba.saturating_add(block_count.saturating_sub(1));
    if resolve_lba(badge, last_relative, rt).is_err()
    {
        return Err(ipc::blk_errors::OUT_OF_BOUNDS);
    }
    Ok(absolute)
}

/// Stop the device after it lost a request, so the request's data buffer is
/// free of device DMA before its Memory cap goes back to the caller.
///
/// A reset the device acknowledges ends its access to the virtqueue and the
/// buffers it describes (`VirtIO` 1.2 §2.4.1). The driver then fails stop:
/// `device_faulted` answers every later transfer with `DEVICE_FAULT`, so a
/// client gets an error rather than a call nobody receives. A device that
/// does not acknowledge the reset may still DMA into the buffer, so the
/// driver exits without replying, and the cap dies with its `CSpace` instead
/// of returning to a caller who could reuse the memory.
fn quiesce_device(rt: &mut BlkRuntime)
{
    if !reset_device(rt.transport)
    {
        std::os::seraph::log!("request lost and device reset unacknowledged; exiting");
        syscall::thread_exit();
    }
    std::os::seraph::log!("request lost; device reset, failing all further I/O");
    rt.device_faulted = true;
}

/// Translate a caller-supplied, partition-relative LBA (in logical blocks)
/// into an absolute device LBA, enforcing per-badge partition bounds.
/// Returns a [`blk_errors`] code on rejection.
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
fn resolve_lba(badge: u64, lba: u64, rt: &BlkRuntime) -> Result<u64, u64>
{
    if badge == 0
    {
        return Err(ipc::blk_errors::OUT_OF_BOUNDS);
    }

    if badge & ipc::blk_labels::MOUNT_AUTHORITY != 0
    {
        // MOUNT_AUTHORITY holders read the whole disk directly,
        // bounded only by device capacity.
        if lba >= rt.geometry.capacity
        {
            return Err(ipc::blk_errors::OUT_OF_BOUNDS);
        }
        return Ok(lba);
    }

    let Some(bound) = rt.partitions.lookup(badge)
    else
    {
        return Err(ipc::blk_errors::OUT_OF_BOUNDS);
    };
    if lba >= bound.length_lba
    {
        return Err(ipc::blk_errors::OUT_OF_BOUNDS);
    }
    let absolute = bound.base_lba.saturating_add(lba);
    if absolute >= rt.geometry.capacity
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
/// Data words: `[BLK_LABELS_VERSION, base_lba, length_lba]`, in logical
/// blocks. The driver registers the range in its [`PartitionTable`], which
/// returns the badge of an identical range already registered or a fresh
/// one, derives a badged `SEND_GRANT` cap on its own service endpoint
/// scoped to that badge, and returns the cap in `caps[0]` of the reply.
/// Server-side derivation is required because
/// [`MOUNT_AUTHORITY`] caps are badged and the kernel rejects
/// re-badging of a badged source — the caller cannot mint partition
/// caps itself.
fn handle_register_partition(msg: &IpcMessage, ipc_buf: *mut u64, rt: &mut BlkRuntime)
{
    // REGISTER_PARTITION takes no cap; one a request carries is deleted.
    drop_caps(msg.caps());
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
    if end > rt.geometry.capacity
    {
        reject(ipc_buf);
        return;
    }

    let Some(badge) = rt.partitions.register(base_lba, length_lba)
    else
    {
        reject(ipc_buf);
        return;
    };

    // A failed derivation leaves the range registered: the entry may be one
    // an earlier registration's cap still uses, and a fresh one is reused by
    // the caller's retry, so the table still holds one entry per range.
    let Ok(partition_cap) =
        syscall::cap_derive_badge(rt.service_ep, syscall::RIGHTS_EP_SEND_GRANT, badge)
    else
    {
        reject(ipc_buf);
        return;
    };

    let reply = IpcMessage::builder(ipc::blk_errors::SUCCESS)
        .cap(partition_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Handle a `BLK_GET_GEOMETRY` request: reply the logical block size and
/// the caller's addressable length in blocks, the whole device for a
/// [`MOUNT_AUTHORITY`] badge and the registered range for a partition badge.
///
/// `data[0]` carries the caller's `BLK_LABELS_VERSION`; a mismatch is
/// answered `LABEL_VERSION_MISMATCH`, and a badge naming no range (unbadged,
/// or never registered) `OUT_OF_BOUNDS`. The geometry is fixed for the
/// device's life, so a client reads it once.
///
/// [`MOUNT_AUTHORITY`]: ipc::blk_labels::MOUNT_AUTHORITY
fn handle_get_geometry(msg: &IpcMessage, ipc_buf: *mut u64, rt: &BlkRuntime)
{
    // BLK_GET_GEOMETRY takes no cap; one a request carries is deleted.
    drop_caps(msg.caps());
    let reply = if msg.word(0) == u64::from(ipc::BLK_LABELS_VERSION)
    {
        let length = if msg.badge & ipc::blk_labels::MOUNT_AUTHORITY != 0
        {
            Some(rt.geometry.capacity)
        }
        else
        {
            rt.partitions.lookup(msg.badge).map(|b| b.length_lba)
        };
        match length
        {
            Some(length) => IpcMessage::builder(ipc::blk_errors::SUCCESS)
                .word(0, u64::from(rt.geometry.block_size))
                .word(1, length)
                .build(),
            None => IpcMessage::new(ipc::blk_errors::OUT_OF_BOUNDS),
        }
    }
    else
    {
        IpcMessage::new(ipc::blk_errors::LABEL_VERSION_MISMATCH)
    };
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
        std::os::seraph::log!("no memmgr endpoint");
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
    // SAFETY: `bar_range` is a fresh reservation of `bar_pages` pages from
    // the per-process arena, owned for the driver's lifetime, and devmgr
    // carves the BAR cap to at most the same `bar_aperture_pages`
    // (`find_virtio_bar_cap`), so the whole-region mapping stays inside it:
    // VA no Rust object or IPC page occupies.
    // `PciTransport` reaches the BAR only through its raw volatile accessors,
    // never a reference, and `bar_range` stays held for the driver's
    // lifetime (`mmio_map` § Safety).
    if unsafe { syscall::mmio_map(caps.self_aspace, caps.bar_mmio_slot, bar_va, 0) }.is_err()
    {
        std::os::seraph::log!("BAR mmio_map failed");
        syscall::thread_exit();
    }

    // Create PCI transport and initialise device.
    let transport = PciTransport::new(bar_va, &pci_info);
    let geometry = init_device(&transport);
    std::os::seraph::log!(
        "capacity (blocks)={:#018x} block size={}",
        geometry.capacity,
        geometry.block_size
    );

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
    let Some(irq_notification) =
        std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
            syscall::cap_create_notification(slab).ok()
        })
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
        geometry,
        device_faulted: false,
    };
    service_loop(caps.service_ep, ipc_buf, &mut rt);
}
