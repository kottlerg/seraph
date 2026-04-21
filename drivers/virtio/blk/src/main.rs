// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/virtio/blk/src/main.rs

//! Seraph `VirtIO` block device driver.
//!
//! Receives BAR MMIO cap, IRQ cap, and `VirtioPciStartupInfo` startup message
//! from devmgr. Initialises the `VirtIO` device via the modern PCI transport,
//! sets up a split virtqueue, and serves block read requests over IPC.

// The `seraph` target is not in rustc's recognised-OS list, so `std` is
// `restricted_std`-gated for downstream bins. Every std-built service on
// seraph carries this preamble.
#![feature(restricted_std)]
// cast_possible_truncation: userspace targets 64-bit only; u64/usize conversions
// are lossless. u32 casts on capability slot indices are bounded by CSpace capacity.
#![allow(clippy::cast_possible_truncation)]

mod io;

use ipc::{IpcBuf, blk_labels, devmgr_labels, procmgr_labels};
use std::os::seraph::{StartupInfo, startup_info};
use virtio_core::pci::PciTransport;
use virtio_core::virtqueue::{self, SplitVirtqueue};
use virtio_core::{
    STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FEATURES_OK, VirtioPciStartupInfo,
};

use crate::io::IoLayout;

// ── Constants ──────────────────────────────────────────────────────────────

const PAGE_SIZE: u64 = 0x1000;

/// VA for mapping BAR0 MMIO.
const BAR_MAP_VA: u64 = 0x0000_0001_0000_0000; // 4 GiB

/// VA for mapping virtqueue ring pages (DMA memory).
const RING_MAP_VA: u64 = 0x0000_0001_0001_0000;

/// VA for mapping the data buffer page (DMA memory).
const DATA_MAP_VA: u64 = 0x0000_0001_0010_0000;

/// Queue size we request (must be <= device max).
const QUEUE_SIZE: u16 = 128;

/// Maximum number of tokened partitions this driver can serve concurrently.
///
/// Partition identity is the caller's cap token. vfsd registers one entry
/// per mount; 16 is ample for early boot (typical disk has 1–2 partitions).
const PARTITION_TABLE_SIZE: usize = 16;

/// Per-token partition bound: absolute LBA range the caller is permitted
/// to access. Token 0 is reserved for the un-tokened (whole-disk) endpoint
/// and is never stored here.
#[derive(Clone, Copy)]
struct PartitionBound
{
    token: u64,
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

    /// Return the bound for `token`, or `None` if no entry is registered.
    fn lookup(&self, token: u64) -> Option<PartitionBound>
    {
        if token == 0
        {
            return None;
        }
        for b in self.entries.iter().flatten()
        {
            if b.token == token
            {
                return Some(*b);
            }
        }
        None
    }

    /// Insert a bound. Fails if `token == 0`, a duplicate token exists, or
    /// the table is full.
    fn insert(&mut self, bound: PartitionBound) -> Result<(), ()>
    {
        if bound.token == 0 || bound.length_lba == 0
        {
            return Err(());
        }
        let mut empty_idx: Option<usize> = None;
        for (i, entry) in self.entries.iter().enumerate()
        {
            match entry
            {
                Some(b) if b.token == bound.token => return Err(()),
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
}

// ── Driver caps from bootstrap protocol ────────────────────────────────────
//
// devmgr → virtio-blk bootstrap plan:
// Round 1 (3 caps):
//   caps[0]: BAR MMIO region
//   caps[1]: IRQ line
//   caps[2]: service endpoint (virtio-blk receives on this)
// Round 2 (1 cap):
//   caps[0]: devmgr query endpoint (tokened per-device — for QUERY_DEVICE_INFO)
//
// log_ep and procmgr_ep arrive via `ProcessInfo`/`StartupInfo`, not through
// this protocol.

struct DriverCaps
{
    bar_mmio_slot: u32,
    irq_slot: u32,
    procmgr_ep: u32,
    service_ep: u32,
    devmgr_ep: u32,
    self_aspace: u32,
}

fn bootstrap_caps(info: &StartupInfo, ipc: IpcBuf) -> Option<DriverCaps>
{
    let creator = info.creator_endpoint;
    if creator == 0
    {
        return None;
    }

    let round1 = ipc::bootstrap::request_round(creator, ipc).ok()?;
    if round1.cap_count < 3 || round1.done
    {
        return None;
    }

    let round2 = ipc::bootstrap::request_round(creator, ipc).ok()?;
    if round2.cap_count < 1 || !round2.done
    {
        return None;
    }

    Some(DriverCaps {
        bar_mmio_slot: round1.caps[0],
        irq_slot: round1.caps[1],
        service_ep: round1.caps[2],
        procmgr_ep: info.procmgr_endpoint,
        devmgr_ep: round2.caps[0],
        self_aspace: info.self_aspace,
    })
}

// ── Device info query via devmgr IPC ──────────────────────────────────────

/// Query devmgr for `VirtIO` PCI capability locations via IPC.
///
/// The driver's devmgr endpoint is tokened — the token identifies the device.
fn query_device_info(devmgr_ep: u32, ipc_buf: *mut u64) -> VirtioPciStartupInfo
{
    let Ok((label, _)) = syscall::ipc_call(devmgr_ep, devmgr_labels::QUERY_DEVICE_INFO, 0, &[])
    else
    {
        println!("virtio-blk: QUERY_DEVICE_INFO ipc_call failed");
        syscall::thread_exit();
    };
    if label != 0
    {
        println!("virtio-blk: QUERY_DEVICE_INFO returned error");
        syscall::thread_exit();
    }
    // SAFETY: ipc_buf is the registered IPC buffer; devmgr wrote IPC_WORD_COUNT words.
    unsafe { VirtioPciStartupInfo::read_from_ipc(ipc_buf.cast_const()) }
}

// ── Frame allocation via procmgr IPC ───────────────────────────────────────

/// Request `page_count` frame caps from procmgr. Returns the first cap slot
/// on success.
fn request_frames(procmgr_ep: u32, page_count: u64, ipc_buf: *mut u64) -> Option<u32>
{
    // SAFETY: ipc_buf is the registered IPC buffer page.
    unsafe { ipc::IpcBuf::from_raw(ipc_buf) }.write_word(0, page_count);

    let Ok((label, _)) = syscall::ipc_call(procmgr_ep, procmgr_labels::REQUEST_FRAMES, 1, &[])
    else
    {
        return None;
    };
    if label != 0
    {
        return None;
    }

    // SAFETY: ipc_buf is registered IPC buffer.
    #[allow(clippy::cast_ptr_alignment)]
    let (cap_count, cap_slots) = unsafe { syscall::read_recv_caps(ipc_buf) };
    if (cap_count as u64) < page_count
    {
        return None;
    }
    Some(cap_slots[0])
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
        println!("virtio-blk: feature negotiation failed");
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
/// the driver's address space. Returns the ring physical address and the
/// ring page count.
fn allocate_and_map_rings(queue_size: u16, caps: &DriverCaps, ipc_buf: *mut u64) -> (u64, u64)
{
    let ring_pages = virtqueue::ring_pages(queue_size) as u64;
    let Some(ring_frame) = request_frames(caps.procmgr_ep, ring_pages, ipc_buf)
    else
    {
        println!("virtio-blk: failed to allocate ring frames");
        syscall::thread_exit();
    };
    if syscall::mem_map(
        ring_frame,
        caps.self_aspace,
        RING_MAP_VA,
        0,
        ring_pages,
        syscall::MAP_READONLY | syscall::MAP_WRITABLE,
    )
    .is_err()
    {
        println!("virtio-blk: ring mem_map failed");
        syscall::thread_exit();
    }
    // SAFETY: RING_MAP_VA is mapped writable, ring_pages * PAGE_SIZE bytes.
    unsafe {
        core::ptr::write_bytes(RING_MAP_VA as *mut u8, 0, (ring_pages * PAGE_SIZE) as usize);
    }
    let Ok(ring_phys) = syscall::dma_grant(ring_frame, 0, syscall_abi::FLAG_DMA_UNSAFE)
    else
    {
        println!("virtio-blk: ring dma_grant failed");
        syscall::thread_exit();
    };
    (ring_phys, ring_pages)
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
    let (ring_phys, _ring_pages) = allocate_and_map_rings(queue_size, caps, ipc_buf);
    program_transport_rings(transport, queue_size, ring_phys);

    // Save notification offset for this queue before changing selection.
    let queue_notify_off = transport.queue_notify_off();

    let desc_size = virtqueue::desc_table_size(queue_size);
    let used_off = virtqueue::used_ring_offset(queue_size);
    let desc_va = RING_MAP_VA;
    let avail_va = RING_MAP_VA + desc_size as u64;
    let used_va = RING_MAP_VA + used_off as u64;

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
    let Some(data_frame) = request_frames(caps.procmgr_ep, 1, ipc_buf)
    else
    {
        println!("virtio-blk: failed to allocate data frame");
        syscall::thread_exit();
    };

    if syscall::mem_map(
        data_frame,
        caps.self_aspace,
        DATA_MAP_VA,
        0,
        1,
        syscall::MAP_READONLY | syscall::MAP_WRITABLE,
    )
    .is_err()
    {
        println!("virtio-blk: data mem_map failed");
        syscall::thread_exit();
    }

    // Fill data buffer with sentinel pattern (0xAA) to detect untouched regions.
    // SAFETY: DATA_MAP_VA is mapped writable, one page.
    unsafe { core::ptr::write_bytes(DATA_MAP_VA as *mut u8, 0xAA, PAGE_SIZE as usize) };

    let Ok(data_phys) = syscall::dma_grant(data_frame, 0, syscall_abi::FLAG_DMA_UNSAFE)
    else
    {
        println!("virtio-blk: data dma_grant failed");
        syscall::thread_exit();
    };

    IoLayout {
        data_va: DATA_MAP_VA,
        data_phys,
    }
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
    pub irq_signal: u32,
    pub irq_cap: u32,
    partitions: PartitionTable,
    capacity: u64,
}

/// Handle incoming IPC requests on the service endpoint.
fn service_loop(service_ep: u32, ipc_buf: *mut u64, rt: &mut BlkRuntime) -> !
{
    println!("virtio-blk: ready, entering service loop");
    loop
    {
        let Ok((label, token)) = syscall::ipc_recv(service_ep)
        else
        {
            continue;
        };

        match label
        {
            blk_labels::READ_BLOCK =>
            {
                handle_read_block(token, ipc_buf, rt);
            }
            blk_labels::REGISTER_PARTITION =>
            {
                handle_register_partition(token, ipc_buf, rt);
            }
            _ =>
            {
                let _ = syscall::ipc_reply(ipc::blk_errors::UNKNOWN_OPCODE, 0, &[]);
            }
        }
    }
}

/// Handle a `READ_BLOCK` request.
///
/// Token semantics:
/// - `token == 0`: un-tokened (whole-disk) endpoint, held only by vfsd.
///   The `sector` word is treated as an absolute LBA and bounded by device
///   capacity.
/// - `token != 0`: tokened (partition-scoped) endpoint. The `sector` word
///   is partition-relative; the driver translates to absolute LBA using
///   the registered bound and rejects out-of-range reads.
fn handle_read_block(token: u64, ipc_buf: *mut u64, rt: &mut BlkRuntime)
{
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let sector = unsafe { ipc::IpcBuf::from_raw(ipc_buf) }.read_word(0);

    let absolute_sector = match resolve_sector(token, sector, rt)
    {
        Ok(s) => s,
        Err(code) =>
        {
            let _ = syscall::ipc_reply(code, 0, &[]);
            return;
        }
    };

    if !io::submit_and_wait(
        rt.layout,
        absolute_sector,
        rt.vq,
        rt.transport,
        rt.queue_notify_off,
        rt.irq_signal,
        rt.irq_cap,
    )
    {
        let status = rt.layout.read_status();
        let code = u64::from(status);
        let _ = syscall::ipc_reply(code, 0, &[]);
        return;
    }

    // SAFETY: ipc_buf is the registered IPC buffer with at least 64 writable words.
    unsafe { rt.layout.copy_sector_to_ipc(ipc_buf) };
    let _ = syscall::ipc_reply(ipc::blk_errors::SUCCESS, 64, &[]);
}

/// Translate a caller-supplied sector number into an absolute device LBA,
/// enforcing per-token partition bounds. Returns a [`blk_errors`] code on
/// rejection.
fn resolve_sector(token: u64, sector: u64, rt: &BlkRuntime) -> Result<u64, u64>
{
    if token == 0
    {
        // Whole-disk endpoint: only device capacity bounds the read.
        if sector >= rt.capacity
        {
            return Err(ipc::blk_errors::OUT_OF_BOUNDS);
        }
        return Ok(sector);
    }

    let Some(bound) = rt.partitions.lookup(token)
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
/// Authority: only the un-tokened (whole-disk) endpoint holder may register
/// partitions. A tokened caller is rejected — it is already partition-scoped
/// and has no authority to create additional scopes.
///
/// Data words: `[token, base_lba, length_lba]`. The registered bound must
/// lie within device capacity; a zero token or zero length is rejected.
fn handle_register_partition(caller_token: u64, ipc_buf: *mut u64, rt: &mut BlkRuntime)
{
    if caller_token != 0
    {
        let _ = syscall::ipc_reply(ipc::blk_errors::REGISTER_REJECTED, 0, &[]);
        return;
    }

    // SAFETY: ipc_buf is the registered IPC buffer page.
    let buf = unsafe { ipc::IpcBuf::from_raw(ipc_buf) };
    let new_token = buf.read_word(0);
    let base_lba = buf.read_word(1);
    let length_lba = buf.read_word(2);

    // Bound must fit inside device capacity.
    let end = base_lba.saturating_add(length_lba);
    if end > rt.capacity || length_lba == 0 || new_token == 0
    {
        let _ = syscall::ipc_reply(ipc::blk_errors::REGISTER_REJECTED, 0, &[]);
        return;
    }

    if rt
        .partitions
        .insert(PartitionBound {
            token: new_token,
            base_lba,
            length_lba,
        })
        .is_err()
    {
        let _ = syscall::ipc_reply(ipc::blk_errors::REGISTER_REJECTED, 0, &[]);
        return;
    }

    let _ = syscall::ipc_reply(ipc::blk_errors::SUCCESS, 0, &[]);
}

// ── Entry point ────────────────────────────────────────────────────────────

fn main() -> !
{
    let info = startup_info();

    // IPC buffer was registered by `std::os::seraph::_start`; no need to
    // re-register. Build a typed view over the same page for local use.
    // SAFETY: IPC buffer is registered by `_start` and page-aligned by the
    // boot protocol.
    let ipc = unsafe { IpcBuf::from_bytes(info.ipc_buffer) };
    let ipc_buf = ipc.as_ptr();

    // Bootstrap caps from devmgr. log + procmgr + stdio are wired by
    // `std::os::seraph::_start` from `ProcessInfo`.
    let Some(caps) = bootstrap_caps(info, ipc)
    else
    {
        syscall::thread_exit();
    };

    println!("virtio-blk: starting");
    if caps.bar_mmio_slot == 0
    {
        println!("virtio-blk: no BAR MMIO cap");
        syscall::thread_exit();
    }
    if caps.procmgr_ep == 0
    {
        println!("virtio-blk: no procmgr endpoint");
        syscall::thread_exit();
    }

    // Query devmgr for VirtIO PCI capability locations via IPC.
    if caps.devmgr_ep == 0
    {
        println!("virtio-blk: no devmgr query endpoint");
        syscall::thread_exit();
    }
    let pci_info = query_device_info(caps.devmgr_ep, ipc_buf);

    // Map BAR MMIO.
    if syscall::mmio_map(caps.self_aspace, caps.bar_mmio_slot, BAR_MAP_VA, 0).is_err()
    {
        println!("virtio-blk: BAR mmio_map failed");
        syscall::thread_exit();
    }

    // Create PCI transport and initialise device.
    let transport = PciTransport::new(BAR_MAP_VA, &pci_info);
    let capacity = init_device(&transport);
    println!("virtio-blk: capacity (sectors)={capacity:#018x}");

    // Set up virtqueue and data buffer.
    let (mut vq, queue_notify_off) = setup_virtqueue(&transport, &caps, ipc_buf);

    // DRIVER_OK.
    transport
        .set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
    println!("virtio-blk: device ready");

    // Set up IRQ-driven completion: create a signal and bind it to the IRQ.
    if caps.irq_slot == 0
    {
        println!("virtio-blk: no IRQ cap, cannot operate");
        syscall::thread_exit();
    }
    let Ok(irq_signal) = syscall::cap_create_signal()
    else
    {
        println!("virtio-blk: failed to create IRQ signal");
        syscall::thread_exit();
    };
    if syscall::irq_register(caps.irq_slot, irq_signal).is_err()
    {
        println!("virtio-blk: irq_register failed");
        syscall::thread_exit();
    }
    // Unmask the interrupt at the controller (IOAPIC/PLIC).
    // irq_register leaves the entry masked; the first irq_ack unmasks it.
    let _ = syscall::irq_ack(caps.irq_slot);
    let irq_cap = caps.irq_slot;

    // Set up I/O buffer and test-read sector 0.
    let layout = setup_io_buffer(&caps, ipc_buf);

    if !io::submit_and_wait(
        &layout,
        0,
        &mut vq,
        &transport,
        queue_notify_off,
        irq_signal,
        irq_cap,
    )
    {
        println!("virtio-blk: sector 0 test read failed");
        syscall::thread_exit();
    }
    println!("virtio-blk: sector 0 read OK");

    // Enter service loop.
    if caps.service_ep == 0
    {
        println!("virtio-blk: no service endpoint, entering idle loop");
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
        irq_signal,
        irq_cap,
        partitions: PartitionTable::new(),
        capacity,
    };
    service_loop(caps.service_ep, ipc_buf, &mut rt);
}
