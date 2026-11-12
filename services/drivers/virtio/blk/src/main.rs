// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/blk/src/main.rs

//! Seraph `VirtIO` block device driver.
//!
//! Receives the MMIO caps of the BARs the device's register regions name and
//! the device's interrupt (MSI-X vector 0, or the wired line) in the resource
//! list devmgr delivers the driver it binds to the device, by the declaration
//! below, and the `VirtioPciStartupInfo` startup message from devmgr.
//! Initialises the `VirtIO` device via the modern PCI transport,
//! sets up a split virtqueue, and serves block reads
//! (`BLK_READ_INTO_MEMORY`), block writes (`BLK_WRITE_FROM_MEMORY`),
//! partition registration (`REGISTER_PARTITION`), and the device geometry
//! (`BLK_GET_GEOMETRY`) over IPC.

// Staged roll-out of these two lints: docs/coding-standards.md § Clippy.
#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod io;

use ipc::{IpcMessage, blk_labels, devmgr_labels, memmgr_errors, memmgr_labels};
use std::os::seraph::{StartupInfo, reserve_pages, startup_info};
use std::time::Instant;
use syscall_abi::PAGE_SIZE;
use virtio_blk::{Geometry, IoOutcome, PartitionTable};
use virtio_core::bootstrap::{DeliveredDevice, DeviceInterrupt};
use virtio_core::pci::PciTransport;
use virtio_core::virtqueue::{self, SplitVirtqueue};
use virtio_core::{
    RegisterLayout, STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FEATURES_OK,
    VirtioPciStartupInfo,
};

use crate::io::IoLayout;

// ── Declaration ────────────────────────────────────────────────────────────

// What devmgr binds this driver to and how it starts it
// (docs/driver-binding.md § Driver Declarations).
driver_binding::driver_declaration!(driver_binding::decl::Declaration {
    name: "virtio-blk",
    class: Some("block"),
    matches: &[
        driver_binding::decl::Match::PciId {
            vendor: 0x1AF4,
            device: 0x1001
        },
        driver_binding::decl::Match::PciId {
            vendor: 0x1AF4,
            device: 0x1042
        }
    ],
    instance_limit: None,
    // One MSI-X vector for the requestq, the only queue; configuration
    // changes are routed to no vector.
    interrupt: driver_binding::decl::Interrupt {
        need: driver_binding::decl::InterruptNeed::Required,
        msi_vectors: 1
    },
    dma: true,
    dma_width: None,
    phys_access: false,
    reset: driver_binding::decl::Reset::VirtioStatus,
    tier: driver_binding::decl::Tier::Boot,
});

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

/// [`PAGE_SIZE`] as a `usize`, for the byte count of a one-page fill.
// cast_possible_truncation: PAGE_SIZE is 4096, which every `usize` holds.
#[allow(clippy::cast_possible_truncation)]
const PAGE_BYTES: usize = PAGE_SIZE as usize;

// ── Driver caps from bootstrap protocol ────────────────────────────────────
//
// devmgr delivers the resource list `virtio_core::bootstrap` reads: the BAR
// ranges with their BAR indices and offsets, the interrupt (MSI-X vector 0 or
// the wired line with its mode word), then the service endpoint, the
// per-device devmgr query endpoint, and the device's DMA capability. log_ep
// and procmgr_ep arrive via `ProcessInfo`/`StartupInfo`, not through this
// protocol.

struct DriverCaps
{
    /// What devmgr delivered; its BAR ranges are mapped from here.
    bars: DeliveredDevice,
    /// The device's interrupt, `None` when devmgr delivered none.
    interrupt: Option<DeviceInterrupt>,
    memmgr_ep: u64,
    service_ep: u64,
    devmgr_ep: u64,
    /// The device's DMA capability (`driver_binding::resources::SLOT_DMA`),
    /// through which every buffer the device reaches is mapped.
    dma_ep: u64,
    self_aspace: u64,
}

fn bootstrap_caps(info: &StartupInfo, ipc_buf: *mut u64) -> Option<DriverCaps>
{
    let creator = info.creator_endpoint;
    if creator == 0
    {
        return None;
    }

    // SAFETY: `ipc_buf` is the registered IPC buffer for this thread.
    let device = unsafe { DeliveredDevice::receive(creator, ipc_buf) }?;
    if device.dma == 0
    {
        std::os::seraph::log!(error: "no DMA capability delivered");
        return None;
    }

    Some(DriverCaps {
        interrupt: device.interrupt,
        service_ep: device.service,
        memmgr_ep: info.memmgr_endpoint,
        devmgr_ep: device.devmgr_query,
        dma_ep: device.dma,
        self_aspace: info.self_aspace,
        bars: device,
    })
}

/// Map every delivered BAR range into one register window laid out as
/// `layout` says, after checking the ranges are the layout's own
/// ([`RegisterLayout::place`]). Returns the window's virtual address; exits
/// on any failure (the device cannot be driven without its registers).
fn map_register_window(caps: &DriverCaps, layout: &RegisterLayout) -> u64
{
    let ranges = caps.bars.ranges();
    let Some(placed) = layout.place(ranges)
    else
    {
        std::os::seraph::log!(error: "delivered BARs do not match the device's register regions");
        syscall::thread_exit();
    };
    let window_pages = layout.window_pages();
    // The BAR mappings live for the driver process's lifetime; the
    // reservation is intentionally never returned to the arena (the
    // ReservedRange has no Drop impl, so falling out of scope is a no-op).
    let Ok(window) = reserve_pages(window_pages)
    else
    {
        std::os::seraph::log!(error: "BAR reserve_pages failed");
        syscall::thread_exit();
    };
    let window_va = window.va_start();
    if !std::os::seraph::fund_aspace_pt_budget(caps.self_aspace, window_pages)
    {
        std::os::seraph::log!(error: "BAR PT-budget funding failed");
        syscall::thread_exit();
    }
    for (range, &offset) in ranges.iter().zip(&placed)
    {
        let Some(range_va) = window_va.checked_add(offset)
        else
        {
            std::os::seraph::log!(error: "BAR range past the address space");
            syscall::thread_exit();
        };
        // SAFETY: `window` is a fresh reservation of `window_pages` pages
        // from the per-process arena, and `place` put this range's pages at
        // `offset` inside its BAR's share of it, overlapping no other
        // range's, so the whole-cap mapping covers VA no Rust object or IPC
        // page occupies. `PciTransport` reaches the BARs only through its raw
        // volatile accessors, never a reference, and the reservation is
        // never returned, so the VA stays reserved for the driver's lifetime
        // (`mmio_map` § Safety).
        if unsafe { syscall::mmio_map(caps.self_aspace, range.cap, range_va, 0) }.is_err()
        {
            std::os::seraph::log!(error: "BAR mmio_map failed");
            syscall::thread_exit();
        }
    }
    window_va
}

// ── Device info query via devmgr IPC ──────────────────────────────────────

/// Query devmgr for `VirtIO` PCI capability locations via IPC.
///
/// The driver's devmgr endpoint is badged — the badge identifies the
/// device. Devmgr replies in the generic `QUERY_DEVICE_INFO` schema:
/// `word[0]` = kind, `word[1]` = version, `word[2]` = `byte_len`,
/// payload bytes packed into the subsequent data words. The driver
/// verifies kind/version before deserialising.
fn query_device_info(devmgr_ep: u64, ipc_buf: *mut u64) -> VirtioPciStartupInfo
{
    let request = IpcMessage::builder(devmgr_labels::QUERY_DEVICE_INFO)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(devmgr_ep, &request, ipc_buf) })
    else
    {
        std::os::seraph::log!(error: "QUERY_DEVICE_INFO ipc_call failed");
        syscall::thread_exit();
    };
    if reply.label != 0
    {
        std::os::seraph::log!(error: "QUERY_DEVICE_INFO returned error");
        syscall::thread_exit();
    }
    match VirtioPciStartupInfo::from_device_info(reply.words())
    {
        Ok(info) => info,
        Err(e) =>
        {
            std::os::seraph::log!(error: "{}", e.describe());
            syscall::thread_exit();
        }
    }
}

/// Report the device set up to devmgr (`ipc::report_driver_ready` on the
/// devmgr query cap), immediately before the service loop: devmgr serves
/// this driver's service endpoint only after the report. Logs the
/// `ReadyError` and exits when the call fails or devmgr refuses the report,
/// since devmgr then serves no client this driver.
fn report_ready(devmgr_ep: u64, ipc_buf: *mut u64)
{
    // SAFETY: ipc_buf is the registered IPC buffer.
    if let Err(e) = unsafe { ipc::report_driver_ready(devmgr_ep, ipc_buf) }
    {
        std::os::seraph::log!(error: "DRIVER_READY failed ({e:?}); exiting");
        syscall::thread_exit();
    }
}

// ── Memory-cap allocation via memmgr IPC ────────────────────────────────────────

/// Request a single contiguous Memory cap covering `page_count` pages from
/// memmgr. Returns the cap's slot on success. The device reaches the pages
/// only once they are mapped for it ([`virtio_core::dma::map_or_exit`]).
fn request_memory_caps(memmgr_ep: u64, page_count: u64, ipc_buf: *mut u64) -> Option<u64>
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
    reply.caps().first().copied()
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
        std::os::seraph::log!(error: "device reset unacknowledged");
        syscall::thread_exit();
    }
    transport.set_status(STATUS_ACKNOWLEDGE);
    transport.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    let features = transport.negotiate_features(|device_features| {
        // VIRTIO_F_VERSION_1, required for modern devices;
        // VIRTIO_F_ACCESS_PLATFORM, since every address the driver programs
        // is a device address devmgr returned; and the block-size report when
        // the device offers it.
        device_features
            & (virtio_core::VIRTIO_F_VERSION_1
                | virtio_core::VIRTIO_F_ACCESS_PLATFORM
                | virtio_blk::VIRTIO_BLK_F_BLK_SIZE)
    });
    let Some(features) = features
    else
    {
        std::os::seraph::log!(error: "feature negotiation failed");
        syscall::thread_exit();
    };

    // Both fields lie in the device configuration region the device reports;
    // a region too short for one is refused, never read past.
    let config = || {
        let blk_size = if features & virtio_blk::VIRTIO_BLK_F_BLK_SIZE == 0
        {
            None
        }
        else
        {
            Some(transport.config_read_u32(virtio_blk::CONFIG_BLK_SIZE_OFFSET)?)
        };
        Some((transport.config_read_u64(0)?, blk_size))
    };
    let Some((capacity, blk_size)) = config()
    else
    {
        std::os::seraph::log!(error: "device configuration region too short for the geometry");
        syscall::thread_exit();
    };
    let Some(geometry) = Geometry::new(capacity, blk_size)
    else
    {
        std::os::seraph::log!(error: "unsupported logical block size {blk_size:?}");
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
        std::os::seraph::log!(error: "device requestq of {queue_size} descriptors holds no request chain");
        syscall::thread_exit();
    }
    transport.queue_set_size(queue_size);
    queue_size
}

/// Allocate the backing DMA memory for the virtqueue rings, map it into the
/// driver's address space, and map it for the device. Returns
/// `(ring_addr, ring_pages, ring_va)`, `ring_addr` the rings' device address.
fn allocate_and_map_rings(queue_size: u16, caps: &DriverCaps, ipc_buf: *mut u64)
-> (u64, u64, u64)
{
    let ring_pages = virtqueue::ring_pages(queue_size) as u64;
    let Some(ring_memory) = request_memory_caps(caps.memmgr_ep, ring_pages, ipc_buf)
    else
    {
        std::os::seraph::log!(error: "failed to allocate ring memory caps");
        syscall::thread_exit();
    };
    // The ring mapping lives for the driver process's lifetime; the
    // reservation is intentionally never returned to the arena (the
    // ReservedRange has no Drop impl, so falling out of scope is a no-op).
    let Ok(ring_range) = reserve_pages(ring_pages)
    else
    {
        std::os::seraph::log!(error: "ring reserve_pages failed");
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
        std::os::seraph::log!(error: "ring mem_map failed");
        syscall::thread_exit();
    }
    let Some(ring_bytes) = ring_pages
        .checked_mul(PAGE_SIZE)
        .and_then(|bytes| usize::try_from(bytes).ok())
    else
    {
        std::os::seraph::log!(error: "{ring_pages} ring pages past the address width");
        syscall::thread_exit();
    };
    // SAFETY: ring_va is mapped writable, ring_pages * PAGE_SIZE bytes.
    unsafe {
        core::ptr::write_bytes(ring_va as *mut u8, 0, ring_bytes);
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let ring_addr = unsafe {
        virtio_core::dma::map_or_exit(caps.dma_ep, ring_memory, ipc_buf, |e| {
            std::os::seraph::log!(error: "ring memory not mapped for the device ({e:?})");
        })
    };
    (ring_addr, ring_pages, ring_va)
}

/// Write the descriptor/avail/used ring device addresses into the PCI
/// transport, route the queue to the driver's interrupt
/// ([`PciTransport::route_queue`]), and mark the queue ready. Exits when the
/// device refuses the queue's MSI-X vector: it would then signal no
/// completion, and the driver requires one.
fn program_transport_rings(
    transport: &PciTransport,
    queue_size: u16,
    ring_addr: u64,
    interrupt: Option<DeviceInterrupt>,
)
{
    let Some((desc_addr, avail_addr, used_addr)) = virtqueue::ring_addresses(ring_addr, queue_size)
    else
    {
        std::os::seraph::log!(error: "ring device addresses past the address width");
        syscall::thread_exit();
    };

    transport.queue_set_rings(desc_addr, avail_addr, used_addr);
    if !transport.route_queue(interrupt)
    {
        std::os::seraph::log!(error: "device refused the requestq's MSI-X vector");
        syscall::thread_exit();
    }

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
    let (ring_addr, _ring_pages, ring_va) = allocate_and_map_rings(queue_size, caps, ipc_buf);
    program_transport_rings(transport, queue_size, ring_addr, caps.interrupt);

    // Save notification offset for this queue before changing selection.
    let queue_notify_off = transport.queue_notify_off();
    if !transport.doorbell_in_region(queue_notify_off)
    {
        std::os::seraph::log!(error: "queue doorbell outside the notification region");
        syscall::thread_exit();
    }

    let Some((desc_va, avail_va, used_va)) = virtqueue::ring_addresses(ring_va, queue_size)
    else
    {
        std::os::seraph::log!(error: "ring virtual addresses past the address space");
        syscall::thread_exit();
    };

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
        std::os::seraph::log!(error: "device offers no usable requestq (queue size {queue_size})");
        syscall::thread_exit();
    };

    (vq, queue_notify_off)
}

/// Allocate the data buffer page for block I/O, map it into the driver's
/// address space and for the device, and return its `IoLayout`.
fn setup_io_buffer(caps: &DriverCaps, ipc_buf: *mut u64) -> IoLayout
{
    let Some(data_memory) = request_memory_caps(caps.memmgr_ep, 1, ipc_buf)
    else
    {
        std::os::seraph::log!(error: "failed to allocate data memory cap");
        syscall::thread_exit();
    };
    // The data mapping lives for the driver process's lifetime; the
    // reservation falls out of scope as a no-op (ReservedRange has no
    // Drop impl).
    let Ok(data_range) = reserve_pages(1)
    else
    {
        std::os::seraph::log!(error: "data reserve_pages failed");
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
        std::os::seraph::log!(error: "data mem_map failed");
        syscall::thread_exit();
    }

    // Fill data buffer with sentinel pattern (0xAA) to detect untouched regions.
    // SAFETY: data_va is mapped writable, one page.
    unsafe { core::ptr::write_bytes(data_va as *mut u8, 0xAA, PAGE_BYTES) };

    // SAFETY: ipc_buf is the registered IPC buffer page.
    let data_addr = unsafe {
        virtio_core::dma::map_or_exit(caps.dma_ep, data_memory, ipc_buf, |e| {
            std::os::seraph::log!(error: "data page not mapped for the device ({e:?})");
        })
    };
    let Some(layout) = IoLayout::new(data_va, data_addr)
    else
    {
        std::os::seraph::log!(error: "data page addresses past the address width");
        syscall::thread_exit();
    };
    layout
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
    /// Notification the interrupt-service thread signals after each
    /// delivery it acknowledged and each interrupt its timed ISR read finds
    /// ([`start_isr_thread`]); the request path waits on it.
    pub completion: u64,
    /// Un-badged `SEND_GRANT` cap on this driver's service endpoint;
    /// kept so `handle_register_partition` can `cap_derive_badge` per-
    /// partition badged caps from it. The kernel rejects re-badging
    /// of a badged source, so partition cap derivation must happen
    /// here (server-side) and not at the caller (which holds a
    /// MOUNT_AUTHORITY-badged cap).
    pub service_ep: u64,
    /// The device's DMA capability, through which each request's data
    /// segment is mapped for the device for the request's duration.
    dma_ep: u64,
    partitions: PartitionTable,
    /// Logical block size and capacity; every wire LBA and count is in
    /// these blocks.
    geometry: Geometry,
    /// Set once [`quiesce_device`] has reset the device after a lost
    /// request; every later transfer is answered `DEVICE_FAULT`.
    device_faulted: bool,
}

/// Start the interrupt-service thread, which runs
/// [`virtio_core::isr::serve_interrupts`] over `irq_notification`, the
/// notification bound to the device's `interrupt`: it acknowledges every
/// delivery of a wired line at once, a request in flight or not, and signals
/// `completion` for the request path. Returns whether the thread started.
fn start_isr_thread(
    transport: PciTransport,
    interrupt: DeviceInterrupt,
    irq_notification: u64,
    completion: u64,
) -> bool
{
    std::thread::Builder::new()
        .spawn(move || {
            virtio_core::isr::serve_interrupts(
                &transport,
                interrupt,
                irq_notification,
                || {
                    let _ = syscall::notification_send(completion, 1);
                },
                isr_diag,
            )
        })
        .is_ok()
}

/// Diagnostic hook of the interrupt-service loop's `RecvGuard`: one line at
/// the start of a failure streak, one more before the fatal exit.
fn isr_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            std::os::seraph::log!(warn: "interrupt wait failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!(error: "interrupt wait wedged (err={err}); exiting");
        }
    }
}

/// `RecvGuard` diagnostic hook: one line at the start of a failure streak,
/// one more before the fatal exit.
fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            std::os::seraph::log!(warn: "ipc_recv failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!(error: "ipc_recv wedged (err={err}); exiting");
        }
    }
}

/// Handle incoming IPC requests on the service endpoint.
fn service_loop(service_ep: u64, ipc_buf: *mut u64, rt: &mut BlkRuntime) -> !
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
fn drop_caps(caps: &[u64])
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
/// `caps[1]` and `caps[2]` are reserved IPC-shape slots and remain null;
/// the driver does not inspect them, and deletes any cap a request carries
/// past `caps[0]`. The driver maps the data segment for the device itself,
/// for the request's duration (`virtio_core::dma`). Every reply moves the
/// Memory cap back to the caller in `caps[0]`; leaving it in the driver's
/// `CSpace` would leak it and keep the frame out of memmgr's pool, so a reply
/// the caller cannot take (it died, or its `CSpace` is full) deletes it. A
/// request the device loses (see
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
        if unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_err() && mem_cap != 0
        {
            // The caller is gone, or its `CSpace` cannot take the cap, so the
            // cap stayed here. Every reply follows the transfer's completion
            // or the device's acknowledged reset, so the device no longer
            // reaches the frame: drop the reference, which would otherwise
            // keep the frame out of memmgr's pool for the boot.
            let _ = syscall::cap_delete(mem_cap);
        }
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
    if let Err(code) = validate_memory_cap(mem_cap, dir, data_len)
    {
        reply_with(code, ipc_buf);
        return;
    }
    // The run's first LBA is below the capacity, so its sector fits.
    let sector = resolve_run(msg.badge, lba, block_count, rt).and_then(|absolute| {
        rt.geometry
            .device_sector(absolute)
            .ok_or(ipc::blk_errors::OUT_OF_BOUNDS)
    });
    let sector = match sector
    {
        Ok(s) => s,
        Err(code) =>
        {
            reply_with(code, ipc_buf);
            return;
        }
    };

    // The data segment is mapped for the device only for this request: from
    // here to the unmap below, which follows the completion or the quiesce
    // of a lost request.
    let access = match dir
    {
        io::IoDirection::Read => virtio_core::dma::DEVICE_READS_WRITES,
        io::IoDirection::Write => virtio_core::dma::DEVICE_READS,
    };
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let data_addr = match unsafe { virtio_core::dma::map(rt.dma_ep, mem_cap, access, ipc_buf) }
    {
        Ok(addr) => addr,
        Err(e) =>
        {
            std::os::seraph::log!(warn: "data segment not mapped for the device ({e:?})");
            reply_with(ipc::blk_errors::DEVICE_FAULT, ipc_buf);
            return;
        }
    };
    let outcome = io::submit_and_wait(
        rt.layout,
        dir,
        sector,
        data_addr,
        data_len,
        rt.vq,
        rt.transport,
        rt.queue_notify_off,
        rt.completion,
    );
    if outcome == IoOutcome::Lost
    {
        quiesce_device(rt);
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if let Err(e) = unsafe { virtio_core::dma::unmap(rt.dma_ep, data_addr, ipc_buf) }
    {
        std::os::seraph::log!(warn: "data segment not unmapped for the device ({e:?})");
    }
    reply_with(outcome.reply_label(), ipc_buf);
}

/// Check the data-segment Memory cap of a transfer of `data_len` bytes;
/// `Err` carries the `blk_errors` code to reply.
///
/// The cap must be a Memory cap of at least `data_len` bytes carrying
/// `MAP|WRITE` for a read (the device writes into it) or `MAP` for a write
/// (the device only reads it).
fn validate_memory_cap(mem_cap: u64, dir: io::IoDirection, data_len: u32) -> Result<(), u64>
{
    let invalid = ipc::blk_errors::INVALID_MEMORY_CAP;
    let tag_rights =
        syscall::cap_info(mem_cap, syscall::CAP_INFO_TAG_RIGHTS).map_err(|_| invalid)?;
    // The tag is the high half whole: a tag word with bits past the tag's
    // `u8` set names no Memory cap, rather than truncating to one.
    let tag = tag_rights >> 32;
    let rights = tag_rights & 0xFFFF_FFFF;
    let required = match dir
    {
        io::IoDirection::Read => syscall::RIGHTS_MEM_MAP_RW,
        io::IoDirection::Write => syscall::RIGHTS_MEM_MAP,
    };
    if tag != u64::from(syscall::CAP_TAG_MEMORY) || (rights & required) != required
    {
        return Err(invalid);
    }
    let size = syscall::cap_info(mem_cap, syscall::CAP_INFO_MEMORY_SIZE).map_err(|_| invalid)?;
    if size < u64::from(data_len)
    {
        return Err(invalid);
    }
    Ok(())
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
        std::os::seraph::log!(error: "request lost and device reset unacknowledged; exiting");
        syscall::thread_exit();
    }
    std::os::seraph::log!(warn: "request lost; device reset, failing all further I/O");
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

/// Create a notification object; exits, logging `what`, when it cannot be
/// created, since the driver cannot wait for its device without it.
fn create_notification(what: &str) -> u64
{
    let notification =
        std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
            syscall::cap_create_notification(slab).ok()
        });
    let Some(notification) = notification
    else
    {
        std::os::seraph::log!(error: "failed to create the {what}");
        syscall::thread_exit();
    };
    notification
}

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
    if caps.memmgr_ep == 0
    {
        std::os::seraph::log!(error: "no memmgr endpoint");
        syscall::thread_exit();
    }

    // Query devmgr for VirtIO PCI capability locations via IPC.
    if caps.devmgr_ep == 0
    {
        std::os::seraph::log!(error: "no devmgr query endpoint");
        syscall::thread_exit();
    }
    let pci_info = query_device_info(caps.devmgr_ep, ipc_buf);

    // Map every BAR the register regions name into one register window.
    let Some(layout) = pci_info.register_layout()
    else
    {
        std::os::seraph::log!(error: "device presents no complete set of register regions");
        syscall::thread_exit();
    };
    let window_va = map_register_window(&caps, &layout);

    // Create PCI transport and initialise device.
    let transport = PciTransport::new(window_va, &layout);
    let geometry = init_device(&transport);
    let Some(interrupt) = caps.interrupt
    else
    {
        std::os::seraph::log!(error: "no interrupt, cannot operate");
        syscall::thread_exit();
    };
    std::os::seraph::log!("interrupt: {}", interrupt.describe());
    if !transport.route_config(caps.interrupt)
    {
        std::os::seraph::log!(error: "device refused the configuration vector");
        syscall::thread_exit();
    }
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

    // Set up interrupt-driven completion: create a notification and bind it
    // to the interrupt.
    let irq_notification = create_notification("IRQ notification");
    let completion = create_notification("completion notification");
    if syscall::irq_register(interrupt.cap(), irq_notification, interrupt.mode()).is_err()
    {
        std::os::seraph::log!(error: "irq_register failed");
        syscall::thread_exit();
    }
    // The interrupt-service thread acknowledges every delivery of a wired
    // line from here on, a request in flight or not, so this driver never
    // holds a shared line masked. Its transport is a copy over the same
    // register window.
    if !start_isr_thread(
        PciTransport::new(window_va, &layout),
        interrupt,
        irq_notification,
        completion,
    )
    {
        std::os::seraph::log!(error: "failed to start the interrupt-service thread");
        syscall::thread_exit();
    }
    // Unmask a wired line at the controller (I/O APIC / APLIC): irq_register
    // leaves the entry masked, and the first irq_ack unmasks it. An MSI-X
    // target is never masked.
    if let DeviceInterrupt::Wired { cap, .. } = interrupt
    {
        let _ = syscall::irq_ack(cap);
    }

    // Set up I/O buffer (driver-owned page hosting request header at offset
    // 0 and status byte at offset 1024). Data segments live in caller-supplied
    // Memory caps per the BLK_READ_INTO_MEMORY contract, so no driver-side
    // smoke-read is possible without allocating a throwaway memory cap; the fs
    // driver's first BPB read serves as the real first-use sanity check.
    let layout = setup_io_buffer(&caps, ipc_buf);

    // Enter service loop.
    if caps.service_ep == 0
    {
        std::os::seraph::log!(warn: "no service endpoint, entering idle loop");
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
        completion,
        service_ep: caps.service_ep,
        dma_ep: caps.dma_ep,
        partitions: PartitionTable::new(),
        geometry,
        device_faulted: false,
    };
    report_ready(caps.devmgr_ep, ipc_buf);
    service_loop(caps.service_ep, ipc_buf, &mut rt);
}
