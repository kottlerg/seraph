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
//! partition registration (`REGISTER_PARTITION`), the device geometry
//! (`BLK_GET_GEOMETRY`), and registered regions (`BLK_REGISTER_REGION`,
//! `BLK_READ_REGION`, `BLK_WRITE_REGION`, `BLK_UNREGISTER_REGION`,
//! `BLK_END_REGIONS`) over IPC.
//! A sweeper thread unregisters the region of a client that holds no
//! liveness cap any more ([`start_sweeper`]).

mod io;

use ipc::serve::{Reply, next_request};
use ipc::{IpcMessage, blk_labels, devmgr_labels, memmgr_errors, memmgr_labels};
use std::os::seraph::{StartupInfo, reserve_pages, startup_info};
use std::time::Instant;
use syscall_abi::PAGE_SIZE;
use virtio_blk::{
    Caller, Geometry, IoOutcome, PartitionTable, Post, Region, RegionAccess, RegionId, RegionTable,
    RequestTiming,
};
use virtio_core::bootstrap::{DeliveredDevice, DeviceInterrupt};
use virtio_core::pci::{ConfigError, PciTransport};
use virtio_core::virtqueue::{self, SplitVirtqueue};
use virtio_core::{
    RegisterLayout, STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FEATURES_OK,
    VirtioPciStartupInfo,
};

use crate::io::IoLayout;

// ── Declaration ────────────────────────────────────────────────────────────

/// The block device's device-specific configuration (`VirtIO` 1.2 § 5.2.4),
/// which the driver reads: its declaration requires the region, and so does
/// the register layout it maps.
const DEVICE_CONFIG: virtio_core::VirtioDeviceConfig = virtio_core::VirtioDeviceConfig::Required;

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
    reset: driver_binding::decl::Reset::VirtioStatus {
        device_config: DEVICE_CONFIG
    },
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
#[expect(
    clippy::cast_possible_truncation,
    reason = "PAGE_SIZE is 4096, which every `usize` holds"
)]
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
    for (range, &offset) in ranges.iter().zip(&placed)
    {
        let Some(range_va) = window_va.checked_add(offset)
        else
        {
            std::os::seraph::log!(error: "BAR range past the address space");
            syscall::thread_exit();
        };
        let range_pages = range.bytes.div_ceil(PAGE_SIZE);
        // SAFETY: `window` is a fresh reservation of `window_pages` pages
        // from the per-process arena, and `place` put this range's pages at
        // `offset` inside its BAR's share of it, overlapping no other
        // range's, so the whole-cap mapping covers VA no Rust object or IPC
        // page occupies. `PciTransport` reaches the BARs only through its raw
        // volatile accessors, never a reference, and the reservation is
        // never returned, so the VA stays reserved for the driver's lifetime
        // (`mmio_map` § Safety).
        let mapped = unsafe {
            std::os::seraph::mmio_map_funded(caps.self_aspace, range.cap, range_va, range_pages)
        };
        if mapped.is_err()
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
    // a region too short for one is refused, never read past, and the 64-bit
    // capacity is read whole or not at all.
    let config = || {
        let blk_size = if features & virtio_blk::VIRTIO_BLK_F_BLK_SIZE == 0
        {
            None
        }
        else
        {
            Some(transport.config_read_u32(virtio_blk::CONFIG_BLK_SIZE_OFFSET)?)
        };
        Ok::<_, ConfigError>((transport.config_read_u64(0)?, blk_size))
    };
    let (capacity, blk_size) = match config()
    {
        Ok(fields) => fields,
        Err(e) =>
        {
            std::os::seraph::log!(error: "device geometry unreadable: {}", e.describe());
            syscall::thread_exit();
        }
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
        std::os::seraph::mem_map_funded(
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
        std::os::seraph::mem_map_funded(
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
    /// segment is mapped for the device for the request's duration, and each
    /// registered region for its registration.
    dma_ep: u64,
    partitions: PartitionTable,
    /// The registered regions, with the capabilities the driver keeps for
    /// each. Only this thread touches it: the sweeper thread hands it each
    /// post as a request ([`start_sweeper`]).
    regions: RegionTable<RegionCaps>,
    /// The event queue every region's liveness binding posts to, which the
    /// sweeper thread waits on.
    sweep_queue: u64,
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
    let mut reply = Reply::new();
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let msg = match unsafe { next_request(service_ep, &mut reply, ipc_buf) }
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
                handle_transfer(&msg, ipc_buf, rt, io::IoDirection::Read, &mut reply);
            }
            blk_labels::BLK_WRITE_FROM_MEMORY =>
            {
                handle_transfer(&msg, ipc_buf, rt, io::IoDirection::Write, &mut reply);
            }
            blk_labels::REGISTER_PARTITION =>
            {
                handle_register_partition(&msg, rt, &mut reply);
            }
            blk_labels::BLK_GET_GEOMETRY =>
            {
                handle_get_geometry(&msg, rt, &mut reply);
            }
            blk_labels::BLK_REGISTER_REGION =>
            {
                handle_register_region(&msg, ipc_buf, rt, &mut reply);
            }
            blk_labels::BLK_READ_REGION =>
            {
                handle_region_transfer(&msg, ipc_buf, rt, io::IoDirection::Read, &mut reply);
            }
            blk_labels::BLK_WRITE_REGION =>
            {
                handle_region_transfer(&msg, ipc_buf, rt, io::IoDirection::Write, &mut reply);
            }
            blk_labels::BLK_UNREGISTER_REGION =>
            {
                handle_unregister_region(&msg, ipc_buf, rt, &mut reply);
            }
            blk_labels::BLK_END_REGIONS =>
            {
                handle_end_regions(&msg, ipc_buf, rt, &mut reply);
            }
            virtio_blk::SWEEP if Caller::of(msg.badge) == Caller::Sweeper =>
            {
                handle_sweep(&msg, ipc_buf, rt, &mut reply);
            }
            _ =>
            {
                drop_caps(msg.caps());
                reply.set_status(ipc::blk_errors::UNKNOWN_OPCODE);
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
/// the caller cannot take (it died, or its `CSpace` is full) deletes it
/// ([`Reply::set_or_delete_caps`]): every reply follows the transfer's
/// completion or the device's acknowledged reset, so the device no longer
/// reaches the frame. A
/// request the device loses (see
/// [`io::submit_and_wait`]) is answered only after [`quiesce_device`] has
/// stopped the device, so the returned cap is free of device DMA
/// ([`run_transfer`]).
fn handle_transfer(
    msg: &IpcMessage,
    ipc_buf: *mut u64,
    rt: &mut BlkRuntime,
    dir: io::IoDirection,
    out: &mut Reply,
)
{
    let mem_cap = msg.caps().first().copied().unwrap_or(0);
    drop_caps(msg.caps().get(1..).unwrap_or(&[]));

    let reply_with = |code: u64, out: &mut Reply| {
        let mut builder = IpcMessage::builder(code);
        if mem_cap != 0
        {
            builder = builder.cap(mem_cap);
        }
        out.set_or_delete_caps(builder.build());
    };

    if rt.device_faulted
    {
        reply_with(ipc::blk_errors::DEVICE_FAULT, out);
        return;
    }
    if mem_cap == 0
    {
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, out);
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
        reply_with(ipc::blk_errors::INVALID_MEMORY_CAP, out);
        return;
    };
    if let Err(code) = validate_memory_cap(mem_cap, dir, data_len)
    {
        reply_with(code, out);
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
            reply_with(code, out);
            return;
        }
    };

    let transfer = Transfer {
        dir,
        sector,
        block_count,
        data_len,
        badge: msg.badge,
    };
    let code = run_transfer(rt, &transfer, mem_cap, ipc_buf);
    reply_with(code, out);
}

/// A checked transfer request: its direction, its first `VirtIO` sector, its
/// length in logical blocks and in bytes, and the client's badge.
struct Transfer
{
    dir: io::IoDirection,
    sector: u64,
    block_count: u64,
    data_len: u32,
    badge: u64,
}

/// Run `transfer` on the data segment `mem_cap`, and return the reply label.
///
/// The data segment is mapped for the device only for this request: from
/// the map here to the unmap, which follows the completion or the quiesce of
/// a lost request. A map that fails is answered `DEVICE_FAULT`. The clock is
/// read at the map, the submission, the completion and the unmap, so a
/// request that took [`virtio_blk::SLOW_REQUEST`] or longer is logged with
/// its [`RequestTiming`] (README § Slow requests).
fn run_transfer(rt: &mut BlkRuntime, transfer: &Transfer, mem_cap: u64, ipc_buf: *mut u64) -> u64
{
    let access = match transfer.dir
    {
        io::IoDirection::Read => virtio_core::dma::DEVICE_READS_WRITES,
        io::IoDirection::Write => virtio_core::dma::DEVICE_READS,
    };
    let map_start = Instant::now();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let data_addr = match unsafe { virtio_core::dma::map(rt.dma_ep, mem_cap, access, ipc_buf) }
    {
        Ok(addr) => addr,
        Err(e) =>
        {
            std::os::seraph::log!(
                warn: "data segment not mapped for the device ({e:?}) after {} ms",
                map_start.elapsed().as_millis()
            );
            return ipc::blk_errors::DEVICE_FAULT;
        }
    };
    let submitted = Instant::now();
    let (outcome, waits) = io::submit_and_wait(
        rt.layout,
        transfer.dir,
        transfer.sector,
        data_addr,
        transfer.data_len,
        rt.vq,
        rt.transport,
        rt.queue_notify_off,
        rt.completion,
    );
    let ended = Instant::now();
    let unmap_start = if outcome == IoOutcome::Lost
    {
        quiesce_device(rt);
        Instant::now()
    }
    else
    {
        ended
    };
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if let Err(e) = unsafe { virtio_core::dma::unmap(rt.dma_ep, data_addr, ipc_buf) }
    {
        std::os::seraph::log!(warn: "data segment not unmapped for the device ({e:?})");
    }
    let timing = RequestTiming {
        map: submitted.duration_since(map_start),
        device: ended.duration_since(submitted),
        unmap: unmap_start.elapsed(),
        waits,
    };
    log_if_slow(transfer, &timing);
    outcome.reply_label()
}

/// Log `transfer` when its `timing` reached [`virtio_blk::SLOW_REQUEST`]
/// (README § Slow requests).
fn log_if_slow(transfer: &Transfer, timing: &RequestTiming)
{
    if timing.is_slow()
    {
        std::os::seraph::log!(
            warn: "slow request: {} of {} blocks at sector {} (badge {:#x}) took {timing}",
            transfer.dir.name(),
            transfer.block_count,
            transfer.sector,
            transfer.badge
        );
    }
}

/// Check the data-segment Memory cap of a transfer of `data_len` bytes;
/// `Err` carries the `blk_errors` code to reply.
///
/// The cap must be a Memory cap of at least `data_len` bytes carrying
/// `MAP|WRITE` for a read (the device writes into it) or `MAP` for a write
/// (the device only reads it).
fn validate_memory_cap(mem_cap: u64, dir: io::IoDirection, data_len: u32) -> Result<(), u64>
{
    let required = match dir
    {
        io::IoDirection::Read => syscall::RIGHTS_MEM_MAP_RW,
        io::IoDirection::Write => syscall::RIGHTS_MEM_MAP,
    };
    let size = memory_cap_size(mem_cap, required)?;
    if size < u64::from(data_len)
    {
        return Err(ipc::blk_errors::INVALID_MEMORY_CAP);
    }
    Ok(())
}

/// The size in bytes of the Memory cap `mem_cap`, checked to carry the
/// `required` rights: `MAP`, and `MAP|WRITE` when the device writes into it;
/// `Err` carries `INVALID_MEMORY_CAP` for any other cap.
fn memory_cap_size(mem_cap: u64, required: u64) -> Result<u64, u64>
{
    let invalid = ipc::blk_errors::INVALID_MEMORY_CAP;
    let tag_rights =
        syscall::cap_info(mem_cap, syscall::CAP_INFO_TAG_RIGHTS).map_err(|_| invalid)?;
    // The tag is the high half whole: a tag word with bits past the tag's
    // `u8` set names no Memory cap, rather than truncating to one.
    let tag = tag_rights >> 32;
    let rights = tag_rights & 0xFFFF_FFFF;
    if tag != u64::from(syscall::CAP_TAG_MEMORY) || (rights & required) != required
    {
        return Err(invalid);
    }
    syscall::cap_info(mem_cap, syscall::CAP_INFO_MEMORY_SIZE).map_err(|_| invalid)
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
fn handle_register_partition(msg: &IpcMessage, rt: &mut BlkRuntime, out: &mut Reply)
{
    // REGISTER_PARTITION takes no cap; one a request carries is deleted.
    drop_caps(msg.caps());
    let reject = |out: &mut Reply| {
        out.set_status(ipc::blk_errors::REGISTER_REJECTED);
    };

    if msg.badge & ipc::blk_labels::MOUNT_AUTHORITY == 0
    {
        reject(out);
        return;
    }

    if msg.word_count() < 3
    {
        reject(out);
        return;
    }
    if msg.word(0) != u64::from(ipc::BLK_LABELS_VERSION)
    {
        out.set_status(ipc::blk_errors::LABEL_VERSION_MISMATCH);
        return;
    }
    let base_lba = msg.word(1);
    let length_lba = msg.word(2);

    // Bound must fit inside device capacity.
    let end = base_lba.saturating_add(length_lba);
    if end > rt.geometry.capacity
    {
        reject(out);
        return;
    }

    let Some(badge) = rt.partitions.register(base_lba, length_lba)
    else
    {
        reject(out);
        return;
    };

    // A failed derivation leaves the range registered: the entry may be one
    // an earlier registration's cap still uses, and a fresh one is reused by
    // the caller's retry, so the table still holds one entry per range.
    let Ok(partition_cap) =
        syscall::cap_derive_badge(rt.service_ep, syscall::RIGHTS_EP_SEND_GRANT, badge)
    else
    {
        reject(out);
        return;
    };

    let reply = IpcMessage::builder(ipc::blk_errors::SUCCESS)
        .cap(partition_cap)
        .build();
    out.set_or_delete_caps(reply);
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
fn handle_get_geometry(msg: &IpcMessage, rt: &BlkRuntime, out: &mut Reply)
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
    out.set(reply);
}

// ── Registered regions ─────────────────────────────────────────────────────

/// What the driver keeps for a registered region: the Memory cap the client
/// sent, from which devmgr's copy for the mapping is derived; the region root,
/// the badged SEND the client's region cap is derived from; and the parent of
/// the region's liveness Notification, whose rights-less child the client
/// holds.
#[derive(Debug, PartialEq, Eq)]
struct RegionCaps
{
    memory: u64,
    root: u64,
    liveness: u64,
}

/// Handle a `BLK_REGISTER_REGION` request (README § Label 6:
/// `BLK_REGISTER_REGION`): register the region the Memory cap in `caps[0]`
/// covers ([`register_region`]) and reply its region cap and its liveness
/// cap. A refused request deletes the Memory cap, of which the client keeps
/// its own copy.
fn handle_register_region(msg: &IpcMessage, ipc_buf: *mut u64, rt: &mut BlkRuntime, out: &mut Reply)
{
    let mem_cap = msg.caps().first().copied().unwrap_or(0);
    drop_caps(msg.caps().get(1..).unwrap_or(&[]));
    match register_region(msg, mem_cap, ipc_buf, rt)
    {
        // A reply the client cannot take deletes both caps; the liveness
        // child's deletion leaves its parent the sole reference, whose post
        // unregisters the region.
        Ok((region_cap, liveness_cap)) => out.set_or_delete_caps(
            IpcMessage::builder(ipc::blk_errors::SUCCESS)
                .cap(region_cap)
                .cap(liveness_cap)
                .build(),
        ),
        Err(code) =>
        {
            drop_caps(&[mem_cap]);
            out.set_status(code);
        }
    }
}

/// Register the region `mem_cap` covers for the caller's partition, and
/// return the client's region cap and liveness cap; `Err` carries the
/// `blk_errors` code to reply.
///
/// The caller is a partition or whole-disk badge, and the access `data[1]`
/// names needs `MAP`, and `MAP|WRITE` when the device writes. The region
/// takes a slot of the [`RegionTable`], is mapped for the device once
/// (`DMA_MAP`), and gets its capabilities ([`region_caps`]); each step that
/// fails undoes the ones before it. The driver keeps `mem_cap` while the
/// region stands.
fn register_region(
    msg: &IpcMessage,
    mem_cap: u64,
    ipc_buf: *mut u64,
    rt: &mut BlkRuntime,
) -> Result<(u64, u64), u64>
{
    if msg.word(0) != u64::from(ipc::BLK_LABELS_VERSION)
    {
        return Err(ipc::blk_errors::LABEL_VERSION_MISMATCH);
    }
    let partition = match Caller::of(msg.badge)
    {
        Caller::WholeDisk(badge) => badge,
        Caller::Partition(badge) if rt.partitions.lookup(badge).is_some() => badge,
        Caller::Partition(_)
        | Caller::Unbadged
        | Caller::Region(_)
        | Caller::Sweeper
        | Caller::Unknown => return Err(ipc::blk_errors::OUT_OF_BOUNDS),
    };
    if rt.device_faulted
    {
        return Err(ipc::blk_errors::DEVICE_FAULT);
    }
    let access = RegionAccess::from_wire(msg.word(1)).ok_or(ipc::blk_errors::INVALID_MEMORY_CAP)?;
    let required = if access.device_writes()
    {
        syscall::RIGHTS_MEM_MAP_RW
    }
    else
    {
        syscall::RIGHTS_MEM_MAP
    };
    let len = memory_cap_size(mem_cap, required)?;
    if len == 0
    {
        return Err(ipc::blk_errors::INVALID_MEMORY_CAP);
    }
    let id = rt
        .regions
        .admit(partition)
        .ok_or(ipc::blk_errors::REGION_LIMIT)?;
    let dma_access = if access.device_writes()
    {
        virtio_core::dma::DEVICE_READS_WRITES
    }
    else
    {
        virtio_core::dma::DEVICE_READS
    };
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let device_addr =
        match unsafe { virtio_core::dma::map(rt.dma_ep, mem_cap, dma_access, ipc_buf) }
        {
            Ok(addr) => addr,
            Err(ipc::DmaError::Refused(
                ipc::devmgr_dma_errors::TOO_MANY_MAPPINGS
                | ipc::devmgr_dma_errors::OUT_OF_RESOURCES,
            )) =>
            {
                return Err(ipc::blk_errors::REGION_LIMIT);
            }
            Err(e) =>
            {
                std::os::seraph::log!(warn: "region not mapped for the device ({e:?})");
                return Err(ipc::blk_errors::DEVICE_FAULT);
            }
        };
    let region = Region {
        partition,
        device_addr,
        len,
        access,
    };
    let Some((kept, region_cap, liveness_cap)) = region_caps(rt, id, mem_cap)
    else
    {
        unmap_region(rt.dma_ep, &region, ipc_buf);
        return Err(ipc::blk_errors::REGION_LIMIT);
    };
    if let Err(kept) = rt.regions.insert(id, region, kept)
    {
        // `admit` found the slot free and nothing has changed the table
        // since; refused all the same, the binding's post finds the slot at
        // another generation and is dropped.
        // The caller deletes `mem_cap` with the refusal.
        drop_caps(&[region_cap, liveness_cap]);
        release_region(
            rt.dma_ep,
            &region,
            &RegionCaps { memory: 0, ..kept },
            ipc_buf,
        );
        return Err(ipc::blk_errors::REGION_LIMIT);
    }
    Ok((region_cap, liveness_cap))
}

/// Make the capabilities of the region `id` names: the region root, a SEND
/// on the service endpoint badged [`RegionId::badge`], and the client's copy
/// of it; and the liveness Notification's parent and its rights-less child,
/// the parent bound to the sweeper's queue with the region's correlator
/// (`SYS_CAP_BIND_SOLE_REFERENCE`) last, so a region whose capabilities exist
/// is always bound. Returns what the driver keeps, with `memory` among it,
/// and the client's two caps; `None`, with every cap made here deleted, when
/// a derivation, the Notification's funding, or the binding fails.
fn region_caps(rt: &BlkRuntime, id: RegionId, memory: u64) -> Option<(RegionCaps, u64, u64)>
{
    let root =
        syscall::cap_derive_badge(rt.service_ep, syscall::RIGHTS_EP_SEND, id.badge()).ok()?;
    let Ok(region_cap) = syscall::cap_derive(root, syscall::RIGHTS_EP_SEND)
    else
    {
        drop_caps(&[root]);
        return None;
    };
    let liveness =
        std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
            syscall::cap_create_notification(slab).ok()
        });
    let Some(liveness) = liveness
    else
    {
        drop_caps(&[region_cap, root]);
        return None;
    };
    // Zero rights: the client's copy can neither signal nor wait; holding it
    // is its only use.
    let child = syscall::cap_derive(liveness, 0).ok();
    let bound = child.is_some()
        && syscall::cap_bind_sole_reference(liveness, rt.sweep_queue, id.correlator()).is_ok();
    let Some(child) = child.filter(|_| bound)
    else
    {
        drop_caps(&[child.unwrap_or(0), liveness, region_cap, root]);
        return None;
    };
    Some((
        RegionCaps {
            memory,
            root,
            liveness,
        },
        region_cap,
        child,
    ))
}

/// Withdraw `region`'s mapping for the device (`DMA_UNMAP`), which replies
/// once the device reaches none of its frames. A failure is logged: devmgr
/// then still holds its copy of the region's Memory cap, so the frames stay
/// out of memmgr's pool.
fn unmap_region(dma_ep: u64, region: &Region, ipc_buf: *mut u64)
{
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if let Err(e) = unsafe { virtio_core::dma::unmap(dma_ep, region.device_addr, ipc_buf) }
    {
        std::os::seraph::log!(warn: "region not unmapped for the device ({e:?})");
    }
}

/// Unregister `region`, which has left the table: unmap it for the device,
/// delete the Memory cap kept for it, and revoke and delete the region root and
/// the liveness parent, so no copy of the client's region cap or liveness cap
/// is left. The revocation of the liveness child is the fall to one reference
/// that the binding of a region its client unregistered posts on.
fn release_region(dma_ep: u64, region: &Region, kept: &RegionCaps, ipc_buf: *mut u64)
{
    unmap_region(dma_ep, region, ipc_buf);
    let _ = syscall::cap_delete(kept.memory);
    let _ = syscall::cap_revoke_all(kept.root);
    let _ = syscall::cap_delete(kept.root);
    let _ = syscall::cap_revoke_all(kept.liveness);
    let _ = syscall::cap_delete(kept.liveness);
}

/// Handle a `BLK_READ_REGION` (`dir` = [`io::IoDirection::Read`]) or
/// `BLK_WRITE_REGION` (`dir` = [`io::IoDirection::Write`]) request on a
/// region cap (README § Label 7: `BLK_READ_REGION`), whose reply carries no
/// cap; one the request carries is deleted.
fn handle_region_transfer(
    msg: &IpcMessage,
    ipc_buf: *mut u64,
    rt: &mut BlkRuntime,
    dir: io::IoDirection,
    out: &mut Reply,
)
{
    drop_caps(msg.caps());
    out.set_status(region_transfer(msg, ipc_buf, rt, dir));
}

/// Run the transfer a region request names, and return the reply label.
///
/// `data[1]` is the LBA within the region's partition, `data[2]` the block
/// count and `data[3]` the byte offset in the region; the run must lie within
/// the partition and within the region ([`Region::span`]), and a read needs a
/// region the device writes. The chain is programmed at the region's device
/// address plus the offset, with no call to devmgr. A request the device
/// loses quiesces it as for any transfer ([`quiesce_device`]); the region
/// stays registered. A slow request's line reports its device time, its map
/// and unmap being 0.
///
/// A region whose kept Memory cap no longer answers `cap_info` is
/// unregistered ([`release_region`]) and the request answered
/// `OUT_OF_BOUNDS`, before the device is programmed: its client revoked the
/// cap it registered, devmgr's copy with it, and memmgr may pool the frames
/// once the client releases them. The window left is the one request in
/// flight, as on the per-transfer path; the check goes once devmgr holds a
/// mapped frame against its lender's revoke
/// (docs/device-management.md § DMA-Safe Teardown).
fn region_transfer(
    msg: &IpcMessage,
    ipc_buf: *mut u64,
    rt: &mut BlkRuntime,
    dir: io::IoDirection,
) -> u64
{
    if msg.word(0) != u64::from(ipc::BLK_LABELS_VERSION)
    {
        return ipc::blk_errors::LABEL_VERSION_MISMATCH;
    }
    let Caller::Region(id) = Caller::of(msg.badge)
    else
    {
        return ipc::blk_errors::OUT_OF_BOUNDS;
    };
    let (Some(region), Some(memory)) = (
        rt.regions.get(id).copied(),
        rt.regions.kept(id).map(|kept| kept.memory),
    )
    else
    {
        return ipc::blk_errors::OUT_OF_BOUNDS;
    };
    if syscall::cap_info(memory, syscall::CAP_INFO_MEMORY_SIZE).is_err()
    {
        if let Some((region, kept)) = rt.regions.remove(id)
        {
            std::os::seraph::log!(warn: "region ended: registered Memory cap revoked");
            release_region(rt.dma_ep, &region, &kept, ipc_buf);
        }
        return ipc::blk_errors::OUT_OF_BOUNDS;
    }
    if rt.device_faulted
    {
        return ipc::blk_errors::DEVICE_FAULT;
    }
    if matches!(dir, io::IoDirection::Read) && !region.access.device_writes()
    {
        return ipc::blk_errors::INVALID_MEMORY_CAP;
    }
    let (lba, block_count, offset) = (msg.word(1), msg.word(2), msg.word(3));
    let Some((data_addr, data_len)) = region.span(rt.geometry, offset, block_count)
    else
    {
        return ipc::blk_errors::INVALID_MEMORY_CAP;
    };
    // The run's first LBA is below the capacity, so its sector fits.
    let sector = resolve_run(region.partition, lba, block_count, rt).and_then(|absolute| {
        rt.geometry
            .device_sector(absolute)
            .ok_or(ipc::blk_errors::OUT_OF_BOUNDS)
    });
    let sector = match sector
    {
        Ok(s) => s,
        Err(code) => return code,
    };
    let transfer = Transfer {
        dir,
        sector,
        block_count,
        data_len,
        badge: msg.badge,
    };
    let submitted = Instant::now();
    let (outcome, waits) = io::submit_and_wait(
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
    let ended = Instant::now();
    if outcome == IoOutcome::Lost
    {
        quiesce_device(rt);
    }
    let timing = RequestTiming {
        map: core::time::Duration::ZERO,
        device: ended.duration_since(submitted),
        unmap: core::time::Duration::ZERO,
        waits,
    };
    log_if_slow(&transfer, &timing);
    outcome.reply_label()
}

/// Handle a `BLK_UNREGISTER_REGION` request on a region cap (README § Label
/// 9: `BLK_UNREGISTER_REGION`): take the region from the table, its slot
/// retiring until its binding's post, and release it ([`release_region`])
/// before the reply, so the device reaches none of its frames once the client
/// has the reply. Served after a lost request too, since the reset device
/// reaches nothing. A badge naming no live region is answered `OUT_OF_BOUNDS`.
fn handle_unregister_region(
    msg: &IpcMessage,
    ipc_buf: *mut u64,
    rt: &mut BlkRuntime,
    out: &mut Reply,
)
{
    drop_caps(msg.caps());
    let code = if msg.word(0) == u64::from(ipc::BLK_LABELS_VERSION)
    {
        let removed = match Caller::of(msg.badge)
        {
            Caller::Region(id) => rt.regions.remove(id),
            Caller::Unbadged
            | Caller::WholeDisk(_)
            | Caller::Partition(_)
            | Caller::Sweeper
            | Caller::Unknown => None,
        };
        if let Some((region, kept)) = removed
        {
            release_region(rt.dma_ep, &region, &kept, ipc_buf);
            ipc::blk_errors::SUCCESS
        }
        else
        {
            ipc::blk_errors::OUT_OF_BOUNDS
        }
    }
    else
    {
        ipc::blk_errors::LABEL_VERSION_MISMATCH
    };
    out.set_status(code);
}

/// Handle a `BLK_END_REGIONS` request on a partition or whole-disk cap
/// (README § Label 10: `BLK_END_REGIONS`): unregister every live region
/// registered through the caller's badge ([`RegionTable::remove_one_of`]),
/// each as `BLK_UNREGISTER_REGION` would ([`release_region`]), before the
/// reply. A partition cap's granter sends it after revoking the caps derived
/// from its own, so no holder it cut off keeps a region. Served after a lost
/// request too, since the reset device reaches nothing.
fn handle_end_regions(msg: &IpcMessage, ipc_buf: *mut u64, rt: &mut BlkRuntime, out: &mut Reply)
{
    drop_caps(msg.caps());
    let code = if msg.word(0) == u64::from(ipc::BLK_LABELS_VERSION)
    {
        match Caller::of(msg.badge)
        {
            Caller::WholeDisk(badge) | Caller::Partition(badge) =>
            {
                while let Some((region, kept)) = rt.regions.remove_one_of(badge)
                {
                    release_region(rt.dma_ep, &region, &kept, ipc_buf);
                }
                ipc::blk_errors::SUCCESS
            }
            Caller::Unbadged | Caller::Region(_) | Caller::Sweeper | Caller::Unknown =>
            {
                ipc::blk_errors::OUT_OF_BOUNDS
            }
        }
    }
    else
    {
        ipc::blk_errors::LABEL_VERSION_MISMATCH
    };
    out.set_status(code);
}

/// Handle the sweeper's [`virtio_blk::SWEEP`] request: apply the
/// sole-reference post whose correlator `data[0]` carries
/// ([`RegionTable::post`]). A live region's post means its client holds no
/// liveness cap any more, its process gone or its cap deleted, so the region
/// is released ([`release_region`]); a retiring slot is freed; a stale post
/// is dropped.
fn handle_sweep(msg: &IpcMessage, ipc_buf: *mut u64, rt: &mut BlkRuntime, out: &mut Reply)
{
    drop_caps(msg.caps());
    if let Post::Ended(region, kept) = rt.regions.post(msg.word(0))
    {
        release_region(rt.dma_ep, &region, &kept, ipc_buf);
    }
    out.set_status(ipc::blk_errors::SUCCESS);
}

/// Create the event queue every region's liveness binding posts to, and start
/// the sweeper thread, which waits on it and hands each post to the service
/// loop as a [`virtio_blk::SWEEP`] request on a SEND of its own, badged
/// [`virtio_blk::SWEEPER_BADGE`], so every change to the region table is made
/// on the service loop's thread and no lock is held across a device wait or a
/// call to devmgr. The queue holds [`virtio_blk::MAX_REGIONS`] entries and
/// observer nodes: each slot has at most one binding awaiting its post
/// ([`RegionTable`]), so neither runs out. Returns the queue; exits when the
/// queue, the SEND or the thread cannot be made, since a region would then
/// outlive its client.
fn start_sweeper(service_ep: u64) -> u64
{
    #[expect(
        clippy::cast_possible_truncation,
        reason = "MAX_REGIONS is 32, which every `u32` holds"
    )]
    const SLOTS: u32 = virtio_blk::MAX_REGIONS as u32;
    let queue = std::os::seraph::object_slab_retype(
        std::os::seraph::event_queue_retype_bytes(u64::from(SLOTS), u64::from(SLOTS)),
        |slab| syscall::event_queue_create_observed(slab, SLOTS, SLOTS).ok(),
    );
    let Some(queue) = queue
    else
    {
        std::os::seraph::log!(error: "failed to create the region sweep queue");
        syscall::thread_exit();
    };
    let Ok(sweep_ep) = syscall::cap_derive_badge(
        service_ep,
        syscall::RIGHTS_EP_SEND,
        virtio_blk::SWEEPER_BADGE,
    )
    else
    {
        std::os::seraph::log!(error: "failed to derive the region sweeper's endpoint cap");
        syscall::thread_exit();
    };
    let started = std::thread::Builder::new()
        .name("blk-sweep".into())
        .spawn(move || sweep(queue, sweep_ep));
    if started.is_err()
    {
        std::os::seraph::log!(error: "failed to start the region sweeper thread");
        syscall::thread_exit();
    }
    queue
}

/// The sweeper thread ([`start_sweeper`]): receive each post and forward its
/// correlator to the service loop, which replies once it has applied it. An
/// interrupted wait is retried. Any other failure of the wait ends the thread
/// with an error line: the regions registered then stay until their clients
/// unregister them.
fn sweep(queue: u64, sweep_ep: u64)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    loop
    {
        match syscall::event_recv_entry(queue, 0)
        {
            Ok(entry) =>
            {
                let request = IpcMessage::builder(virtio_blk::SWEEP)
                    .word(0, entry.tag)
                    .build();
                // SAFETY: ipc_buf is this thread's IPC buffer page, which the
                // runtime's thread start registered.
                if let Err(e) = unsafe { ipc::ipc_call(sweep_ep, &request, ipc_buf) }
                {
                    std::os::seraph::log!(warn: "region post {:#x} not delivered (err={e})", entry.tag);
                }
            }
            Err(e) if e == syscall_abi::SyscallError::Interrupted as i64 =>
            {}
            Err(e) =>
            {
                std::os::seraph::log!(error: "region sweep queue wait failed (err={e}); sweeper exiting");
                return;
            }
        }
    }
}

// ── Entry point ────────────────────────────────────────────────────────────

/// Bind the device's `interrupt` to a new notification and start the
/// interrupt-service thread over it, with a copy of the register window at
/// `window_va` laid out as `layout` says; returns the completion notification
/// the thread signals. Exits on any failure, since the driver cannot wait for
/// its device without it.
fn start_interrupts(interrupt: DeviceInterrupt, window_va: u64, layout: &RegisterLayout) -> u64
{
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
        PciTransport::new(window_va, layout),
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
    completion
}

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

/// Declare this driver on the core path before it serves
/// (`procmgr_labels::DECLARE_NO_CORE`): a core of a block driver would be
/// written through it, so the crash service must write none. A refusal
/// leaves its core to the crash service's dump bound.
fn declare_no_core(procmgr: u64, ipc_buf: *mut u64)
{
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe {
        ipc::ipc_call(
            procmgr,
            &ipc::IpcMessage::new(ipc::procmgr_labels::DECLARE_NO_CORE),
            ipc_buf,
        )
    };
}

fn main() -> !
{
    std::os::seraph::log::register_name(b"virtio-blk");
    let info = startup_info();

    // IPC buffer was registered by `std::os::seraph::_start`; no need to
    // re-register. `info.ipc_buffer` is page-aligned by the boot protocol,
    // so reinterpreting as `*mut u64` satisfies alignment.
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned, stricter than u64"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    declare_no_core(info.procmgr_endpoint, ipc_buf);

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
    let Some(layout) = pci_info.register_layout(DEVICE_CONFIG)
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

    // Set up interrupt-driven completion.
    let completion = start_interrupts(interrupt, window_va, &layout);

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

    let sweep_queue = start_sweeper(caps.service_ep);
    let mut rt = BlkRuntime {
        layout: &layout,
        vq: &mut vq,
        transport: &transport,
        queue_notify_off,
        completion,
        service_ep: caps.service_ep,
        dma_ep: caps.dma_ep,
        partitions: PartitionTable::new(),
        regions: RegionTable::new(),
        sweep_queue,
        geometry,
        device_faulted: false,
    };
    report_ready(caps.devmgr_ep, ipc_buf);
    service_loop(caps.service_ep, ipc_buf, &mut rt);
}
