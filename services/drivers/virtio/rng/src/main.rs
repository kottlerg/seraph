// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/rng/src/main.rs

//! Seraph `VirtIO` entropy device (virtio-rng) driver.
//!
//! Receives the MMIO caps of the BARs the device's register regions name, an
//! optional interrupt (MSI-X vector 0, or the wired line), and the
//! `VirtioPciStartupInfo` startup message from devmgr, the same PCI bring-up
//! path as the sibling drivers. Initialises the device through the modern PCI
//! transport, sets up its one request virtqueue (`VirtIO` 1.2 § 5.4.2), and
//! serves the `hwrng` class protocol ([`hwrng_protocol`]): each
//! [`hwrng_protocol::READ`] posts one device-writable buffer and answers with
//! the bytes the device wrote into it.
//!
//! The driver holds the device's capabilities and nothing more: no kernel
//! authority. A consumer of the class decides what the bytes are for.

use hwrng_protocol::{MAX_READ_BYTES, errors as hwrng_errors};
use ipc::{IpcMessage, devmgr_labels, memmgr_errors, memmgr_labels};
use std::os::seraph::{StartupInfo, reserve_pages, startup_info};
use std::time::{Duration, Instant};
use syscall_abi::{MSG_DATA_WORDS_MAX, PAGE_SIZE};
use virtio_core::bootstrap::{DeliveredDevice, DeviceInterrupt};
use virtio_core::pci::PciTransport;
use virtio_core::virtqueue::{self, SplitVirtqueue};
use virtio_core::{
    RegisterLayout, STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FEATURES_OK,
    VirtioPciStartupInfo,
};

// ── Declaration ────────────────────────────────────────────────────────────

/// The entropy device has no device-specific configuration (`VirtIO` 1.2
/// § 5.4.4): its declaration says the region is absent, and so does the
/// register layout it maps.
const DEVICE_CONFIG: virtio_core::VirtioDeviceConfig = virtio_core::VirtioDeviceConfig::Absent;

// What devmgr binds this driver to and how it starts it
// (docs/driver-binding.md § Driver Declarations).
driver_binding::driver_declaration!(driver_binding::decl::Declaration {
    name: "virtio-rng",
    class: Some("hwrng"),
    matches: &[
        // The transitional and the modern entropy device (VirtIO 1.2 § 4.1.2).
        driver_binding::decl::Match::PciId {
            vendor: 0x1AF4,
            device: 0x1005
        },
        driver_binding::decl::Match::PciId {
            vendor: 0x1AF4,
            device: 0x1044
        }
    ],
    instance_limit: None,
    // One MSI-X vector for the requestq, the only queue; configuration
    // changes are routed to no vector.
    interrupt: driver_binding::decl::Interrupt {
        need: driver_binding::decl::InterruptNeed::Optional,
        msi_vectors: 1
    },
    dma: true,
    dma_width: None,
    phys_access: false,
    reset: driver_binding::decl::Reset::VirtioStatus {
        device_config: DEVICE_CONFIG
    },
    tier: driver_binding::decl::Tier::Auxiliary,
});

// ── Constants ──────────────────────────────────────────────────────────────

/// Descriptors the driver asks the requestq for: one, since a read keeps at
/// most one buffer posted. A queue size is a power of two, and 1 is one.
const REQUEST_QUEUE_SIZE: u16 = 1;

/// How long a read waits for the device to fill its buffer before it answers
/// `NOT_READY`, leaving the buffer posted for the next read. QEMU's device
/// answers in microseconds; a host that rate-limits its device can take
/// longer, and the caller asks again. A bound on one caller's wait, not on a
/// capacity.
const READ_WAIT: Duration = Duration::from_millis(1_000);

/// Per-iteration timeout of a read's wait, in milliseconds. With an interrupt
/// bound, the interrupt-service thread signals `wake` as the device
/// completes; the bounded timeout also re-polls the used ring every tick, so
/// a read completes whether or not an interrupt is available.
const POLL_INTERVAL_MS: u64 = 10;

/// [`PAGE_SIZE`] as a `usize`, for the byte count of a one-page fill.
#[expect(
    clippy::cast_possible_truncation,
    reason = "PAGE_SIZE is 4096, which every `usize` holds"
)]
const PAGE_BYTES: usize = PAGE_SIZE as usize;

// One page holds the request buffer: a read never posts more than it holds.
const _: () = assert!(MAX_READ_BYTES <= PAGE_BYTES);

// ── Driver caps from bootstrap protocol ────────────────────────────────────
//
// devmgr delivers the resource list `virtio_core::bootstrap` reads, as for
// virtio-blk and virtio-input: the BAR ranges with their BAR indices and
// offsets, the interrupt (MSI-X vector 0 or the wired line with its mode
// word; absent when devmgr could give the device none), then the service
// endpoint, the per-device devmgr query endpoint, and the device's DMA
// capability. log_ep and procmgr_ep arrive via `ProcessInfo`/`StartupInfo`.

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
    /// through which the rings and the request buffer are mapped for the
    /// device.
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

/// Query devmgr for `VirtIO` PCI capability locations: the generic
/// `QUERY_DEVICE_INFO` schema every `VirtIO` driver reads; the badge
/// identifies the device.
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

// ── Memory-cap allocation via memmgr IPC ────────────────────────────────────

/// Request a single contiguous Memory cap covering `page_count` pages from
/// memmgr. Returns the cap's slot. The device reaches the pages only once
/// they are mapped for it ([`virtio_core::dma::map_or_exit`]).
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

/// Allocate `pages` zeroed pages, map them writable into the driver's
/// address space and for the device. Returns `(device_addr, va)`; exits on
/// any failure, naming `what` the pages are for.
fn allocate_dma_pages(caps: &DriverCaps, pages: u64, what: &str, ipc_buf: *mut u64) -> (u64, u64)
{
    let Some(memory) = request_memory_caps(caps.memmgr_ep, pages, ipc_buf)
    else
    {
        std::os::seraph::log!(error: "failed to allocate {what} memory");
        syscall::thread_exit();
    };
    let Ok(range) = reserve_pages(pages)
    else
    {
        std::os::seraph::log!(error: "{what} reserve_pages failed");
        syscall::thread_exit();
    };
    let va = range.va_start();
    // SAFETY: `range` is a fresh reservation from the per-process arena,
    // owned here for the mapping's life: VA no Rust object or IPC page
    // occupies.
    let mapped = unsafe {
        std::os::seraph::mem_map_funded(
            memory,
            caps.self_aspace,
            va,
            0,
            pages,
            syscall::MAP_WRITABLE,
        )
    };
    if mapped.is_err()
    {
        std::os::seraph::log!(error: "{what} mem_map failed");
        syscall::thread_exit();
    }
    let Some(bytes) = pages
        .checked_mul(PAGE_SIZE)
        .and_then(|bytes| usize::try_from(bytes).ok())
    else
    {
        std::os::seraph::log!(error: "{pages} {what} pages past the address width");
        syscall::thread_exit();
    };
    // SAFETY: `va` is mapped writable for `pages` pages, `bytes` bytes.
    unsafe {
        core::ptr::write_bytes(va as *mut u8, 0, bytes);
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let addr = unsafe {
        virtio_core::dma::map_or_exit(caps.dma_ep, memory, ipc_buf, |e| {
            std::os::seraph::log!(error: "{what} memory not mapped for the device ({e:?})");
        })
    };
    (addr, va)
}

// ── Device + virtqueue setup ────────────────────────────────────────────────

/// Initialise the device through the standard sequence (`VirtIO` 1.2 §3.1.1):
/// reset, acknowledge, negotiate features. The entropy device defines no
/// feature bits (`VirtIO` 1.2 § 5.4.3); the driver accepts
/// `VIRTIO_F_VERSION_1` and `VIRTIO_F_ACCESS_PLATFORM`, since it programs
/// only device addresses.
fn init_device(transport: &PciTransport)
{
    // The reset wait is bounded on the monotonic clock
    // (`virtio_core::pci::RESET_TIMEOUT`).
    let start = Instant::now();
    if !transport.try_reset(|| start.elapsed())
    {
        std::os::seraph::log!(error: "device reset unacknowledged");
        syscall::thread_exit();
    }
    transport.set_status(STATUS_ACKNOWLEDGE);
    transport.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    if transport
        .negotiate_features(|device_features| {
            device_features
                & (virtio_core::VIRTIO_F_VERSION_1 | virtio_core::VIRTIO_F_ACCESS_PLATFORM)
        })
        .is_none()
    {
        std::os::seraph::log!(error: "feature negotiation failed");
        syscall::thread_exit();
    }
}

/// Set up the requestq (queue 0): size it, allocate and map its rings,
/// program the device with the queue routed to `interrupt`, and build its
/// `SplitVirtqueue`. Returns the queue, its doorbell offset, and the
/// interrupt the queue signals: `interrupt`, or `None` when the device
/// refuses the queue's MSI-X vector, which leaves reads polling.
fn setup_virtqueue(
    transport: &PciTransport,
    caps: &DriverCaps,
    interrupt: Option<DeviceInterrupt>,
    ipc_buf: *mut u64,
) -> (SplitVirtqueue, u16, Option<DeviceInterrupt>)
{
    transport.queue_select(0);
    let queue_size = REQUEST_QUEUE_SIZE.min(transport.queue_max_size());
    transport.queue_set_size(queue_size);

    let ring_pages = virtqueue::ring_pages(queue_size) as u64;
    let (ring_addr, ring_va) = allocate_dma_pages(caps, ring_pages, "ring", ipc_buf);
    let (Some((desc_addr, avail_addr, used_addr)), Some((desc_va, avail_va, used_va))) = (
        virtqueue::ring_addresses(ring_addr, queue_size),
        virtqueue::ring_addresses(ring_va, queue_size),
    )
    else
    {
        std::os::seraph::log!(error: "ring addresses past the address width");
        syscall::thread_exit();
    };
    transport.queue_set_rings(desc_addr, avail_addr, used_addr);
    let routed = transport.route_queue(interrupt);
    if !routed
    {
        std::os::seraph::log!(warn: "device refused the requestq's MSI-X vector");
    }
    transport.queue_set_ready(1);

    let queue_notify_off = transport.queue_notify_off();
    if !transport.doorbell_in_region(queue_notify_off)
    {
        std::os::seraph::log!(error: "queue doorbell outside the notification region");
        syscall::thread_exit();
    }

    // SAFETY: ring memory is zeroed, sized by `ring_pages` for `queue_size`,
    // and exclusively owned; `ring_addresses` keeps each region naturally
    // aligned (the layout the sibling drivers rely on).
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
    (vq, queue_notify_off, interrupt.filter(|_| routed))
}

// ── Service loop ───────────────────────────────────────────────────────────

/// Long-lived driver runtime: the requestq, transport, the read path's
/// notification, the request buffer, and the length of the buffer posted
/// and not yet completed.
struct RngRuntime
{
    vq: SplitVirtqueue,
    transport: PciTransport,
    queue_notify_off: u16,
    /// Notification a read waits on: signalled by the interrupt-service
    /// thread after each delivery it acknowledged and each interrupt its
    /// timed ISR read finds ([`start_interrupts`]), never signalled when no
    /// IRQ is bound, in which case the bounded wait is a timed poll.
    wake: u64,
    /// Virtual address and device address of the request buffer page, which
    /// holds [`MAX_READ_BYTES`] bytes.
    buf_va: u64,
    buf_addr: u64,
    /// The length of the buffer posted to the device and not yet completed:
    /// `Some` after a read that timed out, whose buffer the next read waits
    /// for rather than posting another.
    posted: Option<u32>,
}

impl RngRuntime
{
    /// Post the request buffer for a read of `asked` bytes unless one is
    /// already posted, and tell the device. `false` when the queue takes no
    /// buffer, which a queue of one free descriptor always does.
    fn post(&mut self, asked: usize) -> bool
    {
        if self.posted.is_some()
        {
            return true;
        }
        let len = virtio_rng::post_len(asked);
        if self.vq.add_chain(&[(self.buf_addr, len, true)]).is_none()
        {
            return false;
        }
        self.posted = Some(len);
        self.transport.notify(0, self.queue_notify_off);
        true
    }

    /// Wait up to [`READ_WAIT`] for the posted buffer to complete. Returns the
    /// device's written length and the posted length, or `None` at the bound,
    /// with the buffer still posted. A used element or index `poll_used`
    /// refuses (an id heading no outstanding chain, or an index past the
    /// outstanding chains) frees nothing and is passed over.
    fn wait_completion(&mut self) -> Option<(u32, u32)>
    {
        let start = Instant::now();
        loop
        {
            if let Ok(Some((_head, written))) = self.vq.poll_used()
            {
                let posted = self.posted.take().unwrap_or(0);
                return Some((written, posted));
            }
            if start.elapsed() >= READ_WAIT
            {
                return None;
            }
            let _ = syscall::notification_wait_timeout(self.wake, POLL_INTERVAL_MS);
        }
    }

    /// Copy the first `len` bytes of the request buffer into `out` and zero
    /// them in the buffer, so a later completion whose reported length the
    /// device did not fill hands out zeros, never bytes already handed out.
    fn take_bytes(&self, out: &mut [u8; MAX_READ_BYTES], len: usize)
    {
        for (i, byte) in out.iter_mut().take(len).enumerate()
        {
            // `i` is below MAX_READ_BYTES, inside the buffer page: no
            // saturation.
            let at = self.buf_va.saturating_add(i as u64) as *mut u8;
            // SAFETY: `at` lies in the request buffer page, mapped writable for
            // the driver's lifetime. Volatile: the device wrote the byte, and
            // poll_used's acquire fence ordered that write before this read.
            *byte = unsafe { core::ptr::read_volatile(at) };
            // SAFETY: as above; the device has completed the buffer, so it no
            // longer writes it.
            unsafe { core::ptr::write_volatile(at, 0) };
        }
    }
}

/// Reply `label` with no data.
fn reply_status(label: u64, ipc_buf: *mut u64)
{
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(label), ipc_buf) };
}

/// Handle `READ`: post the request buffer (or keep the one an earlier read
/// left posted), wait for the device to fill it, and reply with at most
/// `asked` of its bytes, or `NOT_READY` when the device fills nothing in
/// time.
fn handle_read(ipc_buf: *mut u64, rt: &mut RngRuntime, asked: usize)
{
    if asked == 0
    {
        reply_bytes(&[], ipc_buf);
        return;
    }
    if !rt.post(asked)
    {
        reply_status(hwrng_errors::NOT_READY, ipc_buf);
        return;
    }
    let Some((written, posted)) = rt.wait_completion()
    else
    {
        reply_status(hwrng_errors::NOT_READY, ipc_buf);
        return;
    };
    let len = virtio_rng::delivered_len(written, posted, asked);
    let mut bytes = [0u8; MAX_READ_BYTES];
    rt.take_bytes(&mut bytes, len);
    reply_bytes(bytes.get(..len).unwrap_or_default(), ipc_buf);
}

/// Reply `SUCCESS` carrying `bytes` ([`hwrng_protocol::encode_reply`]).
fn reply_bytes(bytes: &[u8], ipc_buf: *mut u64)
{
    let mut words = [0u64; MSG_DATA_WORDS_MAX];
    let Some(used) = hwrng_protocol::encode_reply(bytes, &mut words)
    else
    {
        reply_status(hwrng_errors::NOT_READY, ipc_buf);
        return;
    };
    let reply = IpcMessage::builder(hwrng_errors::SUCCESS)
        .words(0, words.get(..used).unwrap_or_default())
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Bind `interrupt` to a fresh notification and start the interrupt-service
/// thread over it, with its own transport over the same register window: it
/// runs [`virtio_core::isr::serve_interrupts`], acknowledging every delivery
/// of a wired line at once, a read in flight or not, so this driver never
/// holds a shared line masked, and signalling `wake` for the read path.
/// Exits on any failure.
fn start_interrupts(interrupt: DeviceInterrupt, window_va: u64, layout: &RegisterLayout, wake: u64)
{
    let Some(irq_notification) = create_notification()
    else
    {
        std::os::seraph::log!(error: "failed to create IRQ notification");
        syscall::thread_exit();
    };
    if syscall::irq_register(interrupt.cap(), irq_notification, interrupt.mode()).is_err()
    {
        std::os::seraph::log!(error: "irq_register failed");
        syscall::thread_exit();
    }
    let transport = PciTransport::new(window_va, layout);
    let started = std::thread::Builder::new()
        .spawn(move || {
            virtio_core::isr::serve_interrupts(
                &transport,
                interrupt,
                irq_notification,
                || {
                    let _ = syscall::notification_send(wake, 1);
                },
                isr_diag,
            )
        })
        .is_ok();
    if !started
    {
        std::os::seraph::log!(error: "failed to start the interrupt-service thread");
        syscall::thread_exit();
    }
    // irq_register leaves a wired line's entry masked; the first ack unmasks
    // it. An MSI-X target is never masked.
    if let DeviceInterrupt::Wired { cap, .. } = interrupt
    {
        let _ = syscall::irq_ack(cap);
    }
}

/// A fresh notification, `None` when it cannot be created.
fn create_notification() -> Option<u64>
{
    std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
        syscall::cap_create_notification(slab).ok()
    })
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

fn service_loop(service_ep: u64, ipc_buf: *mut u64, rt: &mut RngRuntime) -> !
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

        // No label takes a cap: delete every cap the request carries, which
        // would otherwise take a slot of this driver's `CSpace` for good.
        for &cap in msg.caps()
        {
            let _ = syscall::cap_delete(cap);
        }
        if !virtio_rng::authorized(msg.label, msg.badge)
        {
            reply_status(hwrng_errors::UNAUTHORIZED, ipc_buf);
        }
        else if msg.label == hwrng_protocol::READ
        {
            handle_read(ipc_buf, rt, hwrng_protocol::requested_len(msg.words()));
        }
        else
        {
            reply_status(hwrng_errors::UNKNOWN_OPCODE, ipc_buf);
        }
    }
}

// ── Entry point ────────────────────────────────────────────────────────────

fn main() -> !
{
    std::os::seraph::log::register_name(b"virtio-rng");
    let info = startup_info();

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned, stricter than u64"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

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

    let transport = PciTransport::new(window_va, &layout);
    init_device(&transport);
    let interrupt = caps
        .interrupt
        .filter(|_| transport.route_config(caps.interrupt));

    let (vq, queue_notify_off, interrupt) = setup_virtqueue(&transport, &caps, interrupt, ipc_buf);
    let (buf_addr, buf_va) = allocate_dma_pages(&caps, 1, "request buffer", ipc_buf);

    // DRIVER_OK.
    transport
        .set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);

    // The interrupt is optional: devmgr delivers none when it can give the
    // device none, a device may refuse the requestq's MSI-X vector, and a
    // read polls the used ring regardless. With an interrupt, bind a second
    // notification to it and start the interrupt-service thread, which
    // acknowledges every delivery of a wired line and signals `wake`.
    let Some(wake) = create_notification()
    else
    {
        std::os::seraph::log!(error: "failed to create notification");
        syscall::thread_exit();
    };
    if let Some(interrupt) = interrupt
    {
        std::os::seraph::log!("interrupt: {}", interrupt.describe());
        start_interrupts(interrupt, window_va, &layout, wake);
    }
    else
    {
        std::os::seraph::log!(warn: "no interrupt; polling the requestq");
    }
    std::os::seraph::log!("device ready");

    if caps.service_ep == 0
    {
        std::os::seraph::log!(warn: "no service endpoint, entering idle loop");
        loop
        {
            let _ = syscall::thread_yield();
        }
    }

    let mut rt = RngRuntime {
        vq,
        transport,
        queue_notify_off,
        wake,
        buf_va,
        buf_addr,
        posted: None,
    };
    report_ready(caps.devmgr_ep, ipc_buf);
    service_loop(caps.service_ep, ipc_buf, &mut rt);
}
