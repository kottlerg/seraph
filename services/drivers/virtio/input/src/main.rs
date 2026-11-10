// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/input/src/main.rs

//! Seraph `VirtIO` input (keyboard) device driver.
//!
//! Receives a BAR MMIO cap per BAR the device's register regions name, an
//! optional IRQ cap, and the `VirtioPciStartupInfo` startup message from
//! devmgr — the same PCI bring-up path as the sibling block driver.
//! Initialises the device via the modern PCI transport, posts receive buffers
//! to the event virtqueue, decodes `EV_KEY` events into the shared keysym
//! stream ([`ipc::keysym`]), and serves blocking reads over IPC.
//!
//! This is the virtio-input *backend*; a future USB-HID or PS-2 keyboard
//! driver is a sibling that decodes its own raw codes into the same keysym
//! ABI and registers the same devmgr slot ([`devmgr_labels::QUERY_INPUT_DEVICE`]),
//! so consumers never learn the transport.

mod decode;
mod input;

use ipc::{
    IpcMessage, devmgr_labels, input_errors, input_labels, keysym, memmgr_errors, memmgr_labels,
};
use std::os::seraph::{StartupInfo, reserve_pages, startup_info};
use std::time::Instant;
use syscall_abi::PAGE_SIZE;
use virtio_core::bootstrap::{DeliveredBars, DriverEndpoints};
use virtio_core::pci::PciTransport;
use virtio_core::virtqueue::{self, SplitVirtqueue};
use virtio_core::{
    RegisterLayout, STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FEATURES_OK,
    VirtioPciStartupInfo,
};

use crate::decode::ModifierState;
use crate::input::EventRing;

/// Per-iteration timeout on the read-path wait, in milliseconds. When an IRQ is
/// bound the wait wakes when the interrupt-service thread signals `wake`; the
/// bounded timeout also re-drains the used ring every tick, so the driver works
/// whether or not an IRQ is available (devmgr delivers none when it can give
/// the device no IRQ cap) and tolerates a lost PLIC interrupt on QEMU virt
/// RISC-V. At 20 ms the poll-only fallback stays well above human typing rates.
const POLL_INTERVAL_MS: u64 = 20;

/// [`PAGE_SIZE`] as a `usize`, for the byte count of a one-page fill.
// cast_possible_truncation: PAGE_SIZE is 4096, which every `usize` holds.
#[allow(clippy::cast_possible_truncation)]
const PAGE_BYTES: usize = PAGE_SIZE as usize;

// ── Driver caps from bootstrap protocol ────────────────────────────────────
//
// devmgr serves the two rounds `virtio_core::bootstrap` specifies, as for
// virtio-blk: the BAR caps with their BAR indices, then the service
// endpoint, the IRQ (absent when devmgr could give the device no IRQ cap)
// with its line's mode word, the per-device devmgr query endpoint, and the
// device's DMA capability. log_ep and procmgr_ep arrive via
// `ProcessInfo`/`StartupInfo`.

struct DriverCaps
{
    bars: DeliveredBars,
    irq_slot: u64,
    /// The `SYS_IRQ_REGISTER` mode devmgr derived for the IRQ line.
    irq_mode: u64,
    memmgr_ep: u64,
    service_ep: u64,
    devmgr_ep: u64,
    /// The device's DMA capability (`virtio_core::bootstrap::SLOT_DMA`),
    /// through which the rings and event buffers are mapped for the device.
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
    let round1 = unsafe { ipc::bootstrap::request_round(creator, ipc_buf) }.ok()?;
    let bars = DeliveredBars::from_round(&round1)?;

    // SAFETY: same invariant.
    let round2 = unsafe { ipc::bootstrap::request_round(creator, ipc_buf) }.ok()?;
    let endpoints = DriverEndpoints::from_round(&round2)?;
    if endpoints.dma == 0
    {
        std::os::seraph::log!("no DMA capability delivered");
        return None;
    }

    Some(DriverCaps {
        bars,
        irq_slot: endpoints.irq,
        irq_mode: endpoints.irq_mode,
        service_ep: endpoints.service,
        memmgr_ep: info.memmgr_endpoint,
        devmgr_ep: endpoints.devmgr_query,
        dma_ep: endpoints.dma,
        self_aspace: info.self_aspace,
    })
}

/// Map every delivered BAR into one register window laid out as `layout`
/// says, after checking the delivered BARs are the layout's own. Returns the
/// window's virtual address; exits on any failure (the device cannot be
/// driven without its registers).
fn map_register_window(caps: &DriverCaps, layout: &RegisterLayout) -> u64
{
    if !layout.matches_delivered(caps.bars.bar_indices())
    {
        std::os::seraph::log!("delivered BARs do not match the device's register regions");
        syscall::thread_exit();
    }
    let window_pages = layout.window_pages();
    // The BAR mappings live for the driver process's lifetime; the
    // reservation is intentionally never returned to the arena (the
    // ReservedRange has no Drop impl, so falling out of scope is a no-op).
    let Ok(window) = reserve_pages(window_pages)
    else
    {
        std::os::seraph::log!("BAR reserve_pages failed");
        syscall::thread_exit();
    };
    let window_va = window.va_start();
    if !std::os::seraph::fund_aspace_pt_budget(caps.self_aspace, window_pages)
    {
        std::os::seraph::log!("BAR PT-budget funding failed");
        syscall::thread_exit();
    }
    let mut bar_va = window_va;
    for (&bar_cap, aperture) in caps.bars.caps().iter().zip(layout.bars())
    {
        // SAFETY: `window` is a fresh reservation of `window_pages` pages
        // from the per-process arena, and `bar_va` starts this BAR's
        // `aperture.pages`-page share of it. devmgr carves each BAR cap to at
        // most the same `pages` (`carve_virtio_bars`), so the whole-region
        // mapping stays inside that share: VA no Rust object or IPC page
        // occupies. `PciTransport` reaches the BARs only through its raw
        // volatile accessors, never a reference, and the reservation is
        // never returned, so the VA stays reserved for the driver's lifetime
        // (`mmio_map` § Safety).
        if unsafe { syscall::mmio_map(caps.self_aspace, bar_cap, bar_va, 0) }.is_err()
        {
            std::os::seraph::log!("BAR mmio_map failed");
            syscall::thread_exit();
        }
        bar_va += aperture.pages * PAGE_SIZE;
    }
    window_va
}

// ── Device info query via devmgr IPC ──────────────────────────────────────

/// Query devmgr for `VirtIO` PCI capability locations. Identical generic
/// `QUERY_DEVICE_INFO` schema as virtio-blk; the badge identifies the device.
fn query_device_info(devmgr_ep: u64, ipc_buf: *mut u64) -> VirtioPciStartupInfo
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
    // A word past the field's width is a mismatch, not a value to truncate.
    let kind = u32::try_from(words[0]).ok();
    let version = u32::try_from(words[1]).ok();
    let byte_len = usize::try_from(words[2]).unwrap_or(usize::MAX);
    if kind != Some(ipc::device_info_kind::VIRTIO_PCI)
        || version != Some(virtio_core::VIRTIO_PCI_INFO_VERSION)
    {
        std::os::seraph::log!("QUERY_DEVICE_INFO reply kind/version mismatch");
        syscall::thread_exit();
    }
    if byte_len != VirtioPciStartupInfo::SIZE
    {
        std::os::seraph::log!("QUERY_DEVICE_INFO reply byte_len mismatch");
        syscall::thread_exit();
    }
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
        std::os::seraph::log!("DRIVER_READY failed ({e:?}); exiting");
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

// ── Device + virtqueue setup ────────────────────────────────────────────────

/// Initialise the device through the standard sequence (`VirtIO` 1.2 §3.1.1):
/// reset, acknowledge, negotiate features. virtio-input exposes no feature
/// bits the driver needs beyond `VIRTIO_F_VERSION_1`, and the driver accepts
/// `VIRTIO_F_ACCESS_PLATFORM`, since it programs only device addresses.
fn init_device(transport: &PciTransport)
{
    // The reset wait is bounded on the monotonic clock
    // (`virtio_core::pci::RESET_TIMEOUT`).
    let start = Instant::now();
    if !transport.try_reset(|| start.elapsed())
    {
        std::os::seraph::log!("device reset unacknowledged");
        syscall::thread_exit();
    }
    transport.set_status(STATUS_ACKNOWLEDGE);
    transport.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    // Accept VIRTIO_F_VERSION_1, required for modern devices, and
    // VIRTIO_F_ACCESS_PLATFORM, since every address the driver programs is a
    // device address devmgr returned.
    if transport
        .negotiate_features(|device_features| {
            device_features
                & (virtio_core::VIRTIO_F_VERSION_1 | virtio_core::VIRTIO_F_ACCESS_PLATFORM)
        })
        .is_none()
    {
        std::os::seraph::log!("feature negotiation failed");
        syscall::thread_exit();
    }
}

/// Negotiate the eventq (queue 0) size against the device maximum.
fn configure_queue_size(transport: &PciTransport) -> u16
{
    transport.queue_select(0);
    let max_size = transport.queue_max_size();
    let queue_size = input::EVENT_QUEUE_SIZE.min(max_size);
    transport.queue_set_size(queue_size);
    queue_size
}

/// Allocate the virtqueue ring DMA memory, map it into the driver's address
/// space and for the device. Returns `(ring_addr, ring_va)`, `ring_addr` the
/// rings' device address.
fn allocate_and_map_rings(queue_size: u16, caps: &DriverCaps, ipc_buf: *mut u64) -> (u64, u64)
{
    let ring_pages = virtqueue::ring_pages(queue_size) as u64;
    let Some(ring_memory) = request_memory_caps(caps.memmgr_ep, ring_pages, ipc_buf)
    else
    {
        std::os::seraph::log!("failed to allocate ring memory caps");
        syscall::thread_exit();
    };
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
    let Ok(ring_bytes) = usize::try_from(ring_pages * PAGE_SIZE)
    else
    {
        std::os::seraph::log!("{ring_pages} ring pages past the address width");
        syscall::thread_exit();
    };
    // SAFETY: ring_va is mapped writable, ring_pages * PAGE_SIZE bytes.
    unsafe {
        core::ptr::write_bytes(ring_va as *mut u8, 0, ring_bytes);
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let ring_addr = unsafe {
        virtio_core::dma::map_or_exit(caps.dma_ep, ring_memory, ipc_buf, |e| {
            std::os::seraph::log!("ring memory not mapped for the device ({e:?})");
        })
    };
    (ring_addr, ring_va)
}

/// Program the descriptor/avail/used ring device addresses into the
/// transport and mark the queue ready.
fn program_transport_rings(transport: &PciTransport, queue_size: u16, ring_addr: u64)
{
    let desc_size = virtqueue::desc_table_size(queue_size);
    let used_off = virtqueue::used_ring_offset(queue_size);

    let desc_addr = ring_addr;
    let avail_addr = ring_addr + desc_size as u64;
    let used_addr = ring_addr + used_off as u64;

    transport.queue_set_rings(desc_addr, avail_addr, used_addr);

    transport.queue_set_ready(1);
}

/// Set up the eventq (queue 0): allocate/map ring DMA, program the device, and
/// build a `SplitVirtqueue` + notification offset.
fn setup_virtqueue(
    transport: &PciTransport,
    caps: &DriverCaps,
    ipc_buf: *mut u64,
) -> (SplitVirtqueue, u16)
{
    let queue_size = configure_queue_size(transport);
    let (ring_addr, ring_va) = allocate_and_map_rings(queue_size, caps, ipc_buf);
    program_transport_rings(transport, queue_size, ring_addr);

    let queue_notify_off = transport.queue_notify_off();
    if !transport.doorbell_in_region(queue_notify_off)
    {
        std::os::seraph::log!("queue doorbell outside the notification region");
        syscall::thread_exit();
    }

    let desc_size = virtqueue::desc_table_size(queue_size);
    let used_off = virtqueue::used_ring_offset(queue_size);
    let desc_va = ring_va;
    let avail_va = ring_va + desc_size as u64;
    let used_va = ring_va + used_off as u64;

    // SAFETY: ring memory is zeroed, correctly sized, and exclusively owned;
    // the offsets keep each region naturally aligned (same layout virtio-blk
    // relies on).
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
        std::os::seraph::log!("device offers no usable eventq (queue size {queue_size})");
        syscall::thread_exit();
    };

    (vq, queue_notify_off)
}

/// Allocate a single DMA page to back the event receive buffers, and map it
/// into the driver's address space and for the device.
fn setup_event_buffers(caps: &DriverCaps, buf_count: u16, ipc_buf: *mut u64) -> EventRing
{
    let Some(mem) = request_memory_caps(caps.memmgr_ep, 1, ipc_buf)
    else
    {
        std::os::seraph::log!("failed to allocate event buffer cap");
        syscall::thread_exit();
    };
    let Ok(range) = reserve_pages(1)
    else
    {
        std::os::seraph::log!("event buffer reserve_pages failed");
        syscall::thread_exit();
    };
    let va = range.va_start();
    // SAFETY: `range` is a fresh reservation from the per-process arena,
    // owned here for the mapping's life: VA no Rust object or IPC page
    // occupies.
    let mapped =
        unsafe { syscall::mem_map(mem, caps.self_aspace, va, 0, 1, syscall::MAP_WRITABLE) };
    if mapped.is_err()
    {
        std::os::seraph::log!("event buffer mem_map failed");
        syscall::thread_exit();
    }
    // SAFETY: va is mapped writable, one page.
    unsafe {
        core::ptr::write_bytes(va as *mut u8, 0, PAGE_BYTES);
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let addr = unsafe {
        virtio_core::dma::map_or_exit(caps.dma_ep, mem, ipc_buf, |e| {
            std::os::seraph::log!("event buffer page not mapped for the device ({e:?})");
        })
    };
    EventRing::new(va, addr, buf_count)
}

// ── Service loop ───────────────────────────────────────────────────────────

/// Long-lived driver runtime: the event virtqueue, transport, IRQ plumbing,
/// receive-buffer ring, and modifier-decode state.
struct InputRuntime
{
    vq: SplitVirtqueue,
    transport: PciTransport,
    queue_notify_off: u16,
    /// Notification the read loop waits on: signalled by the
    /// interrupt-service thread after each delivery it acknowledged and each
    /// interrupt its timed ISR read finds ([`start_isr_thread`]), never
    /// signalled when no IRQ is bound, in which case the bounded wait is a
    /// timed poll.
    wake: u64,
    ring: EventRing,
    mods: ModifierState,
}

/// Handle `INPUT_READ_EVENTS`: drain and decode pending events, blocking until
/// at least one keysym is produced, then reply with the batch.
fn handle_read_events(ipc_buf: *mut u64, rt: &mut InputRuntime)
{
    let mut events = [0u64; keysym::INPUT_MAX_EVENTS_PER_READ];
    let mut count = 0usize;

    loop
    {
        let mut reposted = false;
        while count < keysym::INPUT_MAX_EVENTS_PER_READ
        {
            let Some(ev) = rt.ring.drain(&mut rt.vq)
            else
            {
                break;
            };
            reposted = true;
            if let Some(decoded) = rt.mods.decode(ev)
            {
                events[count] =
                    keysym::pack_event(decoded.keysym, decoded.modifiers, decoded.pressed);
                count += 1;
            }
        }
        if reposted
        {
            // The drained buffers were re-posted; tell the device.
            rt.transport.notify(0, rt.queue_notify_off);
        }
        if count > 0
        {
            break;
        }
        // Wait for input. When an IRQ is bound the interrupt-service thread
        // signals `wake` on each interrupt, having read the ISR and
        // acknowledged any delivery; otherwise this is a timed poll. The
        // bounded wait re-drains every tick, so a lost or absent IRQ cannot
        // wedge the read.
        let _ = syscall::notification_wait_timeout(rt.wake, POLL_INTERVAL_MS);
    }

    let mut builder = IpcMessage::builder(input_errors::SUCCESS).word(0, count as u64);
    for (i, &ev) in events[..count].iter().enumerate()
    {
        builder = builder.word(1 + i, ev);
    }
    let reply = builder.build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Start the interrupt-service thread, which runs
/// [`virtio_core::isr::serve_interrupts`] over `irq_notification`, the
/// notification bound to the device's line: it acknowledges every delivery
/// at once, a read in flight or not, and signals `wake` for the read loop.
/// Returns whether the thread started.
fn start_isr_thread(transport: PciTransport, irq_notification: u64, irq_cap: u64, wake: u64)
-> bool
{
    std::thread::Builder::new()
        .spawn(move || {
            virtio_core::isr::serve_interrupts(
                &transport,
                irq_notification,
                irq_cap,
                wake,
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
            std::os::seraph::log!("interrupt wait failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!("interrupt wait wedged (err={err}); exiting");
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
            std::os::seraph::log!("ipc_recv failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!("ipc_recv wedged (err={err}); exiting");
        }
    }
}

fn service_loop(service_ep: u64, ipc_buf: *mut u64, rt: &mut InputRuntime) -> !
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
        if !virtio_input::authorized(msg.label, msg.badge)
        {
            let reply = IpcMessage::new(input_errors::UNAUTHORIZED);
            // SAFETY: ipc_buf is the registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        }
        else if msg.label == input_labels::INPUT_READ_EVENTS
        {
            handle_read_events(ipc_buf, rt);
        }
        else
        {
            let reply = IpcMessage::new(input_errors::UNKNOWN_OPCODE);
            // SAFETY: ipc_buf is the registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        }
    }
}

// ── Entry point ────────────────────────────────────────────────────────────

fn main() -> !
{
    std::os::seraph::log::register_name(b"virtio-input");
    let info = startup_info();

    // cast_ptr_alignment: IPC buffer page is 4 KiB-aligned, stricter than u64.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(caps) = bootstrap_caps(info, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    std::os::seraph::log!("starting");
    if caps.memmgr_ep == 0
    {
        std::os::seraph::log!("no memmgr endpoint");
        syscall::thread_exit();
    }
    if caps.devmgr_ep == 0
    {
        std::os::seraph::log!("no devmgr query endpoint");
        syscall::thread_exit();
    }

    let pci_info = query_device_info(caps.devmgr_ep, ipc_buf);

    // Map every BAR the register regions name into one register window.
    let Some(layout) = pci_info.register_layout()
    else
    {
        std::os::seraph::log!("device presents no complete set of register regions");
        syscall::thread_exit();
    };
    let window_va = map_register_window(&caps, &layout);

    let transport = PciTransport::new(window_va, &layout);
    init_device(&transport);

    // Set up the eventq and its receive buffers.
    let (mut vq, queue_notify_off) = setup_virtqueue(&transport, &caps, ipc_buf);
    let buf_count = vq.queue_size();
    let mut ring = setup_event_buffers(&caps, buf_count, ipc_buf);
    ring.post_all(&mut vq);

    // DRIVER_OK.
    transport
        .set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);

    // Create the notification the read path waits on (`wake`). The IRQ is
    // optional: devmgr delivers no IRQ cap when it can give the device none,
    // and the read path polls the eventq regardless. When an IRQ cap is
    // present, bind a second notification to it and start the
    // interrupt-service thread, which acknowledges every delivery and signals
    // `wake`; otherwise the bounded wait degrades to timed polling.
    let create_notification = || {
        std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
            syscall::cap_create_notification(slab).ok()
        })
    };
    let Some(wake) = create_notification()
    else
    {
        std::os::seraph::log!("failed to create notification");
        syscall::thread_exit();
    };
    let irq_cap = caps.irq_slot;
    if irq_cap == 0
    {
        std::os::seraph::log!("no IRQ cap; polling the eventq");
    }
    else
    {
        let Some(irq_notification) = create_notification()
        else
        {
            std::os::seraph::log!("failed to create IRQ notification");
            syscall::thread_exit();
        };
        if syscall::irq_register(irq_cap, irq_notification, caps.irq_mode).is_err()
        {
            std::os::seraph::log!("irq_register failed");
            syscall::thread_exit();
        }
        // The interrupt-service thread acknowledges every delivery from here
        // on, a read in flight or not, so this driver never holds a shared
        // line masked. Its transport is a copy over the same register window.
        if !start_isr_thread(
            PciTransport::new(window_va, &layout),
            irq_notification,
            irq_cap,
            wake,
        )
        {
            std::os::seraph::log!("failed to start the interrupt-service thread");
            syscall::thread_exit();
        }
        // irq_register leaves the entry masked; the first ack unmasks it.
        let _ = syscall::irq_ack(irq_cap);
    }

    // Tell the device its event buffers are available.
    transport.notify(0, queue_notify_off);
    std::os::seraph::log!("device ready");

    if caps.service_ep == 0
    {
        std::os::seraph::log!("no service endpoint, entering idle loop");
        loop
        {
            let _ = syscall::thread_yield();
        }
    }

    let mut rt = InputRuntime {
        vq,
        transport,
        queue_notify_off,
        wake,
        ring,
        mods: ModifierState::new(),
    };
    report_ready(caps.devmgr_ep, ipc_buf);
    service_loop(caps.service_ep, ipc_buf, &mut rt);
}
