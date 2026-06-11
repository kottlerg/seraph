// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/virtio/input/src/main.rs

//! Seraph `VirtIO` input (keyboard) device driver.
//!
//! Receives BAR MMIO cap, IRQ cap, and `VirtioPciStartupInfo` startup message
//! from devmgr — the same PCI bring-up path as the sibling block driver.
//! Initialises the device via the modern PCI transport, posts receive buffers
//! to the event virtqueue, decodes `EV_KEY` events into the shared keysym
//! stream ([`ipc::keysym`]), and serves blocking reads over IPC.
//!
//! This is the virtio-input *backend*; a future USB-HID or PS-2 keyboard
//! driver is a sibling that decodes its own raw codes into the same keysym
//! ABI and registers the same devmgr slot ([`devmgr_labels::QUERY_INPUT_DEVICE`]),
//! so consumers never learn the transport.

// cast_possible_truncation: userspace targets 64-bit only; u64/usize conversions
// are lossless. u32 casts on capability slot indices are bounded by CSpace capacity.
#![allow(clippy::cast_possible_truncation)]

mod decode;
mod input;

use ipc::{
    IpcMessage, devmgr_labels, input_errors, input_labels, keysym, memmgr_errors, memmgr_labels,
};
use std::os::seraph::{StartupInfo, reserve_pages, startup_info};
use syscall_abi::PAGE_SIZE;
use virtio_core::pci::PciTransport;
use virtio_core::virtqueue::{self, SplitVirtqueue};
use virtio_core::{
    STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FEATURES_OK, VirtioPciStartupInfo,
};

use crate::decode::ModifierState;
use crate::input::EventRing;

/// Per-iteration timeout on the read-path wait, in milliseconds. When an IRQ is
/// bound the wait wakes on the device interrupt; the bounded timeout also
/// re-drains the used ring every tick, so the driver works whether or not an
/// IRQ is available (virtio-input may share an `INTx` line, leaving it with
/// none) and tolerates a lost PLIC interrupt on QEMU virt RISC-V. At 20 ms the
/// poll-only fallback stays well above human typing rates.
const POLL_INTERVAL_MS: u64 = 20;

// ── Driver caps from bootstrap protocol ────────────────────────────────────
//
// devmgr → virtio-input bootstrap plan (identical shape to virtio-blk):
// Round 1 (3 caps): [BAR MMIO, IRQ line, service endpoint]
// Round 2 (1 cap):  [devmgr query endpoint — badged per-device]
//
// log_ep and procmgr_ep arrive via `ProcessInfo`/`StartupInfo`.

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
    if round1.done
    {
        return None;
    }
    // Round 1 is [bar, irq, service] when devmgr carved a private IRQ, or
    // [bar, service] when virtio-input shares an INTx line and gets none. The
    // optional IRQ is the middle slot, so a 2-cap round means "no IRQ".
    let (bar_mmio_slot, irq_slot, service_ep) = match round1.cap_count
    {
        n if n >= 3 => (round1.caps[0], round1.caps[1], round1.caps[2]),
        2 => (round1.caps[0], 0, round1.caps[1]),
        _ => return None,
    };

    // SAFETY: same invariant.
    let round2 = unsafe { ipc::bootstrap::request_round(creator, ipc_buf) }.ok()?;
    if round2.cap_count < 1 || !round2.done
    {
        return None;
    }

    Some(DriverCaps {
        bar_mmio_slot,
        irq_slot,
        service_ep,
        memmgr_ep: info.memmgr_endpoint,
        devmgr_ep: round2.caps[0],
        self_aspace: info.self_aspace,
    })
}

// ── Device info query via devmgr IPC ──────────────────────────────────────

/// Query devmgr for `VirtIO` PCI capability locations. Identical generic
/// `QUERY_DEVICE_INFO` schema as virtio-blk; the badge identifies the device.
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

// ── Memory-cap allocation via memmgr IPC ────────────────────────────────────

/// Request a single contiguous Memory cap covering `page_count` pages from
/// memmgr. Returns `(cap_slot, phys_base)`; the physical base is needed for
/// DMA programming on no-IOMMU systems.
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
    if reply.word(0) != 1
    {
        for &c in reply.caps()
        {
            let _ = syscall::cap_delete(c);
        }
        return None;
    }
    let cap = reply.caps().first().copied()?;
    let phys_base = reply.word(2);
    Some((cap, phys_base))
}

// ── Device + virtqueue setup ────────────────────────────────────────────────

/// Initialise the device through the standard sequence (`VirtIO` 1.2 §3.1.1):
/// reset, acknowledge, negotiate features. virtio-input exposes no feature
/// bits the driver needs beyond `VIRTIO_F_VERSION_1`.
fn init_device(transport: &PciTransport)
{
    transport.reset();
    transport.set_status(STATUS_ACKNOWLEDGE);
    transport.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    // Accept only VIRTIO_F_VERSION_1 (bit 32) — required for modern devices.
    if transport
        .negotiate_features(|device_features| device_features & (1 << 32))
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

/// Allocate and map the virtqueue ring DMA memory. Returns
/// `(ring_phys, ring_va)`.
fn allocate_and_map_rings(queue_size: u16, caps: &DriverCaps, ipc_buf: *mut u64) -> (u64, u64)
{
    let ring_pages = virtqueue::ring_pages(queue_size) as u64;
    let Some((ring_memory, ring_phys)) = request_memory_caps(caps.memmgr_ep, ring_pages, ipc_buf)
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
    (ring_phys, ring_va)
}

/// Program the descriptor/avail/used ring physical addresses into the
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

/// Set up the eventq (queue 0): allocate/map ring DMA, program the device, and
/// build a `SplitVirtqueue` + notification offset.
fn setup_virtqueue(
    transport: &PciTransport,
    caps: &DriverCaps,
    ipc_buf: *mut u64,
) -> (SplitVirtqueue, u16)
{
    let queue_size = configure_queue_size(transport);
    let (ring_phys, ring_va) = allocate_and_map_rings(queue_size, caps, ipc_buf);
    program_transport_rings(transport, queue_size, ring_phys);

    let queue_notify_off = transport.queue_notify_off();

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

    (vq, queue_notify_off)
}

/// Allocate and map a single DMA page to back the event receive buffers.
fn setup_event_buffers(caps: &DriverCaps, buf_count: u16, ipc_buf: *mut u64) -> EventRing
{
    let Some((mem, phys)) = request_memory_caps(caps.memmgr_ep, 1, ipc_buf)
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
    if syscall::mem_map(
        mem,
        caps.self_aspace,
        va,
        0,
        1,
        syscall::MAP_READONLY | syscall::MAP_WRITABLE,
    )
    .is_err()
    {
        std::os::seraph::log!("event buffer mem_map failed");
        syscall::thread_exit();
    }
    // SAFETY: va is mapped writable, one page.
    unsafe {
        core::ptr::write_bytes(va as *mut u8, 0, PAGE_SIZE as usize);
    }
    EventRing::new(va, phys, buf_count)
}

// ── Service loop ───────────────────────────────────────────────────────────

/// Long-lived driver runtime: the event virtqueue, transport, IRQ plumbing,
/// receive-buffer ring, and modifier-decode state.
struct InputRuntime
{
    vq: SplitVirtqueue,
    transport: PciTransport,
    queue_notify_off: u16,
    irq_notification: u32,
    irq_cap: u32,
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
        // Wait for input. When an IRQ is bound the notification wakes on the
        // device interrupt; otherwise this is a timed poll. The bounded wait
        // re-drains every tick, so a lost or absent IRQ cannot wedge the read.
        let _ = syscall::notification_wait_timeout(rt.irq_notification, POLL_INTERVAL_MS);
        let _ = rt.transport.read_isr();
        if rt.irq_cap != 0
        {
            let _ = syscall::irq_ack(rt.irq_cap);
        }
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

fn service_loop(service_ep: u32, ipc_buf: *mut u64, rt: &mut InputRuntime) -> !
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

        if msg.label == input_labels::INPUT_READ_EVENTS
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
    if caps.devmgr_ep == 0
    {
        std::os::seraph::log!("no devmgr query endpoint");
        syscall::thread_exit();
    }

    let pci_info = query_device_info(caps.devmgr_ep, ipc_buf);

    // Map BAR MMIO for the driver's lifetime.
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

    let transport = PciTransport::new(bar_va, &pci_info);
    init_device(&transport);

    // Set up the eventq and its receive buffers.
    let (mut vq, queue_notify_off) = setup_virtqueue(&transport, &caps, ipc_buf);
    let buf_count = vq.queue_size();
    let mut ring = setup_event_buffers(&caps, buf_count, ipc_buf);
    ring.post_all(&mut vq);

    // DRIVER_OK.
    transport
        .set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);

    // Create the notification the read path waits on. The IRQ is optional:
    // virtio-input may share an INTx line (devmgr then delivers no IRQ cap), and
    // the read path polls the eventq regardless. When an IRQ cap is present, bind
    // the notification to it for low-latency wakeups; otherwise the bounded wait
    // degrades to timed polling.
    let Some(irq_notification) = std::os::seraph::object_slab_retype(120, |slab| {
        syscall::cap_create_notification(slab).ok()
    })
    else
    {
        std::os::seraph::log!("failed to create notification");
        syscall::thread_exit();
    };
    let irq_cap = caps.irq_slot;
    if irq_cap != 0
    {
        if syscall::irq_register(irq_cap, irq_notification).is_err()
        {
            std::os::seraph::log!("irq_register failed");
            syscall::thread_exit();
        }
        // irq_register leaves the entry masked; the first ack unmasks it.
        let _ = syscall::irq_ack(irq_cap);
    }
    else
    {
        std::os::seraph::log!("no private IRQ; polling the eventq");
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
        irq_notification,
        irq_cap,
        ring,
        mods: ModifierState::new(),
    };
    service_loop(caps.service_ep, ipc_buf, &mut rt);
}
