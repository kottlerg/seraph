// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/console/src/main.rs

//! Seraph `VirtIO` console device driver: the debug port.
//!
//! Receives a BAR MMIO cap per BAR the device's register regions name, an
//! optional IRQ cap, and the `VirtioPciStartupInfo` startup message from
//! devmgr, the same PCI bring-up path as the sibling input driver. Drives
//! the device's port 0 through its receive queue (virtqueue 0) and transmit
//! queue (virtqueue 1), without `VIRTIO_CONSOLE_F_MULTIPORT`, and serves the
//! serial protocol ([`serial_labels`]) on its service endpoint: a write
//! sends the bytes through the transmit queue, a read drains what the
//! receive queue holds, and an RX-notify registration has the
//! interrupt-service thread signal the client's notification.
//!
//! devmgr hands the endpoint only to the holder of the debug-port authority
//! (`devmgr_labels::QUERY_DEBUG_PORT_DEVICE`): this is the debug port, not a
//! console. Any driver that serves the same protocol (a UART driver on
//! hardware) can stand in for it, so the consumer never learns the
//! transport.

use ipc::{IpcMessage, devmgr_labels, memmgr_errors, memmgr_labels, serial_errors, serial_labels};
use std::os::seraph::{StartupInfo, reserve_pages, startup_info};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;
use syscall_abi::PAGE_SIZE;
use virtio_console::RxQueue;
use virtio_core::bootstrap::{DeliveredBars, DriverEndpoints};
use virtio_core::pci::PciTransport;
use virtio_core::virtqueue::{self, SplitVirtqueue};
use virtio_core::{
    RegisterLayout, STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FEATURES_OK,
    VirtioPciStartupInfo,
};

/// Port 0's receive queue.
const RX_QUEUE: u16 = 0;
/// Port 0's transmit queue.
const TX_QUEUE: u16 = 1;

/// Receive buffers posted to the receive queue, each [`RX_BUFFER_BYTES`]
/// long, together one DMA page. A power of two, as the queue size must be;
/// the queue takes fewer when the device offers fewer.
const RX_BUFFERS: u16 = 8;
/// Bytes per receive buffer, as the descriptor's length field takes it: one
/// read reply's worth.
const RX_BUFFER_LEN: u32 = 512;
/// [`RX_BUFFER_LEN`] as a byte count.
const RX_BUFFER_BYTES: usize = RX_BUFFER_LEN as usize;
const _: () = assert!(RX_BUFFERS as u64 * RX_BUFFER_LEN as u64 <= PAGE_SIZE);

/// The most bytes one serial-protocol message carries in either direction:
/// `MSG_DATA_WORDS_MAX` words of 8 bytes.
const MAX_MESSAGE_BYTES: usize = syscall_abi::MSG_DATA_WORDS_MAX * 8;
const _: () = assert!(RX_BUFFER_BYTES == MAX_MESSAGE_BYTES);

/// The transmit queue's size: one write is in flight at a time.
const TX_QUEUE_SIZE: u16 = 1;

/// How long, in milliseconds, a write waits for the device between looks at
/// the transmit queue's used ring. The interrupt-service thread's signal
/// ends the wait early; with no IRQ cap the wait is a timed poll.
const TX_POLL_MS: u64 = 5;

/// The bytes received and not yet read: the device's filled buffers are
/// copied here and re-posted ([`RxQueue`]). Twice a read reply, so a read
/// that leaves a buffer's tail queued still takes the next buffer whole.
type Received = RxQueue<{ 2 * RX_BUFFER_BYTES }>;

// ── Driver caps from bootstrap protocol ────────────────────────────────────
//
// devmgr serves the two rounds `virtio_core::bootstrap` specifies, as for the
// input driver: the BAR caps with their BAR indices, then the service
// endpoint, the IRQ (absent when devmgr could give the device no IRQ cap)
// with its line's mode word, the per-device devmgr query endpoint, and the
// device's DMA capability.

struct DriverCaps
{
    bars: DeliveredBars,
    irq_slot: u64,
    /// The `SYS_IRQ_REGISTER` mode devmgr derived for the IRQ line.
    irq_mode: u64,
    memmgr_ep: u64,
    service_ep: u64,
    devmgr_ep: u64,
    /// The device's DMA capability, through which the rings and buffers are
    /// mapped for the device.
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

/// Log `msg` and end the driver: it cannot serve without what failed.
fn fail(msg: &str) -> !
{
    std::os::seraph::log!("{}", msg);
    syscall::thread_exit();
}

/// Map every delivered BAR into one register window laid out as `layout`
/// says, after checking the delivered BARs are the layout's own. Returns the
/// window's virtual address.
fn map_register_window(caps: &DriverCaps, layout: &RegisterLayout) -> u64
{
    if !layout.matches_delivered(caps.bars.bar_indices())
    {
        fail("delivered BARs do not match the device's register regions");
    }
    let window_pages = layout.window_pages();
    // The BAR mappings live for the driver process's lifetime; the
    // reservation is never returned to the arena.
    let Ok(window) = reserve_pages(window_pages)
    else
    {
        fail("BAR reserve_pages failed");
    };
    let window_va = window.va_start();
    if !std::os::seraph::fund_aspace_pt_budget(caps.self_aspace, window_pages)
    {
        fail("BAR PT-budget funding failed");
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
            fail("BAR mmio_map failed");
        }
        bar_va += aperture.pages * PAGE_SIZE;
    }
    window_va
}

/// Query devmgr for the device's `VirtIO` PCI capability locations: the
/// generic `QUERY_DEVICE_INFO` schema of every `VirtIO` driver.
fn query_device_info(devmgr_ep: u64, ipc_buf: *mut u64) -> VirtioPciStartupInfo
{
    let request = IpcMessage::builder(devmgr_labels::QUERY_DEVICE_INFO)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(devmgr_ep, &request, ipc_buf) })
    else
    {
        fail("QUERY_DEVICE_INFO ipc_call failed");
    };
    if reply.label != 0
    {
        fail("QUERY_DEVICE_INFO returned error");
    }
    let words = reply.words();
    if words.len() < 3
    {
        fail("QUERY_DEVICE_INFO reply truncated (header)");
    }
    // A word past the field's width is a mismatch, not a value to truncate.
    let kind = u32::try_from(words[0]).ok();
    let version = u32::try_from(words[1]).ok();
    let byte_len = usize::try_from(words[2]).unwrap_or(usize::MAX);
    if kind != Some(ipc::device_info_kind::VIRTIO_PCI)
        || version != Some(virtio_core::VIRTIO_PCI_INFO_VERSION)
    {
        fail("QUERY_DEVICE_INFO reply kind/version mismatch");
    }
    if byte_len != VirtioPciStartupInfo::SIZE || words.len() < 3 + byte_len.div_ceil(8)
    {
        fail("QUERY_DEVICE_INFO reply length mismatch");
    }
    let mut buf = [0u8; VirtioPciStartupInfo::SIZE];
    for (i, chunk) in buf.chunks_mut(8).enumerate()
    {
        let bytes = words[3 + i].to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    let Some(info) = VirtioPciStartupInfo::from_bytes(&buf)
    else
    {
        fail("QUERY_DEVICE_INFO from_bytes failed");
    };
    info
}

// ── DMA memory ──────────────────────────────────────────────────────────────

/// `pages` pages of memory, zeroed and mapped writable into the driver and
/// for the device: the virtual address and the device address.
struct DmaPages
{
    va: u64,
    addr: u64,
}

/// Allocate `pages` contiguous pages from memmgr, map them writable into the
/// driver, zero them, and map them for the device through the DMA
/// capability.
fn dma_pages(caps: &DriverCaps, pages: u64, what: &str, ipc_buf: *mut u64) -> DmaPages
{
    let arg = pages | (u64::from(memmgr_labels::REQUIRE_CONTIGUOUS) << 32);
    let request = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, arg)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(caps.memmgr_ep, &request, ipc_buf) };
    let memory = match reply
    {
        Ok(r) if r.label == memmgr_errors::SUCCESS && r.word(0) == 1 && !r.caps().is_empty() =>
        {
            r.caps()[0]
        }
        Ok(r) =>
        {
            for &c in r.caps()
            {
                let _ = syscall::cap_delete(c);
            }
            std::os::seraph::log!("{}: no contiguous memory", what);
            syscall::thread_exit();
        }
        Err(_) =>
        {
            std::os::seraph::log!("{}: memmgr call failed", what);
            syscall::thread_exit();
        }
    };
    let Ok(range) = reserve_pages(pages)
    else
    {
        std::os::seraph::log!("{}: reserve_pages failed", what);
        syscall::thread_exit();
    };
    let va = range.va_start();
    let Ok(bytes) = usize::try_from(pages * PAGE_SIZE)
    else
    {
        std::os::seraph::log!("{}: {} pages past the address width", what, pages);
        syscall::thread_exit();
    };
    // SAFETY: `range` is a fresh reservation from the per-process arena,
    // owned here for the mapping's life: VA no Rust object or IPC page
    // occupies.
    let mapped = unsafe {
        syscall::mem_map(
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
        std::os::seraph::log!("{}: mem_map failed", what);
        syscall::thread_exit();
    }
    // SAFETY: va is mapped writable, pages * PAGE_SIZE bytes.
    unsafe {
        core::ptr::write_bytes(va as *mut u8, 0, bytes);
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let addr = unsafe {
        virtio_core::dma::map_or_exit(caps.dma_ep, memory, ipc_buf, |e| {
            std::os::seraph::log!("{}: not mapped for the device ({:?})", what, e);
        })
    };
    DmaPages { va, addr }
}

// ── Device and virtqueue setup ──────────────────────────────────────────────

/// Initialise the device through the standard sequence (`VirtIO` 1.2
/// §3.1.1): reset, acknowledge, negotiate features. The driver takes none of
/// the console's own features: no `VIRTIO_CONSOLE_F_MULTIPORT`, so the
/// device carries port 0 alone on queues 0 and 1; no `VIRTIO_CONSOLE_F_SIZE`
/// or `EMERG_WRITE`, which a byte transport does not use. It accepts
/// `VIRTIO_F_VERSION_1` and `VIRTIO_F_ACCESS_PLATFORM`, since it programs
/// only device addresses.
fn init_device(transport: &PciTransport)
{
    // The reset wait is bounded on the monotonic clock
    // (`virtio_core::pci::RESET_TIMEOUT`).
    let start = Instant::now();
    if !transport.try_reset(|| start.elapsed())
    {
        fail("device reset unacknowledged");
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
        fail("feature negotiation failed");
    }
}

/// The low 32 bits of a device address, for a transport register that takes
/// the address in halves.
// cast_possible_truncation: keeping the low half is the point; the high half
// goes to the register's pair through `high_half`.
#[allow(clippy::cast_possible_truncation)]
fn low_half(addr: u64) -> u32
{
    addr as u32
}

/// The high 32 bits of a device address ([`low_half`]'s pair).
fn high_half(addr: u64) -> u32
{
    // The shift leaves at most 32 bits, so the conversion cannot fail.
    u32::try_from(addr >> 32).unwrap_or(0)
}

/// One virtqueue: its ring and its doorbell.
struct Queue
{
    vq: SplitVirtqueue,
    index: u16,
    notify_off: u16,
}

/// Set up virtqueue `index` at no more than `wanted` entries: size it against
/// the device's maximum, allocate and map its rings, program them, and mark
/// it ready.
fn setup_queue(
    transport: &PciTransport,
    caps: &DriverCaps,
    index: u16,
    wanted: u16,
    ipc_buf: *mut u64,
) -> Queue
{
    transport.queue_select(index);
    let size = wanted.min(transport.queue_max_size());
    transport.queue_set_size(size);
    let rings = dma_pages(caps, virtqueue::ring_pages(size) as u64, "rings", ipc_buf);

    let desc_off = 0u64;
    let avail_off = virtqueue::desc_table_size(size) as u64;
    let used_off = virtqueue::used_ring_offset(size) as u64;
    let (desc, avail, used) = (
        rings.addr + desc_off,
        rings.addr + avail_off,
        rings.addr + used_off,
    );
    transport.queue_set_desc_lo(low_half(desc));
    transport.queue_set_desc_hi(high_half(desc));
    transport.queue_set_avail_lo(low_half(avail));
    transport.queue_set_avail_hi(high_half(avail));
    transport.queue_set_used_lo(low_half(used));
    transport.queue_set_used_hi(high_half(used));
    transport.queue_set_ready(1);

    let notify_off = transport.queue_notify_off();
    if !transport.doorbell_in_region(notify_off)
    {
        fail("queue doorbell outside the notification region");
    }
    // SAFETY: the ring memory is zeroed, sized for `size` entries, and owned
    // by this queue for the driver's life; the offsets keep each region
    // naturally aligned (the layout every VirtIO driver here relies on).
    let vq = unsafe {
        SplitVirtqueue::new(
            (rings.va + desc_off) as *mut virtqueue::VirtqDesc,
            (rings.va + avail_off) as *mut virtqueue::VirtqAvail,
            (rings.va + used_off) as *mut virtqueue::VirtqUsed,
            size,
        )
    };
    let Some(vq) = vq
    else
    {
        std::os::seraph::log!("device offers no usable queue {} (size {})", index, size);
        syscall::thread_exit();
    };
    Queue {
        vq,
        index,
        notify_off,
    }
}

// ── Runtime ─────────────────────────────────────────────────────────────────

/// The driver's device state, owned by the service loop.
struct Console
{
    transport: PciTransport,
    rx: Queue,
    tx: Queue,
    /// The receive buffers' page; buffer `i` is at `i * RX_BUFFER_BYTES`.
    rx_buffers: DmaPages,
    /// Descriptor head to receive-buffer index, for the buffers posted.
    rx_slot_for_head: [u16; RX_BUFFERS as usize],
    /// The transmit buffer's page.
    tx_buffer: DmaPages,
    received: Received,
    /// Signalled by the interrupt-service thread on each interrupt of the
    /// device; a write waits on it for its completion.
    wake: u64,
    /// The IRQ cap; 0 when devmgr delivered none.
    irq_cap: u64,
    /// The client's RX notification, shared with the interrupt-service thread.
    rx_notify: Arc<Mutex<u64>>,
}

impl Console
{
    /// Post receive buffer `slot` to the receive queue.
    fn post_rx(&mut self, slot: u16)
    {
        let addr = self.rx_buffers.addr + u64::from(slot) * RX_BUFFER_BYTES as u64;
        if let Some(head) = self.rx.vq.add_chain(&[(addr, RX_BUFFER_LEN, true)])
        {
            self.rx_slot_for_head[usize::from(head)] = slot;
        }
    }

    /// Move the bytes of every filled receive buffer into `received` while it
    /// has room for a whole buffer, re-posting each; notify the device when
    /// any buffer went back to it.
    fn drain_rx(&mut self)
    {
        let mut reposted = false;
        while self.received.free() >= RX_BUFFER_BYTES
        {
            let (head, len) = match self.rx.vq.poll_used()
            {
                Ok(Some(used)) => used,
                Ok(None) => break,
                // A used element naming no posted buffer: consumed, nothing
                // to copy.
                Err(_) => continue,
            };
            // poll_used returns only outstanding heads, below the queue size
            // of at most RX_BUFFERS.
            let slot = self.rx_slot_for_head[usize::from(head)];
            let base = self.rx_buffers.va + u64::from(slot) * RX_BUFFER_BYTES as u64;
            // The length is device-written: clamp it to the buffer.
            let len = usize::try_from(len).map_or(RX_BUFFER_BYTES, |l| l.min(RX_BUFFER_BYTES));
            // SAFETY: the buffer lies inside the mapped receive page
            // (slot < RX_BUFFERS, and the page holds RX_BUFFERS buffers); the
            // device has returned it, and poll_used's acquire fence ordered
            // its writes before this read.
            let bytes = unsafe { core::slice::from_raw_parts(base as *const u8, len) };
            self.received.push(bytes);
            self.post_rx(slot);
            reposted = true;
        }
        if reposted
        {
            self.transport.notify(self.rx.index, self.rx.notify_off);
        }
    }

    /// Send `bytes` (at most [`MAX_MESSAGE_BYTES`]) through the transmit
    /// queue and wait until the device has taken them. The wait has no
    /// bound: like a UART's transmit register, the port takes bytes as fast
    /// as its far end does.
    fn write(&mut self, bytes: &[u8])
    {
        if bytes.is_empty()
        {
            return;
        }
        let n = bytes.len().min(MAX_MESSAGE_BYTES);
        // At most MAX_MESSAGE_BYTES, so the conversion cannot fail.
        let len = u32::try_from(n).unwrap_or(0);
        // SAFETY: the transmit page is mapped writable for the driver's life
        // and holds MAX_MESSAGE_BYTES; no transmission is in flight, since
        // the previous write waited for its completion, so the device is not
        // reading it.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.tx_buffer.va as *mut u8, n);
        }
        let Some(head) = self.tx.vq.add_chain(&[(self.tx_buffer.addr, len, false)])
        else
        {
            return;
        };
        self.transport.notify(self.tx.index, self.tx.notify_off);
        loop
        {
            match self.tx.vq.poll_used()
            {
                Ok(Some((done, _))) if done == head => return,
                // Another element (none is outstanding but this write's) or
                // one naming no posted chain: consumed; look again.
                Ok(Some(_)) | Err(_) =>
                {}
                Ok(None) =>
                {
                    let _ = syscall::notification_wait_timeout(self.wake, TX_POLL_MS);
                }
            }
        }
    }

    /// Serve one request. Every cap the request carries and the driver does
    /// not keep (all of them but an accepted RX notification) is deleted
    /// before the reply, so no request leaves a slot taken.
    fn handle(&mut self, msg: &IpcMessage, ipc_buf: *mut u64)
    {
        let op = msg.label & 0xFFFF;
        let authorized = virtio_console::authorized(msg.label, msg.badge);
        let kept = usize::from(authorized && op == serial_labels::SERIAL_REGISTER_RX_NOTIFY);
        for &cap in msg.caps().iter().skip(kept)
        {
            let _ = syscall::cap_delete(cap);
        }
        let reply = if !authorized
        {
            IpcMessage::new(serial_errors::UNAUTHORIZED)
        }
        else if op == serial_labels::SERIAL_WRITE_BYTES
        {
            // The mask bounds the length to 16 bits; it clamps to the bytes
            // the message carries.
            let byte_len = usize::try_from((msg.label >> 16) & 0xFFFF).unwrap_or(0);
            let bytes = msg.data_bytes();
            self.write(&bytes[..byte_len.min(bytes.len())]);
            IpcMessage::new(serial_errors::SUCCESS)
        }
        else if op == serial_labels::SERIAL_READ_BYTES
        {
            self.drain_rx();
            let mut buf = [0u8; MAX_MESSAGE_BYTES];
            let n = self.received.pop(&mut buf);
            // A read may have left buffers the queue had no room for; take
            // them now that it has.
            self.drain_rx();
            IpcMessage::builder(serial_errors::SUCCESS | ((n as u64) << 16))
                .bytes(0, &buf[..n])
                .build()
        }
        else if op == serial_labels::SERIAL_REGISTER_RX_NOTIFY
        {
            self.register_rx_notify(msg.caps().first().copied().unwrap_or(0))
        }
        else
        {
            IpcMessage::new(serial_errors::UNKNOWN_OPCODE)
        };
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    }

    /// Have the interrupt-service thread signal `notification` on each
    /// interrupt from now on, replacing (and deleting) an earlier one.
    /// Refused when no IRQ cap was delivered, since nothing would signal it,
    /// or when no notification came.
    fn register_rx_notify(&mut self, notification: u64) -> IpcMessage
    {
        if self.irq_cap == 0 || notification == 0
        {
            if notification != 0
            {
                let _ = syscall::cap_delete(notification);
            }
            return IpcMessage::new(serial_errors::REGISTER_FAILED);
        }
        // The lock is held across the delete, so the interrupt-service thread
        // never sends on the old cap's slot once it is deleted or reused.
        let mut client = self
            .rx_notify
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let old = core::mem::replace(&mut *client, notification);
        if old != 0
        {
            let _ = syscall::cap_delete(old);
        }
        IpcMessage::new(serial_errors::SUCCESS)
    }
}

// ── Interrupt service ───────────────────────────────────────────────────────

/// Serve the device's line forever, as `virtio_core::isr::serve_interrupts`
/// does (a bounded wait, the ISR read, the acknowledgement of each
/// delivery), signalling both `wake` and, once a client has registered one,
/// its RX notification.
fn serve_interrupts(
    transport: &PciTransport,
    irq_notification: u64,
    irq_cap: u64,
    wake: u64,
    rx_notify: &Mutex<u64>,
) -> !
{
    let mut guard = ipc::recv_guard::RecvGuard::new(isr_diag);
    loop
    {
        let delivered = match syscall::notification_wait_timeout(
            irq_notification,
            virtio_core::isr::ISR_POLL_MS,
        )
        {
            // Ok(0) is a timeout: notification_send rejects zero-bit sends.
            Ok(bits) =>
            {
                guard.on_success();
                bits != 0
            }
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        let step = virtio_core::isr::isr_step(delivered, transport.read_isr());
        if step.ack
        {
            let _ = syscall::irq_ack(irq_cap);
        }
        if step.signal
        {
            let _ = syscall::notification_send(wake, 1);
            // Sent under the lock, so a registration cannot delete the cap
            // between the read of its slot and the send.
            let client = rx_notify.lock().unwrap_or_else(PoisonError::into_inner);
            if *client != 0
            {
                let _ = syscall::notification_send(*client, 1);
            }
        }
    }
}

/// Diagnostic hook of the interrupt-service loop's `RecvGuard`.
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

/// Diagnostic hook of the service loop's `RecvGuard`.
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

/// Create a notification object.
fn create_notification() -> Option<u64>
{
    std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
        syscall::cap_create_notification(slab).ok()
    })
}

/// Bind the IRQ to a fresh notification and start the interrupt-service
/// thread over it, with its own transport over the same register window.
fn start_interrupts(
    caps: &DriverCaps,
    window_va: u64,
    layout: &RegisterLayout,
    wake: u64,
    rx_notify: &Arc<Mutex<u64>>,
)
{
    let irq_cap = caps.irq_slot;
    let Some(irq_notification) = create_notification()
    else
    {
        fail("failed to create IRQ notification");
    };
    if syscall::irq_register(irq_cap, irq_notification, caps.irq_mode).is_err()
    {
        fail("irq_register failed");
    }
    let transport = PciTransport::new(window_va, layout);
    let rx_notify = Arc::clone(rx_notify);
    let started = std::thread::Builder::new()
        .spawn(move || serve_interrupts(&transport, irq_notification, irq_cap, wake, &rx_notify))
        .is_ok();
    if !started
    {
        fail("failed to start the interrupt-service thread");
    }
    // irq_register leaves the entry masked; the first ack unmasks it.
    let _ = syscall::irq_ack(irq_cap);
}

fn service_loop(service_ep: u64, ipc_buf: *mut u64, console: &mut Console) -> !
{
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
        console.handle(&msg, ipc_buf);
    }
}

// ── Entry point ─────────────────────────────────────────────────────────────

fn main() -> !
{
    std::os::seraph::log::register_name(b"virtio-console");
    let info = startup_info();

    // cast_ptr_alignment: IPC buffer page is 4 KiB-aligned, stricter than u64.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(caps) = bootstrap_caps(info, ipc_buf)
    else
    {
        syscall::thread_exit();
    };
    if caps.memmgr_ep == 0 || caps.devmgr_ep == 0 || caps.service_ep == 0
    {
        fail("missing memmgr, devmgr, or service endpoint");
    }

    let pci_info = query_device_info(caps.devmgr_ep, ipc_buf);
    let Some(layout) = pci_info.register_layout()
    else
    {
        fail("device presents no complete set of register regions");
    };
    let window_va = map_register_window(&caps, &layout);
    let transport = PciTransport::new(window_va, &layout);
    init_device(&transport);

    let rx = setup_queue(&transport, &caps, RX_QUEUE, RX_BUFFERS, ipc_buf);
    let tx = setup_queue(&transport, &caps, TX_QUEUE, TX_QUEUE_SIZE, ipc_buf);
    let rx_buffers = dma_pages(&caps, 1, "receive buffers", ipc_buf);
    let tx_buffer = dma_pages(&caps, 1, "transmit buffer", ipc_buf);
    let Some(wake) = create_notification()
    else
    {
        fail("failed to create notification");
    };
    let rx_notify = Arc::new(Mutex::new(0));

    let mut console = Console {
        transport,
        rx,
        tx,
        rx_buffers,
        rx_slot_for_head: [0; RX_BUFFERS as usize],
        tx_buffer,
        received: Received::new(),
        wake,
        irq_cap: caps.irq_slot,
        rx_notify,
    };
    for slot in 0..console.rx.vq.queue_size()
    {
        console.post_rx(slot);
    }
    console
        .transport
        .set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);

    // The IRQ is optional: with none, a write's wait is a timed poll and a
    // client's RX wait relies on its own bounded timeout.
    if caps.irq_slot == 0
    {
        std::os::seraph::log!("no IRQ cap; polling");
    }
    else
    {
        start_interrupts(&caps, window_va, &layout, wake, &console.rx_notify);
    }
    console
        .transport
        .notify(console.rx.index, console.rx.notify_off);

    // SAFETY: ipc_buf is the registered IPC buffer.
    if let Err(e) = unsafe { ipc::report_driver_ready(caps.devmgr_ep, ipc_buf) }
    {
        std::os::seraph::log!("DRIVER_READY failed ({e:?}); exiting");
        syscall::thread_exit();
    }
    service_loop(caps.service_ep, ipc_buf, &mut console);
}
