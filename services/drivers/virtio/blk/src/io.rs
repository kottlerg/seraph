// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/virtio/blk/src/io.rs

//! Block I/O request submission and completion for the `VirtIO` block driver.
//!
//! Provides the descriptor chain layout for `VirtIO` block read and write
//! requests (`VirtIO` 1.2 section 5.2.6) and a single submit/wait helper
//! parameterised over direction.
//!
//! `IoLayout` owns the driver's permanent 1-page DMA buffer. The request
//! header (offset 0, 16 bytes) and status byte (offset 1024, 1 byte) live
//! there permanently. The 512-byte data segment is supplied per-request by
//! the caller as a Frame cap; [`IoLayout::read_chain`] /
//! [`IoLayout::write_chain`] parameterise the data-segment physical
//! address. The driver's own page never holds bulk data.

use virtio_core::pci::PciTransport;
use virtio_core::virtqueue::SplitVirtqueue;

/// Block request type: read (`VirtIO` 1.2 section 5.2.6).
const VIRTIO_BLK_T_IN: u32 = 0;
/// Block request type: write (`VirtIO` 1.2 section 5.2.6).
const VIRTIO_BLK_T_OUT: u32 = 1;

/// Direction of a block I/O request.
#[derive(Copy, Clone)]
pub enum IoDirection
{
    /// Sector read: device DMAs data into the caller-supplied frame.
    Read,
    /// Sector write: device DMAs data out of the caller-supplied frame.
    Write,
}

/// Block request header (`VirtIO` 1.2 section 5.2.6).
#[repr(C)]
pub struct VirtioBlkReqHeader
{
    pub req_type: u32,
    pub reserved: u32,
    pub sector: u64,
}

/// Physical/virtual layout for the driver's permanent DMA page.
///
/// Hosts the request header (offset 0, 16 bytes) and status byte (offset
/// 1024, 1 byte). The 512-byte data segment is supplied per-request via
/// [`read_chain`](IoLayout::read_chain).
pub struct IoLayout
{
    /// Virtual address of the mapped page.
    pub data_va: u64,
    /// Physical address of the mapped page.
    pub data_phys: u64,
}

impl IoLayout
{
    fn header_va(&self) -> *mut VirtioBlkReqHeader
    {
        self.data_va as *mut VirtioBlkReqHeader
    }

    fn status_va(&self) -> u64
    {
        self.data_va + 1024
    }

    /// Descriptor chain for a block read request whose data segment lands at
    /// `data_phys` and is `data_len` bytes long (`data_len` must be a
    /// non-zero multiple of 512).
    ///
    /// Three-element chain: header (readable), data (writable, at the
    /// caller-supplied physical address), status (writable). The header and
    /// status segments stay in the driver's own DMA page.
    pub fn read_chain(&self, data_phys: u64, data_len: u32) -> [(u64, u32, bool); 3]
    {
        let header_phys = self.data_phys;
        let status_phys = self.data_phys + 1024;

        [
            (header_phys, 16, false),    // request header
            (data_phys, data_len, true), // data buffer (device writes)
            (status_phys, 1, true),      // status byte (device writes)
        ]
    }

    /// Descriptor chain for a block write request whose data segment is
    /// sourced from `data_phys` and is `data_len` bytes long (`data_len`
    /// must be a non-zero multiple of 512).
    ///
    /// Mirror of [`Self::read_chain`] with the data segment's writable
    /// flag flipped: the device reads from the caller-supplied frame and
    /// writes only the completion status byte in the driver's page.
    pub fn write_chain(&self, data_phys: u64, data_len: u32) -> [(u64, u32, bool); 3]
    {
        let header_phys = self.data_phys;
        let status_phys = self.data_phys + 1024;

        [
            (header_phys, 16, false),     // request header
            (data_phys, data_len, false), // data buffer (device reads)
            (status_phys, 1, true),       // status byte (device writes)
        ]
    }

    /// Prepare a read or write request for the given sector.
    ///
    /// Writes the block request header and resets the status byte.
    pub fn prepare(&self, dir: IoDirection, sector: u64)
    {
        let req_type = match dir
        {
            IoDirection::Read => VIRTIO_BLK_T_IN,
            IoDirection::Write => VIRTIO_BLK_T_OUT,
        };
        // SAFETY: header_va is within the mapped data page, properly aligned.
        unsafe {
            (*self.header_va()).req_type = req_type;
            (*self.header_va()).reserved = 0;
            (*self.header_va()).sector = sector;
        }
        // VirtIO 1.2 spec §5.2.6.1: device writes status 0 (ok), 1 (ioerr),
        // or 2 (unsupp). 0xFF is outside this range and serves as a "not yet
        // completed" sentinel. A spec-conformant device never writes 0xFF.
        // SAFETY: status_va is within the mapped data page.
        unsafe { core::ptr::write_volatile(self.status_va() as *mut u8, 0xFF) };
    }

    /// Read the device status byte after request completion.
    ///
    /// Returns 0 on success, non-zero on device error.
    pub fn read_status(&self) -> u8
    {
        // SAFETY: status_va is within the mapped data page.
        unsafe { core::ptr::read_volatile(self.status_va() as *const u8) }
    }
}

/// Maximum wait iterations before treating the request as timed out.
const MAX_WAIT_ATTEMPTS: usize = 1000;

/// Per-iteration timeout on the IRQ-signal wait, in milliseconds.
///
/// Bounded so that a lost PLIC external interrupt on QEMU virt RISC-V (see
/// the wait loop comment) cannot park this thread indefinitely: the next
/// iteration's poll-burst will observe completion regardless of whether the
/// IRQ ever fires. The actual completion time of a virtio-blk request on
/// QEMU is sub-millisecond, so a 50 ms ceiling is two orders of magnitude
/// over the expected wake and three orders under the outer-loop deadline
/// (`MAX_WAIT_ATTEMPTS * IRQ_WAIT_TIMEOUT_MS` = 50 s upper bound).
const IRQ_WAIT_TIMEOUT_MS: u64 = 50;

/// Submit a read or write request and wait for completion via IRQ signal.
///
/// `data_phys` is the physical address of the caller-supplied frame's
/// data segment (offset 0 of the frame per the `BLK_READ_INTO_FRAME` /
/// `BLK_WRITE_FROM_FRAME` contract). `data_len` is `count * 512` for
/// `count` consecutive sectors starting at `sector`; the device
/// transfers the entire run in one descriptor chain.
///
/// Blocks on a bounded `signal_wait_timeout` per iteration until the device
/// raises an interrupt or the per-iteration timeout elapses, then reads the
/// device ISR to deassert the level-triggered interrupt, acknowledges at the
/// controller for re-arming, and re-polls the used ring. The bounded wait
/// ensures that a lost PLIC external interrupt on QEMU virt RISC-V cannot
/// park this thread indefinitely — see the wait loop body for details.
// too_many_arguments: layout + direction + sector + data_phys + data_len
// + four hardware handles (virtqueue, transport, irq signal, irq cap) is
// the minimal set this path needs; bundling for the lint would obscure
// the per-call inputs (direction, sector, data_phys, data_len) that vary
// per request.
#[allow(clippy::too_many_arguments)]
pub fn submit_and_wait(
    layout: &IoLayout,
    dir: IoDirection,
    sector: u64,
    data_phys: u64,
    data_len: u32,
    vq: &mut SplitVirtqueue,
    transport: &PciTransport,
    queue_notify_off: u16,
    irq_signal: u32,
    irq_cap: u32,
) -> bool
{
    layout.prepare(dir, sector);

    let chain = match dir
    {
        IoDirection::Read => layout.read_chain(data_phys, data_len),
        IoDirection::Write => layout.write_chain(data_phys, data_len),
    };
    let Some(_head) = vq.add_chain(&chain)
    else
    {
        return false;
    };

    // VirtIO 1.2 §2.9.3 "Driver Notifications": a full memory barrier is
    // required between the avail-ring idx update (DMA memory) and the
    // notification MMIO write, so the device observes the new avail index
    // before servicing the notify. Without this the device can observe
    // notify first, find avail.idx unchanged, and not raise completion
    // IRQ. Release ordering before the idx write is already enforced inside
    // `add_chain`; this SeqCst fence pairs writes to DMA memory with the
    // subsequent MMIO write.
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    transport.notify(0, queue_notify_off);

    // Wait for completion. VirtIO-PCI INTx delivery on QEMU virt (RISC-V
    // PLIC) is occasionally not observed by any hart even though the device
    // processes the request — we have confirmed via instrumentation that
    // completion happens but the PLIC-delivered external interrupt never
    // fires. Two defenses against a lost IRQ: each iteration does a short
    // poll burst, and the per-iteration signal wait carries a bounded
    // timeout so a completion that lands between the poll burst and the
    // kernel parking the thread is recovered on the next iteration's burst
    // rather than wedging the driver forever.
    for _ in 0..MAX_WAIT_ATTEMPTS
    {
        // Poll burst before blocking. VirtIO devices typically complete in
        // microseconds; spinning for a few thousand cycles is still cheap
        // and catches the fast path without a scheduling round trip. On
        // RISC-V QEMU virt we also occasionally see IRQs that are delivered
        // to the PLIC but never picked up by the kernel (suspected TCG/PLIC
        // behaviour with concurrent claim from multiple harts); this burst
        // makes the driver tolerant of those lost IRQs.
        for _ in 0..100_000u32
        {
            if vq.poll_used().is_some()
            {
                let _ = transport.read_isr();
                let _ = syscall::irq_ack(irq_cap);
                return layout.read_status() == 0;
            }
            core::hint::spin_loop();
        }

        // No completion yet — block on the IRQ signal with a bounded timeout.
        // Ok(0) means timeout (signal_send rejects zero-bit sends, so 0 is
        // unambiguous); Ok(_) means a real wake; Err means the cap path
        // failed and there's nothing useful to do but fall through and poll.
        let _ = syscall::signal_wait_timeout(irq_signal, IRQ_WAIT_TIMEOUT_MS);

        // Read ISR to clear level-triggered interrupt at the device before
        // unmasking at the controller, preventing immediate re-delivery.
        let _ = transport.read_isr();
        let _ = syscall::irq_ack(irq_cap);

        if vq.poll_used().is_some()
        {
            return layout.read_status() == 0;
        }
    }

    // Device did not complete within bound — treat as I/O error.
    false
}
