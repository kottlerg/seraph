// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/virtio/blk/src/io.rs

//! Block I/O request submission and completion for the `VirtIO` block driver.
//!
//! Provides the descriptor chain layout for `VirtIO` block read requests
//! (`VirtIO` 1.2 section 5.2.6), and helpers for submitting sector reads and copying
//! completed data into the IPC reply buffer.

use virtio_core::pci::PciTransport;
use virtio_core::virtqueue::SplitVirtqueue;

/// Block request type: read (`VirtIO` 1.2 section 5.2.6).
const VIRTIO_BLK_T_IN: u32 = 0;

/// Block request header (`VirtIO` 1.2 section 5.2.6).
#[repr(C)]
pub struct VirtioBlkReqHeader
{
    pub req_type: u32,
    pub reserved: u32,
    pub sector: u64,
}

/// Physical/virtual layout for a single block I/O data page.
///
/// The data page is carved into three regions: request header (offset 0),
/// sector data buffer (offset 512), and status byte (offset 1024).
pub struct IoLayout
{
    /// Virtual address of the mapped data page.
    pub data_va: u64,
    /// Physical address of the mapped data page.
    pub data_phys: u64,
}

impl IoLayout
{
    fn header_va(&self) -> *mut VirtioBlkReqHeader
    {
        self.data_va as *mut VirtioBlkReqHeader
    }

    fn data_buf_va(&self) -> u64
    {
        self.data_va + 512
    }

    fn status_va(&self) -> u64
    {
        self.data_va + 1024
    }

    /// Descriptor chain for a block read request.
    ///
    /// Three-element chain: header (readable), data (writable), status (writable).
    pub fn read_chain(&self) -> [(u64, u32, bool); 3]
    {
        let header_phys = self.data_phys;
        let data_buf_phys = self.data_phys + 512;
        let status_phys = self.data_phys + 1024;

        [
            (header_phys, 16, false),   // request header
            (data_buf_phys, 512, true), // data buffer (device writes)
            (status_phys, 1, true),     // status byte (device writes)
        ]
    }

    /// Prepare a read request for the given sector.
    ///
    /// Writes the block request header and resets the status byte.
    pub fn prepare_read(&self, sector: u64)
    {
        // SAFETY: header_va is within the mapped data page, properly aligned.
        unsafe {
            (*self.header_va()).req_type = VIRTIO_BLK_T_IN;
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

    /// Copy the 512-byte sector data into a stack-owned 64-word array.
    ///
    /// Volatile reads pull from the DMA data buffer; the returned array is
    /// plain memory suitable for packing into an [`ipc::IpcMessage`].
    #[must_use]
    pub fn sector_words(&self) -> [u64; 64]
    {
        let mut out = [0u64; 64];
        let buf_va = self.data_buf_va();
        for (i, slot) in out.iter_mut().enumerate()
        {
            // SAFETY: buf_va + i*8 is within the mapped data page (one page,
            // 64 * 8 = 512 bytes read starting at offset 512).
            *slot = unsafe { core::ptr::read_volatile((buf_va + (i as u64) * 8) as *const u64) };
        }
        out
    }
}

/// Maximum `signal_wait` iterations before treating the request as timed out.
const MAX_WAIT_ATTEMPTS: usize = 1000;

/// Submit a read request and wait for completion via IRQ signal.
///
/// Blocks on `signal_wait` until the device raises an interrupt, reads the
/// device ISR to deassert the level-triggered interrupt, then acknowledges
/// at the controller for re-arming.
pub fn submit_and_wait(
    layout: &IoLayout,
    sector: u64,
    vq: &mut SplitVirtqueue,
    transport: &PciTransport,
    queue_notify_off: u16,
    irq_signal: u32,
    irq_cap: u32,
) -> bool
{
    layout.prepare_read(sector);

    let chain = layout.read_chain();
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
    // fires. To stay robust without pure polling, each wait iteration does
    // a short poll burst first (catching device-faster-than-schedule cases
    // and IRQ-lost cases both), and only blocks on the signal afterwards.
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
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
            if vq.poll_used().is_some()
            {
                let _ = transport.read_isr();
                let _ = syscall::irq_ack(irq_cap);
                return layout.read_status() == 0;
            }
            core::hint::spin_loop();
        }

        // No completion yet — block until the IRQ fires, then re-check.
        let _ = syscall::signal_wait(irq_signal);

        // Read ISR to clear level-triggered interrupt at the device before
        // unmasking at the controller, preventing immediate re-delivery.
        let _ = transport.read_isr();
        let _ = syscall::irq_ack(irq_cap);

        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);

        if vq.poll_used().is_some()
        {
            return layout.read_status() == 0;
        }
    }

    // Device did not complete within bound — treat as I/O error.
    false
}
