// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/blk/src/io.rs

//! Block I/O request submission and completion for the `VirtIO` block driver.
//!
//! Provides the descriptor chain layout for `VirtIO` block read and write
//! requests (`VirtIO` 1.2 section 5.2.6) and a single submit/wait helper
//! parameterised over direction.
//!
//! `IoLayout` owns the driver's permanent 1-page DMA buffer. The request
//! header (offset 0, 16 bytes) and status byte (offset 1024, 1 byte) live
//! there permanently. The data segment, `count * block_size` bytes for a
//! request of `count` logical blocks, is supplied per-request by the caller
//! as a Memory cap; [`IoLayout::read_chain`] / [`IoLayout::write_chain`] parameterise
//! the data segment's device address and length. Every address a chain
//! carries is a device address devmgr returned for the frames
//! (`virtio_core::dma`), never a physical one. The driver's own page never
//! holds bulk data.

use std::time::{Duration, Instant};

use virtio_blk::IoOutcome;
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
    /// Sector read: device DMAs data into the caller-supplied memory cap.
    Read,
    /// Sector write: device DMAs data out of the caller-supplied memory cap.
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

/// Device-address/virtual layout for the driver's permanent DMA page.
///
/// Hosts the request header (offset 0, 16 bytes) and status byte (offset
/// 1024, 1 byte). The data segment, `count * block_size` bytes for a request
/// of `count` logical blocks, is supplied per-request (address and length) via
/// [`read_chain`](IoLayout::read_chain) and
/// [`write_chain`](IoLayout::write_chain).
pub struct IoLayout
{
    /// Virtual address of the mapped page.
    data_va: u64,
    /// Device address of the mapped page, as devmgr returned it.
    data_addr: u64,
    /// Virtual address of the status byte.
    status_va: u64,
    /// Device address of the status byte.
    status_addr: u64,
}

/// Offset of the status byte in the driver's DMA page.
const STATUS_OFFSET: u64 = 1024;

impl IoLayout
{
    /// The layout of the page mapped at `data_va` and, for the device, at
    /// `data_addr`. `None` when the status byte's address is past `u64`.
    pub fn new(data_va: u64, data_addr: u64) -> Option<Self>
    {
        Some(Self {
            data_va,
            data_addr,
            status_va: data_va.checked_add(STATUS_OFFSET)?,
            status_addr: data_addr.checked_add(STATUS_OFFSET)?,
        })
    }

    fn header_va(&self) -> *mut VirtioBlkReqHeader
    {
        self.data_va as *mut VirtioBlkReqHeader
    }

    /// Descriptor chain for a block read request whose data segment lands at
    /// `data_addr` and is `data_len` bytes long (`data_len` must be a
    /// non-zero multiple of the logical block size).
    ///
    /// Three-element chain: header (readable), data (writable, at the
    /// data segment's device address), status (writable). The header and
    /// status segments stay in the driver's own DMA page.
    pub fn read_chain(&self, data_addr: u64, data_len: u32) -> [(u64, u32, bool); 3]
    {
        [
            (self.data_addr, 16, false), // request header
            (data_addr, data_len, true), // data buffer (device writes)
            (self.status_addr, 1, true), // status byte (device writes)
        ]
    }

    /// Descriptor chain for a block write request whose data segment is
    /// sourced from `data_addr` and is `data_len` bytes long (`data_len`
    /// must be a non-zero multiple of the logical block size).
    ///
    /// Mirror of [`Self::read_chain`] with the data segment's writable
    /// flag flipped: the device reads from the caller-supplied memory cap and
    /// writes only the completion status byte in the driver's page.
    pub fn write_chain(&self, data_addr: u64, data_len: u32) -> [(u64, u32, bool); 3]
    {
        [
            (self.data_addr, 16, false),  // request header
            (data_addr, data_len, false), // data buffer (device reads)
            (self.status_addr, 1, true),  // status byte (device writes)
        ]
    }

    /// Prepare a read or write request starting at `VirtIO` sector `sector`
    /// (512-byte units, whatever the logical block size).
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
        unsafe { core::ptr::write_volatile(self.status_va as *mut u8, 0xFF) };
    }

    /// Read the device status byte after request completion: a `VirtIO`
    /// status (`VIRTIO_BLK_S_*`), or the 0xFF sentinel `prepare` wrote when
    /// the device wrote none.
    pub fn read_status(&self) -> u8
    {
        // SAFETY: status_va is within the mapped data page.
        unsafe { core::ptr::read_volatile(self.status_va as *const u8) }
    }
}

/// How long a request may take before it is treated as timed out, measured
/// on the monotonic clock: a wait that returns early (a stop and restart
/// interrupts it) costs a re-poll, not part of the budget. A tuning value
/// that bounds no capacity: it decides only when a lost request is given up
/// on.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(50);

/// Submit a read or write request and wait for its completion via the
/// completion notification, returning how the request ended.
///
/// [`IoOutcome::Completed`] carries the status byte of the completion of the
/// submitted chain. [`IoOutcome::NotQueued`] means the chain never reached
/// the device. [`IoOutcome::Lost`] means no completion of the submitted chain
/// arrived within [`REQUEST_TIMEOUT`], or the used ring published one the
/// virtqueue refused or one naming another chain: the request may still be
/// in flight, and the caller must quiesce the device before it gives the data
/// segment's Memory cap back.
///
/// `data_addr` is the device address devmgr returned for the caller-supplied memory cap's
/// data segment (offset 0 of the memory cap per the `BLK_READ_INTO_MEMORY` /
/// `BLK_WRITE_FROM_MEMORY` contract). `data_len` is `count * block_size`
/// for `count` consecutive logical blocks starting at `VirtIO` sector
/// `sector`; the device transfers the entire run in one descriptor chain.
///
/// Polls the used ring, then waits on `completion` for what is left of
/// [`REQUEST_TIMEOUT`] ([`virtio_blk::completion_wait_ms`]) until the
/// interrupt-service thread signals an interrupt (it has already read the
/// ISR and acknowledged a wired line's delivery), and polls again. The
/// notification keeps a signal sent before the wait, so a completion that
/// lands between the poll and the wait ends the wait at once.
// too_many_arguments: layout + direction + sector + data_addr + data_len
// + three hardware handles (virtqueue, transport, completion notification) is
// the minimal set this path needs; bundling for the lint would obscure
// the per-call inputs (direction, sector, data_addr, data_len) that vary
// per request.
#[allow(clippy::too_many_arguments)]
pub fn submit_and_wait(
    layout: &IoLayout,
    dir: IoDirection,
    sector: u64,
    data_addr: u64,
    data_len: u32,
    vq: &mut SplitVirtqueue,
    transport: &PciTransport,
    queue_notify_off: u16,
    completion: u64,
) -> IoOutcome
{
    layout.prepare(dir, sector);

    let chain = match dir
    {
        IoDirection::Read => layout.read_chain(data_addr, data_len),
        IoDirection::Write => layout.write_chain(data_addr, data_len),
    };
    let Some(head) = vq.add_chain(&chain)
    else
    {
        return IoOutcome::NotQueued;
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

    let start = Instant::now();
    loop
    {
        if let Some(outcome) = completed(vq, head, layout)
        {
            return outcome;
        }
        let Some(wait_ms) = virtio_blk::completion_wait_ms(REQUEST_TIMEOUT, start.elapsed())
        else
        {
            // No completion within the bound: the request may still be in
            // flight.
            return IoOutcome::Lost;
        };
        // Ok(0) is a timeout, after which the next poll and the bound decide;
        // Err means the cap path failed, and polling until the bound is all
        // that is left.
        let _ = syscall::notification_wait_timeout(completion, wait_ms);
    }
}

/// Poll the used ring once for the completion of the chain at `head`.
///
/// `None` while the device has published nothing. The driver keeps one
/// request outstanding, so any published element other than a valid
/// completion of `head` (one the virtqueue refuses, or one naming another
/// chain) is a device fault and ends the request as [`IoOutcome::Lost`].
fn completed(vq: &mut SplitVirtqueue, head: u16, layout: &IoLayout) -> Option<IoOutcome>
{
    match vq.poll_used()
    {
        Ok(None) => None,
        Ok(Some((done, _len))) if done == head => Some(IoOutcome::Completed {
            status: layout.read_status(),
        }),
        Ok(Some(_)) | Err(_) => Some(IoOutcome::Lost),
    }
}
