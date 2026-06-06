// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/virtio/input/src/input.rs

//! virtio-input event-queue buffer management.
//!
//! The eventq (virtqueue 0) is device-to-driver: the driver posts empty,
//! device-writable buffers and the device fills one [`VirtioInputEvent`] per
//! buffer as input arrives (`VirtIO` 1.2 §5.8). [`EventRing`] owns the
//! contiguous DMA page holding those buffers and the descriptor-head →
//! buffer-slot map needed to find the filled buffer on completion and re-post
//! it. The statusq (virtqueue 1, LED/feedback) is not implemented — out of
//! scope for a v0.1.0 keyboard.

use virtio_core::virtqueue::SplitVirtqueue;

/// virtio-input event type: key press/release (`EV_KEY`, Linux `input.h`).
pub const EV_KEY: u16 = 1;

/// Number of eventq buffers the driver requests (capped to the device max in
/// `configure_queue_size`). One descriptor and one 8-byte buffer per entry; at
/// 64 entries the buffers occupy 512 bytes, well within a single DMA page.
pub const EVENT_QUEUE_SIZE: u16 = 64;

/// Bytes per virtio-input event buffer (`size_of::<VirtioInputEvent>()`).
const EVENT_SIZE: u32 = 8;

/// A virtio-input event (`VirtIO` 1.2 §5.8.6.2). Both target arches are
/// little-endian and the device runs modern (`VIRTIO_F_VERSION_1`), so the
/// little-endian fields are read directly.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtioInputEvent
{
    pub event_type: u16,
    pub code: u16,
    pub value: u32,
}

/// Owns the eventq receive buffers and maps completed descriptor heads back to
/// their buffer slots.
pub struct EventRing
{
    base_va: u64,
    base_phys: u64,
    buf_count: u16,
    /// Descriptor-head index → buffer slot. Indexed by the head returned from
    /// `add_chain`/`poll_used` (always `< queue_size <= EVENT_QUEUE_SIZE`).
    slot_for_head: [u16; EVENT_QUEUE_SIZE as usize],
}

impl EventRing
{
    /// Create a ring over a mapped DMA page. `buf_count` buffers of
    /// `EVENT_SIZE` bytes are carved from `[base_va, base_phys)`; the caller
    /// guarantees the page holds `buf_count * EVENT_SIZE` bytes and that
    /// `buf_count <= EVENT_QUEUE_SIZE`.
    #[must_use]
    pub fn new(base_va: u64, base_phys: u64, buf_count: u16) -> Self
    {
        Self {
            base_va,
            base_phys,
            buf_count,
            slot_for_head: [0; EVENT_QUEUE_SIZE as usize],
        }
    }

    /// Post every buffer to the eventq as a device-writable descriptor. Call
    /// once at init; the device then fills buffers as input events arrive.
    pub fn post_all(&mut self, vq: &mut SplitVirtqueue)
    {
        for slot in 0..self.buf_count
        {
            self.post(vq, slot);
        }
    }

    /// Pull one filled event off the used ring, re-posting its buffer. Returns
    /// `None` when the used ring is empty.
    pub fn drain(&mut self, vq: &mut SplitVirtqueue) -> Option<VirtioInputEvent>
    {
        let (head, _len) = vq.poll_used()?;
        let slot = self.slot_for_head[head as usize];
        let event = self.read_event(slot);
        self.post(vq, slot);
        Some(event)
    }

    /// Post buffer `slot` to the eventq and record its descriptor head. A full
    /// queue drops the buffer from rotation; the remaining buffers keep the
    /// device serviceable.
    fn post(&mut self, vq: &mut SplitVirtqueue, slot: u16)
    {
        let phys = self.base_phys + u64::from(slot) * u64::from(EVENT_SIZE);
        if let Some(head) = vq.add_chain(&[(phys, EVENT_SIZE, true)])
        {
            self.slot_for_head[head as usize] = slot;
        }
    }

    fn read_event(&self, slot: u16) -> VirtioInputEvent
    {
        let addr = self.base_va + u64::from(slot) * u64::from(EVENT_SIZE);
        // SAFETY: slot < buf_count, so addr is within the mapped DMA page and
        // 8-byte aligned (page-aligned base + 8-byte stride). Volatile: the
        // buffer was written by the device; poll_used's acquire fence ordered
        // that write before this read.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            core::ptr::read_volatile(addr as *const VirtioInputEvent)
        }
    }
}
