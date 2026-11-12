// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/input/src/input.rs

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

/// Buffer `slot`'s offset in the event page.
fn slot_offset(slot: u16) -> u64
{
    // `slot` is below EVENT_QUEUE_SIZE, whose buffers fit one page: no
    // saturation.
    u64::from(slot).saturating_mul(u64::from(EVENT_SIZE))
}

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
    /// Device address of the page, as devmgr returned it.
    base_addr: u64,
    buf_count: u16,
    /// Descriptor-head index → buffer slot. Indexed by the head returned from
    /// `add_chain`/`poll_used` (always `< queue_size <= EVENT_QUEUE_SIZE`).
    slot_for_head: [u16; EVENT_QUEUE_SIZE as usize],
}

impl EventRing
{
    /// Create a ring over a mapped DMA page whose virtual address is `base_va`
    /// and whose device address is `base_addr`. `buf_count` buffers of
    /// `EVENT_SIZE` bytes are carved from it; the caller
    /// guarantees the page holds `buf_count * EVENT_SIZE` bytes and that
    /// `buf_count <= EVENT_QUEUE_SIZE`.
    #[must_use]
    pub fn new(base_va: u64, base_addr: u64, buf_count: u16) -> Self
    {
        Self {
            base_va,
            base_addr,
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
    ///
    /// A used element `poll_used` refuses (an id heading no outstanding
    /// chain) is skipped: it names no buffer this ring posted, and the free
    /// list is untouched.
    pub fn drain(&mut self, vq: &mut SplitVirtqueue) -> Option<VirtioInputEvent>
    {
        loop
        {
            match vq.poll_used()
            {
                Ok(Some((head, _len))) =>
                {
                    // poll_used returns only outstanding heads, which add_chain
                    // handed out below queue_size <= EVENT_QUEUE_SIZE, so the
                    // entry exists.
                    let Some(&slot) = self.slot_for_head.get(usize::from(head))
                    else
                    {
                        continue;
                    };
                    let event = self.read_event(slot);
                    self.post(vq, slot);
                    return Some(event);
                }
                Ok(None) => return None,
                Err(_) =>
                {}
            }
        }
    }

    /// Post buffer `slot` to the eventq and record its descriptor head. A full
    /// queue drops the buffer from rotation; the remaining buffers keep the
    /// device serviceable.
    fn post(&mut self, vq: &mut SplitVirtqueue, slot: u16)
    {
        // The page's device range holds every buffer: no saturation.
        let addr = self.base_addr.saturating_add(slot_offset(slot));
        if let Some(head) = vq.add_chain(&[(addr, EVENT_SIZE, true)])
            && let Some(entry) = self.slot_for_head.get_mut(usize::from(head))
        {
            // add_chain returns a head below queue_size <= EVENT_QUEUE_SIZE,
            // so the entry exists.
            *entry = slot;
        }
    }

    fn read_event(&self, slot: u16) -> VirtioInputEvent
    {
        // The page's mapping holds every buffer: no saturation.
        let addr = self.base_va.saturating_add(slot_offset(slot));
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
