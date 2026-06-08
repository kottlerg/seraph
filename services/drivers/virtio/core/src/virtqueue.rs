// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/virtio/core/src/virtqueue.rs

//! Split virtqueue implementation (`VirtIO` 1.2 §2.7).
//!
//! Manages the descriptor table, available ring, and used ring for a single
//! split virtqueue. The caller is responsible for allocating DMA-capable
//! memory and providing physical addresses.

/// Maximum supported queue size. QEMU `virtio-blk` defaults to 256.
pub const MAX_QUEUE_SIZE: u16 = 256;

/// Descriptor flags: next descriptor in chain.
pub const VRING_DESC_F_NEXT: u16 = 1;
/// Descriptor flags: buffer is device-writable (device reads: host-readable).
pub const VRING_DESC_F_WRITE: u16 = 2;

/// Single virtqueue descriptor (`VirtIO` 1.2 §2.7.5).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtqDesc
{
    /// Physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// Descriptor flags (`VRING_DESC_F_*`).
    pub flags: u16,
    /// Index of the next descriptor in the chain (if `VRING_DESC_F_NEXT` set).
    pub next: u16,
}

/// Available ring header (`VirtIO` 1.2 §2.7.6).
///
/// Immediately followed by `ring: [u16; queue_size]`.
#[repr(C)]
pub struct VirtqAvail
{
    pub flags: u16,
    pub idx: u16,
    // ring[queue_size] follows.
}

/// Used ring element (`VirtIO` 1.2 §2.7.8).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtqUsedElem
{
    /// Index of the head descriptor of the completed chain.
    pub id: u32,
    /// Total bytes written by the device into the buffers.
    pub len: u32,
}

/// Used ring header (`VirtIO` 1.2 §2.7.8).
///
/// Immediately followed by `ring: [VirtqUsedElem; queue_size]`.
#[repr(C)]
pub struct VirtqUsed
{
    pub flags: u16,
    pub idx: u16,
    // ring[queue_size] follows.
}

/// Split virtqueue manager.
///
/// Tracks descriptor allocation, available ring submission, and used ring
/// consumption. All ring memory is provided by the caller as raw pointers
/// to DMA-capable pages.
pub struct SplitVirtqueue
{
    /// Virtual address of the descriptor table.
    desc_va: *mut VirtqDesc,
    /// Virtual address of the available ring.
    avail_va: *mut VirtqAvail,
    /// Virtual address of the used ring.
    used_va: *mut VirtqUsed,
    /// Queue size (number of descriptors).
    queue_size: u16,
    /// Next free descriptor index for allocation.
    free_head: u16,
    /// Number of free descriptors.
    num_free: u16,
    /// Last seen used ring index (for polling completions).
    last_used_idx: u16,
}

impl SplitVirtqueue
{
    /// Initialise a virtqueue over pre-allocated DMA memory.
    ///
    /// # Safety
    ///
    /// - `desc_va` must point to `queue_size * 16` bytes of zeroed, DMA-capable memory,
    ///   aligned to `align_of::<VirtqDesc>()`.
    /// - `avail_va` must point to `4 + 2 * queue_size` bytes of zeroed, DMA-capable memory,
    ///   aligned to `align_of::<VirtqAvail>()`.
    /// - `used_va` must point to `4 + 8 * queue_size` bytes of zeroed, DMA-capable memory,
    ///   aligned to `align_of::<VirtqUsed>()`.
    /// - All three regions must not overlap and must remain valid for the virtqueue's lifetime.
    #[must_use]
    pub unsafe fn new(
        desc_va: *mut VirtqDesc,
        avail_va: *mut VirtqAvail,
        used_va: *mut VirtqUsed,
        queue_size: u16,
    ) -> Self
    {
        // Build free descriptor chain: each descriptor's `next` points to the
        // following one.
        for i in 0..queue_size
        {
            // SAFETY: i < queue_size; caller guarantees desc_va points to a table of queue_size entries.
            let desc = unsafe { desc_va.add(i as usize) };
            // SAFETY: desc is within the descriptor table allocation.
            unsafe {
                (*desc).next = i + 1;
                (*desc).flags = 0;
            }
        }

        Self {
            desc_va,
            avail_va,
            used_va,
            queue_size,
            free_head: 0,
            num_free: queue_size,
            last_used_idx: 0,
        }
    }

    /// Allocate a single descriptor from the free list.
    ///
    /// Returns the descriptor index, or `None` if no descriptors are free.
    fn alloc_desc(&mut self) -> Option<u16>
    {
        if self.num_free == 0
        {
            return None;
        }
        let idx = self.free_head;
        // SAFETY: idx is a valid descriptor index (was in the free chain).
        let desc = unsafe { &*self.desc_va.add(idx as usize) };
        self.free_head = desc.next;
        self.num_free -= 1;
        Some(idx)
    }

    /// Return a descriptor to the free list.
    fn free_desc(&mut self, idx: u16)
    {
        // SAFETY: idx is a valid descriptor index; desc_va is within the DMA
        // descriptor table. Volatile: DMA-shared with the device.
        unsafe {
            let desc = self.desc_va.add(idx as usize);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc).flags), 0);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc).next), self.free_head);
        }
        self.free_head = idx;
        self.num_free += 1;
    }

    /// Submit a descriptor chain to the available ring.
    ///
    /// `bufs` is a slice of (`physical_addr`, `length`, `device_writable`) tuples.
    /// Returns the head descriptor index for tracking completion, or `None`
    /// if there aren't enough free descriptors.
    #[allow(clippy::cast_possible_truncation)]
    pub fn add_chain(&mut self, bufs: &[(u64, u32, bool)]) -> Option<u16>
    {
        if bufs.is_empty() || self.num_free < bufs.len() as u16
        {
            return None;
        }

        let head = self.alloc_desc()?;
        let mut prev = head;

        for (i, &(addr, len, writable)) in bufs.iter().enumerate()
        {
            let idx = if i == 0 { head } else { self.alloc_desc()? };
            // SAFETY: idx and prev are valid descriptor indices; desc_va is the
            // DMA descriptor table. Volatile: prevents dead-store elimination
            // across free_desc/add_chain and ensures device sees writes in order.
            unsafe {
                let desc = self.desc_va.add(idx as usize);
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc).addr), addr);
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc).len), len);
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!((*desc).flags),
                    if writable { VRING_DESC_F_WRITE } else { 0 },
                );

                if i > 0
                {
                    let prev_desc = self.desc_va.add(prev as usize);
                    let old_flags =
                        core::ptr::read_volatile(core::ptr::addr_of!((*prev_desc).flags));
                    core::ptr::write_volatile(
                        core::ptr::addr_of_mut!((*prev_desc).flags),
                        old_flags | VRING_DESC_F_NEXT,
                    );
                    core::ptr::write_volatile(core::ptr::addr_of_mut!((*prev_desc).next), idx);
                }
            }
            prev = idx;
        }

        // Add head to available ring.
        // SAFETY: avail_va is valid; ring entry is within bounds.
        unsafe {
            // cast_ptr_alignment: VirtqAvail is 2-byte aligned; offset 4 from
            // a 2-byte-aligned base maintains u16 alignment.
            #[allow(clippy::cast_ptr_alignment)]
            let ring_base = self.avail_va.cast::<u8>().add(4).cast::<u16>();

            // Read avail.idx with read_volatile — the field is shared with the
            // device and was last updated via write_volatile; a non-volatile
            // read could return a stale cached value on repeated add_chain calls.
            let cur_idx = core::ptr::read_volatile(core::ptr::addr_of!((*self.avail_va).idx));
            let ring_idx = cur_idx % self.queue_size;
            core::ptr::write_volatile(ring_base.add(ring_idx as usize), head);

            // Memory barrier: ensure descriptor writes are visible before
            // updating the available index.
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*self.avail_va).idx),
                cur_idx.wrapping_add(1),
            );
        }

        Some(head)
    }

    /// Check if a completion is available in the used ring.
    ///
    /// Returns `Some((head_desc_idx, bytes_written))` if a new used entry
    /// is present, `None` otherwise.
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn debug_avail_idx(&self) -> u64
    {
        // SAFETY: avail_va is valid.
        u64::from(unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*self.avail_va).idx)) })
    }

    #[must_use]
    pub fn debug_used_idx(&self) -> u64
    {
        // SAFETY: used_va is valid.
        u64::from(unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*self.used_va).idx)) })
    }

    pub fn poll_used(&mut self) -> Option<(u16, u32)>
    {
        // SAFETY: used_va is valid.
        let used_idx =
            unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*self.used_va).idx)) };

        if self.last_used_idx == used_idx
        {
            return None;
        }

        // VirtIO 1.2 §2.7.13.2: device publishes data buffer, status, ring
        // elem, then used.idx with release ordering. The acquire fence here
        // gives the used.idx load above acquire semantics so subsequent
        // loads of the elem and the caller-visible data/status cannot hoist
        // above it on RVWMO.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);

        // SAFETY: used_va is valid; ring entry is within bounds.
        let elem = unsafe {
            // cast_ptr_alignment: VirtqUsed is 2-byte aligned; offset 4 from
            // a 2-byte-aligned base maintains u32 alignment for VirtqUsedElem.
            #[allow(clippy::cast_ptr_alignment)]
            let ring_base = self.used_va.cast::<u8>().add(4).cast::<VirtqUsedElem>();
            let ring_idx = self.last_used_idx % self.queue_size;
            core::ptr::read_volatile(ring_base.add(ring_idx as usize))
        };

        self.last_used_idx = self.last_used_idx.wrapping_add(1);

        // Free all descriptors in the completed chain.
        #[allow(clippy::cast_possible_truncation)]
        let head = elem.id as u16;
        self.free_chain(head);

        Some((head, elem.len))
    }

    /// Free all descriptors in a chain starting from `head`.
    fn free_chain(&mut self, head: u16)
    {
        let mut idx = head;
        loop
        {
            // SAFETY: idx is a valid descriptor index.
            let desc = unsafe { &*self.desc_va.add(idx as usize) };
            let has_next = desc.flags & VRING_DESC_F_NEXT != 0;
            let next = desc.next;
            self.free_desc(idx);
            if !has_next
            {
                break;
            }
            idx = next;
        }
    }

    /// Return the queue size.
    #[must_use]
    pub fn queue_size(&self) -> u16
    {
        self.queue_size
    }
}

// ── Ring memory layout helpers ─────────────────────────────────────────────

/// Calculate the total bytes needed for a virtqueue's descriptor table.
#[must_use]
pub const fn desc_table_size(queue_size: u16) -> usize
{
    queue_size as usize * core::mem::size_of::<VirtqDesc>()
}

/// Calculate the total bytes needed for an available ring.
///
/// `VirtIO` 1.2 §2.7.13: Driver Area size = `6 + 2 * Queue Size`.
/// The extra 2 bytes are the `used_event` field (present in the layout
/// regardless of `VIRTIO_F_EVENT_IDX` negotiation).
#[must_use]
pub const fn avail_ring_size(queue_size: u16) -> usize
{
    6 + 2 * queue_size as usize
}

/// Calculate the total bytes needed for a used ring.
///
/// `VirtIO` 1.2 §2.7.13: Device Area size = `6 + 8 * Queue Size`.
/// The extra 2 bytes are the `avail_event` field (present in the layout
/// regardless of `VIRTIO_F_EVENT_IDX` negotiation).
#[must_use]
pub const fn used_ring_size(queue_size: u16) -> usize
{
    6 + 8 * queue_size as usize
}

/// Byte offset of the used ring from the start of ring memory.
///
/// The used ring must be 4-byte aligned (`VirtIO` 1.2 §2.7). This rounds
/// up past the descriptor table + available ring to the next 4-byte boundary.
#[must_use]
pub const fn used_ring_offset(queue_size: u16) -> usize
{
    let raw = desc_table_size(queue_size) + avail_ring_size(queue_size);
    (raw + 3) & !3 // round up to 4-byte alignment
}

/// Calculate total pages needed for all virtqueue ring memory.
///
/// Descriptor table, available ring, and used ring are packed into
/// contiguous pages with the used ring 4-byte aligned.
#[must_use]
pub const fn ring_pages(queue_size: u16) -> usize
{
    let total = used_ring_offset(queue_size) + used_ring_size(queue_size);
    total.div_ceil(4096)
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn avail_and_used_ring_sizes_include_event_suffix_bytes()
    {
        // The 6-byte (not 4-byte) header carries the trailing used_event /
        // avail_event field; reverting to 4 truncates the last ring slot.
        // Expected values are spelled out, not the formula, so a header-size
        // regression trips visibly rather than mirroring the function body.
        assert_eq!(avail_ring_size(4), 14);
        assert_eq!(used_ring_size(4), 38);
    }

    #[test]
    fn used_ring_offset_rounds_descriptor_plus_avail_up_to_four_bytes()
    {
        // queue_size 1: desc 16 + avail 8 = 24, already 4-aligned.
        assert_eq!(used_ring_offset(1), 24);
        // queue_size 2: desc 32 + avail 10 = 42, must round UP to 44, not down.
        assert_eq!(used_ring_offset(2), 44);
    }

    #[test]
    fn ring_pages_rounds_up_partial_trailing_page()
    {
        // 38 bytes still needs a whole page (a truncating /4096 would yield 0).
        assert_eq!(ring_pages(1), 1);
        // queue_size 256 spans 6670 bytes: two pages, not one.
        assert_eq!(ring_pages(256), 2);
    }

    /// Zeroed, 8-byte-aligned host buffers standing in for the DMA pages a real
    /// driver reserves. Backing the descriptor/avail/used pointers with host
    /// memory exercises the pure free-list and chain index arithmetic — the
    /// platform-injection seam coding-standards.md §D endorses, not the kernel
    /// ABI. Only the device wire format (a hand-written used-ring entry in
    /// [`Rings::publish_used`]) is simulated.
    struct Rings
    {
        desc: Vec<VirtqDesc>,
        avail: Vec<u64>,
        used: Vec<u64>,
    }

    impl Rings
    {
        fn new(queue_size: u16) -> Self
        {
            Self {
                desc: vec![VirtqDesc::default(); queue_size as usize],
                avail: vec![0u64; avail_ring_size(queue_size).div_ceil(8)],
                used: vec![0u64; used_ring_size(queue_size).div_ceil(8)],
            }
        }

        fn queue(&mut self, queue_size: u16) -> SplitVirtqueue
        {
            // SAFETY: the three buffers are zeroed, 8-byte aligned (Vec<u64> /
            // Vec<VirtqDesc>), non-overlapping, sized to the VirtIO 1.2 ring
            // helpers, and outlive the returned queue (the caller holds `self`).
            unsafe {
                SplitVirtqueue::new(
                    self.desc.as_mut_ptr(),
                    self.avail.as_mut_ptr().cast::<VirtqAvail>(),
                    self.used.as_mut_ptr().cast::<VirtqUsed>(),
                    queue_size,
                )
            }
        }

        /// Simulate the device publishing one completion: write a used-ring
        /// element at `ring_idx` and advance `used.idx`.
        fn publish_used(&mut self, ring_idx: usize, id: u32, len: u32, used_idx: u16)
        {
            let used = self.used.as_mut_ptr().cast::<VirtqUsed>();
            // SAFETY: `used` is sized for queue_size elements via used_ring_size;
            // ring_idx is in range for the queue sizes used here. Single-threaded.
            #[allow(clippy::cast_ptr_alignment)]
            unsafe {
                let elem = used
                    .cast::<u8>()
                    .add(4)
                    .cast::<VirtqUsedElem>()
                    .add(ring_idx);
                core::ptr::write(elem, VirtqUsedElem { id, len });
                (*used).idx = used_idx;
            }
        }

        fn desc(&self, idx: usize) -> VirtqDesc
        {
            self.desc[idx]
        }
    }

    #[test]
    fn add_chain_links_multi_buffer_chain_and_sets_next_flag()
    {
        let mut rings = Rings::new(8);
        let mut vq = rings.queue(8);
        let head = vq
            .add_chain(&[
                (0xA000, 0x10, false),
                (0xB000, 0x20, true),
                (0xC000, 0x30, false),
            ])
            .expect("three free descriptors available");
        assert_eq!(head, 0);

        let (d0, d1, d2) = (rings.desc(0), rings.desc(1), rings.desc(2));

        // Head and middle carry NEXT and point at the following allocated index.
        assert_ne!(d0.flags & VRING_DESC_F_NEXT, 0);
        assert_eq!(d0.next, 1);
        assert_ne!(d1.flags & VRING_DESC_F_NEXT, 0);
        assert_eq!(d1.next, 2);
        // The tail clears NEXT.
        assert_eq!(d2.flags & VRING_DESC_F_NEXT, 0);
        // Only the device-writable buffer carries WRITE.
        assert_eq!(d0.flags & VRING_DESC_F_WRITE, 0);
        assert_ne!(d1.flags & VRING_DESC_F_WRITE, 0);
        // Each buffer's addr/len lands in its descriptor.
        assert_eq!((d0.addr, d0.len), (0xA000, 0x10));
        assert_eq!((d1.addr, d1.len), (0xB000, 0x20));
        assert_eq!((d2.addr, d2.len), (0xC000, 0x30));
    }

    #[test]
    fn add_chain_returns_none_when_free_descriptors_exhausted()
    {
        let mut rings = Rings::new(2);
        let mut vq = rings.queue(2);
        // A chain longer than the free count is refused, as is an empty chain,
        // and neither consumes descriptors.
        assert!(
            vq.add_chain(&[(0xA000, 1, false), (0xB000, 1, false), (0xC000, 1, false)])
                .is_none()
        );
        assert!(vq.add_chain(&[]).is_none());
        // The free list is intact: a chain that exactly fills it still succeeds.
        assert!(
            vq.add_chain(&[(0xA000, 1, false), (0xB000, 1, false)])
                .is_some()
        );
    }

    #[test]
    fn poll_used_frees_completed_chain_and_advances_last_used_idx()
    {
        let mut rings = Rings::new(8);
        let mut vq = rings.queue(8);
        let head = vq
            .add_chain(&[(0xA000, 0x200, false), (0xB000, 0x200, false)])
            .expect("two free descriptors available");

        // Device publishes the completion: ring[0] = {id: head, len: 0x200}.
        rings.publish_used(0, u32::from(head), 0x200, 1);

        assert_eq!(vq.poll_used(), Some((head, 0x200)));
        // Idempotent until the device advances its index again.
        assert_eq!(vq.poll_used(), None);

        // Both descriptors — not just the head — returned to the free list: a
        // fresh chain spanning the whole queue now succeeds.
        let full: Vec<(u64, u32, bool)> = vec![(0xC000, 1, false); 8];
        assert!(vq.add_chain(&full).is_some());
    }
}
