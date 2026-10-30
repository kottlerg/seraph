// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/core/src/virtqueue.rs

//! Split virtqueue implementation (`VirtIO` 1.2 §2.7).
//!
//! Manages the descriptor table, available ring, and used ring for a single
//! split virtqueue. The caller is responsible for allocating DMA-capable
//! memory and providing physical addresses.

/// Maximum supported queue size. QEMU `virtio-blk` defaults to 256.
pub const MAX_QUEUE_SIZE: u16 = 256;

/// A used-ring completion [`SplitVirtqueue::poll_used`] refused.
///
/// The used ring is device-written memory, so its contents are external
/// input. A refused element is consumed (the next poll moves past it) and
/// frees no descriptor: the free list stays as the driver last left it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtqueueError
{
    /// The element's `id` names no chain the driver has outstanding: it is
    /// outside the descriptor table, or it indexes a free descriptor or a
    /// non-head descriptor of a chain.
    UnknownHead
    {
        /// The `id` field the device wrote.
        id: u32,
    },
}

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
///
/// The bookkeeping (the free list, each chain's links and length) lives in
/// driver memory. The device-visible descriptor table is only written, never
/// read back, so nothing the device writes into it can steer which
/// descriptors are allocated or freed.
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
    /// Next free descriptor index for allocation; below `queue_size`
    /// whenever `num_free > 0`.
    free_head: u16,
    /// Number of free descriptors.
    num_free: u16,
    /// Last seen used ring index (for polling completions). A free-running
    /// `u16` like the ring's own `idx` (`VirtIO` 1.2 §2.7.8); it wraps by spec,
    /// and `% queue_size` stays exact because a split ring's size is a power
    /// of two.
    last_used_idx: u16,
    /// Descriptor count of the chain each outstanding head starts, indexed
    /// by head; 0 marks an index that heads no outstanding chain.
    /// [`poll_used`](Self::poll_used) checks a device-written `id` against it.
    chain_len: [u16; MAX_QUEUE_SIZE as usize],
    /// Driver-private link of each descriptor, indexed by descriptor: the
    /// next free descriptor while it is free, the next descriptor of its
    /// chain while it is outstanding. Every value stored is below
    /// `queue_size` except the free list's terminator (`queue_size`), which
    /// is never followed: `num_free` stops `alloc_desc` at the free list's
    /// end, and `chain_len` stops `free_chain` at a chain's tail, whose link
    /// may still hold the terminator or a stale free-list link.
    links: [u16; MAX_QUEUE_SIZE as usize],
}

impl SplitVirtqueue
{
    /// Initialise a virtqueue over pre-allocated DMA memory.
    ///
    /// Returns `None` when `queue_size` is 0 (the device offers no queue)
    /// or exceeds [`MAX_QUEUE_SIZE`]; the size derives from the device's
    /// `queue_size` register, so it is checked rather than assumed.
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
    ) -> Option<Self>
    {
        if queue_size == 0 || queue_size > MAX_QUEUE_SIZE
        {
            return None;
        }

        // Build the free list in driver memory: each descriptor links to the
        // following one; the last link (queue_size) terminates the list.
        let mut links = [0u16; MAX_QUEUE_SIZE as usize];
        for (i, link) in (1..=queue_size).zip(links.iter_mut())
        {
            *link = i;
        }

        Some(Self {
            desc_va,
            avail_va,
            used_va,
            queue_size,
            free_head: 0,
            num_free: queue_size,
            last_used_idx: 0,
            chain_len: [0; MAX_QUEUE_SIZE as usize],
            links,
        })
    }

    /// Allocate a single descriptor from the free list.
    ///
    /// Returns the descriptor index, or `None` if no descriptors are free.
    /// An index returned is below `queue_size`: the free list holds only the
    /// indices `new` seeded and `free_chain` returns.
    fn alloc_desc(&mut self) -> Option<u16>
    {
        if self.num_free == 0
        {
            return None;
        }
        let idx = self.free_head;
        self.free_head = self.links[usize::from(idx)];
        self.num_free -= 1;
        Some(idx)
    }

    /// Return a descriptor to the free list.
    fn free_desc(&mut self, idx: u16)
    {
        self.links[usize::from(idx)] = self.free_head;
        self.free_head = idx;
        self.num_free += 1;
    }

    /// Submit a descriptor chain to the available ring.
    ///
    /// `bufs` is a slice of (`physical_addr`, `length`, `device_writable`) tuples.
    /// Returns the head descriptor index for tracking completion, or `None`
    /// if `bufs` is empty or longer than the number of free descriptors;
    /// a refused chain allocates nothing.
    pub fn add_chain(&mut self, bufs: &[(u64, u32, bool)]) -> Option<u16>
    {
        // Compared in usize: `bufs.len() as u16` would wrap at 65536 entries
        // and pass the check with too few descriptors free.
        if bufs.is_empty() || usize::from(self.num_free) < bufs.len()
        {
            return None;
        }
        // Fits: bufs.len() <= num_free <= queue_size <= MAX_QUEUE_SIZE.
        let chain_len = u16::try_from(bufs.len()).ok()?;

        let head = self.alloc_desc()?;
        let mut prev = head;
        // The flags the previous iteration wrote to `prev`, kept here so
        // setting its NEXT bit does not read the device-visible table back.
        let mut prev_flags = 0u16;

        for (i, &(addr, len, writable)) in bufs.iter().enumerate()
        {
            // Cannot fail: the length check above reserved bufs.len() free
            // descriptors.
            let idx = if i == 0 { head } else { self.alloc_desc()? };
            if i > 0
            {
                self.links[usize::from(prev)] = idx;
            }
            let flags = if writable { VRING_DESC_F_WRITE } else { 0 };
            // SAFETY: idx and prev come from alloc_desc, so both are below
            // queue_size and inside the DMA descriptor table. Volatile: prevents
            // dead-store elimination and ensures the device sees writes in order.
            unsafe {
                let desc = self.desc_va.add(idx as usize);
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc).addr), addr);
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc).len), len);
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc).flags), flags);

                if i > 0
                {
                    let prev_desc = self.desc_va.add(prev as usize);
                    core::ptr::write_volatile(
                        core::ptr::addr_of_mut!((*prev_desc).flags),
                        prev_flags | VRING_DESC_F_NEXT,
                    );
                    core::ptr::write_volatile(core::ptr::addr_of_mut!((*prev_desc).next), idx);
                }
            }
            prev = idx;
            prev_flags = flags;
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

        self.chain_len[usize::from(head)] = chain_len;
        Some(head)
    }

    /// Consume the next completion from the used ring, if one is present,
    /// and return its chain's descriptors to the free list.
    ///
    /// Returns `Ok(Some((head, bytes_written)))` for a completion of an
    /// outstanding chain, and `Ok(None)` when the device has published no
    /// new used entry.
    ///
    /// # Errors
    ///
    /// The used-ring element is device-written, so it is validated before
    /// any descriptor is freed: [`VirtqueueError::UnknownHead`] when its `id`
    /// heads no outstanding chain. The element is consumed and the free list
    /// is left untouched.
    pub fn poll_used(&mut self) -> Result<Option<(u16, u32)>, VirtqueueError>
    {
        // SAFETY: used_va is valid.
        let used_idx =
            unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*self.used_va).idx)) };

        if self.last_used_idx == used_idx
        {
            return Ok(None);
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

        let head = self
            .outstanding_head(elem.id)
            .ok_or(VirtqueueError::UnknownHead { id: elem.id })?;
        self.free_chain(head);

        Ok(Some((head, elem.len)))
    }

    /// The head index a device-written used-element `id` names, when it
    /// heads a chain [`add_chain`](Self::add_chain) submitted that no
    /// completion has freed yet.
    fn outstanding_head(&self, id: u32) -> Option<u16>
    {
        let head = u16::try_from(id).ok().filter(|&h| h < self.queue_size)?;
        (self.chain_len[usize::from(head)] != 0).then_some(head)
    }

    /// Free every descriptor of the outstanding chain starting at `head`.
    ///
    /// Follows the driver-private links `add_chain` recorded, for exactly the
    /// recorded chain length, so the device-visible descriptor table (which
    /// the device could have overwritten) plays no part.
    fn free_chain(&mut self, head: u16)
    {
        let len = self.chain_len[usize::from(head)];
        self.chain_len[usize::from(head)] = 0;
        let mut idx = head;
        for _ in 0..len
        {
            // Read the chain link before free_desc overwrites it with the
            // free-list link.
            let next = self.links[usize::from(idx)];
            self.free_desc(idx);
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

        fn queue(&mut self, queue_size: u16) -> Option<SplitVirtqueue>
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

        /// Simulate the device overwriting a descriptor's link (the table is
        /// device-visible DMA memory).
        fn set_next(&mut self, idx: usize, next: u16, flags: u16)
        {
            self.desc[idx].next = next;
            self.desc[idx].flags = flags;
        }
    }

    #[test]
    fn new_rejects_zero_and_oversized_queue_sizes()
    {
        let mut empty = Rings::new(1);
        assert!(empty.queue(0).is_none());
        let mut oversized = Rings::new(MAX_QUEUE_SIZE + 1);
        assert!(oversized.queue(MAX_QUEUE_SIZE + 1).is_none());
        let mut max = Rings::new(MAX_QUEUE_SIZE);
        assert!(max.queue(MAX_QUEUE_SIZE).is_some());
    }

    #[test]
    fn add_chain_links_multi_buffer_chain_and_sets_next_flag()
    {
        let mut rings = Rings::new(8);
        let mut vq = rings.queue(8).expect("valid queue size");
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
        let mut vq = rings.queue(2).expect("valid queue size");
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
        let mut vq = rings.queue(8).expect("valid queue size");
        let head = vq
            .add_chain(&[(0xA000, 0x200, false), (0xB000, 0x200, false)])
            .expect("two free descriptors available");

        // Device publishes the completion: ring[0] = {id: head, len: 0x200}.
        rings.publish_used(0, u32::from(head), 0x200, 1);

        assert_eq!(vq.poll_used(), Ok(Some((head, 0x200))));
        // Idempotent until the device advances its index again.
        assert_eq!(vq.poll_used(), Ok(None));

        // Both descriptors — not just the head — returned to the free list: a
        // fresh chain spanning the whole queue now succeeds.
        let full: Vec<(u64, u32, bool)> = vec![(0xC000, 1, false); 8];
        assert!(vq.add_chain(&full).is_some());
    }

    /// Free-descriptor count, observed through `add_chain`: the longest chain
    /// the queue accepts. Consumes the queue's free list, so it ends a test.
    fn free_count(vq: &mut SplitVirtqueue, queue_size: u16) -> usize
    {
        (1..=usize::from(queue_size))
            .rev()
            .find(|&n| {
                let chain: Vec<(u64, u32, bool)> = vec![(0xF000, 1, false); n];
                vq.add_chain(&chain).is_some()
            })
            .unwrap_or(0)
    }

    #[test]
    fn poll_used_rejects_ids_that_head_no_outstanding_chain_without_freeing()
    {
        let mut rings = Rings::new(8);
        let mut vq = rings.queue(8).expect("valid queue size");
        let head = vq
            .add_chain(&[(0xA000, 1, false), (0xB000, 1, false)])
            .expect("two free descriptors available");
        assert_eq!(head, 0);

        // Outside the table, a free descriptor, and the chain's non-head
        // descriptor: each is consumed and refused.
        for (n, id) in [8u32, 5, 1].into_iter().enumerate()
        {
            let used_idx = u16::try_from(n + 1).expect("small");
            rings.publish_used(n, id, 1, used_idx);
            assert_eq!(vq.poll_used(), Err(VirtqueueError::UnknownHead { id }));
        }
        // No refusal freed anything: the two-descriptor chain is still out.
        assert_eq!(free_count(&mut vq, 8), 6);
    }

    #[test]
    fn completion_frees_the_submitted_chain_whatever_the_device_wrote_into_the_table()
    {
        let mut rings = Rings::new(8);
        let mut vq = rings.queue(8).expect("valid queue size");
        let head = vq
            .add_chain(&[(0xA000, 1, false), (0xB000, 1, false), (0xC000, 1, false)])
            .expect("three free descriptors available");
        assert_eq!((head, rings.desc(1).next), (0, 2));
        // The device rewrites the table. The middle descriptor now links to
        // free descriptor 5 marked as the tail: a walk of the DMA links that
        // reached it would free 5 a second time and leak 2. The head now
        // links out of the table: such a walk would leave the table at its
        // first step.
        rings.set_next(1, 5, 0);
        rings.set_next(0, 200, VRING_DESC_F_NEXT);
        rings.publish_used(0, u32::from(head), 1, 1);

        assert_eq!(vq.poll_used(), Ok(Some((head, 1))));
        // Exactly the three submitted descriptors came back: the whole queue
        // is free again, with no descriptor counted twice.
        assert_eq!(free_count(&mut vq, 8), 8);
    }

    #[test]
    fn free_list_hands_out_each_descriptor_once_after_completions()
    {
        let mut rings = Rings::new(4);
        let mut vq = rings.queue(4).expect("valid queue size");
        let a = vq
            .add_chain(&[(0xA000, 1, false), (0xB000, 1, false)])
            .expect("two free descriptors available");
        let b = vq
            .add_chain(&[(0xC000, 1, false), (0xD000, 1, false)])
            .expect("two free descriptors available");
        // Complete out of submission order.
        rings.publish_used(0, u32::from(b), 1, 1);
        rings.publish_used(1, u32::from(a), 1, 2);
        assert_eq!(vq.poll_used(), Ok(Some((b, 1))));
        assert_eq!(vq.poll_used(), Ok(Some((a, 1))));

        // A full-width chain now takes all four descriptors, each once.
        let head = vq
            .add_chain(&[(0x1000, 1, false); 4])
            .expect("all four descriptors free");
        let mut seen = [false; 4];
        let mut idx = usize::from(head);
        for step in 0..4
        {
            assert!(!seen[idx], "descriptor {idx} handed out twice");
            seen[idx] = true;
            if step < 3
            {
                idx = usize::from(rings.desc(idx).next);
            }
        }
    }
}
