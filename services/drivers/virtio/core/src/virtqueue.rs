// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/core/src/virtqueue.rs

//! Split virtqueue implementation (`VirtIO` 1.2 §2.7).
//!
//! Manages the descriptor table, available ring, and used ring for a single
//! split virtqueue. The caller is responsible for allocating DMA-capable
//! memory and providing the device addresses devmgr returned when it mapped
//! that memory for the device ([`crate::dma`]), never physical addresses.

use alloc::vec::Vec;

/// Largest queue size a split virtqueue may have (`VirtIO` 1.2 §2.7: the
/// maximum Queue Size is 32768). A hardware-specification bound: the
/// driver-private bookkeeping is sized to the queue the device negotiates,
/// so a smaller queue pays only for its own descriptors.
pub const MAX_QUEUE_SIZE: u16 = 32768;

/// A used-ring completion [`SplitVirtqueue::poll_used`] refused.
///
/// The used ring is device-written memory, so its index and its elements are
/// external input. A refused element is consumed (the next poll moves past
/// it) and frees no descriptor: the free list and every outstanding chain
/// stay as the driver last left them, so a chain whose completion was refused
/// is still outstanding and a later completion of it is taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtqueueError
{
    /// The used index publishes more elements than the driver has chains
    /// outstanding: it jumped past what the device can have completed, or it
    /// moved back. Every element it published is consumed unread.
    IndexPastOutstanding
    {
        /// The `idx` field the device wrote.
        used_idx: u16,
    },
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
    /// Device address of the buffer ([`crate::dma`]).
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
/// The queue is a shell over its bookkeeping, `Chains`, which lives in
/// driver memory and makes every decision: which descriptors a chain takes,
/// where it is published, and whether a used element completes it. The shell
/// writes the descriptor table, the available ring and its index without
/// reading them back, so nothing the device writes into them can steer which
/// descriptors are allocated or freed or where a chain is published; and it
/// reads each device-written field of the used ring once, handing the copy
/// to the bookkeeping's decode (`Chains::take_used`), so the value checked is
/// the value used.
pub struct SplitVirtqueue
{
    /// Virtual address of the descriptor table.
    desc_va: *mut VirtqDesc,
    /// Virtual address of the available ring.
    avail_va: *mut VirtqAvail,
    /// Virtual address of the used ring.
    used_va: *mut VirtqUsed,
    /// The driver-private bookkeeping.
    pub(crate) chains: Chains,
}

impl SplitVirtqueue
{
    /// Initialise a virtqueue over pre-allocated DMA memory.
    ///
    /// Returns `None` when `queue_size` is 0 (the device offers no queue),
    /// is not a power of two (a split ring's size always is, and the ring
    /// indices rely on it: `% queue_size` of a wrapping `u16` index is exact
    /// only then), or exceeds [`MAX_QUEUE_SIZE`]. The size derives from the
    /// device's `queue_size` register, so it is checked rather than assumed.
    /// The driver-private bookkeeping is allocated at `queue_size` entries;
    /// `None` also when the heap cannot hold it.
    ///
    /// # Safety
    ///
    /// - `desc_va` must point to `queue_size * 16` bytes of zeroed, DMA-capable memory,
    ///   aligned to `align_of::<VirtqDesc>()`.
    /// - `avail_va` must point to `4 + 2 * queue_size` bytes of zeroed, DMA-capable memory,
    ///   aligned to `align_of::<VirtqAvail>()`.
    /// - `used_va` must point to `4 + 8 * queue_size` bytes of zeroed, DMA-capable memory,
    ///   aligned to `align_of::<VirtqUsedElem>()` (4 bytes, `VirtIO` 1.2 §2.7), which the ring's
    ///   elements, 4 bytes past its header, need.
    /// - All three regions must not overlap and must remain valid for the virtqueue's lifetime.
    #[must_use]
    pub unsafe fn new(
        desc_va: *mut VirtqDesc,
        avail_va: *mut VirtqAvail,
        used_va: *mut VirtqUsed,
        queue_size: u16,
    ) -> Option<Self>
    {
        Some(Self {
            desc_va,
            avail_va,
            used_va,
            chains: Chains::new(queue_size)?,
        })
    }

    /// Submit a descriptor chain to the available ring.
    ///
    /// `bufs` is a slice of (`device_addr`, `length`, `device_writable`) tuples.
    /// Returns the head descriptor index for tracking completion, or `None`
    /// if `bufs` is empty or longer than the number of free descriptors;
    /// a refused chain allocates nothing.
    pub fn add_chain(&mut self, bufs: &[(u64, u32, bool)]) -> Option<u16>
    {
        // The bookkeeping records the chain before the shell publishes it, so
        // no published chain is unrecorded.
        let reserved = self.chains.reserve(bufs)?;
        let mut descs = self.chains.chain(reserved.head).zip(bufs).peekable();
        while let Some((idx, &(addr, len, writable))) = descs.next()
        {
            let next = descs.peek().map(|&(next, _)| next);
            let write_flag = if writable { VRING_DESC_F_WRITE } else { 0 };
            let next_flag = if next.is_some() { VRING_DESC_F_NEXT } else { 0 };
            // SAFETY: idx is a descriptor of a chain the bookkeeping recorded,
            // so below queue_size (the invariant `Chains` keeps), and the
            // offset stays inside the descriptor table.
            let desc = unsafe { self.desc_va.add(usize::from(idx)) };
            #[expect(
                clippy::multiple_unsafe_ops_per_block,
                reason = "every write is to a field of descriptor `desc`, which lies inside the \
                          descriptor table `new`'s contract keeps valid"
            )]
            // SAFETY: `desc` lies inside the DMA descriptor table, which `new`'s
            // contract keeps valid, aligned and writable for the queue's
            // lifetime. Volatile: prevents dead-store elimination and ensures
            // the device sees writes in order.
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc).addr), addr);
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc).len), len);
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!((*desc).flags),
                    write_flag | next_flag,
                );
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc).next), next.unwrap_or(0));
            }
        }

        #[expect(
            clippy::cast_ptr_alignment,
            reason = "VirtqAvail is 2-byte aligned; offset 4 from a 2-byte-aligned base \
                      maintains u16 alignment"
        )]
        // SAFETY: the ring entries start 4 bytes past the available ring's
        // header, inside the `4 + 2 * queue_size` bytes `new`'s contract names.
        let ring_base = unsafe { self.avail_va.cast::<u8>().add(4) }.cast::<u16>();
        // SAFETY: the slot is the published index masked with ring_mask, so
        // below queue_size, and the entry lies inside the ring's `queue_size`
        // entries.
        let ring_entry = unsafe { ring_base.add(usize::from(reserved.slot)) };
        // SAFETY: `ring_entry` lies inside the valid, writable available ring.
        unsafe { core::ptr::write_volatile(ring_entry, reserved.head) };

        // Memory barrier: ensure descriptor writes are visible before
        // updating the available index.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

        // SAFETY: `idx` is a field of the available ring header, which `new`'s
        // contract keeps valid and writable; no reference is formed.
        let avail_idx_ptr = unsafe { core::ptr::addr_of_mut!((*self.avail_va).idx) };
        // SAFETY: `avail_idx_ptr` points into the valid, aligned, writable
        // available ring. The index is the bookkeeping's own: the shared copy
        // is never read back.
        unsafe { core::ptr::write_volatile(avail_idx_ptr, reserved.avail_idx) };

        Some(reserved.head)
    }

    /// Consume the next completion from the used ring, if one is present,
    /// and return its chain's descriptors to the free list.
    ///
    /// Returns `Ok(Some((head, bytes_written)))` for a completion of an
    /// outstanding chain, `bytes_written` the element's `len` clamped to the
    /// bytes its device-writable buffers hold, and `Ok(None)` when the device
    /// has published no new used entry.
    ///
    /// The used ring's index is read once, and an element's `id` and `len`
    /// once each, only when the element is consumed; the decode
    /// (`Chains::take_used`) judges those copies, and they are what the call
    /// returns.
    ///
    /// # Errors
    ///
    /// The used ring is device-written, so its index and each element are
    /// validated before any descriptor is freed; a refusal frees nothing
    /// ([`VirtqueueError`] names each).
    pub fn poll_used(&mut self) -> Result<Option<(u16, u32)>, VirtqueueError>
    {
        let used_va = self.used_va;
        // SAFETY: `idx` is a field of the used ring header, which `new`'s
        // contract keeps valid; no reference is formed.
        let used_idx_ptr = unsafe { core::ptr::addr_of!((*used_va).idx) };
        // SAFETY: `used_idx_ptr` points into the valid, aligned used ring.
        let used_idx = unsafe { core::ptr::read_volatile(used_idx_ptr) };

        self.chains.take_used(used_idx, |slot| {
            // VirtIO 1.2 §2.7.13.2: device publishes data buffer, status, ring
            // elem, then used.idx with release ordering. The acquire fence here
            // gives the used.idx load above acquire semantics so subsequent
            // loads of the elem and the caller-visible data/status cannot hoist
            // above it on RVWMO.
            core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);

            #[expect(
                clippy::cast_ptr_alignment,
                reason = "`new`'s contract aligns the used ring to `VirtqUsedElem`'s 4 bytes, and \
                          offset 4 from a 4-byte-aligned base keeps that alignment"
            )]
            // SAFETY: the ring elements start 4 bytes past the used ring's header,
            // inside the `4 + 8 * queue_size` bytes `new`'s contract names.
            let ring_base = unsafe { used_va.cast::<u8>().add(4) }.cast::<VirtqUsedElem>();
            // SAFETY: take_used passes a slot below queue_size, so the element
            // lies inside the ring's `queue_size` elements.
            let ring_elem = unsafe { ring_base.add(usize::from(slot)) };
            // Each field is read on its own, at the 32-bit width `VirtIO` 1.2
            // §2.7.8 gives it.
            #[expect(
                clippy::multiple_unsafe_ops_per_block,
                reason = "every read is of a field of used element `ring_elem`, which lies inside \
                          the used ring `new`'s contract keeps valid"
            )]
            // SAFETY: `ring_elem` lies inside the valid used ring, 4-byte aligned:
            // `new`'s contract aligns the ring to 4 bytes, and the elements start
            // 4 bytes past it, 8 bytes apart; each field is a 4-byte-aligned `u32`
            // of it. No reference is formed.
            unsafe {
                VirtqUsedElem {
                    id: core::ptr::read_volatile(&raw const (*ring_elem).id),
                    len: core::ptr::read_volatile(&raw const (*ring_elem).len),
                }
            }
        })
    }

    /// Return the queue size.
    #[must_use]
    pub fn queue_size(&self) -> u16
    {
        self.chains.queue_size
    }
}

/// The driver-private bookkeeping of a split virtqueue, which makes every
/// decision the queue makes: the free list, the outstanding chains, and the
/// two ring indices. It reads no device-shared memory: the device-written
/// values it decodes are handed to it ([`Chains::take_used`]).
///
/// Invariant, which every step keeps (the `proofs` module proves it, and the
/// property checks it after each operation, `crate::property`): the free
/// list (`num_free` descriptors from `free_head` along `links`) and the
/// outstanding chains (from each head with a non-zero `chain_len`, that many
/// descriptors along `links`) visit every descriptor below `queue_size`
/// exactly once between them; `outstanding` counts the chains; and an index
/// that heads no chain has `writable` 0.
#[cfg_attr(any(test, kani, fuzzing), derive(Clone, Debug))]
pub(crate) struct Chains
{
    /// Queue size (number of descriptors), a power of two.
    pub(crate) queue_size: u16,
    /// `queue_size - 1`: a ring index masked with it is the index modulo
    /// the queue size, since a split ring's size is a power of two.
    pub(crate) ring_mask: u16,
    /// Next free descriptor index for allocation; below `queue_size`
    /// whenever `num_free > 0`.
    pub(crate) free_head: u16,
    /// Number of free descriptors.
    pub(crate) num_free: u16,
    /// Number of outstanding chains: submitted and not yet freed by a
    /// completion. At most `queue_size`, since each holds a descriptor.
    pub(crate) outstanding: u16,
    /// The available ring's index as the driver last published it. A
    /// free-running `u16` like the ring's own (`VirtIO` 1.2 §2.7.6), kept
    /// here so the driver never reads back the copy the device can write.
    pub(crate) avail_idx: u16,
    /// Last used ring index consumed. A free-running `u16` like the ring's
    /// own `idx` (`VirtIO` 1.2 §2.7.8); it wraps by spec, and its ring slot
    /// (masked with `ring_mask`) stays exact because a split ring's size is a
    /// power of two.
    pub(crate) last_used_idx: u16,
    /// Descriptor count of the chain each outstanding head starts, indexed
    /// by head; 0 marks an index that heads no outstanding chain.
    pub(crate) chain_len: Vec<u16>,
    /// Bytes the device-writable descriptors of the chain each outstanding
    /// head starts hold, indexed by head, saturating at `u32::MAX`: a used
    /// element's `len` is a `u32`, so a saturated total still bounds it.
    pub(crate) writable: Vec<u32>,
    /// Driver-private link of each descriptor, indexed by descriptor: the
    /// next free descriptor while it is free, the next descriptor of its
    /// chain while it is outstanding. Every value stored is below
    /// `queue_size` except the free list's terminator (`queue_size`), which
    /// is never followed: `num_free` stops `alloc_desc` at the free list's
    /// end, and `chain_len` stops `free_chain` at a chain's tail, whose link
    /// may still hold the terminator or a stale free-list link.
    pub(crate) links: Vec<u16>,
}

/// A chain [`Chains::reserve`] recorded, and where the shell publishes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Reserved
{
    /// The chain's head descriptor.
    pub(crate) head: u16,
    /// The available-ring slot that takes the head.
    pub(crate) slot: u16,
    /// The available index that publishes it.
    pub(crate) avail_idx: u16,
}

impl Chains
{
    /// The bookkeeping of a queue of `queue_size` descriptors, every one
    /// free and both ring indices at 0. `None` when `queue_size` is 0, not
    /// a power of two, or past [`MAX_QUEUE_SIZE`], or when the heap cannot
    /// hold the bookkeeping.
    pub(crate) fn new(queue_size: u16) -> Option<Self>
    {
        if !queue_size.is_power_of_two() || queue_size > MAX_QUEUE_SIZE
        {
            return None;
        }
        // At least 1: a power of two.
        let ring_mask = queue_size.checked_sub(1)?;

        // Build the free list in driver memory: each descriptor links to the
        // following one; the last link (queue_size) terminates the list.
        let size = usize::from(queue_size);
        let mut links: Vec<u16> = Vec::new();
        let mut chain_len: Vec<u16> = Vec::new();
        let mut writable: Vec<u32> = Vec::new();
        links.try_reserve_exact(size).ok()?;
        chain_len.try_reserve_exact(size).ok()?;
        writable.try_reserve_exact(size).ok()?;
        links.extend(1..=queue_size);
        chain_len.resize(size, 0);
        writable.resize(size, 0);

        Some(Self {
            queue_size,
            ring_mask,
            free_head: 0,
            num_free: queue_size,
            outstanding: 0,
            avail_idx: 0,
            last_used_idx: 0,
            chain_len,
            writable,
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
        let remaining = self.num_free.checked_sub(1)?;
        let idx = self.free_head;
        self.free_head = *self.links.get(usize::from(idx))?;
        self.num_free = remaining;
        Some(idx)
    }

    /// Return descriptor `idx`, which is below `queue_size`, to the free list.
    fn free_desc(&mut self, idx: u16)
    {
        let Some(link) = self.links.get_mut(usize::from(idx))
        else
        {
            return;
        };
        *link = self.free_head;
        self.free_head = idx;
        // `idx` was outstanding, so `num_free` is below `queue_size`: no
        // saturation.
        self.num_free = self.num_free.saturating_add(1);
    }

    /// Record a chain of one descriptor for each of `bufs`, the
    /// (`device_addr`, `length`, `device_writable`) tuples
    /// [`SplitVirtqueue::add_chain`] takes, as outstanding, with the bytes of
    /// its device-writable buffers, and give the available-ring slot and
    /// index that publish it. `None` when `bufs` is empty or longer than the
    /// number of free descriptors; a refused chain allocates nothing.
    pub(crate) fn reserve(&mut self, bufs: &[(u64, u32, bool)]) -> Option<Reserved>
    {
        // Compared in usize: `bufs.len() as u16` would wrap at 65536 entries
        // and pass the check with too few descriptors free.
        if bufs.is_empty() || usize::from(self.num_free) < bufs.len()
        {
            return None;
        }
        // Fits: bufs.len() <= num_free <= queue_size <= MAX_QUEUE_SIZE.
        let chain_len = u16::try_from(bufs.len()).ok()?;
        let writable = bufs
            .iter()
            .filter(|&&(_, _, device_writable)| device_writable)
            .fold(0u32, |sum, &(_, len, _)| sum.saturating_add(len));

        // Cannot fail past this point: the length check above reserved
        // bufs.len() free descriptors, and each one alloc_desc returns is
        // below queue_size.
        let head = self.alloc_desc()?;
        let mut prev = head;
        for _ in 1..chain_len
        {
            let idx = self.alloc_desc()?;
            *self.links.get_mut(usize::from(prev))? = idx;
            prev = idx;
        }
        *self.chain_len.get_mut(usize::from(head))? = chain_len;
        *self.writable.get_mut(usize::from(head))? = writable;
        // Each outstanding chain holds a descriptor, so the count stays at
        // most queue_size: no saturation.
        self.outstanding = self.outstanding.saturating_add(1);

        let slot = self.avail_idx & self.ring_mask;
        self.avail_idx = self.avail_idx.wrapping_add(1);
        Some(Reserved {
            head,
            slot,
            avail_idx: self.avail_idx,
        })
    }

    /// The descriptors of the outstanding chain at `head`, head first, along
    /// the driver's links; none when `head` heads no outstanding chain.
    pub(crate) fn chain(&self, head: u16) -> impl Iterator<Item = u16> + '_
    {
        let len = self.chain_len.get(usize::from(head)).copied().unwrap_or(0);
        core::iter::successors(Some(head), |&idx| self.links.get(usize::from(idx)).copied())
            .take(usize::from(len))
    }

    /// Decode the used ring as the device last wrote it: `used_idx`, the
    /// ring's `idx` field, read once by the caller; and, through `read`,
    /// the element at the ring slot `read` is given. `read` is called at
    /// most once, with a slot below the queue size, and only when an element
    /// is consumed: when the device has published one past the last consumed
    /// and no more than the driver has chains outstanding.
    ///
    /// Returns `Ok(Some((head, len)))` for the completion of an outstanding
    /// chain, whose descriptors it frees; and `Ok(None)` when the device has
    /// published no element past the last one consumed. `len` is the
    /// element's, clamped to the bytes of the chain's device-writable
    /// buffers: `VirtIO` 1.2 §2.7.8 makes it the count of bytes the device
    /// wrote into them, so no more can be valid, and the chain is the
    /// device's to return whatever count it reports (§2.7.8.2 notes devices
    /// that report it wrongly).
    ///
    /// # Errors
    ///
    /// Each refusal frees nothing:
    ///
    /// - [`VirtqueueError::IndexPastOutstanding`] when `used_idx` is more
    ///   elements past the last consumed (counted modulo 2^16, as the index
    ///   wraps) than the driver has chains outstanding; every element it
    ///   published is consumed, and none is read.
    /// - [`VirtqueueError::UnknownHead`] when the element's `id` heads no
    ///   outstanding chain; the element is consumed.
    pub(crate) fn take_used(
        &mut self,
        used_idx: u16,
        read: impl FnOnce(u16) -> VirtqUsedElem,
    ) -> Result<Option<(u16, u32)>, VirtqueueError>
    {
        let pending = used_idx.wrapping_sub(self.last_used_idx);
        if pending == 0
        {
            return Ok(None);
        }
        if pending > self.outstanding
        {
            self.last_used_idx = used_idx;
            return Err(VirtqueueError::IndexPastOutstanding { used_idx });
        }
        let elem = read(self.last_used_idx & self.ring_mask);
        self.last_used_idx = self.last_used_idx.wrapping_add(1);

        let head = self
            .outstanding_head(elem.id)
            .ok_or(VirtqueueError::UnknownHead { id: elem.id })?;
        let posted = self.writable.get(usize::from(head)).copied().unwrap_or(0);
        self.free_chain(head);
        Ok(Some((head, elem.len.min(posted))))
    }

    /// The head index a device-written used-element `id` names, when it
    /// heads a chain [`reserve`](Self::reserve) recorded that no completion
    /// has freed yet.
    fn outstanding_head(&self, id: u32) -> Option<u16>
    {
        let head = u16::try_from(id).ok().filter(|&h| h < self.queue_size)?;
        self.chain_len
            .get(usize::from(head))
            .is_some_and(|&len| len != 0)
            .then_some(head)
    }

    /// Free every descriptor of the outstanding chain starting at `head`.
    ///
    /// Follows the driver-private links `reserve` recorded, for exactly the
    /// recorded chain length, so the device-visible descriptor table (which
    /// the device could have overwritten) plays no part.
    fn free_chain(&mut self, head: u16)
    {
        let Some(slot) = self.chain_len.get_mut(usize::from(head))
        else
        {
            return;
        };
        let len = core::mem::take(slot);
        if let Some(writable) = self.writable.get_mut(usize::from(head))
        {
            *writable = 0;
        }
        // `head` headed an outstanding chain, which the count includes: no
        // saturation.
        self.outstanding = self.outstanding.saturating_sub(1);
        let mut idx = head;
        for _ in 0..len
        {
            // Read the chain link before free_desc overwrites it with the
            // free-list link. Every link of a recorded chain is below
            // queue_size.
            let Some(&next) = self.links.get(usize::from(idx))
            else
            {
                return;
            };
            self.free_desc(idx);
            idx = next;
        }
    }
}

// ── Ring memory layout helpers ─────────────────────────────────────────────

/// Calculate the total bytes needed for a virtqueue's descriptor table.
#[must_use]
pub const fn desc_table_size(queue_size: u16) -> usize
{
    // A `u16` count of 16-byte descriptors: no saturation.
    (queue_size as usize).saturating_mul(core::mem::size_of::<VirtqDesc>())
}

/// Calculate the total bytes needed for an available ring.
///
/// `VirtIO` 1.2 §2.7.13: Driver Area size = `6 + 2 * Queue Size`.
/// The extra 2 bytes are the `used_event` field (present in the layout
/// regardless of `VIRTIO_F_EVENT_IDX` negotiation).
#[must_use]
pub const fn avail_ring_size(queue_size: u16) -> usize
{
    // A `u16` count of 2-byte entries: no saturation.
    (queue_size as usize).saturating_mul(2).saturating_add(6)
}

/// Calculate the total bytes needed for a used ring.
///
/// `VirtIO` 1.2 §2.7.13: Device Area size = `6 + 8 * Queue Size`.
/// The extra 2 bytes are the `avail_event` field (present in the layout
/// regardless of `VIRTIO_F_EVENT_IDX` negotiation).
#[must_use]
pub const fn used_ring_size(queue_size: u16) -> usize
{
    // A `u16` count of 8-byte elements: no saturation.
    (queue_size as usize).saturating_mul(8).saturating_add(6)
}

/// Byte offset of the used ring from the start of ring memory.
///
/// The used ring must be 4-byte aligned (`VirtIO` 1.2 §2.7). This rounds
/// up past the descriptor table + available ring to the next 4-byte boundary.
#[must_use]
pub const fn used_ring_offset(queue_size: u16) -> usize
{
    // Each term is below 2^21 bytes: neither operation saturates.
    let raw = desc_table_size(queue_size).saturating_add(avail_ring_size(queue_size));
    raw.saturating_add(3) & !3 // round up to 4-byte alignment
}

/// The descriptor table's, available ring's, and used ring's addresses in
/// ring memory starting at `base`, laid out as [`ring_pages`] sizes it: a
/// virtual address or a device address alike. `None` when an address is
/// past `u64`.
#[must_use]
pub fn ring_addresses(base: u64, queue_size: u16) -> Option<(u64, u64, u64)>
{
    let avail = base.checked_add(u64::try_from(desc_table_size(queue_size)).ok()?)?;
    let used = base.checked_add(u64::try_from(used_ring_offset(queue_size)).ok()?)?;
    Some((base, avail, used))
}

/// Calculate total pages needed for all virtqueue ring memory.
///
/// Descriptor table, available ring, and used ring are packed into
/// contiguous pages with the used ring 4-byte aligned.
#[must_use]
pub const fn ring_pages(queue_size: u16) -> usize
{
    // Each term is below 2^21 bytes: no saturation.
    let total = used_ring_offset(queue_size).saturating_add(used_ring_size(queue_size));
    total.div_ceil(4096)
}

/// Bounded proofs of the queue's bookkeeping (docs/testing.md § Bounded
/// verification), by induction over its life: the base proofs show that
/// [`Chains::new`] refuses every size that is not a power of two of at most
/// [`MAX_QUEUE_SIZE`] and starts every queue of up to 8 descriptors in the
/// invariant [`Chains`] states; each step proof runs one step from any
/// bookkeeping of a queue of 1 or 4 descriptors that holds the invariant,
/// on any operands, and checks its contract and that the invariant still
/// holds (`crate::property`'s `reserve_holds` and `used_holds`). Every step
/// the shell takes on the bookkeeping is one of these, so the invariant
/// holds over any sequence of them, whatever the device writes. What lies
/// outside the proofs is the shell's volatile access to the rings, and the
/// steps of other queue sizes; the fuzz target `virtio-core`, the replay of
/// the checked-in inputs and the unit tests check them.
#[cfg(kani)]
mod proofs
{
    use super::{Chains, MAX_QUEUE_SIZE, VirtqUsedElem};
    use crate::property;

    /// Bookkeeping of a queue of `size` descriptors in any state the
    /// invariant admits: any free list, links, chain lengths, writable
    /// bytes, outstanding count and indices, assumed to hold the invariant.
    /// `None` only when `new` refuses `size`, which the base proofs show it
    /// does not for a power of two.
    fn any_chains(size: u16) -> Option<Chains>
    {
        let mut chains = Chains::new(size)?;
        chains.free_head = kani::any();
        chains.num_free = kani::any();
        chains.outstanding = kani::any();
        chains.avail_idx = kani::any();
        chains.last_used_idx = kani::any();
        for link in &mut chains.links
        {
            *link = kani::any();
        }
        for len in &mut chains.chain_len
        {
            *len = kani::any();
        }
        for writable in &mut chains.writable
        {
            *writable = kani::any();
        }
        kani::assume(property::invariant(&chains));
        Some(chains)
    }

    /// Every size of a `u16` that is not a power of two of at most
    /// [`MAX_QUEUE_SIZE`] is refused, before any allocation. No loop is
    /// reached: the refusal returns before the free list's build, and the
    /// bound of 2 lets the unwinding check prove that build unreachable
    /// rather than unroll it for a symbolic size.
    #[kani::proof]
    #[kani::unwind(2)]
    fn every_invalid_queue_size_is_refused()
    {
        let size: u16 = kani::any();
        kani::assume(!(size.is_power_of_two() && size <= MAX_QUEUE_SIZE));
        property::new_holds(size);
    }

    /// Every queue of 1, 2, 4 and 8 descriptors starts in the invariant,
    /// empty. The loops are the free list's build and the invariant's
    /// walks, each at most 8 steps.
    #[kani::proof]
    #[kani::unwind(10)]
    fn every_small_queue_starts_in_the_invariant()
    {
        for size in [1, 2, 4, 8]
        {
            property::new_holds(size);
        }
    }

    /// Every chain of at most `size + 1` buffers, reserved on any
    /// bookkeeping of a queue of `size` descriptors, holds the step's
    /// contract: one past the queue, so a chain longer than the free
    /// descriptors, a chain of every length that fits, and the empty chain
    /// are reached.
    fn reserve_step<const N: usize>(size: u16)
    {
        let Some(mut chains) = any_chains(size)
        else
        {
            return;
        };
        let bufs: [(u64, u32, bool); N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bufs.len());
        let _ = property::reserve_holds(&mut chains, &bufs[..len]);
    }

    /// Every used index and element, taken on any bookkeeping of a queue of
    /// `size` descriptors, holds the step's contract: any `idx`, so every
    /// jump, a backwards move and the wrap; any `id` and `len`.
    fn used_step(size: u16)
    {
        let Some(mut chains) = any_chains(size)
        else
        {
            return;
        };
        let elem = VirtqUsedElem {
            id: kani::any(),
            len: kani::any(),
        };
        let _ = property::used_holds(&mut chains, kani::any(), elem);
    }

    /// [`reserve_step`] on a queue of 1 descriptor, whose ring mask is 0.
    /// The loops are the bookkeeping's and the buffers', each at most 2
    /// steps.
    #[kani::proof]
    #[kani::unwind(4)]
    fn every_chain_reserved_on_one_descriptor_keeps_the_invariant()
    {
        reserve_step::<2>(1);
    }

    /// [`reserve_step`] on a queue of 4 descriptors, which holds chains of
    /// one to four descriptors beside one another. The loops are the
    /// bookkeeping's and the buffers', each at most 5 steps.
    #[kani::proof]
    #[kani::unwind(7)]
    fn every_chain_reserved_on_four_descriptors_keeps_the_invariant()
    {
        reserve_step::<5>(4);
    }

    /// [`used_step`] on a queue of 1 descriptor. The loops are the
    /// bookkeeping's walks, each at most 1 step.
    #[kani::proof]
    #[kani::unwind(3)]
    fn every_used_element_taken_on_one_descriptor_keeps_the_invariant()
    {
        used_step(1);
    }

    /// [`used_step`] on a queue of 4 descriptors. The loops are the
    /// bookkeeping's walks, each at most 4 steps.
    #[kani::proof]
    #[kani::unwind(6)]
    fn every_used_element_taken_on_four_descriptors_keeps_the_invariant()
    {
        used_step(4);
    }
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
    fn ring_addresses_follow_the_layout_and_refuse_a_wrap()
    {
        // queue_size 2: avail after 32 descriptor bytes, used at 44.
        assert_eq!(
            ring_addresses(0x10_0000, 2),
            Some((0x10_0000, 0x10_0020, 0x10_002C))
        );
        // Ring memory at the top of the address width has no used ring.
        assert_eq!(ring_addresses(u64::MAX - 40, 2), None);
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
            #[expect(
                clippy::cast_ptr_alignment,
                reason = "`used` is the start of a `Vec<u64>`, so 8-byte aligned, and offset 4 \
                          keeps the 4-byte alignment `VirtqUsedElem` needs"
            )]
            // SAFETY: the ring elements start 4 bytes past the used ring's
            // header, inside `used`, which used_ring_size sized.
            let ring_base = unsafe { used.cast::<u8>().add(4) }.cast::<VirtqUsedElem>();
            // SAFETY: `used` is sized for queue_size elements via used_ring_size;
            // ring_idx is in range for the queue sizes used here.
            let elem = unsafe { ring_base.add(ring_idx) };
            // SAFETY: `elem` lies inside `used`, aligned (above). Single-threaded.
            unsafe { core::ptr::write(elem, VirtqUsedElem { id, len }) };
            // SAFETY: `used` is the start of the used ring, a live, aligned
            // `Vec<u64>` buffer. Single-threaded.
            unsafe { (*used).idx = used_idx };
        }

        /// Simulate the device moving `used.idx` without writing an element.
        fn set_used_idx(&mut self, used_idx: u16)
        {
            let used = self.used.as_mut_ptr().cast::<VirtqUsed>();
            // SAFETY: `used` is the start of the used ring, a live, aligned
            // `Vec<u64>` buffer. Single-threaded.
            unsafe { (*used).idx = used_idx };
        }

        /// The available ring's `idx` field and its entry at `slot`.
        fn avail(&self, slot: usize) -> (u16, u16)
        {
            // The ring as bytes: the 2-byte flags, the 2-byte index and the
            // ring entries after them.
            let bytes: Vec<u8> = self.avail.iter().flat_map(|w| w.to_ne_bytes()).collect();
            let word = |at: usize| u16::from_ne_bytes([bytes[at], bytes[at + 1]]);
            (word(2), word(4 + 2 * slot))
        }

        /// Simulate the device overwriting the available ring's `idx` (the
        /// ring is device-visible DMA memory).
        fn set_avail_idx(&mut self, avail_idx: u16)
        {
            let avail = self.avail.as_mut_ptr().cast::<VirtqAvail>();
            // SAFETY: `avail` is the start of the available ring, a live,
            // aligned `Vec<u64>` buffer. Single-threaded.
            unsafe { (*avail).idx = avail_idx };
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
    fn new_rejects_zero_non_power_of_two_and_oversized_queue_sizes()
    {
        let mut empty = Rings::new(1);
        assert!(empty.queue(0).is_none());
        // `% queue_size` of the wrapping u16 ring index skips or repeats
        // slots at the 65536 wrap unless the size is a power of two.
        let mut odd = Rings::new(3);
        assert!(odd.queue(3).is_none());
        let mut oversized = Rings::new(MAX_QUEUE_SIZE + 1);
        assert!(oversized.queue(MAX_QUEUE_SIZE + 1).is_none());
    }

    #[test]
    fn spec_maximum_queue_takes_a_chain_of_every_descriptor_and_frees_it()
    {
        // The bookkeeping is sized to the negotiated queue: at the spec's
        // 32768 a chain may use every descriptor, and its completion frees
        // every one again.
        let mut rings = Rings::new(MAX_QUEUE_SIZE);
        let mut vq = rings.queue(MAX_QUEUE_SIZE).expect("spec maximum");
        let full: Vec<(u64, u32, bool)> = vec![(0x1000, 1, true); usize::from(MAX_QUEUE_SIZE)];
        let head = vq.add_chain(&full).expect("every descriptor free");
        assert!(vq.add_chain(&[(0x2000, 1, false)]).is_none());
        rings.publish_used(0, u32::from(head), 1, 1);
        assert_eq!(vq.poll_used(), Ok(Some((head, 1))));
        assert!(vq.add_chain(&full).is_some());
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
            .add_chain(&[(0xA000, 0x200, false), (0xB000, 0x200, true)])
            .expect("two free descriptors available");

        // Device publishes the completion: ring[0] = {id: head, len: 0x200},
        // the device-writable buffer filled.
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
        rings.publish_used(0, u32::from(head), 0, 1);

        assert_eq!(vq.poll_used(), Ok(Some((head, 0))));
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
        // Complete out of submission order. No buffer is device-writable, so
        // each completion writes no byte.
        rings.publish_used(0, u32::from(b), 0, 1);
        rings.publish_used(1, u32::from(a), 0, 2);
        assert_eq!(vq.poll_used(), Ok(Some((b, 0))));
        assert_eq!(vq.poll_used(), Ok(Some((a, 0))));

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

    #[test]
    fn a_used_index_past_the_outstanding_chains_is_refused_whole_and_frees_nothing()
    {
        let mut rings = Rings::new(8);
        let mut vq = rings.queue(8).expect("valid queue size");
        let head = vq
            .add_chain(&[(0xA000, 1, true)])
            .expect("a free descriptor");
        // One chain outstanding, two elements published: more than the device
        // can have completed. The refusal consumes both and reads neither, so
        // the next poll sees nothing new.
        rings.publish_used(0, u32::from(head), 1, 1);
        rings.set_used_idx(2);
        assert_eq!(
            vq.poll_used(),
            Err(VirtqueueError::IndexPastOutstanding { used_idx: 2 })
        );
        assert_eq!(vq.poll_used(), Ok(None));
        // An index moved back reads, modulo 2^16, as a jump of 65535.
        rings.set_used_idx(1);
        assert_eq!(
            vq.poll_used(),
            Err(VirtqueueError::IndexPastOutstanding { used_idx: 1 })
        );
        // The chain is still outstanding, and a completion of it is taken.
        rings.publish_used(1, u32::from(head), 1, 2);
        assert_eq!(vq.poll_used(), Ok(Some((head, 1))));
        assert_eq!(free_count(&mut vq, 8), 8);
    }

    #[test]
    fn a_completion_length_is_clamped_to_its_chains_writable_buffers()
    {
        let mut rings = Rings::new(8);
        let mut vq = rings.queue(8).expect("valid queue size");
        // 16 bytes the device reads, then 32 it writes: a len counts only the
        // 32.
        let a = vq
            .add_chain(&[(0xA000, 16, false), (0xB000, 32, true)])
            .expect("two free descriptors available");
        let b = vq
            .add_chain(&[(0xC000, 16, false)])
            .expect("a free descriptor");
        rings.publish_used(0, u32::from(a), 33, 1);
        // A chain the device only reads holds no byte it can have written.
        rings.publish_used(1, u32::from(b), 16, 2);
        assert_eq!(vq.poll_used(), Ok(Some((a, 32))));
        assert_eq!(vq.poll_used(), Ok(Some((b, 0))));
        assert_eq!(free_count(&mut vq, 8), 8);
    }

    #[test]
    fn the_ring_indices_wrap_at_65536_onto_the_next_slot()
    {
        let mut rings = Rings::new(4);
        let mut vq = rings.queue(4).expect("valid queue size");
        // Both indices one short of the wrap, as the device's are after
        // 65535 completions.
        vq.chains.avail_idx = u16::MAX;
        vq.chains.last_used_idx = u16::MAX;
        rings.set_used_idx(u16::MAX);
        let a = vq
            .add_chain(&[(0xA000, 4, true)])
            .expect("a free descriptor");
        let b = vq
            .add_chain(&[(0xB000, 4, true)])
            .expect("a free descriptor");
        // Index 65535 is slot 3, and 0 slot 0.
        assert_eq!(rings.avail(3).1, a);
        assert_eq!(rings.avail(0), (1, b));
        rings.publish_used(3, u32::from(a), 4, 0);
        rings.publish_used(0, u32::from(b), 4, 1);
        assert_eq!(vq.poll_used(), Ok(Some((a, 4))));
        assert_eq!(vq.poll_used(), Ok(Some((b, 4))));
        assert_eq!(vq.poll_used(), Ok(None));
    }

    #[test]
    fn add_chain_publishes_at_its_own_index_whatever_the_device_wrote_there()
    {
        let mut rings = Rings::new(4);
        let mut vq = rings.queue(4).expect("valid queue size");
        let a = vq
            .add_chain(&[(0xA000, 1, false)])
            .expect("a free descriptor");
        // The device rewrites the published index; the next chain still takes
        // slot 1 and publishes index 2.
        rings.set_avail_idx(3);
        let b = vq
            .add_chain(&[(0xB000, 1, false)])
            .expect("a free descriptor");
        assert_eq!(rings.avail(0).1, a);
        assert_eq!(rings.avail(1), (2, b));
        assert_eq!(rings.avail(3).1, 0);
    }
}
