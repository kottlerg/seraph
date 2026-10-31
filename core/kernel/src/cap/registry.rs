// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/cap/registry.rs

//! The global `CSpace` registry: `CSpaceId` → (`*mut CSpace`, epoch).
//!
//! A boot-carved arena sized from RAM, one 16-byte [`RegistryEntry`] per page
//! of DRAM, so the id space never binds before the memory that pays for the
//! `CSpace`s does (every `CSpace` costs at least one creator-paid wrapper
//! page). Storage is two-level: a chunk table sized from RAM at boot
//! ([`chunks_for_ram`]), each slot naming one buddy block of
//! [`ENTRIES_PER_CHUNK`] entries, all installed during Phase 4 before the
//! Phase-7 user-cap drain. Vacant entries keep their
//! epoch and thread the id free list through their `next_free` word, so an
//! epoch persists across vacancy into the next tenant's registration. The
//! design is specified in core/kernel/docs/capability-internals.md
//! § `CSpace` Registry.

use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering};

use super::cspace::CSpace;
use super::slot::CSpaceId;

/// Buddy order of one registry chunk (1 MiB).
pub const REGISTRY_CHUNK_ORDER: usize = 8;

/// Entries per chunk: a `2^REGISTRY_CHUNK_ORDER`-page block of 16-byte
/// entries.
pub const ENTRIES_PER_CHUNK: usize =
    (crate::mm::PAGE_SIZE << REGISTRY_CHUNK_ORDER) / core::mem::size_of::<RegistryEntry>();

/// Most chunks any registry holds: every id they back, and the `NO_NEXT`
/// sentinel above them, fit the `u32` `CSpaceId`. Reached only past 16 TiB of
/// DRAM, where a registry of 2^32 ids still outnumbers the `CSpace`s that RAM
/// can hold beside everything else; a bound of the id width, not of RAM.
pub const MAX_ID_CHUNKS: usize = (u32::MAX as usize - 1) / ENTRIES_PER_CHUNK;

const _: () = assert!(core::mem::size_of::<RegistryEntry>() == 16);

/// `next_free` sentinel: end of the free list.
const NO_NEXT: u32 = u32::MAX;

/// One registry entry.
///
/// `ptr` is the live `CSpace` or null when vacant. `epoch` is a generation
/// tag redrawn each time the id is retired ([`CSpaceRegistry::retire`]); a
/// `SlotId` stamped with an earlier epoch fails [`CSpaceRegistry::lookup`].
/// It starts at 1, never 0, so the `SlotId` sentinel epoch `0` resolves
/// nothing. `next_free` links a vacant id into the free list; it is read and
/// written only under the registry's free-list lock.
///
/// The epoch width is `u32` because `SlotId.epoch` fixes it: widening would
/// grow the 12-byte `SlotId` and the 72-byte `CapabilitySlot` that embeds
/// four of them.
#[repr(C, align(16))]
pub struct RegistryEntry
{
    ptr: AtomicPtr<CSpace>,
    epoch: AtomicU32,
    next_free: AtomicU32,
}

impl RegistryEntry
{
    /// A never-used entry: vacant, epoch 1, unlinked.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            ptr: AtomicPtr::new(core::ptr::null_mut()),
            epoch: AtomicU32::new(1),
            next_free: AtomicU32::new(NO_NEXT),
        }
    }
}

impl Default for RegistryEntry
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// The chunked registry arena and its id allocator.
pub struct CSpaceRegistry
{
    /// The chunk table: `slots` pointers, entry `i` holding ids
    /// `[i * ENTRIES_PER_CHUNK, (i + 1) * ENTRIES_PER_CHUNK)` and null when not
    /// installed. Null with `slots == 0` until [`Self::install_table`];
    /// written during single-threaded Phase 4 and read-only afterwards.
    table: AtomicPtr<AtomicPtr<RegistryEntry>>,
    /// Entries of `table`.
    slots: AtomicUsize,
    /// Ids `[0, capacity)` are backed by installed chunks.
    capacity: AtomicU32,
    /// Ids `[0, high_water)` have been handed out at least once; the rest are
    /// fresh. Mutated only under `free_lock`.
    high_water: AtomicU32,
    /// Head of the intrusive free list of retired ids (`NO_NEXT` when empty).
    /// Mutated only under `free_lock`.
    free_head: AtomicU32,
    /// Serialises `high_water`, `free_head`, and every entry's `next_free`.
    /// `CSpace` create and destroy are rare beside the lookup paths, which
    /// never take it, and every hold is O(1).
    free_lock: crate::sync::Spinlock,
}

impl CSpaceRegistry
{
    /// An empty registry: no chunk installed, every allocation fails.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            table: AtomicPtr::new(core::ptr::null_mut()),
            slots: AtomicUsize::new(0),
            capacity: AtomicU32::new(0),
            high_water: AtomicU32::new(0),
            free_head: AtomicU32::new(NO_NEXT),
            free_lock: crate::sync::Spinlock::new(),
        }
    }

    /// A registry whose one-slot table `table` names an already initialised
    /// first chunk; the host-test registry's constructor.
    #[cfg(test)]
    const fn with_first_chunk(table: *mut AtomicPtr<RegistryEntry>) -> Self
    {
        let mut reg = Self::new();
        reg.table = AtomicPtr::new(table);
        reg.slots = AtomicUsize::new(1);
        reg.capacity = AtomicU32::new(ENTRIES_PER_CHUNK as u32);
        reg
    }

    /// Install the chunk table of `slots` entries at `table`.
    ///
    /// # Safety
    /// `table` points at `slots` null `AtomicPtr`s that live for the rest of
    /// the registry's life and nothing else uses; no table is installed yet
    /// and no other CPU uses the registry.
    pub unsafe fn install_table(&self, table: *mut AtomicPtr<RegistryEntry>, slots: usize)
    {
        self.slots
            .store(slots.min(MAX_ID_CHUNKS), Ordering::Relaxed);
        self.table.store(table, Ordering::Release);
    }

    /// The table slot of chunk `index`, or `None` past the table.
    fn slot(&self, index: usize) -> Option<&AtomicPtr<RegistryEntry>>
    {
        let table = self.table.load(Ordering::Acquire);
        if table.is_null() || index >= self.slots.load(Ordering::Relaxed)
        {
            return None;
        }
        // SAFETY: a non-null table holds `slots` live entries for the
        // registry's life (install_table's contract); index is below it.
        Some(unsafe { &*table.add(index) })
    }

    /// Initialise `entries` as never-used entries and install them as the
    /// next chunk, extending the capacity by [`ENTRIES_PER_CHUNK`].
    ///
    /// Returns `Err(())`, installing nothing, when every slot of the chunk
    /// table is installed.
    ///
    /// # Safety
    /// `entries` points at [`ENTRIES_PER_CHUNK`] writable, suitably aligned
    /// `RegistryEntry`-sized slots that live for the rest of the registry's
    /// life and nothing else uses; no other CPU uses the registry yet.
    pub unsafe fn install_chunk(&self, entries: *mut RegistryEntry) -> Result<(), ()>
    {
        let cap = self.capacity.load(Ordering::Relaxed) as usize;
        let Some(slot) = self.slot(cap / ENTRIES_PER_CHUNK)
        else
        {
            return Err(());
        };
        for i in 0..ENTRIES_PER_CHUNK
        {
            // SAFETY: in bounds of the caller's ENTRIES_PER_CHUNK slots, which
            // are exclusively owned here.
            unsafe { entries.add(i).write(RegistryEntry::new()) };
        }
        slot.store(entries, Ordering::Release);
        // Lossless: cap + ENTRIES_PER_CHUNK is at most the table's id count,
        // which MAX_ID_CHUNKS keeps below u32::MAX.
        #[allow(clippy::cast_possible_truncation)]
        self.capacity
            .store((cap + ENTRIES_PER_CHUNK) as u32, Ordering::Release);
        Ok(())
    }

    /// Ids the installed chunks back.
    #[must_use]
    pub fn capacity(&self) -> u32
    {
        self.capacity.load(Ordering::Acquire)
    }

    /// The entry for `id`, or `None` when no installed chunk backs it.
    fn entry(&self, id: CSpaceId) -> Option<&RegistryEntry>
    {
        let id = id as usize;
        let chunk = self.slot(id / ENTRIES_PER_CHUNK)?.load(Ordering::Acquire);
        if chunk.is_null()
        {
            return None;
        }
        // SAFETY: a non-null chunk holds ENTRIES_PER_CHUNK live entries for
        // the registry's life (install_chunk's contract); the offset is in
        // range.
        Some(unsafe { &*chunk.add(id % ENTRIES_PER_CHUNK) })
    }

    /// Hand out an unused id: the most recently retired one, else the next
    /// fresh one. `None` when every backed id is live.
    pub fn alloc(&self) -> Option<CSpaceId>
    {
        // SAFETY: paired with unlock_raw below; the hold is O(1).
        let saved = unsafe { self.free_lock.lock_raw() };
        let head = self.free_head.load(Ordering::Relaxed);
        let id = if head == NO_NEXT
        {
            let next = self.high_water.load(Ordering::Relaxed);
            if next < self.capacity.load(Ordering::Acquire)
            {
                self.high_water.store(next + 1, Ordering::Relaxed);
                Some(next)
            }
            else
            {
                None
            }
        }
        else
        {
            // A listed id is backed: only retired ids, all below capacity,
            // are pushed.
            let next = self
                .entry(head)
                .map_or(NO_NEXT, |e| e.next_free.swap(NO_NEXT, Ordering::Relaxed));
            self.free_head.store(next, Ordering::Relaxed);
            Some(head)
        };
        // SAFETY: paired with lock_raw above.
        unsafe { self.free_lock.unlock_raw(saved) };
        id
    }

    /// Publish `ptr` as the live `CSpace` for `id` and return the epoch its
    /// `SlotId`s stamp. `Err(())` when no installed chunk backs `id`.
    pub fn register(&self, id: CSpaceId, ptr: *mut CSpace) -> Result<u32, ()>
    {
        let entry = self.entry(id).ok_or(())?;
        debug_assert!(
            entry.ptr.load(Ordering::Acquire).is_null(),
            "register_cspace: id {id} already registered"
        );
        entry.ptr.store(ptr, Ordering::Release);
        Ok(entry.epoch.load(Ordering::Acquire))
    }

    /// Clear `id`'s live pointer; its epoch is unchanged until
    /// [`Self::retire`].
    pub fn unregister(&self, id: CSpaceId)
    {
        if let Some(entry) = self.entry(id)
        {
            entry.ptr.store(core::ptr::null_mut(), Ordering::Release);
        }
    }

    /// Store `new_epoch` as `id`'s epoch and return the id to the free list.
    ///
    /// Pre-condition: `id` is backed, unregistered, and not on the free list;
    /// `new_epoch` is non-zero and differs from the current epoch (the
    /// caller draws it, `cap::free_cspace_id` from the kernel CSPRNG). An
    /// unbacked `id` is ignored.
    pub fn retire(&self, id: CSpaceId, new_epoch: u32)
    {
        let Some(entry) = self.entry(id)
        else
        {
            return;
        };
        debug_assert!(
            entry.ptr.load(Ordering::Acquire).is_null(),
            "free_cspace_id called before unregister_cspace for id {id}"
        );
        debug_assert!(new_epoch != 0 && new_epoch != entry.epoch.load(Ordering::Relaxed));
        // Single logical writer to this entry's epoch in the free window: the
        // id is unregistered and not yet listed, so it is neither live nor
        // recyclable elsewhere. `lookup`'s Acquire double-load still rejects a
        // concurrent reader because the stored value differs from the old one.
        entry.epoch.store(new_epoch, Ordering::Release);
        // SAFETY: paired with unlock_raw below; the hold is O(1).
        let saved = unsafe { self.free_lock.lock_raw() };
        entry
            .next_free
            .store(self.free_head.load(Ordering::Relaxed), Ordering::Relaxed);
        self.free_head.store(id, Ordering::Relaxed);
        // SAFETY: paired with lock_raw above.
        unsafe { self.free_lock.unlock_raw(saved) };
    }

    /// `id`'s current epoch, or 0 when no installed chunk backs it.
    #[must_use]
    pub fn epoch(&self, id: CSpaceId) -> u32
    {
        self.entry(id)
            .map_or(0, |e| e.epoch.load(Ordering::Acquire))
    }

    /// Resolve `id` at `expected_epoch` to its live `CSpace`.
    ///
    /// `None` when `id` is unbacked, vacant, or carries another epoch. The
    /// double epoch load brackets the pointer load so a concurrent
    /// unregister → retire → reuse → register cannot present the new
    /// tenant's pointer alongside the old epoch.
    #[must_use]
    pub fn lookup(&self, id: CSpaceId, expected_epoch: u32) -> Option<*mut CSpace>
    {
        let entry = self.entry(id)?;
        if entry.epoch.load(Ordering::Acquire) != expected_epoch
        {
            return None;
        }
        let ptr = entry.ptr.load(Ordering::Acquire);
        if ptr.is_null() || entry.epoch.load(Ordering::Acquire) != expected_epoch
        {
            return None;
        }
        Some(ptr)
    }

    /// Overwrite `id`'s epoch without listing it, for a host test that
    /// models a recycle through the shared registry.
    #[cfg(test)]
    pub fn force_epoch(&self, id: CSpaceId, epoch: u32)
    {
        if let Some(entry) = self.entry(id)
        {
            entry.epoch.store(epoch, Ordering::Release);
        }
    }
}

impl Default for CSpaceRegistry
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// Chunks the arena needs to give every page of `ram_bytes` an id: at least
/// one, so the root `CSpace` always registers, and at most
/// [`MAX_ID_CHUNKS`], the `CSpaceId` width.
#[must_use]
pub fn chunks_for_ram(ram_bytes: u64) -> usize
{
    let pages = ram_bytes.div_ceil(crate::mm::PAGE_SIZE as u64);
    // Lossless on the 64-bit kernel.
    #[allow(clippy::cast_possible_truncation)]
    (pages as usize)
        .div_ceil(ENTRIES_PER_CHUNK)
        .clamp(1, MAX_ID_CHUNKS)
}

/// The host-test registry's single chunk, wired in by [`CSPACE_REGISTRY`]'s
/// test constructor.
#[cfg(test)]
static TEST_CHUNK: [RegistryEntry; ENTRIES_PER_CHUNK] =
    [const { RegistryEntry::new() }; ENTRIES_PER_CHUNK];

/// The kernel's `CSpace` registry; chunks installed by
/// `cap::init_cspace_registry` in Phase 4.
#[cfg(not(test))]
pub static CSPACE_REGISTRY: CSpaceRegistry = CSpaceRegistry::new();

/// The host-test registry: one statically backed chunk, shared by every
/// test that registers through `cap::register_cspace`.
#[cfg(test)]
pub static CSPACE_REGISTRY: CSpaceRegistry = CSpaceRegistry::with_first_chunk(
    core::ptr::addr_of!(TEST_TABLE)
        .cast::<AtomicPtr<RegistryEntry>>()
        .cast_mut(),
);

/// The host-test registry's one-slot chunk table, naming [`TEST_CHUNK`].
#[cfg(test)]
static TEST_TABLE: [AtomicPtr<RegistryEntry>; 1] = [AtomicPtr::new(
    core::ptr::addr_of!(TEST_CHUNK)
        .cast::<RegistryEntry>()
        .cast_mut(),
)];

#[cfg(test)]
mod tests
{
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    extern crate alloc;

    /// A registry with `chunks` heap-backed chunks installed.
    fn registry(chunks: usize) -> Box<CSpaceRegistry>
    {
        let reg = Box::new(CSpaceRegistry::new());
        let table: Vec<AtomicPtr<RegistryEntry>> = (0..chunks)
            .map(|_| AtomicPtr::new(core::ptr::null_mut()))
            .collect();
        let table = Box::leak(table.into_boxed_slice()).as_mut_ptr();
        // SAFETY: `chunks` leaked null slots, owned by this registry.
        unsafe { reg.install_table(table, chunks) };
        for _ in 0..chunks
        {
            let entries: Vec<RegistryEntry> = (0..ENTRIES_PER_CHUNK)
                .map(|_| RegistryEntry::new())
                .collect();
            let ptr = Box::leak(entries.into_boxed_slice()).as_mut_ptr();
            // SAFETY: ENTRIES_PER_CHUNK leaked entries, owned by this registry.
            unsafe { reg.install_chunk(ptr) }.unwrap();
        }
        reg
    }

    fn tenant(n: usize) -> *mut CSpace
    {
        core::ptr::NonNull::<CSpace>::dangling()
            .as_ptr()
            .wrapping_byte_add(n * 0x1000)
    }

    #[test]
    fn empty_registry_allocates_nothing()
    {
        let reg = registry(0);
        assert_eq!(reg.alloc(), None);
        assert!(reg.register(0, tenant(1)).is_err());
        assert_eq!(reg.lookup(0, 1), None);
    }

    #[test]
    fn alloc_hands_out_every_backed_id_then_fails()
    {
        let reg = registry(1);
        for expected in 0..ENTRIES_PER_CHUNK as u32
        {
            assert_eq!(reg.alloc(), Some(expected));
        }
        assert_eq!(reg.alloc(), None);
    }

    #[test]
    fn retired_ids_are_reused_lifo_before_fresh_ones()
    {
        let reg = registry(1);
        let a = reg.alloc().unwrap();
        let b = reg.alloc().unwrap();
        reg.retire(a, 7);
        reg.retire(b, 9);
        assert_eq!(reg.alloc(), Some(b));
        assert_eq!(reg.alloc(), Some(a));
        assert_eq!(reg.alloc(), Some(2));
    }

    #[test]
    fn epoch_persists_across_vacancy_into_the_next_tenant()
    {
        let reg = registry(1);
        let id = reg.alloc().unwrap();
        let first = reg.register(id, tenant(1)).unwrap();
        assert_eq!(first, 1, "a never-used entry starts at epoch 1");
        reg.unregister(id);
        reg.retire(id, 0xABCD);
        assert_eq!(reg.lookup(id, first), None, "vacant entry resolves nothing");
        assert_eq!(reg.alloc(), Some(id));
        let second = reg.register(id, tenant(2)).unwrap();
        assert_eq!(second, 0xABCD);
        assert_eq!(reg.lookup(id, first), None, "stale epoch rejected");
        assert_eq!(reg.lookup(id, second), Some(tenant(2)));
    }

    #[test]
    fn ids_across_a_chunk_boundary_resolve_to_distinct_entries()
    {
        let reg = registry(2);
        assert_eq!(reg.capacity() as usize, 2 * ENTRIES_PER_CHUNK);
        let last = (ENTRIES_PER_CHUNK - 1) as u32;
        let first_of_second = ENTRIES_PER_CHUNK as u32;
        let e1 = reg.register(last, tenant(1)).unwrap();
        let e2 = reg.register(first_of_second, tenant(2)).unwrap();
        assert_eq!(reg.lookup(last, e1), Some(tenant(1)));
        assert_eq!(reg.lookup(first_of_second, e2), Some(tenant(2)));
        reg.unregister(last);
        assert_eq!(reg.lookup(first_of_second, e2), Some(tenant(2)));
    }

    #[test]
    fn unbacked_id_is_rejected_everywhere()
    {
        let reg = registry(1);
        let beyond = ENTRIES_PER_CHUNK as u32;
        assert!(reg.register(beyond, tenant(1)).is_err());
        assert_eq!(reg.epoch(beyond), 0);
        assert_eq!(reg.lookup(beyond, 1), None);
        reg.retire(beyond, 5);
        assert_eq!(reg.alloc(), Some(0), "an unbacked retire lists nothing");
    }

    #[test]
    fn install_past_the_chunk_table_fails()
    {
        let reg = registry(2);
        let mut spare = RegistryEntry::new();
        // SAFETY: the call fails before touching `spare`.
        let r = unsafe { reg.install_chunk(core::ptr::from_mut(&mut spare)) };
        assert!(r.is_err());
    }

    // Defect caught: a fixed chunk table (the former 1024 slots, 256 GiB)
    // halting a larger machine, or a count that overflows the u32 id space.
    #[test]
    fn chunk_count_grows_with_ram_up_to_the_id_width()
    {
        let tib: u64 = 1 << 40;
        let per_chunk = ENTRIES_PER_CHUNK as u64 * crate::mm::PAGE_SIZE as u64;
        assert_eq!(chunks_for_ram(4 * tib) as u64, 4 * tib / per_chunk);
        assert_eq!(chunks_for_ram(64 * tib), MAX_ID_CHUNKS);
        assert!(MAX_ID_CHUNKS * ENTRIES_PER_CHUNK < u32::MAX as usize);
    }

    #[test]
    fn chunk_count_covers_every_ram_page()
    {
        let page = crate::mm::PAGE_SIZE as u64;
        let per_chunk = ENTRIES_PER_CHUNK as u64 * page;
        assert_eq!(chunks_for_ram(0), 1);
        assert_eq!(chunks_for_ram(per_chunk), 1);
        assert_eq!(chunks_for_ram(per_chunk + page), 2);
        assert_eq!(chunks_for_ram(per_chunk + 1), 2);
    }
}
