// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/mm/frame_map.rs

//! Frame map table: per-physical-frame counts of the user leaf mappings that
//! name each frame of RAM.
//!
//! The invariant the counts keep, the paths that raise and lower them, and the
//! ordering the retype check relies on are defined in
//! `core/kernel/docs/memory-internals.md` § Frame Map Table. The table is the
//! kernel's answer to "is this frame mapped into any address space now", which
//! `cap::retype::retype_allocate` asks before it carves a page into kernel
//! objects (docs/capability-model.md § Typed Memory), and whose per-region sum
//! `SYS_CAP_INFO`'s `CAP_INFO_MEMORY_MAPPINGS` reports to a Memory cap's holder.
//!
//! Storage is two-level: a table of chunk pointers, one per GiB below the top
//! of DRAM, each naming a 1 MiB buddy block of [`FRAMES_PER_CHUNK`]
//! `AtomicU32` counters that covers that GiB. [`init`] sizes the table from the
//! DRAM span and allocates a chunk for every GiB that holds RAM during Phase 4,
//! before the Phase-7 user-cap drain, so the cost is 8 B per GiB of span plus
//! 1 MiB per GiB of RAM, whatever the machine's size. A frame in a GiB with no
//! chunk (device memory, or a hole between RAM ranges) is untracked: raising or
//! lowering its count does nothing, and it never reads as mapped.

use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering};

use crate::mm::PAGE_SIZE;

/// Log2 of the physical span one chunk covers (1 GiB).
const CHUNK_SHIFT: u32 = 30;

/// Counters per chunk: the 4 KiB frames of one GiB.
const FRAMES_PER_CHUNK: usize = 1 << (CHUNK_SHIFT - 12);

/// Buddy order of one chunk's counter block: `FRAMES_PER_CHUNK` four-byte
/// counters fill `2^CHUNK_ORDER` pages exactly.
#[cfg(not(test))]
const CHUNK_ORDER: usize = 8;

// Chunk geometry is an encoding artefact, not a capacity: one GiB of frames is
// exactly one order-`CHUNK_ORDER` buddy block of counters.
#[cfg(not(test))]
const _: () = assert!(FRAMES_PER_CHUNK * 4 == PAGE_SIZE << CHUNK_ORDER);

/// The chunk-table slots covering `[0, dram_top)`: one per GiB the span
/// touches.
#[must_use]
pub fn chunk_slots(dram_top: u64) -> usize
{
    usize::try_from(dram_top.div_ceil(1 << CHUNK_SHIFT)).unwrap_or(usize::MAX)
}

/// The GiB indexes `[first, last]` the non-empty range `[base, base + size)`
/// touches, or `None` for an empty range.
fn chunks_touched(base: u64, size: u64) -> Option<(usize, usize)>
{
    let last_byte = base.checked_add(size.checked_sub(1)?)?;
    Some((
        usize::try_from(base >> CHUNK_SHIFT).ok()?,
        usize::try_from(last_byte >> CHUNK_SHIFT).ok()?,
    ))
}

/// Per-frame user-mapping counters, chunked per GiB of physical address space.
pub struct FrameMap
{
    /// The chunk table: `slots` pointers, entry `i` covering
    /// `[i << CHUNK_SHIFT, (i + 1) << CHUNK_SHIFT)` and null when that GiB
    /// holds no RAM. Null with `slots == 0` until [`FrameMap::install_table`];
    /// written once during single-threaded Phase 4 and read-only afterwards.
    table: AtomicPtr<AtomicPtr<AtomicU32>>,
    /// Entries of `table`.
    slots: AtomicUsize,
}

impl FrameMap
{
    /// An empty table: every frame untracked.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            table: AtomicPtr::new(core::ptr::null_mut()),
            slots: AtomicUsize::new(0),
        }
    }

    /// Install the chunk table of `slots` entries at `table`.
    ///
    /// # Safety
    /// `table` points at `slots` null `AtomicPtr`s (zeroed memory) that live
    /// for the rest of the kernel's life and nothing else uses; no other CPU
    /// reads the map yet, and no table is installed.
    unsafe fn install_table(&self, table: *mut AtomicPtr<AtomicU32>, slots: usize)
    {
        self.slots.store(slots, Ordering::Relaxed);
        self.table.store(table, Ordering::Release);
    }

    /// The table entry for GiB `index`, or `None` past the table.
    fn slot(&self, index: usize) -> Option<&AtomicPtr<AtomicU32>>
    {
        let table = self.table.load(Ordering::Acquire);
        if table.is_null() || index >= self.slots.load(Ordering::Relaxed)
        {
            return None;
        }
        // SAFETY: a non-null table holds `slots` live entries for the kernel's
        // lifetime (install_table's contract), and index is below it.
        Some(unsafe { &*table.add(index) })
    }

    /// Install `counters` as the chunk covering GiB `index`; `false` when the
    /// index is past the table or the GiB already has a chunk.
    ///
    /// # Safety
    /// `counters` points at [`FRAMES_PER_CHUNK`] zeroed `AtomicU32`s that live
    /// for the rest of the kernel's life and nothing else uses; no other CPU
    /// reads the table yet.
    unsafe fn install_chunk(&self, index: usize, counters: *mut AtomicU32) -> bool
    {
        let Some(slot) = self.slot(index)
        else
        {
            return false;
        };
        slot.compare_exchange(
            core::ptr::null_mut(),
            counters,
            Ordering::Release,
            Ordering::Relaxed,
        )
        .is_ok()
    }

    /// Give every GiB that one of `ram` ranges `(base, size)` touches a chunk
    /// from `alloc_chunk`, once each. Returns `Err(())` when `alloc_chunk`
    /// fails; a range past the table is ignored (the table covers DRAM).
    ///
    /// # Safety
    /// Each pointer `alloc_chunk` returns meets [`Self::install_chunk`]'s
    /// contract; the boot thread is alone.
    unsafe fn populate(
        &self,
        ram: impl Iterator<Item = (u64, u64)>,
        mut alloc_chunk: impl FnMut() -> Option<*mut AtomicU32>,
    ) -> Result<(), ()>
    {
        for (base, size) in ram
        {
            let Some((first, last)) = chunks_touched(base, size)
            else
            {
                continue;
            };
            for index in first..=last
            {
                if self
                    .slot(index)
                    .is_none_or(|s| !s.load(Ordering::Relaxed).is_null())
                {
                    continue;
                }
                let counters = alloc_chunk().ok_or(())?;
                // SAFETY: caller's contract; the slot is in range and empty.
                unsafe { self.install_chunk(index, counters) };
            }
        }
        Ok(())
    }

    /// The counter of the frame holding `phys`, or `None` when it is untracked.
    fn counter(&self, phys: u64) -> Option<&AtomicU32>
    {
        let index = usize::try_from(phys >> CHUNK_SHIFT).ok()?;
        let chunk = self.slot(index)?.load(Ordering::Acquire);
        if chunk.is_null()
        {
            return None;
        }
        // Lossless: the mask keeps the low `CHUNK_SHIFT - 12` bits.
        #[allow(clippy::cast_possible_truncation)]
        let slot = ((phys >> 12) as usize) & (FRAMES_PER_CHUNK - 1);
        // SAFETY: a non-null chunk holds FRAMES_PER_CHUNK live counters for the
        // kernel's lifetime (install_chunk's contract) and slot is in range.
        Some(unsafe { &*chunk.add(slot) })
    }

    /// Count one more user leaf mapping of the frame holding `phys`.
    ///
    /// The `u32` ceiling is unreachable: 2^32 leaf PTEs naming one frame need
    /// 32 GiB of page tables, and a saturated count refuses the map, never wraps.
    ///
    /// # Errors
    /// `Err(())` when the count is already `u32::MAX`; nothing changes.
    pub fn raise(&self, phys: u64) -> Result<(), ()>
    {
        let Some(counter) = self.counter(phys)
        else
        {
            return Ok(());
        };
        counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
            .map(|_| ())
            .map_err(|_| ())
    }

    /// Count one fewer user leaf mapping of the frame holding `phys`.
    ///
    /// A count already at zero stays zero; that is an accounting defect (a
    /// removal with no matching raise), reported on the kernel console.
    pub fn lower(&self, phys: u64)
    {
        let Some(counter) = self.counter(phys)
        else
        {
            return;
        };
        if counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_err()
        {
            report_underflow(phys);
        }
    }

    /// True when any frame of `[phys, phys + len)` has a nonzero count.
    #[must_use]
    pub fn any_mapped(&self, phys: u64, len: u64) -> bool
    {
        let p = PAGE_SIZE as u64;
        let mut frame = phys & !(p - 1);
        let end = phys.saturating_add(len);
        while frame < end
        {
            if self
                .counter(frame)
                .is_some_and(|c| c.load(Ordering::SeqCst) != 0)
            {
                return true;
            }
            frame += p;
        }
        false
    }

    /// The sum of the counts of every frame of `[phys, phys + len)`,
    /// saturating at `u64::MAX`; an untracked frame counts zero.
    #[must_use]
    pub fn mappings_in(&self, phys: u64, len: u64) -> u64
    {
        let p = PAGE_SIZE as u64;
        let mut frame = phys & !(p - 1);
        let end = phys.saturating_add(len);
        let mut total: u64 = 0;
        while frame < end
        {
            if let Some(c) = self.counter(frame)
            {
                total = total.saturating_add(u64::from(c.load(Ordering::SeqCst)));
            }
            frame += p;
        }
        total
    }
}

#[cfg(not(test))]
fn report_underflow(phys: u64)
{
    crate::kprintln!(
        "FRAME MAP UNDERFLOW: frame 0x{:x} unmapped with no recorded mapping",
        phys
    );
}

#[cfg(test)]
fn report_underflow(_phys: u64)
{
    panic!("frame map count underflow");
}

impl Default for FrameMap
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// The kernel's frame map table.
pub static FRAME_MAP: FrameMap = FrameMap::new();

/// Size the chunk table from `dram_top` (one slot per GiB of span) and
/// allocate and install a zeroed chunk for every GiB a DRAM-typed entry of
/// `memory_map` touches. Fatal when the buddy cannot supply the table or a
/// chunk.
///
/// # Safety
/// The single boot thread, once, after Phase 3 (the table and chunks are
/// zeroed through the direct map) and before the Phase-7 drain and any user
/// mapping.
#[cfg(not(test))]
pub unsafe fn init(
    alloc: &mut crate::mm::BuddyAllocator,
    memory_map: &[boot_protocol::MemoryMapEntry],
    dram_top: u64,
)
{
    let slots = chunk_slots(dram_top);
    if slots == 0
    {
        return;
    }
    let table = crate::sched::alloc_zeroed_slab::<AtomicPtr<AtomicU32>>(
        slots * core::mem::size_of::<AtomicPtr<AtomicU32>>(),
        alloc,
        "FRAME_MAP_TABLE",
    );
    // SAFETY: the slab holds `slots` zeroed (null) pointers owned by the map
    // for the kernel's life; the boot thread is alone.
    unsafe { FRAME_MAP.install_table(table, slots) };
    let ram = memory_map
        .iter()
        .filter(|e| crate::mm::init::is_dram(e.memory_type))
        .map(|e| (e.physical_base, e.size));
    let alloc_chunk = || {
        let phys = alloc.alloc(CHUNK_ORDER)?;
        let virt = crate::mm::paging::phys_to_virt(phys);
        // SAFETY: the block is freshly allocated, owned here for the kernel's
        // life, and reached through the direct map active since Phase 3.
        unsafe { core::ptr::write_bytes(virt as *mut u8, 0, PAGE_SIZE << CHUNK_ORDER) };
        Some(virt as *mut AtomicU32)
    };
    // SAFETY: each chunk is zeroed and permanently owned; the boot thread is alone.
    if unsafe { FRAME_MAP.populate(ram, alloc_chunk) }.is_err()
    {
        crate::fatal("Phase 4: buddy exhausted allocating the frame map table");
    }
}

/// Count one more user leaf mapping of `phys` in [`FRAME_MAP`].
///
/// # Errors
/// `Err(())` when the frame's count is saturated.
pub fn raise(phys: u64) -> Result<(), ()>
{
    FRAME_MAP.raise(phys)
}

/// Count one fewer user leaf mapping of `phys` in [`FRAME_MAP`].
pub fn lower(phys: u64)
{
    FRAME_MAP.lower(phys);
}

/// True when [`FRAME_MAP`] counts a mapping of any frame of `[phys, phys + len)`.
#[must_use]
pub fn any_mapped(phys: u64, len: u64) -> bool
{
    FRAME_MAP.any_mapped(phys, len)
}

/// The sum of [`FRAME_MAP`]'s counts over the frames of `[phys, phys + len)`
/// (`SYS_CAP_INFO` with `CAP_INFO_MEMORY_MAPPINGS`).
#[must_use]
pub fn mappings_in(phys: u64, len: u64) -> u64
{
    FRAME_MAP.mappings_in(phys, len)
}

/// Runs of frames whose leaf mappings a walk has cleared and whose counts are
/// lowered only once the TLB invalidation covering those leaves is complete
/// (`core/kernel/docs/memory-internals.md` § Frame Map Table).
pub struct ReleaseBatch
{
    /// `(first frame, frame count)` runs of physically contiguous frames.
    runs: [(u64, u64); RELEASE_RUNS],
    len: usize,
}

impl Default for ReleaseBatch
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// Runs one [`ReleaseBatch`] holds before its owner must invalidate and drain.
/// A full batch never fails a walk: `AddressSpace::batch_cleared_frame`
/// invalidates, drains and pushes again, so the size only sets the round count.
const RELEASE_RUNS: usize = 16;

impl ReleaseBatch
{
    /// An empty batch.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            runs: [(0, 0); RELEASE_RUNS],
            len: 0,
        }
    }

    /// Add `phys`, extending the last run when `phys` follows it. Returns
    /// `false`, adding nothing, when it would need a new run and the batch is
    /// full.
    pub fn push(&mut self, phys: u64) -> bool
    {
        let p = PAGE_SIZE as u64;
        if let Some(last) = self.len.checked_sub(1).map(|i| &mut self.runs[i])
            && last.0 + last.1 * p == phys
        {
            last.1 += 1;
            return true;
        }
        if self.len == RELEASE_RUNS
        {
            return false;
        }
        self.runs[self.len] = (phys, 1);
        self.len += 1;
        true
    }

    /// Lower every batched frame's count in `map` and empty the batch.
    pub fn release_into(&mut self, map: &FrameMap)
    {
        let p = PAGE_SIZE as u64;
        for &(first, count) in &self.runs[..self.len]
        {
            for i in 0..count
            {
                map.lower(first + i * p);
            }
        }
        self.len = 0;
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const P: u64 = PAGE_SIZE as u64;

    /// A leaked, zeroed host chunk of counters.
    fn host_chunk() -> *mut AtomicU32
    {
        let counters: &'static mut [AtomicU32] = Box::leak(
            (0..FRAMES_PER_CHUNK)
                .map(|_| AtomicU32::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        counters.as_mut_ptr()
    }

    /// A map whose table spans `slots` GiB, every chunk empty.
    fn map_of(slots: usize) -> &'static FrameMap
    {
        let map: &'static FrameMap = Box::leak(Box::new(FrameMap::new()));
        let table: &'static mut [AtomicPtr<AtomicU32>] = Box::leak(
            (0..slots)
                .map(|_| AtomicPtr::new(core::ptr::null_mut()))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        // SAFETY: null entries leaked for the test's life, used only via `map`.
        unsafe { map.install_table(table.as_mut_ptr(), slots) };
        map
    }

    /// A map spanning 2 GiB whose chunk 1 (physical GiB 1) is backed.
    fn table_with_gib_one() -> &'static FrameMap
    {
        let map = map_of(2);
        // SAFETY: zeroed, leaked for the test's life, used only through `map`.
        assert!(unsafe { map.install_chunk(1, host_chunk()) });
        map
    }

    const GIB: u64 = 1 << 30;

    // Defect caught: a fixed table length (the former 256 GiB) refusing DRAM
    // past it, or a chunk allocated for a hole between RAM ranges.
    #[test]
    fn population_gives_a_chunk_to_each_ram_gib_and_none_to_holes()
    {
        let slots = chunk_slots(600 * GIB);
        assert_eq!(slots, 600);
        let map = map_of(slots);
        let mut allocated = 0;
        // RAM in GiB 0, GiBs 1-2 (a range straddling them, twice), and GiB 599.
        let ram = [
            (0, GIB / 2),
            (GIB + GIB / 2, GIB),
            (GIB + GIB / 2, GIB),
            (599 * GIB, GIB),
        ];
        // SAFETY: host chunks are zeroed and leaked.
        unsafe {
            map.populate(ram.into_iter(), || {
                allocated += 1;
                Some(host_chunk())
            })
        }
        .unwrap();
        assert_eq!(allocated, 4, "GiBs 0, 1, 2 and 599, each once");
        map.raise(599 * GIB + P).unwrap();
        assert!(
            map.any_mapped(599 * GIB + P, P),
            "a frame past 256 GiB is tracked"
        );
        map.raise(300 * GIB).unwrap();
        assert!(!map.any_mapped(300 * GIB, P), "a hole GiB is untracked");
    }

    #[test]
    fn a_failed_chunk_allocation_fails_population()
    {
        let map = map_of(1);
        // SAFETY: no chunk is installed.
        assert_eq!(
            unsafe { map.populate([(0, GIB)].into_iter(), || None) },
            Err(())
        );
    }

    #[test]
    fn a_mapping_is_seen_until_its_last_removal()
    {
        let map = table_with_gib_one();
        let frame = (1 << 30) + 5 * P;
        map.raise(frame).unwrap();
        map.raise(frame).unwrap();
        map.lower(frame);
        assert!(map.any_mapped(frame, P));
        assert!(
            map.any_mapped(frame - 3 * P, 4 * P),
            "a range reaching the frame"
        );
        assert!(!map.any_mapped(frame + P, 8 * P), "a range past the frame");
        map.lower(frame);
        assert!(!map.any_mapped(frame, P));
    }

    #[test]
    fn mappings_in_sums_every_frame_of_the_range()
    {
        let map = table_with_gib_one();
        let base = 1 << 30;
        map.raise(base).unwrap();
        map.raise(base + 2 * P).unwrap();
        map.raise(base + 2 * P).unwrap();
        assert_eq!(map.mappings_in(base, 3 * P), 3);
        assert_eq!(map.mappings_in(base + P, P), 0, "a frame with no mapping");
        assert_eq!(
            map.mappings_in(base - P, 2 * P),
            1,
            "an untracked frame below the chunk counts zero"
        );
    }

    #[test]
    fn frames_without_a_chunk_are_untracked()
    {
        let map = table_with_gib_one();
        map.raise(5 * P).unwrap();
        map.raise(u64::MAX & !(P - 1)).unwrap();
        assert!(!map.any_mapped(5 * P, P));
        // A removal of an untracked frame is not an underflow.
        map.lower(5 * P);
    }

    #[test]
    fn a_saturated_count_refuses_another_mapping()
    {
        let map = table_with_gib_one();
        let frame = 1 << 30;
        map.counter(frame)
            .unwrap()
            .store(u32::MAX, Ordering::SeqCst);
        assert_eq!(map.raise(frame), Err(()));
        assert_eq!(map.counter(frame).unwrap().load(Ordering::SeqCst), u32::MAX);
    }

    #[test]
    #[should_panic(expected = "underflow")]
    fn removing_an_unrecorded_mapping_is_an_underflow()
    {
        table_with_gib_one().lower(1 << 30);
    }

    #[test]
    fn a_release_batch_coalesces_runs_and_lowers_each_frame()
    {
        let map = table_with_gib_one();
        let base = 1 << 30;
        let frames = [base, base + P, base + 2 * P, base + 9 * P];
        let mut batch = ReleaseBatch::new();
        for &f in &frames
        {
            map.raise(f).unwrap();
            assert!(batch.push(f));
        }
        assert_eq!(batch.len, 2, "three contiguous frames form one run");
        batch.release_into(map);
        assert!(!map.any_mapped(base, 10 * P));
        assert_eq!(batch.len, 0);
    }

    #[test]
    fn a_full_release_batch_refuses_a_new_run()
    {
        let mut batch = ReleaseBatch::new();
        for i in 0..RELEASE_RUNS as u64
        {
            assert!(batch.push((1 << 30) + 2 * i * P));
        }
        let last = (1 << 30) + 2 * (RELEASE_RUNS as u64 - 1) * P;
        assert!(
            batch.push(last + P),
            "extending the last run needs no new run"
        );
        assert!(!batch.push(last + 3 * P));
    }
}
