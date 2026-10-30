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
//! objects (docs/capability-model.md § Typed Memory).
//!
//! Storage is two-level: [`MAX_CHUNKS`] chunk pointers in BSS, each naming a
//! 1 MiB buddy block of [`FRAMES_PER_CHUNK`] `AtomicU32` counters that covers
//! one GiB of physical address space. [`init`] allocates a chunk for every GiB
//! the DRAM span touches during Phase 4, before the Phase-7 user-cap drain. A
//! frame in a GiB with no chunk (device memory outside DRAM) is untracked:
//! raising or lowering its count does nothing, and it never reads as mapped.

use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use crate::mm::PAGE_SIZE;

/// Log2 of the physical span one chunk covers (1 GiB).
const CHUNK_SHIFT: u32 = 30;

/// Counters per chunk: the 4 KiB frames of one GiB.
const FRAMES_PER_CHUNK: usize = 1 << (CHUNK_SHIFT - 12);

/// Buddy order of one chunk's counter block: `FRAMES_PER_CHUNK` four-byte
/// counters fill `2^CHUNK_ORDER` pages exactly.
#[cfg(not(test))]
const CHUNK_ORDER: usize = 8;

#[cfg(not(test))]
const _: () = assert!(FRAMES_PER_CHUNK * 4 == PAGE_SIZE << CHUNK_ORDER);

/// Chunk slots: the table covers physical addresses below 256 GiB, above the
/// ~248 GiB the boot table pool can direct-map (`BOOT_TABLE_POOL_SIZE`), so
/// every RAM frame the kernel can address has a slot.
pub const MAX_CHUNKS: usize = 256;

/// Per-frame user-mapping counters, chunked per GiB of physical address space.
pub struct FrameMap
{
    /// Chunk `i` covers `[i << CHUNK_SHIFT, (i + 1) << CHUNK_SHIFT)`; null when
    /// that GiB holds no DRAM. Written once each during single-threaded Phase 4
    /// and read-only afterwards.
    chunks: [AtomicPtr<AtomicU32>; MAX_CHUNKS],
}

impl FrameMap
{
    /// An empty table: every frame untracked.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            chunks: [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_CHUNKS],
        }
    }

    /// Install `counters` as the chunk covering GiB `index`.
    ///
    /// # Safety
    /// `counters` points at [`FRAMES_PER_CHUNK`] zeroed `AtomicU32`s that live
    /// for the rest of the kernel's life and nothing else uses; no other CPU
    /// reads the table yet.
    unsafe fn install_chunk(&self, index: usize, counters: *mut AtomicU32)
    {
        self.chunks[index].store(counters, Ordering::Release);
    }

    /// The counter of the frame holding `phys`, or `None` when it is untracked.
    fn counter(&self, phys: u64) -> Option<&AtomicU32>
    {
        let index = usize::try_from(phys >> CHUNK_SHIFT).ok()?;
        let chunk = self.chunks.get(index)?.load(Ordering::Acquire);
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

impl Default for ReleaseBatch
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// The kernel's frame map table.
pub static FRAME_MAP: FrameMap = FrameMap::new();

/// Allocate and install a zeroed chunk for every GiB that `[dram_bottom,
/// dram_top)` touches. Fatal when DRAM reaches past [`MAX_CHUNKS`] GiB or the
/// buddy cannot supply a chunk.
///
/// # Safety
/// The single boot thread, once, after Phase 3 (the chunks are zeroed through
/// the direct map) and before the Phase-7 drain and any user mapping.
#[cfg(not(test))]
pub unsafe fn init(alloc: &mut crate::mm::BuddyAllocator, dram_bottom: u64, dram_top: u64)
{
    if dram_top <= dram_bottom
    {
        return;
    }
    // Lossless: dram_top is checked against MAX_CHUNKS GiB right below.
    #[allow(clippy::cast_possible_truncation)]
    let (first, last) = (
        (dram_bottom >> CHUNK_SHIFT) as usize,
        ((dram_top - 1) >> CHUNK_SHIFT) as usize,
    );
    if last >= MAX_CHUNKS
    {
        crate::fatal("Phase 4: DRAM extends past the frame map table's 256 GiB");
    }
    for index in first..=last
    {
        let Some(phys) = alloc.alloc(CHUNK_ORDER)
        else
        {
            crate::fatal("Phase 4: buddy exhausted allocating the frame map table");
        };
        let virt = crate::mm::paging::phys_to_virt(phys);
        // SAFETY: the block is freshly allocated, owned here for the kernel's
        // life, and reached through the direct map active since Phase 3.
        unsafe { core::ptr::write_bytes(virt as *mut u8, 0, PAGE_SIZE << CHUNK_ORDER) };
        // SAFETY: zeroed, permanently owned, and the boot thread is alone.
        unsafe { FRAME_MAP.install_chunk(index, virt as *mut AtomicU32) };
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

/// Runs of frames whose leaf mappings a walk has cleared and whose counts are
/// lowered only once the TLB invalidation covering those leaves is complete
/// (`core/kernel/docs/memory-internals.md` § Frame Map Table).
pub struct ReleaseBatch
{
    /// `(first frame, frame count)` runs of physically contiguous frames.
    runs: [(u64, u64); RELEASE_RUNS],
    len: usize,
}

/// Runs one [`ReleaseBatch`] holds before its owner must invalidate and drain.
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

    /// A table whose chunk 1 (physical GiB 1) is backed by a leaked host buffer.
    fn table_with_gib_one() -> &'static FrameMap
    {
        let map: &'static FrameMap = Box::leak(Box::new(FrameMap::new()));
        let counters: &'static mut [AtomicU32] = Box::leak(
            (0..FRAMES_PER_CHUNK)
                .map(|_| AtomicU32::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        // SAFETY: zeroed, leaked for the test's life, used only through `map`.
        unsafe { map.install_chunk(1, counters.as_mut_ptr()) };
        map
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
