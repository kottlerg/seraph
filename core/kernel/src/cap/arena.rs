// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/cap/arena.rs

//! Body arena: the caller-funded storage of the kernel objects a syscall
//! makes at runtime without a Memory capability to retype them from.
//!
//! A range split (`SYS_MEMORY_SPLIT`, `SYS_MMIO_SPLIT`, `SYS_IRQ_SPLIT`,
//! `SYS_IOPORT_SPLIT`, `SYS_SCHED_SPLIT`), a copy or derivation of an `Mmio` or
//! `IoPort` capability, an `Mmio` object's spilled mapping records, and a
//! thread's I/O-port binding table are funded by the `CSpace` the syscall
//! inserts into or resolves through: each takes 128-byte chunks, or whole
//! pages, from that `CSpace`'s slot-page pool, which its holder funds the way
//! it funds slots. The `CSpace` wrapper keeps the chunk free list and the
//! count of leases this module defines; core/kernel/docs/capability-internals.md
//! § Body Arena owns the design, including why a `CSpace`'s donations outlive
//! it while a body it funded lives on.
//!
//! This module holds the parts that are pure logic: the lease count and its
//! teardown transition ([`ArenaLive`]), and the carving and linking of chunks
//! within a page ([`carve_page`], [`push_chunk`], [`pop_chunk`]). The caller
//! serialises the chunk list (the wrapper's pool lock).

use core::sync::atomic::{AtomicU64, Ordering};

/// Bytes of one arena chunk: the size class of every body an arena backs.
pub const CHUNK_BYTES: usize = 128;

/// Chunks one page holds.
pub const CHUNKS_PER_PAGE: usize = crate::mm::PAGE_SIZE / CHUNK_BYTES;

/// The bit of [`ArenaLive`]'s word set once the funding `CSpace`'s teardown
/// has begun. The count of leases below it never reaches it: each lease is a
/// chunk or a page of donated memory.
const DYING: u64 = 1 << 63;

/// The leases an arena has outstanding (chunks and pages handed out and not
/// yet returned), and whether its `CSpace`'s teardown has begun.
///
/// The funding `CSpace`'s teardown reclaims its donations only once both
/// hold: its teardown has begun ([`begin_teardown`](Self::begin_teardown)),
/// and no lease is outstanding. Whichever of those two events comes last
/// reports it, exactly once: `begin_teardown` returns `true` when no lease is
/// outstanding, and otherwise the [`release`](Self::release) of the last
/// lease returns `true`. Leases are never taken after the teardown begins,
/// since a `CSpace` with no references accepts no insert.
pub struct ArenaLive(AtomicU64);

impl ArenaLive
{
    /// No lease outstanding, teardown not begun.
    #[must_use]
    pub const fn new() -> Self
    {
        Self(AtomicU64::new(0))
    }

    /// Count one lease handed out.
    pub fn retain(&self)
    {
        let prev = self.0.fetch_add(1, Ordering::AcqRel);
        debug_assert!(
            prev & DYING == 0,
            "arena lease taken after its CSpace's teardown began"
        );
    }

    /// Count one lease returned. Returns `true` when it was the last one and
    /// the teardown has begun: the caller then completes the teardown.
    #[must_use]
    pub fn release(&self) -> bool
    {
        let prev = self.0.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev & !DYING != 0, "arena lease released twice");
        prev == DYING | 1
    }

    /// Mark the teardown begun. Returns `true` when no lease is outstanding:
    /// the caller then completes the teardown itself.
    #[must_use]
    pub fn begin_teardown(&self) -> bool
    {
        let prev = self.0.fetch_or(DYING, Ordering::AcqRel);
        debug_assert!(prev & DYING == 0, "arena teardown begun twice");
        prev == 0
    }

    /// Whether the teardown has begun: the funding `CSpace` has been drained
    /// and waits only for its last lease.
    #[must_use]
    pub fn teardown_begun(&self) -> bool
    {
        self.0.load(Ordering::Acquire) & DYING != 0
    }
}

impl Default for ArenaLive
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// Link every chunk of the page at `page` onto the list headed by `head`,
/// lowest address first.
///
/// # Safety
/// `page` is a page-aligned, page-sized, writable block that nothing else
/// references; the caller serialises `head`.
pub unsafe fn carve_page(head: &AtomicU64, page: *mut u8)
{
    for i in (0..CHUNKS_PER_PAGE).rev()
    {
        // SAFETY: i < CHUNKS_PER_PAGE keeps the chunk inside the page
        // (caller contract).
        unsafe { push_chunk(head, page.add(i * CHUNK_BYTES)) };
    }
}

/// Push the chunk at `chunk` onto the list headed by `head`. The chunk's first
/// word holds the link to the next.
///
/// # Safety
/// `chunk` is a [`CHUNK_BYTES`]-sized, 8-byte-aligned, writable block of the
/// list's arena that nothing else references; the caller serialises `head`.
pub unsafe fn push_chunk(head: &AtomicU64, chunk: *mut u8)
{
    let next = head.load(Ordering::Relaxed);
    // cast_ptr_alignment: a chunk is CHUNK_BYTES-aligned within its page.
    #[allow(clippy::cast_ptr_alignment)]
    // SAFETY: caller contract.
    unsafe {
        chunk.cast::<u64>().write_volatile(next);
    };
    head.store(chunk as u64, Ordering::Relaxed);
}

/// Pop a chunk from the list headed by `head`, or `None` if it is empty. The
/// chunk is zeroed.
///
/// # Safety
/// Every chunk on the list was put there by [`carve_page`] or [`push_chunk`]
/// and is still owned by the list; the caller serialises `head`.
pub unsafe fn pop_chunk(head: &AtomicU64) -> Option<*mut u8>
{
    let top = head.load(Ordering::Relaxed);
    if top == 0
    {
        return None;
    }
    let chunk = top as *mut u8;
    // cast_ptr_alignment: a chunk is CHUNK_BYTES-aligned within its page.
    #[allow(clippy::cast_ptr_alignment)]
    // SAFETY: the chunk is on the list (caller contract), so its first word is
    // the link to the next; once popped it is the caller's alone.
    unsafe {
        head.store(chunk.cast::<u64>().read_volatile(), Ordering::Relaxed);
        core::ptr::write_bytes(chunk, 0, CHUNK_BYTES);
    }
    Some(chunk)
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Every order of `n` lease releases and one teardown begin, as the
    /// position of the begin among the releases (0 = before the first).
    fn completions_for(n: u64, begin_at: u64) -> u32
    {
        let live = ArenaLive::new();
        for _ in 0..n
        {
            live.retain();
        }
        let mut completions = 0;
        for i in 0..=n
        {
            if i == begin_at && live.begin_teardown()
            {
                completions += 1;
            }
            if i < n && live.release()
            {
                completions += 1;
            }
        }
        completions
    }

    // The defect caught: a teardown that never completes (donations leaked)
    // or completes twice (donations returned twice), for the begin landing
    // before, between, or after the releases of the last leases.
    #[test]
    fn teardown_completes_exactly_once_whatever_the_order_of_the_last_releases()
    {
        for n in 0..6
        {
            for begin_at in 0..=n
            {
                assert_eq!(
                    completions_for(n, begin_at),
                    1,
                    "{n} leases, teardown begun after {begin_at} releases"
                );
            }
        }
    }

    #[test]
    fn a_release_before_the_teardown_begins_completes_nothing()
    {
        let live = ArenaLive::new();
        live.retain();
        live.retain();
        assert!(!live.release());
        assert!(!live.teardown_begun());
        assert!(!live.begin_teardown(), "one lease is still out");
        assert!(live.teardown_begun());
        assert!(live.release(), "the last lease completes the teardown");
    }

    fn page() -> (Vec<u64>, *mut u8)
    {
        let mut backing = vec![0u64; crate::mm::PAGE_SIZE / 8];
        let p = backing.as_mut_ptr().cast::<u8>();
        (backing, p)
    }

    // The defect caught: a carve that overlaps chunks, hands out a chunk
    // outside the page, or loses one, and a pop that returns stale contents.
    #[test]
    fn a_carved_page_yields_each_of_its_chunks_once_zeroed()
    {
        let (_backing, p) = page();
        let head = AtomicU64::new(0);
        // SAFETY: p is a fresh page-sized block; head is local.
        unsafe { carve_page(&head, p) };
        let mut seen = Vec::new();
        // SAFETY: every chunk on the list came from carve_page above.
        while let Some(c) = unsafe { pop_chunk(&head) }
        {
            let off = c as usize - p as usize;
            assert_eq!(off % CHUNK_BYTES, 0);
            assert!(off < crate::mm::PAGE_SIZE);
            // SAFETY: c is a popped chunk of CHUNK_BYTES.
            assert!(
                unsafe { core::slice::from_raw_parts(c, CHUNK_BYTES) }
                    .iter()
                    .all(|&b| b == 0)
            );
            seen.push(off);
        }
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), CHUNKS_PER_PAGE);
    }

    #[test]
    fn a_pushed_chunk_is_the_next_one_popped()
    {
        let (_backing, p) = page();
        let head = AtomicU64::new(0);
        // SAFETY: as above.
        unsafe { carve_page(&head, p) };
        // SAFETY: as above.
        let a = unsafe { pop_chunk(&head) }.unwrap();
        // SAFETY: a is a chunk of this arena, popped above and no longer used.
        unsafe { push_chunk(&head, a) };
        // SAFETY: as above.
        assert_eq!(unsafe { pop_chunk(&head) }, Some(a));
    }
}
