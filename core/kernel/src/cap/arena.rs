// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/cap/arena.rs

//! Body arena: the caller-funded storage of the kernel objects a syscall
//! makes at runtime without a Memory capability to retype them from.
//!
//! A range split (`SYS_MEMORY_SPLIT`, `SYS_MMIO_SPLIT`, `SYS_IRQ_SPLIT`,
//! `SYS_IOPORT_SPLIT`, `SYS_SCHED_SPLIT`), a copy or derivation of an `Mmio` or
//! `IoPort` capability, and an `Mmio` object's spilled mapping records are
//! funded by the `CSpace` the syscall inserts into or resolves through: each
//! takes a 128-byte chunk of a page from that `CSpace`'s slot-page pool, which
//! its holder funds the way it funds slots. Chunk 0 of each arena page holds
//! the page's header (`cap::object::ArenaPage`), a kernel object whose
//! reference count counts the page's live chunks; the wrapper keeps the
//! free-chunk list and the list of its arena pages.
//! core/kernel/docs/capability-internals.md § Body Arena owns the design,
//! including how a dying `CSpace` keeps only the pages that still hold a live
//! body.
//!
//! This module holds the parts that are pure logic: the carving and linking of
//! chunks within a page ([`carve_page`], [`push_chunk`], [`pop_chunk`]), and
//! the sort of a donation's kept arena pages ([`sort_list`]) and the cut of its
//! span around them ([`for_each_run`]). The caller serialises the chunk list (the
//! wrapper's pool lock).

use core::sync::atomic::{AtomicU64, Ordering};

/// Bytes of one arena chunk: the size class of every body an arena backs.
pub const CHUNK_BYTES: usize = 128;

/// Chunks one page holds, the header's chunk 0 included.
pub const CHUNKS_PER_PAGE: usize = crate::mm::PAGE_SIZE / CHUNK_BYTES;

/// Link every chunk of the page at `page` but chunk 0, which holds the page's
/// header, onto the list headed by `head`, lowest address first.
///
/// # Safety
/// `page` is a page-aligned, page-sized, writable block whose chunks 1 and up
/// nothing else references; the caller serialises `head`.
pub unsafe fn carve_page(head: &AtomicU64, page: *mut u8)
{
    for i in (1..CHUNKS_PER_PAGE).rev()
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

/// The page that holds `chunk`: its header sits at the page's first byte.
#[must_use]
pub fn page_of(chunk: usize) -> usize
{
    chunk & !(crate::mm::PAGE_SIZE - 1)
}

/// Call `run(from, to)` for each run of the page-aligned span `[start, end)`
/// left between `holes`, the page addresses of the arena pages a dying
/// `CSpace` keeps past it, given in ascending order. A hole outside the span
/// is skipped. The cost is one pass over `holes`.
pub fn for_each_run(
    start: u64,
    end: u64,
    holes: impl Iterator<Item = u64>,
    mut run: impl FnMut(u64, u64),
)
{
    let page = crate::mm::PAGE_SIZE as u64;
    let mut cur = start;
    for h in holes
    {
        if h < cur || h >= end
        {
            continue;
        }
        if h > cur
        {
            run(cur, h);
        }
        cur = h + page;
    }
    if cur < end
    {
        run(cur, end);
    }
}

/// Sort the intrusive singly linked list headed by `head` ascending by `key`
/// and return its new head: a merge sort, `O(n log n)` with recursion depth
/// `O(log n)`, which allocates nothing. `next` reads a node's link and
/// `set_next` writes it.
///
/// # Safety
/// Every node on the list is valid for `next`, `set_next`, and `key`, and
/// the list ends in null and has no cycle.
pub unsafe fn sort_list<N>(
    head: *mut N,
    next: &impl Fn(*mut N) -> *mut N,
    set_next: &impl Fn(*mut N, *mut N),
    key: &impl Fn(*mut N) -> u64,
) -> *mut N
{
    if head.is_null() || next(head).is_null()
    {
        return head;
    }
    // Split at the middle: `slow` ends on the last node of the first half.
    let mut slow = head;
    let mut fast = next(head);
    while !fast.is_null()
    {
        fast = next(fast);
        if !fast.is_null()
        {
            slow = next(slow);
            fast = next(fast);
        }
    }
    let second = next(slow);
    set_next(slow, core::ptr::null_mut());
    // SAFETY: both halves are null-terminated sublists of the caller's list.
    let (mut a, mut b) = unsafe {
        (
            sort_list(head, next, set_next, key),
            sort_list(second, next, set_next, key),
        )
    };
    let mut merged: *mut N = core::ptr::null_mut();
    let mut tail: *mut N = core::ptr::null_mut();
    while !a.is_null() || !b.is_null()
    {
        let take_a = b.is_null() || (!a.is_null() && key(a) <= key(b));
        let node = if take_a { a } else { b };
        if take_a
        {
            a = next(a);
        }
        else
        {
            b = next(b);
        }
        set_next(node, core::ptr::null_mut());
        if tail.is_null()
        {
            merged = node;
        }
        else
        {
            set_next(tail, node);
        }
        tail = node;
    }
    merged
}

#[cfg(test)]
mod tests
{
    use super::*;

    const P: u64 = crate::mm::PAGE_SIZE as u64;

    /// A zeroed, page-aligned page, freed when the guard drops.
    struct Page(*mut u8);

    impl Drop for Page
    {
        fn drop(&mut self)
        {
            // SAFETY: allocated by page() with this layout.
            unsafe { std::alloc::dealloc(self.0, layout()) };
        }
    }

    fn layout() -> std::alloc::Layout
    {
        std::alloc::Layout::from_size_align(crate::mm::PAGE_SIZE, crate::mm::PAGE_SIZE).unwrap()
    }

    fn page() -> (Page, *mut u8)
    {
        // SAFETY: a non-zero-size layout.
        let p = unsafe { std::alloc::alloc_zeroed(layout()) };
        assert!(!p.is_null());
        (Page(p), p)
    }

    // The defect caught: a carve that overlaps chunks, hands out the header's
    // chunk 0 or a chunk outside the page, or loses one, and a pop that
    // returns stale contents.
    #[test]
    fn a_carved_page_yields_each_chunk_but_the_header_once_zeroed()
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
            assert!(off >= CHUNK_BYTES, "chunk 0 is the page header");
            assert!(off < crate::mm::PAGE_SIZE);
            assert_eq!(page_of(c as usize), p as usize);
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
        assert_eq!(seen.len(), CHUNKS_PER_PAGE - 1);
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

    /// The runs `for_each_run` cuts `[start, end)` into around `holes`.
    fn runs(start: u64, end: u64, holes: &[u64]) -> Vec<(u64, u64)>
    {
        let mut sorted = holes.to_vec();
        sorted.sort_unstable();
        let mut out = Vec::new();
        for_each_run(start, end, sorted.into_iter(), |a, b| out.push((a, b)));
        out
    }

    // The defect caught: a hole returned with its span (a live body freed
    // under its holder), a page of the span never returned (a leak), or a
    // hole outside the span cutting it.
    #[test]
    fn a_span_is_returned_whole_but_for_its_holes()
    {
        let (s, e) = (10 * P, 20 * P);
        assert_eq!(runs(s, e, &[]), [(s, e)]);
        assert_eq!(runs(s, e, &[2 * P, 30 * P]), [(s, e)], "holes outside");
        assert_eq!(
            runs(s, e, &[15 * P, 11 * P]),
            [(s, 11 * P), (12 * P, 15 * P), (16 * P, e)]
        );
        assert_eq!(
            runs(s, e, &[s, e - P]),
            [(s + P, e - P)],
            "holes at both ends"
        );
        assert_eq!(runs(s, s + P, &[s]), [], "a one-page span that is a hole");
    }

    struct Node
    {
        key: u64,
        next: *mut Node,
    }

    // The defect caught: a sort that drops or duplicates a node, leaves the
    // list out of order, or loops, which would leave a kept page out of the
    // cut or cut a span twice.
    #[test]
    fn an_intrusive_list_sorts_ascending_keeping_every_node()
    {
        for n in [0usize, 1, 2, 3, 7, 64, 257]
        {
            let mut nodes: Vec<Box<Node>> = (0..n)
                .map(|i| {
                    Box::new(Node {
                        key: ((i * 7919) % 1009) as u64,
                        next: core::ptr::null_mut(),
                    })
                })
                .collect();
            let mut head: *mut Node = core::ptr::null_mut();
            for node in nodes.iter_mut().rev()
            {
                node.next = head;
                head = core::ptr::from_mut(&mut **node);
            }
            // SAFETY: every node is a live Box above; the list ends in null.
            let mut cur = unsafe {
                sort_list(
                    head,
                    &|p: *mut Node| (*p).next,
                    &|p: *mut Node, q| (*p).next = q,
                    &|p: *mut Node| (*p).key,
                )
            };
            let mut got = Vec::new();
            while !cur.is_null()
            {
                // SAFETY: as above.
                unsafe {
                    got.push((*cur).key);
                    cur = (*cur).next;
                }
            }
            let mut want: Vec<u64> = nodes.iter().map(|b| b.key).collect();
            want.sort_unstable();
            assert_eq!(got, want, "{n} nodes");
        }
    }
}
