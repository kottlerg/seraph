// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/layout.rs

//! Per-process address-space bounds: the heap and reservation arena placed in
//! the zones sized to the user half, one allocation far past the free heap
//! tail, freed reservation VA reused past any fixed run-table size, a
//! main-thread TLS block wider than a page, and the loader's refusal of a
//! stack note above `MAX_PROCESS_STACK_PAGES`.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::io::{Seek, SeekFrom, Write};
use std::os::seraph::{ReservedRange, reserve_pages, startup_info, unreserve_pages};

use crate::bootstrap::Caps;
use crate::runner::Phase;

const PAGE: usize = 4096;

/// Bytes of the wide thread-local below: three pages, so svctest's `PT_TLS`
/// block spans more than one page and its loader maps a multi-page block.
const WIDE_TLS_BYTES: usize = 3 * PAGE;

std::thread_local! {
    static WIDE_TLS: RefCell<[u8; WIDE_TLS_BYTES]> = const { RefCell::new([0; WIDE_TLS_BYTES]) };
}

/// Phases that need only the heap and the arena.
pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "growth_zones_follow_user_half",
            run: growth_zones_phase,
        },
        Phase {
            name: "large_single_allocation",
            run: large_single_allocation_phase,
        },
        Phase {
            name: "reservation_holes_reused",
            run: reservation_holes_reused_phase,
        },
        Phase {
            name: "wide_main_tls",
            run: wide_main_tls_phase,
        },
    ]
}

/// Phases that write a fixture under `/data/svctest`, so they run once the
/// filesystem phases have passed.
pub fn after_fs() -> &'static [Phase]
{
    &[Phase {
        name: "stack_note_refused",
        run: stack_note_refused_phase,
    }]
}

/// The heap and the reservation arena lie in the zones `process-layout`
/// sizes to this process's user half, which `_start` learned from the
/// kernel. Under a user half wider than Sv39's the zones lie above
/// `LAYOUT_VA_CEILING`; a runtime that never learned the size would leave
/// them in the Sv39 zones.
pub fn growth_zones_phase(_: &Caps)
{
    let top = std::os::seraph::user_va_top();
    assert!(
        [1 << 38, (1 << 47) - 4096, 1 << 47, 1 << 56].contains(&top),
        "user_va_top {top:#x} is no supported mode's user top"
    );
    let zones = process_layout::growth_zones(top);

    let boxed = Box::new(0_u64);
    let heap_va = (&raw const *boxed).addr() as u64;
    assert!(
        heap_va >= zones.heap.window.base && heap_va < zones.heap.end_bound(),
        "heap allocation {heap_va:#x} outside the heap zone {:?}",
        zones.heap
    );
    let range = reserve_pages(1).expect("reserve_pages(1)");
    let arena_va = range.va_start();
    unreserve_pages(range);
    assert!(
        arena_va >= zones.arena.window.base && arena_va < zones.arena.end_bound(),
        "reservation {arena_va:#x} outside the arena zone {:?}",
        zones.arena
    );
    if top > process_layout::LAYOUT_VA_CEILING
    {
        assert!(
            heap_va >= process_layout::LAYOUT_VA_CEILING,
            "heap {heap_va:#x} stayed below the fixed tier in a {top:#x} user half"
        );
    }
    std::os::seraph::log!("growth zones: top={top:#x} heap={heap_va:#x} arena={arena_va:#x}");
}

/// One allocation far larger than the free heap tail plus any single grow
/// increment succeeds, and fresh heap pages are backed before the allocator
/// hands them out: the kernel writes into a fresh allocation's spare
/// capacity, which fails on a page the pager has not backed.
pub fn large_single_allocation_phase(_: &Caps)
{
    const LARGE: usize = 8 << 20;

    let mut fresh: Vec<u8> = Vec::with_capacity(16 * PAGE);
    let spare = fresh.spare_capacity_mut();
    for page in 0..16
    {
        let at = spare[page * PAGE..].as_mut_ptr().cast::<u8>();
        // SAFETY: `at` is the start of a page-sized span of the Vec's spare
        // capacity, writable for 64 bytes, and any byte value is a valid u8.
        let n = unsafe { syscall::getrandom_raw(at, 64) }
            .unwrap_or_else(|e| panic!("getrandom into fresh heap page {page} failed: {e}"));
        assert_eq!(n, 64, "short getrandom into fresh heap page {page}");
    }
    drop(fresh);

    let mut big: Vec<u8> = Vec::new();
    big.try_reserve_exact(LARGE)
        .expect("one 8 MiB allocation refused");
    big.resize(LARGE, 0xA5);
    big[LARGE - 1] = 0x5A;
    assert_eq!(big[0], 0xA5);
    assert_eq!(big[LARGE / 2], 0xA5);
    assert_eq!(big[LARGE - 1], 0x5A);
    drop(big);
    std::os::seraph::log!("large single allocation passed ({LARGE} bytes)");
}

/// Freed reservations leave more holes than any fixed run table holds, and
/// every hole is handed out again: a run table that dropped a freed run
/// would leave that VA unreachable until the process exits.
pub fn reservation_holes_reused_phase(_: &Caps)
{
    const HOLES: usize = 100;

    let mut kept: Vec<ReservedRange> = Vec::with_capacity(HOLES + 1);
    let mut holes: BTreeSet<u64> = BTreeSet::new();
    for i in 0..=2 * HOLES
    {
        let range = reserve_pages(1).expect("reserve_pages(1) while making holes");
        if i % 2 == 1
        {
            holes.insert(range.va_start());
            unreserve_pages(range);
        }
        else
        {
            kept.push(range);
        }
    }
    assert_eq!(holes.len(), HOLES);

    // Lowest-address first fit returns the holes before any fresh VA; the
    // bound only stops a leak from looping forever.
    let mut refill: Vec<ReservedRange> = Vec::with_capacity(HOLES);
    while !holes.is_empty() && refill.len() < 4 * HOLES
    {
        let range = reserve_pages(1).expect("reserve_pages(1) while refilling holes");
        holes.remove(&range.va_start());
        refill.push(range);
    }
    let leaked = holes.len();
    for range in kept.into_iter().chain(refill)
    {
        unreserve_pages(range);
    }
    assert_eq!(
        leaked, 0,
        "{leaked} of {HOLES} freed reservation holes were never reused"
    );
    std::os::seraph::log!("reservation holes reused ({HOLES} holes)");
}

/// svctest's main TLS block is wider than a page: the loader maps all of it,
/// and a spawned thread gets its own zeroed copy.
pub fn wide_main_tls_phase(_: &Caps)
{
    let info = startup_info();
    assert!(
        info.tls_template_memsz > PAGE as u64,
        "PT_TLS memsz {} does not exceed a page",
        info.tls_template_memsz
    );
    assert_ne!(info.main_tls_vaddr, 0, "no main TLS block mapped");

    WIDE_TLS.with_borrow_mut(|block| {
        assert_eq!(block[0], 0);
        assert_eq!(block[WIDE_TLS_BYTES - 1], 0);
        block[0] = 0x11;
        block[WIDE_TLS_BYTES - 1] = 0x22;
    });
    let child = std::thread::spawn(|| {
        WIDE_TLS.with_borrow_mut(|block| {
            let seen = (block[0], block[WIDE_TLS_BYTES - 1]);
            block[WIDE_TLS_BYTES - 1] = 0x33;
            seen
        })
    })
    .join()
    .expect("wide-TLS child panicked");
    assert_eq!(child, (0, 0), "a spawned thread's TLS copy is not zeroed");
    WIDE_TLS.with_borrow(|block| {
        assert_eq!((block[0], block[WIDE_TLS_BYTES - 1]), (0x11, 0x22));
    });
    std::os::seraph::log!("wide main TLS passed ({} bytes)", info.tls_template_memsz);
}

/// Where svctest's own stack note's page count lies in its image: the one
/// `.note.seraph.stack` record (header, name, and its declared count).
fn stack_note_pages_offset(image: &[u8]) -> usize
{
    let mut needle: Vec<u8> = Vec::with_capacity(28);
    needle.extend_from_slice(&7_u32.to_le_bytes());
    needle.extend_from_slice(&8_u32.to_le_bytes());
    needle.extend_from_slice(&process_abi::NT_SERAPH_STACK.to_le_bytes());
    needle.extend_from_slice(&process_abi::SERAPH_NOTE_NAME);
    // Opaque to the optimiser, so no folded copy of the whole record can sit
    // in svctest's read-only data beside the real note.
    let pages = std::hint::black_box(crate::SVCTEST_STACK_PAGES);
    needle.extend_from_slice(&pages.to_le_bytes());
    needle.extend_from_slice(&0_u32.to_le_bytes());
    let hits: Vec<usize> = image
        .windows(needle.len())
        .enumerate()
        .filter_map(|(i, w)| (w == needle.as_slice()).then_some(i))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "svctest's stack note found {} times",
        hits.len()
    );
    hits[0] + 20
}

/// A binary whose stack note declares more than `MAX_PROCESS_STACK_PAGES` is
/// refused at spawn, where the loader once clamped it silently; the same
/// image with its note restored spawns and exits cleanly.
pub fn stack_note_refused_phase(_: &Caps)
{
    use std::process::Command;

    let path = "/data/svctest/stacknote";
    let mut image = std::fs::read("/tests/svctest").expect("read /tests/svctest");
    let at = stack_note_pages_offset(&image);
    let oversize = process_abi::MAX_PROCESS_STACK_PAGES + 1;
    image[at..at + 4].copy_from_slice(&oversize.to_le_bytes());
    std::fs::write(path, &image).expect("write the patched image");

    let refused = Command::new(path).arg("exit-code-zero").spawn();
    assert!(
        refused.is_err(),
        "a stack note of {oversize} pages was accepted"
    );

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("reopen the patched image");
    file.seek(SeekFrom::Start(at as u64))
        .expect("seek to the note");
    file.write_all(&crate::SVCTEST_STACK_PAGES.to_le_bytes())
        .expect("restore the note");
    drop(file);
    let status = Command::new(path)
        .arg("exit-code-zero")
        .status()
        .expect("the restored image did not spawn");
    assert!(status.success(), "the restored image exited {status}");

    std::fs::remove_file(path).expect("remove the patched image");
    std::os::seraph::log!("stack note of {oversize} pages refused");
}
