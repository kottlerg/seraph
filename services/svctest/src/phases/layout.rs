// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/layout.rs

//! Per-process address-space bounds: the heap and reservation arena placed in
//! the zones sized to the user half, one allocation far past the free heap
//! tail, freed reservation VA reused past any fixed run-table size, a
//! main-thread TLS block wider than a page, spawned threads' IPC buffers in the
//! arena, and the loader's parse of the stack note std emits.

use std::cell::RefCell;
use std::collections::BTreeSet;
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
        Phase {
            name: "spawned_ipc_buffer_in_arena",
            run: spawned_ipc_buffer_in_arena_phase,
        },
        Phase {
            name: "stack_note_parsed",
            run: stack_note_parsed_phase,
        },
    ]
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
        [
            1 << 38,
            (1 << 47) - 4096,
            1 << 47,
            (1 << 56) - 4096,
            1 << 56
        ]
        .contains(&top),
        "user_va_top {top:#x} is no supported mode's user top"
    );
    let zones = process_layout::growth_zones(top);

    let boxed = Box::new(0u64);
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

/// A spawned thread's IPC buffer is a page of its own in the reservation
/// arena, outside the byte heap, whose demand floor the pager backs: the
/// kernel's IPC-buffer copies are not restartable, so the page is one the
/// runtime mapped from a grant of its own (docs/userspace-memory-model.md
/// § Page Reservations). A thread spawned by that thread gets its own page
/// too, its grant requested over the first thread's buffer, and the two
/// threads, both live, hold different pages.
pub fn spawned_ipc_buffer_in_arena_phase(_: &Caps)
{
    let zones = process_layout::growth_zones(std::os::seraph::user_va_top());
    let own_buffer = || std::os::seraph::current_ipc_buf().addr() as u64;
    let (outer, inner) = std::thread::spawn(move || {
        let inner = std::thread::spawn(own_buffer)
            .join()
            .expect("nested IPC-buffer thread panicked");
        (own_buffer(), inner)
    })
    .join()
    .expect("IPC-buffer thread panicked");

    for (who, va) in [("spawned", outer), ("nested", inner)]
    {
        assert_ne!(va, 0, "{who} thread registered no IPC buffer");
        assert!(
            va.is_multiple_of(syscall_abi::PAGE_SIZE),
            "{who} thread's IPC buffer {va:#x} is not page-aligned"
        );
        assert!(
            va >= zones.arena.window.base && va < zones.arena.end_bound(),
            "{who} thread's IPC buffer {va:#x} outside the arena zone {:?}",
            zones.arena
        );
    }
    assert_ne!(
        outer, inner,
        "two live threads share the IPC buffer {outer:#x}"
    );
    std::os::seraph::log!("spawned IPC buffers in the arena: {outer:#x} {inner:#x}");
}

/// One allocation far larger than the free heap tail plus any single grow
/// increment succeeds, and the kernel can write into fresh heap pages: a
/// `SYS_GETRANDOM` into a fresh allocation's spare capacity fills it, whether
/// a grow mapped the page eagerly or it is a demand-floor page the pager backs
/// on the copy's fault, the call then re-executing (docs/fault-handling.md
/// § Kernel Copies).
pub fn large_single_allocation_phase(_: &Caps)
{
    const LARGE: usize = 8 << 20;

    let mut fresh: Vec<u8> = Vec::with_capacity(16 * PAGE);
    let spare = fresh.spare_capacity_mut();
    for page in 0..16usize
    {
        let at = spare
            .get_mut(page.checked_mul(PAGE).expect("fresh heap page offset")..)
            .expect("fresh heap page inside the spare capacity")
            .as_mut_ptr()
            .cast::<u8>();
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
    *big.last_mut().expect("the 8 MiB allocation is empty") = 0x5A;
    assert_eq!(big.first().copied(), Some(0xA5));
    assert_eq!(big.get(LARGE / 2).copied(), Some(0xA5));
    assert_eq!(big.last().copied(), Some(0x5A));
    drop(big);
    std::os::seraph::log!("large single allocation passed ({LARGE} bytes)");
}

/// Freed reservations leave more holes than any fixed run table holds, and
/// every hole is handed out again: a run table that dropped a freed run
/// would leave that VA unreachable until the process exits.
pub fn reservation_holes_reused_phase(_: &Caps)
{
    const HOLES: usize = 100;

    // Reserve every range first, then free every other one, so each freed
    // page lies between two live reservations and stays its own run.
    let ranges: Vec<ReservedRange> = (0..=2 * HOLES)
        .map(|_| reserve_pages(1).expect("reserve_pages(1) while making holes"))
        .collect();
    let mut kept: Vec<ReservedRange> = Vec::with_capacity(HOLES + 1);
    let mut holes: BTreeSet<u64> = BTreeSet::new();
    for (i, range) in ranges.into_iter().enumerate()
    {
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

/// The loader's parser reads the stack note std's `stack_pages!` emits:
/// `elf::parse_stack_note`, which procmgr runs on every image it creates,
/// finds svctest's own declared page count in its installed image. The
/// loader's refusal of a note outside `1..=MAX_PROCESS_STACK_PAGES` is
/// `process_abi::resolve_stack_pages`, host-tested; no image with such a
/// note is signed, so none reaches the loader in a boot.
pub fn stack_note_parsed_phase(_: &Caps)
{
    #[cfg(target_arch = "x86_64")]
    const MACHINE: u16 = elf::EM_X86_64;
    #[cfg(target_arch = "riscv64")]
    const MACHINE: u16 = elf::EM_RISCV;

    let image = std::fs::read("/tests/svctest").expect("read /tests/svctest");
    let (ehdr, _) =
        elf::validate_executable(&image, MACHINE).expect("svctest's image is a valid executable");
    // Defect guarded: std's copy of the note layout drifts from the one the
    // loader parses, so a std binary's declared stack is silently ignored.
    assert_eq!(
        elf::parse_stack_note(&ehdr, &image),
        Some(crate::SVCTEST_STACK_PAGES),
        "the loader's parser did not read svctest's declared stack pages"
    );
    std::os::seraph::log!("stack note parsed ({} pages)", crate::SVCTEST_STACK_PAGES);
}
