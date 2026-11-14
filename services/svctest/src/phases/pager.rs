// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/pager.rs

//! Demand-paging pager surface: memmgr backs reserved anonymous regions on
//! fault, and declines (kills) faults outside any registered region.
//!
//! Drives `/programs/demandpaged`. Demand paging is the system-wide default, so
//! the first two phases spawn it with no opt-in; the third opts out via
//! `std::os::seraph::CommandExt::pinned`:
//!
//!   * **positive** — the child reserves, registers, touches, and reads back a
//!     multi-page region; memmgr backs each first touch on fault. A clean exit
//!     proves the round-trip (touch → fault → map → resume) and that repeat
//!     access does not re-fault (the read-back pass sees the written pattern) —
//!     all with no opt-in flag, proving the default binds a pager.
//!   * **negative** — the child touches an *unregistered* reserved page; memmgr
//!     declines and the kernel kills it, proving preserved segfault semantics
//!     under a bound pager.
//!   * **pinned** — the child is spawned `pinned(true)`, so procmgr binds no
//!     pager and delegates no address space. Touching its *registered* region
//!     (which exits cleanly in **positive**) now faults with no handler and the
//!     kernel kills it, proving the opt-out leaves the process eager-mapped with
//!     no pager on the fault path.
//!
//! After each spawn/die cycle the all-RAM-accounted identity must still hold,
//! directly guarding against fault-path accounting drift (a stray
//! `pool_total` credit on demand allocation would break it).
//!
//! A fourth phase, **forged badge**, shows a process cannot make the kernel
//! stamp its faults with a badge other than its own memmgr cap's: binding its
//! own thread to its pager cap with a binder-supplied badge (another
//! process's, as a forger would pass) is refused with `InvalidArgument`, and
//! the same bind with the reserved word 0 succeeds, so the badge word alone
//! is the refusal's cause (docs/fault-handling.md § Security). The fault badge
//! is therefore always the derivation badge of a cap the binder holds, and a
//! process holding only its own memmgr cap cannot back another's region.
//!
//! A fifth phase, **refused access**, shows memmgr declines a fault whose
//! access the region's protection refuses, whether or not the page is backed:
//! no backing satisfies such an access, so a resume would fault again forever.
//! Each decline is checked for memmgr's reason code: a refused access, then,
//! once the region is unregistered, no region.
//!
//! A sixth phase, **page-table drain**, shows a demand fault is backed when
//! the faulting address space's page-table pool is empty: the child registers
//! a region, empties its own pool with mappings of its own, then touches a
//! block of the region that needs a fresh page table. memmgr funds the pool
//! itself and resumes rather than declining the fault.
//!
//! A seventh phase, **teardown**, shows `unregister_demand_paged` releases a
//! demand region whole: the child registers and fills a region, tears it
//! down, and registers one of the same size again, which the reservation
//! allocator places on the same VA. memmgr accepts that registration only if
//! the teardown removed the first one.
//!
//! An eighth phase, **fault cost**, times the faults of a demand region one
//! chunk at a time and logs the mean, the figure the cost of memmgr's work on
//! a fault is measured by.
//!
//! A ninth phase, **fragmented**, leaves the pool free pages in runs of one
//! page fewer than a demand chunk and no run of a chunk's size, and touches a
//! demand region: memmgr must back each fault from a smaller run.

use std::os::seraph::process::CommandExt;
use std::os::seraph::startup_info;

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "demand_paging",
            run: demand_paging_phase,
        },
        Phase {
            name: "demand_paging_segfault",
            run: demand_paging_segfault_phase,
        },
        Phase {
            name: "demand_paging_pinned",
            run: demand_paging_pinned_phase,
        },
        Phase {
            name: "pager_forged_badge_refused",
            run: pager_forged_badge_phase,
        },
        Phase {
            name: "pager_refused_access_declined",
            run: pager_refused_access_phase,
        },
        Phase {
            name: "demand_paging_pt_drain",
            run: demand_paging_pt_drain_phase,
        },
        Phase {
            name: "demand_paging_teardown",
            run: demand_paging_teardown_phase,
        },
        Phase {
            name: "demand_fault_cost",
            run: demand_fault_cost_phase,
        },
        Phase {
            name: "demand_fault_fragmented",
            run: demand_fault_fragmented_phase,
        },
    ]
}

/// Send memmgr, on this process's own memmgr cap, the fault message the
/// kernel would for an access to `va` (memmgr attributes a fault by the
/// cap's badge, docs/fault-handling.md § Security), and return its reply
/// label, `FAULT_REPLY_RESUME` or `FAULT_REPLY_FORWARD`, with the decline
/// code a `FAULT_REPLY_FORWARD` carries in the low half of data word 0 (zero
/// on a resume): services/memmgr/docs/ipc-interface.md § Kernel-origin fault
/// message tables the codes.
fn forged_vm_fault(va: u64, access: u64) -> (u64, u64)
{
    let info = startup_info();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = ipc::IpcMessage::builder(syscall_abi::FAULT_LABEL)
        .word(0, syscall_abi::FAULT_KIND_VM)
        .word(1, va)
        .word(2, access)
        .word(3, 0)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(info.memmgr_endpoint, &msg, ipc_buf) }
        .expect("refused_access: forged fault ipc_call failed");
    let code = if reply.label == syscall_abi::FAULT_REPLY_FORWARD
    {
        reply.word(0) & 0xFFFF_FFFF
    }
    else
    {
        0
    };
    (reply.label, code)
}

/// memmgr's decline code for a fault whose access the region refuses.
const DECLINE_ACCESS_REFUSED: u64 = 4;
/// memmgr's decline code for a fault outside every registered region.
const DECLINE_NO_REGION: u64 = 3;

/// An instruction fetch from a read-write demand region is declined before
/// the page is backed and after: a read of the same page is backed and
/// resumed between the two. memmgr once resumed a fault on a backed page
/// whatever its access, so a write to a backed read-only page looped. Each
/// decline carries the reason the kernel's kill diagnostic prints: a refused
/// access, then, once the region is unregistered, no region.
fn pager_refused_access_phase(_: &Caps)
{
    use syscall_abi::{
        FAULT_ACCESS_EXEC, FAULT_ACCESS_READ, FAULT_REPLY_FORWARD, FAULT_REPLY_RESUME,
    };

    let range = std::os::seraph::register_demand_paged(1).expect("refused_access: register");
    let va = range.va_start();
    assert_eq!(
        forged_vm_fault(va, FAULT_ACCESS_EXEC),
        (FAULT_REPLY_FORWARD, DECLINE_ACCESS_REFUSED),
        "refused_access: a fetch from an unbacked read-write page was not declined as refused"
    );
    assert_eq!(
        forged_vm_fault(va, FAULT_ACCESS_READ).0,
        FAULT_REPLY_RESUME,
        "refused_access: a read of a read-write page was not backed"
    );
    assert_eq!(
        forged_vm_fault(va, FAULT_ACCESS_EXEC),
        (FAULT_REPLY_FORWARD, DECLINE_ACCESS_REFUSED),
        "refused_access: a fetch from a backed read-write page was not declined as refused"
    );

    // UNREGISTER_REGION unmaps the backed page and returns its frames.
    let info = startup_info();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = ipc::IpcMessage::builder(ipc::memmgr_labels::UNREGISTER_REGION)
        .word(0, va)
        .word(1, syscall_abi::PAGE_SIZE)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(info.memmgr_endpoint, &msg, ipc_buf) }
        .expect("refused_access: UNREGISTER_REGION ipc_call failed");
    assert_eq!(
        reply.label,
        ipc::memmgr_errors::SUCCESS,
        "refused_access: UNREGISTER_REGION status"
    );
    assert_eq!(
        forged_vm_fault(va, FAULT_ACCESS_READ),
        (FAULT_REPLY_FORWARD, DECLINE_NO_REGION),
        "refused_access: a read of an unregistered page was not declined as outside every region"
    );
    std::os::seraph::unreserve_pages(range);
    assert_ram_identity();
    std::os::seraph::log!("pager_refused_access_declined phase passed");
}

/// Bind this thread to its pager cap with a forged badge word, then with the
/// reserved 0, through the raw syscall the typed wrapper cannot express.
fn pager_forged_badge_phase(_: &Caps)
{
    use syscall_abi::{FAULT_CLASS_VM, SYS_THREAD_SET_FAULT_HANDLER, SyscallError};

    let info = startup_info();
    assert_ne!(
        info.pager_endpoint_cap, 0,
        "svctest is demand-paged: its pager cap must be advertised"
    );
    // Any other process's badge would do; a value that is not this process's
    // stands in for one.
    let forged = info.pager_badge ^ 0x5A5A;
    let bind = |badge: u64| {
        // SAFETY: raw_syscall4's four conditions hold. SYS_THREAD_SET_FAULT_HANDLER
        // takes no pointer and uses no IPC buffer; it changes no mapping; the
        // only thread it can change is the calling one, whose virtual-memory
        // class alone it would set to the pager cap that binding already names
        // (procmgr bound that class of the main thread to `pager_endpoint_cap`),
        // leaving its other classes and its registers alone; and it changes no
        // CSpace slot.
        unsafe {
            syscall::raw_syscall4(
                SYS_THREAD_SET_FAULT_HANDLER,
                info.self_thread,
                info.pager_endpoint_cap,
                badge,
                FAULT_CLASS_VM,
            )
        }
    };
    let refused = bind(forged);
    assert_eq!(
        refused,
        SyscallError::InvalidArgument as i64,
        "a fault-handler bind carrying a binder-supplied badge must be refused"
    );
    let plain = bind(0);
    assert_eq!(
        plain, 0,
        "the same bind with the reserved badge word 0 must succeed"
    );
    std::os::seraph::log!("pager_forged_badge_refused phase passed (forged bind -> {refused})");
}

fn demand_paging_phase(_: &Caps)
{
    use std::process::Command;

    let mut child = Command::new("/programs/demandpaged")
        .spawn()
        .expect("spawn /programs/demandpaged failed");
    let status = child.wait().expect("demandpaged wait failed");
    std::os::seraph::log!("demandpaged exited: {status}");
    assert!(
        status.success(),
        "demand-paged child must exit cleanly: {status}"
    );

    // The child has exited; procmgr's PROCESS_DIED reclaims its demand frames.
    // memmgr's accounting identity must remain closed across the cycle.
    assert_ram_identity();
    std::os::seraph::log!("demand_paging phase passed");
}

/// The child empties its address space's page-table pool after registering a
/// region, then touches a block of the region whose leaf table does not exist
/// yet. A clean exit proves memmgr funded the pool and backed the fault; a
/// fault exit is memmgr declining it with code 9 (`mem_map` failed,
/// `OutOfMemory`). The exit codes are the fixture's
/// (programs/demandpaged/README.md).
fn demand_paging_pt_drain_phase(_: &Caps)
{
    use std::process::Command;

    let mut child = Command::new("/programs/demandpaged")
        .arg("ptdrain")
        .spawn()
        .expect("spawn /programs/demandpaged ptdrain failed");
    let status = child.wait().expect("demandpaged ptdrain wait failed");
    std::os::seraph::log!("demandpaged ptdrain exited: {status}");
    assert!(
        status.success(),
        "a demand fault with the page-table pool empty must be backed: {status}"
    );

    // The pages memmgr donated to the child's page-table pool are accounted to
    // its record and reclaimed with it; the identity must hold.
    assert_ram_identity();
    std::os::seraph::log!("demand_paging_pt_drain phase passed");
}

/// The child registers, fills and tears down a demand region twice, the second
/// region on the first one's VA. A clean exit proves the teardown removed
/// memmgr's registration and released the reservation; exit `2` is memmgr
/// refusing the second registration as an overlap, `4` an unanswered
/// teardown, `5` a second reservation at another VA. The exit codes are the
/// fixture's (programs/demandpaged/README.md).
fn demand_paging_teardown_phase(_: &Caps)
{
    use std::process::Command;

    let mut child = Command::new("/programs/demandpaged")
        .arg("teardown")
        .spawn()
        .expect("spawn /programs/demandpaged teardown failed");
    let status = child.wait().expect("demandpaged teardown wait failed");
    std::os::seraph::log!("demandpaged teardown exited: {status}");
    assert!(
        status.success(),
        "a torn-down demand region must leave its VA free to register again: {status}"
    );

    // The frames memmgr reclaimed at the teardown went back to its pool; the
    // identity must hold.
    assert_ram_identity();
    std::os::seraph::log!("demand_paging_teardown phase passed");
}

#[expect(
    clippy::cast_sign_loss,
    reason = "ExitStatus::code() is i32 but exit reasons are non-negative (fault 0x1000+vec, \
              killed 0x2000); the u64 cast is safe"
)]
fn demand_paging_segfault_phase(_: &Caps)
{
    use std::process::Command;
    use syscall::EXIT_FAULT_BASE;

    let mut child = Command::new("/programs/demandpaged")
        .arg("oor")
        .spawn()
        .expect("spawn /programs/demandpaged oor failed");
    let status = child.wait().expect("demandpaged oor wait failed");
    std::os::seraph::log!("demandpaged oor exited: {status}");
    assert!(
        !status.success(),
        "out-of-region touch must be killed, not exit cleanly: {status}"
    );
    let raw = status.code().expect("oor ExitStatus must carry a code") as u64;
    assert!(
        raw >= EXIT_FAULT_BASE,
        "expected a fault/kill exit_reason >= {EXIT_FAULT_BASE:#x}, got {raw:#x}"
    );
    std::os::seraph::log!("demand_paging_segfault phase passed (exit_reason={raw:#x})");
}

#[expect(
    clippy::cast_sign_loss,
    reason = "ExitStatus::code() is i32 but exit reasons are non-negative (fault 0x1000+vec, \
              killed 0x2000); the u64 cast is safe"
)]
fn demand_paging_pinned_phase(_: &Caps)
{
    use std::process::Command;
    use syscall::EXIT_FAULT_BASE;

    // Pinned: procmgr binds no fault handler and delegates no address space.
    // The child still registers its region (memmgr records it against the badge
    // minted at REGISTER_PROCESS), but the first touch faults with no handler
    // bound, so the kernel kills the process. The same registered-region touch
    // exits cleanly in `demand_paging` — the kill here is the proof that
    // `pinned(true)` suppressed the default pager.
    let mut child = Command::new("/programs/demandpaged")
        .pinned(true)
        .spawn()
        .expect("spawn /programs/demandpaged pinned failed");
    let status = child.wait().expect("demandpaged pinned wait failed");
    std::os::seraph::log!("demandpaged pinned exited: {status}");
    assert!(
        !status.success(),
        "a pinned child has no pager: touching its registered region must be \
         killed, not backed: {status}"
    );
    let raw = status.code().expect("pinned ExitStatus must carry a code") as u64;
    assert!(
        raw >= EXIT_FAULT_BASE,
        "expected a no-handler fault exit_reason >= {EXIT_FAULT_BASE:#x}, got {raw:#x}"
    );

    // The child died with no demand frames mapped (no handler ever backed a
    // page); memmgr reclaims its record on PROCESS_DIED. The identity must hold.
    assert_ram_identity();
    std::os::seraph::log!("demand_paging_pinned phase passed (exit_reason={raw:#x})");
}

/// Assert `system_ram == kernel_reserved + pool_total` via memmgr
/// `QUERY_POOL_STATUS`.
fn assert_ram_identity()
{
    let info = startup_info();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let req = ipc::IpcMessage::builder(ipc::memmgr_labels::QUERY_POOL_STATUS).build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(info.memmgr_endpoint, &req, ipc_buf) }
        .expect("QUERY_POOL_STATUS ipc_call failed");
    assert_eq!(
        reply.label,
        ipc::memmgr_errors::SUCCESS,
        "QUERY_POOL_STATUS status"
    );
    let (system_ram, kernel_reserved, pool_total) = (reply.word(0), reply.word(1), reply.word(2));
    assert_eq!(
        system_ram,
        kernel_reserved.saturating_add(pool_total),
        "RAM identity broken after demand paging: \
         system_ram={system_ram} kernel_reserved={kernel_reserved} pool_total={pool_total}"
    );
}

/// Pages memmgr backs per demand fault when a free run covers them
/// (`DEMAND_CHUNK_PAGES`, services/memmgr/free-pool/src/lib.rs).
const DEMAND_CHUNK_PAGES: u64 = 16;

/// Chunk faults [`demand_fault_cost_phase`] times in each round.
const COST_CHUNKS: u64 = 64;

/// Rounds [`demand_fault_cost_phase`] times, each on a fresh region.
const COST_ROUNDS: usize = 4;

/// Time the faults of a demand region one chunk at a time: each round
/// registers a region of [`COST_CHUNKS`] chunks, writes one word in each
/// chunk's first page, so each write is one fault that memmgr backs with a
/// whole chunk, and logs the mean time per fault. The region's page tables
/// are funded at registration, so the time is memmgr's work on the fault and
/// the kernel's delivery of it. No bound is asserted: the figure is the
/// measure of a change to that work (services/memmgr/docs/memory-pool.md
/// § Frame contents).
fn demand_fault_cost_phase(_: &Caps)
{
    let pages = COST_CHUNKS.saturating_mul(DEMAND_CHUNK_PAGES);
    let chunk_bytes = DEMAND_CHUNK_PAGES.saturating_mul(syscall_abi::PAGE_SIZE);
    let mut means_ns = [0u128; COST_ROUNDS];
    for mean in &mut means_ns
    {
        let region = std::os::seraph::register_demand_paged(pages)
            .expect("demand_fault_cost: registering the region failed");
        let base = region.va_start();
        let start = std::time::Instant::now();
        for chunk in 0..COST_CHUNKS
        {
            let va = base.saturating_add(chunk.saturating_mul(chunk_bytes));
            // SAFETY: `va` is the first page of a chunk of a read-write demand
            // region of this process, whose first write backs it; no Rust
            // reference points into the region.
            unsafe { core::ptr::write_volatile(va as *mut u64, 1) };
        }
        *mean = start
            .elapsed()
            .as_nanos()
            .checked_div(u128::from(COST_CHUNKS))
            .unwrap_or_default();
        // SAFETY: no Rust reference and no IPC buffer lies in the region.
        unsafe { std::os::seraph::unregister_demand_paged(region) }
            .expect("demand_fault_cost: unregistering the region failed");
    }
    std::os::seraph::log!(
        "demand_fault_cost: mean ns per {DEMAND_CHUNK_PAGES}-page chunk fault over \
         {COST_CHUNKS} faults, per round: {means_ns:?}"
    );
}

/// Pages of the demand region [`demand_fault_fragmented_phase`] touches.
const FRAGMENTED_REGION_PAGES: u64 = 64;

/// Grant requests the drain of [`demand_fault_fragmented_phase`] may make: a
/// test bound far above the free runs a boot holds.
const FRAGMENT_MAX_DRAWS: usize = 4096;

/// Free runs of one page fewer than a chunk that
/// [`demand_fault_fragmented_phase`] leaves in the pool: 120 pages, room for
/// its region and the page tables that map it.
const FRAGMENT_HOLES: u64 = 8;

/// A demand fault on a pool that holds free pages but no free run of a
/// chunk's size is backed from a smaller run, not declined
/// (services/memmgr/docs/memory-pool.md § Demand faults). svctest registers a
/// demand region and sets aside one contiguous grant (the carve), then draws
/// every free run of a hole's size (`DEMAND_CHUNK_PAGES - 1` pages) or more
/// whole, so the carve is the only such run once it is released. It cuts the
/// carve, front first, into hole-sized grants and releases every other one,
/// each between two it holds, so the pool holds [`FRAGMENT_HOLES`] runs of a
/// hole's size and none of a chunk's. With the pool so fragmented, it reads
/// and writes every page of the region: a declined fault would kill svctest.
/// Every page must read zero before the write (§ Frame contents) and hold the
/// write after. The grants are released after, and nothing between the drain
/// and the release allocates or logs.
fn demand_fault_fragmented_phase(_: &Caps)
{
    use super::memmgr::{
        SCRUB_MARKER, nonzero_words, pool_free_and_largest, release_grant, words_mut,
    };

    let page = syscall_abi::PAGE_SIZE;
    let chunk_bytes = DEMAND_CHUNK_PAGES.saturating_mul(page);
    let region = std::os::seraph::register_demand_paged(FRAGMENTED_REGION_PAGES)
        .expect("demand_fault_fragmented: registering the region failed");
    let pieces = usize::try_from(FRAGMENT_HOLES.saturating_mul(2).saturating_add(1))
        .expect("demand_fault_fragmented: piece count beyond usize");
    let mut held: Vec<(u64, u64)> = Vec::with_capacity(FRAGMENT_MAX_DRAWS.saturating_add(pieces));
    let (drawn_pages, hole_count) = fragment_pool(&mut held, pieces);
    let (free, largest) = pool_free_and_largest();
    assert!(
        largest < chunk_bytes,
        "demand_fault_fragmented: the pool kept a run of {largest} bytes, a chunk or more"
    );
    assert!(
        free >= FRAGMENTED_REGION_PAGES
            .saturating_add(DEMAND_CHUNK_PAGES)
            .saturating_mul(page),
        "demand_fault_fragmented: {hole_count} holes left {free} free bytes, too few for the region"
    );

    // SAFETY: the span is a read-write demand region of this process, whose
    // first access of each page backs it, and nothing else refers to it.
    let words = unsafe { words_mut(region.va_start(), FRAGMENTED_REGION_PAGES) };
    let (nonzero, _) = nonzero_words(words);
    words.fill(SCRUB_MARKER);
    let (_, written) = nonzero_words(words);
    let len = words.len();

    let grants = held.len();
    for (cap, id) in held
    {
        release_grant(cap, id);
    }
    // SAFETY: no Rust reference and no IPC buffer lies in the region; `words`
    // is not used past this point.
    unsafe { std::os::seraph::unregister_demand_paged(region) }
        .expect("demand_fault_fragmented: unregistering the region failed");
    assert_eq!(
        nonzero, 0,
        "demand_fault_fragmented: the region read {nonzero} nonzero words before the write"
    );
    assert_eq!(
        written, len,
        "demand_fault_fragmented: the region kept {written} of its {len} written words"
    );
    assert_ram_identity();
    std::os::seraph::log!(
        "demand_fault_fragmented: {grants} grants drew {drawn_pages} pages and {hole_count} holes \
         left {free} free bytes in runs of at most {largest}; {FRAGMENTED_REGION_PAGES} demand \
         pages backed"
    );
}

/// Fragment the pool for [`demand_fault_fragmented_phase`]: set aside the
/// carve, draw every free run of a hole's size or more whole, then cut the
/// carve into `pieces` hole-sized grants and release every other one. Every
/// grant it keeps goes onto `held`, which has room for [`FRAGMENT_MAX_DRAWS`]
/// and `pieces` more, so nothing here allocates. Returns the pages the drain
/// drew and the holes released.
fn fragment_pool(held: &mut Vec<(u64, u64)>, pieces: usize) -> (u64, usize)
{
    use super::memmgr::{pool_free_and_largest, release_grant, try_request_contiguous};

    let page = syscall_abi::PAGE_SIZE;
    let hole_pages = DEMAND_CHUNK_PAGES - 1;
    let hole = u32::try_from(hole_pages).expect("demand_fault_fragmented: hole beyond u32 pages");
    // A held piece first, then a hole and a held piece per hole, so no hole
    // touches a run outside the carve.
    let carve_pages = u64::try_from(pieces)
        .ok()
        .and_then(|n| u32::try_from(hole_pages.saturating_mul(n)).ok())
        .expect("demand_fault_fragmented: carve beyond u32 pages");
    let mut holes: Vec<(u64, u64)> = Vec::with_capacity(pieces);
    let carve = try_request_contiguous(carve_pages).unwrap_or_else(|label| {
        panic!("demand_fault_fragmented: the {carve_pages}-page carve was refused ({label:#x})")
    });

    // Draw every free run of a hole's size or more, whole.
    let mut drawn_pages = 0u64;
    let mut drained = false;
    for _ in 0..FRAGMENT_MAX_DRAWS
    {
        let (_, largest) = pool_free_and_largest();
        if largest < hole_pages.saturating_mul(page)
        {
            drained = true;
            break;
        }
        let take =
            u32::try_from(largest / page).expect("demand_fault_fragmented: run beyond u32 pages");
        // A request another process's draw beat to the run is refused; the
        // next query sees the pool as it is.
        if let Ok(grant) = try_request_contiguous(take)
        {
            held.push(grant);
            drawn_pages = drawn_pages.saturating_add(u64::from(take));
        }
    }
    assert!(
        drained,
        "demand_fault_fragmented: the drain did not end within its bound"
    );

    // The carve is now the only run a hole-sized request fits: cut it front
    // first, and release each hole once the piece after it is held.
    release_grant(carve.0, carve.1);
    if let Ok(first) = try_request_contiguous(hole)
    {
        held.push(first);
        for _ in 0..FRAGMENT_HOLES
        {
            let Ok(gap) = try_request_contiguous(hole)
            else
            {
                break;
            };
            let Ok(next) = try_request_contiguous(hole)
            else
            {
                held.push(gap);
                break;
            };
            holes.push(gap);
            held.push(next);
        }
    }
    let hole_count = holes.len();
    for (cap, id) in holes
    {
        release_grant(cap, id);
    }
    (drawn_pages, hole_count)
}
