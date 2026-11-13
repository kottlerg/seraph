// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/memmgr.rs

//! Memmgr / heap allocator surface.

use std::collections::BTreeMap;
use std::os::seraph::{current_ipc_buf, startup_info};

use syscall_abi::MSG_CAP_SLOTS_MAX;

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "alloc",
            run: alloc_phase,
        },
        Phase {
            name: "churn",
            run: churn_phase,
        },
        Phase {
            name: "alloc_grow",
            run: alloc_grow_phase,
        },
        Phase {
            name: "memmgr_donate_unauthorized",
            run: donate_unauthorized_phase,
        },
        Phase {
            name: "memmgr_stray_cap_flood",
            run: stray_cap_flood_phase,
        },
        Phase {
            name: "grant_retyped_unmappable",
            run: grant_retyped_unmappable_phase,
        },
        Phase {
            name: "cspace_slot_budget",
            run: cspace_slot_budget_phase,
        },
        Phase {
            name: "object_slab_release",
            run: object_slab_release_phase,
        },
        Phase {
            name: "frame_reclaim_live_object",
            run: frame_reclaim_live_object_phase,
        },
        Phase {
            name: "frame_reclaim_mapped_release",
            run: frame_reclaim_mapped_release_phase,
        },
        Phase {
            name: "frame_reclaim_held_cap_release",
            run: frame_reclaim_held_cap_release_phase,
        },
        Phase {
            name: "phys_base_withheld",
            run: phys_base_withheld_phase,
        },
    ]
}

/// Role token for [`reclaim_child_main`].
const RECLAIM_CHILD_ROLE: &str = "reclaim-child";

/// Child-mode dispatch for argv tokens this module owns. The matching arm
/// parks until its spawner kills it, or exits through `std::process::exit`
/// on a setup failure; on a miss control returns to the caller.
pub fn reentry_main(role: &str)
{
    if role == RECLAIM_CHILD_ROLE
    {
        reclaim_child_main();
    }
}

/// All-RAM-accounted identity check. Registered last (see [`super::all`]) so
/// init's reap donations have almost always landed; the poll closes the
/// residual race in any case.
pub fn identity() -> &'static [Phase]
{
    &[Phase {
        name: "ram_accounted_identity",
        run: ram_accounted_identity_phase,
    }]
}

pub fn alloc_phase(_: &Caps)
{
    let boxed: Box<u64> = Box::new(0xDEAD_BEEF_CAFE_BABE);
    std::os::seraph::log!("Box<u64>={:#018x}", *boxed);

    let mut v: Vec<u64> = Vec::new();
    for i in 0u64..64
    {
        v.push(i);
    }
    let sum: u64 = v.iter().sum();
    std::os::seraph::log!("Vec sum(0..64)={sum:#018x}");
    let popped = v.pop().unwrap_or(0);
    std::os::seraph::log!("Vec::pop={popped:#018x}");

    let mut s = String::new();
    for _ in 0..8
    {
        s.push_str("seraph ");
    }
    std::os::seraph::log!("String::len={:#018x}", s.len() as u64);

    let mut m: BTreeMap<u64, u64> = BTreeMap::new();
    for k in 0u64..16
    {
        m.insert(k, k.checked_mul(100).expect("BTreeMap value overflowed"));
    }
    std::os::seraph::log!("BTreeMap::len={:#018x}", m.len() as u64);
    if let Some(&v10) = m.get(&10)
    {
        std::os::seraph::log!("BTreeMap[10]={v10:#018x}");
    }

    drop(boxed);
    drop(v);
    drop(s);
    drop(m);
    std::os::seraph::log!("dealloc churn complete");
}

pub fn churn_phase(_: &Caps)
{
    const ITERS: u32 = 10_000;
    let mut seed: u32 = 0x1337_BEEF;
    let mut keep: Vec<Vec<u8>> = Vec::with_capacity(8);
    for i in 0..ITERS
    {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        let size: usize = match seed & 0xF
        {
            0 => 1,
            1 => 5,
            2 => 10,
            3 => 17,
            4 => 23,
            5 => 31,
            6 => 63,
            7 => 77,
            8 => 128,
            9 => 200,
            10 => 500,
            11 => 777,
            _ => ((seed >> 4) & 0x3FF) as usize + 1,
        };
        let capacity = (size / 2).checked_add(1).expect("capacity overflowed");
        let mut v: Vec<u8> = Vec::with_capacity(capacity);
        for b in 0..size
        {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the mask keeps the low byte, so the cast to u8 drops nothing"
            )]
            v.push((b & 0xFF) as u8);
        }
        assert_eq!(v.len(), size, "push count mismatch at iter {i}");
        if i.trailing_zeros() >= 3
        {
            keep.push(v);
            if keep.len() > 8
            {
                let _ = keep.remove(0);
            }
        }
    }
    drop(keep);
    std::os::seraph::log!("churn phase passed ({ITERS} iters)");
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "every cast to u8 in the phase takes an index masked to its low byte or a counter \
              below 8, so none drops a bit"
)]
pub fn alloc_grow_phase(_: &Caps)
{
    const BIG: usize = 600 * 1024;

    let mut big: Vec<u8> = Vec::with_capacity(BIG);
    for i in 0..BIG
    {
        big.push((i & 0xFF) as u8);
    }
    assert_eq!(big.len(), BIG, "grow-path push count mismatch");

    for &idx in &[0, 1, 4095, 4096, 65_535, 65_536, BIG / 2, BIG - 1]
    {
        let expected = (idx & 0xFF) as u8;
        assert_eq!(
            *big.get(idx)
                .expect("grow buffer index within the pushed length"),
            expected,
            "grow buffer[{idx}] mismatch"
        );
    }

    let mut small: Vec<Vec<u8>> = Vec::with_capacity(8);
    for k in 0..8usize
    {
        small.push(vec![k as u8; 1024]);
    }
    for (k, v) in small.iter().enumerate()
    {
        assert_eq!(v.len(), 1024);
        assert_eq!(*v.first().expect("small buffer holds 1024 bytes"), k as u8);
    }

    drop(small);
    drop(big);

    let post: Vec<u32> = (0..4096u32).collect();
    assert_eq!(post.last().copied(), Some(4095));

    std::os::seraph::log!("alloc_grow phase passed ({BIG} bytes + 8 KiB interleaved)");
}

/// Call memmgr over svctest's own badged endpoint, panicking with `what` if
/// the call itself fails.
fn memmgr_call(msg: &ipc::IpcMessage, what: &str) -> ipc::IpcMessage
{
    // SAFETY: `current_ipc_buf` is this thread's kernel-registered IPC buffer.
    unsafe { ipc::ipc_call(startup_info().memmgr_endpoint, msg, current_ipc_buf()) }
        .unwrap_or_else(|e| panic!("memmgr {what} ipc_call failed: {e:?}"))
}

/// Request a one-page grant from memmgr: `(grant cap, region id)`.
fn request_one_page() -> (u64, u64)
{
    let want = 1 | (u64::from(ipc::memmgr_labels::REQUIRE_CONTIGUOUS) << 32);
    let req = ipc::IpcMessage::builder(ipc::memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, want)
        .build();
    let reply = memmgr_call(&req, "REQUEST_MEMORY_CAPS");
    assert_eq!(
        reply.label,
        ipc::memmgr_errors::SUCCESS,
        "REQUEST_MEMORY_CAPS status"
    );
    let grant = *reply
        .caps()
        .first()
        .expect("REQUEST_MEMORY_CAPS returned no cap");
    // One cap: data[1] is its page count, data[2] its region id.
    (grant, reply.word(2))
}

/// Drop the grant cap and hand its region back to memmgr.
fn release_one_page(grant: u64, region_id: u64)
{
    syscall::cap_delete(grant).expect("cap_delete of grant");
    let release = ipc::IpcMessage::builder(ipc::memmgr_labels::RELEASE_MEMORY_CAPS)
        .word(0, 1)
        .word(1, region_id)
        .build();
    let reply = memmgr_call(&release, "RELEASE_MEMORY_CAPS");
    assert_eq!(
        reply.label,
        ipc::memmgr_errors::SUCCESS,
        "RELEASE_MEMORY_CAPS status"
    );
}

/// A `DONATE_MEMORY_CAPS` from a client other than procmgr is refused with
/// `UNAUTHORIZED`. The donated cap is a derivation of a one-page grant svctest
/// still holds, the aliasing donation the gate exists to stop: memmgr would
/// otherwise put a frame it lent to svctest back into its free pool.
pub fn donate_unauthorized_phase(_: &Caps)
{
    let (grant, region_id) = request_one_page();

    let alias = syscall::cap_derive(grant, syscall::RIGHTS_ALL).expect("cap_derive of grant");
    let donate = ipc::IpcMessage::builder(ipc::memmgr_labels::DONATE_MEMORY_CAPS)
        .cap(alias)
        .build();
    let reply = memmgr_call(&donate, "DONATE_MEMORY_CAPS");
    assert_eq!(
        reply.label,
        ipc::memmgr_errors::UNAUTHORIZED,
        "DONATE_MEMORY_CAPS from a non-procmgr client was not refused \
         (accepted_caps={}, accepted_pages={})",
        reply.word(0),
        reply.word(1)
    );

    release_one_page(grant, region_id);
    std::os::seraph::log!("non-procmgr donation refused with UNAUTHORIZED");
}

/// Page-sized wait sets [`object_slab_release_phase`] creates and deletes.
const RELEASE_CHURN: u32 = 64;

/// Members of each of those wait sets: a 512-member set is a four-page
/// retype class in a five-page grant, well past the sub-page classes.
const RELEASE_WS_MEMBERS: u32 = 512;

/// The memmgr free-pool drop [`object_slab_release_phase`] tolerates, for
/// other processes' allocations meanwhile: 32 pages, a tenth of the 320 the
/// churn strands without the release.
const RELEASE_POOL_SLACK_BYTES: u64 = 32 * syscall_abi::PAGE_SIZE;

/// `std::os::seraph::object_slab_retype_reclaimable` returns the dedicated
/// grant of a page-sized retype and none for a sub-page one, and
/// `object_slab_release` returns that grant's run to memmgr's pool:
/// [`RELEASE_CHURN`] page-sized wait sets, each deleted and its grant
/// released, leave memmgr's free pool within [`RELEASE_POOL_SLACK_BYTES`] of
/// where it started. Without the release the churn would strand about
/// 320 pages until svctest exits.
pub fn object_slab_release_phase(_: &Caps)
{
    let small = std::os::seraph::object_slab_retype_reclaimable(
        std::os::seraph::wait_set_retype_bytes(2),
        |slab| syscall::wait_set_create(slab, 2).ok(),
    )
    .expect("object_slab_release: two-member wait set");
    assert!(
        small.1.is_none(),
        "object_slab_release: a sub-page retype returned a grant"
    );
    let _ = syscall::cap_delete(small.0);

    let before =
        std::os::seraph::memmgr_pool_free_bytes().expect("object_slab_release: memmgr pool query");
    for i in 0..RELEASE_CHURN
    {
        let (ws, grant) = std::os::seraph::object_slab_retype_reclaimable(
            std::os::seraph::wait_set_retype_bytes(u64::from(RELEASE_WS_MEMBERS)),
            |slab| syscall::wait_set_create(slab, RELEASE_WS_MEMBERS).ok(),
        )
        .unwrap_or_else(|| panic!("object_slab_release: wait set {i} not created"));
        let grant =
            grant.unwrap_or_else(|| panic!("object_slab_release: wait set {i} returned no grant"));
        syscall::cap_delete(ws)
            .unwrap_or_else(|e| panic!("object_slab_release: delete {i} failed ({e})"));
        std::os::seraph::object_slab_release(grant);
    }
    let after =
        std::os::seraph::memmgr_pool_free_bytes().expect("object_slab_release: memmgr pool query");
    let drop = before.saturating_sub(after);
    assert!(
        drop <= RELEASE_POOL_SLACK_BYTES,
        "object_slab_release: pool dropped {drop} bytes over {RELEASE_CHURN} released wait sets \
         (before {before}, after {after})"
    );
    std::os::seraph::log!(
        "object_slab_release: {RELEASE_CHURN} page-sized wait sets released, pool drop {drop}"
    );
}

/// A process cannot map the slot pages it funded its own `CSpace` with. A
/// one-page memmgr grant augments svctest's `CSpace`, and `mem_map` of that
/// page, writable or read-only, is refused with `InvalidArgument` (the
/// retype/map boundary of docs/capability-model.md § Typed Memory). The
/// donated page stays in the `CSpace`'s pool until svctest exits; memmgr
/// reclaims it then with the rest of the grant.
pub fn grant_retyped_unmappable_phase(_: &Caps)
{
    use syscall::{MAP_READ, MAP_WRITABLE};

    let info = startup_info();
    let (grant, _region_id) = request_one_page();
    syscall::cap_create_cspace(grant, info.self_cspace, 1)
        .expect("augment of svctest's CSpace from the grant failed");

    let range = std::os::seraph::reserve_pages(1).expect("reserve_pages");
    let va = range.va_start();
    let refused = syscall_abi::SyscallError::InvalidArgument as i64;
    for prot in [MAP_WRITABLE, MAP_READ]
    {
        // SAFETY: `range` is a fresh page reservation from the per-process
        // arena, owned here: VA no Rust object or IPC page occupies.
        let mapped = unsafe { syscall::mem_map(grant, info.self_aspace, va, 0, 1, prot) };
        if mapped.is_ok()
        {
            // SAFETY: as for the map above.
            let _ = unsafe { syscall::mem_unmap(info.self_aspace, va, 1) };
        }
        assert_eq!(
            mapped,
            Err(refused),
            "mem_map of the grant page backing svctest's CSpace slots was not refused"
        );
    }

    std::os::seraph::unreserve_pages(range);
    // The donation holds its own reference on the grant's memory.
    syscall::cap_delete(grant).expect("cap_delete of grant");
    std::os::seraph::log!("retyped grant page refused by mem_map");
}

/// `std::os::seraph::fund_cspace_slot_budget` raises svctest's own `CSpace`
/// headroom (free slots above the IPC receive reserve) to at least the asked
/// count, funding the slot-page pool from memmgr: asking for two slot pages
/// past the current headroom must succeed and leave at least that much.
pub fn cspace_slot_budget_phase(_: &Caps)
{
    let info = startup_info();
    let before = std::os::seraph::cspace_slot_headroom(info.self_cspace);
    let want = 2u64
        .checked_mul(syscall_abi::CSPACE_SLOTS_PER_PAGE)
        .and_then(|extra| before.checked_add(extra))
        .expect("cspace slot budget target overflowed");
    assert!(
        std::os::seraph::fund_cspace_slot_budget(info.self_cspace, want),
        "fund_cspace_slot_budget({want}) failed from headroom {before}"
    );
    let after = std::os::seraph::cspace_slot_headroom(info.self_cspace);
    assert!(
        after >= want,
        "CSpace headroom {after} after funding falls short of {want}"
    );
    std::os::seraph::log!("CSpace headroom funded {before} -> {after} (asked {want})");
}

/// One stray-cap flood case: a message memmgr refuses or answers with no
/// lasting effect, sent with `MSG_CAP_SLOTS_MAX` caps attached.
struct StrayCapCase
{
    label: u64,
    words: [u64; 3],
    /// Attached caps memmgr's `dispatch` hands to the handler (the label's
    /// contract caps); `dispatch` deletes the others itself.
    kept: usize,
    expected: u64,
}

/// Every label whose contract carries no caps, the two cap-carrying labels
/// from a caller that is not procmgr, a forged `FAULT_LABEL`, and an unknown
/// label. Each request is refused or has no lasting effect, so the flood
/// changes no memmgr state but its `CSpace`.
const STRAY_CAP_CASES: [StrayCapCase; 11] = [
    // want_pages == 0.
    StrayCapCase {
        label: ipc::memmgr_labels::REQUEST_MEMORY_CAPS,
        words: [0, 0, 0],
        kept: 0,
        expected: ipc::memmgr_errors::INVALID_ARGUMENT,
    },
    // count == 0: nothing to release.
    StrayCapCase {
        label: ipc::memmgr_labels::RELEASE_MEMORY_CAPS,
        words: [0, 0, 0],
        kept: 0,
        expected: ipc::memmgr_errors::SUCCESS,
    },
    StrayCapCase {
        label: ipc::memmgr_labels::REGISTER_PROCESS,
        words: [0, 0, 0],
        kept: 0,
        expected: ipc::memmgr_errors::UNAUTHORIZED,
    },
    StrayCapCase {
        label: ipc::memmgr_labels::PROCESS_DIED,
        words: [0, 0, 0],
        kept: 0,
        expected: ipc::memmgr_errors::UNAUTHORIZED,
    },
    // Every attached cap reaches the handler, which refuses and deletes them.
    StrayCapCase {
        label: ipc::memmgr_labels::DONATE_MEMORY_CAPS,
        words: [0, 0, 0],
        kept: MSG_CAP_SLOTS_MAX,
        expected: ipc::memmgr_errors::UNAUTHORIZED,
    },
    StrayCapCase {
        label: ipc::memmgr_labels::QUERY_POOL_STATUS,
        words: [0, 0, 0],
        kept: 0,
        expected: ipc::memmgr_errors::SUCCESS,
    },
    // len == 0.
    StrayCapCase {
        label: ipc::memmgr_labels::REGISTER_REGION,
        words: [0, 0, 0],
        kept: 0,
        expected: ipc::memmgr_errors::INVALID_ARGUMENT,
    },
    // `cap[0]` reaches the handler, which refuses and deletes it.
    StrayCapCase {
        label: ipc::memmgr_labels::DELEGATE_ASPACE,
        words: [0, 0, 0],
        kept: 1,
        expected: ipc::memmgr_errors::UNAUTHORIZED,
    },
    // No region is registered at [0, 0).
    StrayCapCase {
        label: ipc::memmgr_labels::UNREGISTER_REGION,
        words: [0, 0, 0],
        kept: 0,
        expected: ipc::memmgr_errors::INVALID_ARGUMENT,
    },
    // A non-VM kind: memmgr answers KILL, which an ordinary caller receives
    // as a plain reply label.
    StrayCapCase {
        label: syscall_abi::FAULT_LABEL,
        words: [syscall_abi::FAULT_KIND_EXCEPTION, 0, 0],
        kept: 0,
        expected: syscall_abi::FAULT_REPLY_KILL,
    },
    // No memmgr label: the default arm.
    StrayCapCase {
        label: 0x7FFF,
        words: [0, 0, 0],
        kept: 0,
        expected: ipc::memmgr_errors::INVALID_ARGUMENT,
    },
];

/// memmgr's decline code for a fault that is not a VM fault
/// (services/memmgr/docs/ipc-interface.md § Kernel-origin fault message).
const DECLINE_NOT_VM: u64 = 1;

/// Stray caps one case must leave behind to overflow memmgr's `CSpace`: more
/// than the slots it is seeded with (init's `CSPACE_RETYPE_PAGES` slot pages,
/// about 8 Ki slots), with margin.
const STRAY_CAP_LEAK_BUDGET: usize = 9 * 1024;

/// Calls a case makes so that a leak on either of its two deletion paths alone
/// reaches [`STRAY_CAP_LEAK_BUDGET`]: `dispatch` deletes the
/// `MSG_CAP_SLOTS_MAX - kept` caps past the contract, and the handler deletes
/// the `kept` contract caps it refuses. The smaller nonzero per-call leak of
/// the two sets the count, so a memmgr that kept either path's caps would
/// exhaust its `CSpace` during that case, fail its receive, and exit with
/// `EXIT_RECV_WEDGE`.
const fn stray_cap_calls(kept: usize) -> usize
{
    let dispatch_leak = MSG_CAP_SLOTS_MAX
        .checked_sub(kept)
        .expect("kept contract caps exceed MSG_CAP_SLOTS_MAX");
    let smallest_leak = if kept == 0 || (dispatch_leak != 0 && dispatch_leak < kept)
    {
        dispatch_leak
    }
    else
    {
        kept
    };
    STRAY_CAP_LEAK_BUDGET.div_ceil(smallest_leak)
}

/// Flood memmgr, case by case, with caps attached to messages whose contract
/// does not keep them, then check it still answers. Every call must also get
/// its case's normal reply, so deleting the strays changes no label's
/// behaviour.
#[expect(
    clippy::large_stack_frames,
    reason = "the `builder`, its built copy and the `reply` `IpcMessage`s (568 B each) of each \
              case, and the `QUERY_POOL_STATUS` request; on the 32 KiB main-thread stack of \
              svctest"
)]
pub fn stray_cap_flood_phase(_: &Caps)
{
    let info = startup_info();
    let mut total_calls = 0usize;
    for case in &STRAY_CAP_CASES
    {
        let label = case.label;
        for call in 0..stray_cap_calls(case.kept)
        {
            let mut builder = ipc::IpcMessage::builder(label)
                .word(0, case.words[0])
                .word(1, case.words[1])
                .word(2, case.words[2]);
            for _ in 0..MSG_CAP_SLOTS_MAX
            {
                let stray = syscall::cap_derive(info.memmgr_endpoint, syscall::RIGHTS_EP_SEND)
                    .expect("cap_derive of a stray cap");
                builder = builder.cap(stray);
            }
            let what = format!("stray-cap call {call} with label {label:#x}");
            let reply = memmgr_call(&builder.build(), &what);
            assert_eq!(reply.label, case.expected, "memmgr reply to {what}");
            // The forged non-VM fault's decline carries memmgr's not-VM code
            // in the low half of data word 0.
            if label == syscall_abi::FAULT_LABEL
            {
                assert_eq!(
                    reply.word(0) & 0xFFFF_FFFF,
                    DECLINE_NOT_VM,
                    "decline code in memmgr reply to {what}"
                );
            }
            total_calls = total_calls
                .checked_add(1)
                .expect("stray-cap call count overflowed");
        }
    }

    let req = ipc::IpcMessage::builder(ipc::memmgr_labels::QUERY_POOL_STATUS).build();
    let reply = memmgr_call(&req, "QUERY_POOL_STATUS after the flood");
    assert_eq!(
        reply.label,
        ipc::memmgr_errors::SUCCESS,
        "QUERY_POOL_STATUS status after the flood"
    );
    std::os::seraph::log!(
        "memmgr answered {total_calls} calls carrying {} stray caps",
        total_calls
            .checked_mul(MSG_CAP_SLOTS_MAX)
            .expect("stray cap total overflowed")
    );
}

/// Assert the all-RAM-accounted identity `system_ram == kernel_reserved +
/// pool_total` holds with zero residual. memmgr reports the three terms (bytes)
/// via `QUERY_POOL_STATUS`.
///
/// init's reap donations arrive at memmgr asynchronously after init's main
/// thread exits, racing svctest's startup, so a query issued too early sees a
/// transient positive residual (donations still in flight). The residual only
/// shrinks — `kernel_reserved` is fixed and `pool_total` only grows as
/// donations land — so polling converges to zero on a clean system. A real
/// leak (a page memmgr never takes ownership of) holds the residual above
/// zero and the poll times out. memmgr counts a donated page on ownership,
/// not on free-pool residency, so a run parked by a full pool still closes
/// the identity.
pub fn ram_accounted_identity_phase(_: &Caps)
{
    // A test wait bound: it limits only how long the phase polls before it
    // fails.
    const MAX_POLL: u32 = 4096;

    let info = startup_info();
    let ipc_buf = current_ipc_buf();
    let req = ipc::IpcMessage::builder(ipc::memmgr_labels::QUERY_POOL_STATUS).build();

    let mut terms = (0u64, 0u64, 0u64);
    for _ in 0..MAX_POLL
    {
        // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
        let reply = unsafe { ipc::ipc_call(info.memmgr_endpoint, &req, ipc_buf) }
            .expect("memmgr QUERY_POOL_STATUS ipc_call failed");
        assert_eq!(
            reply.label,
            ipc::memmgr_errors::SUCCESS,
            "QUERY_POOL_STATUS status"
        );
        let (system_ram, kernel_reserved, pool_total) =
            (reply.word(0), reply.word(1), reply.word(2));
        terms = (system_ram, kernel_reserved, pool_total);
        if system_ram == kernel_reserved.saturating_add(pool_total)
        {
            std::os::seraph::log!(
                "ram_accounted_identity passed: system_ram={system_ram} == kernel_reserved={kernel_reserved} + pool_total={pool_total} (residual=0)"
            );
            return;
        }
        let _ = syscall::thread_yield();
    }

    let (system_ram, kernel_reserved, pool_total) = terms;
    let residual = system_ram.abs_diff(kernel_reserved.saturating_add(pool_total));
    panic!(
        "ram_accounted_identity FAILED: system_ram={system_ram} != kernel_reserved={kernel_reserved} + pool_total={pool_total} (residual={residual} bytes; leaked or double-counted)"
    );
}

/// Label of the call a `reclaim-child` makes on its namespace cap, which
/// carries SEND only (procmgr installs it so), to fetch a SEND that may carry
/// a cap.
const FETCH_GRANT_LABEL: u64 = 0x6665_7463;

/// Label of the call a `reclaim-child` makes on that fetched SEND to hand
/// its spawner a SEND of its own.
const HAND_SEND_LABEL: u64 = 0x7265_636c;

/// Badge of the fetched SEND (with GRANT) a `reclaim-child` hands its SEND on.
const RECLAIM_HAND_BADGE: u64 = 0x5702;

/// Badge of the SEND [`frame_reclaim_live_object_phase`] stops its own
/// receiving thread with.
const RECLAIM_STOP_BADGE: u64 = 0x5701;

/// memmgr's deferred total (`QUERY_POOL_STATUS` `data[4]`), in bytes.
fn deferred_bytes() -> u64
{
    let req = ipc::IpcMessage::builder(ipc::memmgr_labels::QUERY_POOL_STATUS).build();
    let reply = memmgr_call(&req, "QUERY_POOL_STATUS");
    assert_eq!(
        reply.label,
        ipc::memmgr_errors::SUCCESS,
        "QUERY_POOL_STATUS status"
    );
    reply.word(4)
}

/// Make memmgr recheck its deferred list: a `RELEASE_MEMORY_CAPS` naming no
/// grant releases nothing and only rechecks.
fn recheck_deferred()
{
    let release = ipc::IpcMessage::builder(ipc::memmgr_labels::RELEASE_MEMORY_CAPS)
        .word(0, 0)
        .build();
    let reply = memmgr_call(&release, "RELEASE_MEMORY_CAPS (recheck)");
    assert_eq!(
        reply.label,
        ipc::memmgr_errors::SUCCESS,
        "RELEASE_MEMORY_CAPS (recheck) status"
    );
}

/// memmgr's deferred total once rechecks stop lowering it: a run already
/// deferred that has become quiescent is pooled now, not by a recheck inside
/// the phase's own later messages, which would lower the total the phase
/// compares against its baseline. One recheck checks only the oldest runs
/// within its budget (services/memmgr/docs/memory-pool.md § Reclamation), so
/// the total counts as settled only after [`SETTLE_QUIET`] rechecks in a row
/// leave it unlowered: enough to cycle a list of `SETTLE_QUIET` batches of
/// runs, far past what a svctest boot defers.
fn settled_deferred_bytes() -> u64
{
    // A test wait bound: it limits only how many rechecks the settle takes.
    const MAX_SETTLE: u32 = 256;
    let mut last = deferred_bytes();
    let mut quiet = 0u32;
    for _ in 0..MAX_SETTLE
    {
        recheck_deferred();
        let now = deferred_bytes();
        quiet = if now < last
        {
            0
        }
        else
        {
            quiet
                .checked_add(1)
                .expect("quiet recheck count overflowed")
        };
        last = now;
        if quiet == SETTLE_QUIET
        {
            break;
        }
    }
    last
}

/// Rechecks in a row that must leave memmgr's deferred total unlowered before
/// [`settled_deferred_bytes`] takes it as settled.
const SETTLE_QUIET: u32 = 8;

/// Trigger rechecks until memmgr's deferred total falls to `target` bytes or
/// below; panics with `what` when it does not within the poll bound.
fn await_deferred_at_most(target: u64, what: &str)
{
    // A test wait bound: it limits only how long the phase polls before it
    // fails. One recheck examines every run of a short deferred list.
    const MAX_POLL: u32 = 64;
    let mut last = 0;
    for _ in 0..MAX_POLL
    {
        recheck_deferred();
        last = deferred_bytes();
        if last <= target
        {
            return;
        }
        let _ = syscall::thread_yield();
    }
    panic!("{what}: memmgr's deferred total stayed at {last} bytes, above {target}");
}

/// A `reclaim-child`: retype an endpoint from a one-page grant of its own,
/// hand a SEND on it to the spawner (whose endpoint arrives as this
/// process's namespace cap), and park until killed. Exit codes: 2 = the
/// endpoint retype failed, 3 = the SEND derive failed, 4 = fetching the
/// hand-off SEND failed, 5 = the hand-off call failed.
fn reclaim_child_main() -> !
{
    let ipc_buf = current_ipc_buf();
    let (grant, _) = request_one_page();
    let Ok(ep) = syscall::cap_create_endpoint(grant)
    else
    {
        std::process::exit(2)
    };
    let Ok(send) = syscall::cap_derive(ep, syscall::RIGHTS_EP_SEND)
    else
    {
        std::process::exit(3)
    };
    let fetch = ipc::IpcMessage::new(FETCH_GRANT_LABEL);
    // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
    let fetched = unsafe { ipc::ipc_call(std::os::seraph::root_dir_cap(), &fetch, ipc_buf) };
    let Some(&hand_ep) = fetched.as_ref().ok().and_then(|reply| reply.caps().first())
    else
    {
        std::process::exit(4)
    };
    let hand = ipc::IpcMessage::builder(HAND_SEND_LABEL).cap(send).build();
    // SAFETY: as above.
    if unsafe { ipc::ipc_call(hand_ep, &hand, ipc_buf) }.is_err()
    {
        std::process::exit(5);
    }
    loop
    {
        std::thread::park();
    }
}

/// Serve `ep` until a `reclaim-child` hands over a SEND, returning it, or
/// until the stop badge arrives, returning `None`. A fetch is answered with
/// a SEND (with GRANT) badged [`RECLAIM_HAND_BADGE`]; any other call is
/// refused and its caps deleted.
fn receive_handed_send(ep: u64) -> Option<u64>
{
    let ipc_buf = current_ipc_buf();
    loop
    {
        // SAFETY: `ipc_buf` is this thread's registered IPC buffer page.
        let msg = unsafe { ipc::ipc_recv(ep, ipc_buf) }.expect("reclaim server: ipc_recv failed");
        let stop = msg.badge == RECLAIM_STOP_BADGE;
        let handed = if msg.badge == RECLAIM_HAND_BADGE && msg.label == HAND_SEND_LABEL
        {
            msg.caps().first().copied()
        }
        else
        {
            None
        };
        for &cap in msg.caps().iter().skip(usize::from(handed.is_some()))
        {
            let _ = syscall::cap_delete(cap);
        }
        let done = stop || handed.is_some();
        let reply = if done
        {
            ipc::IpcMessage::new(0)
        }
        else if msg.label == FETCH_GRANT_LABEL
        {
            let hand_ep =
                syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND_GRANT, RECLAIM_HAND_BADGE)
                    .expect("reclaim server: hand-off SEND derive failed");
            ipc::IpcMessage::builder(0).cap(hand_ep).build()
        }
        else
        {
            ipc::IpcMessage::new(u64::MAX)
        };
        // SAFETY: as above.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        if done
        {
            return handed;
        }
    }
}

/// A frame holding a live kernel object stays out of memmgr's free pool
/// after its process dies, and joins it once the object dies
/// (services/memmgr/docs/memory-pool.md § Reclamation). A `reclaim-child`
/// retypes an endpoint from a one-page grant and hands svctest a SEND on it;
/// svctest kills the child. The page must then be on memmgr's deferred list,
/// spawns after the death must succeed, and the SEND must still name the
/// live endpoint. Once svctest deletes the SEND, the endpoint dies and the
/// page must leave the deferred list at memmgr's next recheck.
pub fn frame_reclaim_live_object_phase(_: &Caps)
{
    use std::os::seraph::process::CommandExt;

    /// Spawns after the death, each drawing frames from the pool.
    const SPAWNS: u32 = 4;

    let ep = std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
        syscall::cap_create_endpoint(slab).ok()
    })
    .expect("frame_reclaim_live_object: endpoint creation failed");
    let root = syscall::cap_derive(ep, syscall::RIGHTS_EP_SEND)
        .expect("frame_reclaim_live_object: root SEND derive failed");
    let stop = syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND, RECLAIM_STOP_BADGE)
        .expect("frame_reclaim_live_object: stop SEND derive failed");
    let server = std::thread::Builder::new()
        .name("reclaim_server".into())
        .spawn(move || receive_handed_send(ep))
        .expect("frame_reclaim_live_object: server thread spawn failed");

    let baseline = settled_deferred_bytes();
    let mut child = std::process::Command::new("/tests/svctest")
        .arg(RECLAIM_CHILD_ROLE)
        .namespace_cap(root)
        .spawn()
        .expect("frame_reclaim_live_object: spawning reclaim-child failed");
    while !server.is_finished()
    {
        if let Some(status) = child
            .try_wait()
            .expect("frame_reclaim_live_object: try_wait failed")
        {
            // SAFETY: `current_ipc_buf` is this thread's registered IPC buffer.
            let _ = unsafe { ipc::ipc_call(stop, &ipc::IpcMessage::new(0), current_ipc_buf()) };
            let _ = server.join();
            panic!(
                "frame_reclaim_live_object: reclaim-child exited {status} before handing its \
                 SEND (2 = retype, 3 = derive, 4 = fetch, 5 = hand-off failed)"
            );
        }
        let _ = syscall::thread_yield();
    }
    let send = server
        .join()
        .expect("frame_reclaim_live_object: server thread panicked")
        .expect("frame_reclaim_live_object: no SEND handed over");
    let _ = syscall::cap_delete(stop);
    let _ = syscall::cap_delete(ep);

    child
        .kill()
        .expect("frame_reclaim_live_object: killing reclaim-child failed");
    let _ = child.wait();
    let after_kill = deferred_bytes();
    assert!(
        after_kill
            >= baseline
                .checked_add(syscall_abi::PAGE_SIZE)
                .expect("deferred baseline plus a page overflowed"),
        "frame_reclaim_live_object: the dead child's endpoint page was pooled \
         (deferred {baseline} -> {after_kill} bytes)"
    );

    for i in 0..SPAWNS
    {
        let status = std::process::Command::new("/programs/hello")
            .status()
            .unwrap_or_else(|e| panic!("frame_reclaim_live_object: spawn {i} failed: {e}"));
        assert!(
            status.success(),
            "frame_reclaim_live_object: spawn {i} exited {status}"
        );
    }

    let tag_rights = syscall::cap_info(send, syscall::CAP_INFO_TAG_RIGHTS)
        .expect("frame_reclaim_live_object: the held SEND no longer resolves");
    assert_eq!(
        tag_rights & 0xFFFF_FFFF,
        syscall::RIGHTS_EP_SEND,
        "frame_reclaim_live_object: the held SEND changed rights"
    );

    syscall::cap_delete(send).expect("frame_reclaim_live_object: deleting the SEND failed");
    await_deferred_at_most(
        after_kill
            .checked_sub(syscall_abi::PAGE_SIZE)
            .expect("deferred bytes below a page after the kill"),
        "frame_reclaim_live_object: endpoint page after its last SEND went",
    );
    std::os::seraph::log!(
        "frame_reclaim_live_object: dead child's endpoint page held ({baseline} -> {after_kill} \
         deferred bytes), then pooled once the SEND went"
    );
}

/// A released frame that its releaser still maps stays out of memmgr's free
/// pool, and joins it once the mapping goes
/// (services/memmgr/docs/memory-pool.md § Reclamation). svctest maps a
/// one-page grant and releases it while mapped: the page must be on memmgr's
/// deferred list, none of the next one-page grants may be that page
/// ([`assert_draws_avoid`]), and the page must leave the deferred list at the
/// first recheck after svctest unmaps it and deletes its cap.
pub fn frame_reclaim_mapped_release_phase(_: &Caps)
{
    use syscall::{MAP_READ, MAP_WRITABLE};

    /// One-page grants drawn while the released page is held.
    const DRAWS: usize = 4;

    let info = startup_info();
    let (grant, region_id) = request_one_page();
    let range = std::os::seraph::reserve_pages(1).expect("frame_reclaim_mapped_release: reserve");
    let va = range.va_start();
    // SAFETY: `range` is a fresh page reservation from the per-process arena,
    // owned here: VA no Rust object or IPC page occupies.
    unsafe { syscall::mem_map(grant, info.self_aspace, va, 0, 1, MAP_READ | MAP_WRITABLE) }
        .expect("frame_reclaim_mapped_release: mem_map of the grant failed");

    let baseline = settled_deferred_bytes();
    let release = ipc::IpcMessage::builder(ipc::memmgr_labels::RELEASE_MEMORY_CAPS)
        .word(0, 1)
        .word(1, region_id)
        .build();
    let reply = memmgr_call(&release, "RELEASE_MEMORY_CAPS (mapped)");
    assert_eq!(
        reply.label,
        ipc::memmgr_errors::SUCCESS,
        "RELEASE_MEMORY_CAPS (mapped) status"
    );
    let held = deferred_bytes();
    assert!(
        held >= baseline
            .checked_add(syscall_abi::PAGE_SIZE)
            .expect("deferred baseline plus a page overflowed"),
        "frame_reclaim_mapped_release: a still-mapped released page was pooled \
         (deferred {baseline} -> {held} bytes)"
    );

    let draws: Vec<(u64, u64)> = (0..DRAWS).map(|_| request_one_page()).collect();
    assert_draws_avoid(
        grant,
        &draws,
        "frame_reclaim_mapped_release: memmgr granted a released page its releaser still maps",
    );
    for (cap, id) in draws
    {
        release_one_page(cap, id);
    }

    // SAFETY: `va` is the page mapped above, in this process's own address
    // space, and no Rust reference points into it.
    unsafe { syscall::mem_unmap(info.self_aspace, va, 1) }
        .expect("frame_reclaim_mapped_release: mem_unmap failed");
    std::os::seraph::unreserve_pages(range);
    syscall::cap_delete(grant).expect("frame_reclaim_mapped_release: cap_delete of grant");
    await_deferred_at_most(
        held.checked_sub(syscall_abi::PAGE_SIZE)
            .expect("deferred bytes below a page after the release"),
        "frame_reclaim_mapped_release: released page after its mapping went",
    );
    std::os::seraph::log!(
        "frame_reclaim_mapped_release: mapped released page held ({baseline} -> {held} deferred \
         bytes), then pooled once unmapped"
    );
}

/// A released frame that another capability still names stays out of
/// memmgr's free pool, and joins it once that capability goes
/// (services/memmgr/docs/memory-pool.md § Reclamation). svctest derives a
/// second, never-mapped cap from a one-page grant, deletes the grant and
/// releases the page: the page must be on memmgr's deferred list and none of
/// the next one-page grants may be that page ([`assert_draws_avoid`]), and it
/// must leave the deferred list at the first recheck after svctest deletes the
/// derived cap.
pub fn frame_reclaim_held_cap_release_phase(_: &Caps)
{
    /// One-page grants drawn while the released page is held.
    const DRAWS: usize = 4;

    let (grant, region_id) = request_one_page();
    let kept = syscall::cap_derive(grant, syscall::RIGHTS_MEM_MAP_RW)
        .expect("frame_reclaim_held_cap_release: cap_derive of the grant failed");
    let baseline = settled_deferred_bytes();
    // `release_one_page` deletes the grant itself; the derived cap stays.
    release_one_page(grant, region_id);
    let held = deferred_bytes();
    assert!(
        held >= baseline
            .checked_add(syscall_abi::PAGE_SIZE)
            .expect("deferred baseline plus a page overflowed"),
        "frame_reclaim_held_cap_release: a released page another cap still names was pooled \
         (deferred {baseline} -> {held} bytes)"
    );

    let draws: Vec<(u64, u64)> = (0..DRAWS).map(|_| request_one_page()).collect();
    assert_draws_avoid(
        kept,
        &draws,
        "frame_reclaim_held_cap_release: memmgr granted a released page a live cap still names",
    );
    for (cap, id) in draws
    {
        release_one_page(cap, id);
    }

    syscall::cap_delete(kept).expect("frame_reclaim_held_cap_release: cap_delete of the kept cap");
    await_deferred_at_most(
        held.checked_sub(syscall_abi::PAGE_SIZE)
            .expect("deferred bytes below a page after the release"),
        "frame_reclaim_held_cap_release: released page after its last other cap went",
    );
    std::os::seraph::log!(
        "frame_reclaim_held_cap_release: released page held by a live cap ({baseline} -> {held} \
         deferred bytes), then pooled once the cap went"
    );
}

/// Assert that no one-page grant of `draws` is the page `held` names, without
/// reading a physical address, which svctest's grants do not let it read:
/// each draw is mapped in turn, and the user mappings of `held`'s page must
/// not rise while it is, which they would by one if the draw were that page
/// (`CAP_INFO_MEMORY_MAPPINGS`).
fn assert_draws_avoid(held: u64, draws: &[(u64, u64)], what: &str)
{
    let info = startup_info();
    let range = std::os::seraph::reserve_pages(1).expect("assert_draws_avoid: reserve");
    let va = range.va_start();
    let before =
        syscall::cap_info_memory_mappings(held, 0, 1).expect("assert_draws_avoid: held mappings");
    for &(cap, _) in draws
    {
        // SAFETY: `range` is a fresh page reservation from the per-process
        // arena, owned here: VA no Rust object or IPC page occupies.
        unsafe { syscall::mem_map(cap, info.self_aspace, va, 0, 1, syscall::MAP_READ) }
            .expect("assert_draws_avoid: mem_map of a draw failed");
        let during = syscall::cap_info_memory_mappings(held, 0, 1)
            .expect("assert_draws_avoid: held mappings");
        // SAFETY: `va` is the page mapped just above, in this process's own
        // address space, and no Rust reference points into it.
        unsafe { syscall::mem_unmap(info.self_aspace, va, 1) }
            .expect("assert_draws_avoid: mem_unmap of a draw failed");
        assert_eq!(during, before, "{what}");
    }
    std::os::seraph::unreserve_pages(range);
}

/// A process memmgr did not register phys-class, as every device driver is,
/// cannot read a physical address (core/kernel/docs/cross-boundary-disclosure.md
/// § Physical-address surfaces): memmgr's grant reply carries a region id in
/// place of the physical base, and the grant itself lacks `RIGHTS_MEM_PHYS`,
/// so `CAP_INFO_MEMORY_PHYS_BASE` refuses it, alone and with the grant
/// presented as its own credential. svctest's own `AddressSpace` cap lacks
/// `RIGHTS_AS_READ`, so `SYS_ASPACE_QUERY` refuses to translate a page it
/// maps, and an address space it creates from a grant is minted without that
/// right either. The grant still maps, and its region id still releases it.
pub fn phys_base_withheld_phase(_: &Caps)
{
    let info = startup_info();
    let (grant, region_id) = request_one_page();
    let rights = syscall::cap_info(grant, syscall::CAP_INFO_TAG_RIGHTS)
        .expect("phys_base_withheld: TAG_RIGHTS of the grant")
        & 0xFFFF_FFFF;
    assert_eq!(
        rights & syscall::RIGHTS_MEM_PHYS,
        0,
        "phys_base_withheld: memmgr granted RIGHTS_MEM_PHYS (rights {rights:#x})"
    );
    let refused = syscall_abi::SyscallError::InsufficientRights as i64;
    assert_eq!(
        syscall::cap_info(grant, syscall::CAP_INFO_MEMORY_PHYS_BASE),
        Err(refused),
        "phys_base_withheld: the physical base of a grant was not refused"
    );
    assert_eq!(
        syscall::cap_info_phys_base(grant, grant),
        Err(refused),
        "phys_base_withheld: a credential without RIGHTS_MEM_PHYS was accepted"
    );

    let range = std::os::seraph::reserve_pages(1).expect("phys_base_withheld: reserve");
    let va = range.va_start();
    // SAFETY: `range` is a fresh page reservation from the per-process arena,
    // owned here: VA no Rust object or IPC page occupies.
    unsafe {
        syscall::mem_map(
            grant,
            info.self_aspace,
            va,
            0,
            1,
            syscall::MAP_READ | syscall::MAP_WRITABLE,
        )
    }
    .expect("phys_base_withheld: mem_map of the grant failed");
    assert_eq!(
        syscall::aspace_query(info.self_aspace, va),
        Err(refused),
        "phys_base_withheld: SYS_ASPACE_QUERY translated a page for a process without the right"
    );
    // SAFETY: `va` is the page mapped just above, in this process's own
    // address space, and no Rust reference points into it.
    unsafe { syscall::mem_unmap(info.self_aspace, va, 1) }
        .expect("phys_base_withheld: mem_unmap of the grant failed");
    std::os::seraph::unreserve_pages(range);

    let aspace_grant =
        std::os::seraph::object_slab_retype_reclaimable(2 * syscall_abi::PAGE_SIZE, |slab| {
            syscall::cap_create_aspace(slab, 0, 2).ok()
        })
        .expect("phys_base_withheld: cap_create_aspace from a grant failed");
    let (aspace, slab_grant) = aspace_grant;
    let aspace_rights = syscall::cap_info(aspace, syscall::CAP_INFO_TAG_RIGHTS)
        .expect("phys_base_withheld: TAG_RIGHTS of the created address space")
        & 0xFFFF_FFFF;
    assert_eq!(
        aspace_rights & syscall::RIGHTS_AS_READ,
        0,
        "phys_base_withheld: an address space created from a grant carries RIGHTS_AS_READ"
    );
    syscall::cap_delete(aspace).expect("phys_base_withheld: cap_delete of the address space");
    if let Some(slab_grant) = slab_grant
    {
        std::os::seraph::object_slab_release(slab_grant);
    }

    release_one_page(grant, region_id);
    std::os::seraph::log!(
        "phys_base_withheld: grant carries a region id, PHYS_BASE and ASPACE_QUERY refused"
    );
}
