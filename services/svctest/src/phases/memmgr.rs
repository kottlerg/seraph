// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/memmgr.rs

//! Memmgr / heap allocator surface.

use std::collections::BTreeMap;
use std::os::seraph::{current_ipc_buf, startup_info};

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
    ]
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
        m.insert(k, k * 100);
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
        let mut v: Vec<u8> = Vec::with_capacity(size / 2 + 1);
        for b in 0..size
        {
            #[allow(clippy::cast_possible_truncation)]
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

#[allow(clippy::cast_possible_truncation)]
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
        assert_eq!(big[idx], expected, "grow buffer[{idx}] mismatch");
    }

    let mut small: Vec<Vec<u8>> = Vec::with_capacity(8);
    for k in 0..8usize
    {
        small.push(vec![k as u8; 1024]);
    }
    for (k, v) in small.iter().enumerate()
    {
        assert_eq!(v.len(), 1024);
        assert_eq!(v[0], k as u8);
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

/// Request a one-page grant from memmgr: `(grant cap, physical base)`.
fn request_one_page() -> (u32, u64)
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
    // One cap: data[1] is its page count, data[2] its physical base.
    (grant, reply.word(2))
}

/// Drop the grant cap and hand its region back to memmgr.
fn release_one_page(grant: u32, phys_base: u64)
{
    syscall::cap_delete(grant).expect("cap_delete of grant");
    let release = ipc::IpcMessage::builder(ipc::memmgr_labels::RELEASE_MEMORY_CAPS)
        .word(0, 1)
        .word(1, phys_base)
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
    let (grant, phys_base) = request_one_page();

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

    release_one_page(grant, phys_base);
    std::os::seraph::log!("non-procmgr donation refused with UNAUTHORIZED");
}

/// Messages whose attached caps memmgr's contract does not keep, as
/// `(label, words, expected reply label)`: every label whose contract carries
/// no caps, the two cap-carrying labels from a caller that is not procmgr, a
/// forged `FAULT_LABEL`, and an unknown label. Each request is refused or has
/// no lasting effect, so the flood changes no memmgr state but its `CSpace`.
const STRAY_CAP_CASES: [(u64, [u64; 3], u64); 11] = [
    // want_pages == 0.
    (
        ipc::memmgr_labels::REQUEST_MEMORY_CAPS,
        [0, 0, 0],
        ipc::memmgr_errors::INVALID_ARGUMENT,
    ),
    // count == 0: nothing to release.
    (
        ipc::memmgr_labels::RELEASE_MEMORY_CAPS,
        [0, 0, 0],
        ipc::memmgr_errors::SUCCESS,
    ),
    (
        ipc::memmgr_labels::REGISTER_PROCESS,
        [0, 0, 0],
        ipc::memmgr_errors::UNAUTHORIZED,
    ),
    (
        ipc::memmgr_labels::PROCESS_DIED,
        [0, 0, 0],
        ipc::memmgr_errors::UNAUTHORIZED,
    ),
    (
        ipc::memmgr_labels::DONATE_MEMORY_CAPS,
        [0, 0, 0],
        ipc::memmgr_errors::UNAUTHORIZED,
    ),
    (
        ipc::memmgr_labels::QUERY_POOL_STATUS,
        [0, 0, 0],
        ipc::memmgr_errors::SUCCESS,
    ),
    // len == 0.
    (
        ipc::memmgr_labels::REGISTER_REGION,
        [0, 0, 0],
        ipc::memmgr_errors::INVALID_ARGUMENT,
    ),
    (
        ipc::memmgr_labels::DELEGATE_ASPACE,
        [0, 0, 0],
        ipc::memmgr_errors::UNAUTHORIZED,
    ),
    // No region is registered at [0, 0).
    (
        ipc::memmgr_labels::UNREGISTER_REGION,
        [0, 0, 0],
        ipc::memmgr_errors::INVALID_ARGUMENT,
    ),
    // A non-VM kind: memmgr answers KILL, which an ordinary caller receives
    // as a plain reply label.
    (
        syscall_abi::FAULT_LABEL,
        [syscall_abi::FAULT_KIND_EXCEPTION, 0, 0],
        syscall_abi::FAULT_REPLY_KILL,
    ),
    // No memmgr label: the default arm.
    (0x7FFF, [0, 0, 0], ipc::memmgr_errors::INVALID_ARGUMENT),
];

/// Calls the stray-cap flood makes per case. Each call carries
/// `MSG_CAP_SLOTS_MAX` caps, so every case on its own attaches 9 Ki caps, more
/// than the slots memmgr's `CSpace` is seeded with (init's
/// `CSPACE_RETYPE_PAGES` slot pages, about 8 Ki slots): a memmgr that kept the
/// stray caps of any one case would exhaust its `CSpace` during that case,
/// fail its receive, and exit with `EXIT_RECV_WEDGE`.
const STRAY_CAP_CALLS_PER_CASE: usize = 2304;

/// Flood memmgr, case by case, with caps attached to messages whose contract
/// does not keep them, then check it still answers. Every call must also get
/// its case's normal reply, so deleting the strays changes no label's
/// behaviour.
pub fn stray_cap_flood_phase(_: &Caps)
{
    let info = startup_info();
    for (label, words, expected) in STRAY_CAP_CASES
    {
        for call in 0..STRAY_CAP_CALLS_PER_CASE
        {
            let mut builder = ipc::IpcMessage::builder(label)
                .word(0, words[0])
                .word(1, words[1])
                .word(2, words[2]);
            for _ in 0..syscall_abi::MSG_CAP_SLOTS_MAX
            {
                let stray = syscall::cap_derive(info.memmgr_endpoint, syscall::RIGHTS_EP_SEND)
                    .expect("cap_derive of a stray cap");
                builder = builder.cap(stray);
            }
            let reply = memmgr_call(&builder.build(), "stray-cap flood");
            assert_eq!(
                reply.label, expected,
                "memmgr reply to stray-cap call {call} with label {label:#x}"
            );
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
        "memmgr answered {} calls carrying {} stray caps",
        STRAY_CAP_CASES.len() * STRAY_CAP_CALLS_PER_CASE,
        STRAY_CAP_CASES.len() * STRAY_CAP_CALLS_PER_CASE * syscall_abi::MSG_CAP_SLOTS_MAX
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
    const MAX_POLL: u32 = 4096;

    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
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
