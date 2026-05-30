// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Memmgr / heap allocator surface.

use std::collections::BTreeMap;
use std::os::seraph::startup_info;

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

/// Assert the all-RAM-accounted identity `system_ram == kernel_reserved +
/// pool_total` holds with zero residual. memmgr reports the three terms (bytes)
/// via `QUERY_POOL_STATUS`.
///
/// init's reap donations arrive at memmgr asynchronously after init's main
/// thread exits, racing svctest's startup, so a query issued too early sees a
/// transient positive residual (donations still in flight). The residual only
/// shrinks — `kernel_reserved` is fixed and `pool_total` only grows as
/// donations land — so polling converges to zero on a clean system. A real
/// leak (a minted page that never reaches the pool) holds the residual above
/// zero and the poll times out.
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
