// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/mmio_revoke_unmaps.rs

//! Integration: revoking an `Mmio` capability unmaps what was mapped through
//! its descendants.
//!
//! Derives `held` from the `Mmio` capability for a side-effect-free register
//! page (`crate::arch::MMIO_PROBE_PHYS`), derives `granted` from `held`, and
//! maps `granted` into ktest's address space. A child thread, on another CPU
//! when there is one, reads the page's probe register in a loop, so that
//! CPU's TLB holds the translation. Revoking `held` frees `granted`, whose
//! teardown unmaps the page with a TLB shootdown before the revoke returns
//! ([docs/capability-model.md § Mmio](../../../../docs/capability-model.md#mmio)):
//! the mapping is gone, and the child's next read faults and kills it.
//!
//! Both derived capabilities are copies with their own objects, so the boot
//! capability and its own mappings (the riscv64 serial console's) are
//! untouched.

use core::sync::atomic::{AtomicU64, Ordering};

use init_protocol::{CapType, InitInfo};
use syscall::{aspace_query, cap_delete, cap_derive, cap_revoke, mmio_map, system_info};
use syscall_abi::{EXIT_FAULT_BASE, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult};

/// Mapping VA, distinct from every other test's mapping window.
const PROBE_VA: u64 = 0x1_5C00_0000;

/// Poll bound (about 1 ms per poll) for the child's first read and for its
/// death; scaled past [`crate::UNSCALED_CPUS`] by [`crate::scaled_polls`].
const MAX_POLLS: u32 = 2000;

/// Reads the child completed.
static READS: AtomicU64 = AtomicU64::new(0);

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    // SAFETY: the kernel maps the read-only InitInfo page at init_info_va for
    // ktest's lifetime.
    let info = unsafe { &*(ctx.init_info_va as *const InitInfo) };
    let Some(boot_cap) = crate::init_info::descriptors(info)
        .iter()
        .find(|d| d.cap_type == CapType::Mmio && d.aux0 == crate::arch::MMIO_PROBE_PHYS)
        .map(|d| d.slot)
    else
    {
        crate::log("ktest: integration::mmio_revoke_unmaps SKIP (no probe Mmio cap)");
        return Ok(());
    };

    let held = cap_derive(boot_cap, syscall::RIGHTS_ALL)
        .map_err(|_| "integration::mmio_revoke_unmaps: cap_derive(held) failed")?;
    let result = check(ctx, held);
    cap_delete(held).ok();
    result
}

fn check(ctx: &TestContext, held: u32) -> TestResult
{
    // Every early return below leaves `granted` derived from `held`, so the
    // caller's delete of `held` hands it to the boot capability, and its own
    // delete here unmaps the page; a started child is stopped by deleting its
    // CSpace.
    let granted = cap_derive(held, syscall::RIGHTS_ALL)
        .map_err(|_| "integration::mmio_revoke_unmaps: cap_derive(granted) failed")?;
    if mmio_map(ctx.aspace_cap, granted, PROBE_VA, 0).is_err()
    {
        cap_delete(granted).ok();
        return Err("integration::mmio_revoke_unmaps: mmio_map failed");
    }

    let Ok(child) = crate::spawn::new_child(ctx)
    else
    {
        cap_delete(granted).ok();
        return Err("integration::mmio_revoke_unmaps: spawn::new_child failed");
    };
    let abandon = |why: &'static str| -> TestResult {
        cap_delete(child.cs).ok();
        cap_delete(child.th).ok();
        cap_delete(granted).ok();
        Err(why)
    };
    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    READS.store(0, Ordering::Relaxed);
    let cpus = system_info(SystemInfoType::CpuCount as u64).unwrap_or(1);
    let started = if cpus >= 2
    {
        crate::spawn::configure_and_start_pinned(&child, reader, stack_top, 0, 1)
    }
    else
    {
        crate::spawn::configure_and_start(&child, reader, stack_top, 0)
    };
    if started.is_err()
    {
        return abandon("integration::mmio_revoke_unmaps: starting the reader failed");
    }

    let polls = crate::scaled_polls(MAX_POLLS);
    let mut waited = 0;
    while READS.load(Ordering::Acquire) == 0
    {
        waited += 1;
        if waited >= polls
        {
            return abandon("integration::mmio_revoke_unmaps: the reader never read the page");
        }
        syscall::thread_sleep(1).ok();
    }

    if cap_revoke(held).is_err()
    {
        return abandon("integration::mmio_revoke_unmaps: cap_revoke failed");
    }
    if aspace_query(ctx.aspace_cap, PROBE_VA).is_ok()
    {
        cap_delete(child.cs).ok();
        cap_delete(child.th).ok();
        return Err("integration::mmio_revoke_unmaps: the mapping survived the revoke");
    }

    let reason = crate::spawn::wait_until_exited(child.th, polls)?;
    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    if reason != EXIT_FAULT_BASE + crate::arch::PAGE_FAULT_LOAD_VECTOR
    {
        return Err("integration::mmio_revoke_unmaps: the reader did not die of a load fault");
    }
    Ok(())
}

/// Child entry: read the probe register until the read faults.
extern "C" fn reader(_arg: u64) -> !
{
    let reg = (PROBE_VA + crate::arch::MMIO_PROBE_OFFSET as u64) as *const u8;
    loop
    {
        // SAFETY: PROBE_VA maps the probe page until the parent's revoke; the
        // probe register has no read side effect. After the revoke the load
        // faults and the kernel kills this thread.
        let _ = unsafe { reg.read_volatile() };
        READS.fetch_add(1, Ordering::Release);
    }
}
