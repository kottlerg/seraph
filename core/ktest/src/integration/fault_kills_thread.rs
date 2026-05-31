// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/fault_kills_thread.rs

//! Integration: a genuine userspace page fault still kills the thread.
//!
//! The kernel's page-fault handler classifies a fault before acting: a stale
//! TLB entry whose live mapping already satisfies the access is retried, while
//! a *genuine* fault (the address is not mapped, or the live mapping forbids
//! the access) terminates the faulting thread. This test exercises the second
//! half on the real fault path:
//!
//!   1. A child thread stores to a deliberately-unmapped user address.
//!   2. The parent polls the child's kernel-authoritative lifecycle state via
//!      `cap_info(CAP_INFO_THREAD_STATE)` until it reports `Exited`.
//!   3. The recorded exit reason must be `EXIT_FAULT_BASE + <fault vector>`
//!      (`#PF` = 14 on x86-64; store/AMO page fault = 15 on RISC-V).
//!
//! Beyond confirming the kill path, the bounded poll guards against a
//! mis-classification that would treat an unmapped address as spurious and
//! retry forever: such a bug never reaches `Exited`, so the test fails on the
//! poll bound rather than hanging.

use syscall::{cap_delete, cap_info, thread_sleep};
use syscall_abi::{CAP_INFO_THREAD_STATE, EXIT_FAULT_BASE, THREAD_STATE_EXITED};

use crate::{ChildStack, TestContext, TestResult};

/// A user-half virtual address that no test maps (96 TiB, canonical, well clear
/// of every other test's mappings).
const WILD_VA: u64 = 0x6000_0000_0000;

/// Fault vector recorded in `exit_reason` for a not-present store.
#[cfg(target_arch = "x86_64")]
const FAULT_VECTOR: u64 = 14; // #PF
#[cfg(target_arch = "riscv64")]
const FAULT_VECTOR: u64 = 15; // store/AMO page fault

/// Poll bound: at ~1 ms per `thread_sleep(1)`, ~2 s before declaring the child
/// never faulted. Comfortably above any scheduling latency on a busy SMP run.
const MAX_POLLS: u32 = 2000;

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    let child = crate::spawn::new_child(ctx)
        .map_err(|_| "integration::fault_kills_thread: spawn::new_child failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    crate::spawn::configure_and_start(&child, fault_child, stack_top, 0)
        .map_err(|_| "integration::fault_kills_thread: configure_and_start failed")?;

    let expected = EXIT_FAULT_BASE + FAULT_VECTOR;
    let mut polls = 0;
    loop
    {
        let packed = cap_info(child.th, CAP_INFO_THREAD_STATE)
            .map_err(|_| "integration::fault_kills_thread: cap_info(THREAD_STATE) failed")?;
        // cast_possible_truncation: the kernel packs an 8-bit state code in the
        // high word and a 32-bit exit reason in the low word.
        #[allow(clippy::cast_possible_truncation)]
        let state = (packed >> 32) as u32;
        if state == THREAD_STATE_EXITED
        {
            let reason = packed & 0xFFFF_FFFF;
            if reason != expected
            {
                return Err("integration::fault_kills_thread: wrong exit reason for fault");
            }
            break;
        }

        polls += 1;
        if polls >= MAX_POLLS
        {
            return Err("integration::fault_kills_thread: child never faulted/exited");
        }
        thread_sleep(1).ok();
    }

    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    Ok(())
}

/// Child entry: store to an unmapped address, which faults and is killed by the
/// kernel before the store returns. The trailing loop only satisfies the `-> !`
/// signature; it is never reached.
fn fault_child(_arg: u64) -> !
{
    let p = WILD_VA as *mut u64;
    // SAFETY: deliberately faulting — WILD_VA is unmapped, so this store raises
    // a page fault the kernel resolves by terminating this thread.
    unsafe {
        p.write_volatile(0xDEAD_BEEF);
    }
    loop
    {
        core::hint::spin_loop();
    }
}
