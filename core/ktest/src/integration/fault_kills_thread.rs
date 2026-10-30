// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/fault_kills_thread.rs

//! Integration: a genuine userspace page fault still kills the thread.
//!
//! A page fault whose live mapping already satisfies the access is retried
//! as spurious ([memory-internals.md](../../../kernel/docs/memory-internals.md)
//! § SMP TLB Shootdown); a genuine fault goes to the thread's bound fault
//! handler or, with none bound, terminates the thread
//! ([fault-handling.md](../../../../docs/fault-handling.md) § Mechanism Overview).
//! This test's child has no handler bound, so it exercises the terminal case on
//! the real fault path:
//!
//!   1. A child thread stores to a deliberately-unmapped user address.
//!   2. The parent polls the child's kernel-authoritative lifecycle state via
//!      `cap_info(CAP_INFO_THREAD_STATE)` until it reports `Exited`.
//!   3. The recorded exit reason must be `EXIT_FAULT_BASE + <fault vector>`
//!      (`crate::arch::PAGE_FAULT_STORE_VECTOR`: `#PF` on x86-64, the
//!      store/AMO page fault on RISC-V).
//!
//! Beyond confirming the kill path, the bounded poll guards against a
//! mis-classification that would treat an unmapped address as spurious and
//! retry forever: such a bug never reaches `Exited`, so the test fails on the
//! poll bound rather than hanging.

use syscall_abi::EXIT_FAULT_BASE;

use crate::{ChildStack, TestContext, TestResult};

/// A user VA that no test maps — canonical in every paging mode (below the
/// 2^38 Sv39 user half), well clear of every other test's mappings.
const WILD_VA: u64 = 0x3E_0000_0000;

/// Poll bound: at ~1 ms per `thread_sleep(1)`, ~2 s before declaring the child
/// never faulted. Comfortably above any scheduling latency on a busy SMP run.
/// Applied through [`crate::scaled_polls`], which stretches it past
/// [`crate::UNSCALED_CPUS`] CPUs, where the child's CPU waits for a host core.
const MAX_POLLS: u32 = 2000;

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "integration::fault_kills_thread: spawn::new_child failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    // SAFETY: the stack is `CHILD_STACK`, this test's own `ChildStack`,
    // on which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(&child, fault_child, stack_top, 0) }
        .map_err(|_| "integration::fault_kills_thread: configure_and_start failed")?;

    let expected = EXIT_FAULT_BASE + crate::arch::PAGE_FAULT_STORE_VECTOR;
    let reason = crate::spawn::wait_until_exited(child.th, crate::scaled_polls(MAX_POLLS))?;
    if reason != expected
    {
        return Err("integration::fault_kills_thread: wrong exit reason for fault");
    }

    child.delete_thread().ok();
    child.delete_cspace().ok();
    Ok(())
}

/// Child entry: store to an unmapped address, which faults and is killed by the
/// kernel before the store returns. The trailing loop only satisfies the `-> !`
/// signature; it is never reached.
extern "C" fn fault_child(_arg: u64) -> !
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
