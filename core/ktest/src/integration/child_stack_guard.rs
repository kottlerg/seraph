// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/child_stack_guard.rs

//! Integration: a frame larger than a page faults in a child stack's guard.
//!
//! ktest is a `lowuser` binary, and its child stacks keep `STACK_GUARD_PAGES`
//! unmapped guard pages below them (`crate::GuardedStack`). The `lowuser`
//! targets emit inline stack probes (docs/build-system.md § Custom Targets), so
//! a frame larger than a page touches its pages from the top down and faults on
//! the guard's top page before any store lands beneath it.
//!
//!   1. A child runs on a `ChildStack` that sits directly above a mapped
//!      landing pad, in one page-aligned static.
//!   2. It calls a function whose frame spans the whole stack, the guard, and
//!      a page of the pad, and stores to the frame's lowest byte.
//!   3. With the probes, the prologue faults in the guard and the kernel kills
//!      the child with the store-fault reason. Without them, the stack pointer
//!      steps over the guard, the store lands in the pad without a fault, and
//!      the child records that it survived: the test fails.

use core::sync::atomic::{AtomicBool, Ordering};

use process_layout::STACK_GUARD_PAGES;
use syscall_abi::EXIT_FAULT_BASE;

use crate::{ChildStack, StackPage, TestContext, TestResult};

/// Mapped pages below the stack's guard, where an unprobed frame's store
/// lands: the frame reaches one page into them.
const PAD_PAGES: usize = 2;

/// Bytes of the overflowing frame's local: the whole stack, the guard, and
/// one page of the pad.
const OVERFLOW_BYTES: usize = ChildStack::BYTES + STACK_GUARD_PAGES as usize * 4096 + 4096;

/// The child stack with the mapped pad directly beneath its guard.
#[repr(C, align(4096))]
struct Fixture
{
    _pad: [StackPage; PAD_PAGES],
    stack: ChildStack,
}

static mut FIXTURE: Fixture = Fixture {
    _pad: [const { StackPage([0; 4096]) }; PAD_PAGES],
    stack: ChildStack::ZERO,
};

/// Set by the child when its overflowing store returned without a fault.
static SURVIVED: AtomicBool = AtomicBool::new(false);

/// Poll bound for the child's exit, as in `fault_kills_thread`: at ~1 ms per
/// poll, ~2 s, through [`crate::scaled_polls`].
const MAX_POLLS: u32 = 2000;

pub fn run(ctx: &TestContext) -> TestResult
{
    SURVIVED.store(false, Ordering::Release);
    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "integration::child_stack_guard: spawn::new_child failed")?;

    // SAFETY: the projection only computes the field's address; it reads and
    // writes nothing.
    let stack = unsafe { core::ptr::addr_of!(FIXTURE.stack) };
    let stack_top = ChildStack::top(stack);
    // SAFETY: the stack is `FIXTURE.stack`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(&child, overflow_child, stack_top, 0) }
        .map_err(|_| "integration::child_stack_guard: configure_and_start failed")?;

    let reason = crate::spawn::wait_until_exited(child.th, crate::scaled_polls(MAX_POLLS))?;
    child.delete_thread().ok();
    child.delete_cspace().ok();
    if SURVIVED.load(Ordering::Acquire)
    {
        return Err("integration::child_stack_guard: an overflowing frame stepped over the guard");
    }
    if reason != EXIT_FAULT_BASE + crate::arch::PAGE_FAULT_STORE_VECTOR
    {
        return Err("integration::child_stack_guard: wrong exit reason for the overflow");
    }
    Ok(())
}

/// Child entry: run the overflowing frame, and record survival if it returns.
extern "C" fn overflow_child(_arg: u64) -> !
{
    overflow();
    SURVIVED.store(true, Ordering::Release);
    syscall::thread_exit()
}

/// A frame larger than the stack and its guard together, which stores to its
/// lowest byte and to no other: the local is left uninitialised, so no fill
/// walks up through the guard from below and faults whatever the probes do.
#[expect(
    clippy::large_stack_frames,
    reason = "the frame overflows its 16 KiB `ChildStack` on purpose: the test is that it faults \
              in the guard"
)]
#[inline(never)]
fn overflow()
{
    let mut frame = core::mem::MaybeUninit::<[u8; OVERFLOW_BYTES]>::uninit();
    let lowest = frame.as_mut_ptr().cast::<u8>();
    // SAFETY: `lowest` points to the first byte of `frame`, a live local;
    // writing a `u8` there needs no initialised value. With the probes the
    // prologue has already faulted in the guard before this store.
    unsafe { lowest.write_volatile(1) };
    core::hint::black_box(&frame);
}
