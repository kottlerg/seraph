// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/thread_lifecycle.rs

//! Integration: full thread lifecycle end-to-end.
//!
//! Exercises the complete thread management lifecycle as a single coherent
//! scenario:
//!
//!   1. Create thread (`cap_create_thread`, `cap_create_cspace`)
//!   2. Configure entry, stack, arg (`thread_configure`)
//!   3. Start (`thread_start`) → child signals readiness (0x1)
//!   4. Stop while child is blocked in `signal_wait` (`thread_stop`)
//!   5. Read register state (`thread_read_regs`) → verify IP non-zero
//!   6. Redirect IP via `write_regs` (`thread_write_regs`) → `phase2_entry`
//!   7. Resume (`thread_start`) → child sends 0x2 to confirm redirection
//!   8. Set priority in normal range (`thread_set_priority`)
//!   9. Set affinity to CPU 0 (`thread_set_affinity`)
//!
//! The intent is to validate that each step leaves the thread in the correct
//! state for the next step — not to test each syscall in isolation (that is
//! the job of unit/thread.rs).

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    cap_copy, cap_create_cspace, cap_create_signal, cap_create_thread, cap_delete, signal_send,
    signal_wait, thread_configure, thread_exit, thread_read_regs, thread_set_affinity,
    thread_set_priority, thread_start, thread_stop, thread_write_regs,
};

use crate::{ChildStack, TestContext, TestResult};

const RIGHTS_SIGNAL: u64 = 1 << 7;
const RIGHTS_WAIT: u64 = 1 << 8;

#[cfg(target_arch = "x86_64")]
const IP_OFFSET: usize = 120;
#[cfg(target_arch = "riscv64")]
const IP_OFFSET: usize = 248;

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

/// Cap slot for `phase2_entry` (see unit/thread.rs for the rationale).
static PHASE2_SIG: AtomicU32 = AtomicU32::new(0);

pub fn run(ctx: &TestContext) -> TestResult
{
    const BUF: usize = 512;
    // Two distinct signals — child→parent readiness and child blocking
    // primitive — so the child cannot self-deliver its own readiness send
    // before the parent has registered as the waiter (race observed on SMP).
    let ready = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "integration::thread_lifecycle: cap_create_signal (ready) failed")?;
    let block = cap_create_signal(ctx.memory_frame_base)
        .map_err(|_| "integration::thread_lifecycle: cap_create_signal (block) failed")?;
    let cs = cap_create_cspace(ctx.memory_frame_base, 0, 4, 16)
        .map_err(|_| "integration::thread_lifecycle: cap_create_cspace failed")?;
    let child_ready = cap_copy(ready, cs, RIGHTS_SIGNAL)
        .map_err(|_| "integration::thread_lifecycle: cap_copy (ready→child) failed")?;
    let child_block = cap_copy(block, cs, RIGHTS_WAIT)
        .map_err(|_| "integration::thread_lifecycle: cap_copy (block→child) failed")?;
    let th = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs)
        .map_err(|_| "integration::thread_lifecycle: cap_create_thread failed")?;

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    let blocker_arg = (u64::from(child_ready) << 32) | u64::from(child_block);
    thread_configure(
        th,
        blocker_entry as *const () as u64,
        stack_top,
        blocker_arg,
    )
    .map_err(|_| "integration::thread_lifecycle: thread_configure failed")?;

    // ── Step 3: Start — child signals readiness. ──────────────────────────────
    thread_start(th).map_err(|_| "integration::thread_lifecycle: thread_start failed")?;
    let ready_bits = signal_wait(ready)
        .map_err(|_| "integration::thread_lifecycle: signal_wait (readiness) failed")?;
    if ready_bits != 0x1
    {
        return Err("integration::thread_lifecycle: child sent wrong readiness bits");
    }

    // ── Step 4: Stop while child is blocked. ──────────────────────────────────
    thread_stop(th).map_err(|_| "integration::thread_lifecycle: thread_stop failed")?;

    // ── Step 5: Read registers — verify IP is non-zero. ───────────────────────
    let mut reg_buf = [0u8; BUF];
    thread_read_regs(th, reg_buf.as_mut_ptr(), BUF)
        .map_err(|_| "integration::thread_lifecycle: thread_read_regs failed")?;

    let ip = u64::from_le_bytes(
        reg_buf[IP_OFFSET..IP_OFFSET + 8]
            .try_into()
            .unwrap_or([0u8; 8]),
    );
    if ip == 0
    {
        return Err("integration::thread_lifecycle: rip/sepc is zero after thread_stop");
    }

    // ── Step 6: Redirect IP to phase2_entry. ──────────────────────────────────
    // phase2_entry will send 0x2 through the same `child_ready` cap parent
    // is now about to wait on.
    PHASE2_SIG.store(child_ready, Ordering::Release);
    let phase2_ptr = phase2_entry as *const () as u64;
    reg_buf[IP_OFFSET..IP_OFFSET + 8].copy_from_slice(&phase2_ptr.to_le_bytes());
    thread_write_regs(th, reg_buf.as_ptr(), BUF)
        .map_err(|_| "integration::thread_lifecycle: thread_write_regs failed")?;

    // ── Step 7: Resume — child lands in phase2_entry and sends 0x2. ──────────
    thread_start(th).map_err(|_| "integration::thread_lifecycle: thread_start (resume) failed")?;
    let phase2_bits = signal_wait(ready)
        .map_err(|_| "integration::thread_lifecycle: signal_wait (phase2) failed")?;
    if phase2_bits != 0x2
    {
        return Err("integration::thread_lifecycle: phase2_entry did not send 0x2");
    }

    // ── Steps 8–9: Set priority and affinity on the (now exited) thread cap. ──
    //
    // The thread cap is still valid even after the thread exits; the kernel
    // allows these operations on any Thread object. Create a fresh thread just
    // to test these without depending on child exit timing.
    let cs2 = cap_create_cspace(ctx.memory_frame_base, 0, 4, 8)
        .map_err(|_| "integration::thread_lifecycle: cap_create_cspace (step 8) failed")?;
    let th2 = cap_create_thread(ctx.memory_frame_base, ctx.aspace_cap, cs2)
        .map_err(|_| "integration::thread_lifecycle: cap_create_thread (step 8) failed")?;

    thread_set_priority(th2, 5, 0)
        .map_err(|_| "integration::thread_lifecycle: thread_set_priority failed")?;
    thread_set_affinity(th2, 0)
        .map_err(|_| "integration::thread_lifecycle: thread_set_affinity failed")?;

    cap_delete(th2).ok();
    cap_delete(cs2).ok();
    cap_delete(th).ok();
    cap_delete(ready).ok();
    cap_delete(block).ok();
    cap_delete(cs).ok();
    Ok(())
}

// cast_possible_truncation: cap slot indices are guaranteed < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn blocker_entry(arg: u64) -> !
{
    let ready_slot = (arg >> 32) as u32;
    let block_slot = (arg & 0xFFFF_FFFF) as u32;
    signal_send(ready_slot, 0x1).ok();
    signal_wait(block_slot).ok();
    loop
    {
        core::hint::spin_loop();
    }
}

fn phase2_entry() -> !
{
    let sig = PHASE2_SIG.load(Ordering::Acquire);
    signal_send(sig, 0x2).ok();
    thread_exit()
}
