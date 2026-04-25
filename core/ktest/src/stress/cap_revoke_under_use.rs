// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Stress test: revoke while derived capabilities are actively used.
//!
//! 4 child threads send on derived caps in a tight loop. The parent revokes
//! the root cap mid-flight. Children detect errors and exit. Verifies no
//! kernel panic or use-after-free occurs.

use syscall::{
    cap_copy, cap_create_cspace, cap_create_signal, cap_create_thread, cap_delete, cap_derive,
    cap_revoke, signal_send, signal_wait, thread_configure, thread_exit, thread_start,
    thread_yield,
};

use crate::{ChildStack, TestContext, TestResult};

const NUM_CHILDREN: usize = 16;
const RIGHTS_SIGNAL: u64 = 1 << 7;

pub fn run(ctx: &TestContext) -> TestResult
{
    let root = cap_create_signal().map_err(|_| "cap_revoke_under_use: create root failed")?;
    let done = cap_create_signal().map_err(|_| "cap_revoke_under_use: create done failed")?;

    // Derive 4 children from root.
    let mut derived = [0u32; NUM_CHILDREN];
    for slot in &mut derived
    {
        *slot =
            cap_derive(root, RIGHTS_SIGNAL).map_err(|_| "cap_revoke_under_use: derive failed")?;
    }

    // Spawn 4 threads, each sending on its derived cap.
    let mut threads = [0u32; NUM_CHILDREN];
    let mut cspaces = [0u32; NUM_CHILDREN];
    for i in 0..NUM_CHILDREN
    {
        let cs = cap_create_cspace(16).map_err(|_| "cap_revoke_under_use: create_cspace failed")?;
        let child_sig = cap_copy(derived[i], cs, RIGHTS_SIGNAL)
            .map_err(|_| "cap_revoke_under_use: cap_copy sig failed")?;
        let child_done =
            cap_copy(done, cs, 1 << 7).map_err(|_| "cap_revoke_under_use: cap_copy done failed")?;

        let th = cap_create_thread(ctx.aspace_cap, cs)
            .map_err(|_| "cap_revoke_under_use: create_thread failed")?;

        let done_bit = 1u64 << i;
        let arg = u64::from(child_sig) | (u64::from(child_done) << 16) | (done_bit << 32);
        // SAFETY: Each child uses a distinct stack index.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
        thread_configure(th, sender_loop_entry as *const () as u64, stack_top, arg)
            .map_err(|_| "cap_revoke_under_use: thread_configure failed")?;
        thread_start(th).map_err(|_| "cap_revoke_under_use: thread_start failed")?;

        threads[i] = th;
        cspaces[i] = cs;
    }

    // Let children run for a while before revoking.
    for _ in 0..10
    {
        let _ = thread_yield();
    }

    // Revoke root — all derived caps become invalid. Children will start
    // getting errors on their sends and exit.
    cap_revoke(root).map_err(|_| "cap_revoke_under_use: cap_revoke failed")?;

    // Wait for all children to report done. Each child sends a unique bit.
    let all_done = (1u64 << NUM_CHILDREN) - 1;
    let mut done_bits: u64 = 0;
    while done_bits != all_done
    {
        done_bits |= signal_wait(done).unwrap_or(0);
    }

    // Root must still be valid.
    signal_send(root, 0x1).map_err(|_| "cap_revoke_under_use: root invalid after revoke")?;
    signal_wait(root).ok();

    // Clean up.
    for i in 0..NUM_CHILDREN
    {
        cap_delete(threads[i]).ok();
        cap_delete(cspaces[i]).ok();
    }
    cap_delete(root).ok();
    cap_delete(done).ok();
    Ok(())
}

// cast_possible_truncation: slot indices are kernel cap slots < 2^32.
#[allow(clippy::cast_possible_truncation)]
fn sender_loop_entry(arg: u64) -> !
{
    let sig_slot = (arg & 0xFFFF) as u32;
    let done_slot = ((arg >> 16) & 0xFFFF) as u32;
    let done_bit = (arg >> 32) & 0xFFFF;

    // Send in a tight loop until the cap is revoked.
    loop
    {
        if signal_send(sig_slot, 0x1).is_err()
        {
            break;
        }
    }

    signal_send(done_slot, done_bit).ok();
    thread_exit()
}
