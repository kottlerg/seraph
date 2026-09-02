// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Stress test: revoke while derived capabilities are actively used.
//!
//! `NUM_CHILDREN` threads send on derived caps in a tight loop. The parent
//! revokes the root cap mid-flight. Children detect errors and exit.
//! Verifies no kernel panic or use-after-free occurs.
//!
//! `BALLAST_CHILDREN` extra derived caps pad the subtree past one revoke
//! batch (`MAX_REVOKE_EDITS` in the kernel), so the revoke runs multi-batch
//! with the root pinned by the revoke-in-progress marker while the sender
//! threads are live. The cleanup `cap_delete(root)` doubles as the check
//! that the marker was released when the revoke completed.

use syscall::{
    cap_copy, cap_create_notification, cap_delete, cap_derive, cap_revoke, notification_send,
    notification_wait, thread_exit, thread_sleep,
};

use crate::{ChildStack, TestContext, TestResult, spawn};

const NUM_CHILDREN: usize = 64;
const BALLAST_CHILDREN: usize = 200;
const RIGHTS_NOTIFY: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

/// Per-sender arguments, handed to `sender_loop_entry` by address.
#[derive(Clone, Copy)]
struct SenderArgs
{
    sig: u32,
    done: u32,
    bit_index: u64,
}

static SENDER_ARGS: spawn::ArgBlock<SenderArgs, NUM_CHILDREN> = spawn::ArgBlock::new(SenderArgs {
    sig: 0,
    done: 0,
    bit_index: 0,
});

pub fn run(ctx: &TestContext) -> TestResult
{
    let root = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_revoke_under_use: create root failed")?;
    let done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_revoke_under_use: create done failed")?;

    // Derive NUM_CHILDREN children from root.
    let mut derived = [0u32; NUM_CHILDREN];
    for slot in &mut derived
    {
        *slot =
            cap_derive(root, RIGHTS_NOTIFY).map_err(|_| "cap_revoke_under_use: derive failed")?;
    }

    // Ballast: pad the subtree past one revoke batch so the revoke below is
    // multi-batch while the sender threads are running.
    let mut ballast_probe = 0u32;
    for _ in 0..BALLAST_CHILDREN
    {
        ballast_probe = cap_derive(root, RIGHTS_NOTIFY)
            .map_err(|_| "cap_revoke_under_use: ballast derive failed")?;
    }

    // Spawn NUM_CHILDREN threads, each sending on its derived cap.
    let mut threads = [0u32; NUM_CHILDREN];
    let mut cspaces = [0u32; NUM_CHILDREN];
    for i in 0..NUM_CHILDREN
    {
        let child =
            spawn::new_child(ctx).map_err(|_| "cap_revoke_under_use: spawn::new_child failed")?;
        let child_sig = cap_copy(derived[i], child.cs, RIGHTS_NOTIFY)
            .map_err(|_| "cap_revoke_under_use: cap_copy sig failed")?;
        let child_done = cap_copy(done, child.cs, syscall_abi::RIGHTS_NTF_NOTIFY)
            .map_err(|_| "cap_revoke_under_use: cap_copy done failed")?;

        // SAFETY: child `i` has not been started yet; the block is reused
        // only after every child has been reaped.
        let arg = unsafe {
            SENDER_ARGS.publish(
                i,
                SenderArgs {
                    sig: child_sig,
                    done: child_done,
                    bit_index: i as u64,
                },
            )
        };
        // SAFETY: Each child uses a distinct stack index.
        let stack_top = ChildStack::top(unsafe { core::ptr::addr_of!(super::STRESS_STACKS[i]) });
        spawn::configure_and_start(&child, sender_loop_entry, stack_top, arg)
            .map_err(|_| "cap_revoke_under_use: configure_and_start failed")?;

        threads[i] = child.th;
        cspaces[i] = child.cs;
    }

    // Let the children (strictly below this thread's priority) run for a
    // while before revoking.
    let _ = thread_sleep(2);

    // Revoke root — all derived caps become invalid. Children will start
    // getting errors on their sends and exit.
    cap_revoke(root).map_err(|_| "cap_revoke_under_use: cap_revoke failed")?;

    // Wait for all children to report done. Each child sends a unique bit.
    // At NUM_CHILDREN=64 the bitmask saturates the u64.
    let all_done: u64 = if NUM_CHILDREN >= 64
    {
        u64::MAX
    }
    else
    {
        (1u64 << NUM_CHILDREN) - 1
    };
    let mut done_bits: u64 = 0;
    while done_bits != all_done
    {
        done_bits |= notification_wait(done).unwrap_or(0);
    }

    // Root must still be valid; every revoked descendant (ballast included)
    // must not be.
    notification_send(root, 0x1).map_err(|_| "cap_revoke_under_use: root invalid after revoke")?;
    notification_wait(root).ok();
    if notification_send(ballast_probe, 0x1).is_ok()
    {
        return Err("cap_revoke_under_use: ballast cap survived revoke");
    }

    // Clean up.
    for i in 0..NUM_CHILDREN
    {
        cap_delete(threads[i]).ok();
        cap_delete(cspaces[i]).ok();
    }
    cap_delete(root).map_err(|_| "cap_revoke_under_use: root delete failed (marker leak?)")?;
    cap_delete(done).ok();
    Ok(())
}

fn sender_loop_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `run` published for this sender.
    let SenderArgs {
        sig: sig_slot,
        done: done_slot,
        bit_index,
    } = unsafe { spawn::child_args(arg) };
    let done_bit = 1u64 << bit_index;

    // Send in a tight loop until the cap is revoked.
    loop
    {
        if notification_send(sig_slot, 0x1).is_err()
        {
            break;
        }
    }

    notification_send(done_slot, done_bit).ok();
    thread_exit()
}
