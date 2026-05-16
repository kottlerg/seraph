// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Init reap-handoff: receives init's own kernel-object caps and
//! reclaimable Frame caps in the post-Phase-3 exit IPCs, binds a
//! death-EQ observer on init's main thread, and on the resulting
//! death event tears down init's `AddressSpace`/`CSpace`/`Thread`
//! objects and donates the Frame caps to memmgr.
//!
//! State machine (single-threaded; serialised under procmgr's
//! `service_ep` recv loop):
//!
//! ```text
//! Empty
//!   │  REGISTER_INIT_TEARDOWN  (first round; data[0] != 0)
//!   ▼
//! Collecting{aspace, cspace, main_thread, logd_thread, caps[..]}
//!   │  REGISTER_INIT_TEARDOWN  (subsequent rounds; data[0] == 0)
//!   ▼ (appends Frame caps to caps[..])
//! Collecting
//!   │  INIT_TEARDOWN_DONE
//!   ▼
//! Armed   (waiting for death-EQ event with INIT_REAP_CORRELATOR)
//!   │
//!   ▼  dispatch_death sees correlator == INIT_REAP_CORRELATOR
//! Reaping (run_reap):
//!   1. cap_delete(logd_thread)
//!   2. cap_delete(main_thread)
//!   3. cap_revoke + cap_delete(aspace)        — mappings gone
//!   4. DONATE_FRAMES(caps[..]) → memmgr       — safe; no aliasing
//!   5. cap_revoke + cap_delete(cspace)        — cascade clears
//!                                                undonated caps to
//!                                                kernel buddy
//!   6. log summary
//! ```

// Procmgr runs single-threaded under its lone `service_ep` recv loop;
// the `Mutex` here is only the `Sync` shell required for a `static`.
// `expect` on `.lock()` therefore cannot fire in practice (no contention
// → no poisoning), and a Vec inside `Option` avoids any unsafe statics.
#![allow(clippy::expect_used)]

use std::sync::Mutex;

use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors, procmgr_labels};
use syscall_abi::MSG_CAP_SLOTS_MAX;

/// Init's kernel-object and reclaim-Frame caps, accumulated across
/// `REGISTER_INIT_TEARDOWN` rounds and consumed by `run_reap`.
///
/// `aspace`/`cspace`/`main_thread`/`logd_thread` are the procmgr-side
/// slots holding the moved-in caps; `donate_caps` is the list of
/// reclaimable Frame caps (segments + stack + `InitInfo` + IPC buffer +
/// any other init-owned Frame the reap-handoff covers).
pub struct InitReapState
{
    aspace: u32,
    cspace: u32,
    main_thread: u32,
    logd_thread: u32,
    donate_caps: Vec<u32>,
    armed: bool,
}

/// State machine slot. `None` until init's first
/// `REGISTER_INIT_TEARDOWN`; populated and progressively filled by
/// later rounds; transitions to `armed = true` on `INIT_TEARDOWN_DONE`.
/// Cleared back to `None` after `run_reap` completes.
static STATE: Mutex<Option<InitReapState>> = Mutex::new(None);

/// Handle a `REGISTER_INIT_TEARDOWN` IPC.
///
/// `data[0] != 0` marks the first round (carrying the 4 kernel-object
/// caps); subsequent rounds carry only reclaimable Frame caps. On the
/// first round, binds the death-EQ observer on init's main thread with
/// `INIT_REAP_CORRELATOR`.
pub fn handle_register(req: &IpcMessage, ipc_buf: *mut u64, death_eq: u32)
{
    let caps = req.caps();
    let is_first = req.word(0) != 0;
    let mut guard = STATE.lock().expect("init-reap state poisoned");

    // Shared invariant for the error arms below: caps the kernel just
    // moved into procmgr's CSpace cannot be `cap_delete`d here.
    //   * AddressSpace caps would trip `dealloc_object`'s
    //     `active_cpu_mask == 0` assert — init's threads are still
    //     running on that AS while this IPC is in flight.
    //   * Frame caps (donation rounds) would buddy-free pages that
    //     init's still-live AS has mapped, recreating the very
    //     aliasing window the reap ordering exists to prevent.
    // Init is the sole legitimate caller, all reject arms are
    // unreachable in well-formed traffic, and on the reject path init
    // observes the error reply and aborts. The orphaned caps are a
    // one-shot leak on a failure-only path.

    if is_first
    {
        if guard.is_some()
        {
            std::os::seraph::log!(
                "init-reap: duplicate first round; refusing (caps leaked in procmgr)"
            );
            reply(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
            return;
        }
        if caps.len() != 4
        {
            std::os::seraph::log!(
                "init-reap: first round expected 4 caps, got {}; refusing (caps leaked in procmgr)",
                caps.len(),
            );
            reply(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
            return;
        }
        let aspace = caps[0];
        let cspace = caps[1];
        let main_thread = caps[2];
        let logd_thread = caps[3];
        if syscall::thread_bind_notification(
            main_thread,
            death_eq,
            procmgr_labels::INIT_REAP_CORRELATOR,
        )
        .is_err()
        {
            std::os::seraph::log!(
                "init-reap: thread_bind_notification failed; refusing handoff (caps leaked in procmgr)"
            );
            reply(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
            return;
        }
        *guard = Some(InitReapState {
            aspace,
            cspace,
            main_thread,
            logd_thread,
            donate_caps: Vec::with_capacity(32),
            armed: false,
        });
        reply(ipc_buf, procmgr_errors::SUCCESS);
        return;
    }

    let Some(state) = guard.as_mut()
    else
    {
        std::os::seraph::log!(
            "init-reap: donation round without prior first round; refusing ({} caps leaked in procmgr)",
            caps.len(),
        );
        reply(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    };
    for &slot in caps
    {
        state.donate_caps.push(slot);
    }
    reply(ipc_buf, procmgr_errors::SUCCESS);
}

/// Handle `INIT_TEARDOWN_DONE`. Marks the state machine armed; the
/// next death-EQ event with `INIT_REAP_CORRELATOR` triggers `run_reap`.
///
/// Rejects when state is `None` (no preceding first round) or when
/// already armed (re-arm is meaningless and signals a malformed
/// caller).
pub fn handle_done(ipc_buf: *mut u64)
{
    let mut guard = STATE.lock().expect("init-reap state poisoned");
    let Some(state) = guard.as_mut()
    else
    {
        std::os::seraph::log!("init-reap: DONE without prior first round; refusing");
        reply(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    };
    if state.armed
    {
        std::os::seraph::log!("init-reap: DONE called while already armed; refusing");
        reply(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    }
    state.armed = true;
    reply(ipc_buf, procmgr_errors::SUCCESS);
}

/// Execute the reap when the death-EQ event for init's main thread
/// fires. Idempotent: a state-less invocation (re-fire after we
/// already reaped) is a no-op.
pub fn run_reap(memmgr_ep: u32, ipc_buf: *mut u64)
{
    let state = {
        let mut guard = STATE.lock().expect("init-reap state poisoned");
        match guard.take()
        {
            Some(s) if s.armed => s,
            other =>
            {
                *guard = other;
                return;
            }
        }
    };

    // 1. Reap init-logd's TCB. Init-logd exited earlier (its
    //    `sys_thread_exit` ran inside the `HANDOVER_PULL` reply path).
    //    `dealloc_object` for Thread handles Exited TCBs cleanly.
    let _ = syscall::cap_delete(state.logd_thread);

    // 2. Reap init's main thread TCB. The death event we're handling
    //    proves the main thread already transitioned to Exited; the
    //    cap_delete drives the dealloc.
    let _ = syscall::cap_delete(state.main_thread);

    // 3. Destroy init's AddressSpace. Revoke first to clear any
    //    derived child caps, then delete to drop procmgr's reference
    //    (which is the last one, since init's CSpace moved its copy
    //    over via IPC). `dealloc_object` for AddressSpace returns PT
    //    chunks via `retype_free`; user-page mappings disappear at
    //    the same moment.
    let _ = syscall::cap_revoke(state.aspace);
    let _ = syscall::cap_delete(state.aspace);

    // 4. Donate every reclaim Frame cap to memmgr. Safe now that
    //    init's AS is dead: no live mapping references the phys
    //    ranges, so memmgr can reissue them without aliasing.
    let (donated_caps, donated_pages, pool_total) =
        donate_to_memmgr(memmgr_ep, &state.donate_caps, ipc_buf);

    // 5. Destroy init's CSpace last. The cascade in `dealloc_object`
    //    deref's every cap init still held (endpoint SENDs, endpoint
    //    slab Frame, leftover memory frames not donated above). Pages
    //    backed by `owns_memory=true` Frame caps return to the kernel
    //    buddy via `free_range` — they don't enter memmgr's pool, but
    //    they are no longer leaked.
    let _ = syscall::cap_revoke(state.cspace);
    let _ = syscall::cap_delete(state.cspace);

    // 6. Summary line so the operator can confirm the reap actually ran.
    std::os::seraph::log!(
        "init reaped: donated {} caps = {} pages ({} KiB) to memmgr; \
         pool reclaim total {} pages",
        donated_caps,
        donated_pages,
        donated_pages * 4,
        pool_total,
    );
}

fn donate_to_memmgr(memmgr_ep: u32, caps: &[u32], ipc_buf: *mut u64) -> (u32, u64, u64)
{
    if memmgr_ep == 0 || caps.is_empty()
    {
        return (0, 0, 0);
    }
    let mut total_caps: u32 = 0;
    let mut total_pages: u64 = 0;
    let mut pool_total: u64 = 0;
    let chunk_size = MSG_CAP_SLOTS_MAX;
    let mut i = 0;
    while i < caps.len()
    {
        let end = (i + chunk_size).min(caps.len());
        let mut builder = IpcMessage::builder(memmgr_labels::DONATE_FRAMES);
        for &slot in &caps[i..end]
        {
            builder = builder.cap(slot);
        }
        let msg = builder.build();
        // SAFETY: ipc_buf is procmgr's registered IPC buffer.
        if let Ok(reply) = unsafe { ipc::ipc_call(memmgr_ep, &msg, ipc_buf) }
            && reply.label == memmgr_errors::SUCCESS
        {
            total_caps += reply.word(0) as u32;
            total_pages = total_pages.saturating_add(reply.word(1));
            pool_total = reply.word(2);
        }
        i = end;
    }
    (total_caps, total_pages, pool_total)
}

fn reply(ipc_buf: *mut u64, code: u64)
{
    let msg = IpcMessage::new(code);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&msg, ipc_buf) };
}
