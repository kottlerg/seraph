// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Init reap-handoff: receives init's own kernel-object caps and
//! reclaimable Memory caps in the post-Phase-3 exit IPCs, binds death-EQ
//! observers on both init threads (main + init-logd), and once both have
//! exited — init threadless — tears down init's
//! `AddressSpace`/`CSpace`/`Thread` objects and donates the Memory caps to
//! memmgr. init-logd outlives the main thread until the svcmgr-launched
//! real-logd pulls its handover, so the reap waits for the later of the two
//! deaths; reclaiming init's aspace/cspace while a thread still runs in them
//! would fault it.
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
//!   ▼ (appends Memory caps to caps[..])
//! Collecting
//!   │  INIT_TEARDOWN_DONE
//!   ▼
//! Armed   (pending_deaths = 2; waiting for both threads' INIT_REAP_CORRELATOR
//!          death events — run_reap counts down, reaping on the last.)
//!   │
//!   └─▼  dispatch_death sees correlator == INIT_REAP_CORRELATOR (×2)
//!      Reaping (run_reap, last death) → do_reap
//!
//! init-logd outlives init's main thread until svcmgr-launched real-logd pulls
//! its handover and releases it (`HANDOVER_RELEASE` → init-logd `thread_exit`).
//! The reap is purely death-driven: procmgr waits for init-logd's natural exit
//! and never force-stops it. If a handover genuinely never completes (real-logd
//! crashes mid-pull or never launches), init-logd serves on and init's memory
//! caps stay held — a benign hold, not a wedge — until shutdown.
//!
//! do_reap:
//!   1. cap_delete(logd_thread)                — Exited
//!   2. cap_delete(main_thread)
//!   3. cap_revoke + cap_delete(aspace)        — mappings gone
//!   4. DONATE_MEMORY_CAPS(caps[..]) → memmgr       — safe; no aliasing
//!   5. cap_revoke + cap_delete(cspace)        — cascade drops
//!                                                init's last caps;
//!                                                none free to the
//!                                                sealed buddy
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

/// Init's kernel-object and reclaim-Memory caps, accumulated across
/// `REGISTER_INIT_TEARDOWN` rounds and consumed by `run_reap`.
///
/// `aspace`/`cspace`/`main_thread`/`logd_thread` are the procmgr-side
/// slots holding the moved-in caps; `donate_caps` is the list of
/// reclaimable Memory caps (ELF segments, user stack pages, `InitInfo`
/// pages, bootloader/bundle reclaim ranges, the AP-trampoline memory cap,
/// and boot-module ELF sources).
pub struct InitReapState
{
    aspace: u32,
    cspace: u32,
    main_thread: u32,
    logd_thread: u32,
    donate_caps: Vec<u32>,
    armed: bool,
    /// Init threads still expected to exit before the reap runs. A process is
    /// reapable only when threadless, so the teardown waits for both init
    /// threads (main + init-logd) — `run_reap` decrements this per death event
    /// and reaps on the last. init-logd outlives the main thread until the
    /// svcmgr-launched real-logd pulls its handover and releases it.
    pending_deaths: u8,
}

/// State machine slot. `None` until init's first
/// `REGISTER_INIT_TEARDOWN`; populated and progressively filled by
/// later rounds; transitions to `armed = true` on `INIT_TEARDOWN_DONE`.
/// Cleared back to `None` after `run_reap` completes.
static STATE: Mutex<Option<InitReapState>> = Mutex::new(None);

/// Handle a `REGISTER_INIT_TEARDOWN` IPC.
///
/// `data[0] != 0` marks the first round (carrying the 4 kernel-object
/// caps); subsequent rounds carry only reclaimable Memory caps. On the
/// first round, binds death-EQ observers on both init threads (main +
/// init-logd) with `INIT_REAP_CORRELATOR` and arms `pending_deaths = 2`.
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
    //   * Memory caps (donation rounds) would buddy-free pages that
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
        // Bind a death-EQ observer on both init threads under the same
        // correlator. Both are alive at this point (init's main is mid-handoff;
        // init-logd is still serving the log endpoint), so neither bind lands
        // on an already-exited thread. The reap waits for both.
        if syscall::thread_bind_notification(
            main_thread,
            death_eq,
            procmgr_labels::INIT_REAP_CORRELATOR,
        )
        .is_err()
            || syscall::thread_bind_notification(
                logd_thread,
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
            pending_deaths: 2,
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

/// Execute the reap once both init threads have exited (init is
/// threadless). Called on each death-EQ event tagged with
/// `INIT_REAP_CORRELATOR`; it decrements the expected-death count and runs
/// the teardown only on the last. Idempotent: a state-less invocation
/// (re-fire after we already reaped, or before arming) is a no-op.
pub fn run_reap(memmgr_ep: u32, ipc_buf: *mut u64)
{
    let state = {
        let mut guard = STATE.lock().expect("init-reap state poisoned");
        let Some(s) = guard.as_mut()
        else
        {
            return;
        };
        // Count the death as soon as it is observed, even before
        // `INIT_TEARDOWN_DONE` arms the reap. The death-EQ observers are bound
        // (first round) before the svcmgr handover can release init-logd, so
        // init-logd's exit may fire while init is still streaming donation
        // rounds — i.e. pre-arm. Dropping a pre-arm death would strand
        // `pending_deaths` and the reap would never fire. Only the *execution*
        // of the reap waits for `armed`: init must finish donating its
        // reclaimable caps, and `do_reap` consumes the kernel-object caps that
        // round delivers.
        s.pending_deaths = s.pending_deaths.saturating_sub(1);
        if s.pending_deaths > 0
        {
            std::os::seraph::log!(
                "init-reap: an init thread exited; {} still running",
                s.pending_deaths
            );
            return;
        }
        if !s.armed
        {
            // Both threads exited before arming. init's main thread sends
            // `INIT_TEARDOWN_DONE` before its own `thread_exit`, so main's death
            // is always post-arm and this branch is unreachable in well-formed
            // teardown; leave the reap for the arming path rather than reaping
            // before init has finished donating.
            return;
        }
        guard.take().expect("init-reap state present")
    };

    do_reap(state, memmgr_ep, ipc_buf);
}

/// Tear init down once it is threadless: both threads `Exited` via the normal
/// handover path (init-logd exits on real-logd's `HANDOVER_RELEASE`). Ordering
/// matters — see the inline steps.
fn do_reap(state: InitReapState, memmgr_ep: u32, ipc_buf: *mut u64)
{
    // Consume the teardown state — this reap is one-shot.
    let InitReapState {
        aspace,
        cspace,
        main_thread,
        logd_thread,
        donate_caps,
        ..
    } = state;

    // 1. Reap init-logd's TCB. It is `Exited` (it released on real-logd's
    //    `HANDOVER_RELEASE` and exited); `dealloc_object` removes it from
    //    scheduler queues and frees the slot.
    let _ = syscall::cap_delete(logd_thread);

    // 2. Reap init's main thread TCB; it exited earlier in the countdown, so
    //    the cap_delete just drives the dealloc.
    let _ = syscall::cap_delete(main_thread);

    // 3. Destroy init's AddressSpace. Revoke first to clear any
    //    derived child caps, then delete to drop procmgr's reference
    //    (which is the last one, since init's CSpace moved its copy
    //    over via IPC). `dealloc_object` for AddressSpace returns PT
    //    chunks via `retype_free`; user-page mappings disappear at
    //    the same moment.
    let _ = syscall::cap_revoke(aspace);
    let _ = syscall::cap_delete(aspace);

    // 4. Donate every reclaim Memory cap to memmgr. Safe now that
    //    init's AS is dead: no live mapping references the phys
    //    ranges, so memmgr can reissue them without aliasing.
    let (donated_caps, donated_pages, pool_total) =
        donate_to_memmgr(memmgr_ep, &donate_caps, ipc_buf);

    // 5. Destroy init's CSpace last. The cascade in `dealloc_object`
    //    drops every cap init still held — endpoint SENDs and the
    //    endpoint-slab arena Memory cap. That arena is retype-pinned and
    //    already forwarded to memmgr's pool, and every reclaimable
    //    Memory cap was donated in step 4, so no `owns_memory` cap reaches
    //    its last reference here: nothing frees to the sealed buddy.
    let _ = syscall::cap_revoke(cspace);
    let _ = syscall::cap_delete(cspace);

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
        let mut builder = IpcMessage::builder(memmgr_labels::DONATE_MEMORY_CAPS);
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
