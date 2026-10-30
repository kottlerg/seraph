// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/src/init_reap.rs

//! Init reap-handoff: receives init's own kernel-object caps and
//! reclaimable Memory caps in the post-Phase-3 exit IPCs, binds death-EQ
//! observers on both init threads (main + init-logd), and once both have
//! exited — init threadless — tears down init's `AddressSpace`/`Thread`
//! objects and donates the Memory caps to memmgr. Tearing down init's
//! `CSpace` is design intent, not yet implemented: it is the kernel-pinned
//! root `CSpace`, so the caps init still holds stay in it, alive but
//! unreachable (`docs/process-lifecycle.md` § Init reap, #540). init-logd
//! outlives the main thread until the svcmgr-launched real-logd pulls its
//! handover, so the reap waits for the later of the two deaths; reclaiming
//! init's aspace/cspace while a thread still runs in them would fault it.
//!
//! The handoff's state machine (`process_table::InitReap`, host-tested
//! there) accepts the rounds and `INIT_TEARDOWN_DONE` only from an un-badged
//! cap (init's, or svcmgr's mint source; see
//! `services/procmgr/docs/ipc-interface.md` § `REGISTER_INIT_TEARDOWN`),
//! counts the two init-thread deaths, and reaps on the last one, whether or
//! not `INIT_TEARDOWN_DONE` armed it (a threadless init can send nothing
//! more). The handoff is one-shot: after the reap every request is refused.
//! This module performs the syscalls and IPC around it, serialised under
//! procmgr's single-threaded `service_ep` recv loop.
//!
//! The reap is purely death-driven, and a handover that never completes
//! leaves init's caps held, a benign hold
//! (`services/procmgr/docs/ipc-interface.md` § `INIT_TEARDOWN_DONE`);
//! `do_reap` tears init's objects down in the order
//! `docs/process-lifecycle.md` § Init reap specifies.

// Procmgr runs single-threaded under its lone `service_ep` recv loop;
// the `Mutex` here is only the `Sync` shell required for a `static`.
// `expect` on `.lock()` therefore cannot fire in practice (no contention
// → no poisoning), and a Vec inside the state avoids any unsafe statics.
#![allow(clippy::expect_used)]

use std::sync::Mutex;

use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors, procmgr_labels};
use process_table::{CapDisposition, DeathOutcome, InitReap, Refusal};
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
}

/// The handoff: `Empty` until init's first `REGISTER_INIT_TEARDOWN`,
/// `Collecting` while rounds arrive and the two init-thread deaths are
/// counted, and `Reaped` (terminal) once `run_reap` has torn init down.
static STATE: Mutex<InitReap<InitReapState>> = Mutex::new(InitReap::Empty);

/// Reply to a refused handoff request and dispose of the caps it moved into
/// procmgr's `CSpace` as `refusal` says.
///
/// A badged sender is not init: its caps are deleted and it gets
/// `UNAUTHORIZED`. An un-badged sender gets `INVALID_ARGUMENT`, and its caps
/// stay in procmgr's `CSpace` while they may still be init's live ones:
///   * an `AddressSpace` cap would trip `dealloc_object`'s
///     `active_cpu_mask == 0` assert — init's threads still run on it while
///     this IPC is in flight;
///   * a Memory cap would buddy-free pages that init's live address space
///     still maps, the aliasing window the reap ordering exists to prevent.
///
/// Init observes the error reply and aborts its handoff, so those caps are a
/// one-shot leak on a failure-only path. After the reap no init mapping is
/// left, and the caps are deleted.
fn refuse(refusal: Refusal, caps: &[u32], ipc_buf: *mut u64)
{
    let (code, disposition) = match refusal
    {
        Refusal::Unauthorized => (procmgr_errors::UNAUTHORIZED, CapDisposition::Release),
        Refusal::Invalid(disposition) => (procmgr_errors::INVALID_ARGUMENT, disposition),
    };
    match disposition
    {
        CapDisposition::Release => crate::release_caps(caps),
        CapDisposition::Keep =>
        {
            std::os::seraph::log!(
                "init-reap: refusing a round; {} caps left in procmgr",
                caps.len()
            );
        }
    }
    reply(ipc_buf, code);
}

/// Handle a `REGISTER_INIT_TEARDOWN` IPC.
///
/// `data[0] != 0` marks the first round (carrying the 4 kernel-object
/// caps); subsequent rounds carry only reclaimable Memory caps. Only an
/// un-badged cap (`req.badge == 0`: init's, or svcmgr's mint source) is
/// accepted, and only before the reap.
/// On the first round, binds death-EQ observers on both init threads (main +
/// init-logd) with `INIT_REAP_CORRELATOR`.
pub fn handle_register(req: &IpcMessage, ipc_buf: *mut u64, death_eq: u32)
{
    let caps = req.caps();
    let is_first = req.word(0) != 0;
    let mut guard = STATE.lock().expect("init-reap state poisoned");

    if !is_first
    {
        match guard.donation(req.badge)
        {
            Ok(state) =>
            {
                state.donate_caps.extend_from_slice(caps);
                reply(ipc_buf, procmgr_errors::SUCCESS);
            }
            Err(refusal) => refuse(refusal, caps, ipc_buf),
        }
        return;
    }

    if let Err(refusal) = guard.check_first_round(req.badge, caps.len())
    {
        refuse(refusal, caps, ipc_buf);
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
        std::os::seraph::log!("init-reap: thread_bind_notification failed; refusing handoff");
        refuse(Refusal::Invalid(CapDisposition::Keep), caps, ipc_buf);
        return;
    }
    guard.open(InitReapState {
        aspace,
        cspace,
        main_thread,
        logd_thread,
        donate_caps: Vec::with_capacity(32),
    });
    reply(ipc_buf, procmgr_errors::SUCCESS);
}

/// Handle `INIT_TEARDOWN_DONE`: mark the handoff armed. Only an un-badged
/// cap (init's, or svcmgr's mint source) is accepted, once, while the
/// handoff is open. The message names no caps, so procmgr deletes any it
/// moved, accepted or refused.
pub fn handle_done(req: &IpcMessage, ipc_buf: *mut u64)
{
    let mut guard = STATE.lock().expect("init-reap state poisoned");
    match guard.done(req.badge)
    {
        Ok(()) =>
        {
            crate::release_caps(req.caps());
            reply(ipc_buf, procmgr_errors::SUCCESS);
        }
        Err(refusal) => refuse(refusal, req.caps(), ipc_buf),
    }
}

/// Count one init-thread death (a death-EQ event tagged with
/// `INIT_REAP_CORRELATOR`) and execute the reap on the last one, once init is
/// threadless, whether or not `INIT_TEARDOWN_DONE` armed the handoff: a
/// threadless init can send no further round. A death with no open handoff
/// (none opened, or the reap already ran) is a no-op.
pub fn run_reap(memmgr_ep: u32, ipc_buf: *mut u64)
{
    let outcome = STATE.lock().expect("init-reap state poisoned").death();
    match outcome
    {
        DeathOutcome::Ignored =>
        {}
        DeathOutcome::Pending(remaining) =>
        {
            std::os::seraph::log!(
                "init-reap: an init thread exited; {} still running",
                remaining
            );
        }
        DeathOutcome::Reap(state) => do_reap(state, memmgr_ep, ipc_buf),
    }
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
    //    (the last one: init's CSpace moved its copy over via IPC, and
    //    on riscv64 init-logd deleted the UART Mmio cap whose mapping
    //    record also referenced the space as it exited).
    //    `dealloc_object` for AddressSpace returns its pool donations
    //    via `retype_free`; user-page mappings disappear at the same
    //    moment.
    let _ = syscall::cap_revoke_all(aspace);
    let _ = syscall::cap_delete(aspace);

    // 4. Donate every reclaim Memory cap to memmgr. Safe now that
    //    init's AS is dead: no live mapping references the phys
    //    ranges, so memmgr can reissue them without aliasing, and the
    //    kernel, which refuses to retype a mapped page, lets their
    //    holders retype them.
    let (donated_caps, donated_pages, pool_total) =
        donate_to_memmgr(memmgr_ep, &donate_caps, ipc_buf);

    // 5. Revoke and delete procmgr's cap on init's CSpace last. init's
    //    CSpace is the kernel-pinned root CSpace, so this drops only
    //    procmgr's reference: the caps init still holds (described in
    //    `docs/process-lifecycle.md` § Init reap) stay in it, alive but
    //    unreachable. Releasing them at the reap is design intent,
    //    not yet implemented (`docs/process-lifecycle.md` § Init reap,
    //    #540).
    let _ = syscall::cap_revoke_all(cspace);
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
