// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/src/main.rs

//! Seraph process manager — IPC server for process lifecycle management.
//!
//! Receives requests via IPC to create, configure, and start new processes.
//! Supports both in-memory ELF loading from boot module memory caps and streaming
//! from the VFS. See `services/procmgr/docs/ipc-interface.md`.
//!
//! `CREATE_PROCESS` and `CREATE_FROM_FILE` accept the child's module source and
//! the caller's bootstrap endpoint (a badged send cap); the endpoint is
//! installed in the child `CSpace` and recorded in `ProcessInfo` as the
//! `creator_endpoint_cap`. The child requests its initial cap set from the
//! caller over IPC at startup. procmgr itself has no knowledge of the child's
//! service-specific capabilities.

// cast_possible_truncation: targets 64-bit only; u64/usize conversions lossless.
#![allow(clippy::cast_possible_truncation)]

mod arch;
mod init_reap;
mod loader;
mod process;

use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors, procmgr_labels};
// Brings `configure_pipe` / `configure_namespace` into method-call scope; their
// pipe/namespace logic moved onto an extension trait when `ProcessTable` was
// extracted into the `procmgr-process-table` crate.
use process::TableExt;
use std::os::seraph::startup_info;

/// Init → procmgr bootstrap plan (one round on procmgr's creator endpoint):
///   caps[0]: service endpoint (procmgr receives requests on this)
///   caps[1]: un-badged SEND copy of the system log endpoint. Procmgr
///            `cap_copy`s this into every child's
///            `ProcessInfo.log_send_cap` at `CREATE_PROCESS` time.
///            Zero means no log endpoint is available yet; children
///            born in that window receive zero and silent-drop
///            `std::os::seraph::log!`.
///   caps[2]: un-badged SEND copy of svcmgr's service endpoint (the
///            global service registry). Procmgr derives a badged SEND
///            per child for `ProcessInfo.service_registry_cap`; the
///            child can `QUERY_ENDPOINT` but not `PUBLISH_ENDPOINT`.
///            Zero means no registry is available yet.
#[allow(clippy::struct_field_names)]
struct InitBootstrap
{
    service_ep: u32,
    log_ep: u32,
    registry_ep: u32,
}

fn bootstrap_from_init(creator_ep: u32, ipc_buf: *mut u64) -> Option<InitBootstrap>
{
    if creator_ep == 0
    {
        return None;
    }
    // SAFETY: caller passes the registered IPC buffer page.
    let round = unsafe { ipc::bootstrap::request_round(creator_ep, ipc_buf) }.ok()?;
    if round.cap_count < 1 || !round.done
    {
        return None;
    }
    Some(InitBootstrap {
        service_ep: round.caps[0],
        log_ep: if round.cap_count >= 2
        {
            round.caps[1]
        }
        else
        {
            0
        },
        registry_ep: if round.cap_count >= 3
        {
            round.caps[2]
        }
        else
        {
            0
        },
    })
}

fn main() -> !
{
    std::os::seraph::log::register_name(b"procmgr");
    let startup = startup_info();

    // IPC buffer is registered by `_start`; reinterpret as `*mut u64`.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = startup.ipc_buffer.cast::<u64>();

    let self_aspace = startup.self_aspace;

    // Bootstrap service endpoint + log endpoint from init.
    let Some(boot) = bootstrap_from_init(startup.creator_endpoint, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    let mut table = process::ProcessTable::new();
    let mut recent = process::RecentExits::new();

    // Death-EQ slab request: the kernel's raw EventQueue debit for the
    // capacity. Capacity is `MAX_PROCESSES * 2` to absorb a simultaneous-crash
    // burst without dropping notifications between drain calls.
    let death_eq_slab_bytes =
        std::os::seraph::event_queue_retype_bytes(process::MAX_PROCESSES as u64 * 2);
    let Some(death_eq) = std::os::seraph::object_slab_retype(death_eq_slab_bytes, |slab| {
        syscall::event_queue_create(slab, (process::MAX_PROCESSES as u32) * 2).ok()
    })
    else
    {
        syscall::thread_exit();
    };
    let Some(ws_cap) =
        std::os::seraph::object_slab_retype(std::os::seraph::WAIT_SET_RETYPE_BYTES, |slab| {
            syscall::wait_set_create(slab).ok()
        })
    else
    {
        syscall::thread_exit();
    };
    if syscall::wait_set_add(ws_cap, boot.service_ep, WS_BADGE_SERVICE).is_err()
    {
        syscall::thread_exit();
    }
    if syscall::wait_set_add(ws_cap, death_eq, WS_BADGE_DEATH).is_err()
    {
        syscall::thread_exit();
    }

    let mut ctx = ProcmgrCtx {
        self_aspace,
        self_endpoint: boot.service_ep,
        log_ep: boot.log_ep,
        registry_ep: boot.registry_ep,
        memmgr_ep: startup.memmgr_endpoint,
        death_eq,
        ws_cap,
        sched_baseline: startup.sched_control_cap,
    };
    let service_ep = boot.service_ep;

    // One guard covers both spin shapes: a failing wait_set_wait, and a
    // level-triggered wait set that keeps reporting ready while the recv in
    // dispatch_ipc keeps failing. Only a successful recv counts as progress.
    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    let mut headroom_warned = false;
    loop
    {
        hold_cspace_headroom(startup.self_cspace, &mut headroom_warned);
        let badge = match syscall::wait_set_wait(ws_cap)
        {
            Ok(badge) => badge,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };

        // Drain any pending deaths before servicing a SERVICE request.
        // SERVICE handlers may allocate from memmgr; without this, a child
        // can die in the same wakeup batch as the parent's spawn-causing
        // IPC, and the SERVICE branch wins the wait_set_wait dispatch
        // ordering — leaving the dead child's memory caps pinned in memmgr's
        // per-process record until the next loop iteration. Under fast
        // spawn-after-wait churn that races allocations against pool
        // reclaim. dispatch_death is a no-op when the EQ is empty.
        dispatch_death(
            ctx.death_eq,
            ctx.memmgr_ep,
            ipc_buf,
            &mut table,
            &mut recent,
        );

        match badge
        {
            WS_BADGE_SERVICE =>
            {
                dispatch_ipc(
                    service_ep, ipc_buf, &mut ctx, &mut table, &recent, &mut guard,
                );
            }
            WS_BADGE_DEATH =>
            {
                // Already drained above; nothing to do.
            }
            _ => (),
        }
    }
}

/// `WaitSet` badge for procmgr's service endpoint.
const WS_BADGE_SERVICE: u64 = 0;
/// `WaitSet` badge for procmgr's shared death event queue.
const WS_BADGE_DEATH: u64 = 1;

/// Pages requested from memmgr per spawned child for the child's Thread
/// retype slab: `KERNEL_STACK_PAGES + 2 = 6` pages (4 kstack, 1
/// wrapper/TCB, 1 extended-state save area), all consumed by the kernel.
pub(crate) const THREAD_RETYPE_PAGES: u64 = 6;

/// Pages requested from memmgr for the child's `AddressSpace` retype slab.
/// Every page reaches the kernel: page 0 holds the wrapper, page 1 the
/// root PT, and the remaining 46 form the initial PT growth pool.
///
/// Sized to cover the typical small-process mapping pattern: 3-6 LOAD
/// segments + stack + IPC buffer + TLS + `ProcessInfo` memory cap. Each
/// distinct user VA region whose PT entry isn't already populated
/// consumes up to 3 intermediate PT pages (PDPT/PD/PT on x86-64), and
/// ASLR (#39) spreads the four bootstrap surfaces across distinct 64 GiB
/// window strides — one shared PDPT plus up to 3 pages per surface (~13
/// pooled pages) where the pre-ASLR clustered layout shared one
/// PDPT/PD/PT triple. Larger processes refill via augment-mode
/// `cap_create_aspace`.
pub(crate) const ASPACE_RETYPE_PAGES: u64 = 48;

/// Pages requested from memmgr for the child's `CSpace` retype slab.
/// Each slot page holds `L2_SIZE` capability slots (currently 56 slots
/// × 72 B = 4032 B/page); the kernel reserves the slab's page 0 as the
/// wrapper page.
///
/// Seeded for the expected startup population of a spawned child
/// (bootstrap caps plus working headroom); a child that outgrows the
/// pool sees the refillable `OutOfMemory` and self-funds via
/// augment-mode `cap_create_cspace`. All 7 pages reach the kernel: page
/// 0 is the wrapper, the 6 slot pages give 6 × 56 − 1 = 335 usable slots.
pub(crate) const CSPACE_RETYPE_PAGES: u64 = 7;

/// Register a new child with memmgr. On success returns
/// `(memmgr_send_cap_slot, memmgr_badge)`. On any failure (memmgr
/// unwired, IPC error, OOM) returns `(0, 0)`.
///
/// The cap slot lands in procmgr's `CSpace`; procmgr both:
///  * uses it for every per-child memory-cap allocation (so memmgr accounts
///    them to the child's record from the moment they leave the pool); and
///  * copies it into the child's `ProcessInfo.memmgr_endpoint_cap` so the
///    child's std heap-bootstrap can call `REQUEST_MEMORY_CAPS` on it.
///
/// The badge is opaque to procmgr but is sent back in the
/// `PROCESS_DIED` payload at child teardown so memmgr can reclaim the
/// right record.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn register_with_memmgr(memmgr_ep: u32, ipc_buf: *mut u64) -> (u32, u64)
{
    if memmgr_ep == 0
    {
        return (0, 0);
    }
    let msg = IpcMessage::builder(memmgr_labels::REGISTER_PROCESS)
        .word(0, u64::from(ipc::MEMMGR_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(reply) = (unsafe { ipc::ipc_call(memmgr_ep, &msg, ipc_buf) })
    else
    {
        return (0, 0);
    };
    if reply.label != memmgr_errors::SUCCESS
    {
        return (0, 0);
    }
    let cap = reply.caps().first().copied().unwrap_or(0);
    let badge = reply.word(0);
    (cap, badge)
}

/// Allocate exactly one page from memmgr. Returns the cap slot of the
/// (single-page) Memory cap in procmgr's `CSpace`, or zero on any failure
/// (memmgr not wired, OOM, derive failure). Caller is responsible for
/// `mem_map`-ping it where appropriate.
///
/// Memory caps allocated against `child_send_cap` are accounted to that child's
/// memmgr record and reclaimed on `PROCESS_DIED`. Memory caps allocated against
/// procmgr's own `pi.memmgr_endpoint_cap` are accounted to procmgr.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn memmgr_alloc_page(memmgr_send: u32, ipc_buf: *mut u64) -> Option<u32>
{
    if memmgr_send == 0
    {
        std::os::seraph::log!("procmgr: alloc_page: memmgr_send=0");
        return None;
    }
    let msg = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, 1)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = match unsafe { ipc::ipc_call(memmgr_send, &msg, ipc_buf) }
    {
        Ok(r) => r,
        Err(e) =>
        {
            std::os::seraph::log!("procmgr: alloc_page: ipc_call err={}", e);
            return None;
        }
    };
    if reply.label != memmgr_errors::SUCCESS
    {
        std::os::seraph::log!(
            "procmgr: alloc_page: memmgr label={} pool: total={} runs={} max={}",
            reply.label,
            reply.word(0),
            reply.word(1),
            reply.word(2)
        );
        return None;
    }
    if reply.word(0) != 1
    {
        std::os::seraph::log!(
            "procmgr: alloc_page: count={} caps={}",
            reply.word(0),
            reply.caps().len()
        );
        for &slot in reply.caps()
        {
            let _ = syscall::cap_delete(slot);
        }
        return None;
    }
    reply.caps().first().copied()
}

/// Allocate exactly `pages` contiguous pages from `memmgr_send` as a
/// single Memory cap. Returns the cap slot in procmgr's `CSpace`, or
/// `None` on any failure (memmgr unwired, OOM, fragmented reply).
///
/// Used to back kernel-object retypes whose source Memory cap must be
/// contiguous (e.g. `Thread`, `AddressSpace`, `CSpace`). Unlike
/// `memmgr_alloc_page`, this rejects multi-cap replies and any cap
/// whose declared `page_count` does not equal `pages` — retypes
/// require one contiguous span and must not silently accept a smaller
/// cap.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn memmgr_alloc_pages_contig(memmgr_send: u32, pages: u64, ipc_buf: *mut u64) -> Option<u32>
{
    if memmgr_send == 0 || pages == 0
    {
        return None;
    }
    let msg = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, pages)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(memmgr_send, &msg, ipc_buf) }.ok()?;
    if reply.label != memmgr_errors::SUCCESS
    {
        return None;
    }
    let caps = reply.caps();
    if caps.len() != 1
    {
        for &slot in caps
        {
            let _ = syscall::cap_delete(slot);
        }
        return None;
    }
    let cap = caps[0];
    if syscall::cap_info(cap, syscall_abi::CAP_INFO_MEMORY_SIZE)
        .is_ok_and(|size| size == pages * 4096)
    {
        Some(cap)
    }
    else
    {
        let _ = syscall::cap_delete(cap);
        None
    }
}

/// General-allocation headroom of procmgr's `CSpace` below which it tops the
/// pool up. procmgr holds several caps per live child, so a burst of spawns
/// draws slots quickly; the mark leaves room for a full spawn even if the
/// top-up itself fails once.
const CSPACE_LOW_WATER: u64 = 256;

/// Headroom a top-up funds: about 18 slot pages.
const CSPACE_TOPUP_SLOTS: u64 = 1024;

/// Keep procmgr's own `CSpace` above [`CSPACE_LOW_WATER`] general slots, so
/// its allocations never meet an exhausted `CSpace` and its receives keep the
/// IPC receive reserve (services/procmgr/README.md § `CSpace` headroom). A
/// failed top-up is retried on the next loop pass; `warned` limits the log
/// to the first failure of a streak.
fn hold_cspace_headroom(self_cspace: u32, warned: &mut bool)
{
    if std::os::seraph::cspace_slot_headroom(self_cspace) >= CSPACE_LOW_WATER
    {
        *warned = false;
        return;
    }
    if std::os::seraph::fund_cspace_slot_budget(self_cspace, CSPACE_TOPUP_SLOTS)
    {
        *warned = false;
    }
    else if !*warned
    {
        *warned = true;
        std::os::seraph::log!("CSpace headroom top-up failed; retrying each pass");
    }
}

/// `RecvGuard` diagnostic hook: one line at the start of a failure streak,
/// one more before the fatal exit.
fn recv_diag(stage: ipc::recv_guard::RecvFailureStage, err: i64)
{
    match stage
    {
        ipc::recv_guard::RecvFailureStage::First =>
        {
            std::os::seraph::log!("recv loop failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!("recv loop wedged (err={err}); exiting");
        }
    }
}

/// Service-endpoint dispatch. Called when the wait-set wakes for the
/// service endpoint; the sender is already queued so `ipc_recv` returns
/// without blocking.
fn dispatch_ipc(
    service_ep: u32,
    ipc_buf: *mut u64,
    ctx: &mut ProcmgrCtx,
    table: &mut process::ProcessTable,
    recent: &process::RecentExits,
    guard: &mut ipc::recv_guard::RecvGuard,
)
{
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let req = match unsafe { ipc::ipc_recv(service_ep, ipc_buf) }
    {
        Ok(req) => req,
        Err(e) =>
        {
            guard.on_failure(e);
            return;
        }
    };
    guard.on_success();
    let label = req.label;
    let badge = req.badge;

    // Every cap a request transfers has already moved into procmgr's
    // CSpace. Each arm releases the caps its wire layout does not name, and
    // every cap on a reject arm, so a padded or refused request cannot grow
    // procmgr's CSpace (`services/procmgr/docs/ipc-interface.md`
    // § Capability Transfer).
    match label & 0xFFFF
    {
        procmgr_labels::CREATE_PROCESS =>
        {
            handle_create(&req, ipc_buf, ctx, table);
        }

        procmgr_labels::START_PROCESS =>
        {
            release_caps(req.caps());
            // Badge from ipc_recv identifies which process to start.
            let code = match process::start_process(badge, table, ctx.self_aspace)
            {
                Ok(()) => procmgr_errors::SUCCESS,
                Err(code) => code,
            };
            reply_empty(ipc_buf, code);
        }

        procmgr_labels::DESTROY_PROCESS =>
        {
            release_caps(req.caps());
            // Badge from ipc_recv identifies which process to destroy.
            process::destroy_process(badge, ctx.memmgr_ep, ipc_buf, table);
            reply_empty(ipc_buf, procmgr_errors::SUCCESS);
        }

        procmgr_labels::QUERY_PROCESS =>
        {
            release_caps(req.caps());
            // Badge identifies which process to query. Reply data:
            //   word 0 = state code (see `procmgr_process_state`)
            //   word 1 = exit_reason (only meaningful for `EXITED`)
            let (state, exit_reason) = resolve_query_state(badge, table, recent);
            let reply = IpcMessage::builder(procmgr_errors::SUCCESS)
                .word(0, state)
                .word(1, exit_reason)
                .build();
            // SAFETY: ipc_buf is the registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        }

        procmgr_labels::CREATE_FROM_FILE =>
        {
            handle_create_from_file(&req, ipc_buf, ctx, table);
        }

        procmgr_labels::CONFIGURE_PIPE =>
        {
            handle_configure_pipe(&req, ipc_buf, ctx.self_aspace, table);
        }

        procmgr_labels::CONFIGURE_NAMESPACE =>
        {
            handle_configure_namespace(&req, ipc_buf, table);
        }

        procmgr_labels::REGISTER_DEATH_EQ =>
        {
            handle_register_death_eq(&req, ipc_buf, table);
        }

        procmgr_labels::REGISTER_INIT_TEARDOWN =>
        {
            init_reap::handle_register(&req, ipc_buf, ctx.death_eq);
        }

        procmgr_labels::INIT_TEARDOWN_DONE =>
        {
            init_reap::handle_done(&req, ipc_buf);
        }

        procmgr_labels::QUERY_INIT_REAP =>
        {
            init_reap::handle_query(&req, ipc_buf);
        }

        _ =>
        {
            release_caps(req.caps());
            reply_empty(ipc_buf, procmgr_errors::UNKNOWN_OPCODE);
        }
    }
}

/// Delete each nonzero slot in `caps` from procmgr's `CSpace`: the caps a
/// request transferred that its wire layout does not name, or every cap of a
/// refused request.
pub(crate) fn release_caps(caps: &[u32])
{
    for &slot in caps
    {
        if slot != 0
        {
            let _ = syscall::cap_delete(slot);
        }
    }
}

/// Handle `REGISTER_DEATH_EQ` — store the caller's `EventQueue` cap
/// as procmgr's logd-death observer, then retroactively bind it to
/// the main thread of every process currently in the process table.
///
/// Wire format:
/// * `caller badge` MUST equal `procmgr_labels::DEATH_EQ_AUTHORITY`
///   (who holds it is in `services/procmgr/docs/ipc-interface.md`
///   § `REGISTER_DEATH_EQ`).
/// * `caps[0]` = `EventQueue` cap with POST right.
///
/// Reply: `procmgr_errors::SUCCESS` on bind, `UNAUTHORIZED` if the
/// caller lacks the authority badge or a death EQ is already
/// registered, `INVALID_ARGUMENT` if no cap (or a zero cap) arrives.
/// Every refused request has its transferred caps deleted, and so do caps
/// past `caps[0]`.
fn handle_register_death_eq(req: &IpcMessage, ipc_buf: *mut u64, table: &mut process::ProcessTable)
{
    let caps = req.caps();
    if req.badge != procmgr_labels::DEATH_EQ_AUTHORITY
    {
        release_caps(caps);
        reply_empty(ipc_buf, procmgr_errors::UNAUTHORIZED);
        return;
    }
    let Some((&logd_eq, extra)) = caps.split_first()
    else
    {
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    };
    release_caps(extra);
    if logd_eq == 0
    {
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    }
    // install_logd_death_eq is first-wins: it stores the cap and
    // binds it as a second observer on the main thread of every
    // process in the table, or returns false if a previous
    // registration already filled the slot. Future spawns pick it up
    // inside finalize_creation by reading the same atomic.
    if process::install_logd_death_eq(table, logd_eq)
    {
        reply_empty(ipc_buf, procmgr_errors::SUCCESS);
    }
    else
    {
        // Slot already filled (legitimate logd is registered).
        // Drop the just-transferred cap so it doesn't leak in
        // procmgr's CSpace; reject the caller.
        let _ = syscall::cap_delete(logd_eq);
        reply_empty(ipc_buf, procmgr_errors::UNAUTHORIZED);
    }
}

/// Answer `QUERY_PROCESS` for the addressed entry.
///
/// Consults the kernel for the authoritative thread-lifecycle snapshot
/// (`CAP_INFO_THREAD_STATE`) so a freshly-faulted child is reported as
/// EXITED even before procmgr's own death-event drain has reaped the
/// entry. Without this, the userspace death-eq drain races a parent's
/// "wait then `QUERY_PROCESS`" sequence and produces a transient ALIVE
/// answer for an already-dead child.
fn resolve_query_state(
    badge: u64,
    table: &process::ProcessTable,
    recent: &process::RecentExits,
) -> (u64, u64)
{
    use ipc::procmgr_process_state;
    if let Some((started, thread_cap)) = table.query_by_badge(badge)
    {
        // Kernel-authoritative override: if the thread has transitioned to
        // Exited, report EXITED with the kernel-recorded reason regardless
        // of whether `dispatch_death` has reaped the entry yet.
        if let Ok(packed) = syscall::cap_info(thread_cap, syscall_abi::CAP_INFO_THREAD_STATE)
        {
            let state_code = (packed >> 32) as u32;
            let reason = packed & 0xFFFF_FFFF;
            if state_code == syscall_abi::THREAD_STATE_EXITED
            {
                return (procmgr_process_state::EXITED, reason);
            }
        }
        if started
        {
            (procmgr_process_state::ALIVE, 0u64)
        }
        else
        {
            (procmgr_process_state::CREATED, 0u64)
        }
    }
    else if let Some(reason) = recent.find(badge)
    {
        (procmgr_process_state::EXITED, reason)
    }
    else
    {
        (procmgr_process_state::UNKNOWN, 0u64)
    }
}

/// Death-queue dispatch. Drains all pending death events on the shared
/// queue, reaps each by correlator, and records the exit reason in the
/// recent-exits ring for `QUERY_PROCESS`.
fn dispatch_death(
    death_eq: u32,
    memmgr_ep: u32,
    ipc_buf: *mut u64,
    table: &mut process::ProcessTable,
    recent: &mut process::RecentExits,
)
{
    loop
    {
        let Ok(death) = syscall::event_try_recv_death(death_eq)
        else
        {
            return;
        };
        // Every bind passes a 32-bit value widened to u64, so the low word is
        // the whole correlator.
        // cast_possible_truncation: see above; the high word is always zero.
        #[allow(clippy::cast_possible_truncation)]
        let correlator = death.correlator as u32;
        let exit_reason = death.exit_reason;
        if correlator == procmgr_labels::INIT_REAP_CORRELATOR
        {
            // An init thread exited. `run_reap` counts down the two init
            // threads and, on the last exit, tears down init's Thread and
            // AddressSpace objects, donates its reclaimable Memory caps to
            // memmgr's pool, and deletes its CSpace cap, which frees the CSpace
            // and releases the caps init still holds
            // (`docs/process-lifecycle.md` § Init reap).
            init_reap::run_reap(memmgr_ep, ipc_buf);
            continue;
        }
        if let Some(entry) = table.take_by_correlator(correlator)
        {
            let entry_badge = entry.badge();
            recent.record(entry_badge, exit_reason);
            process::teardown_entry(entry, memmgr_ep, ipc_buf);
        }
    }
}

/// Reply with the given label code and no data / no caps.
fn reply_empty(ipc_buf: *mut u64, code: u64)
{
    let msg = IpcMessage::new(code);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&msg, ipc_buf) };
}

/// Handle `CONFIGURE_PIPE` — install one direction's shmem-backed
/// stdio pipe on a suspended child.
///
/// Wire format (see `ipc::procmgr_labels::CONFIGURE_PIPE`):
/// * `data[0]` = direction (`PIPE_DIR_STDIN` / `STDOUT` / `STDERR`)
/// * `data[1]` = ring byte capacity (informational; procmgr does not
///   re-init the header — the spawner already called `SpscHeader::init`)
/// * `caps[0]` = memory cap (one shmem page)
/// * `caps[1]` = data-available notification cap
/// * `caps[2]` = space-available notification cap
fn handle_configure_pipe(
    req: &IpcMessage,
    ipc_buf: *mut u64,
    self_aspace: u32,
    table: &mut process::ProcessTable,
)
{
    let badge = req.badge;
    let direction = req.word(0);
    let caps = req.caps();
    if caps.len() < 3
    {
        release_caps(caps);
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    }
    let memory_cap = caps[0];
    let data_notification = caps[1];
    let space_notification = caps[2];
    release_caps(&caps[3..]);

    let code = match table.configure_pipe(
        badge,
        self_aspace,
        direction,
        memory_cap,
        data_notification,
        space_notification,
    )
    {
        Ok(()) => procmgr_errors::SUCCESS,
        Err(code) => code,
    };

    // On success configure_pipe cap_copy'd each cap into the child's
    // CSpace; on failure it installed none. Either way procmgr's slots are
    // dropped, so refcounts hit zero when both peers later release.
    release_caps(&caps[..3]);

    reply_empty(ipc_buf, code);
}

/// Handle `CONFIGURE_NAMESPACE` — install per-process root and
/// (optional) cwd caps on a suspended child. Caps are consumed by
/// procmgr on both success and failure paths; the wire-side caller
/// MUST NOT reuse the slots after the call.
///
/// Wire format (see `ipc::procmgr_labels::CONFIGURE_NAMESPACE`):
/// * `caps[0]` — root cap to deliver to the child at start (mandatory).
/// * `caps[1]` — cwd cap to deliver to the child at start (optional;
///   absent leaves `current_dir_cap` zero in the child).
///
/// Caps past `caps[1]` are deleted.
fn handle_configure_namespace(
    req: &IpcMessage,
    ipc_buf: *mut u64,
    table: &mut process::ProcessTable,
)
{
    let badge = req.badge;
    let caps = req.caps();
    if caps.is_empty()
    {
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    }
    let root_cap = caps[0];
    let cwd_cap = caps.get(1).copied().unwrap_or(0);
    release_caps(caps.get(2..).unwrap_or(&[]));
    let code = match table.configure_namespace(badge, root_cap, cwd_cap)
    {
        Ok(()) => procmgr_errors::SUCCESS,
        Err(code) => code,
    };
    reply_empty(ipc_buf, code);
}

/// Resolve the scheduling fields of a create label against the caller's
/// spawn ceiling. `None` means the request must be rejected with
/// `INVALID_ARGUMENT`: still-reserved label bits are set, the requested
/// band exceeds the creator's, or the requested priority falls outside the
/// resolved band.
///
/// Creator ceiling: badge `0` is init (the unbadged service-endpoint
/// holder) with the full baseline ceiling. A nonzero badge is a
/// procmgr-spawned process whose ceiling is its own minted band; a badge
/// procmgr never minted (e.g. the `DEATH_EQ_AUTHORITY` verb badge) falls
/// back to a conservative default ceiling.
fn resolve_create_sched(
    label: u64,
    badge: u64,
    table: &process::ProcessTable,
) -> Option<process::ChildSched>
{
    if label & procmgr_labels::CREATE_RESERVED_MASK != 0
    {
        return None;
    }
    let requested_priority = ((label >> procmgr_labels::CREATE_PRIORITY_SHIFT)
        & procmgr_labels::CREATE_SCHED_FIELD_MASK) as u8;
    let requested_band = ((label >> procmgr_labels::CREATE_BAND_MAX_SHIFT)
        & procmgr_labels::CREATE_SCHED_FIELD_MASK) as u8;
    let creator_band_max = if badge == 0
    {
        ipc::sched_policy::BASELINE_PRIORITY_MAX
    }
    else
    {
        table
            .band_max_by_badge(badge)
            .unwrap_or(ipc::sched_policy::DEFAULT_SPAWN_PRIORITY)
    };
    let (priority, band_max) = process::resolve_spawn_sched(
        requested_priority,
        requested_band,
        creator_band_max,
        ipc::sched_policy::DEFAULT_SPAWN_PRIORITY,
    )?;
    Some(process::ChildSched { priority, band_max })
}

/// Reply with a successful process creation result, or destroy the child
/// when the reply cannot deliver it.
///
/// Reply caps: `[process_handle, thread]`. The reply's cap transfer is
/// all-or-nothing: when the caller's `CSpace` cannot take both caps (or the
/// caller is gone), the caller resumes with `IPC_REPLY_TRANSFER_FAILED` and
/// no caps, and both caps stay in procmgr's `CSpace`. No one then holds the
/// handle that could start or destroy the suspended child, so procmgr deletes
/// both caps and tears the child down as `DESTROY_PROCESS` does.
fn reply_create_result(
    result: &process::CreateResult,
    ipc_buf: *mut u64,
    memmgr_ep: u32,
    table: &mut process::ProcessTable,
)
{
    let msg = IpcMessage::builder(procmgr_errors::SUCCESS)
        .cap(result.process_handle)
        .cap(result.thread_for_caller)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if unsafe { ipc::ipc_reply(&msg, ipc_buf) }.is_err()
    {
        std::os::seraph::log!("procmgr: create reply undeliverable; destroying the child");
        let _ = syscall::cap_delete(result.thread_for_caller);
        let _ = syscall::cap_delete(result.process_handle);
        process::destroy_process(result.badge, memmgr_ep, ipc_buf, table);
    }
}

/// Handle `CREATE_PROCESS` — create a process from a boot module memory cap.
///
/// Label layout:
///   bits [0..16]  = opcode (`CREATE_PROCESS`)
///   bit  16       = `CREATE_PINNED` (opt out of the default system pager)
///   bit  17       = `CREATE_DEATH_RELAY` (on `CREATE_FROM_FILE` only)
///   bits [18..23] = `CREATE_PRIORITY` (0 = default; see `resolve_create_sched`)
///   bits [23..28] = `CREATE_BAND_MAX` (0 = copy of the creator's band)
///   bits [28..32] = reserved (must be zero)
///   bits [32..48] = `args_bytes` (total byte length of the argv blob; u16)
///   bits [48..56] = `args_count` (number of NUL-terminated strings; u8)
///   bits [56..64] = `env_count` (number of NUL-terminated `KEY=VALUE`
///                    strings; u8). Zero means "no env"; any value >0
///                    requires an env header word + blob after argv.
///
/// IPC data words:
///   word `0..argv_words`         = argv blob, `args_bytes.div_ceil(8)` words
///   word `argv_words`            = `env_bytes` (low 16 bits; only present
///                                  when `env_count > 0`)
///   word `argv_words+1..`        = env blob, `env_bytes.div_ceil(8)` words
///                                  (only present when `env_count > 0`)
///
/// Expects `caps = [module_memory, creator_endpoint?]`; caps past those two
/// are deleted. Stdio pipe wiring is installed via separate `CONFIGURE_PIPE`
/// IPCs (one per piped direction) on the returned badged `process_handle`
/// between create and `START_PROCESS`; the create path itself stays
/// stdio-agnostic.
fn handle_create(
    req: &IpcMessage,
    ipc_buf: *mut u64,
    ctx: &ProcmgrCtx,
    table: &mut process::ProcessTable,
)
{
    let label = req.label;
    let caps = req.caps();

    if caps.is_empty()
    {
        reply_empty(ipc_buf, procmgr_errors::INVALID_ELF);
        return;
    }

    let module_cap = caps[0];
    let creator_ep = if caps.len() >= 2 { caps[1] } else { 0 };
    release_caps(caps.get(2..).unwrap_or(&[]));

    // Resolve the scheduling fields before any resource acquisition. The
    // transferred caps are procmgr's to release on the reject path.
    let Some(sched) = resolve_create_sched(label, req.badge, table)
    else
    {
        let _ = syscall::cap_delete(module_cap);
        if creator_ep != 0
        {
            let _ = syscall::cap_delete(creator_ep);
        }
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    };

    let blobs = process::CreateBlobs::extract(req, 0);

    // Register this child with memmgr. memmgr replies with a badged SEND
    // cap on its endpoint plus the memmgr-side process badge. Procmgr:
    //   - uses the cap for every per-child memory-cap allocation (so memmgr
    //     accounts them to the child's record from the moment they leave
    //     the pool); and
    //   - copies the cap into the child's `ProcessInfo.memmgr_endpoint_cap`
    //     so the child's std heap-bootstrap can call `REQUEST_MEMORY_CAPS`; and
    //   - sends the badge in `PROCESS_DIED` at child teardown.
    // The guard owns the registration until the child's table entry does:
    // on a failed create it retires memmgr's record (PROCESS_DIED, which
    // returns every page already billed to the child) and drops the slot.
    let (memmgr_send, memmgr_badge) = register_with_memmgr(ctx.memmgr_ep, ipc_buf);
    let mms = process::MemmgrSendGuard::new(memmgr_send, memmgr_badge, ctx.memmgr_ep, ipc_buf);

    let universals = process::UniversalCaps {
        procmgr_endpoint: ctx.self_endpoint,
        log_send_source: ctx.log_ep,
        memmgr_endpoint: mms.cap(),
        memmgr_badge: mms.badge(),
        registry_send_source: ctx.registry_ep,
        sched_baseline: ctx.sched_baseline,
        demand_paged: label & procmgr_labels::CREATE_PINNED == 0,
        self_memmgr_ep: ctx.memmgr_ep,
    };

    let result = process::create_process(
        module_cap,
        ctx.self_aspace,
        ctx.memmgr_ep,
        ipc_buf,
        table,
        ctx.self_endpoint,
        creator_ep,
        &universals,
        &blobs.args(),
        &blobs.env(),
        ctx.death_eq,
        sched,
    );

    // Procmgr's parent-side copy of the badged cap stays in procmgr's
    // CSpace as long as the child is alive: it's the channel procmgr
    // uses to call `PROCESS_DIED` at teardown. On success the slot is
    // recorded in ProcessEntry.memmgr_send_cap and dropped only after
    // PROCESS_DIED. On create failure (no entry) the guard's drop sends
    // PROCESS_DIED and deletes the slot; create_process has already
    // released the child's kernel objects, so memmgr reclaims pages no
    // kernel object still uses.
    if result.is_some()
    {
        let _ = mms.disarm();
    }
    else
    {
        drop(mms);
    }

    // Module cap disposition: the module cap is a borrowed derivation of the
    // caller's module-source memory cap. The loader has copied the ELF contents
    // into the child's AddressSpace and has no further use for the source, so
    // delete it. The owner (init) retains the source memory cap and donates it to
    // memmgr's pool at reap.
    if module_cap != 0
    {
        let _ = syscall::cap_delete(module_cap);
    }
    if creator_ep != 0
    {
        let _ = syscall::cap_delete(creator_ep);
    }

    match result
    {
        Some(result) =>
        {
            log_spawn_sched(sched);
            reply_create_result(&result, ipc_buf, ctx.memmgr_ep, table);
        }
        None =>
        {
            reply_empty(ipc_buf, procmgr_errors::OUT_OF_MEMORY);
        }
    }
}

/// One line per successful spawn recording the resolved scheduling
/// placement, so the boot log evidences every process's level and band
/// (there is no priority-readback syscall to query after the fact).
fn log_spawn_sched(sched: process::ChildSched)
{
    std::os::seraph::log!(
        "procmgr: spawn priority={} band=[1,{}]",
        sched.priority,
        sched.band_max
    );
}

/// Long-lived procmgr state used by all request handlers. All fields are
/// fixed for the lifetime of the process.
pub struct ProcmgrCtx
{
    pub self_aspace: u32,
    pub self_endpoint: u32,
    /// Un-badged SEND cap on the log endpoint received from init
    /// during procmgr's own bootstrap. Procmgr uses it as the
    /// `cap_derive_badge` source for minting a badged SEND cap per
    /// child it spawns (badge = the child's process badge). The
    /// minted cap is placed in the child's `ProcessInfo.log_send_cap`.
    /// Zero if init did not provide one (very early boot); children
    /// born in that window receive zero and silent-drop
    /// `std::os::seraph::log!`.
    pub log_ep: u32,
    /// Un-badged SEND cap on svcmgr's service endpoint, received from init
    /// during procmgr's own bootstrap. Used as the `cap_derive_badge` source
    /// for minting a per-child badged SEND (badge = the child's process
    /// badge), installed in the child's `ProcessInfo.service_registry_cap`
    /// so the child can issue `svcmgr_labels::QUERY_ENDPOINT` against svcmgr
    /// for service-name lookups. Zero if init has not yet wired it; children
    /// born in that window receive zero and `registry_client::lookup` no-ops.
    pub registry_ep: u32,
    /// Badged SEND cap on memmgr's service endpoint, identifying procmgr.
    /// Used to mint per-child memmgr SENDs via `REGISTER_PROCESS`, to
    /// notify `PROCESS_DIED`, and as the destination for procmgr's own
    /// memory-cap allocations (memmgr auto-registers procmgr's badge at
    /// bootstrap so `REQUEST_MEMORY_CAPS` on this cap is allowed).
    pub memmgr_ep: u32,
    /// Single shared death-notification event queue. Every spawned child
    /// binds its thread to this queue (via multi-bind in the kernel) with
    /// `correlator = entry.badge as u32`. Multiplexed alongside the
    /// service endpoint via the wait-set in `ws_cap`.
    pub death_eq: u32,
    /// Wait-set cap. Multiplexes procmgr's service endpoint
    /// (`WS_BADGE_SERVICE`) and the shared death event queue
    /// (`WS_BADGE_DEATH`). Fixed two members.
    pub ws_cap: u32,
    /// Procmgr's baseline `SchedControl` cap, delivered via its own
    /// `ProcessInfo.sched_control_cap` (band
    /// `[1, sched_policy::BASELINE_PRIORITY_MAX]`). The fan-out source for
    /// every child band (copied whole or copy-then-split narrowed) and the
    /// authority behind creating child threads at their assigned level.
    /// Zero if init delegated none; children are then created at the floor
    /// and cannot set any priority.
    pub sched_baseline: u32,
}

/// Handle `CREATE_FROM_FILE` — create a process from a caller-supplied file cap.
///
/// Wire layout: see [`procmgr_labels::CREATE_FROM_FILE`]. The caller has
/// already walked its own namespace cap to the binary node; procmgr never
/// touches the namespace tree on this path. procmgr owns every transferred
/// cap: the file cap is `FS_CLOSE`d and deleted after the load, the creator
/// endpoint is deleted once the child holds its own copy, the relay is
/// consumed by `finalize_creation` on success, and every other cap, and every
/// cap of a rejected request, is deleted here.
fn handle_create_from_file(
    req: &IpcMessage,
    ipc_buf: *mut u64,
    ctx: &ProcmgrCtx,
    table: &mut process::ProcessTable,
)
{
    let label = req.label;
    let all_caps = req.caps();

    // The death-relay POST cap, when present, is the LAST cap in the message
    // (see `CREATE_DEATH_RELAY`), peeled off the tail so the
    // `creator_endpoint` slot stays positionally fixed at caps[1]. A relay
    // request whose only cap is the file cap is malformed: taking that cap
    // as the relay too would release one slot twice.
    let Some(caps) = process::split_create_from_file_caps(
        all_caps,
        label & procmgr_labels::CREATE_DEATH_RELAY != 0,
    )
    else
    {
        match all_caps.split_first()
        {
            Some((&file_cap, rest)) if file_cap != 0 =>
            {
                process::vfs_close(file_cap, ipc_buf);
                release_caps(rest);
            }
            _ => release_caps(all_caps),
        }
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    };
    release_caps(caps.extra);

    // Resolve the scheduling fields before any resource acquisition. The
    // transferred caps are procmgr's to release on the reject path — the
    // file cap needs a real FS_CLOSE so the fs driver drops its open-file
    // state, not just a slot delete.
    let Some(sched) = resolve_create_sched(label, req.badge, table)
    else
    {
        process::vfs_close(caps.file, ipc_buf);
        release_caps(&[caps.creator, caps.relay]);
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    };

    let file_size = req.word(0);

    let blobs = process::CreateBlobs::extract(req, 1);

    let result = process::create_process_from_file(
        ctx,
        caps.file,
        file_size,
        table,
        ipc_buf,
        caps.creator,
        &blobs.args(),
        &blobs.env(),
        ctx.death_eq,
        label & procmgr_labels::CREATE_PINNED == 0,
        caps.relay,
        sched,
    );

    // The child holds its own copy of the creator endpoint (populate_child_info
    // cap_copies it), so procmgr's slot is released on both arms, as
    // handle_create does.
    release_caps(&[caps.creator]);

    match result
    {
        Ok(result) =>
        {
            log_spawn_sched(sched);
            reply_create_result(&result, ipc_buf, ctx.memmgr_ep, table);
        }
        Err(code) =>
        {
            // `finalize_creation` consumes (binds + deletes) the relay cap
            // only once the child's table entry exists, which every error
            // return precedes; drop procmgr's copy here.
            release_caps(&[caps.relay]);
            reply_empty(ipc_buf, code);
        }
    }
}
