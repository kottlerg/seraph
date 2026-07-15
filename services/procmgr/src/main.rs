// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// procmgr/src/main.rs

//! Seraph process manager — IPC server for process lifecycle management.
//!
//! Receives requests via IPC to create, configure, and start new processes.
//! Supports both in-memory ELF loading from boot module memory caps and streaming
//! from the VFS. See `procmgr/docs/ipc-interface.md`.
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

    // Death-EQ inline slot (matches `cap::retype::event_queue_raw_bytes`):
    // 24 wrapper + 56 state + (capacity + 1) * 8 ring bytes. Capacity is
    // `MAX_PROCESSES * 2` to absorb a simultaneous-crash burst without
    // dropping notifications between drain calls.
    let death_eq_slab_bytes: u64 = 24 + 56 + ((process::MAX_PROCESSES as u64 * 2) + 1) * 8;
    let Some(death_eq) = std::os::seraph::object_slab_retype(death_eq_slab_bytes, |slab| {
        syscall::event_queue_create(slab, (process::MAX_PROCESSES as u32) * 2).ok()
    })
    else
    {
        syscall::thread_exit();
    };
    let Some(ws_cap) =
        std::os::seraph::object_slab_retype(4096, |slab| syscall::wait_set_create(slab).ok())
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
    loop
    {
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
/// retype slab. The kernel consumes `KERNEL_STACK_PAGES + 1 = 5` pages
/// (4 kstack + 1 wrapper/TCB) plus a small one-time per-`MemoryObject`
/// allocator metadata footprint; one extra page is included so the
/// retype's `available_bytes >= raw_bytes` check passes after that
/// metadata debit.
pub(crate) const THREAD_RETYPE_PAGES: u64 = 6;

/// Pages requested from memmgr for the child's `AddressSpace` retype slab.
/// Page 0 becomes the root PT; the remaining pages form the initial PT
/// growth pool. The +1 covers the ~64 B per-memory-cap allocator metadata
/// footprint debited at the first retype.
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
/// × 72 B = 4032 B/page); the +1 covers the per-memory-cap allocator
/// metadata footprint, and the kernel reserves the slab's page 0 as the
/// wrapper page.
///
/// Seed-to-cover policy (#366): the seeded pool MUST back the child's
/// full `max_slots = 256` quota so a cap insert can never fail on pool
/// exhaustion below quota. 7 pages → 6 to the kernel → 5 pool pages →
/// 5 × 56 − 1 = 279 usable slots ≥ 256.
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

    match label & 0xFFFF
    {
        procmgr_labels::CREATE_PROCESS =>
        {
            handle_create(&req, ipc_buf, ctx, table);
        }

        procmgr_labels::START_PROCESS =>
        {
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
            // Badge from ipc_recv identifies which process to destroy.
            process::destroy_process(badge, ctx.memmgr_ep, ipc_buf, table);
            reply_empty(ipc_buf, procmgr_errors::SUCCESS);
        }

        procmgr_labels::QUERY_PROCESS =>
        {
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
            init_reap::handle_done(ipc_buf);
        }

        _ =>
        {
            reply_empty(ipc_buf, procmgr_errors::UNKNOWN_OPCODE);
        }
    }
}

/// Handle `REGISTER_DEATH_EQ` — store the caller's `EventQueue` cap
/// as procmgr's logd-death observer, then retroactively bind it to
/// every thread currently in the process table.
///
/// Wire format:
/// * `caller badge` MUST equal `procmgr_labels::DEATH_EQ_AUTHORITY`
///   (init derives the authorised badged SEND cap and hands it
///   exclusively to real-logd at bootstrap).
/// * `caps[0]` = `EventQueue` cap with POST right.
///
/// Reply: `procmgr_errors::SUCCESS` on bind, `UNAUTHORIZED` if the
/// caller lacks the authority badge, `INVALID_ARGUMENT` if no cap
/// arrives.
fn handle_register_death_eq(req: &IpcMessage, ipc_buf: *mut u64, table: &mut process::ProcessTable)
{
    if req.badge != procmgr_labels::DEATH_EQ_AUTHORITY
    {
        reply_empty(ipc_buf, procmgr_errors::UNAUTHORIZED);
        return;
    }
    let Some(&logd_eq) = req.caps().first()
    else
    {
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    };
    if logd_eq == 0
    {
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    }
    // install_logd_death_eq is first-wins: it stores the cap and
    // binds it as a second observer on every existing thread, or
    // returns false if a previous registration already filled the
    // slot. Future spawns pick it up inside finalize_creation by
    // reading the same atomic.
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
        let Ok(payload) = syscall::event_try_recv(death_eq)
        else
        {
            return;
        };
        let correlator = (payload >> 32) as u32;
        let exit_reason = payload & 0xFFFF_FFFF;
        if correlator == procmgr_labels::INIT_REAP_CORRELATOR
        {
            // An init thread exited. `run_reap` counts down the two init
            // threads and, on the last exit, tears down init's
            // AS/CSpace/Thread objects and donates its reclaimable Memory caps
            // caps to memmgr's pool.
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
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    }
    let memory_cap = caps[0];
    let data_notification = caps[1];
    let space_notification = caps[2];

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

    // configure_pipe cap_copy'd each cap into the child's CSpace; drop
    // procmgr-side slots so refcounts hit zero when both peers later
    // release. Idempotent on zero. On the failure path the cap_copy may
    // not have happened yet — cap_delete on a stale slot is a no-op.
    let _ = syscall::cap_delete(memory_cap);
    let _ = syscall::cap_delete(data_notification);
    let _ = syscall::cap_delete(space_notification);

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
    let code = match table.configure_namespace(badge, root_cap, cwd_cap)
    {
        Ok(()) => procmgr_errors::SUCCESS,
        Err(code) => code,
    };
    reply_empty(ipc_buf, code);
}

/// Argv/env blobs extracted from a create request's label fields and data
/// words, owning the staging buffers so both create handlers share one
/// extraction path.
struct CreateBlobs
{
    args_buf: [u8; ipc::ARGS_BLOB_MAX],
    args_len: usize,
    args_count: u32,
    env_buf: [u8; ipc::ARGS_BLOB_MAX],
    env_len: usize,
    env_count: u32,
}

impl CreateBlobs
{
    /// Extract the blobs from `req`. `first_word` is the data-word offset
    /// of the argv blob: 0 for `CREATE_PROCESS`, 1 for `CREATE_FROM_FILE`
    /// (which carries `file_size` in word 0). Oversized or absent blobs
    /// degrade to empty, matching the wire contract.
    fn extract(req: &IpcMessage, first_word: usize) -> Self
    {
        let label = req.label;
        let args_bytes = ((label >> 32) & 0xFFFF) as usize;
        let mut blobs = Self {
            args_buf: [0u8; ipc::ARGS_BLOB_MAX],
            args_len: 0,
            args_count: ((label >> 48) & 0xFF) as u32,
            env_buf: [0u8; ipc::ARGS_BLOB_MAX],
            env_len: 0,
            env_count: ((label >> 56) & 0xFF) as u32,
        };
        if args_bytes > 0 && args_bytes <= ipc::ARGS_BLOB_MAX
        {
            copy_bytes_from_msg(req, first_word, args_bytes, &mut blobs.args_buf);
            blobs.args_len = args_bytes;
        }
        // Env blob (when present) sits after the argv words: 1 header word
        // carrying env_bytes, then the blob itself. Bounds: same
        // ARGS_BLOB_MAX as argv — env must also fit in the ProcessInfo
        // page tail.
        let argv_words = args_bytes.div_ceil(8);
        if blobs.env_count > 0
        {
            let env_bytes = (req.word(first_word + argv_words) & 0xFFFF) as usize;
            if env_bytes > 0 && env_bytes <= ipc::ARGS_BLOB_MAX
            {
                copy_bytes_from_msg(
                    req,
                    first_word + argv_words + 1,
                    env_bytes,
                    &mut blobs.env_buf,
                );
                blobs.env_len = env_bytes;
            }
        }
        blobs
    }

    fn args(&self) -> process::ChildArgs<'_>
    {
        process::ChildArgs {
            blob: &self.args_buf[..self.args_len],
            count: self.args_count,
        }
    }

    fn env(&self) -> process::ChildEnv<'_>
    {
        process::ChildEnv {
            blob: &self.env_buf[..self.env_len],
            count: self.env_count,
        }
    }
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

/// Reply with a successful process creation result.
///
/// Reply caps: `[process_handle, thread]`.
fn reply_create_result(result: &process::CreateResult, ipc_buf: *mut u64)
{
    let msg = IpcMessage::builder(procmgr_errors::SUCCESS)
        .cap(result.process_handle)
        .cap(result.thread_for_caller)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&msg, ipc_buf) };
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
/// Expects `caps = [module_memory, creator_endpoint?]`. Stdio pipe
/// wiring is installed via separate `CONFIGURE_PIPE` IPCs (one per
/// piped direction) on the returned badged `process_handle` between
/// create and `START_PROCESS`; the create path itself stays
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

    let blobs = CreateBlobs::extract(req, 0);

    // Register this child with memmgr. memmgr replies with a badged SEND
    // cap on its endpoint plus the memmgr-side process badge. Procmgr:
    //   - uses the cap for every per-child memory-cap allocation (so memmgr
    //     accounts them to the child's record from the moment they leave
    //     the pool); and
    //   - copies the cap into the child's `ProcessInfo.memmgr_endpoint_cap`
    //     so the child's std heap-bootstrap can call `REQUEST_MEMORY_CAPS`; and
    //   - sends the badge in `PROCESS_DIED` at child teardown.
    let (memmgr_send, memmgr_badge) = register_with_memmgr(ctx.memmgr_ep, ipc_buf);

    let universals = process::UniversalCaps {
        procmgr_endpoint: ctx.self_endpoint,
        log_send_source: ctx.log_ep,
        memmgr_endpoint: memmgr_send,
        memmgr_badge,
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
    // uses to call `PROCESS_DIED` at teardown. The slot is recorded in
    // ProcessEntry.memmgr_send_cap and dropped only after PROCESS_DIED.
    // On create failure (no entry) it must be dropped immediately to
    // avoid leaking the slot.
    if result.is_none() && memmgr_send != 0
    {
        let _ = syscall::cap_delete(memmgr_send);
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
            reply_create_result(&result, ipc_buf);
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
/// touches the namespace tree on this path.
fn handle_create_from_file(
    req: &IpcMessage,
    ipc_buf: *mut u64,
    ctx: &ProcmgrCtx,
    table: &mut process::ProcessTable,
)
{
    let label = req.label;

    let caps = req.caps();
    let file_cap = match caps.first().copied()
    {
        Some(c) if c != 0 => c,
        _ =>
        {
            reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
            return;
        }
    };
    // The death-relay POST cap, when present, is the LAST cap in the message
    // (see `CREATE_DEATH_RELAY`). Peel it off the tail first so the
    // `creator_endpoint` slot stays positionally fixed at caps[1].
    let parent_relay_cap = if label & procmgr_labels::CREATE_DEATH_RELAY != 0
    {
        caps.last().copied().unwrap_or(0)
    }
    else
    {
        0
    };
    let creator_ep = match caps.get(1).copied()
    {
        Some(c) if c != parent_relay_cap => c,
        _ => 0,
    };

    // Resolve the scheduling fields before any resource acquisition. The
    // transferred caps are procmgr's to release on the reject path — the
    // file cap needs a real FS_CLOSE so the fs driver drops its open-file
    // state, not just a slot delete.
    let Some(sched) = resolve_create_sched(label, req.badge, table)
    else
    {
        process::vfs_close(file_cap, ipc_buf);
        if creator_ep != 0
        {
            let _ = syscall::cap_delete(creator_ep);
        }
        if parent_relay_cap != 0
        {
            let _ = syscall::cap_delete(parent_relay_cap);
        }
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    };

    let file_size = req.word(0);

    let blobs = CreateBlobs::extract(req, 1);

    let result = process::create_process_from_file(
        ctx,
        file_cap,
        file_size,
        table,
        ipc_buf,
        creator_ep,
        &blobs.args(),
        &blobs.env(),
        ctx.death_eq,
        label & procmgr_labels::CREATE_PINNED == 0,
        parent_relay_cap,
        sched,
    );

    match result
    {
        Ok(result) =>
        {
            log_spawn_sched(sched);
            reply_create_result(&result, ipc_buf);
        }
        Err(code) =>
        {
            // The relay cap is consumed (bound + deleted) only on the
            // success path inside `finalize_creation`; drop procmgr's copy
            // here on any earlier failure so it does not leak.
            if parent_relay_cap != 0
            {
                let _ = syscall::cap_delete(parent_relay_cap);
            }
            reply_empty(ipc_buf, code);
        }
    }
}

/// Copy up to `len` bytes from the IPC message's data-byte view into `dst`,
/// starting at word offset `word_offset`. Used to extract argv/env blobs
/// from positions other than the start of the data area.
fn copy_bytes_from_msg(msg: &IpcMessage, word_offset: usize, len: usize, dst: &mut [u8])
{
    let bytes = msg.data_bytes();
    let src_start = word_offset * 8;
    let avail = bytes.len().saturating_sub(src_start);
    let copy_len = len.min(dst.len()).min(avail);
    if copy_len > 0
    {
        dst[..copy_len].copy_from_slice(&bytes[src_start..src_start + copy_len]);
    }
}
