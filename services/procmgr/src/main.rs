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

#![expect(
    clippy::cast_possible_truncation,
    reason = "targets 64-bit only; u64/usize conversions lossless"
)]
#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]
#![warn(
    clippy::fn_params_excessive_bools,
    clippy::large_stack_frames,
    clippy::significant_drop_tightening,
    clippy::volatile_composites,
    clippy::wildcard_enum_match_arm
)]
#![cfg_attr(
    not(test),
    warn(
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::string_slice,
        clippy::unreachable,
        clippy::unwrap_in_result
    )
)]

mod arch;
mod crash;
mod death_queues;
mod init_reap;
mod loader;
mod process;

use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors, procmgr_labels};
// Brings `configure_pipe` / `configure_namespace` into method-call scope; their
// pipe/namespace logic moved onto an extension trait when `ProcessTable` was
// extracted into the `procmgr-process-table` crate.
use process::TableExt;
use std::os::seraph::startup_info;
use std::sync::{Mutex, MutexGuard, PoisonError};

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
#[expect(
    clippy::struct_field_names,
    reason = "the shared `_ep` suffix says each field is an endpoint cap; dropping it would leave \
              names that hide the cap kind"
)]
struct InitBootstrap
{
    service_ep: u64,
    log_ep: u64,
    registry_ep: u64,
}

fn bootstrap_from_init(creator_ep: u64, ipc_buf: *mut u64) -> Option<InitBootstrap>
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

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "IPC buffer is registered by `_start`; reinterpret as `*mut u64`"
    )]
    let ipc_buf = startup.ipc_buffer.cast::<u64>();

    // Bootstrap service endpoint + log endpoint from init.
    let Some(boot) = bootstrap_from_init(startup.creator_endpoint, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    // The death queues and the wait set the reaper waits on, which holds
    // them alone; further queues join it as pools run out, and it is
    // replaced by a wider one as they fill it.
    let Some(deaths) = death_set::DeathSet::new_death_only(
        WS_BADGE_DEATH,
        death_queues::DEATH_EQ_CAPACITY,
        process_table::death_queues::FIRST_POOL_OBSERVERS,
    )
    else
    {
        syscall::thread_exit();
    };

    // The crash endpoint every process procmgr creates binds its exception
    // class to, and the thread that declines its faults while no crash
    // service is registered; before any process is created.
    crash::start();

    // Every thread of procmgr shares the context for procmgr's life, which
    // never ends, so it is leaked rather than counted.
    let ctx: &'static ProcmgrCtx = Box::leak(Box::new(ProcmgrCtx {
        self_aspace: startup.self_aspace,
        self_cspace: startup.self_cspace,
        self_endpoint: boot.service_ep,
        log_ep: boot.log_ep,
        registry_ep: boot.registry_ep,
        memmgr_ep: startup.memmgr_endpoint,
        deaths: Mutex::new(deaths),
        tables: process::Tables::new(),
        sched_baseline: startup.sched_control_cap,
    }));

    // procmgr's ProcessInfo names no procmgr endpoint, so its own spawned
    // threads send no `REGISTER_THREAD` and start without waiting on it
    // (runtime/ruststd/README.md § Thread registration).
    if std::thread::Builder::new()
        .name("procmgr-reaper".into())
        .spawn(move || reap_loop(ctx))
        .is_err()
    {
        std::os::seraph::log!(error: "reaper thread not started; exiting");
        syscall::thread_exit();
    }

    let pool = recv_pool::RecvPool::new(boot.service_ep, recv_diag, move |req, buf| {
        dispatch_ipc(req, buf.as_ptr(), ctx);
    });
    // The main thread is the last worker, so a failed spawn leaves at least
    // one serving.
    if let Err(e) = pool.spawn("procmgr-recv", RECV_WORKERS - 1)
    {
        std::os::seraph::log!(
            warn: "{} of {RECV_WORKERS} request workers started: {}",
            // `running` counts started workers, bounded by `RECV_WORKERS`.
            e.running.saturating_add(1),
            e.error
        );
    }
    pool.serve_on_current()
}

/// Threads receiving on procmgr's service endpoint, the main thread among
/// them: a concurrency setting that bounds no capacity, since callers past it
/// queue on the endpoint. A create that waits on a slow file server, on
/// memmgr, or on the kernel holds one worker, and the others go on serving.
const RECV_WORKERS: usize = 4;

/// The reaper: wait on the death queues, and on every wake drain them, reap
/// each dead process, and make the checks a death calls for
/// ([`reap_checks`]). The only thread that waits on the death-only wait set.
fn reap_loop(ctx: &ProcmgrCtx) -> !
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        std::os::seraph::log!(error: "reaper has no IPC buffer; exiting");
        syscall::thread_exit();
    }
    // A failing wait counts toward the guard's fatal streak. A wait the
    // replacement of the wait set cancels (`Interrupted`, or
    // `InvalidCapability` for a wait that began after the delete) counts
    // once, and the next pass reads the new set.
    let mut guard = ipc::recv_guard::RecvGuard::new(recv_diag);
    let mut batch: Vec<syscall::DeathEvent> = Vec::new();
    loop
    {
        // Read under the lock and waited on after it: a bind that grows the
        // death queues may replace the set meanwhile.
        let ws = lock(&ctx.deaths).ws_cap();
        if let Err(e) = syscall::wait_set_wait(ws)
        {
            guard.on_failure(e);
            continue;
        }
        guard.on_success();
        dispatch_death(ctx, ipc_buf, &mut batch);
        reap_checks(ctx);
    }
}

/// The checks a death calls for, which the reaper makes on every pass, a
/// worker before it serves each request, and a worker again after a
/// teardown it ran itself, since a teardown's stop of a process posts no
/// death to wake the reaper (docs/process-lifecycle.md, `EXIT_KILLED`):
/// take the crash endpoint's receive side back from a crash
/// service that is gone, and restore the crash bindings of every process
/// whose debugger is gone.
fn reap_checks(ctx: &ProcmgrCtx)
{
    crash::check_registrant();
    // The guard drops at the end of the statement, so the log lines below
    // follow the lock's release.
    let restored = process::check_debuggers(&mut ctx.tables.lock().table);
    for _ in 0..restored
    {
        std::os::seraph::log!("debugger gone; crash bindings restored");
    }
}

/// Lock `mutex`, taking a poisoned lock as it is: procmgr is built with
/// `panic = "abort"`, so no holder unwinds.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T>
{
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Monotonic time since the first call, in nanoseconds, for the
/// recent-exits retention window and the init-reap probe budget. Saturates
/// rather than wraps (a `u64` of nanoseconds covers about 584 years).
pub(crate) fn now_ns() -> u64
{
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(std::time::Instant::now);
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// `WaitSet` badge for procmgr's death event queues, all of them.
const WS_BADGE_DEATH: u64 = 1;

/// Pages requested from memmgr per spawned child for the child's Thread
/// retype slab: `SystemInfoType::ThreadRetypeBytes` in pages (guard page,
/// kernel stack, wrapper/TCB, extended-state save area, which the boot CPU sizes), all
/// consumed by the kernel. Queried once and cached; `None` if the query
/// fails, which fails the spawn.
pub(crate) fn thread_retype_pages() -> Option<u64>
{
    use std::sync::atomic::{AtomicU64, Ordering};
    static CACHED: AtomicU64 = AtomicU64::new(0);
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 0
    {
        return Some(cached);
    }
    let bytes = syscall::system_info(syscall_abi::SystemInfoType::ThreadRetypeBytes as u64).ok()?;
    let pages = bytes.div_ceil(syscall_abi::PAGE_SIZE);
    CACHED.store(pages, Ordering::Relaxed);
    Some(pages)
}

/// Pages requested from memmgr for the child's `AddressSpace` retype slab.
/// Every page reaches the kernel: page 0 holds the wrapper, page 1 the
/// root PT, and the remaining 46 form the initial PT growth pool.
///
/// Sized to cover the typical small-process mapping pattern: 3-6 LOAD
/// segments + stack + IPC buffer + TLS + `ProcessInfo` memory cap. Each
/// distinct user VA region whose PT entry isn't already populated
/// consumes up to 3 intermediate PT pages (PDPT/PD/PT on x86-64; 4, with a
/// shared PML4, under 5-level paging), and ASLR (#39) spreads the four
/// bootstrap surfaces across distinct 64 GiB window strides — one shared
/// PDPT plus up to 3 pages per surface (~13 pooled pages) where the
/// pre-ASLR clustered layout shared one PDPT/PD/PT triple. Larger
/// processes refill via augment-mode `cap_create_aspace`.
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
/// `flags` are the `REGISTER_PROCESS` flags (`ChildSched::memmgr_flags`).
/// The badge is opaque to procmgr, apart from the phys-class bit
/// `process_table::child_memmgr_flags` reads, and is sent back in the
/// `PROCESS_DIED` payload at child teardown so memmgr can reclaim the
/// right record.
#[expect(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "procmgr is a binary, not a library, and every caller passes its thread's registered \
              IPC buffer page as `ipc_buf`"
)]
pub fn register_with_memmgr(memmgr_ep: u64, flags: u64, ipc_buf: *mut u64) -> (u64, u64)
{
    if memmgr_ep == 0
    {
        return (0, 0);
    }
    let msg = IpcMessage::builder(memmgr_labels::REGISTER_PROCESS)
        .word(0, u64::from(ipc::MEMMGR_LABELS_VERSION))
        .word(1, flags)
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
#[expect(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "procmgr is a binary, not a library, and every caller passes its thread's registered \
              IPC buffer page as `ipc_buf`"
)]
pub fn memmgr_alloc_page(memmgr_send: u64, ipc_buf: *mut u64) -> Option<u64>
{
    if memmgr_send == 0
    {
        std::os::seraph::log!(warn: "alloc_page: memmgr_send=0");
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
            std::os::seraph::log!(warn: "alloc_page: ipc_call err={}", e);
            return None;
        }
    };
    if reply.label != memmgr_errors::SUCCESS
    {
        std::os::seraph::log!(
            warn: "alloc_page: memmgr label={} pool: total={} runs={} max={}",
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
            warn: "alloc_page: count={} caps={}",
            reply.word(0),
            reply.caps().len()
        );
        release_grant(memmgr_send, &reply, ipc_buf);
        return None;
    }
    reply.caps().first().copied()
}

/// Allocate exactly `pages` contiguous pages from `memmgr_send` as a
/// single Memory cap. Returns the cap slot in procmgr's `CSpace`, or
/// `None` on any failure (memmgr unwired, OOM, malformed reply).
///
/// Used to back kernel-object retypes whose source Memory cap must be
/// contiguous (e.g. `Thread`, `AddressSpace`, `CSpace`); as
/// [`memmgr_alloc_contig_grant`], without the region id.
pub fn memmgr_alloc_pages_contig(memmgr_send: u64, pages: u64, ipc_buf: *mut u64) -> Option<u64>
{
    memmgr_alloc_contig_grant(memmgr_send, pages, ipc_buf).map(|(cap, _)| cap)
}

/// Allocate exactly `pages` contiguous pages from `memmgr_send` as a
/// single Memory cap. Returns the cap slot in procmgr's `CSpace` and the
/// grant's region id, which names the run to `RELEASE_MEMORY_CAPS`, or
/// `None` on any failure (memmgr unwired, OOM, malformed reply).
///
/// The request sets `REQUIRE_CONTIGUOUS`, so memmgr answers with one cap of
/// exactly `pages` pages or an error. A reply of any other shape is refused,
/// and every cap it carried is returned to memmgr's pool ([`release_grant`])
/// rather than left billed to the account behind `memmgr_send`.
#[expect(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "procmgr is a binary, not a library, and every caller passes its thread's registered \
              IPC buffer page as `ipc_buf`"
)]
pub fn memmgr_alloc_contig_grant(
    memmgr_send: u64,
    pages: u64,
    ipc_buf: *mut u64,
) -> Option<(u64, u64)>
{
    if memmgr_send == 0 || pages == 0 || pages > u64::from(u32::MAX)
    {
        return None;
    }
    let flags = u64::from(memmgr_labels::REQUIRE_CONTIGUOUS) << 32;
    let msg = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, pages | flags)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(memmgr_send, &msg, ipc_buf) }.ok()?;
    if reply.label != memmgr_errors::SUCCESS
    {
        release_caps(reply.caps());
        return None;
    }
    let caps = reply.caps();
    if let Some((_, &[region_id])) = ipc::memmgr_grant_layout(&reply)
        && let Some(&first_cap) = caps.first()
        && syscall::cap_info(first_cap, syscall_abi::CAP_INFO_MEMORY_SIZE)
            .is_ok_and(|size| pages.checked_mul(4096) == Some(size))
    {
        return Some((first_cap, region_id));
    }
    release_grant(memmgr_send, &reply, ipc_buf);
    None
}

/// Return every cap of a `REQUEST_MEMORY_CAPS` success reply procmgr does not
/// keep: delete procmgr's slots and name each run to memmgr by its region id
/// (`RELEASE_MEMORY_CAPS`), so the pages go back to the pool instead of
/// staying billed until the account's `PROCESS_DIED`. A reply whose layout
/// does not decode names no id; its slots are deleted only.
#[expect(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "procmgr is a binary, not a library, and every caller passes its thread's registered \
              IPC buffer page as `ipc_buf`"
)]
pub fn release_grant(memmgr_send: u64, reply: &IpcMessage, ipc_buf: *mut u64)
{
    release_caps(reply.caps());
    let Some((_, region_ids)) = ipc::memmgr_grant_layout(reply)
    else
    {
        return;
    };
    let mut msg =
        IpcMessage::builder(memmgr_labels::RELEASE_MEMORY_CAPS).word(0, region_ids.len() as u64);
    for (i, &id) in region_ids.iter().enumerate()
    {
        // `i` indexes `region_ids`, so it is below the slice length.
        msg = msg.word(i.saturating_add(1), id);
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_call(memmgr_send, &msg.build(), ipc_buf) };
}

/// General-allocation headroom of procmgr's `CSpace` below which it tops the
/// pool up. procmgr holds several caps per live child, so a burst of spawns
/// draws slots quickly; the mark leaves room for a full spawn even if the
/// top-up itself fails once.
const CSPACE_LOW_WATER: u64 = 256;

/// Headroom a top-up funds: about 18 slot pages.
const CSPACE_TOPUP_SLOTS: u64 = 1024;

/// Whether the last top-up failed, so a streak of failures logs once; held
/// by the one worker topping up, and passed over by any other meanwhile.
static HEADROOM_WARNED: Mutex<bool> = Mutex::new(false);

/// Keep procmgr's own `CSpace` above [`CSPACE_LOW_WATER`] general slots, with
/// a page of growth budget beyond them for its body arena, so
/// its allocations never meet an exhausted `CSpace` and its receives keep the
/// IPC receive reserve (services/procmgr/README.md § `CSpace` headroom). Each
/// request runs it before it is served; a worker that finds another topping
/// up goes on, since the low-water mark leaves room for every worker's
/// request. A failed top-up is retried on the next request, and the log
/// names only the first failure of a streak.
fn hold_cspace_headroom(self_cspace: u64)
{
    // The top-up (a call to memmgr) and the failure's log line (a call to
    // logd) are IPC calls made under this lock, which no other lock nests
    // and no thread waits on (`try_lock`).
    let Ok(mut warned) = HEADROOM_WARNED.try_lock()
    else
    {
        return;
    };
    // The growth budget also funds the body arena (the bodies of procmgr's
    // splits), so a page of it is held beyond the slots
    // (`syscall_abi::cspace_topup_pages`).
    let budget = syscall::cap_info(self_cspace, syscall_abi::CAP_INFO_CSPACE_BUDGET).unwrap_or(0);
    let headroom = std::os::seraph::cspace_slot_headroom(self_cspace);
    if syscall_abi::cspace_topup_pages(headroom, budget, CSPACE_LOW_WATER) == 0
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
        std::os::seraph::log!(warn: "CSpace headroom top-up failed; retrying each pass");
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
            std::os::seraph::log!(warn: "recv loop failing (err={err}); backing off");
        }
        ipc::recv_guard::RecvFailureStage::Fatal =>
        {
            std::os::seraph::log!(error: "recv loop wedged (err={err}); exiting");
        }
    }
}

/// Serve one request a worker received on the service endpoint, on that
/// worker's IPC buffer `ipc_buf`. Each arm takes the table lock only for its
/// own reads and writes of the table, and makes its IPC calls with no lock
/// held (services/procmgr/README.md § Concurrency).
fn dispatch_ipc(req: &IpcMessage, ipc_buf: *mut u64, ctx: &ProcmgrCtx)
{
    hold_cspace_headroom(ctx.self_cspace);
    // A crash service or a debugger watch that is a thread other than its
    // process's main thread posts no death when it exits, so every request
    // makes the checks before it is served, as the reaper does on a death.
    reap_checks(ctx);
    let mut req = *req;
    let label = req.label;
    // A process handle carries `PROCESS_HANDLE_TAG` beside its child's
    // badge. Every label is served under the child's badge alone, but the
    // two that name their sender, `DECLARE_NO_DEBUG` and `REGISTER_THREAD`,
    // are refused on a handle, so its holder can neither declare the child
    // nor register a thread into the child's registry.
    let (badge, on_handle) = process_table::request_badge(req.badge);
    req.badge = badge;
    if on_handle && !process_table::served_on_handle(label & 0xFFFF)
    {
        release_caps(req.caps());
        reply_empty(ipc_buf, procmgr_errors::INVALID_BADGE);
        return;
    }

    // Every cap a request transfers has already moved into procmgr's
    // CSpace. Each arm releases the caps its wire layout does not name, and
    // every cap on a reject arm, so a padded or refused request cannot grow
    // procmgr's CSpace (`services/procmgr/docs/ipc-interface.md`
    // § Capability Transfer).
    match label & 0xFFFF
    {
        procmgr_labels::CREATE_PROCESS =>
        {
            handle_create(&req, ipc_buf, ctx);
        }

        procmgr_labels::START_PROCESS =>
        {
            release_caps(req.caps());
            // Badge from ipc_recv identifies which process to start. The
            // start makes syscalls only, under the table lock.
            let started =
                process::start_process(badge, &mut ctx.tables.lock().table, ctx.self_aspace);
            let code = match started
            {
                Ok(()) => procmgr_errors::SUCCESS,
                Err(code) => code,
            };
            reply_empty(ipc_buf, code);
        }

        procmgr_labels::DESTROY_PROCESS =>
        {
            release_caps(req.caps());
            // Badge from ipc_recv identifies which process to destroy. Its
            // exit is recorded like a reaped death's, so a `QUERY_PROCESS`
            // racing a death drain the destroy overtook still answers
            // `EXITED`.
            let _ = process::destroy_process(
                badge,
                ctx.memmgr_ep,
                ipc_buf,
                &ctx.tables,
                process::ExitRecord::Record,
            );
            reply_empty(ipc_buf, procmgr_errors::SUCCESS);
            // The destroyed process may have been the crash service or an
            // attached debugger.
            reap_checks(ctx);
        }

        procmgr_labels::RELEASE_HOLD =>
        {
            release_caps(req.caps());
            // Badge from ipc_recv: the release token of the torn-down child
            // whose held reclaim the creator releases.
            let code = match process::release_hold(badge, ctx.memmgr_ep, ipc_buf, &ctx.tables)
            {
                Ok(()) => procmgr_errors::SUCCESS,
                Err(process_table::ReleaseRefusal::Unauthorized) => procmgr_errors::UNAUTHORIZED,
                Err(process_table::ReleaseRefusal::NotHeld) => procmgr_errors::INVALID_BADGE,
            };
            reply_empty(ipc_buf, code);
        }

        procmgr_labels::QUERY_PROCESS =>
        {
            release_caps(req.caps());
            // Badge identifies which process to query. Reply data:
            //   word 0 = state code (see `procmgr_process_state`)
            //   word 1 = exit_reason (only meaningful for `EXITED`)
            let (state, exit_reason) = resolve_query_state(badge, &mut ctx.tables.lock());
            let reply = IpcMessage::builder(procmgr_errors::SUCCESS)
                .word(0, state)
                .word(1, exit_reason)
                .build();
            // SAFETY: ipc_buf is the registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        }

        procmgr_labels::CREATE_FROM_FILE =>
        {
            handle_create_from_file(&req, ipc_buf, ctx);
        }

        procmgr_labels::CONFIGURE_PIPE =>
        {
            // Maps the child's ProcessInfo page and copies caps into its
            // CSpace: syscalls, and a failed copy's log line, under the
            // table lock (services/procmgr/README.md § Concurrency).
            handle_configure_pipe(&req, ipc_buf, ctx.self_aspace, &mut ctx.tables.lock().table);
        }

        procmgr_labels::CONFIGURE_NAMESPACE =>
        {
            handle_configure_namespace(&req, ipc_buf, &mut ctx.tables.lock().table);
        }

        procmgr_labels::REGISTER_DEATH_EQ =>
        {
            handle_register_death_eq(&req, ipc_buf);
        }

        procmgr_labels::QUERY_LIVE_PROCESSES =>
        {
            release_caps(req.caps());
            handle_query_live_processes(&req, ipc_buf, &ctx.tables.lock().table);
        }

        procmgr_labels::REGISTER_INIT_TEARDOWN =>
        {
            init_reap::handle_register(&req, ipc_buf, &ctx.deaths);
        }

        procmgr_labels::INIT_TEARDOWN_DONE =>
        {
            init_reap::handle_done(&req, ipc_buf);
        }

        procmgr_labels::QUERY_INIT_REAP =>
        {
            init_reap::handle_query(&req, ipc_buf);
        }

        // The debug-authority and thread-registry labels, and unknown opcodes.
        _ => dispatch_debug(&req, ipc_buf, &ctx.tables),
    }
}

/// Delete each nonzero slot in `caps` from procmgr's `CSpace`: the caps a
/// request transferred that its wire layout does not name, or every cap of a
/// refused request.
pub(crate) fn release_caps(caps: &[u64])
{
    for &slot in caps
    {
        if slot != 0
        {
            let _ = syscall::cap_delete(slot);
        }
    }
}

/// Handle `REGISTER_DEATH_EQ` — store the caller's `EventQueue` cap as
/// logd's death queue, to which every later teardown posts the dead
/// process's death entry (`process::forward_death_to_logd`).
///
/// Wire format:
/// * `caller badge` MUST equal `procmgr_labels::DEATH_EQ_AUTHORITY`
///   (who holds it is in `services/procmgr/docs/ipc-interface.md`
///   § `REGISTER_DEATH_EQ`).
/// * `caps[0]` = `EventQueue` cap with POST right.
///
/// Reply: `procmgr_errors::SUCCESS` once stored, `UNAUTHORIZED` if the
/// caller lacks the authority badge or a death EQ is already
/// registered, `INVALID_ARGUMENT` if no cap (or a zero cap) arrives.
/// Every refused request has its transferred caps deleted, and so do caps
/// past `caps[0]`.
fn handle_register_death_eq(req: &IpcMessage, ipc_buf: *mut u64)
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
    // install_logd_death_eq is first-wins: it stores the cap, or returns
    // false if a previous registration already filled the slot. Every
    // teardown after it reads the same atomic to forward the death.
    if process::install_logd_death_eq(logd_eq)
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

/// Dispatch the debug-authority labels, `REGISTER_CRASH_SERVICE`,
/// `ATTACH_PROCESS`, `LIST_PROCESSES`, `DETACH_PROCESS`, `DECLARE_NO_DEBUG`,
/// and `REGISTER_THREAD`, and answer any other opcode `UNKNOWN_OPCODE`,
/// deleting the caps it carried. Every label but `REGISTER_CRASH_SERVICE`,
/// which reads no table and calls the crash decliner, is served under the
/// table lock: each makes syscalls, its reply among them, and a failed
/// rebind's log line (services/procmgr/README.md § Concurrency).
fn dispatch_debug(req: &IpcMessage, ipc_buf: *mut u64, tables: &process::Tables)
{
    let label = req.label & 0xFFFF;
    if label == procmgr_labels::REGISTER_CRASH_SERVICE
    {
        handle_register_crash_service(req, ipc_buf);
        return;
    }
    let table = &mut tables.lock().table;
    match label
    {
        procmgr_labels::ATTACH_PROCESS =>
        {
            let (watch, extra) = req
                .caps()
                .split_first()
                .map_or((0, &[][..]), |(&c, rest)| (c, rest));
            release_caps(extra);
            match handle_attach_process(req, ipc_buf, table)
            {
                Some(badge) if watch != 0 => process::watch_debugger(table, badge, watch),
                _ => release_caps(&[watch]),
            }
        }
        procmgr_labels::LIST_PROCESSES =>
        {
            release_caps(req.caps());
            handle_list_processes(req, ipc_buf, table);
        }
        procmgr_labels::DETACH_PROCESS =>
        {
            release_caps(req.caps());
            handle_detach_process(req, ipc_buf, table);
        }
        procmgr_labels::REGISTER_THREAD => handle_register_thread(req, ipc_buf, table),
        procmgr_labels::DECLARE_NO_DEBUG =>
        {
            release_caps(req.caps());
            handle_declare_no_debug(req.badge, ipc_buf, table);
        }
        // `REGISTER_CRASH_SERVICE` is served above.
        _ =>
        {
            release_caps(req.caps());
            reply_empty(ipc_buf, procmgr_errors::UNKNOWN_OPCODE);
        }
    }
}

/// Handle `REGISTER_THREAD` — keep the sending thread's cap in its process's
/// registry (`process::register_thread`;
/// `services/procmgr/docs/ipc-interface.md` § `REGISTER_THREAD`). Caps past
/// `caps[0]`, and the cap of a refused request, are deleted.
fn handle_register_thread(req: &IpcMessage, ipc_buf: *mut u64, table: &mut process::ProcessTable)
{
    let (thread, extra) = req
        .caps()
        .split_first()
        .map_or((0, &[][..]), |(&t, rest)| (t, rest));
    release_caps(extra);
    let code = match process::register_thread(req.badge, thread, table)
    {
        Ok(()) => procmgr_errors::SUCCESS,
        Err(code) =>
        {
            release_caps(&[thread]);
            code
        }
    };
    reply_empty(ipc_buf, code);
}

/// Handle `REGISTER_CRASH_SERVICE` — hand the crash endpoint's receive side
/// to the caller (`services/procmgr/docs/ipc-interface.md`
/// § `REGISTER_CRASH_SERVICE`).
///
/// Wire format: the caller's badge carries `procmgr_labels::DEBUG_AUTHORITY`;
/// `caps[0]` is a Thread cap of the service's main thread. Reply: `SUCCESS`
/// with a `RECV` cap on the crash endpoint; `UNAUTHORIZED` without the
/// authority; `INVALID_ARGUMENT` without the thread cap or with no crash
/// endpoint; `CRASH_SERVICE_PRESENT` while a registered service lives;
/// `OUT_OF_MEMORY` when the `RECV` cap cannot be derived or the decliner
/// cannot be parked. Caps past `caps[0]`, and every cap of a refused
/// request, are deleted.
fn handle_register_crash_service(req: &IpcMessage, ipc_buf: *mut u64)
{
    let caps = req.caps();
    if !process_table::debug_authorized(req.badge)
    {
        release_caps(caps);
        reply_empty(ipc_buf, procmgr_errors::UNAUTHORIZED);
        return;
    }
    let (thread, extra) = caps
        .split_first()
        .map_or((0, &[][..]), |(&t, rest)| (t, rest));
    release_caps(extra);
    match crash::register(thread, ipc_buf)
    {
        Ok(registered) =>
        {
            let reply = IpcMessage::builder(procmgr_errors::SUCCESS)
                .cap(registered.recv)
                .build();
            // SAFETY: ipc_buf is the registered IPC buffer page.
            if unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_err()
            {
                // The caller holds no RECV cap, so the registration is
                // undone and the decliner receives again.
                let _ = syscall::cap_delete(registered.recv);
                crash::unregister(&registered);
                std::os::seraph::log!(warn: "crash service reply undeliverable; registration undone");
                return;
            }
            std::os::seraph::log!("crash service registered");
        }
        Err(refusal) =>
        {
            let code = match refusal
            {
                crash::RegisterRefusal::NoEndpointOrThread => procmgr_errors::INVALID_ARGUMENT,
                crash::RegisterRefusal::Present => procmgr_errors::CRASH_SERVICE_PRESENT,
                crash::RegisterRefusal::OutOfSlots => procmgr_errors::OUT_OF_MEMORY,
            };
            reply_empty(ipc_buf, code);
        }
    }
}

/// Handle `ATTACH_PROCESS` — reply with the Thread caps procmgr holds for a
/// process, from the index the request names, and where its image lies
/// (`services/procmgr/docs/ipc-interface.md` § `ATTACH_PROCESS`).
///
/// The list is the main thread at index 0, then each registered thread in
/// registration order, those that are gone swept out first, so no exited
/// thread is listed. The request's badge may be a thread crash badge, which
/// names its process and, in the reply's named-thread word, that thread.
/// Returns the target's process badge when the attach succeeded, the reply
/// delivered, for the caller to keep the debugger watch `caps[0]` carried.
fn handle_attach_process(
    req: &IpcMessage,
    ipc_buf: *mut u64,
    table: &mut process::ProcessTable,
) -> Option<u64>
{
    let (entry, named) = match process_table::attach_target(table, req.badge, req.word(0))
    {
        Ok(found) => found,
        Err(refusal) =>
        {
            let code = match refusal
            {
                process_table::AttachRefusal::Unauthorized => procmgr_errors::UNAUTHORIZED,
                process_table::AttachRefusal::Unknown => procmgr_errors::INVALID_BADGE,
                process_table::AttachRefusal::NotAttachable => procmgr_errors::NOT_ATTACHABLE,
            };
            reply_empty(ipc_buf, code);
            return None;
        }
    };
    let first = usize::try_from(req.word(1)).unwrap_or(usize::MAX);
    let mut page = Err(PageFailed::Gone);
    for _ in 0..ATTACH_PAGE_TRIES
    {
        entry.threads.sweep(
            |t| process::thread_is_listed(t.cap),
            process::release_registered_thread,
        );
        page = derive_attach_page(entry, first);
        if !matches!(page, Err(PageFailed::Gone))
        {
            break;
        }
    }
    let Ok((derived, n)) = page
    else
    {
        reply_empty(ipc_buf, procmgr_errors::OUT_OF_MEMORY);
        return None;
    };
    let mut reply = IpcMessage::builder(procmgr_errors::SUCCESS)
        .word(0, (entry.threads.len() as u64).saturating_add(1))
        .word(1, entry.image.load_bias)
        .word(2, entry.image.text_start)
        .word(3, entry.image.text_end)
        .word(4, entry.process_info_va)
        .word(procmgr_labels::ATTACH_WORD_PROCESS_BADGE, entry.badge())
        .word(
            procmgr_labels::ATTACH_WORD_NAMED_THREAD,
            named.index_in(entry),
        );
    // `n` counts slots of `derived`, so it is within the array.
    for &cap in derived.get(..n).unwrap_or_default()
    {
        reply = reply.cap(cap);
    }
    let badge = entry.badge();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if unsafe { ipc::ipc_reply(&reply.build(), ipc_buf) }.is_err()
    {
        // The caller holds none of the caps, so the attach did not succeed
        // and its watch is not kept.
        release_caps(derived.get(..n).unwrap_or_default());
        return None;
    }
    Some(badge)
}

/// Handle `LIST_PROCESSES` — reply with one page of live processes, in
/// ascending badge order after the cursor the request names, each with its
/// name (`services/procmgr/docs/ipc-interface.md` § `LIST_PROCESSES`).
/// Refused `UNAUTHORIZED` without `DEBUG_AUTHORITY`; `INVALID_ARGUMENT` for a
/// `data[0]` other than 0 or 1.
fn handle_list_processes(req: &IpcMessage, ipc_buf: *mut u64, table: &process::ProcessTable)
{
    if !process_table::debug_authorized(req.badge)
    {
        reply_empty(ipc_buf, procmgr_errors::UNAUTHORIZED);
        return;
    }
    let after = match req.word(0)
    {
        0 => None,
        1 => Some(req.word(1)),
        _ =>
        {
            reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
            return;
        }
    };
    let mut words = [0u64; syscall_abi::MSG_DATA_WORDS_MAX];
    let mut count = 0;
    for entry in table
        .entries_after(after)
        .take(procmgr_labels::LIST_PROCESSES_PAGE)
    {
        if procmgr_labels::pack_list_entry(&mut words, count, entry.badge(), entry.name.as_bytes())
        {
            // `count` is below `LIST_PROCESSES_PAGE`, the number of entries taken.
            count = count.saturating_add(1);
        }
    }
    words[0] = count as u64;
    let used = count
        .saturating_mul(procmgr_labels::LIST_PROCESSES_WORDS_PER_ENTRY)
        .saturating_add(1);
    let mut reply = IpcMessage::builder(procmgr_errors::SUCCESS);
    // `pack_list_entry` counted only the entries it fitted, so `used` is within `words`.
    for (i, &w) in words.get(..used).unwrap_or_default().iter().enumerate()
    {
        reply = reply.word(i, w);
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply.build(), ipc_buf) };
}

/// Handle `DETACH_PROCESS` — bind the process `data[0]` names back to the
/// crash endpoint (`process::restore_crash_bindings`;
/// `services/procmgr/docs/ipc-interface.md` § `DETACH_PROCESS`).
fn handle_detach_process(req: &IpcMessage, ipc_buf: *mut u64, table: &mut process::ProcessTable)
{
    let code = match process_table::detach_target(table, req.badge, req.word(0))
    {
        Ok(entry) =>
        {
            let badge = entry.badge();
            process::restore_crash_bindings(table, badge);
            procmgr_errors::SUCCESS
        }
        Err(process_table::AttachRefusal::Unauthorized) => procmgr_errors::UNAUTHORIZED,
        Err(process_table::AttachRefusal::Unknown) => procmgr_errors::INVALID_BADGE,
        Err(process_table::AttachRefusal::NotAttachable) => procmgr_errors::NOT_ATTACHABLE,
    };
    reply_empty(ipc_buf, code);
}

/// Times an attach sweeps and derives its page again when a registered
/// thread's cap went between its sweep and its derive (the runtime revoked
/// it, reclaiming the thread): each try sweeps that thread out, so a retry
/// fails only when another thread goes meanwhile.
const ATTACH_PAGE_TRIES: usize = 4;

/// Why [`derive_attach_page`] derived no page.
enum PageFailed
{
    /// A registered thread's cap went before its derive; sweep and retry.
    Gone,
    /// The derive of a cap that is there failed (`OUT_OF_MEMORY`).
    OutOfMemory,
}

/// Derive the caps of `entry`'s attach list from index `first`, at most
/// `ATTACH_THREADS_PAGE`: the main thread at 0, then the registered threads.
/// Returns them and their count; on failure, deletes the ones derived.
fn derive_attach_page(
    entry: &process::ProcessEntry,
    first: usize,
) -> Result<([u64; procmgr_labels::ATTACH_THREADS_PAGE], usize), PageFailed>
{
    let count = entry.threads.len().saturating_add(1);
    let mut derived = [0u64; procmgr_labels::ATTACH_THREADS_PAGE];
    let mut n = 0;
    for index in first..count.min(first.saturating_add(procmgr_labels::ATTACH_THREADS_PAGE))
    {
        let source = match index
        {
            0 => entry.thread_cap,
            _ => entry
                .threads
                .get(index.saturating_sub(1))
                .map_or(0, |t| t.cap),
        };
        let Ok(cap) = syscall::cap_derive(source, syscall_abi::RIGHTS_THREAD)
        else
        {
            release_caps(derived.get(..n).unwrap_or_default());
            return Err(
                if index > 0 && !process::thread_is_listed(source)
                {
                    PageFailed::Gone
                }
                else
                {
                    PageFailed::OutOfMemory
                },
            );
        };
        // The range holds at most `ATTACH_THREADS_PAGE` indices, so `n` is below the array length.
        let Some(slot) = derived.get_mut(n)
        else
        {
            let _ = syscall::cap_delete(cap);
            break;
        };
        *slot = cap;
        n = n.saturating_add(1);
    }
    Ok((derived, n))
}

/// Handle `DECLARE_NO_DEBUG` from the process `badge` names, on its own
/// procmgr cap: mark it undebuggable, delete the debugger watch an attach
/// left, unbind its main thread and every thread it registered from the
/// crash endpoint and from any debugger (`process::unbind_declared`), and
/// release the registered threads; the runtime copies a binding, unbound,
/// onto the threads it spawns after. Reply `SUCCESS`, or `INVALID_BADGE`
/// when the badge names no live process
/// (`services/procmgr/docs/ipc-interface.md` § `DECLARE_NO_DEBUG`).
fn handle_declare_no_debug(badge: u64, ipc_buf: *mut u64, table: &mut process::ProcessTable)
{
    let code = match table.declare_no_debug(badge)
    {
        Some(declared) =>
        {
            if declared.debugger != 0
            {
                let _ = syscall::cap_delete(declared.debugger);
            }
            if let Some(entry) = table.find_mut_by_badge(badge)
            {
                let registered = entry.threads.take_all();
                process::unbind_declared(entry, declared.thread_cap);
                for t in &registered
                {
                    process::unbind_declared(entry, t.cap);
                }
                registered
                    .into_iter()
                    .for_each(process::release_registered_thread);
            }
            procmgr_errors::SUCCESS
        }
        None => procmgr_errors::INVALID_BADGE,
    };
    reply_empty(ipc_buf, code);
}

/// Handle `QUERY_LIVE_PROCESSES` — reply with one page of live process
/// badges, in ascending order, after the cursor the request names
/// (`services/procmgr/docs/ipc-interface.md` § `QUERY_LIVE_PROCESSES`).
/// Refused `UNAUTHORIZED` unless the caller holds `DEATH_EQ_AUTHORITY`, since
/// a badge names a process handle; `INVALID_ARGUMENT` for a `data[0]` other
/// than 0 or 1.
fn handle_query_live_processes(req: &IpcMessage, ipc_buf: *mut u64, table: &process::ProcessTable)
{
    if req.badge != procmgr_labels::DEATH_EQ_AUTHORITY
    {
        reply_empty(ipc_buf, procmgr_errors::UNAUTHORIZED);
        return;
    }
    let after = match req.word(0)
    {
        0 => None,
        1 => Some(req.word(1)),
        _ =>
        {
            reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
            return;
        }
    };
    let mut page = [0u64; procmgr_labels::LIVE_PROCESSES_PAGE];
    let count = table.live_badges_after(after, &mut page);
    let mut reply = IpcMessage::builder(procmgr_errors::SUCCESS).word(0, count as u64);
    // `live_badges_after` fills at most `page.len()` slots and returns that count.
    for (i, &badge) in page.get(..count).unwrap_or_default().iter().enumerate()
    {
        // `i` is below `count`, so the sum is bounded by the page length.
        reply = reply.word(i.saturating_add(1), badge);
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply.build(), ipc_buf) };
}

/// Answer `QUERY_PROCESS` for the addressed entry, from `state`, the table
/// state the caller holds locked.
///
/// Consults the kernel for the authoritative thread-lifecycle snapshot
/// (`CAP_INFO_THREAD_STATE`) so a freshly-faulted child is reported as
/// EXITED even before procmgr's own death-event drain has reaped the
/// entry. Without this, the userspace death-eq drain races a parent's
/// "wait then `QUERY_PROCESS`" sequence and produces a transient ALIVE
/// answer for an already-dead child.
fn resolve_query_state(badge: u64, state: &mut process::TableState) -> (u64, u64)
{
    use ipc::procmgr_process_state;
    let process::TableState { table, recent } = state;
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
    else if let Some(reason) = recent.find(badge, now_ns())
    {
        (procmgr_process_state::EXITED, reason)
    }
    else
    {
        (procmgr_process_state::UNKNOWN, 0u64)
    }
}

/// Death-queue dispatch, on the reaper. Drains all pending death events on
/// every death queue, reaps each by correlator (the process badge), and
/// records the exit reason in the recent-exits ring for `QUERY_PROCESS`.
///
/// The drain moves the events into `batch` under the death-set lock, and
/// they are handled after it is released: a reap makes IPC calls to memmgr,
/// and the init reap takes the init-reap lock, which `REGISTER_INIT_TEARDOWN`
/// holds while it binds on the death set, so no handling runs under the
/// death-set lock. `batch` keeps its room from pass to pass. An event the
/// heap has no room for is dropped as a full queue drops a post, and the
/// pass resyncs.
///
/// A drain that takes [`death_queues::DEATH_EQ_CAPACITY`] events or more
/// from one queue may have followed a full queue, and the kernel drops a post
/// to a full queue. Any dropped post leaves at least a full queue of events
/// behind it, which this drain or the next one receives, so the drain that
/// crosses the capacity ends after the drop; [`resync_deaths`] then finds the
/// process whose post was lost.
fn dispatch_death(ctx: &ProcmgrCtx, ipc_buf: *mut u64, batch: &mut Vec<syscall::DeathEvent>)
{
    let memmgr_ep = ctx.memmgr_ep;
    batch.clear();
    let mut dropped = false;
    let full = lock(&ctx.deaths).drain(|death| {
        if batch.try_reserve(1).is_ok()
        {
            batch.push(death);
        }
        else
        {
            dropped = true;
        }
    });
    for death in batch.iter()
    {
        if death.correlator == procmgr_labels::INIT_REAP_CORRELATOR
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
        process::reap_dead(
            death.correlator,
            death.exit_reason,
            memmgr_ep,
            ipc_buf,
            &ctx.tables,
        );
    }
    if full || dropped
    {
        std::os::seraph::log!(warn: "a death queue drained full; resyncing the process table");
        resync_deaths(memmgr_ep, ipc_buf, &ctx.tables);
    }
}

/// Reap every live entry whose main thread the kernel reports exited, or
/// whose address space it reports took a terminal fault: the recovery for
/// the death posts a full queue dropped. Reads each entry's main-thread state
/// (`CAP_INFO_THREAD_STATE`) and its address space's terminal-fault reason
/// (`CAP_INFO_ASPACE_TERMINAL_FAULT`), both of which the kernel records
/// before it posts, so a process whose main-thread post, or whose
/// address-space post for a worker thread's fault, was dropped is found here
/// ([`process::resync_exit_reason`]). A process that exits or faults after
/// the scan posts to a queue this drain has emptied.
///
/// An init death the full queue dropped is not recovered here; init's reap
/// then waits, the benign hold of a handover that never completes
/// (`services/procmgr/README.md` § Init reap).
fn resync_deaths(memmgr_ep: u64, ipc_buf: *mut u64, tables: &process::Tables)
{
    let mut dead: Vec<(u64, u64)> = Vec::new();
    let mut short = false;
    // The scan reads kernel state only, under the table lock.
    tables.lock().table.for_each(|entry| {
        let main_thread =
            syscall::cap_info(entry.thread_cap, syscall_abi::CAP_INFO_THREAD_STATE).ok();
        let terminal_fault = syscall::cap_info(
            entry.aspace_cap,
            syscall_abi::CAP_INFO_ASPACE_TERMINAL_FAULT,
        )
        .ok();
        let Some(exit_reason) = process::resync_exit_reason(
            main_thread,
            syscall_abi::THREAD_STATE_EXITED,
            terminal_fault,
        )
        else
        {
            return;
        };
        if dead.try_reserve(1).is_ok()
        {
            dead.push((entry.badge(), exit_reason));
        }
        else
        {
            short = true;
        }
    });
    if short
    {
        std::os::seraph::log!(warn: "death resync could not list every dead process");
    }
    for (badge, exit_reason) in dead
    {
        process::reap_dead(badge, exit_reason, memmgr_ep, ipc_buf, tables);
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
    self_aspace: u64,
    table: &mut process::ProcessTable,
)
{
    let badge = req.badge;
    let direction = req.word(0);
    let caps = req.caps();
    let &[
        memory_cap,
        data_notification,
        space_notification,
        ref extra @ ..,
    ] = caps
    else
    {
        release_caps(caps);
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    };
    release_caps(extra);

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
    release_caps(&[memory_cap, data_notification, space_notification]);

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
    let Some(&root_cap) = caps.first()
    else
    {
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let cwd_cap = caps.get(1).copied().unwrap_or(0);
    release_caps(caps.get(2..).unwrap_or(&[]));
    let code = match table.configure_namespace(badge, root_cap, cwd_cap)
    {
        Ok(()) => procmgr_errors::SUCCESS,
        Err(code) => code,
    };
    reply_empty(ipc_buf, code);
}

/// The checks a create request passes before procmgr acquires anything for
/// the child: its scheduling fields ([`resolve_create_sched`]) and, when the
/// label sets `CREATE_ARGV_ENV`, the header of its argv and env, which starts
/// at data word `first_word`, against the `argv_env_cap` that holds them
/// (`process::check_argv_env`). Returns the resolved placement and the
/// checked argv/env request (`None` without the flag); `None` in place of
/// the pair means the request must be rejected with `INVALID_ARGUMENT`.
fn check_create_request(
    req: &IpcMessage,
    first_word: usize,
    argv_env_cap: u64,
    table: &process::ProcessTable,
) -> Option<(process::ChildSched, Option<process::ArgvEnvRequest>)>
{
    let sched = resolve_create_sched(req.label, req.badge, table)?;
    if req.label & procmgr_labels::CREATE_ARGV_ENV == 0
    {
        return Some((sched, None));
    }
    match process::check_argv_env(req, first_word, argv_env_cap)
    {
        Ok(request) => Some((sched, Some(request))),
        Err(refusal) =>
        {
            std::os::seraph::log!(warn: "create argv/env refused: {refusal:?}");
            None
        }
    }
}

/// Resolve the scheduling fields and the physical-address class of a create
/// label against the caller's spawn ceiling and class. `None` means the
/// request must be rejected with `INVALID_ARGUMENT`: still-reserved label bits
/// are set, the requested band exceeds the creator's, the requested priority
/// falls outside the resolved band, or `CREATE_PHYS_ACCESS` comes from a
/// creator that is not phys-class (`process_table::child_memmgr_flags`).
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
    let memmgr_flags =
        process_table::child_memmgr_flags(label, badge, table.memmgr_badge_by_badge(badge))?;
    Some(process::ChildSched {
        priority,
        band_max,
        memmgr_flags,
    })
}

/// Why [`arm_held_reclaim`] armed no hold.
#[derive(Clone, Copy)]
enum HoldRefusal
{
    /// The heap cannot reserve the room the child's parked record takes
    /// (`ArmError::OutOfMemory`).
    NoRoom,
    /// No live entry holds the child's badge (`ArmError::NotFound`), which
    /// the child's insertion just before rules out unless the table lost it.
    NotFound,
    /// The release token could not be derived; the hold is armed, and the
    /// child's destroy settles it.
    NoToken,
}

/// Arm the held reclaim of a child created with `CREATE_DMA_HOLD`, reserving
/// its record's room, so its teardown never has to free its frames for want
/// of a record, and derive the child's release token, the SEND on procmgr's
/// endpoint badged `badge | HOLD_RELEASE_AUTHORITY` on which alone
/// `RELEASE_HOLD` releases the hold. Returns the token's slot.
///
/// # Errors
/// The [`HoldRefusal`] naming why no hold is armed; the caller refuses the
/// create ([`refuse_unarmed_create`]).
fn arm_held_reclaim(result: &process::CreateResult, ctx: &ProcmgrCtx) -> Result<u64, HoldRefusal>
{
    let armed = ctx.tables.lock().table.arm_dma_hold(result.badge);
    armed.map_err(|e| match e
    {
        process_table::ArmError::OutOfMemory => HoldRefusal::NoRoom,
        process_table::ArmError::NotFound => HoldRefusal::NotFound,
    })?;
    syscall::cap_derive_badge(
        ctx.self_endpoint,
        syscall::RIGHTS_EP_SEND,
        process::release_token_badge(result.badge),
    )
    .map_err(|_| HoldRefusal::NoToken)
}

/// Refuse a `CREATE_DMA_HOLD` create whose hold [`arm_held_reclaim`] could
/// not arm, for the reason `why`: delete both reply caps, destroy the child,
/// which has not run (on `NotFound` the table holds no entry for the teardown
/// to take, so nothing more is released), and answer `OUT_OF_MEMORY`.
fn refuse_unarmed_create(
    result: &process::CreateResult,
    why: HoldRefusal,
    ipc_buf: *mut u64,
    ctx: &ProcmgrCtx,
)
{
    match why
    {
        HoldRefusal::NoRoom =>
        {
            std::os::seraph::log!(warn: "no room for a held reclaim; destroying the child");
        }
        HoldRefusal::NotFound =>
        {
            std::os::seraph::log!(warn: "held-reclaim child missing from the table; refusing the create");
        }
        HoldRefusal::NoToken =>
        {
            std::os::seraph::log!(warn: "release token not derived; destroying the child");
        }
    }
    let _ = syscall::cap_delete(result.thread_for_caller);
    let _ = syscall::cap_delete(result.process_handle);
    let _ = process::destroy_process(
        result.badge,
        ctx.memmgr_ep,
        ipc_buf,
        &ctx.tables,
        process::ExitRecord::Omit,
    );
    reply_empty(ipc_buf, procmgr_errors::OUT_OF_MEMORY);
}

/// Arm the held reclaim of a created child when its create `label` carries
/// `CREATE_DMA_HOLD` ([`arm_held_reclaim`]), then reply the creation
/// ([`reply_create_result`]), or refuse it when no hold can be armed.
fn arm_and_reply_create(
    label: u64,
    result: &process::CreateResult,
    ipc_buf: *mut u64,
    ctx: &ProcmgrCtx,
)
{
    let release_token = if label & procmgr_labels::CREATE_DMA_HOLD == 0
    {
        None
    }
    else
    {
        match arm_held_reclaim(result, ctx)
        {
            Ok(token) => Some(token),
            Err(why) =>
            {
                refuse_unarmed_create(result, why, ipc_buf, ctx);
                return;
            }
        }
    };
    reply_create_result(result, release_token, ipc_buf, ctx.memmgr_ep, &ctx.tables);
}

/// Reply with a successful process creation result, or destroy the child
/// when the reply cannot deliver it.
///
/// Reply caps: `[process_handle, thread, release_token?]`, the token only for a
/// `CREATE_DMA_HOLD` child. The reply's cap transfer is all-or-nothing: when
/// the caller's `CSpace` cannot take every cap (or the caller is gone), the
/// caller resumes with `IPC_REPLY_TRANSFER_FAILED` and no caps, and every cap
/// stays in procmgr's `CSpace`. No one then holds the handle that could start
/// or destroy the suspended child, so procmgr deletes the caps and tears the
/// child down as `DESTROY_PROCESS` does.
fn reply_create_result(
    result: &process::CreateResult,
    release_token: Option<u64>,
    ipc_buf: *mut u64,
    memmgr_ep: u64,
    tables: &process::Tables,
)
{
    let mut msg = IpcMessage::builder(procmgr_errors::SUCCESS)
        .cap(result.process_handle)
        .cap(result.thread_for_caller);
    if let Some(token) = release_token
    {
        msg = msg.cap(token);
    }
    let msg = msg.build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if unsafe { ipc::ipc_reply(&msg, ipc_buf) }.is_err()
    {
        std::os::seraph::log!(warn: "create reply undeliverable; destroying the child");
        let _ = syscall::cap_delete(result.thread_for_caller);
        let _ = syscall::cap_delete(result.process_handle);
        if let Some(token) = release_token
        {
            let _ = syscall::cap_delete(token);
        }
        // No handle to this child survives, so nothing can query its exit.
        let _ = process::destroy_process(
            result.badge,
            memmgr_ep,
            ipc_buf,
            tables,
            process::ExitRecord::Omit,
        );
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
///   bit  28       = `CREATE_DMA_HOLD` (hold the reclaim for `RELEASE_HOLD`)
///   bit  29       = `CREATE_ARGV_ENV` (argv and env in a Memory cap)
///   bit  30       = `CREATE_PHYS_ACCESS` (a phys-class child)
///   bits [31..64] = reserved (must be zero)
///
/// IPC data words: words `0..4` = the `ArgvEnvHeader` (`args_bytes`,
/// `args_count`, `env_bytes`, `env_count`), only with `CREATE_ARGV_ENV`.
///
/// Expects `caps = [module_memory, creator_endpoint?, argv_env?]`, the last
/// only with `CREATE_ARGV_ENV`; caps between the creator endpoint and it are
/// deleted. Stdio pipe wiring is installed via separate `CONFIGURE_PIPE`
/// IPCs (one per piped direction) on the returned badged `process_handle`
/// between create and `START_PROCESS`; the create path itself stays
/// stdio-agnostic.
fn handle_create(req: &IpcMessage, ipc_buf: *mut u64, ctx: &ProcmgrCtx)
{
    let label = req.label;
    let all_caps = req.caps();

    if all_caps.is_empty()
    {
        reply_empty(ipc_buf, procmgr_errors::INVALID_ELF);
        return;
    }

    // `CREATE_PROCESS` ignores `CREATE_DEATH_RELAY`, so only the argv/env
    // cap is peeled off the tail.
    let Some(caps) =
        process::split_create_caps(all_caps, process::CreateTailCaps::of_create_process(label))
    else
    {
        release_caps(all_caps);
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    };
    release_caps(caps.extra);
    let module_cap = caps.source;
    let creator_ep = caps.creator;

    // Resolve the scheduling fields and check the argv/env before any
    // resource acquisition. The transferred caps are procmgr's to release on
    // the reject path.
    let checked = check_create_request(req, 0, caps.argv_env, &ctx.tables.lock().table);
    let Some((sched, argv_env)) = checked
    else
    {
        release_caps(&[module_cap, creator_ep, caps.argv_env]);
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    };

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
    // returns every page already billed to the child) and drops the slot,
    // except after an argv/env copy window that would not unmap, whose
    // record `settle_failed_argv_env` withholds.
    let (memmgr_send, memmgr_badge) =
        register_with_memmgr(ctx.memmgr_ep, sched.memmgr_flags, ipc_buf);
    let mms = process::MemmgrSendGuard::new(memmgr_send, memmgr_badge, ctx.memmgr_ep, ipc_buf);

    // The child's checked copy of the argv and env, on its account. The
    // caller's cap is no longer needed once it is taken (or refused), so it
    // is deleted before any reply.
    let argv_env = match argv_env
    {
        Some(request) => process::copy_argv_env(ctx.self_aspace, mms.cap(), ipc_buf, &request),
        None => Ok(process::ChildArgvEnv::empty()),
    };
    release_caps(&[caps.argv_env]);
    let argv_env = match argv_env
    {
        Ok(argv_env) => argv_env,
        Err(e) =>
        {
            process::settle_failed_argv_env(mms, e);
            release_caps(&[module_cap, creator_ep]);
            reply_empty(ipc_buf, e.code());
            return;
        }
    };

    let universals = process::UniversalCaps {
        procmgr_endpoint: ctx.self_endpoint,
        log_send_source: ctx.log_ep,
        memmgr_endpoint: mms.cap(),
        memmgr_badge: mms.badge(),
        registry_send_source: ctx.registry_ep,
        sched_baseline: ctx.sched_baseline,
        paging: process::Paging::of_label(label),
        self_memmgr_ep: ctx.memmgr_ep,
    };

    let result = process::create_process(
        module_cap,
        ctx.self_aspace,
        ctx.memmgr_ep,
        ipc_buf,
        &ctx.tables,
        ctx.self_endpoint,
        creator_ep,
        &universals,
        argv_env,
        &ctx.deaths,
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
    if result.is_ok()
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
        Ok(result) =>
        {
            log_spawn_sched(sched);
            arm_and_reply_create(label, &result, ipc_buf, ctx);
        }
        // § Label 1 names `OUT_OF_MEMORY` for every creation failure past the
        // request's own checks, whatever the cause `create_process` reports.
        Err(_) =>
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
        debug: "spawn priority={} band=[1,{}]",
        sched.priority,
        sched.band_max
    );
}

/// Long-lived procmgr state every request worker and the reaper share. The
/// cap fields are fixed for the lifetime of the process; the death set and
/// the tables are behind their locks (services/procmgr/README.md
/// § Concurrency).
pub struct ProcmgrCtx
{
    pub self_aspace: u64,
    /// procmgr's own `CSpace`, whose headroom each request tops up.
    pub self_cspace: u64,
    pub self_endpoint: u64,
    /// Un-badged SEND cap on the log endpoint received from init
    /// during procmgr's own bootstrap. Procmgr uses it as the
    /// `cap_derive_badge` source for minting a badged SEND cap per
    /// child it spawns (badge = the child's process badge). The
    /// minted cap is placed in the child's `ProcessInfo.log_send_cap`.
    /// Zero if init did not provide one (very early boot); children
    /// born in that window receive zero and silent-drop
    /// `std::os::seraph::log!`.
    pub log_ep: u64,
    /// Un-badged SEND cap on svcmgr's service endpoint, received from init
    /// during procmgr's own bootstrap. Used as the `cap_derive_badge` source
    /// for minting a per-child badged SEND (badge = the child's process
    /// badge), installed in the child's `ProcessInfo.service_registry_cap`
    /// so the child can issue `svcmgr_labels::QUERY_ENDPOINT` against svcmgr
    /// for service-name lookups. Zero if init has not yet wired it; children
    /// born in that window receive zero and `registry_client::lookup` no-ops.
    pub registry_ep: u64,
    /// Badged SEND cap on memmgr's service endpoint, identifying procmgr.
    /// Used to mint per-child memmgr SENDs via `REGISTER_PROCESS`, to
    /// notify `PROCESS_DIED`, and as the destination for procmgr's own
    /// memory-cap allocations (memmgr auto-registers procmgr's badge at
    /// bootstrap so `REQUEST_MEMORY_CAPS` on this cap is allowed).
    pub memmgr_ep: u64,
    /// The death-notification event queues and the wait set that holds
    /// them alone (every queue under `WS_BADGE_DEATH`), which the reaper
    /// waits on. Every spawned child binds its main thread and its address
    /// space on the queues with `correlator = entry.badge`. A bind that grows
    /// the set funds the new queue or wait set from memmgr while the lock is
    /// held, an IPC call under a lock: memmgr calls no procmgr label, so the
    /// call cannot wait on the lock's holder. The init-reap lock is the one
    /// lock taken around this one (`init_reap::handle_register`); the table
    /// lock is never held with it.
    pub deaths: Mutex<death_set::DeathSet>,
    /// The process table and the recent-exits ring.
    pub tables: process::Tables,
    /// Procmgr's baseline `SchedControl` cap, delivered via its own
    /// `ProcessInfo.sched_control_cap` (band
    /// `[1, sched_policy::BASELINE_PRIORITY_MAX]`). The fan-out source for
    /// every child band (copied whole or copy-then-split narrowed) and the
    /// authority behind creating child threads at their assigned level.
    /// Zero if init delegated none; children are then created at the floor
    /// and cannot set any priority.
    pub sched_baseline: u64,
}

/// Handle `CREATE_FROM_FILE` — create a process from a caller-supplied file cap.
///
/// Wire layout: see [`procmgr_labels::CREATE_FROM_FILE`]. The caller has
/// already walked its own namespace cap to the binary node; procmgr never
/// touches the namespace tree on this path. procmgr owns every transferred
/// cap: the file cap is opened (`FS_OPEN`) and deleted, and procmgr's open
/// `FS_CLOSE`d and deleted after the load, the creator
/// endpoint is deleted once the child holds its own copy, the relay is
/// consumed by `finalize_creation` on success, and every other cap, and every
/// cap of a rejected request, is deleted here.
fn handle_create_from_file(req: &IpcMessage, ipc_buf: *mut u64, ctx: &ProcmgrCtx)
{
    let label = req.label;
    let all_caps = req.caps();

    // The death-relay POST cap, when present, is the LAST cap in the message
    // (see `CREATE_DEATH_RELAY`), and the argv/env cap the one before it,
    // both peeled off the tail so the `creator_endpoint` slot stays
    // positionally fixed at caps[1]. A request that flags a tail cap its caps
    // cannot supply apart from the file cap is malformed: taking that cap as
    // a tail cap too would release one slot twice.
    let Some(caps) = process::split_create_caps(
        all_caps,
        process::CreateTailCaps::of_create_from_file(label),
    )
    else
    {
        release_caps(all_caps);
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    };
    release_caps(caps.extra);

    // Resolve the scheduling fields and check the argv/env before any
    // resource acquisition. The transferred caps are procmgr's to release on
    // the reject path; the file cap is not opened yet, so the fs driver holds
    // no state for it.
    let checked = check_create_request(req, 1, caps.argv_env, &ctx.tables.lock().table);
    let Some((sched, argv_env)) = checked
    else
    {
        release_caps(&[caps.source, caps.creator, caps.argv_env, caps.relay]);
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    };

    let file_size = req.word(0);

    let result = process::create_process_from_file(
        ctx,
        caps.source,
        file_size,
        &ctx.tables,
        ipc_buf,
        caps.creator,
        argv_env.as_ref(),
        &ctx.deaths,
        process::Paging::of_label(label),
        caps.relay,
        sched,
    );

    // The child holds its own copies of the creator endpoint
    // (populate_child_info cap_copies it) and of the argv and env, or no
    // child exists, so procmgr's slots are released on both arms, as
    // handle_create does, before the reply.
    release_caps(&[caps.creator, caps.argv_env]);

    match result
    {
        Ok(result) =>
        {
            log_spawn_sched(sched);
            arm_and_reply_create(label, &result, ipc_buf, ctx);
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
