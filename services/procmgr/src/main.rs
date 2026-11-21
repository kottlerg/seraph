// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/src/main.rs

//! Seraph process manager — IPC server for process lifecycle management.
//!
//! Receives requests via IPC to create, configure, and start new processes.
//! Creates each from a signed object, a boot module's Memory cap or a file,
//! read once into memory of its own and verified against the trust store
//! before it is parsed ([`image`]). See `services/procmgr/docs/ipc-interface.md`.
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

mod arch;
mod crash;
mod death_queues;
mod image;
mod image_cache;
mod init_reap;
mod loader;
mod process;
mod snapshot;
mod trust_store;

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
///   caps[3]: map-only Memory cap on the `trust-store` boot module, with
///            data[0] the store's length in bytes ([`trust_store`]).
///            Absent when init holds no store; procmgr then stops.
struct InitBootstrap
{
    service_ep: u64,
    log_ep: u64,
    registry_ep: u64,
    /// The trust store's Memory cap and length in bytes.
    trust_store: Option<(u64, u64)>,
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
        trust_store: (round.cap_count >= 4 && round.data_words >= 1)
            .then(|| (round.caps[3], round.data[0])),
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

    // The trust store, copied and parsed once (docs/signing.md § Trust
    // Store); without one that parses procmgr stops, and creates no process.
    // Every create verifies its object against it.
    let Some((store_cap, store_len)) = boot.trust_store
    else
    {
        std::os::seraph::log!(error: "init handed no trust store; exiting");
        syscall::thread_exit();
    };
    let Some(trust_store) = trust_store::receive(startup.self_aspace, store_cap, store_len)
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
        trust_store,
        cert_cache: Mutex::new(objsig::CertificateCache::new()),
    }));

    // The memmgr record image objects are sealed on, before any create.
    image_cache::register_store(ctx.memmgr_ep, std::os::seraph::current_ipc_buf());

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
/// kernel stack, wrapper/TCB, extended-state save area, which the boot CPU sizes, and
/// with shadow stacks on a shadow-stack page), all consumed by the kernel. Queried once
/// and cached; `None` if the query fails, which fails the spawn.
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

/// Register a new child with memmgr as `budget` says
/// (`memmgr_labels::REGISTER_PROCESS`: its class and reserve membership in
/// the flags, its budget node's parent in `data[2]`, and its max in
/// `data[3]` with `REGISTER_MAX`, `REGISTER_NODE_HANDLE` for a creator that
/// asked for the child's node handle, and `REGISTER_CHARGE_NODE` with the
/// handle in `caps[0]` for one that charges the child to a node handle, which
/// the call moves to memmgr or this function deletes). On success returns the registration:
/// the SEND cap slot, the child's memmgr badge, the max the node took after
/// memmgr's clamp, and the node handle when asked for. On any failure (memmgr unwired, IPC error, a refused
/// parent, OOM) returns [`process::MemmgrRegistration::NONE`].
///
/// The cap slot lands in procmgr's `CSpace`; procmgr both:
///  * uses it for every per-child memory-cap allocation (so memmgr accounts
///    them to the child's record from the moment they leave the pool); and
///  * copies it into the child's `ProcessInfo.memmgr_endpoint_cap` so the
///    child's std heap-bootstrap can call `REQUEST_MEMORY_CAPS` on it.
///
/// The badge is opaque to procmgr, apart from the phys-class bit
/// `process_table::Creator::phys_class` reads. It is sent back in the
/// `PROCESS_DIED` payload at child teardown so memmgr can reclaim the
/// right record, and as the parent of the child's own children's nodes.
#[expect(
    clippy::not_unsafe_ptr_arg_deref,
    reason = "procmgr is a binary, not a library, and every caller passes its thread's registered \
              IPC buffer page as `ipc_buf`"
)]
pub fn register_with_memmgr(
    memmgr_ep: u64,
    budget: &process_table::ChildBudget,
    ipc_buf: *mut u64,
) -> process::MemmgrRegistration
{
    if memmgr_ep == 0
    {
        if budget.charge != 0
        {
            let _ = syscall::cap_delete(budget.charge);
        }
        return process::MemmgrRegistration::NONE;
    }
    let mut msg = IpcMessage::builder(memmgr_labels::REGISTER_PROCESS)
        .word(0, u64::from(ipc::MEMMGR_LABELS_VERSION))
        .word(1, budget.register_flags())
        .word(2, budget.parent)
        .word(3, budget.max.unwrap_or(0));
    if budget.charge != 0
    {
        msg = msg.cap(budget.charge);
    }
    let msg = msg.build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(memmgr_ep, &msg, ipc_buf) };
    let refusal = match &reply
    {
        Ok(reply) if reply.label == memmgr_errors::SUCCESS => None,
        Ok(reply) => Some(reply.label),
        Err(_) => Some(0),
    };
    if let Some(label) = refusal
    {
        // The charge node's handle is still procmgr's when the call did not
        // transfer it; deleting a moved slot is harmless.
        if budget.charge != 0
        {
            let _ = syscall::cap_delete(budget.charge);
        }
        if label != 0
        {
            std::os::seraph::log!(warn: "memmgr refused the child's registration ({label})");
        }
        return process::MemmgrRegistration::NONE;
    }
    let Ok(reply) = reply
    else
    {
        return process::MemmgrRegistration::NONE;
    };
    // With `REGISTER_NODE_HANDLE` the node handle is the second cap; a cap
    // past what was asked for is deleted.
    let node_handle = reply.caps().get(1).copied().unwrap_or(0);
    let node_handle = if budget.node_handle
    {
        node_handle
    }
    else
    {
        if node_handle != 0
        {
            let _ = syscall::cap_delete(node_handle);
        }
        0
    };
    process::MemmgrRegistration {
        cap: reply.caps().first().copied().unwrap_or(0),
        badge: reply.word(0),
        max: reply.word(1),
        node_handle,
    }
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

/// procmgr's own `CSpace` held above [`CSPACE_LOW_WATER`] general slots
/// (services/procmgr/README.md § `CSpace` headroom).
static HEADROOM: std::os::seraph::CSpaceHeadroom =
    std::os::seraph::CSpaceHeadroom::new(CSPACE_LOW_WATER, CSPACE_TOPUP_SLOTS);

/// Keep procmgr's own `CSpace` above [`CSPACE_LOW_WATER`] general slots.
/// Each request runs it before it is served; a worker that finds another
/// topping up goes on, since the low-water mark leaves room for every
/// worker's request. A failed top-up is retried on the next request, and the
/// log names only the first failure of a streak.
///
/// Returns [`process_table::Headroom::Short`] when the `CSpace` was short of
/// the mark and its top-up was refused. A request that would keep
/// capabilities in procmgr's `CSpace` in a number that grows with requests
/// is then refused: a create before it is served
/// ([`process_table::headroom_refusal`]), a thread registration at its
/// reservation (`process::register_thread`), so the slots left, and the IPC
/// receive reserve the next top-up's reply needs, are not taken.
fn hold_cspace_headroom(self_cspace: u64) -> process_table::Headroom
{
    let held = HEADROOM.hold(self_cspace);
    if HEADROOM.failure_to_report()
    {
        std::os::seraph::log!(warn: "CSpace headroom top-up failed; retrying each pass");
    }
    if held
    {
        process_table::Headroom::Held
    }
    else
    {
        process_table::Headroom::Short
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
#[expect(
    clippy::too_many_lines,
    reason = "one match arm per procmgr label, each a few lines that hand the request to its \
              handler; splitting the match would scatter the dispatch table"
)]
fn dispatch_ipc(req: &IpcMessage, ipc_buf: *mut u64, ctx: &ProcmgrCtx)
{
    let headroom = hold_cspace_headroom(ctx.self_cspace);
    // A crash service or a debugger watch that is a thread other than its
    // process's main thread posts no death when it exits, so every request
    // makes the checks before it is served, as the reaper does on a death.
    reap_checks(ctx);
    let mut req = *req;
    let label = req.label;
    // A process handle carries `PROCESS_HANDLE_TAG` beside its child's
    // badge. Every label is served under the child's badge alone, but the
    // three that name their sender, `DECLARE_NO_DEBUG`, `DECLARE_NO_CORE`
    // and `REGISTER_THREAD`, are refused on a handle, so its holder can
    // neither declare the child nor register a thread into the child's
    // registry, and `BIND_DEATH_OBSERVER` is refused on any other cap, so only the
    // creator chooses who observes the child.
    if let Some(code) = process_table::sender_refusal(label & 0xFFFF, req.badge)
    {
        release_caps(req.caps());
        reply_empty(ipc_buf, code);
        return;
    }
    if headroom == process_table::Headroom::Short
        && let Some(code) = process_table::headroom_refusal(label & 0xFFFF)
    {
        release_caps(req.caps());
        reply_empty(ipc_buf, code);
        return;
    }
    let (badge, _) = process_table::request_badge(req.badge);
    req.badge = badge;

    // Every cap a request transfers has already moved into procmgr's
    // CSpace. Each arm releases the caps its wire layout does not name, and
    // every cap on a reject arm, so a padded or refused request cannot grow
    // procmgr's CSpace (`services/procmgr/docs/ipc-interface.md`
    // § Capability Transfer).
    match label & 0xFFFF
    {
        procmgr_labels::CREATE_PROCESS =>
        {
            handle_create(&req, ipc_buf, ctx, ObjectSource::Module);
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
            // Badge from ipc_recv identifies which process to destroy, with
            // every process below it. Each exit is recorded like a reaped
            // death's, so a `QUERY_PROCESS` racing a death drain the destroy
            // overtook still answers `EXITED`.
            let _ = process::destroy_process(badge, ctx.memmgr_ep, ipc_buf, &ctx.tables);
            reply_empty(ipc_buf, procmgr_errors::SUCCESS);
            // A destroyed process may have been the crash service or an
            // attached debugger.
            reap_checks(ctx);
        }

        procmgr_labels::DESTROY_CHILD =>
        {
            release_caps(req.caps());
            // Served on a process handle alone (`sender_refusal`): the badge
            // names the parent, `data[0]` the child.
            let code =
                if process::destroy_child(badge, req.word(0), ctx.memmgr_ep, ipc_buf, &ctx.tables)
                {
                    procmgr_errors::SUCCESS
                }
                else
                {
                    procmgr_errors::INVALID_BADGE
                };
            reply_empty(ipc_buf, code);
            reap_checks(ctx);
        }

        procmgr_labels::LIST_CHILDREN =>
        {
            release_caps(req.caps());
            handle_list_children(&req, ipc_buf, ctx);
        }

        procmgr_labels::REGISTER_END_QUEUE =>
        {
            // A registration makes no syscall but the reply, under the table
            // lock.
            handle_register_end_queue(&req, ipc_buf, &mut ctx.tables.lock().table);
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

        procmgr_labels::BIND_DEATH_OBSERVER =>
        {
            // A bind makes syscalls only, under the table lock.
            handle_bind_death_observer(&req, ipc_buf, &ctx.tables.lock().table);
        }

        procmgr_labels::CREATE_FROM_FILE =>
        {
            handle_create(&req, ipc_buf, ctx, ObjectSource::File);
        }

        procmgr_labels::READ_VERIFIED =>
        {
            handle_read_verified(&req, ipc_buf, ctx);
        }

        procmgr_labels::SNAPSHOT =>
        {
            handle_snapshot(&req, ipc_buf, ctx);
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
        _ => dispatch_debug(&req, ipc_buf, &ctx.tables, ctx.memmgr_ep, headroom),
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
/// Reply: `procmgr_errors::SUCCESS` once stored, in place of the queue a
/// previous registration stored, whose cap is deleted
/// (`process::install_logd_death_eq`); `UNAUTHORIZED` if the caller lacks
/// the authority badge; `INVALID_ARGUMENT` if no cap (or a zero cap)
/// arrives. Every refused request has its transferred caps deleted, and so do
/// caps past `caps[0]`.
///
/// It writes no log line: the registering logd waits on this reply before its
/// receive workers take the log endpoint.
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
    // Every teardown from here on forwards its death to the new queue. The
    // replaced cap, the previous logd instance's, is no longer posted to.
    let replaced = process::install_logd_death_eq(logd_eq);
    if replaced != 0
    {
        let _ = syscall::cap_delete(replaced);
    }
    reply_empty(ipc_buf, procmgr_errors::SUCCESS);
}

/// Dispatch the debug-authority labels, `REGISTER_CRASH_SERVICE`,
/// `ATTACH_PROCESS`, `LIST_PROCESSES`, `DETACH_PROCESS`, `MAKE_RESIDENT`,
/// `MAKE_PRIVATE`, `DECLARE_NO_DEBUG`, `DECLARE_NO_CORE`, and
/// `REGISTER_THREAD`, and answer any other opcode `UNKNOWN_OPCODE`, deleting
/// the caps it carried. Every label but `REGISTER_CRASH_SERVICE`, which reads
/// no table and calls the crash decliner, and `MAKE_RESIDENT` and
/// `MAKE_PRIVATE`, which call memmgr at `memmgr_ep` after the lock, is served
/// under the table lock: each makes syscalls, its
/// reply among them, and a failed rebind's log line
/// (services/procmgr/README.md § Concurrency). `headroom` is the request's
/// hold of procmgr's `CSpace`, which `REGISTER_THREAD` reads.
fn dispatch_debug(
    req: &IpcMessage,
    ipc_buf: *mut u64,
    tables: &process::Tables,
    memmgr_ep: u64,
    headroom: process_table::Headroom,
)
{
    let label = req.label & 0xFFFF;
    if label == procmgr_labels::REGISTER_CRASH_SERVICE
    {
        handle_register_crash_service(req, ipc_buf);
        return;
    }
    if label == procmgr_labels::MAKE_RESIDENT
    {
        release_caps(req.caps());
        handle_make_resident(req, ipc_buf, tables, memmgr_ep);
        return;
    }
    if label == procmgr_labels::MAKE_PRIVATE
    {
        release_caps(req.caps());
        handle_make_private(req, ipc_buf, tables, memmgr_ep);
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
            handle_attach_process(req, ipc_buf, table, watch);
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
        procmgr_labels::REGISTER_THREAD => handle_register_thread(req, ipc_buf, table, headroom),
        procmgr_labels::DECLARE_NO_DEBUG =>
        {
            release_caps(req.caps());
            handle_declare_no_debug(req.badge, ipc_buf, table);
        }
        procmgr_labels::DECLARE_NO_CORE =>
        {
            release_caps(req.caps());
            // The mark is read by `ATTACH_PROCESS` alone
            // (`services/procmgr/docs/ipc-interface.md` § `DECLARE_NO_CORE`).
            let code = if table.declare_no_core(req.badge)
            {
                procmgr_errors::SUCCESS
            }
            else
            {
                procmgr_errors::INVALID_BADGE
            };
            reply_empty(ipc_buf, code);
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
/// `caps[0]`, and the cap of a refused request, are deleted. Under
/// [`process_table::Headroom::Short`] the registration is refused
/// `OUT_OF_MEMORY` at its reservation.
fn handle_register_thread(
    req: &IpcMessage,
    ipc_buf: *mut u64,
    table: &mut process::ProcessTable,
    headroom: process_table::Headroom,
)
{
    let (thread, extra) = req
        .caps()
        .split_first()
        .map_or((0, &[][..]), |(&t, rest)| (t, rest));
    release_caps(extra);
    let code = match process::register_thread(req.badge, thread, table, headroom)
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
/// `watch` is the debugger watch `caps[0]` carried (`0`: none), which this
/// takes: an attach that succeeds keeps it as the target's, from before its
/// reply is sent (`process::watch_debugger`), and every other deletes it.
fn handle_attach_process(
    req: &IpcMessage,
    ipc_buf: *mut u64,
    table: &mut process::ProcessTable,
    watch: u64,
)
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
            release_caps(&[watch]);
            reply_empty(ipc_buf, code);
            return;
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
        release_caps(&[watch]);
        reply_empty(ipc_buf, procmgr_errors::OUT_OF_MEMORY);
        return;
    };
    let reply = attach_reply(
        entry,
        named.index_in(entry),
        derived.get(..n).unwrap_or_default(),
    );
    let send = || {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_ok()
    };
    if !process::watch_debugger(entry, watch, send)
    {
        // The caller holds none of the caps, so the attach did not succeed,
        // and its watch is not kept.
        release_caps(derived.get(..n).unwrap_or_default());
    }
}

/// The `ATTACH_PROCESS` reply for `entry`: its thread count, image, badge,
/// the named thread's index `named`, its flags, and the thread caps
/// `caps`. Built apart from `handle_attach_process`, so the builder's
/// by-value steps do not share that function's stack frame.
#[inline(never)]
fn attach_reply(entry: &process::ProcessEntry, named: u64, caps: &[u64]) -> IpcMessage
{
    let mut reply = IpcMessage::builder(procmgr_errors::SUCCESS)
        .word(0, (entry.threads.len() as u64).saturating_add(1))
        .word(1, entry.image.load_bias)
        .word(2, entry.image.text_start)
        .word(3, entry.image.text_end)
        .word(4, entry.process_info_va)
        .word(procmgr_labels::ATTACH_WORD_PROCESS_BADGE, entry.badge())
        .word(procmgr_labels::ATTACH_WORD_NAMED_THREAD, named)
        .word(procmgr_labels::ATTACH_WORD_FLAGS, entry.attach_flags());
    for &cap in caps
    {
        reply = reply.cap(cap);
    }
    reply.build()
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

/// Handle `MAKE_RESIDENT` — have memmgr make the range `data[1]`, `data[2]`
/// (an address and a length) of the process `data[0]` names resident, so a
/// debugger whose `SYS_THREAD_READ_MEM` failed on a page of an evicted chunk
/// reads it when it retries (`services/procmgr/docs/ipc-interface.md`
/// § `MAKE_RESIDENT`). A process that declared itself undebuggable is served
/// too: making its pages resident reads and writes nothing of it, and only
/// does what its own next touch of them would. The target is found under the
/// table lock, and memmgr is called after it, as for `RELEASE_HOLD`. A
/// success carries memmgr's words 0 to 2: where it stopped, which the sender
/// asks again from until it is the range's end, whether it stopped at a chunk
/// on disk the swap service was asked to restore, and where its walk stopped.
fn handle_make_resident(
    req: &IpcMessage,
    ipc_buf: *mut u64,
    tables: &process::Tables,
    memmgr_ep: u64,
)
{
    if !process_table::debug_authorized(req.badge)
    {
        reply_empty(ipc_buf, procmgr_errors::UNAUTHORIZED);
        return;
    }
    let target = tables
        .lock()
        .table
        .find_by_badge(req.word(0))
        .map(|e| e.memmgr_badge);
    let (code, words) = match target
    {
        Some(badge) => process::make_resident(memmgr_ep, badge, req.word(1), req.word(2), ipc_buf),
        None => (procmgr_errors::INVALID_BADGE, [0; 3]),
    };
    if code != procmgr_errors::SUCCESS
    {
        reply_empty(ipc_buf, code);
        return;
    }
    let reply = IpcMessage::builder(code)
        .word(0, words[0])
        .word(1, words[1])
        .word(2, words[2])
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Handle `MAKE_PRIVATE` — have memmgr give each page of the range
/// `data[1]`, `data[2]` (an address and a length) of the process `data[0]`
/// names that maps a memory object's frame a copy of its own, so a debugger's
/// text write of `SYS_THREAD_WRITE_MEM` there patches that process alone
/// (`services/procmgr/docs/ipc-interface.md` § `MAKE_PRIVATE`). A process
/// that declared itself undebuggable is refused `NOT_ATTACHABLE`: no
/// debugger may write it, so the copies would only cost it memory. The target
/// is found under the table lock, and memmgr is called after it, as for
/// `MAKE_RESIDENT`. A success carries memmgr's word 0, where it stopped,
/// which the sender asks again from until it is the range's end.
fn handle_make_private(
    req: &IpcMessage,
    ipc_buf: *mut u64,
    tables: &process::Tables,
    memmgr_ep: u64,
)
{
    if !process_table::debug_authorized(req.badge)
    {
        reply_empty(ipc_buf, procmgr_errors::UNAUTHORIZED);
        return;
    }
    let target = tables
        .lock()
        .table
        .find_by_badge(req.word(0))
        .map(|e| (e.memmgr_badge, e.no_debug));
    let (code, reached) = match target
    {
        Some((_, true)) => (procmgr_errors::NOT_ATTACHABLE, 0),
        Some((badge, false)) =>
        {
            process::make_private(memmgr_ep, badge, req.word(1), req.word(2), ipc_buf)
        }
        None => (procmgr_errors::INVALID_BADGE, 0),
    };
    if code != procmgr_errors::SUCCESS
    {
        reply_empty(ipc_buf, code);
        return;
    }
    let reply = IpcMessage::builder(code).word(0, reached).build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
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

/// Handle `BIND_DEATH_OBSERVER` — bind the queue of `caps[0]` as a
/// terminal-end death observer, correlator `data[0]`, on the address
/// space of the child the process handle names
/// (`services/procmgr/docs/ipc-interface.md` § Label 25:
/// `BIND_DEATH_OBSERVER`). `dispatch_ipc` has refused it on any cap but a
/// process handle (`process_table::sender_refusal`); procmgr's own copy of
/// the child's address space keeps its `Control` right. The queue cap is
/// deleted on every path: the kernel binding holds its own reference to the
/// queue.
fn handle_bind_death_observer(req: &IpcMessage, ipc_buf: *mut u64, table: &process::ProcessTable)
{
    let caps = req.caps();
    let queue = caps.first().copied().unwrap_or(0);
    release_caps(caps.get(1..).unwrap_or(&[]));
    let code = if queue == 0
    {
        procmgr_errors::INVALID_ARGUMENT
    }
    else
    {
        match table.find_by_badge(req.badge)
        {
            None => procmgr_errors::INVALID_BADGE,
            Some(entry) =>
            {
                match syscall::aspace_bind_notification(entry.aspace_cap, queue, req.word(0))
                {
                    Ok(()) => procmgr_errors::SUCCESS,
                    Err(e) if e == syscall_abi::SyscallError::OutOfMemory as i64 =>
                    {
                        procmgr_errors::OUT_OF_MEMORY
                    }
                    Err(_) => procmgr_errors::INVALID_ARGUMENT,
                }
            }
        }
    };
    if queue != 0
    {
        let _ = syscall::cap_delete(queue);
    }
    reply_empty(ipc_buf, code);
}

/// Handle `LIST_CHILDREN` — reply with one page of the children of the
/// process the handle names, each with its name and its subtree's pages
/// (`services/procmgr/docs/ipc-interface.md` § Label 27: `LIST_CHILDREN`).
/// `dispatch_ipc` has refused it on any cap but a process handle.
///
/// The page is read under the table lock: each child's badge, its name, and a
/// copy of procmgr's memmgr SEND for it, badged with the child's memmgr
/// badge. After the release each copy's `QUERY_MEMORY_USAGE` reads the
/// child's subtree pages, `data[2]` of the reply, and the copy is deleted:
/// the call to memmgr waits on no lock, and a child torn down meanwhile
/// leaves its copy valid, which memmgr then answers for an unknown badge,
/// listed as `0`. `INVALID_BADGE` when the handle names no live process;
/// `INVALID_ARGUMENT` for a `data[0]` other than 0 or 1.
fn handle_list_children(req: &IpcMessage, ipc_buf: *mut u64, ctx: &ProcmgrCtx)
{
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
    let mut page =
        [(0u64, process_table::ProcessName::EMPTY, 0u64); procmgr_labels::LIST_CHILDREN_PAGE];
    let mut count = 0usize;
    {
        let state = ctx.tables.lock();
        if state.table.find_by_badge(req.badge).is_none()
        {
            drop(state);
            reply_empty(ipc_buf, procmgr_errors::INVALID_BADGE);
            return;
        }
        for (slot, child) in page
            .iter_mut()
            .zip(state.table.children_after(req.badge, after))
        {
            let usage = if child.memmgr_send_cap == 0
            {
                0
            }
            else
            {
                syscall::cap_derive(child.memmgr_send_cap, syscall::RIGHTS_EP_SEND).unwrap_or(0)
            };
            *slot = (child.badge(), child.name, usage);
            // `count` counts the slots of `page`, so it cannot overflow.
            count = count.saturating_add(1);
        }
    }
    let mut words = [0u64; syscall_abi::MSG_DATA_WORDS_MAX];
    for (index, (badge, name, usage)) in page.iter().take(count).enumerate()
    {
        let pages = subtree_pages(*usage, ipc_buf);
        if *usage != 0
        {
            let _ = syscall::cap_delete(*usage);
        }
        // `LIST_CHILDREN_PAGE` entries fit the data words after the count.
        let _ = procmgr_labels::pack_child_entry(&mut words, index, *badge, name.as_bytes(), pages);
    }
    words[0] = count as u64;
    let used = count
        .saturating_mul(procmgr_labels::LIST_CHILDREN_WORDS_PER_ENTRY)
        .saturating_add(1);
    let mut reply = IpcMessage::builder(procmgr_errors::SUCCESS);
    for (i, &w) in words.get(..used).unwrap_or_default().iter().enumerate()
    {
        reply = reply.word(i, w);
    }
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&reply.build(), ipc_buf) };
}

/// The pages charged to the budget node, and every node below it, of the
/// process whose memmgr badge `usage` (a SEND on memmgr's endpoint) carries:
/// `data[2]` of its `QUERY_MEMORY_USAGE` reply; `0` for no cap, a refusal
/// (memmgr no longer knows the badge), or a failed call.
fn subtree_pages(usage: u64, ipc_buf: *mut u64) -> u64
{
    if usage == 0
    {
        return 0;
    }
    let msg = IpcMessage::new(memmgr_labels::QUERY_MEMORY_USAGE);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    match unsafe { ipc::ipc_call(usage, &msg, ipc_buf) }
    {
        Ok(reply) if reply.label == memmgr_errors::SUCCESS => reply.word(2),
        _ => 0,
    }
}

/// Handle `REGISTER_END_QUEUE` — record `caps[0]` as the sender's end
/// queue, posted `data[0]` as the correlator with its end
/// (`services/procmgr/docs/ipc-interface.md` § Label 29:
/// `REGISTER_END_QUEUE`). `dispatch_ipc` has refused it on a process
/// handle, so the badge is the sender's own. Replies `SUCCESS`;
/// `INVALID_ARGUMENT` without a queue cap; `INVALID_BADGE` when the badge
/// names no live process (the un-badged creator's); `END_QUEUE_PRESENT` when
/// the sender registered one before. Caps past `caps[0]`, and the queue of a
/// refused request, are deleted.
fn handle_register_end_queue(req: &IpcMessage, ipc_buf: *mut u64, table: &mut process::ProcessTable)
{
    let caps = req.caps();
    let queue = caps.first().copied().unwrap_or(0);
    release_caps(caps.get(1..).unwrap_or(&[]));
    let code = if queue == 0
    {
        procmgr_errors::INVALID_ARGUMENT
    }
    else
    {
        match table.register_end_queue(req.badge, queue, req.word(0))
        {
            Ok(()) => procmgr_errors::SUCCESS,
            Err(process_table::EndQueueRefusal::NotFound) => procmgr_errors::INVALID_BADGE,
            Err(process_table::EndQueueRefusal::Present) => procmgr_errors::END_QUEUE_PRESENT,
        }
    };
    if code != procmgr_errors::SUCCESS && queue != 0
    {
        let _ = syscall::cap_delete(queue);
    }
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
/// Consults the kernel for the authoritative records, the main thread's
/// lifecycle snapshot (`CAP_INFO_THREAD_STATE`) and the address space's
/// terminal end (`CAP_INFO_ASPACE_END`), so a child whose main thread exited
/// or any of whose threads took a terminal fault or exited the process is
/// reported
/// as EXITED even before procmgr's own death-event drain has reaped the
/// entry (`process_table::QueryEntry::state`). Without this, the userspace
/// death-eq drain races a parent's "wait then `QUERY_PROCESS`" sequence and
/// produces a transient ALIVE answer for an already-dead child. The first
/// `EXITED` answer for a live entry fixes its reason
/// (`ProcessTable::latch_end`), which later answers and its reap or destroy
/// carry, so an end of the address space after a main-thread exit the query
/// already reported changes no answer.
fn resolve_query_state(badge: u64, state: &mut process::TableState) -> (u64, u64)
{
    use ipc::procmgr_process_state;
    let process::TableState { table, recent } = state;
    if let Some(entry) = table.query_by_badge(badge)
    {
        let main_thread =
            syscall::cap_info(entry.thread_cap, syscall_abi::CAP_INFO_THREAD_STATE).ok();
        let aspace_end = syscall::cap_info(entry.aspace_cap, syscall_abi::CAP_INFO_ASPACE_END).ok();
        match entry.state(main_thread, syscall_abi::THREAD_STATE_EXITED, aspace_end)
        {
            process::QueryState::Exited(reason) => (
                procmgr_process_state::EXITED,
                table.latch_end(badge, reason),
            ),
            process::QueryState::Alive => (procmgr_process_state::ALIVE, 0u64),
            process::QueryState::Created => (procmgr_process_state::CREATED, 0u64),
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
/// whose address space it reports ended: the recovery for the death posts a
/// full queue dropped. Reads each entry's main-thread state
/// (`CAP_INFO_THREAD_STATE`) and its address space's terminal end
/// (`CAP_INFO_ASPACE_END`), both of which the kernel records before it
/// posts, so a process whose main-thread post, or whose address-space post
/// for a worker thread's fault or process exit, was dropped is found here
/// ([`process::resync_exit_reason`]). A process that exits or faults after
/// the scan posts to a queue this drain has emptied.
///
/// An init death the full queue dropped is not recovered here; init's reap
/// then waits, the benign hold of a handover that never completes
/// (`services/procmgr/README.md` § Init reap).
fn resync_deaths(memmgr_ep: u64, ipc_buf: *mut u64, tables: &process::Tables)
{
    let mut dead: Vec<(u64, u64)> = Vec::new();
    // The scan reads kernel state only, under the table lock
    // (`ProcessTable::resync_dead`).
    let listed_all = tables.lock().table.resync_dead(
        syscall_abi::THREAD_STATE_EXITED,
        |entry| {
            (
                syscall::cap_info(entry.thread_cap, syscall_abi::CAP_INFO_THREAD_STATE).ok(),
                syscall::cap_info(entry.aspace_cap, syscall_abi::CAP_INFO_ASPACE_END).ok(),
            )
        },
        &mut dead,
    );
    if !listed_all
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

/// A create request that passed [`check_create_request`].
struct CheckedCreate<'a>
{
    /// The child's placement, with its creator's signature policy.
    sched: process::ChildSched,
    /// The checked argv/env request; `None` without `CREATE_ARGV_ENV`.
    argv_env: Option<process::ArgvEnvRequest>,
    /// The name the creator expects the object to be signed under.
    name: &'a [u8],
}

/// The checks a create request passes before procmgr acquires anything for
/// the child: its creator, scheduling fields, memory max, class and
/// signature policy ([`resolve_create_sched`]), its name block, which must
/// hold a name in the canonical form
/// (`process_table::sign_policy::requested_name`), and, when the label sets
/// `CREATE_ARGV_ENV`, the header of its argv and env against the
/// `argv_env_cap` that holds them (`process::check_argv_env`). Its data
/// word 0, the object's length, must be nonzero. `None` means the request
/// must be rejected with `INVALID_ARGUMENT`.
fn check_create_request<'a>(
    req: &'a IpcMessage,
    argv_env_cap: u64,
    table: &process::ProcessTable,
) -> Option<CheckedCreate<'a>>
{
    let sched = resolve_create_sched(req, table)?;
    let Some(name) = process_table::sign_policy::requested_name(req)
    else
    {
        std::os::seraph::log!(warn: "create without a name in the canonical form refused");
        return None;
    };
    if req.word(0) == 0
    {
        std::os::seraph::log!(warn: "create of a zero-length object refused");
        return None;
    }
    let argv_env = if req.label & procmgr_labels::CREATE_ARGV_ENV == 0
    {
        None
    }
    else
    {
        match process::check_argv_env(req, procmgr_labels::CREATE_FIRST_WORD, argv_env_cap)
        {
            Ok(request) => Some(request),
            Err(refusal) =>
            {
                std::os::seraph::log!(warn: "create argv/env refused: {refusal:?}");
                return None;
            }
        }
    };
    Some(CheckedCreate {
        sched,
        argv_env,
        name,
    })
}

/// Resolve a create request against its creator: the scheduling fields
/// against the creator's spawn ceiling, and the child's memmgr registration
/// (its budget node's parent, its max, reserve membership and class) against
/// the creator's node and class; the child's signature policy starts as the
/// creator's (`process_table::Creator::sign_roles`). `None` means the request
/// must be rejected with
/// `INVALID_ARGUMENT`: still-reserved label bits are set, the badge names no
/// creator (`process_table::ProcessTable::creator_of`), the requested band
/// exceeds the creator's, the requested priority falls outside the resolved
/// band, `CREATE_MEMORY_MAX` comes without its word, `CREATE_PHYS_ACCESS`
/// or `CREATE_RESERVE` comes from a creator that may not ask for it, or
/// `CREATE_RESERVE` comes with `CREATE_CHARGE_NODE`
/// (`process_table::child_budget`).
///
/// Creator: badge `0` is init (the unbadged service-endpoint holder), or
/// svcmgr's un-badged mint source, with the full baseline ceiling, and its
/// children not charged to a node handle are top-level reserve nodes; a
/// charged child sits under the handle's node outside the reserve. A nonzero
/// badge is a live procmgr-spawned process, whose ceiling is its own minted
/// band and under whose node the child's sits. Any other badge (a reaped process's own cap or
/// handle, a verb-badged cap, a release token) is refused: its child would
/// escape every memory max.
fn resolve_create_sched(
    req: &IpcMessage,
    table: &process::ProcessTable,
) -> Option<process::ChildSched>
{
    let label = req.label;
    if label & procmgr_labels::CREATE_RESERVED_MASK != 0
    {
        return None;
    }
    let Some(creator) = table.creator_of(req.badge)
    else
    {
        std::os::seraph::log!(warn: "create from a badge that names no live process refused");
        return None;
    };
    let requested_priority = ((label >> procmgr_labels::CREATE_PRIORITY_SHIFT)
        & procmgr_labels::CREATE_SCHED_FIELD_MASK) as u8;
    let requested_band = ((label >> procmgr_labels::CREATE_BAND_MAX_SHIFT)
        & procmgr_labels::CREATE_SCHED_FIELD_MASK) as u8;
    let (priority, band_max) = process::resolve_spawn_sched(
        requested_priority,
        requested_band,
        creator.band_max,
        ipc::sched_policy::DEFAULT_SPAWN_PRIORITY,
    )?;
    let budget = process_table::decode_memory_max(req, procmgr_labels::CREATE_FIRST_WORD)
        .and_then(|max| process_table::child_budget(label, max, &creator));
    let budget = match budget
    {
        Ok(budget) => budget,
        Err(refusal) =>
        {
            std::os::seraph::log!(warn: "create budget refused: {refusal:?}");
            return None;
        }
    };
    Some(process::ChildSched {
        priority,
        band_max,
        budget,
        sign_roles: creator.sign_roles,
        creator: req.badge,
        contained: label & procmgr_labels::CREATE_CONTAIN != 0,
    })
}

/// Why [`arm_held_reclaim`] armed no hold.
#[derive(Clone, Copy)]
enum HoldRefusal
{
    /// The heap cannot reserve the room the child's parked record takes
    /// (`ArmError::OutOfMemory`).
    NoRoom,
    /// No live entry holds the child's badge (`ArmError::NotFound`). The
    /// child's insertion just before rules it out: until the create is
    /// answered only the create's own refusal takes the entry
    /// (`ProcessEntry::unanswered`), a destroy that marks it meanwhile
    /// included, so this arm is reached only if the table lost the entry.
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
    if result.node_handle != 0
    {
        let _ = syscall::cap_delete(result.node_handle);
    }
    process::destroy_created(result.badge, ctx.memmgr_ep, ipc_buf, &ctx.tables);
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
/// when the reply cannot deliver it or a destroy has marked it.
///
/// The reply is made under the table lock, through
/// `ProcessTable::answer_create`, so a destroy marks the child either
/// before the reply, which is then not made and the create is refused with
/// `INVALID_ARGUMENT`, as for a create a destroy marked before its insert,
/// or after it, once the creator holds the child. Until the answer the
/// destroy leaves the entry to this create, so a refused create deletes the
/// death relay unposted. `ipc_reply` does not block on the caller.
///
/// Reply caps: `[process_handle, thread, release_token?, node_handle?]`, the
/// token only for a `CREATE_DMA_HOLD` child and the node handle only for a
/// `CREATE_NODE_HANDLE` one; `data[0]` is the max the child's memmgr budget
/// node took, `u64::MAX` for none. The reply's cap transfer is all-or-nothing: when
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
        .word(0, result.memory_max)
        .cap(result.process_handle)
        .cap(result.thread_for_caller);
    if let Some(token) = release_token
    {
        msg = msg.cap(token);
    }
    if result.node_handle != 0
    {
        msg = msg.cap(result.node_handle);
    }
    let msg = msg.build();
    let answer = tables.lock().table.answer_create(result.badge, || {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        unsafe { ipc::ipc_reply(&msg, ipc_buf) }.is_ok()
    });
    if answer != process_table::CreateAnswer::Answered
    {
        if answer == process_table::CreateAnswer::Undelivered
        {
            std::os::seraph::log!(warn: "create reply undeliverable; destroying the child");
        }
        let _ = syscall::cap_delete(result.thread_for_caller);
        let _ = syscall::cap_delete(result.process_handle);
        if let Some(token) = release_token
        {
            let _ = syscall::cap_delete(token);
        }
        if result.node_handle != 0
        {
            let _ = syscall::cap_delete(result.node_handle);
        }
        // No handle to this child survives, so nothing can query its exit.
        process::destroy_created(result.badge, memmgr_ep, ipc_buf, tables);
        if answer == process_table::CreateAnswer::Refused
        {
            reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        }
    }
}

/// Where a create request's object comes from: the source cap, `caps[0]`, of
/// `CREATE_PROCESS` or of `CREATE_FROM_FILE`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ObjectSource
{
    /// A Memory cap holding the object from its first byte (a boot module).
    Module,
    /// A file node cap on the caller's fs driver.
    File,
}

/// Handle `CREATE_PROCESS` (`source` [`ObjectSource::Module`]) and
/// `CREATE_FROM_FILE` (`source` [`ObjectSource::File`]): create a suspended
/// process from a signed object, verified before any of it is parsed
/// (docs/signing.md § Verifier Discipline).
///
/// Wire layout: see [`procmgr_labels::CREATE_PROCESS`] and
/// [`procmgr_labels::CREATE_FROM_FILE`]; both lay out their data words alike:
/// word 0 the object's length, then the argv/env header, the memory max and
/// the name block, each present or not. Caps: `[source, creator_endpoint?,
/// charge?, argv_env?, relay?]`, `charge` only with `CREATE_CHARGE_NODE`,
/// `argv_env` only with `CREATE_ARGV_ENV` and `relay` only with
/// `CREATE_DEATH_RELAY`; caps between the creator endpoint and them are
/// deleted. procmgr owns every transferred cap: the source is deleted once
/// its object is copied (a file's opened, read and closed first), the creator
/// endpoint once the child holds its own copy, the argv/env cap once its
/// blobs are copied, the charge node's handle goes to memmgr with the
/// registration, and the relay is kept in the child's table entry by
/// `finalize_creation` on success; every cap of a refused request is
/// deleted here. Stdio pipe
/// wiring is installed by separate `CONFIGURE_PIPE` IPCs on the returned
/// `process_handle` between create and `START_PROCESS`.
fn handle_create(req: &IpcMessage, ipc_buf: *mut u64, ctx: &ProcmgrCtx, source: ObjectSource)
{
    let label = req.label;
    let all_caps = req.caps();

    // A request that flags a tail cap its caps cannot supply apart from the
    // source cap is malformed: taking that cap as a tail cap too would
    // release one slot twice.
    let Some(caps) =
        process::split_create_caps(all_caps, process::CreateTailCaps::of_create(label))
    else
    {
        release_caps(all_caps);
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    };
    release_caps(caps.extra);

    // Resolve the scheduling fields, the name and the argv/env before any
    // resource acquisition. The transferred caps are procmgr's to release on
    // the reject path; a file cap is not opened yet, so its fs driver holds
    // no state for it.
    let checked = check_create_request(req, caps.argv_env, &ctx.tables.lock().table);
    let Some(mut checked) = checked
    else
    {
        release_caps(&[
            caps.source,
            caps.creator,
            caps.argv_env,
            caps.relay,
            caps.charge,
        ]);
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    };
    checked.sched.budget.charge = caps.charge;

    let request = CreateRequest {
        label,
        source,
        source_cap: process::CapGuard::new(caps.source),
        len: req.word(0),
        name: checked.name,
        creator_ep: caps.creator,
        argv_env: checked.argv_env,
        argv_env_cap: caps.argv_env,
        relay: caps.relay,
    };
    let result = create_child(ctx, request, &mut checked.sched, ipc_buf);

    // The child holds its own copies of the creator endpoint and of the argv
    // and env, or no child exists, so procmgr's slots are released on both
    // arms before the reply. The charge node's handle went to memmgr with the
    // registration, or is released here when the create failed before it
    // (deleting a moved slot is harmless).
    release_caps(&[caps.creator, caps.argv_env, caps.charge]);

    match result
    {
        Ok(result) =>
        {
            arm_and_reply_create(label, &result, ipc_buf, ctx);
            log_spawn(&result, checked.sched);
        }
        Err(code) =>
        {
            // `finalize_creation` moves the relay into the child's table
            // entry only once that entry exists, which every error return
            // precedes; procmgr's copy is dropped here.
            release_caps(&[caps.relay]);
            reply_empty(ipc_buf, code);
        }
    }
}

/// Handle `READ_VERIFIED`: read the data file `caps[0]` names once into one
/// run of frames on the sender's memmgr account, verify the copy in the data
/// role under the name the request gives, and give the sender the run
/// read-only (docs/signing.md § Verifier Discipline). Wire layout:
/// [`procmgr_labels::READ_VERIFIED`].
///
/// The sender's memmgr SEND is derived under the table lock, so a teardown of
/// the sender that deletes its own slot meanwhile leaves this request a cap
/// that names the same account, or one memmgr refuses, never another cap
/// that took the slot. The read and the verification hold no lock. The file
/// cap is deleted on every path (opened, read and closed first once the
/// request is admitted), and every cap past it at once. A run the reply
/// cannot deliver is released to the sender's account here.
fn handle_read_verified(req: &IpcMessage, ipc_buf: *mut u64, ctx: &ProcmgrCtx)
{
    let caps = req.caps();
    let file_cap = caps.first().copied().unwrap_or(0);
    release_caps(caps.get(1..).unwrap_or(&[]));
    let read = process_table::sign_policy::data_read(req).filter(|_| file_cap != 0);
    let Some(read) = read
    else
    {
        release_caps(&[file_cap]);
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    };
    let memmgr = {
        let state = ctx.tables.lock();
        state
            .table
            .find_by_badge(req.badge)
            .map(|entry| entry.memmgr_send_cap)
            .map(|cap| {
                if cap == 0
                {
                    None
                }
                else
                {
                    syscall::cap_derive(cap, syscall::RIGHTS_ALL).ok()
                }
            })
    };
    let memmgr = match memmgr
    {
        Some(Some(cap)) => process::CapGuard::new(cap),
        Some(None) =>
        {
            release_caps(&[file_cap]);
            reply_empty(ipc_buf, procmgr_errors::OUT_OF_MEMORY);
            return;
        }
        None =>
        {
            release_caps(&[file_cap]);
            reply_empty(ipc_buf, procmgr_errors::INVALID_BADGE);
            return;
        }
    };
    let result = image::read_file(
        ctx.self_aspace,
        file_cap,
        read.len,
        memmgr.cap(),
        ipc_buf,
        image::Shape::Contiguous,
    )
    .and_then(|buffer| {
        let body_len = image::verify(
            ctx,
            buffer.bytes(),
            read.name,
            process_table::sign_policy::DATA,
        )
        .map_err(|_| procmgr_errors::SIGNATURE_REFUSED)?
        .body
        .len();
        let run = buffer.into_read_only()?;
        Ok((body_len, run))
    });
    match result
    {
        Ok((body_len, run)) =>
        {
            let reply = IpcMessage::builder(procmgr_errors::SUCCESS)
                .word(0, body_len as u64)
                .word(1, run.region)
                .word(2, run.pages)
                .cap(run.cap)
                .build();
            // SAFETY: ipc_buf is the registered IPC buffer page.
            if unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_err()
            {
                // The cap stayed in procmgr's CSpace: the sender is gone or
                // could not take it, so the run goes back to its account.
                let _ = syscall::cap_delete(run.cap);
                let msg = IpcMessage::builder(memmgr_labels::RELEASE_MEMORY_CAPS)
                    .word(0, 1)
                    .word(1, run.region)
                    .build();
                // SAFETY: ipc_buf is the registered IPC buffer page.
                let _ = unsafe { ipc::ipc_call(memmgr.cap(), &msg, ipc_buf) };
            }
        }
        Err(code) => reply_empty(ipc_buf, code),
    }
}

/// Handle `SNAPSHOT`: capture the live process `data[0]` names into a memory
/// object sealed on the account `caps[0]`, a memmgr SEND the sender presents
/// ([`snapshot::capture`]; `services/procmgr/docs/ipc-interface.md`
/// § Label 33: `SNAPSHOT`). Wire layout: [`procmgr_labels::SNAPSHOT`].
///
/// The request is checked, and the target's address-space and thread caps
/// derived (the main thread, then each registered thread the sweep leaves
/// listed), under the table lock, so a teardown of the target meanwhile
/// leaves caps that name its objects or that the kernel refuses, never
/// another cap that took the slot. The capture holds no lock, and takes this
/// worker for its length. The account cap is deleted on every path, and
/// every cap past it at once. An object the reply cannot deliver is released.
fn handle_snapshot(req: &IpcMessage, ipc_buf: *mut u64, ctx: &ProcmgrCtx)
{
    let caps = req.caps();
    let account = process::CapGuard::new(caps.first().copied().unwrap_or(0));
    release_caps(caps.get(1..).unwrap_or(&[]));
    let mut image_ref = 0;
    let target = {
        let table = &mut ctx.tables.lock().table;
        process_table::snapshot_target(table, req.badge, req.word(0), account.cap())
            .map_err(process_table::SnapshotRefusal::code)
            .and_then(|entry| {
                let derive = |cap| {
                    process::CapGuard::new(
                        syscall::cap_derive(cap, syscall::RIGHTS_ALL).unwrap_or(0),
                    )
                };
                let (aspace, thread) = (derive(entry.aspace_cap), derive(entry.thread_cap));
                if aspace.cap() == 0 || thread.cap() == 0
                {
                    return Err(procmgr_errors::OUT_OF_MEMORY);
                }
                image_ref = entry.image_ref;
                Ok(snapshot::Target {
                    aspace,
                    thread,
                    registered: derive_registered(entry)?,
                    memmgr_badge: entry.memmgr_badge,
                    load_bias: entry.image.load_bias,
                    image: None,
                })
            })
    };
    // The image, by the target's reference, under the cache's lock alone: a
    // teardown meanwhile drops the reference, and the capture then names no
    // image, memmgr writing the pages it attaches as any other object's.
    let target = target.map(|mut target| {
        target.image =
            image_cache::snapshot_image(image_ref).map(|(handle, key)| snapshot::TargetImage {
                handle: process::CapGuard::new(handle),
                image: ipc::procmgr_snapshot::Image {
                    hash: key.hash,
                    len: key.len,
                },
            });
        target
    });
    let capture = snapshot::Context {
        self_aspace: ctx.self_aspace,
        memmgr_ep: ctx.memmgr_ep,
        ipc_buf,
    };
    match target.and_then(|target| snapshot::capture(&capture, &target, account.cap()))
    {
        Ok(captured) =>
        {
            let complete = if captured.complete
            {
                ipc::procmgr_snapshot::SNAPSHOT_COMPLETE
            }
            else
            {
                0
            };
            let reply = IpcMessage::builder(procmgr_errors::SUCCESS)
                .word(0, captured.pages)
                .word(1, complete)
                .cap(captured.handle)
                .build();
            // SAFETY: ipc_buf is the registered IPC buffer page.
            if unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_err()
            {
                // The handle stayed in procmgr's CSpace: the sender is gone or
                // could not take it, so the object goes.
                snapshot::release_object(captured.handle, ipc_buf);
            }
        }
        Err(code) => reply_empty(ipc_buf, code),
    }
}

/// Observe caps to `entry`'s registered threads, swept first so no thread
/// that exited is listed, each with its `ATTACH_PROCESS` index, for a
/// `SNAPSHOT` to record their state. A thread whose cap the runtime revoked
/// since the sweep has none, as one that exited.
///
/// # Errors
/// `OUT_OF_MEMORY` when the heap refuses the list.
fn derive_registered(entry: &mut process::ProcessEntry)
-> Result<Vec<snapshot::TargetThread>, u64>
{
    entry.threads.sweep(
        |t| process::thread_is_listed(t.cap),
        process::release_registered_thread,
    );
    let mut out = Vec::new();
    out.try_reserve_exact(entry.threads.len())
        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    for i in 0..entry.threads.len()
    {
        let Some(thread) = entry.threads.get(i)
        else
        {
            break;
        };
        if let Ok(cap) = syscall::cap_derive(thread.cap, syscall_abi::RIGHTS_THREAD_OBSERVE)
        {
            out.push(snapshot::TargetThread {
                index: (i as u64).saturating_add(1),
                cap: process::CapGuard::new(cap),
            });
        }
    }
    Ok(out)
}

/// What [`create_child`] takes from a checked create request.
struct CreateRequest<'a>
{
    label: u64,
    source: ObjectSource,
    /// The source cap, deleted when the guard drops, after the object is
    /// read or on any earlier failure.
    source_cap: process::CapGuard,
    /// The object's length in bytes, data word 0.
    len: u64,
    /// The name the object must be signed under.
    name: &'a [u8],
    creator_ep: u64,
    argv_env: Option<process::ArgvEnvRequest>,
    argv_env_cap: u64,
    relay: u64,
}

/// Create the child of a checked request: register it with memmgr, copy its
/// argv and env, read its object once into a buffer on its account
/// ([`image::read_module`], [`image::read_file`]), verify the copy under the
/// request's name and `sched`'s signature policy ([`image::verify`]), narrow
/// the policy by the verified role set, and load the verified body
/// (`process::create_process_from_bytes`), its read-only segments shared with
/// the binary's other instances unless the label sets
/// `procmgr_labels::CREATE_PRIVATE_IMAGE`. The buffer goes back to memmgr
/// before the registration settles. Single exit: any failure, a refused
/// signature among them, creates nothing and releases what it took.
///
/// # Errors
/// `OUT_OF_MEMORY` when memmgr does not register the child; the argv/env
/// copy's code ([`process::ArgvEnvCopyError::code`]); the read's code;
/// `SIGNATURE_REFUSED` when the object does not verify; the load's code.
fn create_child(
    ctx: &ProcmgrCtx,
    request: CreateRequest<'_>,
    sched: &mut process::ChildSched,
    ipc_buf: *mut u64,
) -> Result<process::CreateResult, u64>
{
    // memmgr's badged SEND for the child: every page procmgr takes for the
    // child, the object's buffer included, is billed to the child's record
    // from the moment it leaves the pool. The guard owns the registration
    // until the child's table entry does: on a failed create it retires the
    // record (PROCESS_DIED, which returns every page already billed to the
    // child) and drops the slot, except after an argv/env copy window that
    // would not unmap, whose record `settle_failed_argv_env` withholds.
    let registration = register_with_memmgr(ctx.memmgr_ep, &sched.budget, ipc_buf);
    let mms = process::MemmgrSendGuard::new(registration, ctx.memmgr_ep, ipc_buf);
    if mms.cap() == 0
    {
        return Err(procmgr_errors::OUT_OF_MEMORY);
    }

    // The child's checked copy of the argv and env, on its account; a
    // malformed blob refuses the create here. The caller's cap is no longer
    // needed once it is taken.
    let argv_env = match &request.argv_env
    {
        Some(argv_env) => process::copy_argv_env(ctx.self_aspace, mms.cap(), ipc_buf, argv_env),
        None => Ok(process::ChildArgvEnv::empty()),
    };
    release_caps(&[request.argv_env_cap]);
    let argv_env = match argv_env
    {
        Ok(argv_env) => argv_env,
        Err(e) =>
        {
            process::settle_failed_argv_env(mms, e);
            return Err(e.code());
        }
    };

    // Declared after `mms`, so on every exit the buffer drops first: its
    // frames are unmapped, their caps deleted and their runs released before
    // the registration's `PROCESS_DIED` or the child's entry takes over.
    let buffer = match request.source
    {
        ObjectSource::Module =>
        {
            let buffer = image::read_module(
                ctx.self_aspace,
                request.source_cap.cap(),
                request.len,
                mms.cap(),
                ipc_buf,
            );
            drop(request.source_cap);
            buffer
        }
        ObjectSource::File => image::read_file(
            ctx.self_aspace,
            request.source_cap.disarm(),
            request.len,
            mms.cap(),
            ipc_buf,
            image::Shape::BestEffort,
        ),
    }?;
    let verified = image::verify(ctx, buffer.bytes(), request.name, sched.sign_roles)
        .map_err(|_| procmgr_errors::SIGNATURE_REFUSED)?;
    sched.sign_roles =
        process_table::sign_policy::child_roles(sched.sign_roles, verified.attrs.roles);

    let universals = process::UniversalCaps {
        procmgr_endpoint: ctx.self_endpoint,
        log_send_source: ctx.log_ep,
        memmgr_endpoint: mms.cap(),
        memmgr_badge: mms.badge(),
        memmgr_max: mms.max(),
        registry_send_source: ctx.registry_ep,
        sched_baseline: ctx.sched_baseline,
        paging: process::Paging::of_label(request.label),
        self_memmgr_ep: ctx.memmgr_ep,
    };
    // A creator's private image shares nothing; the others name the binary by
    // its signed body (services/procmgr/README.md § Image Sharing).
    let image_key = (request.label & procmgr_labels::CREATE_PRIVATE_IMAGE == 0).then_some(
        process_table::image_share::ImageKey {
            hash: verified.attrs.body_hash,
            len: verified.attrs.body_len,
        },
    );
    let mut result = process::create_process_from_bytes(
        verified.body,
        ctx.self_aspace,
        &ctx.tables,
        ctx.self_endpoint,
        request.creator_ep,
        &universals,
        argv_env,
        &ctx.deaths,
        request.relay,
        *sched,
        image_key.as_ref(),
        ipc_buf,
    );
    // The segments are copied into the child's own frames or the image
    // object's; the buffer's frames go back to memmgr before the registration
    // settles.
    drop(buffer);
    mms.settle(&mut result);
    result
}

/// Log a created child's image bias and its scheduling placement, after the
/// create's reply: the creator then goes on while a line waits on logd, which
/// matters when the child is logd's next instance, created while no logd
/// receives, whose creator, svcmgr, would otherwise wait out the line's bound
/// (`LOG_CALL_TIMEOUT_MS`) before it can start it. The bias line is the one a
/// debugger reads the image's placement from
/// (`docs/userspace-memory-model.md` § Image Placement), and names the child,
/// since concurrent creates interleave their lines; no `ProcessInfo`
/// field carries the bias, and an `ET_EXEC` image, at bias 0, has none. The
/// scheduling line evidences every process's level and band in the boot log,
/// since no syscall reads a priority back.
fn log_spawn(result: &process::CreateResult, sched: process::ChildSched)
{
    if result.image_bias != 0
    {
        std::os::seraph::log!(
            "spawn image bias=0x{:x} ({})",
            result.image_bias,
            String::from_utf8_lossy(result.name.as_bytes())
        );
    }
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
    /// The trust store every create's object is verified against
    /// ([`image::verify`]), parsed once from procmgr's copy, which lives for
    /// procmgr's life.
    pub trust_store: objsig::TrustStore<'static>,
    /// The certificates whose signature has verified, so the certificate
    /// every object of one signer carries is checked once; a memo, copied
    /// out and back by each verification ([`image::verify`]).
    pub cert_cache: Mutex<objsig::CertificateCache>,
}
