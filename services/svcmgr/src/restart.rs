// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/src/restart.rs

//! Service death handling and restart logic.
//!
//! Whether a crashed service is restarted is decided solely by its restart
//! policy + budget; `system_critical` decides only what happens once the
//! service is permanently down (continue, or graceful shutdown). On restart
//! svcmgr re-creates the process via procmgr, replays the recipe's
//! argv/env/cwd/seed surfaces, its scheduling fields (`priority`,
//! `sched_max`), its create flags (`reserve`, the node handle an
//! `oom_stop` service is created with, and the containment of a
//! `stop_source` service), its log-sink flag and its
//! debug-, stop- and entropy-authority caps, binds the new instance's death observers
//! before it starts, and serves its bootstrap.
//!
//! Bootstrap delivery re-resolves the recipe's `seed` caps (the log-sink
//! service instead gets a round minted from the reserved log-sink sources).
//! log and procmgr endpoints arrive via `ProcessInfo`, so they are not part
//! of the restart cap set.

use crate::definitions::launch::{
    LaunchKind, assemble_boot_caps, delete_caps, mint_logd_boot_caps, resolve_seeds,
    serve_boot_slots,
};
use crate::definitions::{build_blob, cwd_rights};
use crate::service::{Bootstrap, POLICY_ALWAYS, POLICY_ON_FAILURE, RestartRecipe, ServiceEntry};
use ipc::bootstrap::ServeFailure;
use ipc::{IpcMessage, procmgr_errors, procmgr_labels};
use std::os::seraph::process::ArgvEnvCap;
use svcmgr_defs::DeathTag;
use syscall_abi::SyscallError;

/// Outcome of [`handle_death`], routed by the caller (`dispatch_deaths`
/// in `main.rs`) to either continue, log degradation, or initiate a
/// graceful system shutdown through the shutdown actuator.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeathOutcome
{
    /// Service was successfully restarted.
    Restarted,
    /// Service is marked inactive; system continues degraded.
    Degraded,
    /// Service was `system_critical` and svcmgr cannot recover it
    /// (restart not attempted, budget exhausted, or restart failed).
    /// Caller must ask the shutdown actuator to power the system off.
    Unrecoverable,
}

/// Result of a successful `CREATE_FROM_FILE` reply, shared by the
/// restart path and the post-handover launch path.
pub struct CreatedProcess
{
    pub process_handle: u64,
    pub thread_cap: u64,
    pub child_badge: u64,
    /// The node handle of the child's budget node, the reply's last cap, when
    /// the create asked for it (`procmgr_labels::CREATE_NODE_HANDLE`); `0`
    /// otherwise. The caller releases it on every path that destroys the
    /// child.
    pub node_handle: u64,
}

/// Allocate a fresh bootstrap badge — a random `u64` from the kernel entropy
/// pool, redrawn off the reserved `0` value (an unbadged SEND carries badge 0)
/// — and mint a badged SEND on `bootstrap_ep` for a soon-to-spawn child. Every
/// child that receives its bootstrap rounds on svcmgr's `bootstrap_ep` gets a
/// distinct badge so svcmgr can correlate each round to the right service entry.
/// Random rather than monotonic so the service-spawn count it would otherwise
/// leak stays unguessable; svcmgr matches each round by exact badge value, never
/// by index. The `u64` width is the kernel badge word, so the space never runs
/// out. Returns `None` if the entropy draw or cap derivation fails.
pub fn mint_child_creator(bootstrap_ep: u64) -> Option<(u64, u64)>
{
    let mut badge = syscall::random_u64().ok()?;
    while badge == 0
    {
        badge = syscall::random_u64().ok()?;
    }
    let badged = syscall::cap_derive_badge(bootstrap_ep, syscall::RIGHTS_EP_SEND, badge).ok()?;
    Some((badge, badged))
}

/// Argv and env blobs seeded into a child at `CREATE_FROM_FILE` time.
///
/// Each blob is NUL-separated and NUL-terminated (the shape procmgr's
/// `CREATE_ARGV_ENV` checks); `count` is the number of entries in the blob.
/// An empty blob with `count = 0` skips that surface entirely — the child
/// inherits no argv / no env from svcmgr.
#[derive(Default, Clone, Copy)]
pub struct StartupBlobs<'a>
{
    pub argv: &'a [u8],
    pub argv_count: u64,
    pub env: &'a [u8],
    pub env_count: u64,
}

/// Mint a `DEBUG_AUTHORITY` `SEND|GRANT` on procmgr for a `debug_authority`
/// service's bootstrap round, from the un-badged procmgr source init endows;
/// `GRANT` because `REGISTER_CRASH_SERVICE` transfers a cap. `0` when the
/// source is absent or the derive fails, and the slot is then absent.
pub(crate) fn mint_debug_authority(ctx: &RestartCtx) -> u64
{
    if ctx.procmgr_death_auth_source == 0
    {
        return 0;
    }
    syscall::cap_derive_badge(
        ctx.procmgr_death_auth_source,
        syscall::RIGHTS_EP_SEND_GRANT,
        procmgr_labels::DEBUG_AUTHORITY,
    )
    .unwrap_or(0)
}

/// Mint a `STOP_AUTHORITY` SEND on svcmgr's own service endpoint for a
/// `stop_authority` service's bootstrap round. `0` when the derive fails,
/// and the slot is then absent.
pub(crate) fn mint_stop_authority(ctx: &RestartCtx) -> u64
{
    syscall::cap_derive_badge(
        ctx.service_ep,
        syscall::RIGHTS_EP_SEND,
        ipc::stop_labels::STOP_AUTHORITY,
    )
    .unwrap_or(0)
}

/// Derive the `EntropyControl` copy carrying `Contribute` for the
/// `entropy_authority` service's bootstrap round, from the source init
/// endows. `0` when the source is absent or the derive fails, and the slot is
/// then absent.
pub(crate) fn mint_entropy_authority(ctx: &RestartCtx) -> u64
{
    if ctx.entropy_source == 0
    {
        return 0;
    }
    syscall::cap_derive(ctx.entropy_source, syscall::RIGHTS_ENTROPY_CONTRIBUTE).unwrap_or(0)
}

/// Mint a receive-only derivation of the queue svcmgr's own death posts to,
/// for the bootstrap round of the shutdown actuator, which observes svcmgr
/// through it (docs/supervision.md § Observing svcmgr). `0` when svcmgr has
/// no such queue or the derive fails, and the slot is then absent.
pub(crate) fn mint_self_death_recv(ctx: &RestartCtx) -> u64
{
    if ctx.self_death_queue == 0
    {
        return 0;
    }
    syscall::cap_derive(ctx.self_death_queue, syscall::RIGHTS_EQ_RECV).unwrap_or(0)
}

/// The `CREATE_FROM_FILE` request labelled `label` for `file` (its file
/// cap, its size, and the path walked to it, the name it is verified under),
/// with creator endpoint `badged_creator` and the argv/env cap when present.
/// Caps: `[file_cap, badged_creator, argv_env?]`; the header rides in data
/// words 1..5, after `file_size`, and the path in the name block after them.
/// `None` when the path does not fit a name block.
#[expect(
    clippy::large_stack_frames,
    reason = "the builder's by-value copies (568 B each) across the header and the name block, and \
              the built `IpcMessage`; on the 32 KiB main-thread stack of svcmgr"
)]
fn create_msg(
    label: u64,
    file: (u64, u64, &str),
    badged_creator: u64,
    argv_env: Option<&ArgvEnvCap>,
) -> Option<IpcMessage>
{
    let (file_cap, file_size, path) = file;
    let mut builder = IpcMessage::builder(label)
        .word(0, file_size)
        .cap(file_cap)
        .cap(badged_creator);
    if let Some(cap) = argv_env
    {
        builder = builder
            .words(procmgr_labels::CREATE_FIRST_WORD, &cap.header_words())
            .cap(cap.cap());
    }
    Some(procmgr_labels::with_create_name(builder, label, path.as_bytes())?.build())
}
/// Walk svcmgr's root for `path`, then call procmgr `CREATE_FROM_FILE`.
/// Returns the freshly created (suspended) process, or `None` (each arm
/// logged) when the argv/env cap cannot be built
/// (`std::os::seraph::process::ArgvEnvCap`: blobs past the argv/env region,
/// which the `.svc` parser already refuses, or a run memmgr will not fund),
/// the bootstrap-badge mint fails, svcmgr has no root cap, the walk fails,
/// or the create call fails in transport, in procmgr, or with a reply short
/// of its two caps. Every `None` arm releases the file and badged-creator caps it
/// still holds, and the short-reply arm destroys the child procmgr created.
/// An error reply carries no handle to destroy and needs none: when procmgr
/// created the child but the reply's cap transfer into svcmgr's `CSpace`
/// failed, svcmgr receives `IPC_REPLY_TRANSFER_FAILED` with zero caps, and
/// procmgr destroys the child it could not hand over.
/// Caller is responsible for `CONFIGURE_NAMESPACE`, bootstrap delivery, and
/// `START_PROCESS`.
///
/// `path` is interpreted relative to svcmgr's own `root_dir_cap`
/// (universal), so callers pass paths exactly
/// as they appear in `.svc` files — e.g. `"/services/logd"`.
///
/// `blobs` carries argv/env for the child. Both paths build them from
/// the recipe: launch from the parsed `Definition`, restart from the
/// stored [`RestartRecipe`]. A caller with no recipe (defensive) passes
/// [`StartupBlobs::default`] for empty surfaces.
///
/// `label_bits` are the create label's fields beyond the opcode and
/// `CREATE_ARGV_ENV`, which [`create_label_bits`] builds from the recipe:
/// its scheduling fields, whose values above svcmgr's own band ceiling make
/// procmgr reject the create with `INVALID_ARGUMENT`, and its create flags
/// (`svcmgr_defs::create_flags`). With `CREATE_NODE_HANDLE` among them the
/// reply's last cap is the child's node handle, returned in
/// [`CreatedProcess::node_handle`]; a reply without it is logged and the
/// child runs with none.
pub fn walk_and_create_from_file(
    path: &str,
    blobs: StartupBlobs<'_>,
    label_bits: u64,
    procmgr_ep: u64,
    bootstrap_ep: u64,
    ipc_buf: *mut u64,
) -> Option<CreatedProcess>
{
    // The argv/env cap holds both blobs; `ArgvEnvCap::settle` once the
    // create call returns gives its run back to memmgr (procmgr has copied
    // the blobs by then, or refused the request), or withholds it on
    // `ARGV_ENV_STILL_MAPPED`.
    let argv_env = match ArgvEnvCap::new(blobs.argv, blobs.argv_count, blobs.env, blobs.env_count)
    {
        Ok(cap) => cap,
        Err(e) =>
        {
            std::os::seraph::log!(warn: "create: {path:?} argv/env cap failed: {e}");
            return None;
        }
    };

    let Some((child_badge, badged_creator)) = mint_child_creator(bootstrap_ep)
    else
    {
        std::os::seraph::log!(warn: "create: bootstrap badge mint failed");
        return None;
    };

    let root_cap = std::os::seraph::root_dir_cap();
    if root_cap == 0
    {
        std::os::seraph::log!(warn: "create: no root_dir_cap configured");
        let _ = syscall::cap_delete(badged_creator);
        return None;
    }
    let (file_cap, file_size) = match std::os::seraph::namespace_lookup_file(root_cap, path)
    {
        Ok(p) => p,
        Err(e) =>
        {
            std::os::seraph::log!(warn: "create: NS_LOOKUP {path:?} failed: {e}");
            let _ = syscall::cap_delete(badged_creator);
            return None;
        }
    };

    let argv_env_flag = if argv_env.is_some()
    {
        procmgr_labels::CREATE_ARGV_ENV
    }
    else
    {
        0
    };
    let label = procmgr_labels::CREATE_FROM_FILE | label_bits | argv_env_flag;

    let Some(create_msg) = create_msg(
        label,
        (file_cap, file_size, path),
        badged_creator,
        argv_env.as_ref(),
    )
    else
    {
        std::os::seraph::log!(warn: "create: {path:?} too long a name to verify");
        delete_caps(&[file_cap, badged_creator]);
        return None;
    };

    // A failed call may leave `file_cap` and `badged_creator` in svcmgr's
    // CSpace: a transport error, or a post-block refusal that delivers the
    // request with zero caps and draws an error reply. Deleting a slot the
    // kernel already transferred is a generation-checked no-op.
    // SAFETY: `ipc_buf` is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(procmgr_ep, &create_msg, ipc_buf) };
    if let Some(argv_env) = argv_env
    {
        argv_env.settle(reply.as_ref().map_or(0, |r| r.label));
    }
    let reply = match reply
    {
        Ok(r) => r,
        Err(e) =>
        {
            std::os::seraph::log!(warn: "create: CREATE_FROM_FILE ipc failed (err={e})");
            delete_caps(&[file_cap, badged_creator]);
            return None;
        }
    };
    if reply.label == ipc::procmgr_errors::SIGNATURE_REFUSED
    {
        std::os::seraph::log!(warn: "create: {path:?} refused: its signature did not verify");
        delete_caps(&[file_cap, badged_creator]);
        delete_caps(reply.caps());
        return None;
    }
    if reply.label != 0
    {
        std::os::seraph::log!(warn: "create: CREATE_FROM_FILE returned {:#x}", reply.label);
        delete_caps(&[file_cap, badged_creator]);
        delete_caps(reply.caps());
        return None;
    }
    let reply_caps = reply.caps();
    let &[process_handle, thread_cap, ..] = reply_caps
    else
    {
        std::os::seraph::log!(warn: "create: reply missing caps");
        // A label-0 reply means procmgr created the child; destroy it
        // through whatever handle arrived. Slot 0 stands in for an absent
        // thread cap.
        if let Some(&process_handle) = reply_caps.first()
        {
            destroy_partial_child(process_handle, 0, ipc_buf);
        }
        return None;
    };
    Some(CreatedProcess {
        process_handle,
        thread_cap,
        child_badge,
        node_handle: reply_node_handle(path, label_bits, reply_caps),
    })
}

/// The node handle a create reply carries as its last cap, after the process
/// handle and the thread, when `label_bits` asked for one
/// (`CREATE_NODE_HANDLE`); `0` when it did not, or when the reply carries
/// none, which is logged.
fn reply_node_handle(path: &str, label_bits: u64, reply_caps: &[u64]) -> u64
{
    if label_bits & procmgr_labels::CREATE_NODE_HANDLE == 0
    {
        return 0;
    }
    let handle = reply_caps
        .get(2..)
        .and_then(<[u64]>::last)
        .copied()
        .unwrap_or(0);
    if handle == 0
    {
        std::os::seraph::log!(warn: "create: {path:?} reply carries no node handle");
    }
    handle
}

/// The create label's fields beyond the opcode and `CREATE_ARGV_ENV` for a
/// recipe: its scheduling fields (`priority` and `sched_max`, `0` for
/// unspecified, when procmgr applies its defaults against svcmgr's band) and
/// the create flags its `reserve`, `oom_stop` and `stop_source` keys ask
/// for (`svcmgr_defs::create_flags`). Shared by the launch and restart paths.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`reserve`, `oom_stop` and `stop_source` are whether the recipe sets the keys \
              of those names"
)]
pub(crate) fn create_label_bits(
    priority: u8,
    sched_max: u8,
    reserve: bool,
    oom_stop: bool,
    stop_source: bool,
) -> u64
{
    procmgr_labels::create_sched_bits(priority, sched_max)
        | svcmgr_defs::create_flags(reserve, oom_stop, stop_source)
}

/// Send `START_PROCESS` via the badged process handle. Shared by the
/// restart path and the post-handover launch path.
pub fn start_process(process_handle: u64, ipc_buf: *mut u64) -> bool
{
    let start_msg = IpcMessage::new(procmgr_labels::START_PROCESS);
    // SAFETY: `ipc_buf` is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(process_handle, &start_msg, ipc_buf) };
    if !matches!(reply, Ok(r) if r.label == 0)
    {
        std::os::seraph::log!(warn: "START_PROCESS failed");
        return false;
    }
    true
}

/// Endpoints and IPC state needed by restart paths. Holds nothing per-service,
/// so the same instance is reused across all death events.
pub struct RestartCtx
{
    pub procmgr_ep: u64,
    /// svcmgr's own service endpoint, from which it mints a
    /// `stop_authority = yes` service's `STOP_AUTHORITY` SEND.
    pub service_ep: u64,
    pub bootstrap_ep: u64,
    pub ipc_buf: *mut u64,
    /// The death-notification queues. A restarted service's observers are
    /// bound here under its slot and its new instance, so the routing in
    /// `dispatch_deaths` lands on the same `ServiceEntry` and drops a late
    /// post of the dead instance.
    pub deaths: death_set::DeathSet,
    /// Reserved master-log endpoint source. svcmgr mints real-logd's RECV (and
    /// the first-launch `HANDOVER_PULL` SEND) from it on every (re)launch.
    pub master_log_source: u64,
    /// Badge-0 `SEND|GRANT` source on procmgr's service endpoint. svcmgr mints
    /// real-logd's `DEATH_EQ_AUTHORITY` `SEND|GRANT` cap from it, and a
    /// `debug_authority = yes` service's `DEBUG_AUTHORITY` `SEND|GRANT` cap.
    pub procmgr_death_auth_source: u64,
    /// `EntropyControl` source carrying `Contribute`, from which svcmgr
    /// derives the `entropy_authority = yes` service's copy on every launch
    /// ([`mint_entropy_authority`]). `0` when init endowed none.
    pub entropy_source: u64,
    /// The queue svcmgr's own main thread and address space post their
    /// death to (`observe_own_death` in `main.rs`), from which svcmgr mints
    /// the shutdown actuator's receive-only derivation on every launch
    /// ([`mint_self_death_recv`]). `0` when it could not be made.
    pub self_death_queue: u64,
}

/// Handle a service death detected via event queue notification.
///
/// Restart is decided solely by [`should_restart`] (restart policy +
/// budget + restart source). When the service ends up permanently down
/// — restart not attempted or failed — `system_critical` alone decides
/// whether the system can continue without it. Marks the service
/// inactive if not restarted. For the log-sink service (`recipe.log_sink`)
/// the death's lines are written only once the new instance runs, and none
/// when no instance follows (`services/svcmgr/docs/restart-protocol.md`
/// § Supervision hierarchy). `tag` is the death tag the routed post
/// carried: the restarted instance's observers are bound under the same slot
/// and the next instance, so its death routes back to the same
/// `ServiceEntry` and a late post of this instance is dropped.
///
/// A restarted instance that dies during its bootstrap rounds
/// ([`Respawn::DiedInBootstrap`]) is a death of its own, decided here the
/// same way, its restart charged to the same budget, so the budget bounds the
/// repeats. Its late posts carry an instance already routed and are dropped.
///
/// Returns a [`DeathOutcome`] the caller routes:
///
/// * `Restarted` — service is back up; supervision loop continues.
/// * `Degraded` — service is permanently down but `system_critical` is
///   false; the system continues without it.
/// * `Unrecoverable` — `system_critical` service that restart cannot
///   recover. Caller must initiate the graceful-shutdown path (the
///   shutdown request through the shutdown actuator's declared name).
pub fn handle_death(
    svc: &mut ServiceEntry,
    exit_reason: u64,
    ctx: &RestartCtx,
    tag: DeathTag,
    recipe: Option<&RestartRecipe>,
    registry: &mut registry::Registry,
) -> DeathOutcome
{
    // The log sink's death leaves the master log endpoint with no receiver
    // until its next instance runs, so a line svcmgr wrote before then would
    // wait out its bound (`LOG_CALL_TIMEOUT_MS`, shared/log) and be dropped:
    // it would delay the respawn and reach no log. For the log-sink service,
    // svcmgr writes this death's lines once the new instance has started and
    // been served its bootstrap round, and none when no instance follows,
    // since then no receiver is left to take them.
    //
    // A line svcmgr wrote while the dead instance received nothing (one
    // that died before its receive workers started, in its handover from
    // init-logd) timed out, and after a timeout the log client bounds each
    // call by a few milliseconds until one is answered, less than the new
    // instance takes to start receiving. svcmgr therefore tells the client
    // that the receiver restarted before it writes the held lines, so they
    // wait for the new instance as any first line would.
    let lines = if matches!(recipe, Some(r) if r.log_sink)
    {
        DeathLines::Held
    }
    else
    {
        DeathLines::Written
    };
    // The routed death, and the deaths of the instances that died during
    // their bootstrap since, with the reason of the last.
    let routed_reason = exit_reason;
    let mut exit_reason = exit_reason;
    let mut bootstrap_deaths: u32 = 0;
    loop
    {
        if lines == DeathLines::Written
        {
            log_death(svc, exit_reason);
        }

        if !should_restart(svc, exit_reason, lines)
        {
            svc.active = false;
            return permanent_death_outcome(svc, lines);
        }

        if lines == DeathLines::Written
        {
            let attempt = u64::from(svc.restart_count.saturating_add(1));
            std::os::seraph::log!("restarting (attempt {attempt:#018x})");
        }

        let respawn = restart_process(svc, ctx, tag.slot, recipe, registry);
        if respawn == Respawn::Failed
        {
            svc.active = false;
            return permanent_death_outcome(svc, lines);
        }
        // A restart count cannot meaningfully exceed its type, so it
        // saturates; an instance that started counts, whether or not it lived
        // through its bootstrap.
        svc.restart_count = svc.restart_count.saturating_add(1);
        let Respawn::DiedInBootstrap(reason) = respawn
        else
        {
            break;
        };
        if lines == DeathLines::Written
        {
            std::os::seraph::log!("  the new instance died during its bootstrap");
        }
        bootstrap_deaths = bootstrap_deaths.saturating_add(1);
        exit_reason = reason;
    }

    if lines == DeathLines::Held
    {
        std::os::seraph::log::receiver_restarted();
        log_death(svc, routed_reason);
        if bootstrap_deaths != 0
        {
            std::os::seraph::log!(
                "  {bootstrap_deaths} later instance(s) died during their bootstrap; last \
                 exit_reason={exit_reason:#018x}"
            );
        }
        let attempt = u64::from(svc.restart_count);
        std::os::seraph::log!("restarting (attempt {attempt:#018x})");
    }
    std::os::seraph::log!("service restarted: {}", svc.name_str());
    DeathOutcome::Restarted
}

/// Whether [`handle_death`] writes a death's lines as it goes, or holds them
/// until the service's next instance runs: the log-sink service's lines are
/// held, since no logd receives until then.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DeathLines
{
    /// Written as the handler goes.
    Written,
    /// Held until the next instance runs; dropped when none follows.
    Held,
}

/// Log the death of `svc` and its exit reason.
fn log_death(svc: &ServiceEntry, exit_reason: u64)
{
    std::os::seraph::log!("service died: {}", svc.name_str());
    std::os::seraph::log!("  exit_reason={exit_reason:#018x}");
}

/// Outcome when a service is permanently down (restart not attempted,
/// budget exhausted, or restart failed). `system_critical` alone decides
/// whether the system can continue without it: `true` → `Unrecoverable`
/// (caller initiates graceful shutdown); `false` → `Degraded` (continue).
/// With [`DeathLines::Held`] (the log-sink service) it writes no line.
fn permanent_death_outcome(svc: &ServiceEntry, lines: DeathLines) -> DeathOutcome
{
    if svc.system_critical
    {
        if lines == DeathLines::Written
        {
            std::os::seraph::log!(
                error: "critical service unrecoverable: {}; initiating graceful shutdown",
                svc.name_str()
            );
        }
        DeathOutcome::Unrecoverable
    }
    else
    {
        if lines == DeathLines::Written
        {
            std::os::seraph::log!(
                warn: "service down: {}; system continues degraded",
                svc.name_str()
            );
        }
        DeathOutcome::Degraded
    }
}

/// Determine whether a service should be restarted based on its policy and
/// its windowed restart budget, charging the budget when it is restarted.
/// With [`DeathLines::Held`] (the log-sink service) it writes no line.
fn should_restart(svc: &mut ServiceEntry, exit_reason: u64, lines: DeathLines) -> bool
{
    let restart = match svc.restart_policy
    {
        POLICY_ALWAYS => true,
        POLICY_ON_FAILURE => exit_reason >= syscall_abi::EXIT_FAULT_BASE,
        _ => false,
    };

    if !restart
    {
        if lines == DeathLines::Written
        {
            std::os::seraph::log!("restart policy says no restart");
        }
        return false;
    }

    if svc.vfs_path.is_empty()
    {
        if lines == DeathLines::Written
        {
            std::os::seraph::log!(warn: "no restart source (vfs_path), cannot restart");
        }
        return false;
    }

    if !svc.restart_budget.try_charge(crate::now_ns())
    {
        if lines == DeathLines::Written
        {
            std::os::seraph::log!(warn: "restart budget spent for this window");
        }
        return false;
    }

    true
}

/// What [`restart_process`] made of a service's next instance.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Respawn
{
    /// The instance runs and took its bootstrap rounds.
    Started,
    /// The instance started and died during its bootstrap rounds, with this
    /// exit reason. The entry names it, and the next restart releases it as it
    /// releases any dead instance.
    DiedInBootstrap(u64),
    /// A step failed: the new child, if one was created, is destroyed, and
    /// the entry names no instance.
    Failed,
}

/// Release the dead instance, create a new process via procmgr, bind its
/// death observers (its main thread's, and its address space's through
/// procmgr) under the slot's next instance, start it, and serve its bootstrap
/// rounds. The observers are bound before `START_PROCESS`, so no death of the
/// new instance precedes them. Returns [`Respawn::Started`] on success, and
/// [`Respawn::DiedInBootstrap`] when the instance dies before its rounds
/// reach it ([`serve_boot_slots`]); on a failure after the create the new
/// child is destroyed and the entry holds no instance (`process_handle` and
/// `thread_cap` zero), [`Respawn::Failed`].
fn restart_process(
    svc: &mut ServiceEntry,
    ctx: &RestartCtx,
    slot: u32,
    recipe: Option<&RestartRecipe>,
    registry: &mut registry::Registry,
) -> Respawn
{
    // Reclaim the previous instance's kernel objects (thread/aspace/cspace/
    // ProcessInfo memory cap) before spawning a fresh one. CSpace teardown
    // cascades: memory caps handed to the dead process via `REQUEST_MEMORY_CAPS`
    // (which procmgr no longer holds caps on) get dec-ref'd and reclaimed
    // into memmgr's pool. A service init created by raw syscalls (memmgr,
    // procmgr) has no process handle, and is never restarted: its recipe is
    // `restart = never`. Every other service holds the handle its launch, its
    // last restart, or init's endowment (devmgr, vfsd) recorded. A teardown
    // procmgr already ran makes the call a no-op reply.
    if svc.process_handle != 0
    {
        let destroy_msg = IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
        // SAFETY: ctx.ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_call(svc.process_handle, &destroy_msg, ctx.ipc_buf) };
        let _ = syscall::cap_delete(svc.process_handle);
        svc.process_handle = 0;
    }
    // Release svcmgr's references to the dead instance: its exited thread,
    // for an instance init created by raw syscalls its address space, and the
    // node handle of its budget node, which memmgr refuses once it is gone.
    for cap in [
        &mut svc.thread_cap,
        &mut svc.aspace_cap,
        &mut svc.node_handle,
    ]
    {
        if *cap != 0
        {
            let _ = syscall::cap_delete(*cap);
            *cap = 0;
        }
    }

    let Some(CreatedProcess {
        process_handle,
        thread_cap: new_thread_cap,
        child_badge,
        node_handle,
    }) = create_process(svc, recipe, ctx)
    else
    {
        return Respawn::Failed;
    };

    let instance = svc.instance.wrapping_add(1);
    let tag = DeathTag { slot, instance };
    if !bind_instance_observers(ctx, new_thread_cap, process_handle, tag.correlator())
    {
        std::os::seraph::log!(warn: "failed to bind the new instance's death observers");
        destroy_partial_child(process_handle, new_thread_cap, ctx.ipc_buf);
        delete_caps(&[node_handle]);
        return Respawn::Failed;
    }
    svc.process_handle = process_handle;
    svc.thread_cap = new_thread_cap;
    svc.node_handle = node_handle;
    svc.instance = instance;
    // The entry names the new instance from here; a failure below destroys it
    // and leaves the entry holding none.
    let fail = |svc: &mut ServiceEntry| {
        destroy_partial_child(process_handle, new_thread_cap, ctx.ipc_buf);
        delete_caps(&[node_handle]);
        svc.process_handle = 0;
        svc.thread_cap = 0;
        svc.node_handle = 0;
        Respawn::Failed
    };

    if !start_process(process_handle, ctx.ipc_buf)
    {
        return fail(svc);
    }

    let Some(boot_caps) = restart_boot_caps(svc, ctx, recipe, registry)
    else
    {
        return fail(svc);
    };

    match serve_boot_slots(ctx, child_badge, new_thread_cap, &boot_caps)
    {
        Ok(()) =>
        {}
        Err(ServeFailure::ChildDied(exit_reason)) =>
        {
            // The caps of the rounds not served are still svcmgr's (delete of
            // an already-transferred slot is a no-op). The entry keeps the
            // dead instance for the caller to route.
            delete_caps(&boot_caps);
            return Respawn::DiedInBootstrap(exit_reason);
        }
        Err(ServeFailure::Refused(_)) =>
        {
            std::os::seraph::log!(warn: "bootstrap serve failed");
            // A round MOVES its caps on success; on failure they may or
            // may not have been consumed. Best-effort delete is safe
            // (delete of an already-transferred slot is a no-op). The
            // started child is blocked in its bootstrap request; destroy it.
            delete_caps(&boot_caps);
            return fail(svc);
        }
    }

    svc.bootstrap_badge = child_badge;
    svc.bootstrap = Bootstrap::Served;
    Respawn::Started
}

/// Assemble the restart bootstrap cap set for `svc`. Returns `None`, with
/// the resolved seeds released, when the provider-RECV derive fails; the
/// caller then destroys the new child.
///
/// The log-sink service (real-logd) gets a freshly-minted round from the
/// reserved log-sink sources. Once an instance has taken all its rounds
/// (`ServiceEntry::bootstrap`) the round carries no `HANDOVER_PULL`
/// SEND: that instance held the handover, so the restarted logd skips the
/// history pull and takes over the log endpoint directly. Until then no
/// instance has received the SEND and init-logd still serves the endpoint, so
/// the round is the first launch's, with the SEND. Senders are unaffected:
/// their SENDs target the endpoint object, and svcmgr's reserved source kept
/// it alive across the crash.
///
/// Otherwise the recipe's `seed = ...` names are re-resolved from the
/// registry, in declaration order — byte-for-byte the positional set first
/// launch delivered (empty for a recipe with no seeds, such as the
/// init-endowed substrate's). A `provides` service's
/// own service-endpoint RECV leads as cap[0]; the endpoint persists on the
/// entry, so a fresh RECV reattaches the restarted instance to the same object
/// consumers already hold a SEND on. A missing RECV would shift the seeds down
/// into cap[0], where the child expects its service RECV, so it fails the
/// restart instead, as it fails first launch.
fn restart_boot_caps(
    svc: &ServiceEntry,
    ctx: &RestartCtx,
    recipe: Option<&RestartRecipe>,
    registry: &mut registry::Registry,
) -> Option<Vec<u64>>
{
    if matches!(recipe, Some(r) if r.log_sink)
    {
        let kind = match svc.bootstrap
        {
            Bootstrap::Served => LaunchKind::Restart,
            Bootstrap::Pending => LaunchKind::First,
        };
        return Some(mint_logd_boot_caps(ctx, kind, registry));
    }

    let mut restart_caps: Vec<u64> = match recipe
    {
        Some(r) => resolve_seeds(&r.seed, svc.name_str(), registry),
        None => Vec::new(),
    };
    // A debug-authority holder's authority cap rides the slot after its
    // seeds, as on first launch.
    if matches!(recipe, Some(r) if r.debug_authority)
    {
        restart_caps.push(mint_debug_authority(ctx));
    }
    // A stop-authority holder's cap rides the slot after those.
    if matches!(recipe, Some(r) if r.stop_authority)
    {
        restart_caps.push(mint_stop_authority(ctx));
    }
    // The entropy-authority holder's cap rides the slot after those.
    if matches!(recipe, Some(r) if r.entropy_authority)
    {
        restart_caps.push(mint_entropy_authority(ctx));
    }
    // The shutdown actuator's receive-only derivation of svcmgr's own death
    // queue rides the slot after those, so each instance observes svcmgr.
    if matches!(recipe, Some(r) if r.observes_svcmgr)
    {
        restart_caps.push(mint_self_death_recv(ctx));
    }

    let provided_recv = if svc.provided_endpoint != 0
    {
        let Ok(recv) = syscall::cap_derive(svc.provided_endpoint, syscall::RIGHTS_EP_RECEIVE)
        else
        {
            std::os::seraph::log!(warn: "restart: provider RECV derive failed");
            delete_caps(&restart_caps);
            return None;
        };
        recv
    }
    else
    {
        0
    };
    Some(assemble_boot_caps(provided_recv, restart_caps))
}

/// Spawn a fresh instance of `svc` via procmgr from its recorded
/// `vfs_path` ([`walk_and_create_from_file`]), with the recipe's create
/// flags. After create, applies the per-service namespace policy recorded at
/// registration via `CONFIGURE_NAMESPACE`; on its failure the child is
/// destroyed and its node handle released.
fn create_process(
    svc: &ServiceEntry,
    recipe: Option<&RestartRecipe>,
    ctx: &RestartCtx,
) -> Option<CreatedProcess>
{
    if svc.vfs_path.is_empty()
    {
        std::os::seraph::log!(warn: "restart: no vfs_path source for {}", svc.name_str());
        return None;
    }
    let path_str = svc.vfs_path.as_str();
    // Replay argv/env from the stored recipe so the respawned child gets the
    // same startup surfaces first launch built. The blobs must outlive the
    // create call — `StartupBlobs` borrows them.
    let (argv_blob, argv_count) = recipe.map_or_else(|| (Vec::new(), 0), |r| build_blob(&r.argv));
    let (env_blob, env_count) = recipe.map_or_else(|| (Vec::new(), 0), |r| build_blob(&r.env));
    let blobs = StartupBlobs {
        argv: &argv_blob,
        argv_count,
        env: &env_blob,
        env_count,
    };
    let label_bits = recipe.map_or(0, |r| {
        create_label_bits(
            r.priority,
            r.sched_max,
            r.reserve,
            r.oom_stop,
            r.stop_source.is_some(),
        )
    });
    let created = walk_and_create_from_file(
        path_str,
        blobs,
        label_bits,
        ctx.procmgr_ep,
        ctx.bootstrap_ep,
        ctx.ipc_buf,
    )?;

    let cwd = recipe.and_then(|r| r.cwd.as_deref());
    if !apply_namespace_policy(svc, cwd, created.process_handle, created.thread_cap, ctx)
    {
        delete_caps(&[created.node_handle]);
        return None;
    }

    Some(created)
}

/// Apply the namespace policy recorded on `svc` to a freshly-created
/// (suspended) child. Restart's namespace resolver: it walks svcmgr's own
/// `root_dir_cap` (universal after init's Phase-3 handover) to derive the
/// child's namespace cap and feeds it to [`configure_namespace_caps`],
/// which first launch reaches through `definitions::launch`'s own
/// `configure_namespace`.
///
/// * `NS_POLICY_NONE` → skip `CONFIGURE_NAMESPACE`; the child's
///   `system_root_cap` stays zero (`Unsupported` on absolute-path
///   fs ops in std).
/// * `NS_POLICY_UNIVERSAL` → `cap_copy` of svcmgr's own root with
///   `RIGHTS_EP_SEND`.
/// * `NS_POLICY_SUBTREE` → walk svcmgr's root for the stored
///   subtree path with the stored rights mask, hand the resulting
///   directory cap to the child.
///
/// `cwd` is the recipe's optional working-directory path, walked and
/// delivered alongside the namespace cap by [`configure_namespace_caps`]
/// so relative `std::fs` ops resolve identically across restarts. It is
/// `None` for `NS_POLICY_NONE` (the parser forbids `cwd` there).
///
/// On any failure the partial child is destroyed and `false` is
/// returned (caller treats handle as no longer usable).
pub fn apply_namespace_policy(
    svc: &ServiceEntry,
    cwd: Option<&str>,
    process_handle: u64,
    thread_cap: u64,
    ctx: &RestartCtx,
) -> bool
{
    if svc.ns_policy_kind == ipc::svcmgr_labels::NS_POLICY_NONE
    {
        return true;
    }

    let root_cap = std::os::seraph::root_dir_cap();
    if root_cap == 0
    {
        std::os::seraph::log!(warn: "ns policy: no root_dir_cap for CONFIGURE_NAMESPACE");
        destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
        return false;
    }
    let Some(info) = std::os::seraph::try_startup_info()
    else
    {
        std::os::seraph::log!(warn: "ns policy: no startup info for cap_copy");
        destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
        return false;
    };

    let ns_cap = match svc.ns_policy_kind
    {
        ipc::svcmgr_labels::NS_POLICY_UNIVERSAL =>
        {
            let Ok(c) = syscall::cap_copy(root_cap, info.self_cspace, syscall::RIGHTS_EP_SEND)
            else
            {
                std::os::seraph::log!(warn: "ns policy: cap_copy of root for child failed");
                destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
                return false;
            };
            c
        }
        ipc::svcmgr_labels::NS_POLICY_SUBTREE =>
        {
            let path_str = svc.ns_subtree_path.as_str();
            match std::os::seraph::namespace_lookup_dir(
                root_cap,
                path_str,
                u64::from(svc.ns_subtree_rights),
            )
            {
                Ok(c) => c,
                Err(e) =>
                {
                    std::os::seraph::log!(warn: "ns policy: subtree walk {path_str:?} failed: {e}");
                    destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
                    return false;
                }
            }
        }
        _ =>
        {
            std::os::seraph::log!(warn: "ns policy: unknown ns_policy_kind");
            destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
            return false;
        }
    };

    let subtree_rights = (svc.ns_policy_kind == ipc::svcmgr_labels::NS_POLICY_SUBTREE)
        .then_some(svc.ns_subtree_rights);
    configure_namespace_caps(
        ns_cap,
        cwd,
        cwd_rights(subtree_rights),
        root_cap,
        process_handle,
        thread_cap,
        ctx,
    )
}

/// Walk the optional `cwd` against `root_cap` requesting `cwd_rights`
/// ([`cwd_rights`] of the namespace shape), then deliver the namespace
/// cap (and the cwd cap, when present) to the suspended child via
/// `CONFIGURE_NAMESPACE`. Shared by the restart path
/// ([`apply_namespace_policy`]) and the launch path
/// ([`crate::definitions::launch`]) so both install cwd identically and
/// own the same cleanup. `ns_cap` is consumed (deleted) here regardless
/// of outcome — the kernel transfers it on the IPC. On any failure the
/// partial child is destroyed and `false` is returned.
pub(crate) fn configure_namespace_caps(
    ns_cap: u64,
    cwd: Option<&str>,
    cwd_rights: u32,
    root_cap: u64,
    process_handle: u64,
    thread_cap: u64,
    ctx: &RestartCtx,
) -> bool
{
    // cwd is walked from svcmgr's universal root; the `.svc` parser keeps a
    // subtree recipe's cwd inside the subtree, and `cwd_rights` keeps the cap
    // within the subtree's rights (service-definitions.md § cwd).
    let cwd_cap = if let Some(cwd_path) = cwd
    {
        match std::os::seraph::namespace_lookup_dir(root_cap, cwd_path, u64::from(cwd_rights))
        {
            Ok(c) => c,
            Err(e) =>
            {
                std::os::seraph::log!(warn: "ns policy: cwd walk {cwd_path:?} failed: {e}");
                let _ = syscall::cap_delete(ns_cap);
                destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
                return false;
            }
        }
    }
    else
    {
        0
    };

    let mut builder = IpcMessage::builder(procmgr_labels::CONFIGURE_NAMESPACE).cap(ns_cap);
    if cwd_cap != 0
    {
        builder = builder.cap(cwd_cap);
    }
    let ns_msg = builder.build();
    // SAFETY: ctx.ipc_buf is the registered IPC buffer.
    let ns_reply = unsafe { ipc::ipc_call(process_handle, &ns_msg, ctx.ipc_buf) };
    // The kernel transferred the caps on the IPC regardless of the reply
    // label; release svcmgr's source slots unconditionally.
    let _ = syscall::cap_delete(ns_cap);
    if cwd_cap != 0
    {
        let _ = syscall::cap_delete(cwd_cap);
    }
    match ns_reply
    {
        Ok(r) if r.label == 0 => true,
        Ok(r) =>
        {
            std::os::seraph::log!(warn: "ns policy: CONFIGURE_NAMESPACE returned {:#x}", r.label);
            destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
            false
        }
        Err(_) =>
        {
            std::os::seraph::log!(warn: "ns policy: CONFIGURE_NAMESPACE syscall failed");
            destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
            false
        }
    }
}

/// Tear down a partially-created child: send `DESTROY_PROCESS` over its
/// badged handle and release procmgr-side cap slots. Called when a step
/// between procmgr's CREATE and START fails and the partial child must
/// be reaped before the supervision loop retries.
pub(crate) fn destroy_partial_child(process_handle: u64, thread_cap: u64, ipc_buf: *mut u64)
{
    let destroy_msg = IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_buf) };
    let _ = syscall::cap_delete(process_handle);
    let _ = syscall::cap_delete(thread_cap);
}

/// Bind both death observers of a new instance under `correlator`: one on its
/// main thread (`thread_cap`), and one on its address space, which procmgr
/// binds on svcmgr's behalf through `process_handle` ([`bind_fault_observer`]),
/// so the first terminal fault of any of its threads reaches svcmgr. True when
/// both are bound. Shared by the launch and restart paths, which call it
/// before `START_PROCESS`.
pub(crate) fn bind_instance_observers(
    ctx: &RestartCtx,
    thread_cap: u64,
    process_handle: u64,
    correlator: u64,
) -> bool
{
    ctx.deaths.bind_thread(thread_cap, correlator).is_ok()
        && bind_fault_observer(&ctx.deaths, process_handle, correlator, ctx.ipc_buf)
}

/// The exit reason of a service the kernel shows dead in the caps svcmgr holds
/// on it, else `None`: its main thread's state through `thread_cap` and, when
/// `aspace_cap` is non-zero (memmgr and procmgr), its address space's retained
/// terminal fault (`svcmgr_defs::death_caps::caps_death` decodes both). A zero
/// `thread_cap` is not read.
pub(crate) fn caps_death(thread_cap: u64, aspace_cap: u64) -> Option<u64>
{
    let thread_state = (thread_cap != 0)
        .then(|| syscall::cap_info(thread_cap, syscall_abi::CAP_INFO_THREAD_STATE));
    let aspace_fault = (aspace_cap != 0)
        .then(|| syscall::cap_info(aspace_cap, syscall_abi::CAP_INFO_ASPACE_TERMINAL_FAULT));
    svcmgr_defs::death_caps::caps_death(thread_state, aspace_fault)
}

/// The exit reason of the process `process_handle` names when procmgr reports
/// it dead (`procmgr_labels::QUERY_PROCESS`), else `None`. procmgr answers
/// `EXITED` with the main thread's reason or the address space's retained
/// terminal fault before it reaps the process, and for a while after;
/// `UNKNOWN` (no entry) reads as `EXIT_KILLED`. A failed or refused call is
/// `None`. The caller holds procmgr alive, since the call blocks until procmgr
/// answers.
pub(crate) fn queried_death(process_handle: u64, ipc_buf: *mut u64) -> Option<u64>
{
    let msg = IpcMessage::new(procmgr_labels::QUERY_PROCESS);
    // SAFETY: `ipc_buf` is svcmgr's registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(process_handle, &msg, ipc_buf) }.ok()?;
    if reply.label != procmgr_errors::SUCCESS
    {
        return None;
    }
    match reply.word(0)
    {
        ipc::procmgr_process_state::EXITED => Some(reply.word(1)),
        ipc::procmgr_process_state::UNKNOWN => Some(syscall_abi::EXIT_KILLED),
        _ => None,
    }
}

/// Have procmgr bind one of svcmgr's death queues as a terminal-fault death
/// observer, posting `correlator`, on the address space of the child
/// `process_handle` names (`procmgr_labels::BIND_DEATH_OBSERVER`), through a
/// `POST` copy of the queue the call transfers. The death set picks the queue
/// as for a thread bind: procmgr's `OUT_OF_MEMORY` reply (the queue has no free
/// observer node) moves the bind to another queue, or grows the set. True
/// when procmgr bound it; false, any copy released, when the copy cannot be
/// derived or the call fails or is refused (a child procmgr already tore down
/// among the causes).
pub(crate) fn bind_fault_observer(
    deaths: &death_set::DeathSet,
    process_handle: u64,
    correlator: u64,
    ipc_buf: *mut u64,
) -> bool
{
    deaths
        .bind_with(|queue| {
            let post = syscall::cap_derive(queue, syscall::RIGHTS_EQ_POST)?;
            let msg = IpcMessage::builder(procmgr_labels::BIND_DEATH_OBSERVER)
                .word(0, correlator)
                .cap(post)
                .build();
            // SAFETY: `ipc_buf` is svcmgr's registered IPC buffer.
            match unsafe { ipc::ipc_call(process_handle, &msg, ipc_buf) }
            {
                // procmgr deletes its copy on every reply.
                Ok(reply) if reply.label == procmgr_errors::SUCCESS => Ok(()),
                Ok(reply) if reply.label == procmgr_errors::OUT_OF_MEMORY =>
                {
                    Err(SyscallError::OutOfMemory as i64)
                }
                Ok(_) => Err(SyscallError::InvalidArgument as i64),
                Err(e) =>
                {
                    // The call did not transfer the copy.
                    let _ = syscall::cap_delete(post);
                    Err(e)
                }
            }
        })
        .is_ok()
}
