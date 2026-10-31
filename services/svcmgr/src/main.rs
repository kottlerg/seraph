// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/src/main.rs

//! Seraph service manager — monitors services, detects crashes via a
//! single shared death-notification event queue, and restarts them per
//! their restart policy.
//!
//! svcmgr is loaded from the root filesystem by init (via procmgr's
//! `CREATE_FROM_FILE`). Init serves svcmgr its handover endowment
//! over bootstrap rounds, then sends `HANDOVER_COMPLETE` through a
//! `HANDOVER_AUTHORITY`-badged SEND and exits. svcmgr runs for the lifetime
//! of the system.
//!
//! Every supervised service binds death notification onto the same
//! `deaths_eq` with `correlator = service_index`. The wait set has two
//! members: the service endpoint (badge 0) and the deaths queue
//! (badge 1). On death wakeup svcmgr drains the queue and routes each
//! payload to its `ServiceEntry` via the correlator. Multiplexing
//! avoids consuming a wait-set slot per supervised process and keeps
//! the wait set inside the 16-member retype-bin sizing.
//!
//! See `svcmgr/docs/ipc-interface.md` and `svcmgr/docs/restart-protocol.md`.

// cast_possible_truncation: targets 64-bit only; u64/usize conversions lossless.
#![allow(clippy::cast_possible_truncation)]

mod arch;
mod definitions;
mod restart;
mod service;

use definitions::reconcile::{PendingRegistration, ServiceTable};
use ipc::{IpcMessage, svcmgr_labels};
use registry::{Resolver, Visibility};
use service::bootstrap_caps;
use std::os::seraph::{StartupInfo, startup_info};

/// Capacity of svcmgr's shared death `EventQueue`: a tuning value, not a
/// service ceiling. The kernel drops a death post to a full queue, so a burst
/// of more deaths than this between drains is recovered by
/// [`resync_deaths`], which [`dispatch_deaths`] runs after any drain that
/// took a full queue's worth of events; the service table has no fixed size.
const DEATHS_EQ_CAPACITY: u32 = 64;

/// Monotonic time since svcmgr started, in nanoseconds, for the windowed
/// restart budget. Saturates rather than wraps.
pub(crate) fn now_ns() -> u64
{
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(std::time::Instant::now);
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// Read a name of `name_len` bytes packed into IPC data words from word 0,
/// as `svcmgr_labels::pack_name` packs it. `None` when the length is 0 or
/// past `svcmgr_labels::NAME_MAX`, or the message carries too few words.
fn read_name_from_msg(msg: &IpcMessage, name_len: usize) -> Option<[u8; svcmgr_labels::NAME_MAX]>
{
    svcmgr_labels::unpack_name(msg.words(), name_len)
}

// ── Halt ───────────────────────────────────────────────────────────────────

/// Halt the CPU in an infinite loop. Used on unrecoverable failures.
pub fn halt_loop() -> !
{
    loop
    {
        arch::current::halt();
    }
}

// ── Entry point ────────────────────────────────────────────────────────────

fn main() -> !
{
    std::os::seraph::log::register_name(b"svcmgr");
    let info = startup_info();

    // IPC buffer was registered by `std::os::seraph::_start`. The raw
    // pointer is all the new `ipc::ipc_call`/`ipc_recv`/`ipc_reply` and
    // `ipc::bootstrap::*` wrappers need.
    // cast_ptr_alignment: IPC buffer is page-aligned by the boot protocol.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // State is created before the endowment is drained so `bootstrap_caps`
    // can park the substrate `(name, thread_cap)` pairs directly in
    // `state.pending`; `HANDOVER_COMPLETE` reconciles them later.
    let mut state = SvcmgrState {
        table: ServiceTable::new(),
        pending: Vec::new(),
        registry: registry::Registry::new(),
        handover_done: false,
    };

    let Some(caps) = bootstrap_caps(info, ipc_buf, &mut state.pending)
    else
    {
        syscall::thread_exit();
    };

    std::os::seraph::log!("started");

    if caps.service_ep == 0
    {
        std::os::seraph::log!("no service endpoint, halting");
        halt_loop();
    }
    if info.procmgr_endpoint == 0
    {
        std::os::seraph::log!("no procmgr endpoint, halting");
        halt_loop();
    }

    let Some(ws_cap) =
        std::os::seraph::object_slab_retype(std::os::seraph::WAIT_SET_RETYPE_BYTES, |slab| {
            syscall::wait_set_create(slab).ok()
        })
    else
    {
        std::os::seraph::log!("failed to create wait set");
        halt_loop();
    };

    // One shared death-notification queue of `DEATHS_EQ_CAPACITY`; the slab
    // request is the kernel's raw EventQueue debit for that capacity.
    let deaths_eq_slab_bytes =
        std::os::seraph::event_queue_retype_bytes(u64::from(DEATHS_EQ_CAPACITY));
    let Some(deaths_eq) = std::os::seraph::object_slab_retype(deaths_eq_slab_bytes, |slab| {
        syscall::event_queue_create(slab, DEATHS_EQ_CAPACITY).ok()
    })
    else
    {
        std::os::seraph::log!("failed to create deaths event queue");
        halt_loop();
    };

    if syscall::wait_set_add(ws_cap, caps.service_ep, WS_BADGE_SERVICE).is_err()
    {
        std::os::seraph::log!("failed to add service endpoint to wait set");
        halt_loop();
    }
    if syscall::wait_set_add(ws_cap, deaths_eq, WS_BADGE_DEATHS).is_err()
    {
        std::os::seraph::log!("failed to add deaths event queue to wait set");
        halt_loop();
    }

    // Publish the well-known names svcmgr owns and hand devmgr its
    // drivers dir — both from the handover endowment caps — before the
    // event loop, so they are in place before `HANDOVER_COMPLETE` drives
    // reconciliation and any launched consumer resolves them.
    publish_well_known(&mut state.registry, &caps);
    install_drivers_dir(&caps, ipc_buf);

    std::os::seraph::log!("endowed; waiting for handover");

    event_loop(info, &caps, ws_cap, deaths_eq, ipc_buf, &mut state);
}

/// Publish the well-known names svcmgr owns into its own discovery
/// registry, from the caps init endowed at handover. These are internal
/// `registry.publish` calls (no `PUBLISH_AUTHORITY` badge — svcmgr owns
/// the registry). Each provider's own `provides` names are published
/// separately on the launch path ([`definitions::launch`]).
fn publish_well_known(registry: &mut registry::Registry, caps: &service::SvcmgrCaps)
{
    // rootfs.root — SEND on the root filesystem's namespace endpoint,
    // endowed pre-derived by init. Seed-only: the whole-filesystem namespace
    // reaches only the recipes that seed it.
    publish_endowed_send(
        registry,
        caps.rootfs_root,
        ipc::published_names::ROOTFS_ROOT,
    );
    // vfsd.mount / vfsd.deny — SENDs on vfsd's service endpoint, endowed
    // pre-badged by init (`MOUNT_AUTHORITY`, and the no-authority
    // `DENY_BADGE`). Seed-only: svctest alone seeds them.
    publish_endowed_send(registry, caps.vfsd_mount, ipc::published_names::VFSD_MOUNT);
    publish_endowed_send(registry, caps.vfsd_deny, ipc::published_names::VFSD_DENY);

    // svcmgr — SEND on svcmgr's own service endpoint (crasher seeds it),
    // badged so no consumer holds an unbadged source it could re-badge with
    // a verb bit.
    match syscall::cap_derive_badge(
        caps.service_ep,
        syscall::RIGHTS_EP_SEND,
        svcmgr_labels::PUBLISHED_SEND_BADGE,
    )
    {
        Ok(send) =>
        {
            if registry
                .publish(ipc::published_names::SVCMGR, send, Visibility::Public)
                .is_err()
            {
                std::os::seraph::log!("publish svcmgr failed");
                let _ = syscall::cap_delete(send);
            }
        }
        Err(_) => std::os::seraph::log!("derive svcmgr SEND failed"),
    }

    // devmgr.registry / devmgr.shutdown / devmgr.test — badged SENDs minted
    // from the endowed badge-0 `SEND|GRANT` source. The badge bits ride
    // through `registry_lookup_derived`'s plain `cap_derive` to consumers.
    // Each carries verb-bit authority, so each is seed-only: `QUERY_ENDPOINT`
    // refuses it, and only the recipes that seed the name hold its bits.
    let query = ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY;
    for (name, badge) in [
        (ipc::published_names::DEVMGR_REGISTRY, query),
        (
            ipc::published_names::DEVMGR_SHUTDOWN,
            query | ipc::devmgr_labels::SHUTDOWN_DEVICE_AUTHORITY,
        ),
        (
            ipc::published_names::DEVMGR_TEST,
            query | ipc::devmgr_labels::TEST_LABEL_AUTHORITY,
        ),
    ]
    {
        publish_devmgr_registry_send(registry, caps.devmgr_registry, name, badge);
    }
}

/// Publish the endowed, pre-derived SEND `cap` seed-only as `name`, as-is:
/// `registry_lookup_derived` re-derives a SEND per consumer and the badge
/// survives. Logs and skips when the cap is absent; deletes it when the
/// publish fails.
fn publish_endowed_send(registry: &mut registry::Registry, cap: u32, name: &[u8])
{
    let shown = core::str::from_utf8(name).unwrap_or("?");
    if cap == 0
    {
        std::os::seraph::log!("no {shown} source cap; not published");
        return;
    }
    if registry.publish(name, cap, Visibility::SeedOnly).is_err()
    {
        std::os::seraph::log!("publish {shown} failed");
        let _ = syscall::cap_delete(cap);
    }
}

/// Publish `name` seed-only as a `badge`-badged SEND minted from the
/// endowed devmgr-registry `source`; logs and skips when the source is
/// absent or the derive or publish fails.
fn publish_devmgr_registry_send(
    registry: &mut registry::Registry,
    source: u32,
    name: &[u8],
    badge: u64,
)
{
    let shown = core::str::from_utf8(name).unwrap_or("?");
    if source == 0
    {
        std::os::seraph::log!("no devmgr-registry source cap; {shown} not published");
        return;
    }
    match syscall::cap_derive_badge(source, syscall::RIGHTS_EP_SEND, badge)
    {
        Ok(send) =>
        {
            if registry.publish(name, send, Visibility::SeedOnly).is_err()
            {
                std::os::seraph::log!("publish {shown} failed");
                let _ = syscall::cap_delete(send);
            }
        }
        Err(_) => std::os::seraph::log!("derive {shown} cap failed"),
    }
}

/// Hand devmgr a `LOOKUP | READ`-attenuated `/services/drivers/` subtree
/// cap via `SET_DRIVERS_DIR`, so devmgr can lazily walk + spawn its on-disk
/// driver binaries (the per-arch RTC and virtio-input). svcmgr walks its universal
/// root for the dir and mints a `DRIVERS_DIR_AUTHORITY` `SEND|GRANT` from
/// the endowed devmgr-registry source.
///
/// Best-effort: any failure leaves devmgr without a drivers dir, so timed
/// sees `NO_DEVICE` on its first `QUERY_RTC_DEVICE` and degrades to its
/// no-RTC path; the rest of startup proceeds.
fn install_drivers_dir(caps: &service::SvcmgrCaps, ipc_buf: *mut u64)
{
    if caps.devmgr_registry == 0
    {
        std::os::seraph::log!("SET_DRIVERS_DIR skipped: no devmgr registry source");
        return;
    }
    let root_cap = std::os::seraph::root_dir_cap();
    if root_cap == 0
    {
        std::os::seraph::log!("SET_DRIVERS_DIR skipped: no root_dir_cap");
        return;
    }

    // Attenuated rights: only what devmgr needs to walk into the subtree
    // and read driver-binary contents; the namespace server intersects
    // per hop.
    let rights = u64::from(namespace_protocol::rights::LOOKUP | namespace_protocol::rights::READ);
    let drivers_dir =
        match std::os::seraph::namespace_lookup_dir(root_cap, "/services/drivers", rights)
        {
            Ok(c) => c,
            Err(e) =>
            {
                std::os::seraph::log!("SET_DRIVERS_DIR: walk /services/drivers failed: {e}");
                return;
            }
        };

    // `RIGHTS_EP_SEND_GRANT` (not bare SEND): SET_DRIVERS_DIR transfers the
    // dir cap, and the IPC kernel requires the GRANT bit to move caps.
    let Ok(bind_ep) = syscall::cap_derive_badge(
        caps.devmgr_registry,
        syscall::RIGHTS_EP_SEND_GRANT,
        ipc::devmgr_labels::DRIVERS_DIR_AUTHORITY,
    )
    else
    {
        std::os::seraph::log!("SET_DRIVERS_DIR: DRIVERS_DIR_AUTHORITY derive failed");
        let _ = syscall::cap_delete(drivers_dir);
        return;
    };

    let msg = IpcMessage::builder(ipc::devmgr_labels::SET_DRIVERS_DIR)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .cap(drivers_dir)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let result = unsafe { ipc::ipc_call(bind_ep, &msg, ipc_buf) };
    let _ = syscall::cap_delete(bind_ep);

    match result
    {
        Ok(reply) if reply.label == ipc::devmgr_errors::SUCCESS =>
        {
            std::os::seraph::log!("SET_DRIVERS_DIR ok");
        }
        Ok(_) => std::os::seraph::log!("SET_DRIVERS_DIR rejected; RTC unavailable"),
        Err(_) =>
        {
            // Transport error before the kernel committed the transfer;
            // the source slot still owns `drivers_dir`.
            let _ = syscall::cap_delete(drivers_dir);
            std::os::seraph::log!("SET_DRIVERS_DIR ipc error; RTC unavailable");
        }
    }
}

/// `WaitSet` badge for svcmgr's service endpoint.
const WS_BADGE_SERVICE: u64 = 0;
/// `WaitSet` badge for svcmgr's shared death event queue.
const WS_BADGE_DEATHS: u64 = 1;

/// Monitored service table, pending-registration table, discovery
/// registry, and handover flag. Held across the event loop for the
/// lifetime of the process.
///
/// `pending` is populated by [`service::bootstrap_caps`] as it drains
/// init's handover endowment (one substrate `(name, thread_cap)` round
/// each). On `HANDOVER_COMPLETE`
/// [`definitions::reconcile::reconcile_and_launch`] pairs each entry with
/// a `.svc` recipe, binds death-notification, and populates `services`.
/// After reconciliation `pending` is effectively read-only — the
/// unconsumed entries persist as logged configuration errors but are not
/// re-used.
pub struct SvcmgrState
{
    /// Supervised services and their restart recipes, index-aligned via the
    /// death correlator; grows on the heap with no fixed count.
    pub table: ServiceTable,
    /// Substrate registrations parked from init's endowment.
    pub pending: Vec<PendingRegistration>,
    pub registry: registry::Registry,
    /// Set by the one `HANDOVER_COMPLETE` svcmgr honours; a repeat is
    /// rejected so reconciliation cannot launch a second instance of every
    /// defined service.
    pub handover_done: bool,
}

/// Main event loop: dispatches IPC registrations and death notifications.
fn event_loop(
    info: &StartupInfo,
    caps: &service::SvcmgrCaps,
    ws_cap: u32,
    deaths_eq: u32,
    ipc_buf: *mut u64,
    state: &mut SvcmgrState,
) -> !
{
    let restart_ctx = restart::RestartCtx {
        procmgr_ep: info.procmgr_endpoint,
        bootstrap_ep: caps.bootstrap_ep,
        ipc_buf,
        deaths_eq,
        master_log_source: caps.master_log_source,
        procmgr_death_auth_source: caps.procmgr_death_auth_source,
        devmgr_registry: caps.devmgr_registry,
    };

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

        match badge
        {
            WS_BADGE_SERVICE => dispatch_ipc(caps.service_ep, state, &restart_ctx, &mut guard),
            WS_BADGE_DEATHS => dispatch_deaths(deaths_eq, state, &restart_ctx),
            _ => std::os::seraph::log!("unexpected wait-set badge"),
        }
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

/// Handle an IPC message on the service endpoint (registration, handover,
/// or discovery-registry publish/query). `ctx` carries the procmgr /
/// bootstrap / deaths-EQ state the `HANDOVER_COMPLETE` →
/// `reconcile_and_launch` path needs to spawn `.svc`-defined services.
fn dispatch_ipc(
    service_ep: u32,
    state: &mut SvcmgrState,
    ctx: &restart::RestartCtx,
    guard: &mut ipc::recv_guard::RecvGuard,
)
{
    let ipc_buf = ctx.ipc_buf;
    // SAFETY: ipc_buf is the registered IPC buffer.
    let msg = match unsafe { ipc::ipc_recv(service_ep, ipc_buf) }
    {
        Ok(msg) => msg,
        Err(e) =>
        {
            guard.on_failure(e);
            return;
        }
    };
    guard.on_success();

    let opcode = msg.label & 0xFFFF;
    match opcode
    {
        svcmgr_labels::HANDOVER_COMPLETE =>
        {
            if !definitions::handover_permitted(msg.badge, state.handover_done)
            {
                let reply = IpcMessage::new(ipc::svcmgr_errors::UNAUTHORIZED);
                // SAFETY: ipc_buf is the registered IPC buffer.
                let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
                return;
            }
            state.handover_done = true;
            // Reply BEFORE reconciliation: init's call returns and it
            // proceeds to teardown / thread_exit; svcmgr then runs the
            // (potentially slow) scan + launch path without holding
            // init blocked on the IPC reply path.
            let reply = IpcMessage::new(ipc::svcmgr_errors::SUCCESS);
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            std::os::seraph::log!("handover complete; scanning /config/svcmgr/services/");
            definitions::reconcile::reconcile_and_launch(
                &mut state.pending,
                &mut state.table,
                ctx.deaths_eq,
                ctx,
                &mut state.registry,
            );
            std::os::seraph::log!(
                "monitoring {} service(s) after reconciliation",
                state.table.services.len()
            );
        }
        svcmgr_labels::PUBLISH_ENDPOINT =>
        {
            let result = handle_publish_endpoint(&msg, &mut state.registry);
            let reply = IpcMessage::new(result);
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        }
        svcmgr_labels::QUERY_ENDPOINT =>
        {
            handle_query_endpoint(&msg, &mut state.registry, ipc_buf);
        }
        _ =>
        {
            let reply = IpcMessage::new(ipc::svcmgr_errors::UNKNOWN_OPCODE);
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        }
    }
}

/// Handle `PUBLISH_ENDPOINT`: add a `name → cap` mapping to the discovery
/// registry. The name is packed into data words 0.. per
/// [`read_name_from_msg`]; the cap arrives as the first received cap.
fn handle_publish_endpoint(msg: &IpcMessage, registry: &mut registry::Registry) -> u64
{
    // IPC delivers caps into svcmgr's CSpace before dispatch — every
    // reject path must release the delivered value cap, otherwise a
    // hostile or buggy publisher can leak a cap per call. The wire
    // only carries one cap; release every trailing slot the caller
    // may have delivered defensively.
    let recv_caps = msg.caps();
    let delivered_cap = recv_caps.first().copied().unwrap_or(0);
    for &extra in recv_caps.iter().skip(1)
    {
        if extra != 0
        {
            let _ = syscall::cap_delete(extra);
        }
    }
    let reject = |code: u64| -> u64 {
        if delivered_cap != 0
        {
            let _ = syscall::cap_delete(delivered_cap);
        }
        code
    };

    if msg.badge & svcmgr_labels::PUBLISH_AUTHORITY == 0
    {
        return reject(ipc::svcmgr_errors::UNAUTHORIZED);
    }
    let name_len = ((msg.label >> 16) & 0xFFFF) as usize;
    let Some(name) = read_name_from_msg(msg, name_len)
    else
    {
        return reject(ipc::svcmgr_errors::INVALID_NAME);
    };
    if delivered_cap == 0
    {
        return ipc::svcmgr_errors::INSUFFICIENT_CAPS;
    }
    if registry
        .publish(&name[..name_len], delivered_cap, Visibility::Public)
        .is_err()
    {
        return reject(ipc::svcmgr_errors::REGISTER_REJECTED);
    }
    ipc::svcmgr_errors::SUCCESS
}

/// Look up `name` in the discovery registry and derive a fresh
/// `RIGHTS_EP_SEND` cap on the published endpoint. Evicts the entry on
/// `cap_derive` failure (publisher's endpoint is gone), so subsequent
/// queries see `UNKNOWN_NAME` instead of looping on
/// `INSUFFICIENT_CAPS`. Returns a `svcmgr_errors::*` code on miss or
/// derivation failure.
///
/// Shared by `QUERY_ENDPOINT` (IPC, [`Resolver::Query`]: seed-only names
/// answer `UNKNOWN_NAME`) and svcmgr's own resolution ([`Resolver::Seed`]:
/// each `.svc` `seed = ...` name on the launch and restart paths, and the
/// `pwrmgr.shutdown` cap of a graceful shutdown).
pub(crate) fn registry_lookup_derived(
    registry: &mut registry::Registry,
    name: &[u8],
    resolver: Resolver,
) -> Result<u32, u64>
{
    let Some(cap) = registry.lookup(name, resolver)
    else
    {
        return Err(ipc::svcmgr_errors::UNKNOWN_NAME);
    };
    let Ok(derived) = syscall::cap_derive(cap, syscall::RIGHTS_EP_SEND)
    else
    {
        let _ = registry.remove(name);
        let _ = syscall::cap_delete(cap);
        return Err(ipc::svcmgr_errors::INSUFFICIENT_CAPS);
    };
    Ok(derived)
}

/// Handle `QUERY_ENDPOINT`: look up a name in the discovery registry and
/// reply with a derived SEND cap if found.
fn handle_query_endpoint(msg: &IpcMessage, registry: &mut registry::Registry, ipc_buf: *mut u64)
{
    let name_len = ((msg.label >> 16) & 0xFFFF) as usize;
    let Some(name) = read_name_from_msg(msg, name_len)
    else
    {
        let reply = IpcMessage::new(ipc::svcmgr_errors::INVALID_NAME);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };
    match registry_lookup_derived(registry, &name[..name_len], Resolver::Query)
    {
        Ok(derived) =>
        {
            let reply = IpcMessage::builder(ipc::svcmgr_errors::SUCCESS)
                .cap(derived)
                .build();
            // SAFETY: ipc_buf is the registered IPC buffer.
            let send_result = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            if send_result.is_err()
            {
                // ipc_reply did not transfer the cap out of svcmgr's
                // CSpace; delete the freshly-derived slot to avoid
                // cumulative leakage over svcmgr's lifetime.
                let _ = syscall::cap_delete(derived);
            }
        }
        Err(code) =>
        {
            let reply = IpcMessage::new(code);
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        }
    }
}

/// Drain all pending death notifications from the shared queue. Each
/// payload encodes the dying service's table index in the high 32 bits
/// (set as the correlator at `thread_bind_notification` time) and the
/// exit reason in the low 32. The wait-set notifies once per
/// not-empty → empty transition, so a single wakeup may cover several
/// deaths; the try-recv loop runs until the queue empties.
///
/// A drain that takes [`DEATHS_EQ_CAPACITY`] events or more may have
/// followed a full queue, whose dropped posts leave a full queue's worth of
/// events behind them for this drain or the next; the drain that crosses the
/// capacity then runs [`resync_deaths`].
fn dispatch_deaths(deaths_eq: u32, state: &mut SvcmgrState, ctx: &restart::RestartCtx)
{
    let mut drained: u32 = 0;
    while let Ok(payload) = syscall::event_try_recv(deaths_eq)
    {
        drained = drained.saturating_add(1);
        let correlator = (payload >> 32) as u32;
        let exit_reason = payload & 0xFFFF_FFFF;
        route_death(correlator, exit_reason, state, ctx);
    }
    if drained >= DEATHS_EQ_CAPACITY
    {
        std::os::seraph::log!("death queue drained {drained} events; resyncing services");
        resync_deaths(state, ctx);
    }
}

/// Route one death to its `ServiceEntry` by correlator (the table index) and
/// run the restart decision for an active entry.
fn route_death(
    correlator: u32,
    exit_reason: u64,
    state: &mut SvcmgrState,
    ctx: &restart::RestartCtx,
)
{
    let idx = correlator as usize;
    if idx >= state.table.services.len()
    {
        std::os::seraph::log!("death notification with unknown correlator");
        return;
    }
    let svc = &state.table.services[idx];
    if !svc.active
    {
        return;
    }
    // A slot's correlator outlives its instances, so a post can arrive for
    // an instance [`resync_deaths`] already routed and restarted. The kernel
    // reports the current instance's thread state; a live thread means the
    // post is the dead instance's, already handled.
    if syscall::cap_info(svc.thread_cap, syscall_abi::CAP_INFO_THREAD_STATE)
        .is_ok_and(|packed| (packed >> 32) as u32 != syscall_abi::THREAD_STATE_EXITED)
    {
        return;
    }

    // Split disjoint field borrows so handle_death gets the entry, its
    // restart recipe, and the registry (for seed re-resolution) at once.
    let SvcmgrState {
        table, registry, ..
    } = state;
    let outcome = restart::handle_death(
        &mut table.services[idx],
        exit_reason,
        ctx,
        correlator,
        table.recipes[idx].as_ref(),
        registry,
    );
    if matches!(outcome, restart::DeathOutcome::Unrecoverable)
    {
        initiate_graceful_shutdown(state, ctx, idx);
    }
}

/// Route a death for every active service whose thread the kernel reports
/// exited (`CAP_INFO_THREAD_STATE`): the recovery for death posts a full
/// queue dropped. The kernel records the state before it posts, so a service
/// whose post was lost is found here; a restart rebinds the new instance,
/// whose own death posts to the queue this drain has emptied. A post for a
/// service routed here that does arrive later is the dead instance's, and
/// [`route_death`] drops it because the entry's current thread is live.
fn resync_deaths(state: &mut SvcmgrState, ctx: &restart::RestartCtx)
{
    for idx in 0..state.table.services.len()
    {
        let svc = &state.table.services[idx];
        if !svc.active || svc.thread_cap == 0
        {
            continue;
        }
        let Ok(packed) = syscall::cap_info(svc.thread_cap, syscall_abi::CAP_INFO_THREAD_STATE)
        else
        {
            continue;
        };
        if (packed >> 32) as u32 != syscall_abi::THREAD_STATE_EXITED
        {
            continue;
        }
        // `idx` came from the table, whose slots each have a `u32`
        // correlator (`ServiceTable::reserve`).
        let Ok(correlator) = u32::try_from(idx)
        else
        {
            continue;
        };
        route_death(correlator, packed & 0xFFFF_FFFF, state, ctx);
    }
}

/// Resolve `published_names::PWRMGR_SHUTDOWN` from the discovery
/// registry and issue `pwrmgr_labels::SHUTDOWN` to power the system
/// off cleanly. Called from [`dispatch_deaths`] when a `system_critical`
/// service dies unrecoverably.
///
/// Edge case: if the dying service IS pwrmgr, the shutdown source
/// itself is gone; svcmgr logs the degraded state and returns.
/// No fallback raw-shutdown path — same shape as today's lack of a
/// recovery story for procmgr / memmgr death.
fn initiate_graceful_shutdown(state: &mut SvcmgrState, ctx: &restart::RestartCtx, dying_idx: usize)
{
    let name = state.table.services[dying_idx].name_str();
    if name == "pwrmgr"
    {
        std::os::seraph::log!(
            "critical service unrecoverable: pwrmgr; graceful shutdown impossible; \
             system in degraded state"
        );
        return;
    }

    let shutdown_cap = match registry_lookup_derived(
        &mut state.registry,
        ipc::published_names::PWRMGR_SHUTDOWN,
        Resolver::Seed,
    )
    {
        Ok(c) => c,
        Err(code) =>
        {
            std::os::seraph::log!(
                "graceful shutdown: cannot resolve {} (code={code})",
                core::str::from_utf8(ipc::published_names::PWRMGR_SHUTDOWN).unwrap_or("?")
            );
            return;
        }
    };

    let shutdown_msg = IpcMessage::new(ipc::pwrmgr_labels::SHUTDOWN);
    // SAFETY: `ctx.ipc_buf` is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_call(shutdown_cap, &shutdown_msg, ctx.ipc_buf) };
    // On the success path pwrmgr powers off and this never returns.
    // On a failure path we surface the cap leak rather than ignore it.
    let _ = syscall::cap_delete(shutdown_cap);
    std::os::seraph::log!("graceful shutdown: SHUTDOWN call returned (failure path)");
}
