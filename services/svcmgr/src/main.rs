// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// svcmgr/src/main.rs

//! Seraph service manager — monitors services, detects crashes via a
//! single shared death-notification event queue, and restarts them per
//! their restart policy.
//!
//! svcmgr is loaded from the root filesystem by init (via procmgr's
//! `CREATE_PROCESS_FROM_VFS`). Init registers services via IPC, then sends
//! `HANDOVER_COMPLETE` and exits. svcmgr runs for the lifetime of the system.
//!
//! Every supervised service binds death notification onto the same
//! `deaths_eq` with `correlator = service_index`. The wait set has two
//! members: the service endpoint (token 0) and the deaths queue
//! (token 1). On death wakeup svcmgr drains the queue and routes each
//! payload to its `ServiceEntry` via the correlator. Multiplexing
//! avoids consuming a wait-set slot per supervised process and keeps
//! the wait set inside the 16-member retype-bin sizing.
//!
//! See `svcmgr/docs/ipc-interface.md` and `svcmgr/docs/restart-protocol.md`.

// The `seraph` target is not in rustc's recognised-OS list, so `std` is
// `restricted_std`-gated for downstream bins. Every std-built service on
// seraph carries this preamble.
#![feature(restricted_std)]
// cast_possible_truncation: targets 64-bit only; u64/usize conversions lossless.
#![allow(clippy::cast_possible_truncation)]

mod arch;
mod definitions;
mod restart;
mod service;

use definitions::reconcile::PendingRegistration;
use ipc::{IpcMessage, svcmgr_labels};
use service::{MAX_SERVICES, RestartRecipe, ServiceEntry, bootstrap_caps};
use std::os::seraph::{StartupInfo, startup_info};

/// Global discovery registry size. Enough for a handful of top-level named
/// endpoints (vfsd, logd, procmgr, …) plus slack.
const REGISTRY_CAPACITY: usize = 8;

/// Maximum services init may pre-register before
/// [`svcmgr_labels::HANDOVER_COMPLETE`] runs reconciliation. Sized to
/// match [`MAX_SERVICES`] — svcmgr cannot supervise more entries
/// than its `ServiceEntry` table can hold.
const MAX_PENDING_REGISTRATIONS: usize = MAX_SERVICES;

// ── Registration handling ──────────────────────────────────────────────────

/// Handle a `REGISTER_SERVICE` IPC message under the v3 wire (post-#21).
///
/// The recipe lives on disk at `/config/svcmgr/services/<name>.svc`; the
/// wire conveys only what cannot be on disk:
///
/// * `word 0`: `SVCMGR_LABELS_VERSION` handshake.
/// * `word 1`: `name_len` (byte length of the service name).
/// * `words 2..`: `name` bytes.
/// * `caps[0]`: thread cap for death-notification binding.
///
/// The thread cap is parked in `pending`; binding to the deaths event
/// queue is deferred to [`definitions::reconcile::reconcile_and_launch`]
/// after handover, where each pending entry is paired with its `.svc`
/// definition (or reported as a configuration error if no recipe
/// exists). See [`ipc::svcmgr_labels::REGISTER_SERVICE`] for the
/// authoritative spec.
fn handle_register(
    msg: &IpcMessage,
    pending: &mut [PendingRegistration],
    pending_count: &mut usize,
) -> u64
{
    // IPC delivers caps into svcmgr's CSpace before dispatch — every
    // reject path must release the delivered thread cap, otherwise a
    // hostile or buggy registrar can leak a cap per request over
    // svcmgr's lifetime. The v3 wire only carries one cap; release
    // every trailing slot the caller may have delivered defensively.
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

    if msg.word(0) != u64::from(ipc::SVCMGR_LABELS_VERSION)
    {
        return reject(ipc::svcmgr_errors::LABEL_VERSION_MISMATCH);
    }

    let name_len = msg.word(1) as usize;
    if name_len == 0 || name_len > 32
    {
        return reject(ipc::svcmgr_errors::INVALID_NAME);
    }

    if *pending_count >= MAX_PENDING_REGISTRATIONS
    {
        return reject(ipc::svcmgr_errors::TABLE_FULL);
    }

    if delivered_cap == 0
    {
        return ipc::svcmgr_errors::INSUFFICIENT_CAPS;
    }

    // delivered_cap transfers into PendingRegistration from here.
    let mut name = [0u8; 32];
    read_packed_bytes(msg, 2, name_len, &mut name);

    let idx = *pending_count;
    pending[idx] = PendingRegistration {
        name,
        name_len: name_len as u8,
        thread_cap: delivered_cap,
        consumed: false,
    };
    *pending_count += 1;

    std::os::seraph::log!("registered: {}", pending[idx].name_str());

    ipc::svcmgr_errors::SUCCESS
}

/// Read a short name packed into IPC data words starting at `first_word`.
fn read_tail_name_from_msg(
    msg: &IpcMessage,
    first_word: usize,
    name_len: usize,
) -> [u8; registry::NAME_MAX]
{
    let mut out = [0u8; registry::NAME_MAX];
    read_packed_bytes(msg, first_word, name_len, &mut out);
    out
}

/// Unpack `byte_len` bytes from IPC data words starting at `first_word`
/// into `out`. Caller must ensure `byte_len <= out.len()`.
fn read_packed_bytes(msg: &IpcMessage, first_word: usize, byte_len: usize, out: &mut [u8])
{
    let words = byte_len.div_ceil(8);
    for w in 0..words
    {
        let word = msg.word(first_word + w);
        for b in 0..8
        {
            let idx = w * 8 + b;
            if idx < byte_len && idx < out.len()
            {
                out[idx] = (word >> (b * 8)) as u8;
            }
        }
    }
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

    let Some(caps) = bootstrap_caps(info, ipc_buf)
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

    let Some(ws_slab) = std::os::seraph::object_slab_acquire(512)
    else
    {
        std::os::seraph::log!("failed to acquire frame for wait set");
        halt_loop();
    };
    let Ok(ws_cap) = syscall::wait_set_create(ws_slab)
    else
    {
        std::os::seraph::log!("failed to create wait set");
        halt_loop();
    };

    // One shared death-notification queue, capacity sized so a burst of
    // simultaneous service crashes (worst case `MAX_SERVICES`) cannot
    // overflow before svcmgr drains. Inline-slot bytes follow
    // `cap::retype::event_queue_raw_bytes`: 24 wrapper + 56 state +
    // (capacity + 1) * 8 ring.
    let deaths_eq_slab_bytes: u64 = 24 + 56 + ((MAX_SERVICES as u64 * 2) + 1) * 8;
    let Some(eq_slab) = std::os::seraph::object_slab_acquire(deaths_eq_slab_bytes)
    else
    {
        std::os::seraph::log!("failed to acquire frame for deaths event queue");
        halt_loop();
    };
    let Ok(deaths_eq) = syscall::event_queue_create(eq_slab, (MAX_SERVICES as u32) * 2)
    else
    {
        std::os::seraph::log!("failed to create deaths event queue");
        halt_loop();
    };

    // Frame slab svcmgr retypes provider service endpoints from. One page
    // backs every `provides = ...` service (each `cap_create_endpoint`
    // carves an endpoint object from it); the provider set is small.
    let Some(endpoint_slab) = std::os::seraph::object_slab_acquire(syscall_abi::PAGE_SIZE)
    else
    {
        std::os::seraph::log!("failed to acquire frame for provider endpoint slab");
        halt_loop();
    };

    if syscall::wait_set_add(ws_cap, caps.service_ep, WS_TOKEN_SERVICE).is_err()
    {
        std::os::seraph::log!("failed to add service endpoint to wait set");
        halt_loop();
    }
    if syscall::wait_set_add(ws_cap, deaths_eq, WS_TOKEN_DEATHS).is_err()
    {
        std::os::seraph::log!("failed to add deaths event queue to wait set");
        halt_loop();
    }

    let mut state = SvcmgrState {
        services: [const { ServiceEntry::empty() }; MAX_SERVICES],
        recipes: [const { None }; MAX_SERVICES],
        service_count: 0,
        pending: [const { PendingRegistration::empty() }; MAX_PENDING_REGISTRATIONS],
        pending_count: 0,
        registry: registry::Registry::new(),
    };

    std::os::seraph::log!("waiting for registrations");

    event_loop(
        info,
        &caps,
        ws_cap,
        deaths_eq,
        endpoint_slab,
        ipc_buf,
        &mut state,
    );
}

/// `WaitSet` token for svcmgr's service endpoint.
const WS_TOKEN_SERVICE: u64 = 0;
/// `WaitSet` token for svcmgr's shared death event queue.
const WS_TOKEN_DEATHS: u64 = 1;

/// Monitored service table, pending-registration table, discovery
/// registry, and handover flag. Held across the event loop for the
/// lifetime of the process.
///
/// `pending` is populated by [`handle_register`] as init announces
/// each running service it spawned during Phase 3. On
/// `HANDOVER_COMPLETE` [`definitions::reconcile::reconcile_and_launch`]
/// pairs each entry with a `.svc` recipe, binds death-notification,
/// and populates `services`. After reconciliation `pending` is
/// effectively read-only — the unconsumed entries persist as logged
/// configuration errors but are not re-used.
pub struct SvcmgrState
{
    pub services: [ServiceEntry; MAX_SERVICES],
    /// Heap-backed restart surfaces, index-aligned with `services` via
    /// the death correlator. `None` for slots with no svcmgr-launched
    /// recipe. See [`RestartRecipe`].
    pub recipes: [Option<RestartRecipe>; MAX_SERVICES],
    pub service_count: usize,
    pub pending: [PendingRegistration; MAX_PENDING_REGISTRATIONS],
    pub pending_count: usize,
    pub registry: registry::Registry<REGISTRY_CAPACITY>,
}

/// Main event loop: dispatches IPC registrations and death notifications.
fn event_loop(
    info: &StartupInfo,
    caps: &service::SvcmgrCaps,
    ws_cap: u32,
    deaths_eq: u32,
    endpoint_slab: u32,
    ipc_buf: *mut u64,
    state: &mut SvcmgrState,
) -> !
{
    let restart_ctx = restart::RestartCtx {
        procmgr_ep: info.procmgr_endpoint,
        bootstrap_ep: caps.bootstrap_ep,
        ipc_buf,
        deaths_eq,
        endpoint_slab,
    };

    loop
    {
        let Ok(token) = syscall::wait_set_wait(ws_cap)
        else
        {
            std::os::seraph::log!("wait_set_wait failed");
            continue;
        };

        match token
        {
            WS_TOKEN_SERVICE => dispatch_ipc(caps.service_ep, state, &restart_ctx),
            WS_TOKEN_DEATHS => dispatch_deaths(deaths_eq, state, &restart_ctx),
            _ => std::os::seraph::log!("unexpected wait-set token"),
        }
    }
}

/// Handle an IPC message on the service endpoint (registration, handover,
/// or discovery-registry publish/query). `ctx` carries the procmgr /
/// bootstrap / deaths-EQ state the `HANDOVER_COMPLETE` →
/// `reconcile_and_launch` path needs to spawn `.svc`-defined services.
fn dispatch_ipc(service_ep: u32, state: &mut SvcmgrState, ctx: &restart::RestartCtx)
{
    let ipc_buf = ctx.ipc_buf;
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(msg) = (unsafe { ipc::ipc_recv(service_ep, ipc_buf) })
    else
    {
        return;
    };

    let opcode = msg.label & 0xFFFF;
    match opcode
    {
        svcmgr_labels::REGISTER_SERVICE =>
        {
            let result = handle_register(&msg, &mut state.pending, &mut state.pending_count);
            let reply = IpcMessage::new(result);
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        }
        svcmgr_labels::HANDOVER_COMPLETE =>
        {
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
                state.pending_count,
                &mut state.services,
                &mut state.recipes,
                &mut state.service_count,
                ctx.deaths_eq,
                ctx,
                &mut state.registry,
            );
            std::os::seraph::log!(
                "monitoring {} service(s) after reconciliation",
                state.service_count
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
/// [`read_tail_name_from_msg`]; the cap arrives as the first received cap.
fn handle_publish_endpoint(
    msg: &IpcMessage,
    registry: &mut registry::Registry<REGISTRY_CAPACITY>,
) -> u64
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

    if msg.token & svcmgr_labels::PUBLISH_AUTHORITY == 0
    {
        return reject(ipc::svcmgr_errors::UNAUTHORIZED);
    }
    let name_len = ((msg.label >> 16) & 0xFFFF) as usize;
    if name_len == 0 || name_len > registry::NAME_MAX
    {
        return reject(ipc::svcmgr_errors::INVALID_NAME);
    }
    if delivered_cap == 0
    {
        return ipc::svcmgr_errors::INSUFFICIENT_CAPS;
    }
    let name = read_tail_name_from_msg(msg, 0, name_len);
    if registry.publish(&name[..name_len], delivered_cap).is_err()
    {
        return reject(ipc::svcmgr_errors::REGISTER_REJECTED);
    }
    ipc::svcmgr_errors::SUCCESS
}

/// Look up `name` in the discovery registry and derive a fresh
/// `RIGHTS_SEND` cap on the published endpoint. Evicts the entry on
/// `cap_derive` failure (publisher's endpoint is gone), so subsequent
/// queries see `UNKNOWN_NAME` instead of looping on
/// `INSUFFICIENT_CAPS`. Returns a `svcmgr_errors::*` code on miss or
/// derivation failure.
///
/// Shared by `QUERY_ENDPOINT` (IPC) and the post-handover launch path
/// (resolves each `.svc` `seed = ...` name into a cap to inject into
/// the child's bootstrap round).
pub(crate) fn registry_lookup_derived(
    registry: &mut registry::Registry<REGISTRY_CAPACITY>,
    name: &[u8],
) -> Result<u32, u64>
{
    let Some(cap) = registry.lookup(name)
    else
    {
        return Err(ipc::svcmgr_errors::UNKNOWN_NAME);
    };
    let Ok(derived) = syscall::cap_derive(cap, syscall::RIGHTS_SEND)
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
fn handle_query_endpoint(
    msg: &IpcMessage,
    registry: &mut registry::Registry<REGISTRY_CAPACITY>,
    ipc_buf: *mut u64,
)
{
    let name_len = ((msg.label >> 16) & 0xFFFF) as usize;
    if name_len == 0 || name_len > registry::NAME_MAX
    {
        let reply = IpcMessage::new(ipc::svcmgr_errors::INVALID_NAME);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    }
    let name = read_tail_name_from_msg(msg, 0, name_len);
    match registry_lookup_derived(registry, &name[..name_len])
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
fn dispatch_deaths(deaths_eq: u32, state: &mut SvcmgrState, ctx: &restart::RestartCtx)
{
    loop
    {
        let Ok(payload) = syscall::event_try_recv(deaths_eq)
        else
        {
            return;
        };
        let correlator = (payload >> 32) as u32;
        let exit_reason = payload & 0xFFFF_FFFF;
        let idx = correlator as usize;

        if idx >= state.service_count
        {
            std::os::seraph::log!("death notification with unknown correlator");
            continue;
        }
        if !state.services[idx].active
        {
            continue;
        }

        // Split disjoint field borrows so handle_death gets the entry, its
        // restart recipe, and the registry (for seed re-resolution) at once.
        let SvcmgrState {
            services,
            recipes,
            registry,
            ..
        } = state;
        let outcome = restart::handle_death(
            &mut services[idx],
            exit_reason,
            ctx,
            correlator,
            recipes[idx].as_ref(),
            registry,
        );
        if matches!(outcome, restart::DeathOutcome::Unrecoverable)
        {
            initiate_graceful_shutdown(state, ctx, idx);
        }
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
    let name = state.services[dying_idx].name_str();
    if name == "pwrmgr"
    {
        std::os::seraph::log!(
            "critical service unrecoverable: pwrmgr; graceful shutdown impossible; \
             system in degraded state"
        );
        return;
    }

    let shutdown_cap =
        match registry_lookup_derived(&mut state.registry, ipc::published_names::PWRMGR_SHUTDOWN)
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
