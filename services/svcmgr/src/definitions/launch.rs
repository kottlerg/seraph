// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/src/definitions/launch.rs

//! First-launch spawn path driven by a parsed `.svc` [`Definition`].
//!
//! Mirrors restart's spawn primitives ([`crate::restart`]) so that
//! services launched by svcmgr post-handover go through exactly the
//! same procmgr surface (`CREATE_FROM_FILE` → `CONFIGURE_NAMESPACE`
//! → `START_PROCESS` → bootstrap rounds) that restart uses. Returns
//! the [`Launched`] handles; for a supervised launch [`launch`] binds
//! the service's death observers itself, before `START_PROCESS`.

use ipc::bootstrap::ServeFailure;
use ipc::procmgr_labels;
use registry::{Resolver, Visibility};
use svcmgr_defs::DeathTag;
use svcmgr_defs::class::class_publication;

use super::{Definition, NamespaceShape, ProvidedName, build_blob, cwd_rights};
use crate::registry_lookup_derived;
use crate::restart::{
    CreatedProcess, RestartCtx, StartupBlobs, bind_instance_observers, caps_death,
    create_label_bits, destroy_partial_child, mint_core_death_recv, mint_debug_authority,
    mint_entropy_authority, mint_stop_authority, start_process, walk_and_create_from_file,
};

/// Outcome of a successful launch — the bits svcmgr records on the
/// resulting `ServiceEntry`. A one-shot (`restart = never`) caller records
/// nothing and deletes the handles.
pub struct Launched
{
    pub thread_cap: u64,
    pub process_handle: u64,
    /// Persistent service-endpoint source for a `provides = ...` service,
    /// stored on the `ServiceEntry` so restarts re-serve a fresh RECV on
    /// the same object. Zero for pure-consumer services.
    pub provided_endpoint: u64,
    /// The node handle of the child's budget node for an `oom_stop = yes`
    /// service ([`CreatedProcess::node_handle`]); zero for every other.
    pub node_handle: u64,
    /// The exit reason of a child that died during its bootstrap rounds, which
    /// the caller routes as the service's death; `None` for a child that took
    /// them.
    pub died: Option<u64>,
}

/// Whether a launch is of the recognised shutdown actuator, which owns the
/// core set's death: it is created pinned, and its bootstrap round carries a
/// receive-only derivation of the core-death queue (docs/supervision.md
/// § Core Set and System Death).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role
{
    /// The shutdown actuator `reconcile_and_launch` recognised.
    ShutdownActuator,
    /// Every other service.
    Ordinary,
}

/// Delete a set of cap slots, skipping the zero sentinel. Used on the
/// launch/restart cleanup paths where a partially-assembled cap set must
/// be released; deleting an already-transferred slot is a kernel no-op.
pub(crate) fn delete_caps(caps: &[u64])
{
    for &c in caps
    {
        if c != 0
        {
            let _ = syscall::cap_delete(c);
        }
    }
}

/// Assemble a child's positional bootstrap slots: the provider
/// service-endpoint RECV (`provided_recv`, slot 0) ahead of the positional
/// `seeds`. A `provided_recv` of `0` (pure consumer) is skipped. Any number
/// of slots is served, over as many rounds as they need (see
/// [`serve_boot_slots`]). Consumes `seeds`.
pub(crate) fn assemble_boot_caps(provided_recv: u64, seeds: Vec<u64>) -> Vec<u64>
{
    let mut caps: Vec<u64> = Vec::with_capacity(seeds.len().saturating_add(1));
    if provided_recv != 0
    {
        caps.push(provided_recv);
    }
    caps.extend(seeds);
    caps
}

/// Serve a child's bootstrap rounds from its positional `slots` (`0` marks
/// an absent cap). A round carries at most `MSG_CAP_SLOTS_MAX` caps, so the
/// slots are split over [`ipc::bootstrap::slot_rounds`] windows, one round
/// each, the last marked done. The kernel refuses a message carrying a null
/// cap slot, so each round transfers only its window's present caps, in slot
/// order, with the window's presence word in `data[0]`; the child
/// concatenates the rounds with [`ipc::bootstrap::request_slots`] (encoding
/// in [service-definitions.md § `seed`](../../docs/service-definitions.md#seed)).
/// Shared by the launch and restart paths.
///
/// Each round's wait for the child's request is watched
/// ([`ipc::bootstrap::serve_round_watched`]): every
/// [`ipc::bootstrap::WATCH_POLL_MS`] svcmgr reads the child's main thread
/// through `thread_cap` ([`caps_death`]), so a child that dies before a
/// request ends the serve
/// instead of holding svcmgr's only thread, and with it every death svcmgr
/// routes, for good. The read is svcmgr's own `cap_info`, which no other
/// service answers. A live child that sends no request is still waited for.
///
/// # Errors
/// The [`ServeFailure`] of the first round that fails: the child's death,
/// or the round's refusal; the caps of the rounds after it are still the
/// caller's.
pub(crate) fn serve_boot_slots(
    ctx: &RestartCtx,
    child_badge: u64,
    thread_cap: u64,
    slots: &[u64],
) -> Result<(), ServeFailure>
{
    let rounds = ipc::bootstrap::slot_round_count(slots.len());
    for (k, packed) in ipc::bootstrap::slot_rounds(slots).enumerate()
    {
        // SAFETY: `ctx.ipc_buf` is the registered IPC buffer.
        unsafe {
            ipc::bootstrap::serve_round_watched(
                ctx.bootstrap_ep,
                child_badge,
                ctx.ipc_buf,
                k.saturating_add(1) == rounds,
                packed.caps(),
                &[packed.presence()],
                ipc::bootstrap::WATCH_POLL_MS,
                || caps_death(thread_cap, 0),
            )
        }?;
    }
    Ok(())
}

/// Which launch of the log-sink service [`mint_logd_boot_caps`] mints for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum LaunchKind
{
    /// The reconciliation launch, and a respawn while procmgr does not report
    /// init reaped (`svcmgr_defs::log_sink_handover_owed`): init-logd may
    /// still serve the log endpoint, so the round carries the
    /// `HANDOVER_PULL` SEND.
    First,
    /// A respawn once procmgr reports init reaped: init-logd has exited, so
    /// the `HANDOVER_PULL` slot is `0`.
    Restart,
}

/// Mint the five bootstrap caps real-logd expects, from the reserved
/// log-sink sources svcmgr holds for the system's life and from the
/// `devmgr.class.*` publications ([`crate::classes`]):
///   * `[0]` master-log endpoint RECV (svcmgr's source stays valid, so a
///     fresh RECV reattaches each (re)launched logd to the same object that
///     every sender's `log_send_cap` targets);
///   * `[1]` a SEND on the same endpoint for the one-shot `HANDOVER_PULL`,
///     present only for [`LaunchKind::First`] — a restart after init's reap has
///     no init-logd to pull from, so this is `0` and logd skips the history pull;
///   * `[2]` a `DEATH_EQ_AUTHORITY` `SEND|GRANT` on procmgr (logd registers sender
///     death-notifications for slot reclaim) — `SEND|GRANT` because that
///     registration transfers a cap;
///   * `[3]` the `serial` class SEND (`devmgr.class.serial`), through which
///     logd resolves the serial driver with `QUERY_DEVICE`;
///   * `[4]` the `framebuffer` class SEND (`devmgr.class.framebuffer`), the
///     same for the framebuffer driver.
///
/// A publication is named by its class file's stem, not by the class the
/// file configures; these two carry the `serial` and `framebuffer` classes
/// because the shipped `serial.class` and `framebuffer.class` set no `class`
/// key naming another.
///
/// logd's recipe declares `log_sink`, which excludes `seed`, so svcmgr
/// resolves these two publications for it here.
/// A source absent from the endowment, an unpublished class, or a derive
/// that fails, yields `0` in its slot. The slots are positional; [`serve_boot_slots`] transfers
/// only the present caps and names the slot each fills in the round's
/// presence word, so a round with an absent slot, such as every
/// [`LaunchKind::Restart`] round, still reaches logd.
pub(crate) fn mint_logd_boot_caps(
    ctx: &RestartCtx,
    kind: LaunchKind,
    registry: &mut registry::Registry,
) -> Vec<u64>
{
    let recv = if ctx.master_log_source != 0
    {
        syscall::cap_derive(ctx.master_log_source, syscall::RIGHTS_EP_RECEIVE).unwrap_or(0)
    }
    else
    {
        0
    };
    let handover_send = if kind == LaunchKind::First && ctx.master_log_source != 0
    {
        syscall::cap_derive(ctx.master_log_source, syscall::RIGHTS_EP_SEND).unwrap_or(0)
    }
    else
    {
        0
    };
    let death_auth = if ctx.procmgr_death_auth_source != 0
    {
        syscall::cap_derive_badge(
            ctx.procmgr_death_auth_source,
            syscall::RIGHTS_EP_SEND_GRANT,
            procmgr_labels::DEATH_EQ_AUTHORITY,
        )
        .unwrap_or(0)
    }
    else
    {
        0
    };
    let mut class_send = |class: &[u8]| {
        class_publication(class)
            .and_then(|name| registry_lookup_derived(registry, &name, Resolver::Seed).ok())
            .unwrap_or(0)
    };
    let serial = class_send(b"serial");
    let framebuffer = class_send(b"framebuffer");
    std::vec![recv, handover_send, death_auth, serial, framebuffer]
}

/// Publish each name in a provider's `provides` list under the discovery
/// registry once the endpoint exists, so consumers launched after it
/// resolve them. Each name's SEND is stamped with its
/// [`ProvidedName::badge`] (`cap_derive_badge` when non-zero, plain
/// `cap_derive` for a bare entry); the badge rides through to a
/// consumer unchanged. A name whose badge carries a verb bit is published
/// seed-only, so `QUERY_ENDPOINT` refuses it; a `:grant` name
/// ([`ProvidedName::grant`]) is published `SEND|GRANT` and
/// [`Visibility::SeedOnlyGrant`], so its seeds can move caps to the provider. The endpoint persists on
/// the `ServiceEntry`, so the SENDs stay valid across restarts. No-op for
/// a pure consumer (`provided_endpoint == 0`) or an empty list.
fn publish_provided(
    provided_endpoint: u64,
    provides: &[ProvidedName],
    registry: &mut registry::Registry,
    svc_name: &str,
)
{
    if provided_endpoint == 0
    {
        return;
    }
    for p in provides
    {
        let rights = if p.grant
        {
            syscall::RIGHTS_EP_SEND_GRANT
        }
        else
        {
            syscall::RIGHTS_EP_SEND
        };
        let derived = if p.badge == 0
        {
            syscall::cap_derive(provided_endpoint, rights)
        }
        else
        {
            syscall::cap_derive_badge(provided_endpoint, rights, p.badge)
        };
        let Ok(send) = derived
        else
        {
            std::os::seraph::log!(
                warn: "launch {svc_name}: provider SEND derive for {:?} failed",
                p.name
            );
            continue;
        };
        // An entry whose badge carries a verb bit (`:auth`, `:grant`) is
        // authority; only the recipes seeding it may hold it. A `:grant`
        // entry always carries the verb bit (the parser stamps it).
        let visibility = if p.grant
        {
            Visibility::SeedOnlyGrant
        }
        else if p.badge & ipc::VERB_BIT_MASK == 0
        {
            Visibility::Public
        }
        else
        {
            Visibility::SeedOnly
        };
        if registry
            .publish(p.name.as_bytes(), send, visibility)
            .is_err()
        {
            std::os::seraph::log!(warn: "launch {svc_name}: publish {:?} failed", p.name);
            let _ = syscall::cap_delete(send);
        }
    }
}

/// Assemble the non-log-sink bootstrap cap set: create the persistent
/// provider service endpoint (when `provides` is non-empty) so svcmgr owns the
/// restart-stable source, resolve the `seed` caps, and lead with the provider
/// RECV as cap[0] ahead of the positional seeds. Returns
/// `(provided_endpoint, boot_caps)`; `provided_endpoint` is `0` for a pure
/// consumer. Runs after namespace + death bind and before `START_PROCESS`, so
/// any failure destroys the partial child and returns `None`. The recognised
/// shutdown actuator ([`Role::ShutdownActuator`]) also receives a receive-only
/// derivation of the core-death queue, in the slot after its seeds and
/// authority caps.
fn assemble_provided_boot_caps(
    def: &Definition,
    created: &CreatedProcess,
    ctx: &RestartCtx,
    registry: &mut registry::Registry,
    role: Role,
) -> Option<(u64, Vec<u64>)>
{
    let provided_endpoint = if def.provides.is_empty()
    {
        0
    }
    else
    {
        let Some(ep) =
            std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
                syscall::cap_create_endpoint(slab).ok()
            })
        else
        {
            std::os::seraph::log!(warn: "launch {}: provider endpoint create failed", def.name);
            destroy_partial_child(created.process_handle, created.thread_cap, ctx.ipc_buf);
            return None;
        };
        ep
    };

    // Resolve seeds after namespace setup. Resolution cannot fail: an
    // unresolved name becomes `0` in its slot (see `resolve_seeds`). A
    // debug-authority holder's authority cap rides the slot after them, a
    // stop-authority holder's the slot after that, and the entropy-authority
    // holder's the slot after those.
    let mut seed_caps = resolve_seeds(&def.seed, &def.name, registry);
    if def.debug_authority
    {
        seed_caps.push(mint_debug_authority(ctx));
    }
    if def.stop_authority
    {
        seed_caps.push(mint_stop_authority(ctx));
    }
    if def.entropy_authority
    {
        seed_caps.push(mint_entropy_authority(ctx));
    }
    if role == Role::ShutdownActuator
    {
        seed_caps.push(mint_core_death_recv(ctx));
    }

    // A provider's own service-endpoint RECV is cap[0], ahead of the positional
    // seeds. Derive it before assembly so a derive failure tears the partial
    // child down cleanly.
    let provided_recv = if provided_endpoint != 0
    {
        let Ok(recv) = syscall::cap_derive(provided_endpoint, syscall::RIGHTS_EP_RECEIVE)
        else
        {
            std::os::seraph::log!(warn: "launch {}: provider RECV derive failed", def.name);
            delete_caps(&seed_caps);
            let _ = syscall::cap_delete(provided_endpoint);
            destroy_partial_child(created.process_handle, created.thread_cap, ctx.ipc_buf);
            return None;
        };
        recv
    }
    else
    {
        0
    };
    Some((
        provided_endpoint,
        assemble_boot_caps(provided_recv, seed_caps),
    ))
}

/// Spawn a service from its parsed `.svc` definition.
///
/// Returns `Some(Launched)` on success, with the child running and
/// its bootstrap rounds delivered, or with the child dead during them
/// ([`Launched::died`]): the rounds not served are released, the provided
/// names are published as for a child that took them, since the endpoint
/// outlives the instance, and the caller routes the death. Returns `None` if
/// any step fails;
/// in that case the child has been destroyed and any resolved seed caps
/// and its node handle have been released; a create whose reply caps never reach svcmgr (see
/// [`walk_and_create_from_file`]) leaves no child, since procmgr destroys
/// a child whose create reply it cannot deliver.
///
/// A seed that fails to resolve leaves its slot absent: the round omits it
/// and clears its presence bit, so the child's decoder sees `0` in that
/// position. This matches the "absent dep ⇒ skip" pattern consumers use
/// for an optional seed; consumers that don't tolerate a missing cap fail on
/// first use, which is the right surface for a real misconfiguration.
///
/// `bind_target` carries the death tag of a supervised launch: when present,
/// both death observers are bound on `ctx.deaths` under it before
/// `START_PROCESS` ([`bind_instance_observers`]), one on the main thread and
/// one on the address space, so a death of any thread of the service, from
/// the instant it runs, reaches svcmgr. For one-shot launches
/// (`restart = never`, e.g. `svctest`) the caller passes `None` and forgoes
/// supervision binding.
///
/// `role` marks the recognised shutdown actuator, which is created pinned and
/// whose round carries a receive-only derivation of the core-death queue
/// (docs/supervision.md § Core Set and System Death).
pub fn launch(
    def: &Definition,
    ctx: &RestartCtx,
    registry: &mut registry::Registry,
    bind_target: Option<DeathTag>,
    role: Role,
) -> Option<Launched>
{
    let (argv_blob, argv_count) = build_blob(&def.argv);
    let (env_blob, env_count) = build_blob(&def.env);
    let blobs = StartupBlobs {
        argv: &argv_blob,
        argv_count,
        env: &env_blob,
        env_count,
    };

    let created = walk_and_create_from_file(
        &def.binary,
        blobs,
        create_label_bits(
            def.priority.unwrap_or(0),
            def.sched_max.unwrap_or(0),
            def.reserve,
            def.oom_stop,
            def.stop_source.is_some(),
            role == Role::ShutdownActuator,
        ),
        ctx.procmgr_ep,
        ctx.bootstrap_ep,
        ctx.ipc_buf,
    )?;

    let launched = launch_created(def, &created, ctx, registry, bind_target, role);
    if launched.is_none()
    {
        // Every failure after the create destroyed the child; its node
        // handle, which memmgr now refuses, is released here.
        delete_caps(&[created.node_handle]);
    }
    launched
}

/// The steps of [`launch`] after the create: namespace, death observers,
/// bootstrap caps, `START_PROCESS` and the bootstrap rounds, then the
/// publication of the provided names. `None` when a step fails, the child
/// destroyed; a child that died during its rounds is no failed step
/// ([`Launched::died`]).
fn launch_created(
    def: &Definition,
    created: &CreatedProcess,
    ctx: &RestartCtx,
    registry: &mut registry::Registry,
    bind_target: Option<DeathTag>,
    role: Role,
) -> Option<Launched>
{
    if !configure_namespace(def, created, ctx)
    {
        return None;
    }

    // Bind the death observers BEFORE start_process so any immediate
    // post-start death is captured. Thread is suspended at this
    // point — no userspace code has run yet.
    if let Some(tag) = bind_target
        && !bind_instance_observers(
            ctx,
            created.thread_cap,
            created.process_handle,
            tag.correlator(),
        )
    {
        std::os::seraph::log!(warn: "launch {}: death observer bind failed", def.name);
        destroy_partial_child(created.process_handle, created.thread_cap, ctx.ipc_buf);
        return None;
    }

    // Bootstrap cap set + (for providers) the persistent service endpoint.
    // The log-sink service (real-logd) gets a svcmgr-minted round from the
    // reserved log-sink sources; the parser guarantees it declares neither
    // `provides` nor `seed`, so it never enters the provider/seed path.
    let (provided_endpoint, boot_caps) = if def.log_sink
    {
        (0, mint_logd_boot_caps(ctx, LaunchKind::First, registry))
    }
    else
    {
        assemble_provided_boot_caps(def, created, ctx, registry, role)?
    };

    if !start_process(created.process_handle, ctx.ipc_buf)
    {
        delete_caps(&boot_caps);
        if provided_endpoint != 0
        {
            let _ = syscall::cap_delete(provided_endpoint);
        }
        destroy_partial_child(created.process_handle, created.thread_cap, ctx.ipc_buf);
        return None;
    }

    let died = match serve_boot_slots(ctx, created.child_badge, created.thread_cap, &boot_caps)
    {
        Ok(()) => None,
        Err(ServeFailure::ChildDied(exit_reason)) =>
        {
            // The caps of the rounds not served are still svcmgr's (deleting
            // a transferred slot is a no-op). The dead child is the caller's
            // to route, and no line is written here: the death's lines are
            // the routing's, which holds the log sink's until a next instance
            // runs.
            delete_caps(&boot_caps);
            Some(exit_reason)
        }
        Err(ServeFailure::Refused(_)) =>
        {
            std::os::seraph::log!(warn: "launch {}: bootstrap serve failed", def.name);
            // The started child is blocked in its bootstrap request; destroy
            // it rather than leave it waiting on a round that will not come.
            delete_caps(&boot_caps);
            if provided_endpoint != 0
            {
                let _ = syscall::cap_delete(provided_endpoint);
            }
            destroy_partial_child(created.process_handle, created.thread_cap, ctx.ipc_buf);
            return None;
        }
    };

    // Publish the provided name now that the endpoint exists, so consumers
    // launched after this provider resolve it.
    publish_provided(provided_endpoint, &def.provides, registry, &def.name);

    Some(Launched {
        thread_cap: created.thread_cap,
        process_handle: created.process_handle,
        provided_endpoint,
        node_handle: created.node_handle,
        died,
    })
}

/// Resolve each `seed = ...` name to a derived `RIGHTS_EP_SEND` cap on
/// the published endpoint. Unresolved names become `0` in their slot
/// so positional ordering is preserved; [`serve_boot_slots`] leaves an
/// absent slot off the round and clears its presence bit.
///
/// Shared by the launch path and the restart path (which passes the
/// service's stored [`crate::service::RestartRecipe`] seeds), so a
/// restarted child gets the same positional cap set it got on first
/// launch. `svc_name` is for logging only.
pub(crate) fn resolve_seeds(
    seed: &[String],
    svc_name: &str,
    registry: &mut registry::Registry,
) -> Vec<u64>
{
    let mut caps: Vec<u64> = Vec::with_capacity(seed.len());
    for name in seed
    {
        match registry_lookup_derived(registry, name.as_bytes(), Resolver::Seed)
        {
            Ok(cap) => caps.push(cap),
            Err(code) =>
            {
                std::os::seraph::log!(warn: "launch {svc_name}: seed {name:?} unresolved (code={code})");
                caps.push(0);
            }
        }
    }
    caps
}

/// Resolve `def.namespace` into the child's namespace cap, then hand it
/// (plus `def.cwd`) to [`crate::restart::configure_namespace_caps`], the
/// cwd-walk + `CONFIGURE_NAMESPACE` delivery shared with the restart path.
/// On any failure the partial child is destroyed and `false` is returned.
fn configure_namespace(def: &Definition, created: &CreatedProcess, ctx: &RestartCtx) -> bool
{
    let process_handle = created.process_handle;
    let thread_cap = created.thread_cap;

    // The subtree's path and rights, `None` for the universal namespace.
    let subtree = match &def.namespace
    {
        NamespaceShape::None =>
        {
            if def.cwd.is_some()
            {
                std::os::seraph::log!(warn: "launch {}: cwd with namespace=none rejected", def.name);
                destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
                return false;
            }
            return true;
        }
        NamespaceShape::Universal => None,
        NamespaceShape::Subtree { path, rights } => Some((path, *rights)),
    };

    let root_cap = std::os::seraph::root_dir_cap();
    if root_cap == 0
    {
        std::os::seraph::log!(warn: "launch {}: no root_dir_cap configured", def.name);
        destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
        return false;
    }
    let Some(info) = std::os::seraph::try_startup_info()
    else
    {
        std::os::seraph::log!(warn: "launch {}: no startup info for cap_copy", def.name);
        destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
        return false;
    };

    let ns_cap = match subtree
    {
        None =>
        {
            let Ok(c) = syscall::cap_copy(root_cap, info.self_cspace, syscall::RIGHTS_EP_SEND)
            else
            {
                std::os::seraph::log!(warn: "launch {}: cap_copy of root failed", def.name);
                destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
                return false;
            };
            c
        }
        Some((path, rights)) =>
        {
            match std::os::seraph::namespace_lookup_dir(root_cap, path, u64::from(rights))
            {
                Ok(c) => c,
                Err(e) =>
                {
                    std::os::seraph::log!(
                        warn: "launch {}: subtree walk {:?} failed: {e}",
                        def.name,
                        path
                    );
                    destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
                    return false;
                }
            }
        }
    };

    // cwd walk + CONFIGURE_NAMESPACE delivery + cap cleanup is shared
    // with the restart path so both paths install cwd identically.
    crate::restart::configure_namespace_caps(
        ns_cap,
        def.cwd.as_deref(),
        cwd_rights(subtree.map(|(_, rights)| rights)),
        root_cap,
        process_handle,
        thread_cap,
        ctx,
    )
}
