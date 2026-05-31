// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// svcmgr/src/definitions/launch.rs

//! First-launch spawn path driven by a parsed `.svc` [`Definition`].
//!
//! Mirrors restart's spawn primitives ([`crate::restart`]) so that
//! services launched by svcmgr post-handover go through exactly the
//! same procmgr surface (`CREATE_FROM_FILE` → `CONFIGURE_NAMESPACE`
//! → bootstrap round → `START_PROCESS`) that restart uses. Returns
//! the freshly spawned child's thread cap so the caller can bind
//! death-notification on it.

use ipc::{devmgr_labels, procmgr_labels};

use super::{Definition, NamespaceShape, ProvidedName};
use crate::REGISTRY_CAPACITY;
use crate::registry_lookup_derived;
use crate::restart::{
    CreatedProcess, RestartCtx, StartupBlobs, destroy_partial_child, start_process,
    walk_and_create_from_file,
};

/// Outcome of a successful launch — the bits svcmgr needs to record
/// on the resulting `ServiceEntry` (or to bind death-notification on
/// for one-shot consumers).
pub struct Launched
{
    pub thread_cap: u32,
    pub process_handle: u32,
    /// Persistent service-endpoint source for a `provides = ...` service,
    /// stored on the `ServiceEntry` so restarts re-serve a fresh RECV on
    /// the same object. Zero for pure-consumer services.
    pub provided_endpoint: u32,
}

/// Build the NUL-separated, NUL-terminated wire blob procmgr's
/// stack-envelope writer expects from a list of tokens. Returns
/// `(blob, count)`. Empty input yields an empty blob with `count = 0`,
/// matching the "no argv / no env" wire shape.
pub(crate) fn build_blob(tokens: &[String]) -> (Vec<u8>, u32)
{
    if tokens.is_empty()
    {
        return (Vec::new(), 0);
    }
    let mut blob: Vec<u8> = Vec::with_capacity(tokens.iter().map(|t| t.len() + 1).sum());
    for tok in tokens
    {
        blob.extend_from_slice(tok.as_bytes());
        blob.push(0);
    }
    (blob, tokens.len() as u32)
}

/// Delete a set of cap slots, skipping the zero sentinel. Used on the
/// launch/restart cleanup paths where a partially-assembled cap set must
/// be released; deleting an already-transferred slot is a kernel no-op.
pub(crate) fn delete_caps(caps: &[u32])
{
    for &c in caps
    {
        if c != 0
        {
            let _ = syscall::cap_delete(c);
        }
    }
}

/// Assemble a child's bootstrap cap set: the provider service-endpoint
/// RECV (`provided_recv`, cap[0]) ahead of the positional `seeds`, capped
/// at `MSG_CAP_SLOTS_MAX`. A `provided_recv` of `0` (pure consumer) is
/// skipped. Overflow seeds beyond the cap are deleted so they don't leak.
/// Consumes `seeds`.
pub(crate) fn assemble_boot_caps(provided_recv: u32, seeds: Vec<u32>) -> Vec<u32>
{
    let mut caps: Vec<u32> = Vec::with_capacity(syscall_abi::MSG_CAP_SLOTS_MAX);
    if provided_recv != 0
    {
        caps.push(provided_recv);
    }
    for c in seeds
    {
        if caps.len() < syscall_abi::MSG_CAP_SLOTS_MAX
        {
            caps.push(c);
        }
        else if c != 0
        {
            let _ = syscall::cap_delete(c);
        }
    }
    caps
}

/// Mint the four bootstrap caps real-logd expects, from the reserved
/// log-sink sources svcmgr holds for the system's life:
///   * `[0]` master-log endpoint RECV (svcmgr's source stays valid, so a
///     fresh RECV reattaches each (re)launched logd to the same object that
///     every sender's `log_send_cap` targets);
///   * `[1]` a SEND on the same endpoint for the one-shot `HANDOVER_PULL`,
///     present only on the first launch — a restart has no init-logd to pull
///     from, so this is `0` and logd skips the history pull;
///   * `[2]` a `DEATH_EQ_AUTHORITY` SEND on procmgr (logd registers sender
///     death-notifications for slot reclaim) — `SEND|GRANT` because that
///     registration transfers a cap;
///   * `[3]` a `REGISTRY_QUERY_AUTHORITY` SEND on devmgr's registry (logd
///     resolves the serial driver via `QUERY_SERIAL_DEVICE`).
///
/// A source absent from the endowment yields `0` in its slot; logd then
/// degrades on first use of that cap. The four slots are positional, so
/// zeros are preserved (the round still carries `MSG_CAP_SLOTS_MAX` caps).
pub(crate) fn mint_logd_boot_caps(ctx: &RestartCtx, first_launch: bool) -> Vec<u32>
{
    let recv = if ctx.master_log_source != 0
    {
        syscall::cap_derive(ctx.master_log_source, syscall::RIGHTS_RECEIVE).unwrap_or(0)
    }
    else
    {
        0
    };
    let handover_send = if first_launch && ctx.master_log_source != 0
    {
        syscall::cap_derive(ctx.master_log_source, syscall::RIGHTS_SEND).unwrap_or(0)
    }
    else
    {
        0
    };
    let death_auth = if ctx.procmgr_death_auth_source != 0
    {
        syscall::cap_derive_token(
            ctx.procmgr_death_auth_source,
            syscall::RIGHTS_SEND_GRANT,
            procmgr_labels::DEATH_EQ_AUTHORITY,
        )
        .unwrap_or(0)
    }
    else
    {
        0
    };
    let registry_query = if ctx.devmgr_registry != 0
    {
        syscall::cap_derive_token(
            ctx.devmgr_registry,
            syscall::RIGHTS_SEND,
            devmgr_labels::REGISTRY_QUERY_AUTHORITY,
        )
        .unwrap_or(0)
    }
    else
    {
        0
    };
    std::vec![recv, handover_send, death_auth, registry_query]
}

/// Publish each name in a provider's `provides` list under the discovery
/// registry once the endpoint exists, so consumers launched after it
/// resolve them. Each name's SEND is stamped with its
/// [`ProvidedName::token`] (`cap_derive_token` when non-zero, plain
/// `cap_derive` for a bare entry); the token rides through to a
/// consumer's `QUERY_ENDPOINT` lookup unchanged. The endpoint persists on
/// the `ServiceEntry`, so the SENDs stay valid across restarts. No-op for
/// a pure consumer (`provided_endpoint == 0`) or an empty list.
fn publish_provided(
    provided_endpoint: u32,
    provides: &[ProvidedName],
    registry: &mut registry::Registry<REGISTRY_CAPACITY>,
    svc_name: &str,
)
{
    if provided_endpoint == 0
    {
        return;
    }
    for p in provides
    {
        let derived = if p.token == 0
        {
            syscall::cap_derive(provided_endpoint, syscall::RIGHTS_SEND)
        }
        else
        {
            syscall::cap_derive_token(provided_endpoint, syscall::RIGHTS_SEND, p.token)
        };
        let Ok(send) = derived
        else
        {
            std::os::seraph::log!(
                "launch {svc_name}: provider SEND derive for {:?} failed",
                p.name
            );
            continue;
        };
        if registry.publish(p.name.as_bytes(), send).is_err()
        {
            std::os::seraph::log!("launch {svc_name}: publish {:?} failed", p.name);
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
/// any failure destroys the partial child and returns `None`.
fn assemble_provided_boot_caps(
    def: &Definition,
    created: &CreatedProcess,
    ctx: &RestartCtx,
    registry: &mut registry::Registry<REGISTRY_CAPACITY>,
) -> Option<(u32, Vec<u32>)>
{
    let provided_endpoint = if def.provides.is_empty()
    {
        0
    }
    else
    {
        let Ok(ep) = syscall::cap_create_endpoint(ctx.endpoint_slab)
        else
        {
            std::os::seraph::log!("launch {}: provider endpoint create failed", def.name);
            destroy_partial_child(created.process_handle, created.thread_cap, ctx.ipc_buf);
            return None;
        };
        ep
    };

    // Resolve seeds AFTER namespace setup so a seed-lookup miss does not leave a
    // configured-but-orphan partial child; on failure we still tear down here.
    let seed_caps = resolve_seeds(&def.seed, &def.name, registry);

    // A provider's own service-endpoint RECV is cap[0], ahead of the positional
    // seeds. Derive it before assembly so a derive failure tears the partial
    // child down cleanly.
    let provided_recv = if provided_endpoint != 0
    {
        let Ok(recv) = syscall::cap_derive(provided_endpoint, syscall::RIGHTS_RECEIVE)
        else
        {
            std::os::seraph::log!("launch {}: provider RECV derive failed", def.name);
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
/// its bootstrap round delivered. Returns `None` if any step fails;
/// in that case the partial child has been destroyed (where possible)
/// and any resolved seed caps have been released.
///
/// Seed caps that fail to resolve are passed through as slot `0`, so
/// the child's bootstrap decoder sees a zero in that position. This
/// matches the existing "absent dep ⇒ skip" pattern already used by
/// svctest's pwrmgr phases; consumers that don't tolerate a missing
/// cap fail on first use, which is the right surface for a real
/// misconfiguration.
///
/// `bind_target` carries the `(deaths_eq, correlator)` for supervised
/// launches: when present, death-notification is bound BEFORE
/// `START_PROCESS` so an immediate post-start death cannot be lost
/// (the kernel walks the observer set at the moment of death; an
/// empty observer set silently drops the event). For one-shot
/// launches (`restart = never`, e.g. `svctest`) the caller passes
/// `None` and forgoes supervision binding.
pub fn launch(
    def: &Definition,
    ctx: &RestartCtx,
    registry: &mut registry::Registry<REGISTRY_CAPACITY>,
    bind_target: Option<(u32, u32)>,
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
        ctx.procmgr_ep,
        ctx.bootstrap_ep,
        ctx.ipc_buf,
    )?;

    if !configure_namespace(def, &created, ctx)
    {
        return None;
    }

    // Bind death-notification BEFORE start_process so any immediate
    // post-start death is captured. Thread is suspended at this
    // point — no userspace code has run yet.
    if let Some((deaths_eq, correlator)) = bind_target
        && syscall::thread_bind_notification(created.thread_cap, deaths_eq, correlator).is_err()
    {
        std::os::seraph::log!("launch {}: thread_bind_notification failed", def.name);
        destroy_partial_child(created.process_handle, created.thread_cap, ctx.ipc_buf);
        return None;
    }

    // Bootstrap cap set + (for providers) the persistent service endpoint.
    // The log-sink service (real-logd) gets a svcmgr-minted round from the
    // reserved log-sink sources; the parser guarantees it declares neither
    // `provides` nor `seed`, so it never enters the provider/seed path.
    let (provided_endpoint, boot_caps) = if def.log_sink
    {
        (0, mint_logd_boot_caps(ctx, true))
    }
    else
    {
        assemble_provided_boot_caps(def, &created, ctx, registry)?
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

    // SAFETY: `ctx.ipc_buf` is the registered IPC buffer.
    let bootstrap_result = unsafe {
        ipc::bootstrap::serve_round(
            ctx.bootstrap_ep,
            created.child_token,
            ctx.ipc_buf,
            true,
            &boot_caps,
            &[],
        )
    };
    if bootstrap_result.is_err()
    {
        std::os::seraph::log!("launch {}: bootstrap serve failed", def.name);
        // Process is already started; can't unspawn. The child will
        // observe an empty bootstrap and degrade per its own logic.
        delete_caps(&boot_caps);
    }

    // Publish the provided name now that the endpoint exists, so consumers
    // launched after this provider resolve it.
    publish_provided(provided_endpoint, &def.provides, registry, &def.name);

    Some(Launched {
        thread_cap: created.thread_cap,
        process_handle: created.process_handle,
        provided_endpoint,
    })
}

/// Resolve each `seed = ...` name to a derived `RIGHTS_SEND` cap on
/// the published endpoint. Unresolved names become `0` in their slot
/// so positional ordering is preserved. Truncated to
/// `MSG_CAP_SLOTS_MAX` (the bootstrap round's cap limit).
///
/// Shared by the launch path and the restart path (which passes the
/// service's stored [`crate::service::RestartRecipe`] seeds), so a
/// restarted child gets the same positional cap set it got on first
/// launch. `svc_name` is for logging only.
pub(crate) fn resolve_seeds(
    seed: &[String],
    svc_name: &str,
    registry: &mut registry::Registry<REGISTRY_CAPACITY>,
) -> Vec<u32>
{
    let cap_max = syscall_abi::MSG_CAP_SLOTS_MAX;
    let mut caps: Vec<u32> = Vec::with_capacity(seed.len().min(cap_max));
    for name in seed.iter().take(cap_max)
    {
        match registry_lookup_derived(registry, name.as_bytes())
        {
            Ok(cap) => caps.push(cap),
            Err(code) =>
            {
                std::os::seraph::log!("launch {svc_name}: seed {name:?} unresolved (code={code})");
                caps.push(0);
            }
        }
    }
    if seed.len() > cap_max
    {
        std::os::seraph::log!(
            "launch {svc_name}: seed list truncated to {cap_max} entries (had {})",
            seed.len()
        );
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

    if matches!(def.namespace, NamespaceShape::None)
    {
        if def.cwd.is_some()
        {
            std::os::seraph::log!("launch {}: cwd with namespace=none rejected", def.name);
            destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
            return false;
        }
        return true;
    }

    let root_cap = std::os::seraph::root_dir_cap();
    if root_cap == 0
    {
        std::os::seraph::log!("launch {}: no root_dir_cap configured", def.name);
        destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
        return false;
    }
    let Some(info) = std::os::seraph::try_startup_info()
    else
    {
        std::os::seraph::log!("launch {}: no startup info for cap_copy", def.name);
        destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
        return false;
    };

    let ns_cap = match &def.namespace
    {
        NamespaceShape::None => unreachable!("guarded above"),
        NamespaceShape::Universal =>
        {
            let Ok(c) = syscall::cap_copy(root_cap, info.self_cspace, syscall::RIGHTS_SEND)
            else
            {
                std::os::seraph::log!("launch {}: cap_copy of root failed", def.name);
                destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
                return false;
            };
            c
        }
        NamespaceShape::Subtree { path, rights } =>
        {
            match std::os::seraph::namespace_lookup_dir(root_cap, path, u64::from(*rights))
            {
                Ok(c) => c,
                Err(e) =>
                {
                    std::os::seraph::log!(
                        "launch {}: subtree walk {:?} failed: {e}",
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
        root_cap,
        process_handle,
        thread_cap,
        ctx,
    )
}
