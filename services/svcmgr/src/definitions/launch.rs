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

use ipc::{IpcMessage, procmgr_labels};

use super::{Definition, NamespaceShape};
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
}

/// Build the NUL-separated, NUL-terminated wire blob procmgr's
/// stack-envelope writer expects from a list of tokens. Returns
/// `(blob, count)`. Empty input yields an empty blob with `count = 0`,
/// matching the "no argv / no env" wire shape.
fn build_blob(tokens: &[String]) -> (Vec<u8>, u32)
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
/// usertest's pwrmgr phases; consumers that don't tolerate a missing
/// cap fail on first use, which is the right surface for a real
/// misconfiguration.
pub fn launch(
    def: &Definition,
    ctx: &RestartCtx,
    registry: &mut registry::Registry<REGISTRY_CAPACITY>,
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

    // Resolve seeds AFTER namespace setup so a seed-lookup miss does
    // not leave a configured-but-orphan partial child; if the seed
    // section fails, we still tear down here before launching.
    let seed_caps = resolve_seeds(def, registry);

    if !start_process(created.process_handle, ctx.ipc_buf)
    {
        for &c in &seed_caps
        {
            if c != 0
            {
                let _ = syscall::cap_delete(c);
            }
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
            &seed_caps,
            &[],
        )
    };
    if bootstrap_result.is_err()
    {
        std::os::seraph::log!("launch {}: bootstrap serve failed", def.name);
        // Process is already started; can't unspawn. The child will
        // observe an empty bootstrap and degrade per its own logic.
        for &c in &seed_caps
        {
            if c != 0
            {
                let _ = syscall::cap_delete(c);
            }
        }
    }

    Some(Launched {
        thread_cap: created.thread_cap,
        process_handle: created.process_handle,
    })
}

/// Resolve each `seed = ...` name to a derived `RIGHTS_SEND` cap on
/// the published endpoint. Unresolved names become `0` in their slot
/// so positional ordering is preserved. Truncated to
/// `MSG_CAP_SLOTS_MAX` (the bootstrap round's cap limit).
fn resolve_seeds(def: &Definition, registry: &mut registry::Registry<REGISTRY_CAPACITY>)
-> Vec<u32>
{
    let cap_max = syscall_abi::MSG_CAP_SLOTS_MAX;
    let mut caps: Vec<u32> = Vec::with_capacity(def.seed.len().min(cap_max));
    for name in def.seed.iter().take(cap_max)
    {
        match registry_lookup_derived(registry, name.as_bytes())
        {
            Ok(cap) => caps.push(cap),
            Err(code) =>
            {
                std::os::seraph::log!(
                    "launch {}: seed {:?} unresolved (code={code})",
                    def.name,
                    name
                );
                caps.push(0);
            }
        }
    }
    if def.seed.len() > cap_max
    {
        std::os::seraph::log!(
            "launch {}: seed list truncated to {} entries (had {})",
            def.name,
            cap_max,
            def.seed.len()
        );
    }
    caps
}

/// Apply `def.namespace` + `def.cwd` to a freshly created child via
/// `CONFIGURE_NAMESPACE`. Local to the launch path because cwd
/// handling is not present in the restart-side
/// [`crate::restart::apply_namespace_policy`] (`ServiceEntry` does
/// not preserve cwd today). On any failure the partial child is
/// destroyed and `false` is returned.
#[allow(clippy::too_many_lines)]
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

    // cwd: walk against svcmgr's root with read+stat+readdir+lookup —
    // the minimum a child needs for relative file ops in std::fs.
    // (Tighter rights are a per-service concern handled at the
    // namespace cap; cwd shares the same path-walk machinery.)
    let cwd_cap = if let Some(cwd_path) = &def.cwd
    {
        let rights = u64::from(
            namespace_protocol::rights::LOOKUP
                | namespace_protocol::rights::READDIR
                | namespace_protocol::rights::STAT
                | namespace_protocol::rights::READ,
        );
        match std::os::seraph::namespace_lookup_dir(root_cap, cwd_path, rights)
        {
            Ok(c) => c,
            Err(e) =>
            {
                std::os::seraph::log!("launch {}: cwd walk {:?} failed: {e}", def.name, cwd_path);
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

    // SAFETY: `ctx.ipc_buf` is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(process_handle, &ns_msg, ctx.ipc_buf) };
    let _ = syscall::cap_delete(ns_cap);
    if cwd_cap != 0
    {
        let _ = syscall::cap_delete(cwd_cap);
    }

    match reply
    {
        Ok(r) if r.label == 0 => true,
        Ok(r) =>
        {
            std::os::seraph::log!(
                "launch {}: CONFIGURE_NAMESPACE returned {:#x}",
                def.name,
                r.label
            );
            destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
            false
        }
        Err(_) =>
        {
            std::os::seraph::log!("launch {}: CONFIGURE_NAMESPACE syscall failed", def.name);
            destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
            false
        }
    }
}
