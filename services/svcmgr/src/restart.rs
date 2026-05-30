// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// svcmgr/src/restart.rs

//! Service death handling and restart logic.
//!
//! Whether a crashed service is restarted is decided solely by its restart
//! policy + budget; `system_critical` decides only what happens once the
//! service is permanently down (continue, or graceful shutdown). On restart
//! svcmgr re-creates the process via procmgr, replays the recipe's
//! argv/env/cwd/seed surfaces, serves its bootstrap, and rebinds death
//! notification.
//!
//! Bootstrap delivery re-resolves the recipe's `seed` caps (or, for
//! init-registered services, re-derives the restart-bundle caps). log and
//! procmgr endpoints arrive via `ProcessInfo`, so they are not part of the
//! restart cap set.

use crate::REGISTRY_CAPACITY;
use crate::definitions::launch::{build_blob, resolve_seeds};
use crate::service::{MAX_RESTARTS, POLICY_ALWAYS, POLICY_ON_FAILURE, RestartRecipe, ServiceEntry};
use ipc::{IpcMessage, procmgr_labels};

/// Outcome of [`handle_death`], routed by the caller (`dispatch_deaths`
/// in `main.rs`) to either continue, log degradation, or initiate a
/// graceful system shutdown via pwrmgr.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeathOutcome
{
    /// Service was successfully restarted.
    Restarted,
    /// Service is marked inactive; system continues degraded.
    Degraded,
    /// Service was `system_critical` and svcmgr cannot recover it
    /// (either `restart = never` or the restart budget is exhausted).
    /// Caller must initiate `pwrmgr_labels::SHUTDOWN`.
    Unrecoverable,
}

/// Monotonic counter for child bootstrap tokens. Shared between the
/// restart path and the post-handover launch path: every child that
/// receives its bootstrap round on svcmgr's `bootstrap_ep` gets a
/// distinct token so svcmgr can correlate the round to the right
/// service entry.
static NEXT_BOOTSTRAP_TOKEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Result of a successful `CREATE_FROM_FILE` reply, shared by the
/// restart path and the post-handover launch path.
pub struct CreatedProcess
{
    pub process_handle: u32,
    pub thread_cap: u32,
    pub child_token: u64,
}

/// Allocate a fresh bootstrap token and mint a tokened SEND on
/// `bootstrap_ep` for a soon-to-spawn child.
pub fn mint_child_creator(bootstrap_ep: u32) -> Option<(u64, u32)>
{
    let token = NEXT_BOOTSTRAP_TOKEN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let tokened = syscall::cap_derive_token(bootstrap_ep, syscall::RIGHTS_SEND, token).ok()?;
    Some((token, tokened))
}

/// Argv and env blobs seeded into a child at `CREATE_FROM_FILE` time.
///
/// Each blob is NUL-separated and NUL-terminated (the wire shape
/// procmgr's stack-envelope writer expects); `count` is the number of
/// entries in the blob. An empty blob with `count = 0` skips that
/// surface entirely — the child inherits no argv / no env from svcmgr.
#[derive(Default, Clone, Copy)]
pub struct StartupBlobs<'a>
{
    pub argv: &'a [u8],
    pub argv_count: u32,
    pub env: &'a [u8],
    pub env_count: u32,
}

/// Walk svcmgr's root for `path`, then call procmgr `CREATE_FROM_FILE`.
/// Returns the freshly created (suspended) process. Caller is
/// responsible for `CONFIGURE_NAMESPACE`, bootstrap delivery, and
/// `START_PROCESS`.
///
/// `path` is interpreted relative to svcmgr's own `root_dir_cap`
/// (universal post-#21 init handover), so callers pass paths exactly
/// as they appear in `.svc` files — e.g. `"/services/logd"`.
///
/// `blobs` carries argv/env for the child. Both paths build them from
/// the recipe: launch from the parsed `Definition`, restart from the
/// stored [`RestartRecipe`]. A caller with no recipe (defensive) passes
/// [`StartupBlobs::default`] for empty surfaces.
pub fn walk_and_create_from_file(
    path: &str,
    blobs: StartupBlobs<'_>,
    procmgr_ep: u32,
    bootstrap_ep: u32,
    ipc_buf: *mut u64,
) -> Option<CreatedProcess>
{
    let (child_token, tokened_creator) = mint_child_creator(bootstrap_ep)?;

    let root_cap = std::os::seraph::root_dir_cap();
    if root_cap == 0
    {
        std::os::seraph::log!("create: no root_dir_cap configured");
        let _ = syscall::cap_delete(tokened_creator);
        return None;
    }
    let (file_cap, file_size) = match std::os::seraph::namespace_lookup_file(root_cap, path)
    {
        Ok(p) => p,
        Err(e) =>
        {
            std::os::seraph::log!("create: NS_LOOKUP {path:?} failed: {e}");
            let _ = syscall::cap_delete(tokened_creator);
            return None;
        }
    };

    let argv_bytes = blobs.argv.len();
    let argv_words = argv_bytes.div_ceil(8);
    let env_bytes = blobs.env.len();
    let env_words = env_bytes.div_ceil(8);

    let label = procmgr_labels::CREATE_FROM_FILE
        | ((argv_bytes as u64) << 32)
        | (u64::from(blobs.argv_count) << 48)
        | (u64::from(blobs.env_count) << 56);

    // word layout matches the procmgr `CREATE_FROM_FILE` wire layout:
    //   word 0:           file_size
    //   words 1..1+argv_w: argv blob (NUL-separated, NUL-terminated)
    //   word  1+argv_w:   env_bytes
    //   words ...:        env blob
    let argv_word_offset: usize = 1;
    let env_len_word_offset = argv_word_offset + argv_words;
    let env_blob_word_offset = env_len_word_offset + 1;
    let data_count = 1 + argv_words + 1 + env_words;

    let mut builder = IpcMessage::builder(label).word(0, file_size);
    if argv_bytes > 0
    {
        builder = builder.bytes(argv_word_offset, blobs.argv);
    }
    builder = builder
        .word(env_len_word_offset, env_bytes as u64)
        .word_count(data_count);
    if env_bytes > 0
    {
        builder = builder.bytes(env_blob_word_offset, blobs.env);
    }
    let create_msg = builder.cap(file_cap).cap(tokened_creator).build();

    // SAFETY: `ipc_buf` is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(procmgr_ep, &create_msg, ipc_buf) }.ok()?;
    if reply.label != 0
    {
        std::os::seraph::log!("create: CREATE_FROM_FILE returned {:#x}", reply.label);
        return None;
    }
    let reply_caps = reply.caps();
    if reply_caps.len() < 2
    {
        std::os::seraph::log!("create: reply missing caps");
        return None;
    }
    Some(CreatedProcess {
        process_handle: reply_caps[0],
        thread_cap: reply_caps[1],
        child_token,
    })
}

/// Send `START_PROCESS` via the tokened process handle. Shared by the
/// restart path and the post-handover launch path.
pub fn start_process(process_handle: u32, ipc_buf: *mut u64) -> bool
{
    let start_msg = IpcMessage::new(procmgr_labels::START_PROCESS);
    // SAFETY: `ipc_buf` is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(process_handle, &start_msg, ipc_buf) };
    if !matches!(reply, Ok(r) if r.label == 0)
    {
        std::os::seraph::log!("START_PROCESS failed");
        return false;
    }
    true
}

/// Endpoints and IPC state needed by restart paths. Holds nothing per-service,
/// so the same instance is reused across all death events.
pub struct RestartCtx
{
    pub procmgr_ep: u32,
    pub bootstrap_ep: u32,
    pub ipc_buf: *mut u64,
    /// Shared death-notification queue. Restarted services are
    /// rebound here with the same correlator they used pre-crash, so
    /// the routing in `dispatch_deaths` continues to land on the
    /// correct `ServiceEntry`.
    pub deaths_eq: u32,
}

/// Handle a service death detected via event queue notification.
///
/// Restart is decided solely by [`should_restart`] (restart policy +
/// budget + restart source). When the service ends up permanently down
/// — restart not attempted or failed — `system_critical` alone decides
/// whether the system can continue without it. Marks the service
/// inactive if not restarted. `correlator` is the death-payload tag
/// used to route this entry — the restarted thread is rebound under
/// the same value so subsequent crashes route back to the same
/// `ServiceEntry`.
///
/// Returns a [`DeathOutcome`] the caller routes:
///
/// * `Restarted` — service is back up; supervision loop continues.
/// * `Degraded` — service is permanently down but `system_critical` is
///   false; the system continues without it.
/// * `Unrecoverable` — `system_critical` service that restart cannot
///   recover. Caller must initiate the graceful-shutdown path
///   (`pwrmgr_labels::SHUTDOWN` via the `pwrmgr.shutdown` cap).
pub fn handle_death(
    svc: &mut ServiceEntry,
    exit_reason: u64,
    ctx: &RestartCtx,
    correlator: u32,
    recipe: Option<&RestartRecipe>,
    registry: &mut registry::Registry<REGISTRY_CAPACITY>,
) -> DeathOutcome
{
    std::os::seraph::log!("service died: {}", svc.name_str());
    std::os::seraph::log!("  exit_reason={exit_reason:#018x}");

    if !should_restart(svc, exit_reason)
    {
        svc.active = false;
        return permanent_death_outcome(svc);
    }

    std::os::seraph::log!(
        "restarting (attempt {:#018x})",
        u64::from(svc.restart_count + 1)
    );

    if !restart_process(svc, ctx, correlator, recipe, registry)
    {
        svc.active = false;
        return permanent_death_outcome(svc);
    }

    svc.restart_count += 1;
    std::os::seraph::log!("service restarted: {}", svc.name_str());
    DeathOutcome::Restarted
}

/// Outcome when a service is permanently down (restart not attempted,
/// budget exhausted, or restart failed). `system_critical` alone decides
/// whether the system can continue without it: `true` → `Unrecoverable`
/// (caller initiates graceful shutdown); `false` → `Degraded` (continue).
fn permanent_death_outcome(svc: &ServiceEntry) -> DeathOutcome
{
    if svc.system_critical
    {
        std::os::seraph::log!(
            "critical service unrecoverable: {}; initiating graceful shutdown",
            svc.name_str()
        );
        DeathOutcome::Unrecoverable
    }
    else
    {
        std::os::seraph::log!(
            "service down: {}; system continues degraded",
            svc.name_str()
        );
        DeathOutcome::Degraded
    }
}

/// Determine whether a service should be restarted based on its policy and
/// restart count.
fn should_restart(svc: &ServiceEntry, exit_reason: u64) -> bool
{
    let restart = match svc.restart_policy
    {
        POLICY_ALWAYS => true,
        POLICY_ON_FAILURE => exit_reason >= syscall_abi::EXIT_FAULT_BASE,
        _ => false,
    };

    if !restart
    {
        std::os::seraph::log!("restart policy says no restart");
        return false;
    }

    if svc.restart_count >= MAX_RESTARTS
    {
        std::os::seraph::log!("max restarts reached, marking degraded");
        return false;
    }

    if svc.module_cap == 0 && svc.vfs_path_len == 0
    {
        std::os::seraph::log!("no restart source (module or vfs_path), cannot restart");
        return false;
    }

    true
}

/// Create a new process via procmgr, serve bootstrap (log endpoint), start it,
/// and rebind death notification. Returns `true` on success.
fn restart_process(
    svc: &mut ServiceEntry,
    ctx: &RestartCtx,
    correlator: u32,
    recipe: Option<&RestartRecipe>,
    registry: &mut registry::Registry<REGISTRY_CAPACITY>,
) -> bool
{
    // Reclaim the previous instance's kernel objects (thread/aspace/cspace/
    // ProcessInfo frame) before spawning a fresh one. CSpace teardown
    // cascades: frames handed to the dead process via `REQUEST_FRAMES`
    // (which procmgr no longer holds caps on) get dec-ref'd and reclaimed
    // into memmgr's pool. The initial instance was created
    // by init, not svcmgr, so svcmgr has no handle for it — `process_handle
    // == 0` on first death, and we skip; subsequent deaths reclaim.
    if svc.process_handle != 0
    {
        let destroy_msg = IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
        // SAFETY: ctx.ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_call(svc.process_handle, &destroy_msg, ctx.ipc_buf) };
        let _ = syscall::cap_delete(svc.process_handle);
        svc.process_handle = 0;
    }

    let Some((process_handle, new_thread_cap, child_token)) = create_process(svc, recipe, ctx)
    else
    {
        return false;
    };
    svc.process_handle = process_handle;

    if !start_process(process_handle, ctx.ipc_buf)
    {
        destroy_partial_child(process_handle, new_thread_cap, ctx.ipc_buf);
        svc.process_handle = 0;
        return false;
    }

    // Assemble the restart bootstrap cap set. A service whose recipe
    // declares `seed = ...` gets those seeds re-resolved from the registry
    // by name, in declaration order — byte-for-byte the positional set
    // first launch delivered (see `definitions::launch::launch`). Otherwise
    // fall back to the registration-time bundle caps (init-bootstrapped
    // services that registered caps over `REGISTER_SERVICE`). The two
    // sources are disjoint in practice: recipe-launched services carry
    // seeds and no bundle; init-registered services carry a bundle and no
    // seeds. Each cap is freshly derived so the child owns its own copy.
    let restart_caps: Vec<u32> = match recipe
    {
        Some(r) if !r.seed.is_empty() => resolve_seeds(&r.seed, svc.name_str(), registry),
        _ =>
        {
            let mut caps: Vec<u32> = Vec::new();
            for i in 0..(svc.bundle_count as usize)
            {
                if caps.len() >= syscall_abi::MSG_CAP_SLOTS_MAX
                {
                    break;
                }
                let entry = &svc.bundle[i];
                if entry.cap == 0
                {
                    continue;
                }
                let Ok(c) = syscall::cap_derive(entry.cap, syscall::RIGHTS_SEND)
                else
                {
                    std::os::seraph::log!("cannot derive bundle cap for restart");
                    for &derived in &caps
                    {
                        if derived != 0
                        {
                            let _ = syscall::cap_delete(derived);
                        }
                    }
                    let _ = syscall::cap_delete(new_thread_cap);
                    return false;
                };
                caps.push(c);
            }
            caps
        }
    };

    // SAFETY: ctx.ipc_buf is the registered IPC buffer.
    if unsafe {
        ipc::bootstrap::serve_round(
            ctx.bootstrap_ep,
            child_token,
            ctx.ipc_buf,
            true,
            &restart_caps,
            &[],
        )
    }
    .is_err()
    {
        std::os::seraph::log!("bootstrap serve failed");
        // serve_round MOVES caps on success; on failure they may or
        // may not have been consumed. Best-effort delete is safe
        // (delete of an already-transferred slot is a no-op). Child
        // is started; cannot destroy from here — it will exit on the
        // receive-side failure and procmgr will reap.
        for &derived in &restart_caps
        {
            if derived != 0
            {
                let _ = syscall::cap_delete(derived);
            }
        }
        let _ = syscall::cap_delete(new_thread_cap);
        return false;
    }

    svc.bootstrap_token = child_token;

    rebind_death_notification(svc, ctx.deaths_eq, new_thread_cap, correlator)
}

/// Spawn a fresh instance of `svc` via procmgr. Branches on the recorded
/// restart source: VFS path → [`walk_and_create_from_file`]; module
/// cap → `CREATE_PROCESS`. After create, applies the per-service
/// namespace policy recorded at registration via
/// `CONFIGURE_NAMESPACE`. Returns `(process_handle, thread, child_token)`.
fn create_process(
    svc: &ServiceEntry,
    recipe: Option<&RestartRecipe>,
    ctx: &RestartCtx,
) -> Option<(u32, u32, u64)>
{
    let created = if svc.vfs_path_len > 0
    {
        let path_bytes = &svc.vfs_path[..svc.vfs_path_len as usize];
        let path_str = core::str::from_utf8(path_bytes).ok()?;
        // Replay argv/env from the stored recipe so the respawned child
        // gets the same startup surfaces first launch built. The blobs
        // must outlive the create call — `StartupBlobs` borrows them.
        let (argv_blob, argv_count) =
            recipe.map_or_else(|| (Vec::new(), 0), |r| build_blob(&r.argv));
        let (env_blob, env_count) = recipe.map_or_else(|| (Vec::new(), 0), |r| build_blob(&r.env));
        let blobs = StartupBlobs {
            argv: &argv_blob,
            argv_count,
            env: &env_blob,
            env_count,
        };
        walk_and_create_from_file(
            path_str,
            blobs,
            ctx.procmgr_ep,
            ctx.bootstrap_ep,
            ctx.ipc_buf,
        )?
    }
    else
    {
        // TODO(#78): this module-cap restart branch is unreachable today —
        // `ServiceEntry::module_cap` is never populated (REGISTER_SERVICE
        // delivers only a thread cap; the restart source is set from
        // `vfs_path` by the reconcile pass), so `create_process` always takes
        // the `vfs_path` arm above. Deferred to #78, which decides whether
        // svcmgr must restart boot-substrate services from an in-memory ELF
        // before the filesystem is reachable. If so, init endows svcmgr with
        // those module source caps (excluding them from its reap donation)
        // and this branch goes live; otherwise drop `module_cap` and this
        // branch and restart everything from `vfs_path`.
        let (child_token, tokened_creator) = mint_child_creator(ctx.bootstrap_ep)?;
        let Ok(module_copy) = syscall::cap_derive(svc.module_cap, syscall::RIGHTS_ALL)
        else
        {
            let _ = syscall::cap_delete(tokened_creator);
            return None;
        };
        let create_msg = IpcMessage::builder(procmgr_labels::CREATE_PROCESS)
            .cap(module_copy)
            .cap(tokened_creator)
            .build();
        // SAFETY: `ctx.ipc_buf` is the registered IPC buffer.
        let reply = unsafe { ipc::ipc_call(ctx.procmgr_ep, &create_msg, ctx.ipc_buf) }.ok()?;
        if reply.label != 0
        {
            std::os::seraph::log!("restart create failed");
            return None;
        }
        let reply_caps = reply.caps();
        if reply_caps.len() < 2
        {
            std::os::seraph::log!("restart reply missing caps");
            return None;
        }
        CreatedProcess {
            process_handle: reply_caps[0],
            thread_cap: reply_caps[1],
            child_token,
        }
    };

    let cwd = recipe.and_then(|r| r.cwd.as_deref());
    if !apply_namespace_policy(svc, cwd, created.process_handle, created.thread_cap, ctx)
    {
        return None;
    }

    Some((
        created.process_handle,
        created.thread_cap,
        created.child_token,
    ))
}

/// Apply the namespace policy recorded on `svc` to a freshly-created
/// (suspended) child. Shared by the restart path and the post-handover
/// launch path: both walk svcmgr's own `root_dir_cap` (universal after
/// init's Phase-3 handover) to derive the child's namespace cap.
///
/// * `NS_POLICY_NONE` → skip `CONFIGURE_NAMESPACE`; the child's
///   `system_root_cap` stays zero (`Unsupported` on absolute-path
///   fs ops in std).
/// * `NS_POLICY_UNIVERSAL` → `cap_copy` of svcmgr's own root with
///   `RIGHTS_SEND`.
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
    process_handle: u32,
    thread_cap: u32,
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
        std::os::seraph::log!("ns policy: no root_dir_cap for CONFIGURE_NAMESPACE");
        destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
        return false;
    }
    let Some(info) = std::os::seraph::try_startup_info()
    else
    {
        std::os::seraph::log!("ns policy: no startup info for cap_copy");
        destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
        return false;
    };

    let ns_cap = match svc.ns_policy_kind
    {
        ipc::svcmgr_labels::NS_POLICY_UNIVERSAL =>
        {
            let Ok(c) = syscall::cap_copy(root_cap, info.self_cspace, syscall::RIGHTS_SEND)
            else
            {
                std::os::seraph::log!("ns policy: cap_copy of root for child failed");
                destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
                return false;
            };
            c
        }
        ipc::svcmgr_labels::NS_POLICY_SUBTREE =>
        {
            let path = &svc.ns_subtree_path[..svc.ns_subtree_path_len as usize];
            let Ok(path_str) = core::str::from_utf8(path)
            else
            {
                std::os::seraph::log!("ns policy: subtree path not UTF-8");
                destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
                return false;
            };
            match std::os::seraph::namespace_lookup_dir(
                root_cap,
                path_str,
                u64::from(svc.ns_subtree_rights),
            )
            {
                Ok(c) => c,
                Err(e) =>
                {
                    std::os::seraph::log!("ns policy: subtree walk {path_str:?} failed: {e}");
                    destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
                    return false;
                }
            }
        }
        _ =>
        {
            std::os::seraph::log!("ns policy: unknown ns_policy_kind");
            destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
            return false;
        }
    };

    configure_namespace_caps(ns_cap, cwd, root_cap, process_handle, thread_cap, ctx)
}

/// Walk the optional `cwd` against `root_cap`, then deliver the namespace
/// cap (and the cwd cap, when present) to the suspended child via
/// `CONFIGURE_NAMESPACE`. Shared by the restart path
/// ([`apply_namespace_policy`]) and the launch path
/// ([`crate::definitions::launch`]) so both install cwd identically and
/// own the same cleanup. `ns_cap` is consumed (deleted) here regardless
/// of outcome — the kernel transfers it on the IPC. On any failure the
/// partial child is destroyed and `false` is returned.
pub(crate) fn configure_namespace_caps(
    ns_cap: u32,
    cwd: Option<&str>,
    root_cap: u32,
    process_handle: u32,
    thread_cap: u32,
    ctx: &RestartCtx,
) -> bool
{
    // cwd: walk against svcmgr's root with lookup+readdir+stat+read — the
    // minimum a child needs for relative file ops in std::fs. (Tighter
    // confinement is the namespace cap's job; cwd shares the path-walk.)
    let cwd_cap = if let Some(cwd_path) = cwd
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
                std::os::seraph::log!("ns policy: cwd walk {cwd_path:?} failed: {e}");
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
            std::os::seraph::log!("ns policy: CONFIGURE_NAMESPACE returned {:#x}", r.label);
            destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
            false
        }
        Err(_) =>
        {
            std::os::seraph::log!("ns policy: CONFIGURE_NAMESPACE syscall failed");
            destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
            false
        }
    }
}

/// Tear down a partially-created child: send `DESTROY_PROCESS` over its
/// tokened handle and release procmgr-side cap slots. Called when a step
/// between procmgr's CREATE and START fails and the partial child must
/// be reaped before the supervision loop retries.
pub(crate) fn destroy_partial_child(process_handle: u32, thread_cap: u32, ipc_buf: *mut u64)
{
    let destroy_msg = IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_buf) };
    let _ = syscall::cap_delete(process_handle);
    let _ = syscall::cap_delete(thread_cap);
}

/// Rebind death notification onto the shared queue using the same
/// correlator the dead instance used. No new event queue is created —
/// every supervised service routes through `ctx.deaths_eq`, and the
/// payload tag is what links a death back to its `ServiceEntry`.
fn rebind_death_notification(
    svc: &mut ServiceEntry,
    deaths_eq: u32,
    new_thread_cap: u32,
    correlator: u32,
) -> bool
{
    if syscall::thread_bind_notification(new_thread_cap, deaths_eq, correlator).is_err()
    {
        std::os::seraph::log!("failed to rebind death notification");
        return false;
    }

    svc.thread_cap = new_thread_cap;
    true
}
