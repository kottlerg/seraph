// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// svcmgr/src/restart.rs

//! Service death handling and restart logic.
//!
//! Detects whether a crashed service should be restarted based on its restart
//! policy and criticality, then creates a new process instance via procmgr,
//! serves its bootstrap, and rebinds death notification.
//!
//! Bootstrap delivery re-injects the extra named caps registered in the
//! service's restart bundle. log and procmgr endpoints arrive via
//! `ProcessInfo`, so they are not part of the restart cap set.

use crate::service::{
    CRITICALITY_HIGH, CRITICALITY_LOW, CRITICALITY_NORMAL, MAX_RESTARTS, POLICY_ALWAYS,
    POLICY_ON_FAILURE, ServiceEntry,
};
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
    /// Service was `critical = high` and svcmgr cannot recover it
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
/// as they appear in `.svc` files — e.g. `"/bin/crasher"`.
///
/// `blobs` carries argv/env if the caller wants the child to see
/// them; restart-path callers pass [`StartupBlobs::default`] to leave
/// both surfaces empty (matching the pre-#21 restart shape).
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
/// Checks criticality and restart policy, then attempts to restart
/// the service if appropriate. Marks the service inactive if restart
/// is not attempted or fails. `correlator` is the death-payload tag
/// used to route this entry — the restarted thread is rebound under
/// the same value so subsequent crashes route back to the same
/// `ServiceEntry`.
///
/// Returns a [`DeathOutcome`] the caller routes:
///
/// * `Restarted` — service is back up; supervision loop continues.
/// * `Degraded` — service is inactive; system continues without it.
///   Used for `critical = low` deaths (informational) and for
///   `critical = normal` deaths where restart is unavailable / the
///   budget is exhausted.
/// * `Unrecoverable` — `critical = high` death where restart cannot
///   recover. Caller must initiate the graceful-shutdown path
///   (`pwrmgr_labels::SHUTDOWN` via the `pwrmgr.shutdown` cap).
pub fn handle_death(
    svc: &mut ServiceEntry,
    exit_reason: u64,
    ctx: &RestartCtx,
    correlator: u32,
) -> DeathOutcome
{
    std::os::seraph::log!("service died: {}", svc.name_str());
    std::os::seraph::log!("  exit_reason={exit_reason:#018x}");

    if svc.criticality == CRITICALITY_LOW
    {
        std::os::seraph::log!("low-criticality death; informational");
        svc.active = false;
        return DeathOutcome::Degraded;
    }

    if !should_restart(svc, exit_reason)
    {
        svc.active = false;
        return unrecoverable_or_degraded(svc);
    }

    std::os::seraph::log!(
        "restarting (attempt {:#018x})",
        u64::from(svc.restart_count + 1)
    );

    if !restart_process(svc, ctx, correlator)
    {
        svc.active = false;
        return unrecoverable_or_degraded(svc);
    }

    svc.restart_count += 1;
    std::os::seraph::log!("service restarted: {}", svc.name_str());
    DeathOutcome::Restarted
}

/// Choose between `Unrecoverable` (critical = high) and `Degraded`
/// (any other criticality) when restart is not attempted / failed.
fn unrecoverable_or_degraded(svc: &ServiceEntry) -> DeathOutcome
{
    if svc.criticality == CRITICALITY_HIGH
    {
        std::os::seraph::log!(
            "critical service unrecoverable: {}; initiating graceful shutdown",
            svc.name_str()
        );
        DeathOutcome::Unrecoverable
    }
    else
    {
        if svc.criticality != CRITICALITY_NORMAL
        {
            std::os::seraph::log!("unknown criticality {}", svc.criticality);
        }
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
fn restart_process(svc: &mut ServiceEntry, ctx: &RestartCtx, correlator: u32) -> bool
{
    // Reclaim the previous instance's kernel objects (thread/aspace/cspace/
    // ProcessInfo frame) before spawning a fresh one. CSpace teardown
    // cascades: frames handed to the dead process via `REQUEST_FRAMES`
    // (which procmgr no longer holds caps on) get dec-ref'd and recycled
    // back to the kernel buddy allocator. The initial instance was created
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

    let Some((process_handle, new_thread_cap, child_token)) = create_process(svc, ctx)
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

    // Assemble the restart cap set: bundle caps only. Each is freshly derived
    // from the stored authoritative cap so the restarted child owns its own
    // copies. Bundle order is positional — children that registered with
    // bundle caps must expect them in the same order on restart as at first
    // boot. Mirrors the launch-side cleanup in `definitions::launch::launch`:
    // on derive failure, release every cap derived so far before returning.
    let mut restart_caps: [u32; syscall_abi::MSG_CAP_SLOTS_MAX] =
        [0; syscall_abi::MSG_CAP_SLOTS_MAX];
    let mut cap_count = 0usize;

    for i in 0..(svc.bundle_count as usize)
    {
        if cap_count >= syscall_abi::MSG_CAP_SLOTS_MAX
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
            for &derived in &restart_caps[..cap_count]
            {
                let _ = syscall::cap_delete(derived);
            }
            let _ = syscall::cap_delete(new_thread_cap);
            return false;
        };
        restart_caps[cap_count] = c;
        cap_count += 1;
    }

    // SAFETY: ctx.ipc_buf is the registered IPC buffer.
    if unsafe {
        ipc::bootstrap::serve_round(
            ctx.bootstrap_ep,
            child_token,
            ctx.ipc_buf,
            true,
            &restart_caps[..cap_count],
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
        for &derived in &restart_caps[..cap_count]
        {
            let _ = syscall::cap_delete(derived);
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
fn create_process(svc: &ServiceEntry, ctx: &RestartCtx) -> Option<(u32, u32, u64)>
{
    let created = if svc.vfs_path_len > 0
    {
        let path_bytes = &svc.vfs_path[..svc.vfs_path_len as usize];
        let path_str = core::str::from_utf8(path_bytes).ok()?;
        walk_and_create_from_file(
            path_str,
            StartupBlobs::default(),
            ctx.procmgr_ep,
            ctx.bootstrap_ep,
            ctx.ipc_buf,
        )?
    }
    else
    {
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

    if !apply_namespace_policy(svc, created.process_handle, created.thread_cap, ctx)
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
/// On any failure the partial child is destroyed and `false` is
/// returned (caller treats handle as no longer usable).
pub fn apply_namespace_policy(
    svc: &ServiceEntry,
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

    let ns_msg = IpcMessage::builder(procmgr_labels::CONFIGURE_NAMESPACE)
        .cap(ns_cap)
        .build();
    // SAFETY: ctx.ipc_buf is the registered IPC buffer.
    let ns_reply = unsafe { ipc::ipc_call(process_handle, &ns_msg, ctx.ipc_buf) };
    // The kernel transferred the cap on the IPC regardless of the
    // reply label; release svcmgr's source slot unconditionally.
    let _ = syscall::cap_delete(ns_cap);
    match ns_reply
    {
        Ok(r) if r.label == 0 => true,
        Ok(r) =>
        {
            std::os::seraph::log!("restart: CONFIGURE_NAMESPACE returned {:#x}", r.label);
            destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
            false
        }
        Err(_) =>
        {
            std::os::seraph::log!("restart: CONFIGURE_NAMESPACE syscall failed");
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
