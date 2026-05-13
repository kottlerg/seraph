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

use crate::halt_loop;
use crate::service::{
    CRITICALITY_FATAL, CRITICALITY_NORMAL, MAX_RESTARTS, POLICY_ALWAYS, POLICY_ON_FAILURE,
    ServiceEntry,
};
use ipc::{IpcMessage, procmgr_labels};

/// Monotonic counter for restart-child bootstrap tokens.
static NEXT_BOOTSTRAP_TOKEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

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
/// Checks criticality and restart policy, then attempts to restart the service
/// if appropriate. Marks the service inactive if restart is not attempted or
/// fails. `correlator` is the death-payload tag used to route this entry —
/// the restarted thread is rebound under the same value so subsequent
/// crashes route back to the same `ServiceEntry`.
pub fn handle_death(svc: &mut ServiceEntry, exit_reason: u64, ctx: &RestartCtx, correlator: u32)
{
    std::os::seraph::log!("service died: {}", svc.name_str());
    std::os::seraph::log!("  exit_reason={exit_reason:#018x}");

    if svc.criticality == CRITICALITY_FATAL
    {
        std::os::seraph::log!("FATAL service crashed, halting");
        halt_loop();
    }

    if svc.criticality != CRITICALITY_NORMAL
    {
        std::os::seraph::log!("unknown criticality, not restarting");
        svc.active = false;
        return;
    }

    if !should_restart(svc, exit_reason)
    {
        svc.active = false;
        return;
    }

    std::os::seraph::log!(
        "restarting (attempt {:#018x})",
        u64::from(svc.restart_count + 1)
    );

    if !restart_process(svc, ctx, correlator)
    {
        svc.active = false;
        return;
    }

    svc.restart_count += 1;
    std::os::seraph::log!("service restarted: {}", svc.name_str());
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

    // Start the new process.
    if !start_process(process_handle, ctx.ipc_buf)
    {
        return false;
    }

    // Assemble the restart cap set: bundle caps only. Each is freshly derived
    // from the stored authoritative cap so the restarted child owns its own
    // copies. Bundle order is positional — children that registered with
    // bundle caps must expect them in the same order on restart as at first
    // boot.
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
        return false;
    }

    svc.bootstrap_token = child_token;

    rebind_death_notification(svc, ctx.deaths_eq, new_thread_cap, correlator)
}

/// Spawn a fresh instance of `svc` via procmgr. Branches on the recorded
/// restart source: VFS path → walk svcmgr's `root_dir_cap` to the binary
/// then `CREATE_FROM_FILE`; module cap → `CREATE_PROCESS`. After create,
/// installs a `cap_copy` of svcmgr's root cap on the child via
/// `CONFIGURE_NAMESPACE`. Returns `(process_handle, thread, child_token)`.
fn create_process(svc: &ServiceEntry, ctx: &RestartCtx) -> Option<(u32, u32, u64)>
{
    // Allocate a fresh bootstrap token for this child.
    let child_token = NEXT_BOOTSTRAP_TOKEN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    // Derive a tokened send cap on our bootstrap endpoint. The child uses this
    // as its creator_endpoint; the token lets us identify them on recv.
    let tokened_creator =
        syscall::cap_derive_token(ctx.bootstrap_ep, syscall::RIGHTS_SEND, child_token).ok()?;

    let create_msg = if svc.vfs_path_len > 0
    {
        let root_cap = std::os::seraph::root_dir_cap();
        if root_cap == 0
        {
            std::os::seraph::log!("restart: no root_dir_cap configured");
            let _ = syscall::cap_delete(tokened_creator);
            return None;
        }
        let path_bytes = &svc.vfs_path[..svc.vfs_path_len as usize];
        let Ok(path_str) = core::str::from_utf8(path_bytes)
        else
        {
            std::os::seraph::log!("restart: vfs_path is not UTF-8");
            let _ = syscall::cap_delete(tokened_creator);
            return None;
        };
        let (file_cap, file_size) = match std::os::seraph::namespace_lookup_file(root_cap, path_str)
        {
            Ok(p) => p,
            Err(e) =>
            {
                std::os::seraph::log!("restart: NS_LOOKUP {path_str:?} failed: {e}");
                let _ = syscall::cap_delete(tokened_creator);
                return None;
            }
        };
        IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE)
            .word(0, file_size)
            .cap(file_cap)
            .cap(tokened_creator)
            .build()
    }
    else
    {
        let module_copy = syscall::cap_derive(svc.module_cap, syscall::RIGHTS_ALL).ok()?;
        IpcMessage::builder(procmgr_labels::CREATE_PROCESS)
            .cap(module_copy)
            .cap(tokened_creator)
            .build()
    };

    // SAFETY: ctx.ipc_buf is the registered IPC buffer.
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

    let process_handle = reply_caps[0];
    let thread_cap = reply_caps[1];

    // Install a `cap_copy` of svcmgr's own root cap on the child. The
    // restart-created child needs its own namespace cap installed
    // explicitly because procmgr no longer holds a broadcast root.
    // A failure here means the restarted service would boot without
    // namespace authority, presenting to the operator as "running but
    // broken" — destroy the partial child instead so the supervision
    // loop retries on the next death tick.
    let info = std::os::seraph::try_startup_info()?;
    let root_cap = std::os::seraph::root_dir_cap();
    if root_cap != 0
    {
        let Ok(ns_cap) = syscall::cap_copy(root_cap, info.self_cspace, syscall::RIGHTS_SEND)
        else
        {
            std::os::seraph::log!("restart: cap_copy of root for child failed");
            destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
            return None;
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
            Ok(r) if r.label == 0 =>
            {}
            Ok(r) =>
            {
                std::os::seraph::log!("restart: CONFIGURE_NAMESPACE returned {:#x}", r.label);
                destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
                return None;
            }
            Err(_) =>
            {
                std::os::seraph::log!("restart: CONFIGURE_NAMESPACE syscall failed");
                destroy_partial_child(process_handle, thread_cap, ctx.ipc_buf);
                return None;
            }
        }
    }

    Some((process_handle, thread_cap, child_token))
}

/// Tear down a partially-created child: send `DESTROY_PROCESS` over its
/// tokened handle and release procmgr-side cap slots. Called when a step
/// between procmgr's CREATE and START fails and the partial child must
/// be reaped before the supervision loop retries.
fn destroy_partial_child(process_handle: u32, thread_cap: u32, ipc_buf: *mut u64)
{
    let destroy_msg = IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_buf) };
    let _ = syscall::cap_delete(process_handle);
    let _ = syscall::cap_delete(thread_cap);
}

/// Send `START_PROCESS` via the tokened process handle.
fn start_process(process_handle: u32, ipc_buf: *mut u64) -> bool
{
    let start_msg = IpcMessage::new(procmgr_labels::START_PROCESS);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(process_handle, &start_msg, ipc_buf) };
    if !matches!(reply, Ok(r) if r.label == 0)
    {
        std::os::seraph::log!("restart START_PROCESS failed");
        return false;
    }
    true
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
