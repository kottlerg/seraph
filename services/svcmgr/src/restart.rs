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
    pub ws_cap: u32,
}

/// Handle a service death detected via event queue notification.
///
/// Checks criticality and restart policy, then attempts to restart the service
/// if appropriate. Marks the service inactive if restart is not attempted or
/// fails.
pub fn handle_death(svc: &mut ServiceEntry, exit_reason: u64, ctx: &RestartCtx)
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

    if !restart_process(svc, ctx)
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
fn restart_process(svc: &mut ServiceEntry, ctx: &RestartCtx) -> bool
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

    rebind_death_notification(svc, ctx.ws_cap, new_thread_cap)
}

/// Spawn a fresh instance of `svc` via procmgr. Branches on the recorded
/// restart source: VFS path → `CREATE_FROM_VFS`; module cap →
/// `CREATE_PROCESS`. Returns `(process_handle, thread, child_token)`.
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
        let path_len = svc.vfs_path_len as usize;
        let path_bytes = &svc.vfs_path[..path_len];
        let label = procmgr_labels::CREATE_FROM_VFS | ((path_len as u64) << 16);
        let path_words = path_len.div_ceil(8);
        IpcMessage::builder(label)
            .bytes(0, path_bytes)
            .word_count(path_words)
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

    Some((process_handle, reply_caps[1], child_token))
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

/// Rebind death notification: create a new event queue on the new thread,
/// remove the old one from the wait set.
fn rebind_death_notification(svc: &mut ServiceEntry, ws_cap: u32, new_thread_cap: u32) -> bool
{
    let _ = syscall::wait_set_remove(ws_cap, svc.event_queue_cap);
    let _ = syscall::cap_delete(svc.event_queue_cap);

    let Ok(new_eq) = syscall::event_queue_create(4)
    else
    {
        std::os::seraph::log!("failed to create new event queue for restart");
        return false;
    };

    // Correlator 0: payload is the bare exit_reason (see rebind rationale
    // in `handle_register`).
    if syscall::thread_bind_notification(new_thread_cap, new_eq, 0).is_err()
    {
        std::os::seraph::log!("failed to rebind death notification");
        return false;
    }

    svc.event_queue_cap = new_eq;
    svc.thread_cap = new_thread_cap;
    true
}
