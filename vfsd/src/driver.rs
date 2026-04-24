// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// vfsd/src/driver.rs

//! Filesystem driver process spawning.
//!
//! Creates fatfs driver processes via procmgr's two-phase protocol. The child
//! is spawned with a tokened SEND cap on vfsd's worker-owned bootstrap
//! endpoint as its creator endpoint. Main publishes a plan keyed by that
//! token through the shared [`worker::Channel`], then blocks on the channel's
//! condvar while the worker thread delivers the bootstrap round. After the
//! worker signals completion, main sends a zero-payload `FS_MOUNT` to the
//! driver as a BPB-validation probe.
//!
//! This routes fatfs through the generic bootstrap protocol without
//! clobbering the main thread's reply target (= init) while servicing MOUNT.
//!
//! The `partition_ep` passed in is a tokened SEND cap on virtio-blk's service
//! endpoint, already registered with virtio-blk against a specific LBA range.
//! fatfs is never handed the whole-disk cap and cannot escape the partition
//! regardless of what sector number it computes.

use std::sync::atomic::{AtomicU64, Ordering};

use ipc::{IpcMessage, fs_labels, procmgr_labels};

use crate::{VfsdCaps, worker};

/// Monotonic counter for fatfs-child bootstrap tokens.
static NEXT_BOOTSTRAP_TOKEN: AtomicU64 = AtomicU64::new(1);

/// Spawn the fatfs driver via procmgr, deliver its cap set over the bootstrap
/// protocol, and probe it with `FS_MOUNT` to confirm BPB validation.
///
/// `partition_ep` is a tokened SEND cap on virtio-blk's service endpoint,
/// already bound in virtio-blk's partition table to the partition's LBA range.
///
/// Returns the driver's IPC endpoint (send cap) on success.
pub fn spawn_fatfs_driver(
    caps: &VfsdCaps,
    channel: &worker::Channel,
    partition_ep: u32,
    ipc_buf: *mut u64,
) -> Option<u32>
{
    if caps.bootstrap_ep == 0
    {
        println!("spawn_fatfs: worker thread not initialised");
        return None;
    }

    let module_copy = syscall::cap_derive(caps.fatfs_module_cap, syscall::RIGHTS_ALL).ok()?;

    // Create fatfs's service endpoint. fatfs receives service calls on this;
    // vfsd holds a SEND_GRANT copy for forwarding FS_OPEN.
    let driver_ep = syscall::cap_create_endpoint().ok()?;
    let driver_ep_for_child = syscall::cap_derive(driver_ep, syscall::RIGHTS_ALL).ok()?;
    let driver_send = syscall::cap_derive(driver_ep, syscall::RIGHTS_SEND_GRANT).ok()?;

    // partition_ep is already a tokened SEND cap; hand it to the child as-is.
    // A fresh derive would discard the token, so this is moved into the plan.
    // log_ep arrives via stdout_cap in ProcessInfo (minted below via
    // MINT_LOG_CAP), so it's not part of the publish plan either.

    // Allocate a bootstrap token and publish the plan for the worker.
    let token = NEXT_BOOTSTRAP_TOKEN.fetch_add(1, Ordering::Relaxed);
    let tokened_creator =
        syscall::cap_derive_token(caps.bootstrap_ep, syscall::RIGHTS_SEND, token).ok()?;
    worker::publish_plan(
        channel,
        worker::Plan {
            token,
            blk: partition_ep,
            service: driver_ep_for_child,
        },
    );

    // Phase 1: CREATE_PROCESS. Caps [module, creator]. Stdio wiring
    // happens via CONFIGURE_STDIO below.
    let create_msg = IpcMessage::builder(procmgr_labels::CREATE_PROCESS)
        .cap(module_copy)
        .cap(tokened_creator)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(create_reply) = (unsafe { ipc::ipc_call(caps.procmgr_ep, &create_msg, ipc_buf) })
    else
    {
        println!("fatfs CREATE_PROCESS ipc_call failed");
        return None;
    };
    if create_reply.label != 0
    {
        println!("fatfs CREATE_PROCESS failed");
        return None;
    }

    let reply_caps = create_reply.caps();
    if reply_caps.len() < 2
    {
        println!("fatfs CREATE_PROCESS reply missing caps");
        return None;
    }
    let process_handle = reply_caps[0];

    // CONFIGURE_STDIO: mint a tokened log SEND and cap_copy it into a
    // second slot in vfsd's own CSpace so the child's stdout and stderr
    // share the same registered display name in the mediator.
    let log_out = mint_log_cap(caps.procmgr_ep, ipc_buf);
    let log_err = if log_out != 0
    {
        syscall::cap_copy(log_out, caps.self_cspace, syscall::RIGHTS_SEND).unwrap_or(0)
    }
    else
    {
        0
    };
    configure_stdio(process_handle, ipc_buf, log_out, log_err, 0);

    // START_PROCESS — fatfs begins executing and issues its bootstrap request.
    let start_msg = IpcMessage::new(procmgr_labels::START_PROCESS);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let start_ok = matches!(
        unsafe { ipc::ipc_call(process_handle, &start_msg, ipc_buf) },
        Ok(ref r) if r.label == 0
    );
    if !start_ok
    {
        println!("fatfs START_PROCESS failed");
        return None;
    }

    // Wait for the worker to deliver the bootstrap round.
    if !worker::wait_result(channel)
    {
        println!("fatfs bootstrap delivery failed");
        return None;
    }

    // Probe the driver with an empty FS_MOUNT: fatfs validates the BPB in its
    // handler and replies with fs_errors::SUCCESS or an error label.
    let mount_msg = IpcMessage::new(fs_labels::FS_MOUNT);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let mount_reply = unsafe { ipc::ipc_call(driver_send, &mount_msg, ipc_buf) }.ok()?;
    if mount_reply.label != 0
    {
        println!("fatfs FS_MOUNT probe failed (label={})", mount_reply.label);
        return None;
    }

    println!("fatfs driver started");
    Some(driver_send)
}

/// Call `MINT_LOG_CAP` on procmgr, returning the minted tokened SEND cap
/// slot. Zero on failure.
fn mint_log_cap(procmgr_ep: u32, ipc_buf: *mut u64) -> u32
{
    let req = IpcMessage::new(ipc::procmgr_labels::MINT_LOG_CAP);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_ep, &req, ipc_buf) })
    else
    {
        return 0;
    };
    if reply.label != 0
    {
        return 0;
    }
    reply.caps().first().copied().unwrap_or(0)
}

/// Issue `CONFIGURE_STDIO` on a suspended child's `process_handle`. All
/// three caps optional — trailing zeros omitted.
fn configure_stdio(process_handle: u32, ipc_buf: *mut u64, stdout: u32, stderr: u32, stdin: u32)
{
    let mut builder = IpcMessage::builder(ipc::procmgr_labels::CONFIGURE_STDIO);
    if stdout != 0
    {
        builder = builder.cap(stdout);
        if stderr != 0
        {
            builder = builder.cap(stderr);
            if stdin != 0
            {
                builder = builder.cap(stdin);
            }
        }
    }
    let msg = builder.build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_call(process_handle, &msg, ipc_buf) };
}
