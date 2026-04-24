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
        println!("vfsd: spawn_fatfs: worker thread not initialised");
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
    // log_ep arrives via the child's ProcessInfo, so it's not part of the
    // publish plan.

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

    // Phase 1: CREATE_PROCESS with [module, tokened bootstrap cap].
    let create_msg = IpcMessage::builder(procmgr_labels::CREATE_PROCESS)
        .cap(module_copy)
        .cap(tokened_creator)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(create_reply) = (unsafe { ipc::ipc_call(caps.procmgr_ep, &create_msg, ipc_buf) })
    else
    {
        println!("vfsd: fatfs CREATE_PROCESS ipc_call failed");
        return None;
    };
    if create_reply.label != 0
    {
        println!("vfsd: fatfs CREATE_PROCESS failed");
        return None;
    }

    let reply_caps = create_reply.caps();
    if reply_caps.len() < 2
    {
        println!("vfsd: fatfs CREATE_PROCESS reply missing caps");
        return None;
    }
    let process_handle = reply_caps[0];

    // START_PROCESS — fatfs begins executing and issues its bootstrap request.
    let start_msg = IpcMessage::new(procmgr_labels::START_PROCESS);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let start_ok = matches!(
        unsafe { ipc::ipc_call(process_handle, &start_msg, ipc_buf) },
        Ok(ref r) if r.label == 0
    );
    if !start_ok
    {
        println!("vfsd: fatfs START_PROCESS failed");
        return None;
    }

    // Wait for the worker to deliver the bootstrap round.
    if !worker::wait_result(channel)
    {
        println!("vfsd: fatfs bootstrap delivery failed");
        return None;
    }

    // Probe the driver with an empty FS_MOUNT: fatfs validates the BPB in its
    // handler and replies with fs_errors::SUCCESS or an error label.
    let mount_msg = IpcMessage::new(fs_labels::FS_MOUNT);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let mount_reply = unsafe { ipc::ipc_call(driver_send, &mount_msg, ipc_buf) }.ok()?;
    if mount_reply.label != 0
    {
        println!(
            "vfsd: fatfs FS_MOUNT probe failed (label={})",
            mount_reply.label
        );
        return None;
    }

    println!("vfsd: fatfs driver started");
    Some(driver_send)
}
