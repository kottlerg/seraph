// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// devmgr/src/spawn.rs

//! Driver process spawning with per-device capability delivery via bootstrap.
//!
//! Creates driver processes via procmgr, then serves the driver's bootstrap
//! over IPC to deliver its per-device capability set (BAR MMIO, IRQ, service
//! endpoint, devmgr query endpoint). log + procmgr caps arrive via
//! `ProcessInfo` and are not part of this protocol.

use ipc::{IpcMessage, procmgr_labels};

/// Monotonic counter for driver-child bootstrap tokens.
static NEXT_BOOTSTRAP_TOKEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Per-device BAR capability set delivered to a driver. `bases` and `sizes`
/// parallel `caps` and are retained for future multi-BAR drivers; only the
/// first BAR is consumed by the current block driver path.
pub struct BarSpec<'a>
{
    pub caps: &'a [u32],
    pub bases: &'a [u64],
    pub sizes: &'a [u64],
}

/// Endpoints and identifiers needed to spawn a driver process and hand it
/// the per-device capability set. Grouped into one struct because every
/// driver spawn needs the full set.
pub struct DriverSpawnConfig<'a>
{
    pub procmgr_ep: u32,
    pub bootstrap_ep: u32,
    pub module_cap: u32,
    pub bars: BarSpec<'a>,
    pub irq_cap: Option<u32>,
    pub service_ep: u32,
    pub registry_ep: u32,
    pub device_token: u64,
}

/// Spawn a driver process with per-device capabilities.
///
/// Creates the process via procmgr, starts it, and serves its bootstrap over
/// IPC to deliver the BAR MMIO, IRQ, and endpoint caps. The `device_token` is
/// used to derive a per-device tokened send cap from `registry_ep` so the
/// driver can query devmgr for its device configuration.
///
/// Layout matches `drivers/virtio/blk/src/main.rs::bootstrap_caps`:
///   Round 1 (3 caps): BAR MMIO, IRQ, driver service endpoint.
///   Round 2 (1 cap): devmgr query endpoint.
///
/// log + procmgr endpoints arrive via `ProcessInfo`.
// clippy::too_many_lines: driver spawn is a single transaction — derive the
// per-child caps, install them into the suspended child, and serve two
// bootstrap rounds against one shared `ipc` buffer. Each derive owns a slot
// that must be released cooperatively on partial failure; extracting helpers
// requires passing the same `DriverSpawnConfig` to each. The linear
// presentation matches the bootstrap protocol one-to-one.
#[allow(clippy::too_many_lines)]
pub fn spawn_driver(config: &DriverSpawnConfig, ipc_buf: *mut u64)
{
    let _ = config.bars.bases;
    let _ = config.bars.sizes;

    let Some(bar_cap) = config.bars.caps.first().copied()
    else
    {
        println!("devmgr: driver spawn: no BAR cap");
        return;
    };
    let Some(irq_slot) = config.irq_cap
    else
    {
        println!("devmgr: driver spawn: no IRQ cap");
        return;
    };
    let procmgr_ep = config.procmgr_ep;
    let bootstrap_ep = config.bootstrap_ep;
    let module_cap = config.module_cap;
    let service_ep = config.service_ep;
    let registry_ep = config.registry_ep;
    let device_token = config.device_token;

    // Allocate a bootstrap token for the child.
    let child_token = NEXT_BOOTSTRAP_TOKEN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let Ok(tokened_creator) =
        syscall::cap_derive_token(bootstrap_ep, syscall::RIGHTS_SEND, child_token)
    else
    {
        println!("devmgr: driver spawn: tokened creator derivation failed");
        return;
    };

    // Phase 1: CREATE_PROCESS via procmgr. Word 0 is the stdio_token; zero
    // means "no stdio attached" (drivers emit their log lines via the log
    // endpoint delivered in ProcessInfo, not stdout).
    let create_msg = IpcMessage::builder(procmgr_labels::CREATE_PROCESS)
        .word(0, 0)
        .cap(module_cap)
        .cap(tokened_creator)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_ep, &create_msg, ipc_buf) })
    else
    {
        println!("devmgr: driver CREATE_PROCESS ipc_call failed");
        return;
    };
    if reply.label != 0
    {
        println!("devmgr: driver CREATE_PROCESS failed");
        return;
    }

    let reply_caps = reply.caps();
    if reply_caps.len() < 2
    {
        println!("devmgr: driver CREATE_PROCESS reply missing caps");
        return;
    }
    let process_handle = reply_caps[0];

    // Derive all per-child caps for delivery via bootstrap.
    let Ok(bar_copy) = syscall::cap_derive(bar_cap, syscall::RIGHTS_ALL)
    else
    {
        return;
    };
    let Ok(irq_copy) = syscall::cap_derive(irq_slot, syscall::RIGHTS_ALL)
    else
    {
        return;
    };
    let service_copy = if service_ep != 0
    {
        syscall::cap_derive(service_ep, syscall::RIGHTS_ALL).unwrap_or(0)
    }
    else
    {
        0
    };
    let Ok(devmgr_copy) =
        syscall::cap_derive_token(registry_ep, syscall::RIGHTS_SEND, device_token)
    else
    {
        return;
    };

    // START_PROCESS.
    let start_msg = IpcMessage::new(procmgr_labels::START_PROCESS);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let start_ok = matches!(
        unsafe { ipc::ipc_call(process_handle, &start_msg, ipc_buf) },
        Ok(r) if r.label == 0
    );
    if !start_ok
    {
        println!("devmgr: driver START_PROCESS failed");
        return;
    }

    // Serve bootstrap round 1: [bar, irq, service].
    // SAFETY: ipc_buf is the registered IPC buffer.
    if unsafe {
        ipc::bootstrap::serve_round(
            bootstrap_ep,
            child_token,
            ipc_buf,
            false,
            &[bar_copy, irq_copy, service_copy],
            &[],
        )
    }
    .is_err()
    {
        println!("devmgr: driver bootstrap round 1 failed");
        return;
    }

    // Round 2: [devmgr_query], done.
    // SAFETY: ipc_buf is the registered IPC buffer.
    if unsafe {
        ipc::bootstrap::serve_round(
            bootstrap_ep,
            child_token,
            ipc_buf,
            true,
            &[devmgr_copy],
            &[],
        )
    }
    .is_err()
    {
        println!("devmgr: driver bootstrap round 2 failed");
        return;
    }

    println!("devmgr: driver started");
}
