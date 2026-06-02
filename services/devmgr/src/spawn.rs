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

/// Source the child's ELF binary is loaded from. Selected per spawn site:
/// boot-bundle modules (the bootstrap-essential drivers virtio-blk,
/// serial, framebuffer) carry a procmgr Frame cap and use
/// [`CreateSource::Module`]; non-essential drivers loaded from the rootfs
/// (today: the per-arch RTC, walked by devmgr through its
/// `SET_DRIVERS_DIR` subtree cap) carry a vfsd file SEND cap plus a size
/// hint and use [`CreateSource::File`]. The variant decides the procmgr
/// request label and payload shape; the rest of [`spawn_simple_device`]
/// — service-endpoint derivation, `START_PROCESS`, bootstrap rounds —
/// is identical across both paths.
#[derive(Clone, Copy)]
pub enum CreateSource
{
    /// Frame cap to an in-memory ELF image (`procmgr_labels::CREATE_PROCESS`).
    /// Caller retains the slot on failure to match the existing
    /// `spawn_simple_device` contract; kernel transfers ownership on
    /// successful `CREATE_PROCESS`.
    Module(u32),
    /// vfsd file SEND cap (`procmgr_labels::CREATE_FROM_FILE`). `size` is
    /// the file size hint reported by the resolving `NS_LOOKUP`. On any
    /// pre-`ipc_call` failure inside [`spawn_simple_device`], the function
    /// deletes the file cap on the caller's behalf — the cap was just
    /// derived by the namespace walk and has no retry value.
    File
    {
        file_cap: u32, size: u64
    },
}

/// Monotonic counter for driver-child bootstrap badges.
static NEXT_BOOTSTRAP_BADGE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

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
    pub device_badge: u64,
}

/// Spawn a driver process with per-device capabilities.
///
/// Creates the process via procmgr, starts it, and serves its bootstrap over
/// IPC to deliver the BAR MMIO, IRQ, and endpoint caps. The `device_badge` is
/// used to derive a per-device badged send cap from `registry_ep` so the
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
        std::os::seraph::log!("driver spawn: no BAR cap");
        return;
    };
    let Some(irq_slot) = config.irq_cap
    else
    {
        std::os::seraph::log!("driver spawn: no IRQ cap");
        return;
    };
    let procmgr_ep = config.procmgr_ep;
    let bootstrap_ep = config.bootstrap_ep;
    let module_cap = config.module_cap;
    let service_ep = config.service_ep;
    let registry_ep = config.registry_ep;
    let device_badge = config.device_badge;

    // Allocate a bootstrap badge for the child.
    let child_badge = NEXT_BOOTSTRAP_BADGE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let Ok(badged_creator) =
        syscall::cap_derive_badge(bootstrap_ep, syscall::RIGHTS_SEND, child_badge)
    else
    {
        std::os::seraph::log!("driver spawn: badged creator derivation failed");
        return;
    };

    // CREATE_PROCESS via procmgr. Caps [module, creator]. The child has no
    // stdio wired by default — it logs through `seraph::log!` via the
    // discovery cap procmgr installs in `ProcessInfo`.
    let create_msg = IpcMessage::builder(procmgr_labels::CREATE_PROCESS)
        .cap(module_cap)
        .cap(badged_creator)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_ep, &create_msg, ipc_buf) })
    else
    {
        std::os::seraph::log!("driver CREATE_PROCESS ipc_call failed");
        return;
    };
    if reply.label != 0
    {
        std::os::seraph::log!("driver CREATE_PROCESS failed");
        return;
    }

    let reply_caps = reply.caps();
    if reply_caps.len() < 2
    {
        std::os::seraph::log!("driver CREATE_PROCESS reply missing caps");
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
        syscall::cap_derive_badge(registry_ep, syscall::RIGHTS_SEND, device_badge)
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
        std::os::seraph::log!("driver START_PROCESS failed");
        return;
    }

    // Serve bootstrap round 1: [bar, irq, service].
    // SAFETY: ipc_buf is the registered IPC buffer.
    if unsafe {
        ipc::bootstrap::serve_round(
            bootstrap_ep,
            child_badge,
            ipc_buf,
            false,
            &[bar_copy, irq_copy, service_copy],
            &[],
        )
    }
    .is_err()
    {
        std::os::seraph::log!("driver bootstrap round 1 failed");
        return;
    }

    // Round 2: [devmgr_query], done.
    // SAFETY: ipc_buf is the registered IPC buffer.
    if unsafe {
        ipc::bootstrap::serve_round(
            bootstrap_ep,
            child_badge,
            ipc_buf,
            true,
            &[devmgr_copy],
            &[],
        )
    }
    .is_err()
    {
        std::os::seraph::log!("driver bootstrap round 2 failed");
        return;
    }

    std::os::seraph::log!("driver started");
}

/// Spawn a non-PCI platform device driver with a minimal capability set: a
/// RECV-rights copy of `service_ep` plus the device's arch authority cap
/// (`hw_cap`). Unlike [`spawn_driver`] there is no BAR or IRQ.
///
/// `devmgr_query_ep` is an optional badged SEND on devmgr's
/// registry-query endpoint, delivered as a round-2 cap so the driver can
/// fetch runtime metadata via `QUERY_DEVICE_INFO`. Pass `0` to omit
/// (single terminal round `[service, hw_cap]`, behaviour identical to
/// the pre-extension shape used by drivers that need no runtime
/// platform metadata). When non-zero a two-round protocol is served:
///   Round 1 (non-terminal): `[service, hw_cap]`
///   Round 2 (terminal):     `[devmgr_query_ep]`
///
/// The `devmgr_query_ep` is a generic mechanism — any future simple
/// device needing runtime platform metadata uses it. The driver-class
/// payload shape lives in the driver's crate; devmgr stores opaque
/// bytes in its `DeviceCatalog`.
///
/// devmgr retains `service_ep` to mint client SEND caps on query; the
/// `hw_cap` is *moved* into the child (delivered directly, not copied), so
/// devmgr holds no device-specific authority after a successful spawn. The
/// caller transfers ownership of `hw_cap` to this function — it is moved to
/// the child on success and deleted on failure. Returns `false` on any
/// spawn-path failure.
// too_many_lines: simple-device spawn is one transaction — derive the
// per-child caps, install them into the suspended child, and serve one or
// two bootstrap rounds against the shared `ipc` buffer. Each fallible step
// owns slots that must be released cooperatively on partial failure;
// extracting helpers requires threading the same parameters through. The
// linear presentation matches the bootstrap protocol one-to-one.
#[allow(clippy::too_many_lines)]
pub fn spawn_simple_device(
    procmgr_ep: u32,
    bootstrap_ep: u32,
    source: CreateSource,
    service_ep: u32,
    hw_cap: u32,
    devmgr_query_ep: u32,
    ipc_buf: *mut u64,
) -> bool
{
    // Source-aware cleanup: on any failure before the procmgr ipc_call
    // completes, `CreateSource::File`'s file_cap is deleted (the
    // namespace walk just produced it; there is no retry value), while
    // `CreateSource::Module`'s frame cap stays in the caller's slot
    // (existing contract — module caps came from bootstrap and the
    // caller may have other uses for them).
    let source_cap_to_clean: u32 = match source
    {
        CreateSource::Module(_) => 0,
        CreateSource::File { file_cap, .. } => file_cap,
    };
    let source_cap_present: bool = match source
    {
        CreateSource::Module(m) => m != 0,
        CreateSource::File { file_cap, .. } => file_cap != 0,
    };
    let cleanup_on_fail = |hw: u32, query: u32, srccap: u32| {
        let _ = syscall::cap_delete(hw);
        if query != 0
        {
            let _ = syscall::cap_delete(query);
        }
        if srccap != 0
        {
            let _ = syscall::cap_delete(srccap);
        }
    };

    if !source_cap_present || service_ep == 0 || hw_cap == 0
    {
        std::os::seraph::log!("simple-device spawn: missing source/service/hw cap");
        cleanup_on_fail(hw_cap, devmgr_query_ep, source_cap_to_clean);
        return false;
    }

    let child_badge = NEXT_BOOTSTRAP_BADGE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let Ok(badged_creator) =
        syscall::cap_derive_badge(bootstrap_ep, syscall::RIGHTS_SEND, child_badge)
    else
    {
        std::os::seraph::log!("simple-device spawn: badged creator derivation failed");
        cleanup_on_fail(hw_cap, devmgr_query_ep, source_cap_to_clean);
        return false;
    };

    let create_msg = match source
    {
        CreateSource::Module(module_cap) => IpcMessage::builder(procmgr_labels::CREATE_PROCESS)
            .cap(module_cap)
            .cap(badged_creator)
            .build(),
        CreateSource::File { file_cap, size } =>
        {
            IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE)
                .word(0, size)
                .cap(file_cap)
                .cap(badged_creator)
                .build()
        }
    };
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_ep, &create_msg, ipc_buf) })
    else
    {
        std::os::seraph::log!("simple-device CREATE_* ipc_call failed");
        cleanup_on_fail(hw_cap, devmgr_query_ep, source_cap_to_clean);
        return false;
    };
    if reply.label != 0
    {
        std::os::seraph::log!("simple-device CREATE_* failed");
        // ipc_call completed: kernel either transferred the source cap
        // to procmgr (procmgr then deletes per its CREATE_FROM_FILE
        // contract) or the transfer failed and the cap is back in our
        // slot. Be conservative and skip our source cleanup; let
        // any residual leak be handled by the broader procmgr error.
        let _ = syscall::cap_delete(hw_cap);
        if devmgr_query_ep != 0
        {
            let _ = syscall::cap_delete(devmgr_query_ep);
        }
        return false;
    }
    let reply_caps = reply.caps();
    if reply_caps.is_empty()
    {
        std::os::seraph::log!("simple-device CREATE_PROCESS reply missing caps");
        let _ = syscall::cap_delete(hw_cap);
        if devmgr_query_ep != 0
        {
            let _ = syscall::cap_delete(devmgr_query_ep);
        }
        return false;
    }
    let process_handle = reply_caps[0];

    // RECV-rights copy of the service endpoint for the child; devmgr keeps
    // the original to mint client SEND caps on query.
    let Ok(service_copy) = syscall::cap_derive(service_ep, syscall::RIGHTS_ALL)
    else
    {
        let _ = syscall::cap_delete(hw_cap);
        if devmgr_query_ep != 0
        {
            let _ = syscall::cap_delete(devmgr_query_ep);
        }
        return false;
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
        std::os::seraph::log!("simple-device START_PROCESS failed");
        let _ = syscall::cap_delete(service_copy);
        let _ = syscall::cap_delete(hw_cap);
        if devmgr_query_ep != 0
        {
            let _ = syscall::cap_delete(devmgr_query_ep);
        }
        return false;
    }

    // Bootstrap rounds. With no query endpoint, one terminal round
    // [service, hw_cap]. With a query endpoint, two rounds: round 1
    // non-terminal [service, hw_cap], round 2 terminal [query_ep].
    let round1_done = devmgr_query_ep == 0;
    // SAFETY: ipc_buf is the registered IPC buffer.
    if unsafe {
        ipc::bootstrap::serve_round(
            bootstrap_ep,
            child_badge,
            ipc_buf,
            round1_done,
            &[service_copy, hw_cap],
            &[],
        )
    }
    .is_err()
    {
        std::os::seraph::log!("simple-device bootstrap round 1 failed");
        // serve_round may or may not have consumed the caps; best-effort
        // delete is safe (deleting a transferred slot is a no-op).
        let _ = syscall::cap_delete(service_copy);
        let _ = syscall::cap_delete(hw_cap);
        if devmgr_query_ep != 0
        {
            let _ = syscall::cap_delete(devmgr_query_ep);
        }
        return false;
    }

    if devmgr_query_ep != 0
    {
        // SAFETY: ipc_buf is the registered IPC buffer.
        if unsafe {
            ipc::bootstrap::serve_round(
                bootstrap_ep,
                child_badge,
                ipc_buf,
                true,
                &[devmgr_query_ep],
                &[],
            )
        }
        .is_err()
        {
            std::os::seraph::log!("simple-device bootstrap round 2 failed");
            let _ = syscall::cap_delete(devmgr_query_ep);
            return false;
        }
    }

    std::os::seraph::log!("simple-device driver started");
    true
}
