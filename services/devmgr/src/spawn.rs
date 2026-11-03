// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/spawn.rs

//! Driver process spawning with per-device capability delivery via bootstrap.
//!
//! Creates driver processes via procmgr, then serves the driver's bootstrap
//! over IPC to deliver its per-device capability set (BAR MMIO, IRQ, service
//! endpoint, devmgr query endpoint). log + procmgr caps arrive via
//! `ProcessInfo` and are not part of this protocol.

use ipc::{IpcMessage, procmgr_labels};
use virtio_core::MAX_VIRTIO_BARS;
use virtio_core::bootstrap::{ROUND2_SLOTS, SLOT_DEVMGR_QUERY, SLOT_IRQ, SLOT_SERVICE};

/// Source the child's ELF binary is loaded from. Selected per spawn site:
/// boot-bundle modules (the bootstrap-essential drivers virtio-blk,
/// serial, framebuffer) carry a procmgr Memory cap and use
/// [`CreateSource::Module`]; non-essential drivers loaded from the rootfs
/// (today: the per-arch RTC and virtio-input, walked by devmgr through its
/// `SET_DRIVERS_DIR` subtree cap) carry a vfsd file SEND cap plus a size
/// hint and use [`CreateSource::File`]. The variant decides the procmgr
/// request label and payload shape; the rest of [`spawn_simple_device`]
/// and [`spawn_driver`] — service-endpoint derivation, `START_PROCESS`,
/// bootstrap rounds — is identical across both sources.
#[derive(Clone, Copy)]
pub enum CreateSource
{
    /// Memory cap to an in-memory ELF image (`procmgr_labels::CREATE_PROCESS`).
    /// A `CREATE_PROCESS` `ipc_call` transfers the cap to procmgr (which deletes
    /// it on both success and failure). On any failure BEFORE that transfer,
    /// [`spawn_simple_device`] deletes the cap on the caller's behalf — a
    /// retained boot-module cap is a live derivation child of init's donated
    /// pool-run source and pins that run unsplittable.
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

/// RAII guard for a boot-module Memory cap not yet consumed by a successful
/// `CREATE_PROCESS`. While armed, `Drop` `cap_delete`s the slot.
///
/// A retained module cap is a live `cap_derive` child of init's donated
/// pool-run source, so leaving it held pins that run unsplittable (a later
/// demand fault landing on it is then wrongly killed). Guarding it releases the
/// cap on every not-consumed exit — a skipped spawn (e.g. headless framebuffer,
/// absent virtio device) or any failure before `CREATE_PROCESS` moves the cap
/// to procmgr. Call [`disarm`](Self::disarm) once ownership has moved on (the
/// `CREATE_PROCESS` `ipc_call` returned, transferring the cap, or an inner spawn
/// step has taken over its lifecycle) so the cap is not double-freed — the slot
/// is freed and the kernel's LIFO freelist promptly reuses it for a live cap.
pub struct ModuleCapGuard(u32);

impl ModuleCapGuard
{
    /// Arm a guard over `slot` (0 = nothing to guard).
    pub fn new(slot: u32) -> Self
    {
        Self(slot)
    }

    /// Disarm: the cap's ownership has moved on; do not delete on drop.
    pub fn disarm(&mut self)
    {
        self.0 = 0;
    }
}

impl Drop for ModuleCapGuard
{
    fn drop(&mut self)
    {
        if self.0 != 0
        {
            let _ = syscall::cap_delete(self.0);
        }
    }
}

/// RAII guard for a child created via `CREATE_PROCESS` whose bootstrap has not
/// yet reached its final `done` round. `Drop` releases the caller-side
/// `thread_cap` slot delivered in the `CREATE_PROCESS` reply, and the
/// `process_handle` slot unless [`keep_handle`](Self::keep_handle) took it.
/// While still armed, `Drop` additionally sends `DESTROY_PROCESS` over the
/// badged `process_handle` first ([`destroy_child`]), so procmgr reaps the
/// orphan (thread, cspace, aspace torn down; pages returned to memmgr) instead
/// of leaving it hung in `request_round`.
struct ChildGuard
{
    process_handle: u32,
    thread_cap: u32,
    ipc_buf: *mut u64,
    destroy: bool,
}

impl ChildGuard
{
    /// Arm a guard over a freshly-created child's reply caps.
    fn new(process_handle: u32, thread_cap: u32, ipc_buf: *mut u64) -> Self
    {
        Self {
            process_handle,
            thread_cap,
            ipc_buf,
            destroy: true,
        }
    }

    /// Bootstrap completed: keep the child alive and hand its process handle
    /// to the caller, which keeps it until the driver's settle batch settles
    /// (to destroy a driver that never reports ready). `Drop` still frees the
    /// thread cap.
    fn keep_handle(mut self) -> u32
    {
        self.destroy = false;
        core::mem::take(&mut self.process_handle)
    }
}

impl Drop for ChildGuard
{
    fn drop(&mut self)
    {
        if self.destroy
        {
            destroy_child(self.process_handle, self.ipc_buf);
        }
        else if self.process_handle != 0
        {
            let _ = syscall::cap_delete(self.process_handle);
        }
        if self.thread_cap != 0
        {
            let _ = syscall::cap_delete(self.thread_cap);
        }
    }
}

/// Destroy a child through its badged `process_handle` (`DESTROY_PROCESS`:
/// procmgr tears down its thread, `CSpace`, and address space, which returns
/// its pages and drops every capability it holds) and release the handle. A
/// child that has already died is a no-op for procmgr.
pub fn destroy_child(process_handle: u32, ipc_buf: *mut u64)
{
    let destroy_msg = IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_buf) };
    let _ = syscall::cap_delete(process_handle);
}

/// Draw a fresh non-zero driver-child bootstrap badge: a random `u64` from the
/// kernel entropy pool, redrawn off the reserved `0` value (an unbadged SEND
/// carries badge 0). Random rather than monotonic so the driver-spawn count it
/// would otherwise leak stays unguessable; both spawn paths match the bootstrap
/// round by badge value, not index. Returns `None` if the entropy draw fails.
/// The loop is unbounded but redraws only on a zero draw, at 2^-64 per draw.
fn mint_bootstrap_badge() -> Option<u64>
{
    loop
    {
        let b = syscall::random_u64().ok()?;
        if b != 0
        {
            return Some(b);
        }
    }
}

/// One BAR `Mmio` cap delivered to a driver, with the PCI BAR index (0-5)
/// it covers.
#[derive(Clone, Copy, Default)]
pub struct BarSpec
{
    pub bar: u8,
    pub cap: u32,
}

/// Endpoints and identifiers needed to spawn a driver process and hand it
/// the per-device capability set. Grouped into one struct because every
/// driver spawn needs the full set.
pub struct DriverSpawnConfig<'a>
{
    pub procmgr_ep: u32,
    pub bootstrap_ep: u32,
    /// ELF source for the child: a boot-module Memory cap
    /// ([`CreateSource::Module`], the bootstrap-essential PCI drivers) or a
    /// rootfs file cap ([`CreateSource::File`], for on-disk PCI drivers loaded
    /// after vfsd-mount, e.g. virtio-input). Both spawn `CREATE_PINNED` — a PCI
    /// device with a BAR/IRQ is DMA-capable and must be eager-mapped.
    pub source: CreateSource,
    /// The device's BAR caps, one per distinct BAR its `VirtIO` register
    /// regions name, in ascending BAR index
    /// ([`virtio_core::RegisterLayout::bars`]); 1 to [`MAX_VIRTIO_BARS`].
    pub bars: &'a [BarSpec],
    pub irq_cap: Option<u32>,
    pub service_ep: u32,
    /// Endpoint the driver's devmgr query cap is a `device_badge`-badged
    /// SEND on: the private driver endpoint of the driver's settle batch
    /// ([`crate::settle::SettleBatch::driver_ep`]).
    pub query_ep: u32,
    /// Event queue the driver's death observer posts to, with `device_badge`
    /// as the correlator: devmgr's driver death queue
    /// ([`crate::settle::DriverWatch::death_eq`]).
    pub death_eq: u32,
    pub device_badge: u64,
    /// Priority level the driver is created at; its band ceiling equals
    /// its level (a driver never spawns further processes). Rides the
    /// create label's scheduling fields; must not exceed devmgr's own band
    /// ceiling (`sched_policy::DEVMGR_BAND_MAX`) or procmgr rejects the
    /// spawn.
    pub priority: u8,
}

/// Spawn a driver process with per-device capabilities.
///
/// Creates the process via procmgr, starts it, and serves its bootstrap over
/// IPC to deliver the BAR MMIO, IRQ, and endpoint caps. The `device_badge` is
/// used to derive a per-device badged send cap from `query_ep` so the
/// driver can query devmgr for its device configuration and report its
/// device ready. Once the final round is served it binds a death observer
/// on the driver's thread to `death_eq`, correlator `device_badge`, so devmgr
/// sees the driver's death, before it reports ready or after it is served.
///
/// The rounds are the ones [`virtio_core::bootstrap`] specifies and the
/// virtio-blk and virtio-input drivers decode:
///   Round 1: one `Mmio` cap per entry of `bars`, in its order, with that
///     entry's BAR index as the matching data word.
///   Round 2 (terminal): the positional slots service endpoint, IRQ, and
///     devmgr query endpoint, packed with [`ipc::bootstrap::pack_slots`];
///     the IRQ slot is absent when `irq_cap` is `None`.
///
/// log + procmgr endpoints arrive via `ProcessInfo`. Returns the child's
/// badged process handle, which the caller keeps until the driver's settle
/// batch settles and then releases, or destroys the driver through
/// ([`destroy_child`]) when it never reported ready. Returns `None`, the
/// child torn down, on any failure, including a service endpoint that cannot
/// be copied (a driver delivered none would never report ready).
// clippy::too_many_lines: driver spawn is a single transaction — derive the
// per-child caps, install them into the suspended child, and serve two
// bootstrap rounds against one shared `ipc` buffer. Each derive owns a slot
// that must be released cooperatively on partial failure; extracting helpers
// requires passing the same `DriverSpawnConfig` to each. The linear
// presentation matches the bootstrap protocol one-to-one.
#[allow(clippy::too_many_lines)]
pub fn spawn_driver(config: &DriverSpawnConfig, ipc_buf: *mut u64) -> Option<u32>
{
    // Release the source ELF cap on every exit before the create call consumes
    // it (missing BAR/IRQ, badge-derive failure, ipc_call failure). Disarmed
    // once the ipc_call returns, which transfers the cap to procmgr.
    let source_cap = match config.source
    {
        CreateSource::Module(m) => m,
        CreateSource::File { file_cap, .. } => file_cap,
    };
    let mut module_guard = ModuleCapGuard::new(source_cap);

    if config.bars.is_empty() || config.bars.len() > MAX_VIRTIO_BARS
    {
        std::os::seraph::log!("driver spawn: BAR count outside 1..={}", MAX_VIRTIO_BARS);
        return None;
    }
    let procmgr_ep = config.procmgr_ep;
    let bootstrap_ep = config.bootstrap_ep;
    let service_ep = config.service_ep;
    let query_ep = config.query_ep;
    let device_badge = config.device_badge;

    // Allocate a bootstrap badge for the child.
    let Some(child_badge) = mint_bootstrap_badge()
    else
    {
        std::os::seraph::log!("driver spawn: entropy draw failed");
        return None;
    };
    let Ok(badged_creator) =
        syscall::cap_derive_badge(bootstrap_ep, syscall::RIGHTS_EP_SEND, child_badge)
    else
    {
        std::os::seraph::log!("driver spawn: badged creator derivation failed");
        return None;
    };

    // Create the process via procmgr. Caps [source, creator]. The child has no
    // stdio wired by default — it logs through `seraph::log!` via the discovery
    // cap procmgr installs in `ProcessInfo`.
    //
    // CREATE_PINNED: drivers reached through `spawn_driver` are PCI devices with
    // BAR + IRQ — the DMA-capable class. A device may write driver memory before
    // a demand fault could back it (the kernel never pins), so these must be
    // eager-mapped, not demand-paged. Applies to both the boot-module and the
    // on-disk (`CREATE_FROM_FILE`) source. #165 replaces the spawn-path keying
    // with an explicit per-driver DMA attribute.
    let sched_bits = procmgr_labels::create_sched_bits(config.priority, config.priority);
    let create_msg = match config.source
    {
        CreateSource::Module(module_cap) => IpcMessage::builder(
            procmgr_labels::CREATE_PROCESS | procmgr_labels::CREATE_PINNED | sched_bits,
        )
        .cap(module_cap)
        .cap(badged_creator)
        .build(),
        CreateSource::File { file_cap, size } => IpcMessage::builder(
            procmgr_labels::CREATE_FROM_FILE | procmgr_labels::CREATE_PINNED | sched_bits,
        )
        .word(0, size)
        .cap(file_cap)
        .cap(badged_creator)
        .build(),
    };
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_ep, &create_msg, ipc_buf) })
    else
    {
        std::os::seraph::log!("driver create ipc_call failed");
        return None;
    };
    // ipc_call returned: the source cap was transferred to procmgr regardless of
    // the reply label (procmgr owns its teardown on its own failure). Disarm so
    // the guard does not free the now-reused slot.
    module_guard.disarm();
    if reply.label != 0
    {
        std::os::seraph::log!("driver create failed");
        return None;
    }

    let reply_caps = reply.caps();
    if reply_caps.len() < 2
    {
        std::os::seraph::log!("driver CREATE_PROCESS reply missing caps");
        return None;
    }
    let process_handle = reply_caps[0];
    let thread_cap = reply_caps[1];
    // Tear down the child (and free its reply-cap slots) on any failure before
    // the final bootstrap round completes; disarmed on success.
    let child_guard = ChildGuard::new(process_handle, thread_cap, ipc_buf);

    // Derive all per-child caps for delivery via bootstrap. Each derivation
    // owns a devmgr slot that must be released on later failure paths so devmgr
    // does not leak it; the child itself is reaped by `child_guard`.
    let mut bar_copies = [0u32; MAX_VIRTIO_BARS];
    let mut bar_indices = [0u64; MAX_VIRTIO_BARS];
    let bar_count = config.bars.len();
    let drop_bars = |copies: &[u32]| {
        for &c in copies
        {
            let _ = syscall::cap_delete(c);
        }
    };
    for (i, bar) in config.bars.iter().enumerate()
    {
        let Ok(copy) = syscall::cap_derive(bar.cap, syscall::RIGHTS_ALL)
        else
        {
            std::os::seraph::log!("driver bar cap derivation failed");
            drop_bars(&bar_copies[..i]);
            return None;
        };
        bar_copies[i] = copy;
        bar_indices[i] = u64::from(bar.bar);
    }
    let bar_copies = &bar_copies[..bar_count];
    let bar_indices = &bar_indices[..bar_count];
    // IRQ is optional. A device devmgr could give no IRQ cap (for instance,
    // its line no held range covers, or the UART's exclusive line) is
    // delivered a null IRQ slot; the driver then polls its queue instead of
    // waiting on interrupts.
    let irq_copy = match config.irq_cap
    {
        Some(slot) =>
        {
            let Ok(c) = syscall::cap_derive(slot, syscall::RIGHTS_ALL)
            else
            {
                std::os::seraph::log!("driver irq cap derivation failed");
                drop_bars(bar_copies);
                return None;
            };
            c
        }
        None => 0,
    };
    let Ok(service_copy) = syscall::cap_derive(service_ep, syscall::RIGHTS_ALL)
    else
    {
        std::os::seraph::log!("driver service endpoint derivation failed");
        drop_bars(bar_copies);
        let _ = syscall::cap_delete(irq_copy);
        return None;
    };
    let Ok(devmgr_copy) =
        syscall::cap_derive_badge(query_ep, syscall::RIGHTS_EP_SEND, device_badge)
    else
    {
        std::os::seraph::log!("driver devmgr query cap derivation failed");
        drop_bars(bar_copies);
        let _ = syscall::cap_delete(irq_copy);
        let _ = syscall::cap_delete(service_copy);
        return None;
    };

    // Best-effort release of every derived per-child cap. Deleting a slot a
    // serve_round transfer already consumed is a no-op, so it is safe on any
    // post-derive failure arm.
    let drop_derived = || {
        drop_bars(bar_copies);
        let _ = syscall::cap_delete(irq_copy);
        let _ = syscall::cap_delete(service_copy);
        let _ = syscall::cap_delete(devmgr_copy);
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
        drop_derived();
        return None;
    }

    // Round 1: the BAR caps, each with its BAR index.
    // SAFETY: ipc_buf is the registered IPC buffer.
    if unsafe {
        ipc::bootstrap::serve_round(
            bootstrap_ep,
            child_badge,
            ipc_buf,
            false,
            bar_copies,
            bar_indices,
        )
    }
    .is_err()
    {
        std::os::seraph::log!("driver bootstrap round 1 failed");
        drop_derived();
        return None;
    }

    // Round 2: [service, irq, devmgr_query] as positional slots, done. A
    // null slot cannot be transferred, so an absent IRQ (a device sharing
    // an INTx line) is named absent in the presence word instead.
    let mut slots = [0u32; ROUND2_SLOTS];
    slots[SLOT_SERVICE] = service_copy;
    slots[SLOT_IRQ] = irq_copy;
    slots[SLOT_DEVMGR_QUERY] = devmgr_copy;
    let round2 = ipc::bootstrap::pack_slots(&slots);
    // SAFETY: ipc_buf is the registered IPC buffer.
    if unsafe {
        ipc::bootstrap::serve_round(
            bootstrap_ep,
            child_badge,
            ipc_buf,
            true,
            round2.caps(),
            &[round2.presence()],
        )
    }
    .is_err()
    {
        std::os::seraph::log!("driver bootstrap round 2 failed");
        drop_derived();
        return None;
    }

    // Observe the driver's death from here on. Bound only once every round
    // has succeeded, so the death queue takes posts only from the drivers a
    // roster records; a child that already died posts at once.
    if syscall::thread_bind_notification(thread_cap, config.death_eq, device_badge).is_err()
    {
        std::os::seraph::log!("driver death observer bind failed");
        return None;
    }

    // Child owns its full cap set: keep it alive, and its process handle.
    std::os::seraph::log!("driver started");
    Some(child_guard.keep_handle())
}

/// Capabilities and identifiers for one non-PCI platform device driver
/// spawn ([`spawn_simple_device`]).
pub struct SimpleSpawnConfig<'a>
{
    pub procmgr_ep: u32,
    pub bootstrap_ep: u32,
    /// ELF source: a boot-module Memory cap (serial, framebuffer) or a
    /// rootfs file cap (the per-arch RTC, `test-orphan`).
    pub source: CreateSource,
    /// devmgr-owned service endpoint; the driver receives on a copy.
    pub service_ep: u32,
    /// The device's arch authority cap, moved into the child.
    pub hw_cap: u32,
    /// The UART interrupt cap, moved into the child; 0 for none.
    pub irq_cap: u32,
    /// The driver's devmgr query cap, moved into the child: a SEND badged
    /// with `device_badge` on its settle batch's private endpoint
    /// ([`crate::settle::SettleBatch::driver_ep`]).
    pub query_ep: u32,
    /// Event queue the driver's death observer posts to, with
    /// `device_badge` as the correlator: devmgr's driver death queue
    /// ([`crate::settle::DriverWatch::death_eq`]). `None` binds no observer
    /// (the `test-orphan` shim, whose child never runs past its bootstrap).
    pub death_eq: Option<u32>,
    pub device_badge: u64,
    /// Data words round 1 carries: the CMOS RTC's century register index,
    /// and empty for every other device.
    pub round1_words: &'a [u64],
    /// Priority level the driver is created at (band ceiling equal); `0`
    /// takes procmgr's defaults (the `test-orphan` shim only).
    pub priority: u8,
}

/// Spawn a non-PCI platform device driver with a minimal capability set: a
/// copy of `service_ep`, the device's arch authority cap (`hw_cap`), an
/// optional IRQ cap (`irq_cap`, the serial UART's), and the driver's devmgr
/// query cap (`query_ep`). Unlike [`spawn_driver`] there is no BAR.
///
/// Two bootstrap rounds are served:
///   Round 1 (not terminal): `[service, hw_cap, irq_cap?]`, `round1_words`
///   Round 2 (terminal):     `[query_ep]`
/// The driver calls `QUERY_DEVICE_INFO` on the query cap when it needs
/// runtime platform metadata (the framebuffer's geometry; the payload shape
/// lives in the driver's crate, devmgr stores opaque bytes in its
/// `DeviceCatalog`), and `DRIVER_READY` on it once its device is set up.
/// Once the final round is served a death observer is bound on the driver's
/// thread to `death_eq`, correlator `device_badge`.
///
/// devmgr retains `service_ep` to mint client SEND caps on query; `hw_cap`,
/// `irq_cap`, and `query_ep` are *moved* into the child (delivered directly,
/// not copied), so devmgr holds no device-specific authority after a
/// successful spawn. The caller transfers ownership of those three caps and
/// of the source cap to this function: each is moved to the child or
/// procmgr on success and deleted on failure. Returns the child's badged
/// process handle, kept by the caller as [`spawn_driver`]'s is, or `None` on
/// any spawn-path failure, the child torn down.
// too_many_lines: simple-device spawn is one transaction — derive the
// per-child caps, install them into the suspended child, and serve two
// bootstrap rounds against the shared `ipc` buffer. Each fallible step
// owns slots that must be released cooperatively on partial failure;
// extracting helpers requires threading the same parameters through. The
// linear presentation matches the bootstrap protocol one-to-one.
#[allow(clippy::too_many_lines)]
pub fn spawn_simple_device(config: &SimpleSpawnConfig, ipc_buf: *mut u64) -> Option<u32>
{
    let source_cap = match config.source
    {
        CreateSource::Module(m) => m,
        CreateSource::File { file_cap, .. } => file_cap,
    };
    // Release the source cap on every exit before the create call transfers
    // it: for `File` the namespace walk just produced it; for `Module` a
    // retained cap is a live derivation child of init's donated pool-run
    // source and pins that run unsplittable. Disarmed once the create
    // `ipc_call` returns.
    let mut source_guard = ModuleCapGuard::new(source_cap);
    // The caps this function moves into the child, released on every
    // failure (deleting a slot a round already transferred is a no-op).
    let release_moved = || {
        for cap in [config.hw_cap, config.irq_cap, config.query_ep]
        {
            if cap != 0
            {
                let _ = syscall::cap_delete(cap);
            }
        }
    };

    if source_cap == 0 || config.service_ep == 0 || config.hw_cap == 0 || config.query_ep == 0
    {
        std::os::seraph::log!("simple-device spawn: missing source/service/hw/query cap");
        release_moved();
        return None;
    }

    let Some(child_badge) = mint_bootstrap_badge()
    else
    {
        std::os::seraph::log!("simple-device spawn: entropy draw failed");
        release_moved();
        return None;
    };
    let Ok(badged_creator) =
        syscall::cap_derive_badge(config.bootstrap_ep, syscall::RIGHTS_EP_SEND, child_badge)
    else
    {
        std::os::seraph::log!("simple-device spawn: badged creator derivation failed");
        release_moved();
        return None;
    };

    // Band ceiling equals the driver's level; `0` = procmgr's defaults
    // (used only by the test-orphan shim).
    let sched_bits = procmgr_labels::create_sched_bits(config.priority, config.priority);
    let create_msg = match config.source
    {
        CreateSource::Module(module_cap) =>
        {
            IpcMessage::builder(procmgr_labels::CREATE_PROCESS | sched_bits)
                .cap(module_cap)
                .cap(badged_creator)
                .build()
        }
        CreateSource::File { file_cap, size } =>
        {
            IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE | sched_bits)
                .word(0, size)
                .cap(file_cap)
                .cap(badged_creator)
                .build()
        }
    };
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(config.procmgr_ep, &create_msg, ipc_buf) })
    else
    {
        std::os::seraph::log!("simple-device CREATE_* ipc_call failed");
        release_moved();
        return None;
    };
    // ipc_call returned: the kernel transferred the source cap to procmgr,
    // which deletes it on its own failure too. Disarm so the guard does not
    // free a slot since reused.
    source_guard.disarm();
    if reply.label != 0
    {
        std::os::seraph::log!("simple-device CREATE_* failed");
        release_moved();
        return None;
    }
    let reply_caps = reply.caps();
    if reply_caps.len() < 2
    {
        // CREATE reported success without the process handle and thread cap
        // it returns on success. Defensive; with no handle there is no badge
        // to tear the child down with.
        std::os::seraph::log!("simple-device CREATE_PROCESS reply missing caps");
        for &cap in reply_caps
        {
            let _ = syscall::cap_delete(cap);
        }
        release_moved();
        return None;
    }
    let process_handle = reply_caps[0];
    let thread_cap = reply_caps[1];
    // Tear down the child (and free its reply-cap slots) on any failure before
    // the death observer is bound; on success the caller keeps the handle.
    let child_guard = ChildGuard::new(process_handle, thread_cap, ipc_buf);

    // Copy of the service endpoint for the child; devmgr keeps the original
    // to mint client SEND caps on query.
    let Ok(service_copy) = syscall::cap_derive(config.service_ep, syscall::RIGHTS_ALL)
    else
    {
        std::os::seraph::log!("simple-device service endpoint derivation failed");
        release_moved();
        return None;
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
        release_moved();
        return None;
    }

    // Round 1 (not terminal): [service, hw_cap, irq_cap?] with the round-1
    // words. irq_cap rides only when present (the serial driver).
    let round1_caps: [u32; 3] = [service_copy, config.hw_cap, config.irq_cap];
    let round1_len = if config.irq_cap != 0 { 3 } else { 2 };
    // SAFETY: ipc_buf is the registered IPC buffer.
    if unsafe {
        ipc::bootstrap::serve_round(
            config.bootstrap_ep,
            child_badge,
            ipc_buf,
            false,
            &round1_caps[..round1_len],
            config.round1_words,
        )
    }
    .is_err()
    {
        std::os::seraph::log!("simple-device bootstrap round 1 failed");
        let _ = syscall::cap_delete(service_copy);
        release_moved();
        return None;
    }

    // Round 2 (terminal): [query_ep].
    // SAFETY: ipc_buf is the registered IPC buffer.
    if unsafe {
        ipc::bootstrap::serve_round(
            config.bootstrap_ep,
            child_badge,
            ipc_buf,
            true,
            &[config.query_ep],
            &[],
        )
    }
    .is_err()
    {
        std::os::seraph::log!("simple-device bootstrap round 2 failed");
        let _ = syscall::cap_delete(config.query_ep);
        return None;
    }

    // Observe the driver's death from here on, as `spawn_driver` does.
    if let Some(death_eq) = config.death_eq
        && syscall::thread_bind_notification(thread_cap, death_eq, config.device_badge).is_err()
    {
        std::os::seraph::log!("simple-device death observer bind failed");
        return None;
    }

    std::os::seraph::log!("simple-device driver started");
    Some(child_guard.keep_handle())
}
