// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/spawn.rs

//! Driver process spawning with per-device capability delivery via bootstrap.
//!
//! Creates driver processes via procmgr, then serves the driver's bootstrap
//! over IPC to deliver its per-device capability set: for a driver bound to
//! a device, the device's resource list ([`driver_binding::resources`]); for
//! the IOMMU driver, its own rounds. log + procmgr caps arrive via
//! `ProcessInfo` and are not part of this protocol.

use driver_binding::resources::{END_SLOTS, Endpoints, Resource, Round};
use ipc::{IpcMessage, procmgr_labels};

/// Source the child's ELF binary is loaded from: a boot module devmgr holds
/// (the drivers the boot bundle carries) carries a procmgr Memory cap and
/// uses [`CreateSource::Module`]; a driver loaded from the rootfs (walked by
/// devmgr through the directory cap of `SET_DRIVERS_DIR` or `BIND_DRIVERS`)
/// carries a vfsd file SEND cap plus a size hint and uses
/// [`CreateSource::File`]. The variant decides the procmgr request label and
/// payload shape; the rest of [`spawn_bound_driver`] — service-endpoint
/// derivation, `START_PROCESS`, bootstrap rounds — is identical across both
/// sources.
#[derive(Clone, Copy)]
pub enum CreateSource
{
    /// Memory cap to an in-memory ELF image (`procmgr_labels::CREATE_PROCESS`).
    /// A `CREATE_PROCESS` `ipc_call` transfers the cap to procmgr (which deletes
    /// it on both success and failure). On any failure BEFORE that transfer,
    /// [`spawn_bound_driver`] deletes the cap on the caller's behalf — a
    /// retained boot-module cap is a live derivation child of init's donated
    /// pool-run source and pins that run unsplittable.
    Module(u64),
    /// vfsd file SEND cap (`procmgr_labels::CREATE_FROM_FILE`). `size` is
    /// the file size hint reported by the resolving `NS_LOOKUP`. On any
    /// pre-`ipc_call` failure inside [`spawn_bound_driver`], the function
    /// deletes the file cap on the caller's behalf — the cap was just
    /// derived by the namespace walk and has no retry value.
    File
    {
        file_cap: u64, size: u64
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
pub struct ModuleCapGuard(u64);

impl ModuleCapGuard
{
    /// Arm a guard over `slot` (0 = nothing to guard).
    pub fn new(slot: u64) -> Self
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
/// `thread_cap` slot delivered in the `CREATE_PROCESS` reply, the
/// `process_handle` slot unless [`keep_handle`](Self::keep_handle) or
/// [`keep_held`](Self::keep_held) took it, and the `release_token` slot (a
/// `CREATE_DMA_HOLD` child's) unless [`keep_held`](Self::keep_held) took it.
/// While still armed, `Drop` additionally sends `DESTROY_PROCESS` over the
/// badged `process_handle` first ([`destroy_child`]), so procmgr reaps the
/// orphan (thread, cspace, aspace torn down; pages returned to memmgr) instead
/// of leaving it hung in `request_round`.
struct ChildGuard
{
    process_handle: u64,
    thread_cap: u64,
    release_token: u64,
    ipc_buf: *mut u64,
    destroy: bool,
}

impl ChildGuard
{
    /// Arm a guard over a freshly-created child's reply caps; `release_token`
    /// is 0 for a child created without `CREATE_DMA_HOLD`.
    fn new(process_handle: u64, thread_cap: u64, release_token: u64, ipc_buf: *mut u64) -> Self
    {
        Self {
            process_handle,
            thread_cap,
            release_token,
            ipc_buf,
            destroy: true,
        }
    }

    /// The child was started: keep it alive and hand its process handle to
    /// the caller, which keeps it at least until the driver's settle batch
    /// settles (to destroy a driver that never reports ready) or withdraws
    /// the started driver at once when its bootstrap failed. `Drop` still
    /// frees the thread cap, and the release token, so a `CREATE_DMA_HOLD`
    /// child kept this way has its hold never released.
    fn keep_handle(mut self) -> u64
    {
        self.destroy = false;
        core::mem::take(&mut self.process_handle)
    }

    /// As [`Self::keep_handle`], for a `CREATE_DMA_HOLD` child whose hold the
    /// caller releases once its device is confirmed stopped: hand it the
    /// release token too.
    fn keep_held(mut self) -> HeldChild
    {
        self.destroy = false;
        HeldChild {
            process_handle: core::mem::take(&mut self.process_handle),
            release_token: core::mem::take(&mut self.release_token),
        }
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
        if self.release_token != 0
        {
            let _ = syscall::cap_delete(self.release_token);
        }
    }
}

/// The two procmgr caps devmgr keeps for a started `CREATE_DMA_HOLD` driver:
/// its badged process handle, and its release token, the third cap of the
/// create reply, on which alone procmgr serves `RELEASE_HOLD`
/// (`services/procmgr/docs/ipc-interface.md` § Label 3), so no copy of the
/// driver's own procmgr cap can release its memory early.
#[derive(Clone, Copy)]
pub struct HeldChild
{
    /// devmgr's slot of the child's badged process handle.
    pub process_handle: u64,
    /// devmgr's slot of the child's release token, the only cap procmgr
    /// serves `RELEASE_HOLD` on.
    pub release_token: u64,
}

/// Destroy a child through its badged `process_handle` (`DESTROY_PROCESS`:
/// procmgr tears down its thread, `CSpace`, and address space, which drops
/// every capability it holds and returns its pages, unless the child was
/// created with `CREATE_DMA_HOLD` and started, whose pages procmgr then holds
/// until a `RELEASE_HOLD` this function never sends) and release the handle.
/// A child that has already died is a no-op for procmgr.
pub fn destroy_child(process_handle: u64, ipc_buf: *mut u64)
{
    send_destroy(process_handle, ipc_buf);
    let _ = syscall::cap_delete(process_handle);
}

/// Destroy a held child as [`destroy_child`] does and delete its release
/// token without sending the release: its device is not confirmed stopped,
/// so procmgr keeps its pages held for the rest of the boot.
pub fn destroy_held(child: HeldChild, ipc_buf: *mut u64)
{
    destroy_child(child.process_handle, ipc_buf);
    let _ = syscall::cap_delete(child.release_token);
}

/// Destroy a `CREATE_DMA_HOLD` child as [`destroy_child`] does, then release
/// its held pages to memmgr (`RELEASE_HOLD` on its release token), and
/// release both caps. Called only once the child's device is confirmed quiet;
/// procmgr's teardown of the child, by this destroy or by its own reap of a
/// dead child, precedes the release: procmgr replies to the destroy only
/// once the child is torn down and its reclaim parked, by whichever of its
/// threads tore it down (services/procmgr/README.md § Concurrency).
pub fn destroy_and_release(child: HeldChild, ipc_buf: *mut u64)
{
    send_destroy(child.process_handle, ipc_buf);
    let release_msg = IpcMessage::new(procmgr_labels::RELEASE_HOLD);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let released = unsafe { ipc::ipc_call(child.release_token, &release_msg, ipc_buf) };
    if !matches!(released, Ok(r) if r.label == 0)
    {
        std::os::seraph::log!(warn: "driver memory hold not released");
    }
    let _ = syscall::cap_delete(child.process_handle);
    let _ = syscall::cap_delete(child.release_token);
}

/// Send `DESTROY_PROCESS` on `process_handle`; procmgr replies success
/// whatever the child's state.
fn send_destroy(process_handle: u64, ipc_buf: *mut u64)
{
    let destroy_msg = IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_buf) };
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

/// The most resources one bound driver is delivered: every range of a PCI
/// function's BARs (`driver_binding::resources::MAX_PCI_RANGES`) and either
/// its wired line or the most message-signaled vectors a declaration
/// requests, one `Interrupt` resource each.
pub const MAX_BOUND_RESOURCES: usize =
    driver_binding::resources::MAX_PCI_RANGES + driver_binding::decl::MAX_MSI_VECTORS as usize;

/// What devmgr needs to start a driver it has bound to a device and deliver
/// it the device's resource list (docs/driver-binding.md § Binding).
pub struct BoundSpawnConfig<'a>
{
    pub procmgr_ep: u64,
    pub bootstrap_ep: u64,
    /// ELF source for the child: a copy of a boot module
    /// ([`CreateSource::Module`]) or of a drivers-directory file node cap
    /// ([`CreateSource::File`]), consumed by the spawn.
    pub source: CreateSource,
    /// The device's resources, each with the cap devmgr keeps for it, from
    /// which the driver's copy is derived; at most [`MAX_BOUND_RESOURCES`].
    pub resources: &'a [Resource],
    /// devmgr's copy of the device's DMA capability
    /// ([`crate::dma::DmaGrant::cap`]) for a DMA declaration; the driver is
    /// then created `CREATE_PINNED` and `CREATE_DMA_HOLD`. `None` for a
    /// driver of a device that performs no DMA.
    pub dma_cap: Option<u64>,
    pub service_ep: u64,
    /// Endpoint the driver's devmgr query cap is a `device_badge`-badged
    /// SEND on: the private driver endpoint of the driver's settle batch
    /// ([`crate::settle::SettleBatch::driver_ep`]).
    pub query_ep: u64,
    /// Event queue the driver's death observer posts to, with `device_badge`
    /// as the correlator: devmgr's driver death queue
    /// ([`crate::settle::DriverWatch::death_eq`]).
    pub death_eq: u64,
    pub device_badge: u64,
    /// Priority level the driver is created at; its band ceiling equals
    /// its level (a driver never spawns further processes). Rides the
    /// create label's scheduling fields; must not exceed devmgr's own band
    /// ceiling (`sched_policy::DEVMGR_BAND_MAX`) or procmgr rejects the
    /// spawn.
    pub priority: u8,
}

/// How a driver spawn ended. `H` is what the caller keeps of the started
/// driver: its badged process handle ([`spawn_iommu_driver`]), or that and
/// its release token ([`spawn_bound_driver`], [`HeldChild`]).
pub enum DriverSpawn<H = u64>
{
    /// The driver completed its bootstrap: what the caller keeps of it.
    Bootstrapped(H),
    /// The driver was started but its bootstrap failed after it, so it may
    /// hold the device's caps: what the caller keeps of it, through which it
    /// withdraws the driver from the device and destroys it as a live
    /// driver.
    Unbootstrapped(H),
    /// The spawn failed before the driver started; the child, if created,
    /// is torn down and its pages returned.
    Failed,
}

/// Delete every cap in `caps` that is not 0.
fn delete_all(caps: &[u64])
{
    for &cap in caps.iter().filter(|&&c| c != 0)
    {
        let _ = syscall::cap_delete(cap);
    }
}

/// The resource round of `resource` carrying `copy`, the driver's copy of
/// its cap.
fn resource_round(resource: &Resource, copy: u64) -> Option<Round>
{
    match *resource
    {
        Resource::Mmio {
            bar,
            phys,
            bytes,
            offset,
            ..
        } => Some(Round::mmio_at(copy, bar, phys, bytes, offset)),
        Resource::IoPort { base, count, .. } => Some(Round::io_port(copy, base, count)),
        Resource::Interrupt {
            kind, vector, mode, ..
        } => Round::interrupts(kind, vector, mode, &[copy]),
    }
}

/// Start a driver devmgr has bound to a device and deliver it the device's
/// resource list ([`driver_binding::resources`]): one non-terminal round per
/// resource, in `config.resources`' order, each carrying a copy of its cap,
/// then the terminal round carrying the service endpoint, the devmgr query
/// cap (a SEND on `query_ep` badged `device_badge`, through which the driver
/// fetches its device info and reports ready), and, for a DMA declaration,
/// the DMA capability. Once the end round is served it binds a death
/// observer on the driver's thread to `death_eq`, correlator
/// `device_badge`, so devmgr sees the driver's death, before it reports
/// ready or after it is served.
///
/// A driver of a DMA device is created `CREATE_PINNED`, since its device may
/// write its memory before a demand fault could back it, and
/// `CREATE_DMA_HOLD`, since it may write it after the driver dies until
/// devmgr has stopped its DMA; procmgr then holds its pages after it is torn
/// down until devmgr releases them on its release token
/// ([`destroy_and_release`]). Any other driver is created demand-paged, with
/// no hold and no release token.
///
/// Returns [`DriverSpawn::Bootstrapped`] with the child's badged process
/// handle and release token (0 without a hold) ([`HeldChild`]), which the
/// caller keeps to withdraw the driver through;
/// [`DriverSpawn::Unbootstrapped`] with them when a round or the death
/// observer's bind failed after the start; and [`DriverSpawn::Failed`], the
/// child torn down, on any failure before the start.
// too_many_lines: one spawn transaction: derive the per-child caps, create
// and start the child, and serve its rounds against one shared IPC buffer;
// every derived slot must be released on a partial failure, and the linear
// presentation matches the bootstrap protocol one-to-one.
#[allow(clippy::too_many_lines)]
pub fn spawn_bound_driver(config: &BoundSpawnConfig, ipc_buf: *mut u64) -> DriverSpawn<HeldChild>
{
    // Release the source ELF cap on every exit before the create call
    // consumes it. Disarmed once the ipc_call returns, which transfers the
    // cap to procmgr.
    let source_cap = match config.source
    {
        CreateSource::Module(m) => m,
        CreateSource::File { file_cap, .. } => file_cap,
    };
    let mut source_guard = ModuleCapGuard::new(source_cap);

    if config.resources.len() > MAX_BOUND_RESOURCES
    {
        std::os::seraph::log!(warn: "driver spawn: more than {} resources", MAX_BOUND_RESOURCES);
        return DriverSpawn::Failed;
    }
    let Some(child_badge) = mint_bootstrap_badge()
    else
    {
        std::os::seraph::log!(warn: "driver spawn: entropy draw failed");
        return DriverSpawn::Failed;
    };
    let Ok(badged_creator) =
        syscall::cap_derive_badge(config.bootstrap_ep, syscall::RIGHTS_EP_SEND, child_badge)
    else
    {
        std::os::seraph::log!(warn: "driver spawn: badged creator derivation failed");
        return DriverSpawn::Failed;
    };

    let held = config.dma_cap.is_some();
    let flags = if held
    {
        procmgr_labels::CREATE_PINNED | procmgr_labels::CREATE_DMA_HOLD
    }
    else
    {
        0
    };
    let sched_bits = procmgr_labels::create_sched_bits(config.priority, config.priority);
    let create_msg = match config.source
    {
        CreateSource::Module(module_cap) =>
        {
            IpcMessage::builder(procmgr_labels::CREATE_PROCESS | flags | sched_bits)
                .cap(module_cap)
                .cap(badged_creator)
                .build()
        }
        CreateSource::File { file_cap, size } =>
        {
            IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE | flags | sched_bits)
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
        std::os::seraph::log!(warn: "driver create ipc_call failed");
        return DriverSpawn::Failed;
    };
    // ipc_call returned: the source cap was transferred to procmgr whatever
    // the reply label.
    source_guard.disarm();
    if reply.label != 0
    {
        std::os::seraph::log!(warn: "driver create failed");
        return DriverSpawn::Failed;
    }

    // [process handle, thread], and the release token of a held child.
    let reply_caps = reply.caps();
    let (process_handle, thread_cap, release_token) = match (held, reply_caps)
    {
        (true, &[p, t, r]) => (p, t, r),
        (false, &[p, t]) => (p, t, 0),
        _ =>
        {
            std::os::seraph::log!(warn: "driver create reply carries the wrong caps");
            delete_all(reply_caps);
            return DriverSpawn::Failed;
        }
    };
    // Tear down the child (and free its reply-cap slots) on any failure
    // before the end round completes; disarmed on success.
    let child_guard = ChildGuard::new(process_handle, thread_cap, release_token, ipc_buf);

    // Derive every per-child cap. Deleting a slot a served round already
    // transferred is a no-op, so `derived` is released whole on any later
    // failure.
    let mut derived = [0u64; MAX_BOUND_RESOURCES + END_SLOTS];
    for (slot, resource) in derived.iter_mut().zip(config.resources)
    {
        // A driver's Interrupt cap binds and acknowledges its source and no
        // more: the authority to mint message-signaled targets
        // (`RIGHTS_IRQ_MINT`) stays with devmgr.
        let rights = match resource
        {
            Resource::Interrupt { .. } => syscall::RIGHTS_IRQ_NOTIFY,
            Resource::Mmio { .. } | Resource::IoPort { .. } => syscall::RIGHTS_ALL,
        };
        let Ok(copy) = syscall::cap_derive(resource.cap(), rights)
        else
        {
            std::os::seraph::log!(warn: "driver resource cap derivation failed");
            delete_all(&derived);
            return DriverSpawn::Failed;
        };
        *slot = copy;
    }
    let count = config.resources.len();
    let Ok(service_copy) = syscall::cap_derive(config.service_ep, syscall::RIGHTS_ALL)
    else
    {
        std::os::seraph::log!(warn: "driver service endpoint derivation failed");
        delete_all(&derived);
        return DriverSpawn::Failed;
    };
    derived[count] = service_copy;
    let Ok(query_copy) = syscall::cap_derive_badge(
        config.query_ep,
        syscall::RIGHTS_EP_SEND,
        config.device_badge,
    )
    else
    {
        std::os::seraph::log!(warn: "driver devmgr query cap derivation failed");
        delete_all(&derived);
        return DriverSpawn::Failed;
    };
    derived[count + 1] = query_copy;
    let dma_copy = match config.dma_cap
    {
        Some(dma) =>
        {
            let Ok(copy) = syscall::cap_derive(dma, syscall::RIGHTS_EP_SEND_GRANT)
            else
            {
                std::os::seraph::log!(warn: "driver DMA cap derivation failed");
                delete_all(&derived);
                return DriverSpawn::Failed;
            };
            copy
        }
        None => 0,
    };
    derived[count + 2] = dma_copy;

    let start_msg = IpcMessage::new(procmgr_labels::START_PROCESS);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let start_ok = matches!(
        unsafe { ipc::ipc_call(process_handle, &start_msg, ipc_buf) },
        Ok(r) if r.label == 0
    );
    if !start_ok
    {
        std::os::seraph::log!(warn: "driver START_PROCESS failed");
        delete_all(&derived);
        return DriverSpawn::Failed;
    }

    // The resource rounds, then the end round.
    let end = Round::end(&Endpoints {
        service: service_copy,
        devmgr_query: query_copy,
        dma: dma_copy,
    });
    let rounds = config
        .resources
        .iter()
        .zip(derived)
        .map(|(resource, copy)| resource_round(resource, copy))
        .chain(core::iter::once(Some(end)));
    for round in rounds
    {
        let Some(round) = round
        else
        {
            std::os::seraph::log!(warn: "driver resource round not encodable");
            delete_all(&derived);
            return DriverSpawn::Unbootstrapped(child_guard.keep_held());
        };
        // SAFETY: ipc_buf is the registered IPC buffer.
        let served = unsafe {
            ipc::bootstrap::serve_round(
                config.bootstrap_ep,
                child_badge,
                ipc_buf,
                round.done(),
                round.caps(),
                round.data(),
            )
        };
        if served.is_err()
        {
            std::os::seraph::log!(warn: "driver bootstrap round failed");
            delete_all(&derived);
            return DriverSpawn::Unbootstrapped(child_guard.keep_held());
        }
    }

    // Observe the driver's death from here on. Bound only once every round
    // has succeeded, so the death queue takes posts only from the drivers a
    // roster records; a child that already died posts at once.
    if syscall::thread_bind_notification(thread_cap, config.death_eq, config.device_badge).is_err()
    {
        std::os::seraph::log!(warn: "driver death observer bind failed");
        return DriverSpawn::Unbootstrapped(child_guard.keep_held());
    }
    std::os::seraph::log!("driver started");
    DriverSpawn::Bootstrapped(child_guard.keep_held())
}

/// One remapping unit handed to the IOMMU driver: its register `Mmio` cap,
/// which the spawn moves to the driver (devmgr keeps no copy), and its
/// bootstrap round's data words (`iommu_core::bootstrap`).
pub struct UnitRound
{
    pub cap: u64,
    pub words: Vec<u64>,
}

/// Capabilities and identifiers for the IOMMU driver's spawn
/// ([`spawn_iommu_driver`]).
pub struct IommuSpawnConfig<'a>
{
    pub procmgr_ep: u64,
    pub bootstrap_ep: u64,
    /// The driver's boot-module Memory cap, consumed by `CREATE_PROCESS` or
    /// deleted on a failure before it.
    pub module_cap: u64,
    /// The units, in unit-index order; every cap is moved to the driver or
    /// deleted.
    pub units: &'a [UnitRound],
    /// devmgr-owned service endpoint; the driver receives on a copy.
    pub service_ep: u64,
    /// The private endpoint of the driver's settle batch.
    pub query_ep: u64,
    /// devmgr's driver death queue.
    pub death_eq: u64,
    /// The IOMMU death watch's queue, a second observer of the driver's
    /// death that no call of devmgr's control thread can delay
    /// (`crate::iommu`).
    pub watch_eq: u64,
    pub device_badge: u64,
    pub priority: u8,
}

/// Spawn the IOMMU driver and serve its bootstrap
/// (`iommu_core::bootstrap`): one round per unit with its register cap, then
/// the terminal round with a copy of `service_ep` and a SEND badged
/// `device_badge` on `query_ep`; once that is served, two death observers,
/// on `death_eq` and `watch_eq`. Created `CREATE_PINNED`, since the units
/// walk its table pages and they must never fault, `CREATE_DMA_HOLD`,
/// since the units can walk those pages after it dies: devmgr never releases
/// the hold, so it deletes the release token and the pages stay quarantined
/// for the boot, and `CREATE_PHYS_ACCESS`, since the units are programmed
/// with physical addresses, of its table pages and of every frame `MAP`
/// installs. Both observers carry the correlator `device_badge`. Returns as
/// [`spawn_bound_driver`] does, with the process handle alone.
// too_many_lines: one spawn transaction, as `spawn_bound_driver`: every derived
// cap owns a slot released on a later failure, and the rounds follow the
// bootstrap protocol one to one.
#[allow(clippy::too_many_lines)]
pub fn spawn_iommu_driver(config: &IommuSpawnConfig, ipc_buf: *mut u64) -> DriverSpawn
{
    let mut module_guard = ModuleCapGuard::new(config.module_cap);
    let release_units = |from: usize| {
        for u in &config.units[from..]
        {
            let _ = syscall::cap_delete(u.cap);
        }
    };
    let Some(child_badge) = mint_bootstrap_badge()
    else
    {
        std::os::seraph::log!(warn: "IOMMU driver spawn: entropy draw failed");
        release_units(0);
        return DriverSpawn::Failed;
    };
    let Ok(badged_creator) =
        syscall::cap_derive_badge(config.bootstrap_ep, syscall::RIGHTS_EP_SEND, child_badge)
    else
    {
        std::os::seraph::log!(warn: "IOMMU driver spawn: badged creator derivation failed");
        release_units(0);
        return DriverSpawn::Failed;
    };
    let flags = procmgr_labels::CREATE_PINNED
        | procmgr_labels::CREATE_DMA_HOLD
        | procmgr_labels::CREATE_PHYS_ACCESS;
    let sched_bits = procmgr_labels::create_sched_bits(config.priority, config.priority);
    let create_msg = IpcMessage::builder(procmgr_labels::CREATE_PROCESS | flags | sched_bits)
        .cap(config.module_cap)
        .cap(badged_creator)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(config.procmgr_ep, &create_msg, ipc_buf) };
    let Ok(reply) = reply
    else
    {
        std::os::seraph::log!(warn: "IOMMU driver create ipc_call failed");
        release_units(0);
        return DriverSpawn::Failed;
    };
    // The call transferred the module cap to procmgr whatever its reply.
    module_guard.disarm();
    // `CREATE_DMA_HOLD`: [process handle, thread, release token].
    let reply_caps = reply.caps();
    let (0, &[process_handle, thread_cap, release_token]) = (reply.label, reply_caps)
    else
    {
        std::os::seraph::log!(warn: "IOMMU driver create failed");
        for &c in reply_caps
        {
            let _ = syscall::cap_delete(c);
        }
        release_units(0);
        return DriverSpawn::Failed;
    };
    let child_guard = ChildGuard::new(process_handle, thread_cap, release_token, ipc_buf);
    let Ok(service_copy) = syscall::cap_derive(config.service_ep, syscall::RIGHTS_ALL)
    else
    {
        std::os::seraph::log!(warn: "IOMMU driver service endpoint derivation failed");
        release_units(0);
        return DriverSpawn::Failed;
    };
    let Ok(query_copy) = syscall::cap_derive_badge(
        config.query_ep,
        syscall::RIGHTS_EP_SEND,
        config.device_badge,
    )
    else
    {
        std::os::seraph::log!(warn: "IOMMU driver query cap derivation failed");
        release_units(0);
        let _ = syscall::cap_delete(service_copy);
        return DriverSpawn::Failed;
    };
    // Deleting a slot a round already moved is a no-op.
    let release_endpoints = || {
        let _ = syscall::cap_delete(service_copy);
        let _ = syscall::cap_delete(query_copy);
    };
    let start_msg = IpcMessage::new(procmgr_labels::START_PROCESS);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let started = unsafe { ipc::ipc_call(process_handle, &start_msg, ipc_buf) };
    if !matches!(started, Ok(r) if r.label == 0)
    {
        std::os::seraph::log!(warn: "IOMMU driver START_PROCESS failed");
        release_units(0);
        release_endpoints();
        return DriverSpawn::Failed;
    }
    for (i, unit) in config.units.iter().enumerate()
    {
        // SAFETY: ipc_buf is the registered IPC buffer.
        let served = unsafe {
            ipc::bootstrap::serve_round(
                config.bootstrap_ep,
                child_badge,
                ipc_buf,
                false,
                &[unit.cap],
                &unit.words,
            )
        };
        if served.is_err()
        {
            std::os::seraph::log!(warn: "IOMMU driver bootstrap unit round failed");
            release_units(i);
            release_endpoints();
            return DriverSpawn::Unbootstrapped(child_guard.keep_handle());
        }
    }
    // SAFETY: ipc_buf is the registered IPC buffer.
    let served = unsafe {
        ipc::bootstrap::serve_round(
            config.bootstrap_ep,
            child_badge,
            ipc_buf,
            true,
            &[service_copy, query_copy],
            &[iommu_core::bootstrap::ROUND_ENDPOINTS],
        )
    };
    if served.is_err()
    {
        std::os::seraph::log!(warn: "IOMMU driver bootstrap endpoint round failed");
        release_endpoints();
        return DriverSpawn::Unbootstrapped(child_guard.keep_handle());
    }
    if syscall::thread_bind_notification(thread_cap, config.death_eq, config.device_badge).is_err()
        || syscall::thread_bind_notification(thread_cap, config.watch_eq, config.device_badge)
            .is_err()
    {
        std::os::seraph::log!(warn: "IOMMU driver death observer bind failed");
        return DriverSpawn::Unbootstrapped(child_guard.keep_handle());
    }
    std::os::seraph::log!("IOMMU driver started");
    DriverSpawn::Bootstrapped(child_guard.keep_handle())
}
