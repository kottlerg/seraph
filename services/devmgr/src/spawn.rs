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
/// serial, framebuffer) carry a procmgr Memory cap and use
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
/// yet reached its final `done` round. `Drop` always releases the caller-side
/// `process_handle` and `thread_cap` slots delivered in the `CREATE_PROCESS`
/// reply — devmgr retains no per-child handle past a spawn, so leaving them
/// held leaks devmgr `CSpace` slots for its resident lifetime. While still armed,
/// `Drop` additionally sends `DESTROY_PROCESS` over the badged `process_handle`
/// first, so procmgr reaps the orphan (thread, cspace, aspace torn down; pages
/// returned to memmgr) instead of leaving it hung in `request_round`.
///
/// Call [`disarm`](Self::disarm) once the final round's `done` reply has been
/// served and the child owns its full cap set: the slots are still freed, but
/// the now-live child is left running.
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

    /// Bootstrap completed: keep the child alive. `Drop` still frees devmgr's
    /// handles to it but no longer destroys it.
    fn disarm(&mut self)
    {
        self.destroy = false;
    }
}

impl Drop for ChildGuard
{
    fn drop(&mut self)
    {
        if self.destroy
        {
            let destroy_msg = IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_call(self.process_handle, &destroy_msg, self.ipc_buf) };
        }
        let _ = syscall::cap_delete(self.process_handle);
        if self.thread_cap != 0
        {
            let _ = syscall::cap_delete(self.thread_cap);
        }
    }
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
    /// ELF source for the child: a boot-module Memory cap
    /// ([`CreateSource::Module`], the bootstrap-essential PCI drivers) or a
    /// rootfs file cap ([`CreateSource::File`], for on-disk PCI drivers loaded
    /// after vfsd-mount, e.g. virtio-input). Both spawn `CREATE_PINNED` — a PCI
    /// device with a BAR/IRQ is DMA-capable and must be eager-mapped.
    pub source: CreateSource,
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
pub fn spawn_driver(config: &DriverSpawnConfig, ipc_buf: *mut u64) -> bool
{
    let _ = config.bars.bases;
    let _ = config.bars.sizes;

    // Release the source ELF cap on every exit before the create call consumes
    // it (missing BAR/IRQ, badge-derive failure, ipc_call failure). Disarmed
    // once the ipc_call returns, which transfers the cap to procmgr.
    let source_cap = match config.source
    {
        CreateSource::Module(m) => m,
        CreateSource::File { file_cap, .. } => file_cap,
    };
    let mut module_guard = ModuleCapGuard::new(source_cap);

    let Some(bar_cap) = config.bars.caps.first().copied()
    else
    {
        std::os::seraph::log!("driver spawn: no BAR cap");
        return false;
    };
    let procmgr_ep = config.procmgr_ep;
    let bootstrap_ep = config.bootstrap_ep;
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
        return false;
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
    let create_msg = match config.source
    {
        CreateSource::Module(module_cap) =>
        {
            IpcMessage::builder(procmgr_labels::CREATE_PROCESS | procmgr_labels::CREATE_PINNED)
                .cap(module_cap)
                .cap(badged_creator)
                .build()
        }
        CreateSource::File { file_cap, size } =>
        {
            IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE | procmgr_labels::CREATE_PINNED)
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
        std::os::seraph::log!("driver create ipc_call failed");
        return false;
    };
    // ipc_call returned: the source cap was transferred to procmgr regardless of
    // the reply label (procmgr owns its teardown on its own failure). Disarm so
    // the guard does not free the now-reused slot.
    module_guard.disarm();
    if reply.label != 0
    {
        std::os::seraph::log!("driver create failed");
        return false;
    }

    let reply_caps = reply.caps();
    if reply_caps.len() < 2
    {
        std::os::seraph::log!("driver CREATE_PROCESS reply missing caps");
        return false;
    }
    let process_handle = reply_caps[0];
    let thread_cap = reply_caps[1];
    // Tear down the child (and free its reply-cap slots) on any failure before
    // the final bootstrap round completes; disarmed on success.
    let mut child_guard = ChildGuard::new(process_handle, thread_cap, ipc_buf);

    // Derive all per-child caps for delivery via bootstrap. Each derivation
    // owns a devmgr slot that must be released on later failure paths so devmgr
    // does not leak it; the child itself is reaped by `child_guard`.
    let Ok(bar_copy) = syscall::cap_derive(bar_cap, syscall::RIGHTS_ALL)
    else
    {
        std::os::seraph::log!("driver bar cap derivation failed");
        return false;
    };
    // IRQ is optional. A device sharing an INTx line (so devmgr could not carve
    // it a private IRQ cap) is delivered a null IRQ slot; the driver then polls
    // its queue instead of waiting on interrupts.
    let irq_copy = match config.irq_cap
    {
        Some(slot) =>
        {
            let Ok(c) = syscall::cap_derive(slot, syscall::RIGHTS_ALL)
            else
            {
                std::os::seraph::log!("driver irq cap derivation failed");
                let _ = syscall::cap_delete(bar_copy);
                return false;
            };
            c
        }
        None => 0,
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
        std::os::seraph::log!("driver devmgr query cap derivation failed");
        let _ = syscall::cap_delete(bar_copy);
        let _ = syscall::cap_delete(irq_copy);
        if service_copy != 0
        {
            let _ = syscall::cap_delete(service_copy);
        }
        return false;
    };

    // Best-effort release of every derived per-child cap. Deleting a slot a
    // serve_round transfer already consumed is a no-op, so it is safe on any
    // post-derive failure arm.
    let drop_derived = || {
        let _ = syscall::cap_delete(bar_copy);
        let _ = syscall::cap_delete(irq_copy);
        if service_copy != 0
        {
            let _ = syscall::cap_delete(service_copy);
        }
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
        return false;
    }

    // Serve bootstrap round 1. With an IRQ: [bar, irq, service] (the original
    // shape virtio-blk decodes). Without: [bar, service] — a null IRQ slot
    // cannot be transferred, so it is omitted and the driver infers "no IRQ"
    // from the 2-cap round and polls instead.
    let round1_with_irq = [bar_copy, irq_copy, service_copy];
    let round1_no_irq = [bar_copy, service_copy];
    let round1_caps: &[u32] = if irq_copy != 0
    {
        &round1_with_irq
    }
    else
    {
        &round1_no_irq
    };
    // SAFETY: ipc_buf is the registered IPC buffer.
    if unsafe {
        ipc::bootstrap::serve_round(bootstrap_ep, child_badge, ipc_buf, false, round1_caps, &[])
    }
    .is_err()
    {
        std::os::seraph::log!("driver bootstrap round 1 failed");
        drop_derived();
        return false;
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
        drop_derived();
        return false;
    }

    // Child owns its full cap set: keep it alive, but release devmgr's handles.
    child_guard.disarm();
    std::os::seraph::log!("driver started");
    true
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
// too_many_arguments: each parameter is a distinct cap or endpoint handed to
// the child's bootstrap round; they have no natural grouping beyond "the spawn
// inputs", and threading them positionally keeps the four call sites readable.
#[allow(clippy::too_many_arguments)]
pub fn spawn_simple_device(
    procmgr_ep: u32,
    bootstrap_ep: u32,
    source: CreateSource,
    service_ep: u32,
    hw_cap: u32,
    irq_cap: u32,
    devmgr_query_ep: u32,
    ipc_buf: *mut u64,
) -> bool
{
    // Source-aware cleanup: on any failure before the procmgr ipc_call
    // completes (so the source cap was not transferred), the source cap is
    // deleted. For `File` the namespace walk just produced it; for `Module` a
    // retained cap is a live derivation child of init's donated pool-run source
    // and pins that run unsplittable, so it must be freed. The post-ipc_call
    // failure paths below do NOT run this cleanup — there the source cap is
    // already owned by procmgr.
    let source_cap_to_clean: u32 = match source
    {
        CreateSource::Module(m) => m,
        CreateSource::File { file_cap, .. } => file_cap,
    };
    let source_cap_present: bool = match source
    {
        CreateSource::Module(m) => m != 0,
        CreateSource::File { file_cap, .. } => file_cap != 0,
    };
    let cleanup_on_fail = |hw: u32, query: u32, srccap: u32| {
        let _ = syscall::cap_delete(hw);
        if irq_cap != 0
        {
            let _ = syscall::cap_delete(irq_cap);
        }
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
        if irq_cap != 0
        {
            let _ = syscall::cap_delete(irq_cap);
        }
        if devmgr_query_ep != 0
        {
            let _ = syscall::cap_delete(devmgr_query_ep);
        }
        return false;
    }
    let reply_caps = reply.caps();
    if reply_caps.is_empty()
    {
        // CREATE reported success but delivered no handle, so there is no badge
        // to tear the child down with. Defensive — procmgr returns two caps on
        // success.
        std::os::seraph::log!("simple-device CREATE_PROCESS reply missing caps");
        let _ = syscall::cap_delete(hw_cap);
        if irq_cap != 0
        {
            let _ = syscall::cap_delete(irq_cap);
        }
        if devmgr_query_ep != 0
        {
            let _ = syscall::cap_delete(devmgr_query_ep);
        }
        return false;
    }
    let process_handle = reply_caps[0];
    let thread_cap = reply_caps.get(1).copied().unwrap_or(0);
    // Tear down the child (and free its reply-cap slots) on any failure before
    // the final bootstrap round completes; disarmed on success. The source cap
    // is already owned by procmgr (the CREATE ipc_call transferred it), so the
    // guard never touches it.
    let mut child_guard = ChildGuard::new(process_handle, thread_cap, ipc_buf);

    // RECV-rights copy of the service endpoint for the child; devmgr keeps
    // the original to mint client SEND caps on query.
    let Ok(service_copy) = syscall::cap_derive(service_ep, syscall::RIGHTS_ALL)
    else
    {
        let _ = syscall::cap_delete(hw_cap);
        if irq_cap != 0
        {
            let _ = syscall::cap_delete(irq_cap);
        }
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
        if irq_cap != 0
        {
            let _ = syscall::cap_delete(irq_cap);
        }
        if devmgr_query_ep != 0
        {
            let _ = syscall::cap_delete(devmgr_query_ep);
        }
        return false;
    }

    // Bootstrap rounds. With no query endpoint, one terminal round
    // [service, hw_cap, irq_cap?]. With a query endpoint, two rounds: round 1
    // non-terminal [service, hw_cap, irq_cap?], round 2 terminal [query_ep].
    // irq_cap rides round 1 only when present (the serial driver); other
    // simple devices pass 0 and the round carries the bare [service, hw_cap].
    let round1_done = devmgr_query_ep == 0;
    let round1_caps: [u32; 3] = [service_copy, hw_cap, irq_cap];
    let round1_len = if irq_cap != 0 { 3 } else { 2 };
    // SAFETY: ipc_buf is the registered IPC buffer.
    if unsafe {
        ipc::bootstrap::serve_round(
            bootstrap_ep,
            child_badge,
            ipc_buf,
            round1_done,
            &round1_caps[..round1_len],
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
        if irq_cap != 0
        {
            let _ = syscall::cap_delete(irq_cap);
        }
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

    // Child owns its full cap set: keep it alive, but release devmgr's handles.
    child_guard.disarm();
    std::os::seraph::log!("simple-device driver started");
    true
}
