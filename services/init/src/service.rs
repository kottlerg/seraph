// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/init/src/service.rs

//! Service creation helpers for init.
//!
//! Creates suspended child processes via procmgr IPC (`CREATE_PROCESS` /
//! `CREATE_FROM_FILE`), installs init's seed namespace cap on each child
//! via `CONFIGURE_NAMESPACE`, starts them, then serves their bootstrap
//! requests on init's bootstrap endpoint to deliver their per-service
//! capability set.

use crate::idle_loop;
use crate::logging::log;
use crate::walk;
use init_protocol::{CapType, InitInfo};
use ipc::{IpcMessage, procmgr_labels, svcmgr_labels};

/// Thread caps init collects across Phases 1-3 to hand svcmgr in the
/// handover endowment (one `SUBSTRATE` round each). Zero in a slot means
/// init could not capture (or chose not to capture) that service's thread
/// cap; the corresponding endowment round is then skipped.
///
/// Field order matches reconciliation order in the boot log, not
/// spawn order. memmgr / procmgr come from
/// [`crate::bootstrap::MemmgrBootstrap::mm_thread`] /
/// [`crate::bootstrap::ProcmgrBootstrap::pm_thread`]; the rest come
/// from the matching spawn-helper return values.
#[derive(Default, Clone, Copy)]
pub struct ServiceThreadCaps
{
    pub memmgr: u32,
    pub procmgr: u32,
    pub devmgr: u32,
    pub vfsd: u32,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn derive_badged_creator(bootstrap_ep: u32) -> Option<(u32, u64)>
{
    let badge = crate::bootstrap::mint_bootstrap_badge()?;
    let badged = syscall::cap_derive_badge(bootstrap_ep, syscall::RIGHTS_EP_SEND, badge).ok()?;
    Some((badged, badge))
}

/// Issue `procmgr_labels::CONFIGURE_NAMESPACE` on a freshly-created
/// (suspended) child, handing it a universal `cap_copy` of
/// `system_root_cap` at full rights plus the optional `cwd`.
///
/// `cwd`, when `Some`, walks `(path, rights)` from `system_root_cap`
/// and delivers the resulting directory cap as `caps[1]` so the
/// child's `current_dir_cap` is non-zero from the first instruction.
///
/// Per-service subtree attenuation lives in svcmgr (parsed from each
/// `/config/svcmgr/services/<name>.svc`'s `namespace =` line); init
/// hands its sole namespace consumer — svcmgr — the universal root.
///
/// On any failure the partial child is destroyed (`DESTROY_PROCESS`
/// on `process_handle`, then `cap_delete`) so a false return tells
/// callers the handle is no longer usable. Callers holding additional
/// caps from the same CREATE reply (e.g. a separate thread cap)
/// remain responsible for releasing those.
fn configure_child_namespace(
    process_handle: u32,
    system_root_cap: u32,
    init_self_cspace: u32,
    cwd: Option<(&[u8], u64)>,
    ipc_buf: *mut u64,
) -> bool
{
    let Ok(ns_cap) = syscall::cap_copy(system_root_cap, init_self_cspace, syscall::RIGHTS_EP_SEND)
    else
    {
        log("phase 3: cap_copy of system root for child failed");
        destroy_partial_child(process_handle, ipc_buf);
        return false;
    };

    let cwd_cap = if let Some((path, rights)) = cwd
    {
        // SAFETY: `ipc_buf` is init's main-thread IPC buffer (`INIT_IPC_BUF_VA`,
        // registered in `run`), passed down unchanged.
        let Some(c) = (unsafe { walk::walk_to_dir(system_root_cap, path, rights, ipc_buf) })
        else
        {
            log("phase 3: cwd walk for child failed");
            let _ = syscall::cap_delete(ns_cap);
            destroy_partial_child(process_handle, ipc_buf);
            return false;
        };
        c
    }
    else
    {
        0
    };

    let mut builder = IpcMessage::builder(procmgr_labels::CONFIGURE_NAMESPACE).cap(ns_cap);
    if cwd_cap != 0
    {
        builder = builder.cap(cwd_cap);
    }
    let ns_msg = builder.build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(process_handle, &ns_msg, ipc_buf) };
    // The kernel transferred the caps on the IPC; release init's
    // source slots unconditionally.
    let _ = syscall::cap_delete(ns_cap);
    if cwd_cap != 0
    {
        let _ = syscall::cap_delete(cwd_cap);
    }
    match reply
    {
        Ok(r) if r.label == 0 => true,
        _ =>
        {
            log("phase 3: CONFIGURE_NAMESPACE failed");
            destroy_partial_child(process_handle, ipc_buf);
            false
        }
    }
}

/// Tear down a partially-created child: send `DESTROY_PROCESS` over its
/// badged handle and release init's procmgr-side slot. Used by every
/// helper that reaches a failure between procmgr's CREATE and START.
fn destroy_partial_child(process_handle: u32, ipc_buf: *mut u64)
{
    let destroy_msg = IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_buf) };
    let _ = syscall::cap_delete(process_handle);
}

/// Start a process by calling `START_PROCESS` on its badged process handle.
fn start_process(process_handle: u32, ipc_buf: *mut u64, ok_msg: &str, fail_msg: &str) -> bool
{
    let msg = IpcMessage::new(procmgr_labels::START_PROCESS);
    // SAFETY: ipc_buf is caller's registered IPC buffer.
    match unsafe { ipc::ipc_call(process_handle, &msg, ipc_buf) }
    {
        Ok(reply) if reply.label == 0 =>
        {
            log(ok_msg);
            true
        }
        _ =>
        {
            log(fail_msg);
            false
        }
    }
}

/// Serve one bootstrap round from init to the named child. Logs `context`
/// and returns `false` on failure; [`serve_checked`] keeps the error code.
fn serve(
    bootstrap_ep: u32,
    badge: u64,
    ipc_buf: *mut u64,
    done: bool,
    caps: &[u32],
    data: &[u64],
    context: &str,
) -> bool
{
    serve_checked(bootstrap_ep, badge, ipc_buf, done, caps, data, context).is_ok()
}

/// [`serve`], returning the `ipc::bootstrap::serve_round` error code
/// (`bootstrap_errors::NO_CHILD` when another child's request was received
/// and refused, so the named child's request is still pending;
/// `bootstrap_errors::INVALID` otherwise, including a failed reply that has
/// already woken the child with an error).
fn serve_checked(
    bootstrap_ep: u32,
    badge: u64,
    ipc_buf: *mut u64,
    done: bool,
    caps: &[u32],
    data: &[u64],
    context: &str,
) -> Result<(), u64>
{
    // SAFETY: ipc_buf is caller's registered IPC buffer.
    unsafe { ipc::bootstrap::serve_round(bootstrap_ep, badge, ipc_buf, done, caps, data) }
        .inspect_err(|_| log(context))
}

// ── Hardware cap partitioning for devmgr ────────────────────────────────────

/// Maximum number of MMIO apertures init forwards to devmgr in one go.
/// Kernel's `MmioApertureSlice` is sized at `MAX_APERTURES = 16` today; 32
/// is a comfortable upper bound.
const MAX_APERTURE_CAPS: usize = 32;

/// Maximum number of ACPI reclaimable-region Memory caps. Matches the
/// kernel's `MAX_ACPI_REGIONS`; 8 is generous.
const MAX_ACPI_REGION_CAPS: usize = 8;

/// Collected hardware caps: init forwards raw firmware + MMIO surfaces
/// to devmgr. Parsing (MCFG / DTB → ECAM, FADT → `PM1a`) lives in devmgr.
struct HwCaps
{
    /// Root `Interrupt` range cap. Zero if the kernel did not mint one.
    irq_range_slot: u32,
    /// RO Memory cap covering the ACPI RSDP page. Zero if none.
    rsdp_slot: u32,
    rsdp_page_base: u64,
    /// RO Memory cap covering the DTB blob. Zero if none.
    dtb_slot: u32,
    dtb_page_base: u64,
    dtb_size: u64,
    /// All MMIO aperture caps (slot, base, size).
    apertures: [(u32, u64, u64); MAX_APERTURE_CAPS],
    aperture_count: usize,
    /// ACPI reclaimable-region Memory caps (slot, base, size).
    acpi_regions: [(u32, u64, u64); MAX_ACPI_REGION_CAPS],
    acpi_region_count: usize,
}

impl HwCaps
{
    const fn new() -> Self
    {
        Self {
            irq_range_slot: 0,
            rsdp_slot: 0,
            rsdp_page_base: 0,
            dtb_slot: 0,
            dtb_page_base: 0,
            dtb_size: 0,
            apertures: [(0, 0, 0); MAX_APERTURE_CAPS],
            aperture_count: 0,
            acpi_regions: [(0, 0, 0); MAX_ACPI_REGION_CAPS],
            acpi_region_count: 0,
        }
    }
}

fn collect_hw_caps(info: &InitInfo) -> HwCaps
{
    let mut hw = HwCaps::new();

    // Named slots from InitInfo (protocol v5).
    hw.irq_range_slot = info.irq_range_cap;
    hw.rsdp_slot = info.acpi_rsdp_memory_cap;
    hw.dtb_slot = info.dtb_memory_cap;

    // Walk the descriptor array once to capture aperture + ACPI-region
    // metadata. RSDP / DTB base + size come from their descriptors too.
    for d in crate::descriptors(info)
    {
        match d.cap_type
        {
            CapType::Mmio if hw.aperture_count < MAX_APERTURE_CAPS =>
            {
                hw.apertures[hw.aperture_count] = (d.slot, d.aux0, d.aux1);
                hw.aperture_count += 1;
            }
            CapType::Memory if d.slot == hw.rsdp_slot && hw.rsdp_slot != 0 =>
            {
                hw.rsdp_page_base = d.aux0;
            }
            CapType::Memory if d.slot == hw.dtb_slot && hw.dtb_slot != 0 =>
            {
                hw.dtb_page_base = d.aux0;
                hw.dtb_size = d.aux1;
            }
            _ =>
            {}
        }
    }

    // ACPI region caps occupy a contiguous slot range starting at
    // `acpi_region_memory_base`. Walk the descriptor array a second time
    // to pick them out by slot range; their aux0/aux1 carry (base, size).
    let ar_start = info.acpi_region_memory_base;
    let ar_end = ar_start + info.acpi_region_memory_count;
    if info.acpi_region_memory_count != 0
    {
        for d in crate::descriptors(info)
        {
            if d.cap_type == CapType::Memory
                && d.slot >= ar_start
                && d.slot < ar_end
                && hw.acpi_region_count < MAX_ACPI_REGION_CAPS
            {
                hw.acpi_regions[hw.acpi_region_count] = (d.slot, d.aux0, d.aux1);
                hw.acpi_region_count += 1;
            }
        }
    }

    hw
}

// ── devmgr creation ──────────────────────────────────────────────────────────

/// Round-kind discriminator for post-R1 bootstrap rounds (devmgr side).
/// Matches `devmgr/src/caps.rs::BootstrapKind`.
mod kind
{
    pub const MODULE: u64 = 1;
    pub const APERTURE: u64 = 2;
    pub const ACPI_REGION: u64 = 3;
    pub const SVCMGR_BUNDLE: u64 = 4;
    pub const FRAMEBUFFER_INFO: u64 = 5;
}

/// Per-cap class tag carried in a `kind::MODULE` round's data words so
/// devmgr resolves a driver module by class rather than delivery position.
/// Mirrors `devmgr/src/caps.rs::module_kind`.
///
/// Only bootstrap-essential drivers ship as bundle modules. The per-arch
/// RTC binary lives on the rootfs disk and is loaded lazily by devmgr
/// after init delivers a `/services/drivers/` subtree cap via
/// `devmgr_labels::SET_DRIVERS_DIR`; no RTC `module_kind` is delivered.
mod module_kind
{
    pub const VIRTIO_BLK: u64 = 1;
    pub const SERIAL: u64 = 2;
    pub const FRAMEBUFFER: u64 = 3;
}

/// Presence-bitmap bits on R1's `data[0]`. Tells devmgr which optional
/// caps (in order after `registry_ep`) are present in the cap list.
mod present
{
    pub const IRQ_RANGE: u64 = 1 << 0;
    pub const RSDP: u64 = 1 << 1;
    pub const DTB: u64 = 1 << 2;
}

/// Serve devmgr the `round_kind` rounds (`kind::APERTURE` or `kind::ACPI_REGION`) for
/// `regions`, four `(slot, base, size)` entries per round. A region whose cap
/// derive fails is left out of its round (cap and `(base, size)` pair alike):
/// the kernel refuses a reply carrying a Null cap slot, so a zero handle would
/// fail the whole round. Returns `false`, after logging `context`, when a
/// round fails.
fn serve_region_rounds(
    bootstrap_ep: u32,
    child_badge: u64,
    ipc_buf: *mut u64,
    round_kind: u64,
    regions: &[(u32, u64, u64)],
    context: &str,
) -> bool
{
    for batch in regions.chunks(4)
    {
        let mut caps = [0u32; 4];
        let mut data = [0u64; 2 + 4 * 2];
        let mut n = 0usize;
        for &(slot, base, size) in batch
        {
            let Ok(c) = syscall::cap_derive(slot, syscall::RIGHTS_ALL)
            else
            {
                log("devmgr: region cap derive failed; region skipped");
                continue;
            };
            caps[n] = c;
            data[2 + n * 2] = base;
            data[3 + n * 2] = size;
            n += 1;
        }
        data[0] = round_kind;
        data[1] = n as u64;
        if !serve(
            bootstrap_ep,
            child_badge,
            ipc_buf,
            false,
            &caps[..n],
            &data[..2 + n * 2],
            context,
        )
        {
            return false;
        }
    }
    true
}

/// Create devmgr via procmgr and serve its bootstrap (raw firmware caps).
///
/// The bootstrap protocol is:
///
/// * Round 1 (fixed, 4 caps, 3 data words)
///   - caps: `[registry_ep, irq_range, rsdp_memory, dtb_memory]`
///     (zero-slots pass through where the kernel minted none)
///   - data: `[rsdp_page_base, dtb_page_base, dtb_size]`
/// * Round 2+ (variable, ≤4 caps, up to 9 data words)
///   - `data[0]` = round kind (`APERTURE` / `ACPI_REGION` / `MODULE`)
///   - `data[1]` = count of caps in this round
///   - `data[2..]` = kind-specific payload:
///       - aperture / ACPI: `(base, size)` pairs per cap
///       - module: none
///   - terminal round has `done = true`.
///
/// The bootstrap layout mirrors `devmgr/src/caps.rs::bootstrap_caps`.
// too_many_lines: devmgr's spawn and bootstrap round are one ordered sequence
// whose cap derivations each later step consumes; splitting it would only
// thread those slots through helpers.
#[allow(clippy::too_many_lines)]
pub fn create_devmgr_with_caps(
    info: &InitInfo,
    procmgr_ep: u32,
    bootstrap_ep: u32,
    registry_ep: u32,
    svcmgr_service_ep: u32,
    ipc_buf: *mut u64,
) -> Option<u32>
{
    let devmgr_memory_cap = crate::find_module_by_name(info, b"devmgr")?;
    let devmgr_module_copy = module_spawn_copy(devmgr_memory_cap)?;

    let (badged_creator, child_badge) = derive_badged_creator(bootstrap_ep)?;

    // caps: [module, creator]. No stdio pipes — devmgr reaches the
    // system log via the discovery cap procmgr installs in ProcessInfo.
    // Band ceiling deliberately above devmgr's own level so it can place
    // the drivers it spawns at the boot/aux driver levels.
    let create_msg = IpcMessage::builder(
        procmgr_labels::CREATE_PROCESS
            | procmgr_labels::create_sched_bits(
                ipc::sched_policy::DEVMGR_PRIORITY,
                ipc::sched_policy::DEVMGR_BAND_MAX,
            ),
    )
    .cap(devmgr_module_copy)
    .cap(badged_creator)
    .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_ep, &create_msg, ipc_buf) })
    else
    {
        log("devmgr: CREATE_PROCESS ipc_call failed");
        return None;
    };
    if reply.label != 0
    {
        log("devmgr: CREATE_PROCESS failed");
        return None;
    }

    let reply_caps = reply.caps();
    if reply_caps.len() < 2
    {
        log("devmgr: CREATE_PROCESS reply missing caps");
        return None;
    }
    let process_handle = reply_caps[0];
    let thread_cap = reply_caps[1];

    let hw = collect_hw_caps(info);

    // log + procmgr are auto-delivered via ProcessInfo; only the devmgr-
    // specific caps traverse this bootstrap protocol.
    let _ = procmgr_ep;
    let Ok(registry_copy) = syscall::cap_derive(registry_ep, syscall::RIGHTS_ALL)
    else
    {
        log("devmgr: registry cap derive failed");
        return None;
    };

    // Derive sendable copies of the firmware-authority caps. Zero slots
    // stay zero (devmgr handles the absence).
    let irq_copy = if hw.irq_range_slot != 0
    {
        syscall::cap_derive(hw.irq_range_slot, syscall::RIGHTS_ALL).unwrap_or(0)
    }
    else
    {
        0
    };
    let rsdp_copy = if hw.rsdp_slot != 0
    {
        syscall::cap_derive(hw.rsdp_slot, syscall::RIGHTS_ALL).unwrap_or(0)
    }
    else
    {
        0
    };
    let dtb_copy = if hw.dtb_slot != 0
    {
        syscall::cap_derive(hw.dtb_slot, syscall::RIGHTS_ALL).unwrap_or(0)
    }
    else
    {
        0
    };

    // No stdio caps wired: devmgr reaches the system log via the
    // discovery cap procmgr installs in `ProcessInfo`.

    // START_PROCESS.
    if !start_process(
        process_handle,
        ipc_buf,
        "devmgr started; serving bootstrap",
        "devmgr: START_PROCESS failed",
    )
    {
        return None;
    }

    // Round 1: [registry, ...present(irq,rsdp,dtb)].
    // data[0] = presence bitmap; data[1]=rsdp_base, data[2]=dtb_base,
    // data[3]=dtb_size (always written; bitmap indicates validity).
    let mut r1_caps = [0u32; 4];
    let mut r1_cap_count: usize = 1;
    r1_caps[0] = registry_copy;
    let mut presence: u64 = 0;
    if irq_copy != 0
    {
        presence |= present::IRQ_RANGE;
        r1_caps[r1_cap_count] = irq_copy;
        r1_cap_count += 1;
    }
    if rsdp_copy != 0
    {
        presence |= present::RSDP;
        r1_caps[r1_cap_count] = rsdp_copy;
        r1_cap_count += 1;
    }
    if dtb_copy != 0
    {
        presence |= present::DTB;
        r1_caps[r1_cap_count] = dtb_copy;
        r1_cap_count += 1;
    }
    if !serve(
        bootstrap_ep,
        child_badge,
        ipc_buf,
        false,
        &r1_caps[..r1_cap_count],
        &[presence, hw.rsdp_page_base, hw.dtb_page_base, hw.dtb_size],
        "devmgr: bootstrap round 1 failed",
    )
    {
        return None;
    }

    // SVCMGR_BUNDLE is unconditionally the terminal round; every prior
    // round therefore sets `done=false` regardless of what follows.
    let virtio_blk_module = crate::find_module_by_name(info, b"virtio-blk");

    // ── Aperture and ACPI region rounds ─────────────────────────────────
    if !serve_region_rounds(
        bootstrap_ep,
        child_badge,
        ipc_buf,
        kind::APERTURE,
        &hw.apertures[..hw.aperture_count],
        "devmgr: bootstrap aperture round failed",
    ) || !serve_region_rounds(
        bootstrap_ep,
        child_badge,
        ipc_buf,
        kind::ACPI_REGION,
        &hw.acpi_regions[..hw.acpi_region_count],
        "devmgr: bootstrap ACPI region round failed",
    )
    {
        return None;
    }

    // ── Module round (driver binaries devmgr spawns) ────────────────────
    //
    // Each delivered cap is tagged with its `module_kind` in the data
    // words so devmgr binds a module by class, not by delivery position.
    // Only bootstrap-essential drivers are delivered; the per-arch RTC
    // lives on the rootfs and is loaded by devmgr lazily after the
    // `SET_DRIVERS_DIR` handshake (Phase 3, below).
    let serial_module = crate::find_module_by_name(info, b"serial");
    let framebuffer_module = crate::find_module_by_name(info, b"framebuffer");
    {
        let mut module_caps = [0u32; 3];
        let mut module_data = [0u64; 2 + 3];
        module_data[0] = kind::MODULE;
        let mut n = 0usize;

        for (source, tag) in [
            (virtio_blk_module, module_kind::VIRTIO_BLK),
            (serial_module, module_kind::SERIAL),
            (framebuffer_module, module_kind::FRAMEBUFFER),
        ]
        {
            let Some(module_cap) = source
            else
            {
                continue;
            };
            // A failed derive skips the module, as `serve_region_rounds` skips
            // a region: returning here would leave devmgr blocked in
            // `request_round` without the terminal round.
            let Ok(module_copy) = syscall::cap_derive(module_cap, syscall::RIGHTS_ALL)
            else
            {
                log("devmgr: driver module cap derive failed; module skipped");
                continue;
            };
            module_caps[n] = module_copy;
            module_data[2 + n] = tag;
            n += 1;
        }

        if n > 0
        {
            module_data[1] = n as u64;
            if !serve(
                bootstrap_ep,
                child_badge,
                ipc_buf,
                false,
                &module_caps[..n],
                &module_data[..2 + n],
                "devmgr: bootstrap module round failed",
            )
            {
                return None;
            }
        }
    }

    // ── Framebuffer-info round ──────────────────────────────────────────
    //
    // Always emitted; `physical_base == 0` tells devmgr to skip the
    // framebuffer driver spawn (headless boot, e.g. QEMU with
    // `-display none`). The geometry's authoritative source is GOP,
    // which dies at `ExitBootServices`; the bootloader captured it into
    // `BootInfo.framebuffer` and the kernel forwarded it through
    // `InitInfo.framebuffer`.
    {
        let fb = info.framebuffer;
        let wh = u64::from(fb.width) | (u64::from(fb.height) << 32);
        let pf_disc = fb.pixel_format as u32;
        let sf = u64::from(fb.stride) | (u64::from(pf_disc) << 32);
        if !serve(
            bootstrap_ep,
            child_badge,
            ipc_buf,
            false,
            &[],
            &[kind::FRAMEBUFFER_INFO, fb.physical_base, wh, sf],
            "devmgr: bootstrap framebuffer-info round failed",
        )
        {
            return None;
        }
    }

    // ── Terminal SVCMGR_BUNDLE round ────────────────────────────────────
    //
    // caps: [svcmgr_publish_cap, arch_shutdown_cap]. The SEND-rights cap
    // on svcmgr's service endpoint is stamped with the PUBLISH_AUTHORITY
    // verb-bit in its badge so devmgr can register service caps in
    // svcmgr's registry (reserved for future devmgr publications; svcmgr
    // publishes the active well-known names itself, per
    // `services/init/docs/bootstrap.md` § Per-stage authority transfers).
    // The arch shutdown-authority cap is a full-rights derivation of the
    // root `IoPort` on x86-64 (devmgr derives narrow per-driver IoPort caps
    // from it for ISA peripherals like the CMOS RTC, and carves the PM1a +
    // 8042 ports for pwrmgr) and an `SbiControl` derivation narrowed to
    // Reset and Suspend on RISC-V (devmgr serves a Reset-only derivation to
    // pwrmgr for SBI SRST). devmgr is the hardware authority; pwrmgr
    // acquires its shutdown caps from devmgr, not from init.
    // SVCMGR_BUNDLE is unconditionally the terminal round. On any
    // preparation failure init MUST still emit a `done=true` round so
    // devmgr's bootstrap_rounds loop in `services/devmgr/src/caps.rs`
    // unblocks; otherwise devmgr spins in `request_round` forever.
    // Empty-caps terminal round signals "no bundle delivered"; devmgr's
    // SVCMGR_BUNDLE absorber rejects a zero-cap message and returns
    // None, which propagates to a clean failure rather than a hang.
    let prep_failed = svcmgr_service_ep == 0;
    let svcmgr_publish = if prep_failed
    {
        0
    }
    else
    {
        // RIGHTS_EP_SEND_GRANT (not bare SEND): PUBLISH_ENDPOINT carries the
        // service's SEND cap in the message, and the IPC kernel requires the
        // GRANT bit on the caller's send-cap to transfer caps.
        syscall::cap_derive_badge(
            svcmgr_service_ep,
            syscall::RIGHTS_EP_SEND_GRANT,
            ipc::svcmgr_labels::PUBLISH_AUTHORITY,
        )
        .unwrap_or(0)
    };
    if prep_failed
    {
        log("devmgr: SVCMGR_BUNDLE prep skipped — no svcmgr service endpoint");
    }
    else if svcmgr_publish == 0
    {
        log("devmgr: PUBLISH_AUTHORITY cap derive failed");
    }
    if svcmgr_publish == 0
    {
        // Emit a terminal SVCMGR_BUNDLE with zero caps; devmgr will
        // notice cap_count == 0 in its absorber and refuse to bootstrap,
        // but it WILL exit the round-receive loop.
        let _ = serve(
            bootstrap_ep,
            child_badge,
            ipc_buf,
            true,
            &[],
            &[kind::SVCMGR_BUNDLE, 0],
            "devmgr: empty SVCMGR_BUNDLE failsafe round failed",
        );
        return None;
    }

    let arch_shutdown_cap = if cfg!(target_arch = "x86_64")
    {
        crate::find_cap_by_type(info, init_protocol::CapType::IoPort)
            .and_then(|root| syscall::cap_derive(root, syscall::RIGHTS_ALL).ok())
            .unwrap_or(0)
    }
    else if info.sbi_control_cap != 0
    {
        // RISC-V: devmgr is the steady-state holder of the platform firmware
        // authority (init is reaped, so its root cap becomes unreachable).
        // Transfer only the power-state extensions — system reset (served to
        // pwrmgr on QUERY_SHUTDOWN_DEVICE, narrowed to Reset there) and suspend
        // (reserved for a future path). The other sanctioned SBI rights are
        // carried into no surviving cap: the root cap stays in init's CSpace
        // and is released when the reap frees it (`docs/process-lifecycle.md`
        // § Init reap).
        syscall::cap_derive(
            info.sbi_control_cap,
            syscall::RIGHTS_SBI_RESET | syscall::RIGHTS_SBI_SUSPEND,
        )
        .unwrap_or(0)
    }
    else
    {
        0
    };

    let bundle_caps: [u32; 2] = [svcmgr_publish, arch_shutdown_cap];
    let bundle_cap_count = if arch_shutdown_cap != 0 { 2 } else { 1 };

    let _ = serve(
        bootstrap_ep,
        child_badge,
        ipc_buf,
        true,
        &bundle_caps[..bundle_cap_count],
        &[kind::SVCMGR_BUNDLE, bundle_cap_count as u64],
        "devmgr: bootstrap SVCMGR_BUNDLE round failed",
    );
    Some(thread_cap)
}

// ── vfsd creation ────────────────────────────────────────────────────────────

/// Endpoint set passed to vfsd via its bootstrap round.
pub struct VfsdSpawnCaps
{
    pub registry_ep: u32,
    pub vfsd_service_ep: u32,
}

/// Create vfsd via procmgr and serve its bootstrap.
pub fn create_vfsd_with_caps(
    info: &InitInfo,
    procmgr_ep: u32,
    bootstrap_ep: u32,
    spawn: &VfsdSpawnCaps,
    ipc_buf: *mut u64,
) -> Option<u32>
{
    let vfsd_memory_cap = crate::find_module_by_name(info, b"vfsd")?;
    let vfsd_module_copy = module_spawn_copy(vfsd_memory_cap)?;

    let (badged_creator, child_badge) = derive_badged_creator(bootstrap_ep)?;

    let create_msg = IpcMessage::builder(
        procmgr_labels::CREATE_PROCESS
            | procmgr_labels::create_sched_bits(
                ipc::sched_policy::VFSD_PRIORITY,
                ipc::sched_policy::VFSD_PRIORITY,
            ),
    )
    .cap(vfsd_module_copy)
    .cap(badged_creator)
    .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_ep, &create_msg, ipc_buf) })
    else
    {
        log("vfsd: CREATE_PROCESS ipc_call failed");
        return None;
    };
    if reply.label != 0
    {
        log("vfsd: CREATE_PROCESS failed");
        return None;
    }

    let reply_caps = reply.caps();
    if reply_caps.len() < 2
    {
        log("vfsd: CREATE_PROCESS reply missing caps");
        return None;
    }
    let process_handle = reply_caps[0];
    let thread_cap = reply_caps[1];

    let Ok(service_copy) = syscall::cap_derive(spawn.vfsd_service_ep, syscall::RIGHTS_ALL)
    else
    {
        return None;
    };
    // vfsd is the sole devmgr `QUERY_BLOCK_DEVICE` consumer, and this is
    // the only registry cap carrying `BLOCK_DEVICE_AUTHORITY`, the bit
    // devmgr's gate on that label requires: the reply is whole-disk
    // authority, which no svcmgr-published registry cap may obtain.
    // `REGISTRY_QUERY_AUTHORITY` rides beside it, as on every consumer query
    // cap.
    let Ok(registry_copy) = syscall::cap_derive_badge(
        spawn.registry_ep,
        syscall::RIGHTS_EP_SEND,
        ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY | ipc::devmgr_labels::BLOCK_DEVICE_AUTHORITY,
    )
    else
    {
        return None;
    };

    if !start_process(
        process_handle,
        ipc_buf,
        "vfsd started; serving bootstrap",
        "vfsd: START_PROCESS failed",
    )
    {
        return None;
    }

    // Round 1: [service, registry]
    // (log + procmgr auto-delivered via ProcessInfo.)
    if !serve(
        bootstrap_ep,
        child_badge,
        ipc_buf,
        false,
        &[service_copy, registry_copy],
        &[],
        "vfsd: bootstrap round 1 failed",
    )
    {
        return None;
    }

    // Round 2: fatfs module. An absent or underived module rides as an empty
    // cap list, not a zero handle, which the kernel would refuse along with
    // the whole round; vfsd then rejects the round (it needs the module to
    // mount root) instead of failing on a reply error.
    let fatfs_cap = match crate::find_module_by_name(info, b"fatfs")
    {
        Some(slot) => syscall::cap_derive(slot, syscall::RIGHTS_ALL).unwrap_or(0),
        None => 0,
    };
    let fatfs_slot = [fatfs_cap];
    let fatfs_caps = if fatfs_cap == 0
    {
        &fatfs_slot[..0]
    }
    else
    {
        &fatfs_slot[..]
    };

    let _ = serve(
        bootstrap_ep,
        child_badge,
        ipc_buf,
        true,
        fatfs_caps,
        &[],
        "vfsd: bootstrap round 2 failed",
    );

    Some(thread_cap)
}

// ── svcmgr / procmgr coordination ───────────────────────────────────────────

/// Create svcmgr from `/services/svcmgr` via `CREATE_FROM_FILE` and install
/// init's seed system-root cap on the child via `CONFIGURE_NAMESPACE`.
///
/// Returns `(process_handle, child_badge)` on success.
pub fn create_svcmgr_from_file(
    procmgr_ep: u32,
    bootstrap_ep: u32,
    system_root_cap: u32,
    init_self_cspace: u32,
    ipc_buf: *mut u64,
) -> Option<(u32, u64)>
{
    // SAFETY: `ipc_buf` is init's main-thread IPC buffer (`INIT_IPC_BUF_VA`,
    // registered in `run`), passed down unchanged.
    let walked =
        unsafe { walk::walk_to_file(system_root_cap, b"/services/svcmgr", 0xFFFF, ipc_buf) }?;

    let (badged_creator, child_badge) = derive_badged_creator(bootstrap_ep)?;

    let msg = IpcMessage::builder(
        procmgr_labels::CREATE_FROM_FILE
            | procmgr_labels::create_sched_bits(
                ipc::sched_policy::SVCMGR_PRIORITY,
                ipc::sched_policy::SVCMGR_PRIORITY,
            ),
    )
    .word(0, walked.size)
    .cap(walked.file_cap)
    .cap(badged_creator)
    .build();

    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_ep, &msg, ipc_buf) })
    else
    {
        log("phase 3: svcmgr CREATE_FROM_FILE ipc_call failed");
        return None;
    };
    if reply.label != 0
    {
        log("phase 3: svcmgr CREATE_FROM_FILE failed");
        return None;
    }

    let reply_caps = reply.caps();
    if reply_caps.is_empty()
    {
        log("phase 3: svcmgr reply missing caps");
        return None;
    }
    let process_handle = reply_caps[0];
    // CREATE_FROM_FILE returns (process_handle, thread_cap); this caller
    // path has no use for the thread cap. Release the slot so it does
    // not accumulate in init's CSpace.
    if reply_caps.len() >= 2
    {
        let _ = syscall::cap_delete(reply_caps[1]);
    }

    // svcmgr is the supervisor and holds the universal root: it
    // reads `/config/svcmgr/services/*.svc` at handover,
    // walks the recipe's `binary` path (typically
    // `/services/<name>` or `/programs/<name>`) for first-launch of
    // defined-but-unregistered services, and applies per-service
    // namespace attenuation from each `.svc` recipe when configuring
    // the child. svcmgr therefore holds the universal root.
    if !configure_child_namespace(
        process_handle,
        system_root_cap,
        init_self_cspace,
        None,
        ipc_buf,
    )
    {
        return None;
    }

    Some((process_handle, child_badge))
}

/// Source + endpoint caps init endows svcmgr with at handover. svcmgr
/// derives the shapes it publishes / sends / launches with from these
/// reserved sources; it keeps the log-sink sources for the system's life
/// so it can (re)launch real-logd any number of times.
pub struct SvcmgrEndowment
{
    pub svcmgr_service_ep: u32,
    pub svcmgr_bootstrap_ep: u32,
    /// Seed system-root cap (`GET_SYSTEM_ROOT_CAP` from vfsd). svcmgr
    /// derives the published `rootfs.root` SEND from it.
    pub rootfs_root_cap: u32,
    pub devmgr_registry_ep: u32,
    /// vfsd's un-badged service endpoint. init mints the endowed
    /// `MOUNT_AUTHORITY` SEND (published as `vfsd.mount`) and the
    /// `DENY_BADGE` SEND (published as `vfsd.deny`) from it.
    pub vfsd_service_ep: u32,
    /// Reserved master-log endpoint source (`cap_derive(log_ep, RIGHTS_ALL)`).
    /// svcmgr mints real-logd's master-log RECV from it on every (re)launch,
    /// plus the one-shot `HANDOVER_PULL` SEND on the first launch. Holding it
    /// keeps the endpoint object alive across a logd crash so log senders are
    /// agnostic to which process holds the RECV.
    pub master_log_source: u32,
    /// Reserved badge-0 `SEND|GRANT` source on procmgr's service endpoint.
    /// svcmgr mints real-logd's `DEATH_EQ_AUTHORITY` `SEND|GRANT` cap from it per launch
    /// (used by logd to register sender death-notifications for slot reclaim).
    pub procmgr_death_auth_source: u32,
}

/// Start svcmgr, then serve the handover endowment over the bootstrap
/// protocol.
///
/// The `CAPS` rounds (two rounds for the six slots) deliver
/// svcmgr's service + bootstrap endpoints (full
/// rights) and the publish-role source caps: a `SEND` on the root
/// filesystem namespace endpoint (svcmgr publishes it as `rootfs.root`) and
/// a badge-0 `SEND|GRANT` source on devmgr's registry endpoint (svcmgr mints
/// the `devmgr.registry` / `devmgr.shutdown` / `devmgr.test` publish caps and
/// the `DRIVERS_DIR_AUTHORITY` `SET_DRIVERS_DIR` cap from it), plus two SENDs on
/// vfsd's service endpoint svcmgr publishes seed-only: `MOUNT_AUTHORITY`-badged
/// (`vfsd.mount`) and `DENY_BADGE`-badged (`vfsd.deny`). An absent source
/// cap is left off its round and its presence bit clear (the
/// `svcmgr_endowment` encoding), since the kernel refuses a null cap slot.
///
/// Each `SUBSTRATE` round then delivers one init-bootstrapped service's
/// thread cap plus its name (memmgr/procmgr/devmgr/vfsd); svcmgr parks the
/// pairs for death-supervision binding at reconciliation.
///
/// The terminal `LOGD_SOURCES` round delivers the two reserved caps svcmgr
/// keeps to launch + supervise + restart real-logd: the master-log endpoint
/// source and a badge-0 procmgr `SEND|GRANT` source (see [`SvcmgrEndowment`]).
///
/// Best-effort. The endpoint copies are derived before svcmgr starts; a
/// failed derive or `START_PROCESS` destroys the unstarted svcmgr. A round
/// that fails with svcmgr's request still pending (`NO_CHILD`: another
/// child's request was refused) ends the rounds before it: after a failed
/// `CAPS` round an empty terminal round ([`end_endowment`]) lets svcmgr
/// leave its round loop and exit; after a failed `SUBSTRATE` round the real
/// terminal `LOGD_SOURCES` round follows, and svcmgr runs without the
/// remaining substrates. A `NO_CHILD` failure of the terminal round itself
/// leaves svcmgr blocked in its round loop with nothing more from init, and
/// init skips the handover. Any other failure has already woken svcmgr with
/// an error (it exits) or left its state unknown, so init receives nothing
/// further.
///
/// Returns whether svcmgr holds its endowment through a delivered terminal
/// round, so it is serving its service endpoint: only then can it receive
/// `HANDOVER_COMPLETE`, and phase 3 sends that only on `true`.
fn endow_svcmgr(
    bootstrap_ep: u32,
    process_handle: u32,
    child_badge: u64,
    endow: &SvcmgrEndowment,
    thread_caps: ServiceThreadCaps,
    ipc_buf: *mut u64,
) -> bool
{
    let Ok(service_copy) = syscall::cap_derive(endow.svcmgr_service_ep, syscall::RIGHTS_ALL)
    else
    {
        log("phase 3: svcmgr service-ep derive failed; svcmgr not started");
        destroy_partial_child(process_handle, ipc_buf);
        return false;
    };
    let Ok(boot_copy) = syscall::cap_derive(endow.svcmgr_bootstrap_ep, syscall::RIGHTS_ALL)
    else
    {
        log("phase 3: svcmgr bootstrap-ep derive failed; svcmgr not started");
        destroy_partial_child(process_handle, ipc_buf);
        return false;
    };

    if !start_process(
        process_handle,
        ipc_buf,
        "phase 3: svcmgr started; serving endowment",
        "phase 3: svcmgr START_PROCESS failed",
    )
    {
        destroy_partial_child(process_handle, ipc_buf);
        return false;
    }
    // rootfs.root SEND — badge inherited from the root fs namespace cap.
    let rootfs_send = if endow.rootfs_root_cap != 0
    {
        syscall::cap_derive(endow.rootfs_root_cap, syscall::RIGHTS_EP_SEND).unwrap_or(0)
    }
    else
    {
        0
    };
    // devmgr-registry source: badge-0 SEND|GRANT so svcmgr can mint the
    // badged query + drivers-dir caps. SEND|GRANT (not RIGHTS_ALL) is the
    // minimum — it withholds the RECV right on devmgr's registry endpoint.
    let devmgr_registry_src = if endow.devmgr_registry_ep != 0
    {
        syscall::cap_derive(endow.devmgr_registry_ep, syscall::RIGHTS_EP_SEND_GRANT).unwrap_or(0)
    }
    else
    {
        0
    };

    // vfsd service-endpoint SENDs: one badged MOUNT_AUTHORITY alone (no
    // SEED_AUTHORITY, which would hand over the system root), one badged
    // DENY_BADGE (no verb bit). Both are badged, so svcmgr and the recipes
    // seeding them cannot re-badge them into either authority.
    let vfsd_send = |badge: u64| {
        if endow.vfsd_service_ep == 0
        {
            return 0;
        }
        syscall::cap_derive_badge(endow.vfsd_service_ep, syscall::RIGHTS_EP_SEND, badge)
            .unwrap_or(0)
    };
    let vfsd_mount = vfsd_send(ipc::vfsd_labels::MOUNT_AUTHORITY);
    let vfsd_deny = vfsd_send(ipc::vfsd_labels::DENY_BADGE);

    // The CAPS rounds: the positional slot list [service, bootstrap, rootfs,
    // devmgr_reg, vfsd_mount, vfsd_deny], split over as many rounds as it needs, each carrying the
    // present caps of its window, named by its presence word, and the count
    // of CAPS rounds after it. The LOGD_SOURCES round is always terminal, so
    // no earlier round is.
    let caps_rounds = svcmgr_endowment::encode_caps(&svcmgr_endowment::CapsRound {
        service_ep: service_copy,
        bootstrap_ep: boot_copy,
        rootfs_root: rootfs_send,
        devmgr_registry: devmgr_registry_src,
        vfsd_mount,
        vfsd_deny,
    });
    for caps_round in &caps_rounds
    {
        if let Err(code) = serve_checked(
            bootstrap_ep,
            child_badge,
            ipc_buf,
            false,
            caps_round.caps(),
            caps_round.data(),
            "phase 3: svcmgr endowment CAPS round failed",
        )
        {
            if code == ipc::bootstrap_errors::NO_CHILD
            {
                end_endowment(bootstrap_ep, child_badge, ipc_buf);
            }
            return false;
        }
    }

    // A substrate round that fails on NO_CHILD leaves svcmgr's request
    // pending: skip the remaining substrates and serve the real terminal
    // round below, so svcmgr keeps its log-sink sources.
    if let Err(code) = serve_substrate_rounds(bootstrap_ep, child_badge, thread_caps, ipc_buf)
        && code != ipc::bootstrap_errors::NO_CHILD
    {
        return false;
    }

    // Terminal round (LOGD_SOURCES): the reserved master-log endpoint source
    // and the badge-0 procmgr `SEND|GRANT` source. svcmgr mints real-logd's
    // bootstrap caps from these on every (re)launch. A source whose derive
    // failed is left off the round and its presence bit clear, and svcmgr
    // holds it as absent; an absent source then leaves its slot of logd's
    // own bootstrap round absent, and logd runs without that cap (or, for
    // the master-log source, exits at startup).
    let logd_round = svcmgr_endowment::encode_logd_sources(&svcmgr_endowment::LogdSources {
        master_log_source: endow.master_log_source,
        procmgr_death_auth_source: endow.procmgr_death_auth_source,
    });
    serve(
        bootstrap_ep,
        child_badge,
        ipc_buf,
        true,
        logd_round.caps(),
        logd_round.data(),
        "phase 3: svcmgr endowment LOGD_SOURCES round failed",
    )
}

/// Serve svcmgr one `SUBSTRATE` round per init-bootstrapped service whose
/// thread cap init captured, stopping at the first failure with its
/// `serve_round` error code.
///
/// init skips a service whose thread cap it could not capture, so a missing
/// recipe match is bind-only-absent rather than a `registered without
/// definition` orphan in svcmgr. logd is absent: it is a svcmgr-launched
/// service (the `LOGD_SOURCES` round), not a parked substrate.
fn serve_substrate_rounds(
    bootstrap_ep: u32,
    child_badge: u64,
    thread_caps: ServiceThreadCaps,
    ipc_buf: *mut u64,
) -> Result<(), u64>
{
    let registrations: &[(&[u8], u32)] = &[
        (b"memmgr", thread_caps.memmgr),
        (b"procmgr", thread_caps.procmgr),
        (b"devmgr", thread_caps.devmgr),
        (b"vfsd", thread_caps.vfsd),
    ];
    for &(name, thread_cap) in registrations
    {
        if thread_cap == 0
        {
            continue;
        }
        let mut name_words = [0u64; 2];
        let nw = pack_svc_name(name, &mut name_words);
        let mut data = [0u64; 2 + 2];
        data[0] = svcmgr_endowment::kind::SUBSTRATE;
        data[1] = name.len() as u64;
        data[2..2 + nw].copy_from_slice(&name_words[..nw]);
        serve_checked(
            bootstrap_ep,
            child_badge,
            ipc_buf,
            false,
            &[thread_cap],
            &data[..2 + nw],
            "phase 3: svcmgr endowment SUBSTRATE round failed",
        )?;
    }
    Ok(())
}

/// End a failed endowment with an empty terminal `LOGD_SOURCES` round, so
/// svcmgr leaves its round loop (`request_round`) rather than block in it.
/// Called only after a `NO_CHILD` failure, which leaves svcmgr's request
/// pending, so the receive is answered. A further failure is logged.
fn end_endowment(bootstrap_ep: u32, child_badge: u64, ipc_buf: *mut u64)
{
    let empty = svcmgr_endowment::encode_logd_sources(&svcmgr_endowment::LogdSources {
        master_log_source: 0,
        procmgr_death_auth_source: 0,
    });
    let _ = serve(
        bootstrap_ep,
        child_badge,
        ipc_buf,
        true,
        empty.caps(),
        empty.data(),
        "phase 3: svcmgr endowment terminal round after a failure failed",
    );
}

// ── Phase 3 orchestration ───────────────────────────────────────────────────

/// Phase 3: load svcmgr, serve it the handover endowment (its own
/// endpoints + publish-role source caps + one `(name, thread_cap)` round
/// per init-bootstrapped substrate service + the reserved log-sink
/// sources), then notification `HANDOVER_COMPLETE` so svcmgr scans
/// `/config/svcmgr/services/`. svcmgr owns all post-handover work from the
/// endowment: it publishes the well-known names, installs devmgr's drivers
/// dir, and launches + supervises the non-bootstrap services. On a normal
/// boot the defined services are the bind-only substrate plus the
/// svcmgr-launched services (`logd`, `timed`, `pwrmgr`); svcmgr's
/// pure-consumer launch path fires only for staged test recipes (svctest /
/// usertest, and crasher co-staged with svctest).
// too_many_arguments: the function carries both svcmgr's endowment and
// procmgr's reap-handoff inputs, each from a different bootstrap stage.
// too_many_lines: the handover is one ordered protocol (spawn, endowment
// rounds, teardown registration, completion) that must run in sequence.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub fn phase3_svcmgr_handover(
    info: &InitInfo,
    procmgr_ep: u32,
    bootstrap_ep: u32,
    svcmgr_service_ep: u32,
    devmgr_registry_ep: u32,
    vfsd_service_ep: u32,
    system_root_cap: u32,
    log_ep: u32,
    thread_caps: ServiceThreadCaps,
    ipc_buf: *mut u64,
    init_logd_thread_cap: u32,
    mem_reap_floor: u32,
    orphan_memory_caps: &[u32],
) -> !
{
    let init_self_cspace = info.cspace_cap;

    // svcmgr's service endpoint is created in early init
    // (before bootstrap_procmgr) so procmgr can receive an un-badged
    // SEND on it in its bootstrap round and distribute query caps via
    // `ProcessInfo.service_registry_cap`. svcmgr's bootstrap endpoint
    // is local to this phase and stays created here.
    let Ok(svcmgr_bootstrap_ep) = syscall::cap_create_endpoint(crate::endpoint_slab())
    else
    {
        log("phase 3: cannot create svcmgr bootstrap endpoint");
        idle_loop();
    };

    log("phase 3: loading svcmgr from /services/svcmgr");
    let Some((svcmgr_handle, svcmgr_badge)) = create_svcmgr_from_file(
        procmgr_ep,
        bootstrap_ep,
        system_root_cap,
        init_self_cspace,
        ipc_buf,
    )
    else
    {
        log("phase 3: failed to create svcmgr, idling");
        idle_loop();
    };

    // Serve svcmgr its handover endowment: the CAPS rounds carry svcmgr's own
    // endpoints plus the publish-role source caps (rootfs root, devmgr
    // registry, the two vfsd SENDs), then one round per init-bootstrapped
    // substrate service carries that service's (name, thread_cap) for
    // death-supervision binding, and the terminal round carries the reserved
    // log-sink sources. svcmgr drains it all in `bootstrap_caps`, publishes
    // the well-known names it owns (`rootfs.root` / `svcmgr` / the `devmgr.*`
    // and `vfsd.*` names), installs devmgr's drivers dir, and reconciles
    // `/config/svcmgr/services/` on HANDOVER_COMPLETE — launching
    // logd/timed/pwrmgr and acquiring their caps for them.
    //
    // The publish source for `rootfs.root` is the seed system-root cap
    // (vfsd's synthetic root): vfsd self-mounts root, so there is no
    // per-mount fatfs cap to publish.
    let master_log_source = syscall::cap_derive(log_ep, syscall::RIGHTS_ALL).unwrap_or(0);
    // Badge-0 `SEND|GRANT` source on procmgr's service endpoint; svcmgr mints
    // logd's `DEATH_EQ_AUTHORITY` `SEND|GRANT` cap from it. `GRANT` because logd's
    // death-EQ registration transfers a cap, which the IPC kernel gates on it.
    let procmgr_death_auth_source =
        syscall::cap_derive(procmgr_ep, syscall::RIGHTS_EP_SEND_GRANT).unwrap_or(0);
    let endowment = SvcmgrEndowment {
        svcmgr_service_ep,
        svcmgr_bootstrap_ep,
        rootfs_root_cap: system_root_cap,
        devmgr_registry_ep,
        vfsd_service_ep,
        master_log_source,
        procmgr_death_auth_source,
    };
    let svcmgr_endowed = endow_svcmgr(
        bootstrap_ep,
        svcmgr_handle,
        svcmgr_badge,
        &endowment,
        thread_caps,
        ipc_buf,
    );

    // Bind procmgr's init-reap death observers on both init threads BEFORE the
    // svcmgr handover. svcmgr launches real-logd in response to
    // HANDOVER_COMPLETE, and real-logd's acknowledged HANDOVER_RELEASE (after
    // its HANDOVER_PULL drain) releases init-logd; binding first keeps the
    // reap's death countdown from depending on a bind that races init-logd's
    // exit, so both deaths are observed and init is reaped. Transferring init's
    // kernel-object caps here is safe: svcmgr is already created and endowed
    // (the only consumer of init's own CSpace cap), and the cap handles move
    // while the underlying objects keep backing init's still-running threads.
    let reap_bound = register_init_reap_objects(procmgr_ep, info, init_logd_thread_cap, ipc_buf);

    // A svcmgr that never received its service endpoint cannot receive
    // HANDOVER_COMPLETE; the call would block init here forever and leave the
    // reap unarmed, so it is skipped then.
    if svcmgr_endowed
    {
        send_handover_complete(svcmgr_service_ep, ipc_buf);
    }
    else
    {
        log("phase 3: svcmgr endowment failed; handover skipped");
    }

    // Reap-handoff (donation + arm): stream init's reclaimable Memory caps to
    // procmgr and notify INIT_TEARDOWN_DONE. The death observers were bound
    // above; procmgr reaps once both init threads have exited — init-logd on
    // real-logd's acknowledged HANDOVER_RELEASE, main on the thread_exit
    // below. The Memory caps land in memmgr's pool at reap. Skipped if the
    // object round failed: the reap cannot run without it.
    if reap_bound
    {
        finish_init_reap_handoff(
            info,
            procmgr_ep,
            ipc_buf,
            mem_reap_floor,
            orphan_memory_caps,
        );
    }

    log("main thread exiting; init handed off to procmgr for reap");
    syscall::thread_exit();
}

/// Send svcmgr `HANDOVER_COMPLETE` on its service endpoint through a SEND
/// carrying the `HANDOVER_AUTHORITY` verb-bit, derived for the call and
/// deleted after it. Logs the outcome; a failure is not fatal to init.
fn send_handover_complete(svcmgr_service_ep: u32, ipc_buf: *mut u64)
{
    let handover_msg = IpcMessage::new(svcmgr_labels::HANDOVER_COMPLETE);
    match syscall::cap_derive_badge(
        svcmgr_service_ep,
        syscall::RIGHTS_EP_SEND,
        svcmgr_labels::HANDOVER_AUTHORITY,
    )
    {
        Ok(handover_send) =>
        {
            // SAFETY: ipc_buf is caller's registered IPC buffer.
            let result = unsafe { ipc::ipc_call(handover_send, &handover_msg, ipc_buf) };
            let _ = syscall::cap_delete(handover_send);
            match result
            {
                Ok(reply) if reply.label == 0 => log("phase 3: handover complete"),
                _ => log("phase 3: handover failed"),
            }
        }
        Err(_) => log("phase 3: handover cap derive failed"),
    }
}

/// Send one `REGISTER_INIT_TEARDOWN` donate-only round (word 0 = 0)
/// carrying `slots` as caps. Non-fatal on failure: init exits regardless,
/// and any un-sent cap stays in init's `CSpace` until the reap frees it, when
/// its pages free into the sealed post-handoff buddy instead of reaching
/// memmgr's pool: an accounting violation, which trips the kernel's post-seal
/// `debug_assert` in a debug build (`docs/process-lifecycle.md` § Init reap;
/// `docs/userspace-memory-model.md` § Ownership Boundaries).
///
/// # Safety
/// `ipc_buf` must be init's registered IPC buffer; `procmgr_ep` must carry
/// SEND|GRANT.
unsafe fn send_teardown_round(procmgr_ep: u32, slots: &[u32], ipc_buf: *mut u64)
{
    if slots.is_empty()
    {
        return;
    }
    let mut builder = IpcMessage::builder(procmgr_labels::REGISTER_INIT_TEARDOWN).word(0, 0);
    for &slot in slots
    {
        builder = builder.cap(slot);
    }
    let msg = builder.build();
    // SAFETY: forwarded from the caller's contract above.
    match unsafe { ipc::ipc_call(procmgr_ep, &msg, ipc_buf) }
    {
        Ok(reply) if reply.label == ipc::procmgr_errors::SUCCESS =>
        {}
        Ok(_) => log("reap-handoff: donation round refused"),
        Err(_) => log("reap-handoff: donation round IPC failed"),
    }
}

/// Derive a transient full-rights copy of a boot-module Memory cap for a
/// `CREATE_PROCESS` spawn. Init retains the original — it is the sole owner
/// of the module-source `MemoryObject` and donates it to memmgr at reap. The
/// loader borrows this copy (deriving a read-only child for the load-time
/// mapping) and deletes it once the ELF is loaded.
fn module_spawn_copy(module_memory_cap: u32) -> Option<u32>
{
    syscall::cap_derive(module_memory_cap, syscall::RIGHTS_ALL).ok()
}

/// Round 1 of the reap handoff: transfer init's four kernel-object caps
/// (aspace, cspace, main thread, init-logd thread) to procmgr, which binds a
/// death-EQ observer on both threads (`data[0] = 1` distinguishes this from the
/// later donate-only rounds). IPC cap-transfer MOVES the caps; after this init's
/// `CSpace` no longer holds those four slots, but its threads keep running in
/// the underlying objects.
///
/// MUST run before the svcmgr handover — see the call site. Returns whether the
/// round succeeded; on failure the caller skips the donation rounds and arming,
/// since the reap cannot run without the bound observers.
///
/// # Safety
/// `ipc_buf` must be init's registered IPC buffer; `procmgr_ep` must carry
/// `SEND|GRANT`.
fn register_init_reap_objects(
    procmgr_ep: u32,
    info: &InitInfo,
    init_logd_thread_cap: u32,
    ipc_buf: *mut u64,
) -> bool
{
    let round1 = IpcMessage::builder(procmgr_labels::REGISTER_INIT_TEARDOWN)
        .word(0, 1)
        .cap(info.aspace_cap)
        .cap(info.cspace_cap)
        .cap(info.thread_cap)
        .cap(init_logd_thread_cap)
        .build();
    // SAFETY: ipc_buf is init's registered IPC buffer; procmgr_ep carries SEND|GRANT.
    match unsafe { ipc::ipc_call(procmgr_ep, &round1, ipc_buf) }
    {
        Ok(reply) if reply.label == ipc::procmgr_errors::SUCCESS => true,
        Ok(_) =>
        {
            log("reap-handoff: procmgr refused kernel-object round; skipping reap handoff");
            false
        }
        Err(_) =>
        {
            log("reap-handoff: kernel-object round IPC failed; skipping reap handoff");
            false
        }
    }
}

/// Donation + arm phase of the reap handoff: stream every reclaimable Memory
/// cap init solely holds to procmgr, then notify `INIT_TEARDOWN_DONE`. Run after
/// the svcmgr handover and only when [`register_init_reap_objects`] bound the
/// death observers. IPC cap-transfer MOVES the donated caps out of init's
/// `CSpace`.
///
/// Failures here are logged but otherwise non-fatal — init still calls
/// `sys_thread_exit` afterward, leaving the un-transferred caps in init's
/// `CSpace` until the reap frees it, when their pages free into the sealed
/// post-handoff buddy instead of reaching memmgr's pool: an accounting
/// violation, which trips the kernel's post-seal `debug_assert` in a debug
/// build (`docs/process-lifecycle.md` § Init reap).
fn finish_init_reap_handoff(
    info: &InitInfo,
    procmgr_ep: u32,
    ipc_buf: *mut u64,
    mem_reap_floor: u32,
    orphan_memory_caps: &[u32],
)
{
    // Donate every `owns_memory` Memory cap init solely holds, streamed in
    // MSG_CAP_SLOTS_MAX-sized rounds. Three disjoint sources:
    //  - explicit InitInfo ranges (not in the descriptor array): init's ELF
    //    segments, user stack, and the InitInfo region. (init's IPC buffer is
    //    not here: it lives in init's bootstrap arena, forwarded to memmgr at
    //    `finalize_memmgr` as an in-use run, not donated at reap.)
    //  - a descriptor walk for the unnamed reclaimable Memory caps — the
    //    bootloader and bundle reclaim ranges plus the AP-trampoline late
    //    cap — which carry no named InitInfo slot.
    //  - MemoryAlloc's orphans: free remainders abandoned while carving the
    //    bootstrap arenas, below the floor with no descriptor.
    // The walk skips caps init does not solely own or that are not RAM: the
    // consumed/forwarded usable-RAM prefix (below `mem_reap_floor` —
    // `MemoryAlloc` arenas and the memory caps `finalize_memmgr` already forwarded;
    // memmgr keeps them alive) and the firmware read-only caps (RSDP/ACPI/DTB;
    // owns_memory=false). The usable-RAM *tail* at or above the floor — free
    // memory caps that did not fit the single bootstrap round — IS donated here, so
    // every page of RAM reaches memmgr's pool. Boot-module Memory caps are also
    // included: init is their sole owner once every loader has copied the ELF
    // and dropped its borrowed read-only derivation.
    let seg = info.segment_memory_base..info.segment_memory_base + info.segment_memory_count;
    let stack =
        info.init_stack_memory_base..info.init_stack_memory_base + info.init_stack_memory_count;
    let inf = info.init_info_memory_base..info.init_info_memory_base + info.init_info_memory_count;

    let mem_lo = info.memory_base;
    let acpi_lo = info.acpi_region_memory_base;
    let acpi_hi = info
        .acpi_region_memory_base
        .saturating_add(info.acpi_region_memory_count);

    let mut chunk = [0u32; syscall_abi::MSG_CAP_SLOTS_MAX];
    let mut cn = 0usize;
    {
        let mut push = |slot: u32| {
            chunk[cn] = slot;
            cn += 1;
            if cn == chunk.len()
            {
                // SAFETY: ipc_buf is registered; procmgr_ep carries SEND|GRANT.
                unsafe { send_teardown_round(procmgr_ep, &chunk, ipc_buf) };
                cn = 0;
            }
        };

        for slot in seg.chain(stack).chain(inf)
        {
            push(slot);
        }
        for desc in crate::descriptors(info)
        {
            if desc.cap_type != CapType::Memory
            {
                continue;
            }
            let s = desc.slot;
            if s >= mem_lo && s < mem_reap_floor
            {
                continue;
            }
            if (info.acpi_rsdp_memory_cap != 0 && s == info.acpi_rsdp_memory_cap)
                || (info.dtb_memory_cap != 0 && s == info.dtb_memory_cap)
                || (info.acpi_region_memory_count != 0 && s >= acpi_lo && s < acpi_hi)
            {
                continue;
            }
            push(s);
        }
        // The free Memory caps MemoryAlloc abandoned while carving bootstrap
        // arenas: memory_split remainders below the floor with no descriptor.
        // Without this the reap's teardown of init's CSpace would free them
        // into the sealed post-handoff buddy, tripping the kernel's post-seal
        // `debug_assert` in a debug build, and their pages would never reach
        // memmgr (`docs/process-lifecycle.md` § Init reap). They carry
        // RETYPE + owns_memory like any RAM memory
        // cap, so memmgr ingests them into its pool.
        for &slot in orphan_memory_caps
        {
            push(slot);
        }
    }
    if cn > 0
    {
        // SAFETY: ipc_buf is registered; procmgr_ep carries SEND|GRANT.
        unsafe { send_teardown_round(procmgr_ep, &chunk[..cn], ipc_buf) };
    }

    // Notification the cap stream is closed. Procmgr arms the death-EQ
    // observer; the next event with INIT_REAP_CORRELATOR triggers the
    // reap. (Done by this point — REGISTER_INIT_TEARDOWN's first round
    // already bound the EQ.)
    let done = IpcMessage::new(procmgr_labels::INIT_TEARDOWN_DONE);
    // SAFETY: ipc_buf is registered.
    match unsafe { ipc::ipc_call(procmgr_ep, &done, ipc_buf) }
    {
        Ok(reply) if reply.label == ipc::procmgr_errors::SUCCESS =>
        {}
        _ => log("reap-handoff: INIT_TEARDOWN_DONE IPC failed (reap may not run)"),
    }
}

// ── svcmgr endowment name packing ───────────────────────────────────────────

/// Pack a short ASCII name into IPC data words, little-endian within each
/// word. Matches svcmgr's unpack in `service::ingest_substrate` /
/// `read_tail_name_from_msg`. Returns the word count used.
fn pack_svc_name(name: &[u8], out: &mut [u64; 2]) -> usize
{
    for (i, &b) in name.iter().enumerate()
    {
        out[i / 8] |= u64::from(b) << ((i % 8) * 8);
    }
    name.len().div_ceil(8)
}
