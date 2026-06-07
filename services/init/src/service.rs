// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// init/src/service.rs

//! Service creation helpers for init.
//!
//! Creates suspended child processes via procmgr IPC (`CREATE_PROCESS` /
//! `CREATE_FROM_FILE`), installs init's seed namespace cap on each child
//! via `CONFIGURE_NAMESPACE`, starts them, then serves their bootstrap
//! requests on init's bootstrap endpoint to deliver their per-service
//! capability set.

use crate::bootstrap::NEXT_BOOTSTRAP_BADGE;
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
    let badge = NEXT_BOOTSTRAP_BADGE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let badged = syscall::cap_derive_badge(bootstrap_ep, syscall::RIGHTS_SEND, badge).ok()?;
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
    let Ok(ns_cap) = syscall::cap_copy(system_root_cap, init_self_cspace, syscall::RIGHTS_SEND)
    else
    {
        log("phase 3: cap_copy of system root for child failed");
        destroy_partial_child(process_handle, ipc_buf);
        return false;
    };

    let cwd_cap = if let Some((path, rights)) = cwd
    {
        let Some(c) = walk::walk_to_dir(system_root_cap, path, rights, ipc_buf)
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

/// Serve one bootstrap round from init to the named child.
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
    // SAFETY: ipc_buf is caller's registered IPC buffer.
    if unsafe { ipc::bootstrap::serve_round(bootstrap_ep, badge, ipc_buf, done, caps, data) }
        .is_err()
    {
        log(context);
        return false;
    }
    true
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
/// to devmgr. Parsing (MCFG → ECAM, MADT → GSI routing) lives in devmgr.
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
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
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
    let create_msg = IpcMessage::builder(procmgr_labels::CREATE_PROCESS)
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

    // ── Aperture rounds ─────────────────────────────────────────────────
    let mut idx = 0;
    while idx < hw.aperture_count
    {
        let batch_end = (idx + 4).min(hw.aperture_count);
        let batch_count = batch_end - idx;
        let mut caps = [0u32; 4];
        let mut data = [0u64; 2 + 4 * 2];
        data[0] = kind::APERTURE;
        data[1] = batch_count as u64;
        for j in 0..batch_count
        {
            let (slot, base, size) = hw.apertures[idx + j];
            if let Ok(c) = syscall::cap_derive(slot, syscall::RIGHTS_ALL)
            {
                caps[j] = c;
            }
            data[2 + j * 2] = base;
            data[3 + j * 2] = size;
        }

        if !serve(
            bootstrap_ep,
            child_badge,
            ipc_buf,
            false,
            &caps[..batch_count],
            &data[..2 + batch_count * 2],
            "devmgr: bootstrap aperture round failed",
        )
        {
            return None;
        }
        idx = batch_end;
    }

    // ── ACPI region rounds ──────────────────────────────────────────────
    let mut idx = 0;
    while idx < hw.acpi_region_count
    {
        let batch_end = (idx + 4).min(hw.acpi_region_count);
        let batch_count = batch_end - idx;
        let mut caps = [0u32; 4];
        let mut data = [0u64; 2 + 4 * 2];
        data[0] = kind::ACPI_REGION;
        data[1] = batch_count as u64;
        for j in 0..batch_count
        {
            let (slot, base, size) = hw.acpi_regions[idx + j];
            if let Ok(c) = syscall::cap_derive(slot, syscall::RIGHTS_ALL)
            {
                caps[j] = c;
            }
            data[2 + j * 2] = base;
            data[3 + j * 2] = size;
        }

        if !serve(
            bootstrap_ep,
            child_badge,
            ipc_buf,
            false,
            &caps[..batch_count],
            &data[..2 + batch_count * 2],
            "devmgr: bootstrap ACPI region round failed",
        )
        {
            return None;
        }
        idx = batch_end;
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
            let Ok(module_copy) = syscall::cap_derive(module_cap, syscall::RIGHTS_ALL)
            else
            {
                log("devmgr: driver module cap derive failed");
                return None;
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
    // svcmgr's registry on init's behalf (today's only use is reserved
    // for future devmgr publications; the active publications — `timed`,
    // `rootfs.root`, `svcmgr`, `devmgr.registry` — are init-issued).
    // The arch shutdown-authority cap is the root `IoPort` on x86-64
    // (devmgr derives narrow per-driver IoPort caps from it for ISA
    // peripherals like the CMOS RTC, and carves the PM1a + 8042 ports for
    // pwrmgr) and `SbiControl` on RISC-V (devmgr serves a copy to pwrmgr
    // for SBI SRST). devmgr is the hardware authority; pwrmgr acquires its
    // shutdown caps from devmgr, not from init.
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
        // RIGHTS_SEND_GRANT (not bare SEND): PUBLISH_ENDPOINT carries the
        // service's SEND cap in the message, and the IPC kernel requires the
        // GRANT bit on the caller's send-cap to transfer caps.
        syscall::cap_derive_badge(
            svcmgr_service_ep,
            syscall::RIGHTS_SEND_GRANT,
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
        // authority (init is reaped, so its root cap is dropped). Transfer only
        // the power-state extensions — system reset (served to pwrmgr on
        // QUERY_SHUTDOWN_DEVICE, narrowed to Reset there) and suspend (reserved
        // for a future path). The other sanctioned SBI rights are carried into
        // no surviving cap and are therefore dropped at init's reap.
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
#[allow(clippy::struct_field_names)]
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

    let create_msg = IpcMessage::builder(procmgr_labels::CREATE_PROCESS)
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
    // vfsd is the sole devmgr `QUERY_BLOCK_DEVICE` consumer today;
    // tag its SEND with `REGISTRY_QUERY_AUTHORITY` so devmgr's
    // upstream gate admits the call. Future registry consumers
    // receive a copy without the bit and are rejected at devmgr.
    let Ok(registry_copy) = syscall::cap_derive_badge(
        spawn.registry_ep,
        syscall::RIGHTS_SEND,
        ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY,
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

    // Round 2: fatfs module.
    let fatfs_cap = match crate::find_module_by_name(info, b"fatfs")
    {
        Some(slot) => syscall::cap_derive(slot, syscall::RIGHTS_ALL).unwrap_or(0),
        None => 0,
    };

    let _ = serve(
        bootstrap_ep,
        child_badge,
        ipc_buf,
        true,
        &[fatfs_cap],
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
    let walked = walk::walk_to_file(system_root_cap, b"/services/svcmgr", 0xFFFF, ipc_buf)?;

    let (badged_creator, child_badge) = derive_badged_creator(bootstrap_ep)?;

    let msg = IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE)
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

/// Round kinds for the svcmgr handover endowment, tagged in `data[0]`.
/// Mirrors the receive side in `services/svcmgr/src/service.rs::endow_kind`.
mod endow_kind
{
    /// Round 1: svcmgr's own endpoints + publish-role source caps.
    pub const CAPS: u64 = 1;
    /// One substrate `(name, thread_cap)` registration.
    pub const SUBSTRATE: u64 = 2;
    /// Terminal round: the reserved source caps svcmgr keeps to launch +
    /// supervise + restart real-logd (master-log endpoint, procmgr death-auth).
    pub const LOGD_SOURCES: u64 = 3;
}

/// Source + endpoint caps init endows svcmgr with at handover. svcmgr
/// derives the shapes it publishes / sends / launches with from these
/// reserved sources; it keeps the log-sink sources for the system's life
/// so it can (re)launch real-logd any number of times.
#[allow(clippy::struct_field_names)]
pub struct SvcmgrEndowment
{
    pub svcmgr_service_ep: u32,
    pub svcmgr_bootstrap_ep: u32,
    /// Seed system-root cap (`GET_SYSTEM_ROOT_CAP` from vfsd). svcmgr
    /// derives the published `rootfs.root` SEND from it.
    pub rootfs_root_cap: u32,
    pub devmgr_registry_ep: u32,
    /// Reserved master-log endpoint source (`cap_derive(log_ep, RIGHTS_ALL)`).
    /// svcmgr mints real-logd's master-log RECV from it on every (re)launch,
    /// plus the one-shot `HANDOVER_PULL` SEND on the first launch. Holding it
    /// keeps the endpoint object alive across a logd crash so log senders are
    /// agnostic to which process holds the RECV.
    pub master_log_source: u32,
    /// Reserved badge-0 `SEND|GRANT` source on procmgr's service endpoint.
    /// svcmgr mints real-logd's `DEATH_EQ_AUTHORITY` SEND from it per launch
    /// (used by logd to register sender death-notifications for slot reclaim).
    pub procmgr_death_auth_source: u32,
}

/// Start svcmgr, then serve the handover endowment over the bootstrap
/// protocol.
///
/// Round 1 (`CAPS`) delivers svcmgr's service + bootstrap endpoints (full
/// rights) and the publish-role source caps: a `SEND` on the root
/// filesystem namespace endpoint (svcmgr publishes it as `rootfs.root`) and
/// a badge-0 `SEND|GRANT` source on devmgr's registry endpoint (svcmgr mints
/// the `REGISTRY_QUERY_AUTHORITY` `devmgr.registry` publish cap and the
/// `DRIVERS_DIR_AUTHORITY` `SET_DRIVERS_DIR` cap from it). An absent source
/// cap rides as a zero slot, which svcmgr tolerates.
///
/// Each `SUBSTRATE` round then delivers one init-bootstrapped service's
/// thread cap plus its name (memmgr/procmgr/devmgr/vfsd); svcmgr parks the
/// pairs for death-supervision binding at reconciliation.
///
/// The terminal `LOGD_SOURCES` round delivers the two reserved caps svcmgr
/// keeps to launch + supervise + restart real-logd: the master-log endpoint
/// source and a badge-0 procmgr `SEND|GRANT` source (see [`SvcmgrEndowment`]).
///
/// Best-effort: a failed round logs and aborts the endowment; svcmgr then
/// runs with whatever it received (the system is already non-viable if a
/// substrate thread cap cannot be delivered).
fn endow_svcmgr(
    bootstrap_ep: u32,
    process_handle: u32,
    child_badge: u64,
    endow: &SvcmgrEndowment,
    thread_caps: ServiceThreadCaps,
    ipc_buf: *mut u64,
)
{
    if !start_process(
        process_handle,
        ipc_buf,
        "phase 3: svcmgr started; serving endowment",
        "phase 3: svcmgr START_PROCESS failed",
    )
    {
        return;
    }

    let Ok(service_copy) = syscall::cap_derive(endow.svcmgr_service_ep, syscall::RIGHTS_ALL)
    else
    {
        log("phase 3: svcmgr service-ep derive failed");
        return;
    };
    let Ok(boot_copy) = syscall::cap_derive(endow.svcmgr_bootstrap_ep, syscall::RIGHTS_ALL)
    else
    {
        log("phase 3: svcmgr bootstrap-ep derive failed");
        return;
    };
    // rootfs.root SEND — badge inherited from the root fs namespace cap.
    let rootfs_send = if endow.rootfs_root_cap != 0
    {
        syscall::cap_derive(endow.rootfs_root_cap, syscall::RIGHTS_SEND).unwrap_or(0)
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
        syscall::cap_derive(endow.devmgr_registry_ep, syscall::RIGHTS_SEND_GRANT).unwrap_or(0)
    }
    else
    {
        0
    };

    // Substrate set; init skips a service whose thread cap it could not
    // capture, so a missing recipe match is bind-only-absent rather than a
    // `registered without definition` orphan in svcmgr. logd is absent — it
    // is a svcmgr-launched service (LOGD_SOURCES round), not a parked
    // substrate.
    let registrations: &[(&[u8], u32)] = &[
        (b"memmgr", thread_caps.memmgr),
        (b"procmgr", thread_caps.procmgr),
        (b"devmgr", thread_caps.devmgr),
        (b"vfsd", thread_caps.vfsd),
    ];

    // Round 1 (CAPS), positional: [service, bootstrap, rootfs, devmgr_reg].
    // The LOGD_SOURCES round is always terminal, so no earlier round is.
    if !serve(
        bootstrap_ep,
        child_badge,
        ipc_buf,
        false,
        &[service_copy, boot_copy, rootfs_send, devmgr_registry_src],
        &[endow_kind::CAPS, u64::from(ipc::SVCMGR_LABELS_VERSION)],
        "phase 3: svcmgr endowment CAPS round failed",
    )
    {
        return;
    }

    // Substrate rounds: one (name, thread_cap) each.
    for &(name, thread_cap) in registrations
    {
        if thread_cap == 0
        {
            continue;
        }
        let mut name_words = [0u64; 2];
        let nw = pack_svc_name(name, &mut name_words);
        let mut data = [0u64; 2 + 2];
        data[0] = endow_kind::SUBSTRATE;
        data[1] = name.len() as u64;
        data[2..2 + nw].copy_from_slice(&name_words[..nw]);
        if !serve(
            bootstrap_ep,
            child_badge,
            ipc_buf,
            false,
            &[thread_cap],
            &data[..2 + nw],
            "phase 3: svcmgr endowment SUBSTRATE round failed",
        )
        {
            return;
        }
    }

    // Terminal round (LOGD_SOURCES): the reserved master-log endpoint source
    // and the badge-0 procmgr `SEND|GRANT` source. svcmgr mints real-logd's
    // bootstrap caps from these on every (re)launch. A zero slot rides if a
    // source derive failed; svcmgr degrades (logd unlaunchable) but survives.
    let _ = serve(
        bootstrap_ep,
        child_badge,
        ipc_buf,
        true,
        &[endow.master_log_source, endow.procmgr_death_auth_source],
        &[endow_kind::LOGD_SOURCES],
        "phase 3: svcmgr endowment LOGD_SOURCES round failed",
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
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub fn phase3_svcmgr_handover(
    info: &InitInfo,
    procmgr_ep: u32,
    bootstrap_ep: u32,
    svcmgr_service_ep: u32,
    devmgr_registry_ep: u32,
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

    // Serve svcmgr its handover endowment: round 1 carries svcmgr's own
    // endpoints plus the publish-role source caps (rootfs root, devmgr
    // registry), then one round per init-bootstrapped substrate service
    // carries that service's (name, thread_cap) for death-supervision
    // binding, and the terminal round carries the reserved log-sink sources.
    // svcmgr drains it all in `bootstrap_caps`, publishes the well-known
    // names it owns (`rootfs.root` / `svcmgr` / `devmgr.registry`), installs
    // devmgr's drivers dir, and reconciles `/config/svcmgr/services/` on
    // HANDOVER_COMPLETE — launching logd/timed/pwrmgr and acquiring their
    // caps for them.
    //
    // The publish source for `rootfs.root` is the seed system-root cap
    // (vfsd's synthetic root): vfsd self-mounts root, so there is no
    // per-mount fatfs cap to publish.
    let master_log_source = syscall::cap_derive(log_ep, syscall::RIGHTS_ALL).unwrap_or(0);
    // Badge-0 `SEND|GRANT` source on procmgr's service endpoint; svcmgr mints
    // logd's `DEATH_EQ_AUTHORITY` SEND from it. `GRANT` because logd's
    // death-EQ registration transfers a cap, which the IPC kernel gates on it.
    let procmgr_death_auth_source =
        syscall::cap_derive(procmgr_ep, syscall::RIGHTS_SEND_GRANT).unwrap_or(0);
    let endowment = SvcmgrEndowment {
        svcmgr_service_ep,
        svcmgr_bootstrap_ep,
        rootfs_root_cap: system_root_cap,
        devmgr_registry_ep,
        master_log_source,
        procmgr_death_auth_source,
    };
    endow_svcmgr(
        bootstrap_ep,
        svcmgr_handle,
        svcmgr_badge,
        &endowment,
        thread_caps,
        ipc_buf,
    );

    // Bind procmgr's init-reap death observers on both init threads BEFORE the
    // svcmgr handover. svcmgr launches real-logd in response to
    // HANDOVER_COMPLETE, and real-logd's HANDOVER_PULL releases init-logd; if
    // the observer bind ran after that release it would land on an already
    // -exited init-logd and silently lose the death — the kernel bind only
    // appends an observer, it does not fire for a thread that has already
    // exited — so the reap's death countdown would wait forever for an exit it
    // already missed, and init would never be reaped. Transferring init's
    // kernel-object caps here is safe: svcmgr is already created and endowed
    // (the only consumer of init's own CSpace cap), and the cap handles move
    // while the underlying objects keep backing init's still-running threads.
    let reap_bound = register_init_reap_objects(procmgr_ep, info, init_logd_thread_cap, ipc_buf);

    let handover_msg = IpcMessage::new(svcmgr_labels::HANDOVER_COMPLETE);
    // SAFETY: ipc_buf is caller's registered IPC buffer.
    match unsafe { ipc::ipc_call(svcmgr_service_ep, &handover_msg, ipc_buf) }
    {
        Ok(reply) if reply.label == 0 => log("phase 3: handover complete"),
        _ => log("phase 3: handover failed"),
    }

    // Reap-handoff (donation + arm): stream init's reclaimable Memory caps to
    // procmgr and notify INIT_TEARDOWN_DONE. The death observers were bound
    // above; procmgr reaps once both init threads have exited — init-logd when
    // real-logd pulls the handover, main on the thread_exit below. The Memory
    // caps land in memmgr's pool at reap. Skipped if the object round failed:
    // the reap cannot run without it.
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

/// Send one `REGISTER_INIT_TEARDOWN` donate-only round (word 0 = 0)
/// carrying `slots` as caps. Non-fatal on failure: init exits regardless,
/// and any un-sent cap falls to the `CSpace` cascade.
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
/// `sys_thread_exit` afterward, just leaving the un-transferred caps
/// to cascade through `CSpace` teardown to the kernel buddy on eventual
/// cap death.
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
        // Without this they would cascade into the sealed buddy at CSpace
        // teardown and leak. They carry RETYPE + owns_memory like any RAM
        // memory cap, so memmgr ingests them into its pool.
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
