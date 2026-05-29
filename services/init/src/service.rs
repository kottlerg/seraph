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

use crate::bootstrap::NEXT_BOOTSTRAP_TOKEN;
use crate::idle_loop;
use crate::logging::log;
use crate::walk;
use init_protocol::{CapType, InitInfo};
use ipc::{IpcMessage, procmgr_labels, svcmgr_labels};

/// Thread caps init collects across Phases 1-3 for v3
/// `REGISTER_SERVICE` once svcmgr is up. Zero in a slot means init
/// could not capture (or chose not to capture) that service's thread
/// cap; the corresponding `register_service` call is then skipped.
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
    pub logd: u32,
    pub timed: u32,
}

/// Per-spawn namespace-cap policy for [`configure_child_namespace`].
///
/// The variants encode the two shapes a child's `system_root_cap`
/// can take when init still spawns the service directly: a `cap_copy`
/// of the spawner's seed root, or nothing at all. Per-service subtree
/// attenuation lives in svcmgr (parsed from `/config/svcmgr/services/<name>.svc`'s
/// `namespace = subtree:<path>:<rights>` line) post-#21.
#[derive(Clone, Copy)]
pub enum NsPolicy
{
    /// Hand the child a `cap_copy` of `system_root_cap` at full
    /// rights.
    Universal,
    /// Do not call `CONFIGURE_NAMESPACE` at all. The child's
    /// `system_root_cap` stays zero; std-side absolute-path fs ops
    /// return `Unsupported`.
    None,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn derive_tokened_creator(bootstrap_ep: u32) -> Option<(u32, u64)>
{
    let token = NEXT_BOOTSTRAP_TOKEN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let tokened = syscall::cap_derive_token(bootstrap_ep, syscall::RIGHTS_SEND, token).ok()?;
    Some((tokened, token))
}

/// Issue `procmgr_labels::CONFIGURE_NAMESPACE` on a freshly-created
/// (suspended) child according to `policy` and the optional `cwd`.
///
/// * `policy` selects the shape of the child's `system_root_cap`:
///   universal copy of `system_root_cap`, an attenuated subtree
///   walked from it, or no cap at all.
/// * `cwd`, when `Some`, walks `(path, rights)` from `system_root_cap`
///   and delivers the resulting directory cap as `caps[1]` so the
///   child's `current_dir_cap` is non-zero from the first instruction.
///
/// `NsPolicy::None` with `cwd = None` skips the IPC entirely
/// (procmgr's default leaves both `ProcessInfo` slots at zero).
/// `NsPolicy::None` with `cwd = Some(_)` is rejected by procmgr
/// (`root_cap == 0` is `INVALID_ARGUMENT`); callers MUST pair a cwd
/// with at least `Universal` or `Subtree`.
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
    policy: NsPolicy,
    cwd: Option<(&[u8], u64)>,
    ipc_buf: *mut u64,
) -> bool
{
    let ns_cap = match policy
    {
        NsPolicy::None =>
        {
            if cwd.is_some()
            {
                // cwd without root is unrepresentable on the wire
                // (procmgr enforces root_cap != 0). Treat as a
                // caller bug.
                log("phase 3: NsPolicy::None with cwd is invalid");
                destroy_partial_child(process_handle, ipc_buf);
                return false;
            }
            return true;
        }
        NsPolicy::Universal =>
        {
            let Ok(c) = syscall::cap_copy(system_root_cap, init_self_cspace, syscall::RIGHTS_SEND)
            else
            {
                log("phase 3: cap_copy of system root for child failed");
                destroy_partial_child(process_handle, ipc_buf);
                return false;
            };
            c
        }
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
/// tokened handle and release init's procmgr-side slot. Used by every
/// helper that reaches a failure between procmgr's CREATE and START.
fn destroy_partial_child(process_handle: u32, ipc_buf: *mut u64)
{
    let destroy_msg = IpcMessage::new(procmgr_labels::DESTROY_PROCESS);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_call(process_handle, &destroy_msg, ipc_buf) };
    let _ = syscall::cap_delete(process_handle);
}

/// Start a process by calling `START_PROCESS` on its tokened process handle.
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
    token: u64,
    ipc_buf: *mut u64,
    done: bool,
    caps: &[u32],
    data: &[u64],
    context: &str,
) -> bool
{
    // SAFETY: ipc_buf is caller's registered IPC buffer.
    if unsafe { ipc::bootstrap::serve_round(bootstrap_ep, token, ipc_buf, done, caps, data) }
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

/// Maximum number of ACPI reclaimable-region Frame caps. Matches the
/// kernel's `MAX_ACPI_REGIONS`; 8 is generous.
const MAX_ACPI_REGION_CAPS: usize = 8;

/// Collected hardware caps: init forwards raw firmware + MMIO surfaces
/// to devmgr. Parsing (MCFG → ECAM, MADT → GSI routing) lives in devmgr.
struct HwCaps
{
    /// Root `Interrupt` range cap. Zero if the kernel did not mint one.
    irq_range_slot: u32,
    /// RO Frame cap covering the ACPI RSDP page. Zero if none.
    rsdp_slot: u32,
    rsdp_page_base: u64,
    /// RO Frame cap covering the DTB blob. Zero if none.
    dtb_slot: u32,
    dtb_page_base: u64,
    dtb_size: u64,
    /// All MMIO aperture caps (slot, base, size).
    apertures: [(u32, u64, u64); MAX_APERTURE_CAPS],
    aperture_count: usize,
    /// ACPI reclaimable-region Frame caps (slot, base, size).
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
    hw.rsdp_slot = info.acpi_rsdp_frame_cap;
    hw.dtb_slot = info.dtb_frame_cap;

    // Walk the descriptor array once to capture aperture + ACPI-region
    // metadata. RSDP / DTB base + size come from their descriptors too.
    for d in crate::descriptors(info)
    {
        match d.cap_type
        {
            CapType::MmioRegion if hw.aperture_count < MAX_APERTURE_CAPS =>
            {
                hw.apertures[hw.aperture_count] = (d.slot, d.aux0, d.aux1);
                hw.aperture_count += 1;
            }
            CapType::Frame if d.slot == hw.rsdp_slot && hw.rsdp_slot != 0 =>
            {
                hw.rsdp_page_base = d.aux0;
            }
            CapType::Frame if d.slot == hw.dtb_slot && hw.dtb_slot != 0 =>
            {
                hw.dtb_page_base = d.aux0;
                hw.dtb_size = d.aux1;
            }
            _ =>
            {}
        }
    }

    // ACPI region caps occupy a contiguous slot range starting at
    // `acpi_region_frame_base`. Walk the descriptor array a second time
    // to pick them out by slot range; their aux0/aux1 carry (base, size).
    let ar_start = info.acpi_region_frame_base;
    let ar_end = ar_start + info.acpi_region_frame_count;
    if info.acpi_region_frame_count != 0
    {
        for d in crate::descriptors(info)
        {
            if d.cap_type == CapType::Frame
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
///   - caps: `[registry_ep, irq_range, rsdp_frame, dtb_frame]`
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
    let devmgr_frame_cap = crate::find_module_by_name(info, b"devmgr")?;
    let devmgr_module_copy = module_spawn_copy(devmgr_frame_cap)?;

    let (tokened_creator, child_token) = derive_tokened_creator(bootstrap_ep)?;

    // caps: [module, creator]. No stdio pipes — devmgr reaches the
    // system log via the discovery cap procmgr installs in ProcessInfo.
    let create_msg = IpcMessage::builder(procmgr_labels::CREATE_PROCESS)
        .cap(devmgr_module_copy)
        .cap(tokened_creator)
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
        child_token,
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
            child_token,
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
            child_token,
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
                child_token,
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
            child_token,
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
    // caps: [svcmgr_publish_cap, ioport_root_cap (x86 only)]. The
    // SEND-rights cap on svcmgr's service endpoint is stamped with the
    // PUBLISH_AUTHORITY verb-bit in its token so devmgr can register
    // service caps in svcmgr's registry on init's behalf (today's only
    // use is reserved for future devmgr publications; the active
    // publications — `timed`, `rootfs.root`, `pwrmgr.*`, `svcmgr`,
    // `devmgr.registry` — are init-issued). The IoPortRange copy is
    // delivered only on x86-64 (RISC-V has no I/O ports); devmgr
    // derives narrow per-driver IoPort caps from it for ISA
    // peripherals like the CMOS RTC.
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
        syscall::cap_derive_token(
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
            child_token,
            ipc_buf,
            true,
            &[],
            &[kind::SVCMGR_BUNDLE, 0],
            "devmgr: empty SVCMGR_BUNDLE failsafe round failed",
        );
        return None;
    }

    let ioport_root_cap = if cfg!(target_arch = "x86_64")
    {
        crate::find_cap_by_type(info, init_protocol::CapType::IoPortRange)
            .and_then(|root| syscall::cap_derive(root, syscall::RIGHTS_ALL).ok())
            .unwrap_or(0)
    }
    else
    {
        0
    };

    let bundle_caps: [u32; 2] = [svcmgr_publish, ioport_root_cap];
    let bundle_cap_count = if ioport_root_cap != 0 { 2 } else { 1 };

    let _ = serve(
        bootstrap_ep,
        child_token,
        ipc_buf,
        true,
        &bundle_caps[..bundle_cap_count],
        &[kind::SVCMGR_BUNDLE, bundle_cap_count as u64],
        "devmgr: bootstrap SVCMGR_BUNDLE round failed",
    );
    Some(thread_cap)
}

// ── pwrmgr creation ─────────────────────────────────────────────────────────

/// Pwrmgr-side result of [`create_and_start_pwrmgr`].
///
/// `service_ep` is the un-tokened source on pwrmgr's service endpoint
/// (init keeps it to mint tokened SENDs); `thread_cap` is pwrmgr's
/// main thread in init's `CSpace`, registered with svcmgr so the
/// supervisor can bind death-notification.
pub struct PwrmgrSpawn
{
    pub service_ep: u32,
    pub thread_cap: u32,
}

/// Walk `/services/pwrmgr`, create the process, transfer platform shutdown
/// caps via bootstrap rounds, and start it.
///
/// Returns the service-endpoint slot init owns (the RECV side stays with
/// pwrmgr; init keeps the source for deriving tokened SENDs to
/// authorized consumers) plus pwrmgr's main thread cap. Returns `None`
/// on any failure; partial state is torn down before returning.
///
/// Bootstrap layout (matches `services/pwrmgr/src/caps.rs`):
/// * Round 1 (≤2 caps, 2 data words):
///   - `caps[0]` = pwrmgr's service endpoint (derived copy).
///   - `caps[1]` = arch authority cap (`IoPortRange` on x86-64,
///     `SbiControl` on RISC-V). Omitted when absent.
///   - `data[0]` = presence bitmap (bit 0 = arch cap present).
///   - `data[1]` = `PWRMGR_LABELS_VERSION`.
///   - `done` = true on RISC-V or when no ACPI regions follow.
/// * Round 2..N (x86-64 only): ACPI region Frame caps, ≤4 per round.
#[allow(clippy::too_many_lines)]
pub fn create_and_start_pwrmgr(
    info: &InitInfo,
    procmgr_ep: u32,
    bootstrap_ep: u32,
    system_root_cap: u32,
    init_self_cspace: u32,
    ipc_buf: *mut u64,
) -> Option<PwrmgrSpawn>
{
    let walked = walk::walk_to_file(system_root_cap, b"/services/pwrmgr", 0xFFFF, ipc_buf)?;

    let (tokened_creator, child_token) = derive_tokened_creator(bootstrap_ep)?;

    let msg = IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE)
        .word(0, walked.size)
        .cap(walked.file_cap)
        .cap(tokened_creator)
        .build();

    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_ep, &msg, ipc_buf) })
    else
    {
        log("pwrmgr: CREATE_FROM_FILE ipc_call failed");
        return None;
    };
    if reply.label != 0
    {
        log("pwrmgr: CREATE_FROM_FILE error");
        return None;
    }

    let reply_caps = reply.caps();
    if reply_caps.is_empty()
    {
        log("pwrmgr: CREATE_FROM_FILE reply missing caps");
        return None;
    }
    let process_handle = reply_caps[0];
    // CREATE_FROM_FILE returns (process_handle, thread_cap). Pwrmgr is
    // svcmgr-registered for death monitoring (post-#21); the thread
    // cap is preserved here and returned via [`PwrmgrSpawn`] for the
    // Phase-3 v3 `REGISTER_SERVICE` call.
    if reply_caps.len() < 2
    {
        log("pwrmgr: CREATE_FROM_FILE reply missing thread cap");
        destroy_partial_child(process_handle, ipc_buf);
        return None;
    }
    let thread_cap = reply_caps[1];

    // pwrmgr's only surface is the gated SHUTDOWN/REBOOT IPC; it
    // owns IoPortRange/SbiControl/ACPI frames directly and never
    // touches the filesystem. Spawn with no namespace cap.
    if !configure_child_namespace(
        process_handle,
        system_root_cap,
        init_self_cspace,
        NsPolicy::None,
        None,
        ipc_buf,
    )
    {
        let _ = syscall::cap_delete(thread_cap);
        return None;
    }

    // Service endpoint: init owns the RECV source; pwrmgr receives a
    // derived RECV copy. Source stays in init's CSpace for deriving
    // tokened SENDs (SHUTDOWN_AUTHORITY) to authorized consumers.
    let Ok(pwrmgr_service_ep) = syscall::cap_create_endpoint(crate::endpoint_slab())
    else
    {
        log("pwrmgr: cannot create service endpoint");
        destroy_partial_child(process_handle, ipc_buf);
        let _ = syscall::cap_delete(thread_cap);
        return None;
    };
    let Ok(service_copy) = syscall::cap_derive(pwrmgr_service_ep, syscall::RIGHTS_ALL)
    else
    {
        log("pwrmgr: service endpoint derive failed");
        let _ = syscall::cap_delete(pwrmgr_service_ep);
        destroy_partial_child(process_handle, ipc_buf);
        let _ = syscall::cap_delete(thread_cap);
        return None;
    };

    // Arch authority cap: IoPortRange on x86_64, SbiControl on
    // RISC-V. Both are present in InitInfo's hw caps; on the absent arch
    // the corresponding slot is zero.
    let arch_cap_source: u32 = {
        #[cfg(target_arch = "x86_64")]
        {
            crate::find_cap_by_type(info, CapType::IoPortRange).unwrap_or(0)
        }
        #[cfg(target_arch = "riscv64")]
        {
            info.sbi_control_cap
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
        {
            let _ = info;
            0
        }
    };
    let arch_cap_copy = if arch_cap_source != 0
    {
        syscall::cap_derive(arch_cap_source, syscall::RIGHTS_ALL).unwrap_or(0)
    }
    else
    {
        0
    };

    if !start_process(
        process_handle,
        ipc_buf,
        "phase 3: pwrmgr started; serving bootstrap",
        "phase 3: pwrmgr START_PROCESS failed",
    )
    {
        let _ = syscall::cap_delete(pwrmgr_service_ep);
        let _ = syscall::cap_delete(thread_cap);
        return None;
    }

    // Round 1: service endpoint + (optionally) arch cap. The ACPI
    // region rounds (x86_64 only) follow when present.
    let acpi_present = info.acpi_region_frame_count > 0;
    let mut r1_caps = [0u32; 2];
    let mut r1_cap_count: usize = 1;
    r1_caps[0] = service_copy;
    let mut presence: u64 = 0;
    if arch_cap_copy != 0
    {
        presence |= 1u64 << 0;
        r1_caps[r1_cap_count] = arch_cap_copy;
        r1_cap_count += 1;
    }
    let r1_done = !acpi_present;
    if !serve(
        bootstrap_ep,
        child_token,
        ipc_buf,
        r1_done,
        &r1_caps[..r1_cap_count],
        &[presence, u64::from(ipc::PWRMGR_LABELS_VERSION)],
        "pwrmgr: bootstrap round 1 failed",
    )
    {
        let _ = syscall::cap_delete(pwrmgr_service_ep);
        let _ = syscall::cap_delete(thread_cap);
        return None;
    }

    if acpi_present
    {
        let ar_start = info.acpi_region_frame_base;
        let ar_end = ar_start + info.acpi_region_frame_count;
        // Collect ACPI region metadata from descriptor array.
        let mut regions: [(u32, u64, u64); MAX_ACPI_REGION_CAPS] =
            [(0, 0, 0); MAX_ACPI_REGION_CAPS];
        let mut region_count: usize = 0;
        for d in crate::descriptors(info)
        {
            if d.cap_type == CapType::Frame
                && d.slot >= ar_start
                && d.slot < ar_end
                && region_count < MAX_ACPI_REGION_CAPS
            {
                regions[region_count] = (d.slot, d.aux0, d.aux1);
                region_count += 1;
            }
        }

        let mut idx = 0;
        while idx < region_count
        {
            let batch_end = (idx + 4).min(region_count);
            let batch_count = batch_end - idx;
            let mut caps = [0u32; 4];
            let mut data = [0u64; 2 + 4 * 2];
            data[0] = kind::ACPI_REGION;
            data[1] = batch_count as u64;
            for j in 0..batch_count
            {
                let (slot, base, size) = regions[idx + j];
                if let Ok(c) = syscall::cap_derive(slot, syscall::RIGHTS_ALL)
                {
                    caps[j] = c;
                }
                data[2 + j * 2] = base;
                data[3 + j * 2] = size;
            }
            let is_last = batch_end == region_count;
            if !serve(
                bootstrap_ep,
                child_token,
                ipc_buf,
                is_last,
                &caps[..batch_count],
                &data[..2 + batch_count * 2],
                "pwrmgr: bootstrap ACPI region round failed",
            )
            {
                let _ = syscall::cap_delete(pwrmgr_service_ep);
                let _ = syscall::cap_delete(thread_cap);
                return None;
            }
            idx = batch_end;
        }
    }

    Some(PwrmgrSpawn {
        service_ep: pwrmgr_service_ep,
        thread_cap,
    })
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
    let vfsd_frame_cap = crate::find_module_by_name(info, b"vfsd")?;
    let vfsd_module_copy = module_spawn_copy(vfsd_frame_cap)?;

    let (tokened_creator, child_token) = derive_tokened_creator(bootstrap_ep)?;

    let create_msg = IpcMessage::builder(procmgr_labels::CREATE_PROCESS)
        .cap(vfsd_module_copy)
        .cap(tokened_creator)
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
    let Ok(registry_copy) = syscall::cap_derive_token(
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
        child_token,
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
        child_token,
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
/// Returns `(process_handle, child_token)` on success.
pub fn create_svcmgr_from_file(
    procmgr_ep: u32,
    bootstrap_ep: u32,
    system_root_cap: u32,
    init_self_cspace: u32,
    ipc_buf: *mut u64,
) -> Option<(u32, u64)>
{
    let walked = walk::walk_to_file(system_root_cap, b"/services/svcmgr", 0xFFFF, ipc_buf)?;

    let (tokened_creator, child_token) = derive_tokened_creator(bootstrap_ep)?;

    let msg = IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE)
        .word(0, walked.size)
        .cap(walked.file_cap)
        .cap(tokened_creator)
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

    // Post-#21 svcmgr is the supervisor and holds the universal
    // root: it reads `/config/svcmgr/services/*.svc` at handover,
    // walks the recipe's `binary` path (typically
    // `/services/<name>` or `/programs/<name>`) for first-launch of
    // defined-but-unregistered
    // services, and applies per-service namespace attenuation from
    // each `.svc` recipe when configuring the child. Init no longer
    // pre-attenuates svcmgr to `/bin`.
    if !configure_child_namespace(
        process_handle,
        system_root_cap,
        init_self_cspace,
        NsPolicy::Universal,
        None,
        ipc_buf,
    )
    {
        return None;
    }

    Some((process_handle, child_token))
}

/// Endpoint set handed to svcmgr in its bootstrap round.
#[allow(clippy::struct_field_names)]
pub struct SvcmgrHandoverCaps
{
    pub svcmgr_service_ep: u32,
    pub svcmgr_bootstrap_ep: u32,
}

/// Start svcmgr, then serve its bootstrap.
pub fn setup_and_start_svcmgr(
    bootstrap_ep: u32,
    process_handle: u32,
    child_token: u64,
    handover: &SvcmgrHandoverCaps,
    ipc_buf: *mut u64,
)
{
    if !start_process(
        process_handle,
        ipc_buf,
        "phase 3: svcmgr started; serving bootstrap",
        "phase 3: svcmgr START_PROCESS failed",
    )
    {
        return;
    }

    let Ok(service_copy) = syscall::cap_derive(handover.svcmgr_service_ep, syscall::RIGHTS_ALL)
    else
    {
        return;
    };
    let Ok(boot_copy) = syscall::cap_derive(handover.svcmgr_bootstrap_ep, syscall::RIGHTS_ALL)
    else
    {
        return;
    };

    // One round: [service, bootstrap_ep].
    // (log + procmgr auto-delivered via ProcessInfo.)
    let _ = serve(
        bootstrap_ep,
        child_token,
        ipc_buf,
        true,
        &[service_copy, boot_copy],
        &[],
        "phase 3: svcmgr bootstrap failed",
    );
}

/// Minimal v3 `REGISTER_SERVICE` payload: name + thread cap.
///
/// Post-#21 the recipe (binary, argv, env, restart policy,
/// criticality, namespace shape, seed names) lives on disk at
/// `/config/svcmgr/services/<name>.svc`. The wire conveys only what
/// cannot be on disk: which named recipe this running process
/// implements, and the thread cap svcmgr binds death-notification on.
pub struct ServiceRegistration<'a>
{
    pub name: &'a [u8],
    pub thread_cap: u32,
}

/// Register a currently-running service with svcmgr via the v3
/// [`svcmgr_labels::REGISTER_SERVICE`] wire (`word 0` =
/// `SVCMGR_LABELS_VERSION`, `word 1` = `name_len`, `words 2..` = name
/// bytes, `caps[0]` = thread cap). svcmgr parks the entry and
/// reconciles against `/config/svcmgr/services/` on `HANDOVER_COMPLETE`.
pub fn register_service(svcmgr_ep: u32, ipc_buf: *mut u64, reg: &ServiceRegistration)
{
    let name_len = reg.name.len();
    if name_len == 0 || name_len > 32 || reg.thread_cap == 0
    {
        log("phase 3: REGISTER_SERVICE caller bug (empty name or zero thread cap)");
        return;
    }
    let name_words = name_len.div_ceil(8);
    let data_count = 2 + name_words;

    let msg = IpcMessage::builder(svcmgr_labels::REGISTER_SERVICE)
        .word(0, u64::from(ipc::SVCMGR_LABELS_VERSION))
        .word(1, name_len as u64)
        .bytes(2, reg.name)
        .word_count(data_count)
        .cap(reg.thread_cap)
        .build();

    // SAFETY: ipc_buf is the caller's registered IPC buffer.
    match unsafe { ipc::ipc_call(svcmgr_ep, &msg, ipc_buf) }
    {
        Ok(reply) if reply.label == 0 =>
        {}
        _ => log("phase 3: REGISTER_SERVICE failed"),
    }
}

// ── Phase 3 orchestration ───────────────────────────────────────────────────

/// Phase 3: spawn svcmgr, bring up the wallclock chain, spawn pwrmgr,
/// register pwrmgr with svcmgr (v3 wire), publish the named caps
/// post-#21 consumers resolve from `/config/svcmgr/services/<name>.svc` `seed = ...`
/// lines, then signal `HANDOVER_COMPLETE` so svcmgr scans
/// `/config/svcmgr/services/`. On a normal boot the defined services there are
/// all init-registered (bind-only); svcmgr's launch path fires only for staged
/// test recipes (svctest / usertest, and crasher co-staged with svctest).
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub fn phase3_svcmgr_handover(
    info: &InitInfo,
    procmgr_ep: u32,
    bootstrap_ep: u32,
    svcmgr_service_ep: u32,
    devmgr_registry_ep: u32,
    system_root_cap: u32,
    rootfs_root_cap: u32,
    mut thread_caps: ServiceThreadCaps,
    ipc_buf: *mut u64,
    init_logd_thread_cap: u32,
    init_ipc_buf_cap: u32,
) -> !
{
    let init_self_cspace = info.cspace_cap;

    // svcmgr's service endpoint is created in early init
    // (before bootstrap_procmgr) so procmgr can receive an un-tokened
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
    let Some((svcmgr_handle, svcmgr_token)) = create_svcmgr_from_file(
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

    let handover = SvcmgrHandoverCaps {
        svcmgr_service_ep,
        svcmgr_bootstrap_ep,
    };
    setup_and_start_svcmgr(
        bootstrap_ep,
        svcmgr_handle,
        svcmgr_token,
        &handover,
        ipc_buf,
    );

    // Hand devmgr a least-privilege `/services/drivers/` subtree cap so
    // it can lazily walk + spawn its on-disk driver binaries (today: the
    // per-arch RTC). Ack-only handshake; init does not block on driver
    // work. Best-effort: a failure here means timed will see NO_DEVICE
    // on its first QUERY_RTC_DEVICE and degrade to its no-RTC path; the
    // rest of Phase 3 proceeds normally.
    set_drivers_dir_on_devmgr(devmgr_registry_ep, system_root_cap, ipc_buf);

    // Wallclock chain: timed (init-spawned, svcmgr-published) consumes
    // devmgr's QUERY_RTC_DEVICE for the per-arch RTC driver, which devmgr
    // loads lazily from disk after the SET_DRIVERS_DIR handshake above.
    // Failures are logged but do not abort phase 3 — svctest tolerates
    // `SystemTime::now()` returning UNIX_EPOCH and exercises the live
    // path only when the chain came up.
    thread_caps.timed = bring_up_timed(
        procmgr_ep,
        bootstrap_ep,
        svcmgr_service_ep,
        devmgr_registry_ep,
        system_root_cap,
        init_self_cspace,
        ipc_buf,
    )
    .unwrap_or(0);

    let pwrmgr_spawn = create_and_start_pwrmgr(
        info,
        procmgr_ep,
        bootstrap_ep,
        system_root_cap,
        init_self_cspace,
        ipc_buf,
    );
    let (pwrmgr_service_ep, pwrmgr_thread_cap) = if let Some(s) = pwrmgr_spawn
    {
        (s.service_ep, s.thread_cap)
    }
    else
    {
        log("phase 3: pwrmgr not available; naked xtask run will not exit cleanly");
        (0, 0)
    };

    // Derive a PUBLISH_AUTHORITY-tokened SEND_GRANT on svcmgr's
    // service ep so init can publish the named caps post-#21 consumers
    // resolve through `/config/svcmgr/services/<name>.svc` `seed = ...`.
    // `RIGHTS_SEND_GRANT` (not bare SEND): PUBLISH_ENDPOINT carries the
    // value cap in the message, and the IPC kernel requires the GRANT
    // bit on the caller's send-cap to transfer caps. After the four
    // publications init drops this cap; runtime consumers use the
    // un-tokened SEND seeded into `ProcessInfo.service_registry_cap`.
    let publish_cap = syscall::cap_derive_token(
        svcmgr_service_ep,
        syscall::RIGHTS_SEND_GRANT,
        svcmgr_labels::PUBLISH_AUTHORITY,
    )
    .ok();

    // 1. rootfs.root — tokened SEND on the root filesystem's namespace
    //    endpoint at its root directory. FS-driver-agnostic by design:
    //    today fatfs, tomorrow any other FS driver, same name.
    if let Some(cap) = publish_cap
        && rootfs_root_cap != 0
        && let Ok(derived) = syscall::cap_derive(rootfs_root_cap, syscall::RIGHTS_SEND)
        && !svcmgr_publish(cap, ipc::published_names::ROOTFS_ROOT, derived, ipc_buf)
    {
        log("phase 3: publish rootfs.root failed");
        let _ = syscall::cap_delete(derived);
    }

    // 2/3. pwrmgr.shutdown + pwrmgr.deny — derived from pwrmgr's
    //      service endpoint with the SHUTDOWN_AUTHORITY token bit set
    //      (or a non-AUTHORITY sentinel `1` for the negative-test
    //      twin). Plain SEND would let consumers re-tokenize the cap
    //      and defeat the gate; cap_derive_token rejects sources with
    //      a non-zero token, so the AUTHORITY shape stays sealed.
    if let Some(cap) = publish_cap
        && pwrmgr_service_ep != 0
    {
        if let Ok(auth) = syscall::cap_derive_token(
            pwrmgr_service_ep,
            syscall::RIGHTS_SEND,
            ipc::pwrmgr_labels::SHUTDOWN_AUTHORITY,
        )
        {
            if !svcmgr_publish(cap, ipc::published_names::PWRMGR_SHUTDOWN, auth, ipc_buf)
            {
                log("phase 3: publish pwrmgr.shutdown failed");
                let _ = syscall::cap_delete(auth);
            }
        }
        else
        {
            log("phase 3: derive pwrmgr.shutdown cap failed");
        }
        if let Ok(deny) = syscall::cap_derive_token(pwrmgr_service_ep, syscall::RIGHTS_SEND, 1)
        {
            if !svcmgr_publish(cap, ipc::published_names::PWRMGR_DENY, deny, ipc_buf)
            {
                log("phase 3: publish pwrmgr.deny failed");
                let _ = syscall::cap_delete(deny);
            }
        }
        else
        {
            log("phase 3: derive pwrmgr.deny cap failed");
        }
    }

    // 4. svcmgr — tokened SEND on svcmgr's own service endpoint. Used
    //    by crasher.svc's `seed = svcmgr` line so the launched
    //    crasher receives the same cap shape today's hard-coded
    //    bundle gave it. Per-publisher attenuation (so children can
    //    only QUERY, not PUBLISH) lives in the SEND-without-AUTHORITY
    //    shape — same as `ProcessInfo.service_registry_cap`.
    if let Some(cap) = publish_cap
        && let Ok(svc_send) = syscall::cap_derive(svcmgr_service_ep, syscall::RIGHTS_SEND)
        && !svcmgr_publish(cap, ipc::published_names::SVCMGR, svc_send, ipc_buf)
    {
        log("phase 3: publish svcmgr failed");
        let _ = syscall::cap_delete(svc_send);
    }

    // 5. devmgr.registry — `REGISTRY_QUERY_AUTHORITY`-tokened SEND on
    //    devmgr's registry endpoint. Today's consumer is
    //    `programs/fb-charset` via `seed = devmgr.registry`; future
    //    non-init consumers of devmgr's discovery surface use the same
    //    name. The token bit survives svcmgr's plain `cap_derive` in
    //    `registry_lookup_derived`.
    if let Some(cap) = publish_cap
        && devmgr_registry_ep != 0
    {
        match syscall::cap_derive_token(
            devmgr_registry_ep,
            syscall::RIGHTS_SEND,
            ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY,
        )
        {
            Ok(derived) =>
            {
                if !svcmgr_publish(cap, ipc::published_names::DEVMGR_REGISTRY, derived, ipc_buf)
                {
                    log("phase 3: publish devmgr.registry failed");
                    let _ = syscall::cap_delete(derived);
                }
            }
            Err(_) => log("phase 3: derive devmgr.registry cap failed"),
        }
    }

    if let Some(cap) = publish_cap
    {
        let _ = syscall::cap_delete(cap);
    }

    // Register every foundational service init bootstrapped with
    // svcmgr (v3 wire: name + thread cap). svcmgr's reconciliation
    // path pairs each name with the matching `.svc` recipe on disk
    // and binds death-notification. Zero in a slot means init could
    // not capture the thread cap (e.g. the spawn failed or the
    // helper had no cap to share); the register call is then
    // skipped and the recipe ⇒ `registered without definition`
    // entries are absent rather than surfacing as orphans.
    let registrations: &[(&[u8], u32)] = &[
        (b"memmgr", thread_caps.memmgr),
        (b"procmgr", thread_caps.procmgr),
        (b"devmgr", thread_caps.devmgr),
        (b"vfsd", thread_caps.vfsd),
        (b"logd", thread_caps.logd),
        (b"timed", thread_caps.timed),
        (b"pwrmgr", pwrmgr_thread_cap),
    ];
    for (name, thread_cap) in registrations
    {
        if *thread_cap != 0
        {
            register_service(
                svcmgr_service_ep,
                ipc_buf,
                &ServiceRegistration {
                    name,
                    thread_cap: *thread_cap,
                },
            );
        }
    }

    let handover_msg = IpcMessage::new(svcmgr_labels::HANDOVER_COMPLETE);
    // SAFETY: ipc_buf is caller's registered IPC buffer.
    match unsafe { ipc::ipc_call(svcmgr_service_ep, &handover_msg, ipc_buf) }
    {
        Ok(reply) if reply.label == 0 => log("phase 3: handover complete"),
        _ => log("phase 3: handover failed"),
    }

    // Reap-handoff: move init's kernel-object caps + every reclaimable
    // Frame cap to procmgr. Procmgr binds a death-EQ on init's main
    // thread; when this function returns into `sys_thread_exit`
    // immediately below, procmgr's reap path tears init's AS/CSpace
    // /Threads down and donates the Frame caps to memmgr's pool.
    handoff_to_procmgr_reap(
        info,
        procmgr_ep,
        init_logd_thread_cap,
        init_ipc_buf_cap,
        ipc_buf,
    );

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

/// Derive a transient full-rights copy of a boot-module Frame cap for a
/// `CREATE_PROCESS` spawn. Init retains the original — it is the sole owner
/// of the module-source `FrameObject` and donates it to memmgr at reap. The
/// loader borrows this copy (deriving a read-only child for the load-time
/// mapping) and deletes it once the ELF is loaded.
fn module_spawn_copy(module_frame_cap: u32) -> Option<u32>
{
    syscall::cap_derive(module_frame_cap, syscall::RIGHTS_ALL).ok()
}

/// Move init's kernel-object caps + every reclaimable Frame cap to
/// procmgr via `REGISTER_INIT_TEARDOWN`, then signal
/// `INIT_TEARDOWN_DONE`. IPC cap-transfer MOVES caps, so after this
/// returns init's `CSpace` no longer holds the transferred slots.
///
/// Failures here are logged but otherwise non-fatal — init still calls
/// `sys_thread_exit` afterward, just leaving the un-transferred caps
/// to cascade through `CSpace` teardown to the kernel buddy on eventual
/// cap death.
fn handoff_to_procmgr_reap(
    info: &InitInfo,
    procmgr_ep: u32,
    init_logd_thread_cap: u32,
    init_ipc_buf_cap: u32,
    ipc_buf: *mut u64,
)
{
    // Round 1: kernel-object caps. `data[0] = 1` distinguishes from
    // subsequent donate-only rounds.
    let round1 = IpcMessage::builder(procmgr_labels::REGISTER_INIT_TEARDOWN)
        .word(0, 1)
        .cap(info.aspace_cap)
        .cap(info.cspace_cap)
        .cap(info.thread_cap)
        .cap(init_logd_thread_cap)
        .build();
    // SAFETY: ipc_buf is init's registered IPC buffer; procmgr_ep carries SEND|GRANT.
    if let Ok(reply) = unsafe { ipc::ipc_call(procmgr_ep, &round1, ipc_buf) }
    {
        if reply.label != ipc::procmgr_errors::SUCCESS
        {
            log("reap-handoff: procmgr refused kernel-object round; aborting handoff");
            return;
        }
    }
    else
    {
        log("reap-handoff: kernel-object round IPC failed; aborting handoff");
        return;
    }

    // Donate every owns_memory Frame cap init solely holds, streamed in
    // MSG_CAP_SLOTS_MAX-sized rounds. Two disjoint sources:
    //  - explicit InitInfo ranges (not in the descriptor array): init's ELF
    //    segments, user stack, the InitInfo region, and the IPC buffer page.
    //  - a descriptor walk for the unnamed reclaimable Frame caps — the
    //    bootloader and bundle reclaim ranges plus the AP-trampoline late
    //    cap — which carry no named InitInfo slot.
    // The walk skips caps init does not solely own or that are not RAM: the
    // usable-RAM range (memmgr owns it, forwarded at bootstrap) and the
    // firmware read-only caps (RSDP/ACPI/DTB; owns_memory=false). Boot-module
    // Frame caps are included: init is their sole owner once every loader has
    // copied the ELF and dropped its borrowed read-only derivation, so they
    // donate to memmgr here like any other reclaimable frame.
    let seg = info.segment_frame_base..info.segment_frame_base + info.segment_frame_count;
    let stack =
        info.init_stack_frame_base..info.init_stack_frame_base + info.init_stack_frame_count;
    let inf = info.init_info_frame_base..info.init_info_frame_base + info.init_info_frame_count;

    let mem_lo = info.memory_frame_base;
    let mem_hi = info
        .memory_frame_base
        .saturating_add(info.memory_frame_count);
    let acpi_lo = info.acpi_region_frame_base;
    let acpi_hi = info
        .acpi_region_frame_base
        .saturating_add(info.acpi_region_frame_count);

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
        if init_ipc_buf_cap != 0
        {
            push(init_ipc_buf_cap);
        }
        for desc in crate::descriptors(info)
        {
            if desc.cap_type != CapType::Frame
            {
                continue;
            }
            let s = desc.slot;
            if s >= mem_lo && s < mem_hi
            {
                continue;
            }
            if (info.acpi_rsdp_frame_cap != 0 && s == info.acpi_rsdp_frame_cap)
                || (info.dtb_frame_cap != 0 && s == info.dtb_frame_cap)
                || (info.acpi_region_frame_count != 0 && s >= acpi_lo && s < acpi_hi)
            {
                continue;
            }
            push(s);
        }
    }
    if cn > 0
    {
        // SAFETY: ipc_buf is registered; procmgr_ep carries SEND|GRANT.
        unsafe { send_teardown_round(procmgr_ep, &chunk[..cn], ipc_buf) };
    }

    // Signal the cap stream is closed. Procmgr arms the death-EQ
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

// ── logd spawn ──────────────────────────────────────────────────────────────

/// Spawn real-logd from `/services/logd` at the end of Phase 2, immediately
/// after the root mount completes. Init transfers:
///
/// * a RECV cap on the master log endpoint (so logd becomes the
///   receive-side; init-logd terminates as part of the handover);
/// * a SEND cap on the same endpoint (single-use, for the
///   `HANDOVER_PULL` IPC to init-logd);
/// * a tokened SEND cap on procmgr carrying
///   `procmgr_labels::DEATH_EQ_AUTHORITY` (for `REGISTER_DEATH_EQ`);
/// * a SEND cap on devmgr's registry endpoint carrying
///   `devmgr_labels::REGISTRY_QUERY_AUTHORITY`, with which logd resolves
///   the serial driver (via `QUERY_SERIAL_DEVICE`) and routes its own
///   diagnostics and the per-sender log lines it receives through the
///   driver's `SERIAL_WRITE_BYTES`. Logd holds no UART hardware authority
///   and cannot route diagnostics through `seraph::log!` because it IS the
///   log receiver.
///
/// Returns `true` on successful spawn + bootstrap; `false` on any
/// failure (logged at fault; init continues without real-logd, with
/// init-logd running indefinitely until init's process is otherwise
/// reaped).
// too_many_lines: one transactional spawn path; splitting would push
// most of the body into helpers and obscure the cap-flow sequencing.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn create_and_start_logd(
    procmgr_ep: u32,
    procmgr_service_ep_source: u32,
    bootstrap_ep: u32,
    log_ep: u32,
    devmgr_registry_ep: u32,
    system_root_cap: u32,
    init_self_cspace: u32,
    ipc_buf: *mut u64,
) -> Option<u32>
{
    let walked = walk::walk_to_file(system_root_cap, b"/services/logd", 0xFFFF, ipc_buf)?;

    let (tokened_creator, child_token) = derive_tokened_creator(bootstrap_ep)?;

    let create_msg = IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE)
        .word(0, walked.size)
        .cap(walked.file_cap)
        .cap(tokened_creator)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_ep, &create_msg, ipc_buf) })
    else
    {
        log("logd: CREATE_FROM_FILE ipc_call failed");
        return None;
    };
    if reply.label != 0
    {
        log("logd: CREATE_FROM_FILE error");
        return None;
    }
    let reply_caps = reply.caps();
    if reply_caps.len() < 2
    {
        log("logd: CREATE_FROM_FILE reply missing caps");
        return None;
    }
    let process_handle = reply_caps[0];
    let thread_cap = reply_caps[1];

    // logd owns the master log endpoint RECV plus a devmgr-registry query
    // cap (to resolve the serial driver via QUERY_SERIAL_DEVICE); its
    // serial output is driver-mediated, so it holds no UART hardware
    // authority. It does no filesystem I/O. Spawn with no namespace cap.
    if !configure_child_namespace(
        process_handle,
        system_root_cap,
        init_self_cspace,
        NsPolicy::None,
        None,
        ipc_buf,
    )
    {
        return None;
    }

    // Derive the three bootstrap caps logd needs.
    let Ok(log_recv) = syscall::cap_derive(log_ep, syscall::RIGHTS_ALL)
    else
    {
        log("logd: log_ep RECV derive failed");
        destroy_partial_child(process_handle, ipc_buf);
        return None;
    };
    let Ok(log_handover_send) = syscall::cap_derive(log_ep, syscall::RIGHTS_SEND)
    else
    {
        log("logd: log_ep SEND derive failed");
        let _ = syscall::cap_delete(log_recv);
        destroy_partial_child(process_handle, ipc_buf);
        return None;
    };
    // RIGHTS_SEND_GRANT (not bare SEND): the IPC kernel requires the
    // GRANT bit when the caller transfers any cap in the message, and
    // logd's REGISTER_DEATH_EQ call hands over its `death_eq` cap.
    let Ok(procmgr_death_auth) = syscall::cap_derive_token(
        procmgr_service_ep_source,
        syscall::RIGHTS_SEND_GRANT,
        procmgr_labels::DEATH_EQ_AUTHORITY,
    )
    else
    {
        log("logd: procmgr DEATH_EQ_AUTHORITY derive failed");
        let _ = syscall::cap_delete(log_recv);
        let _ = syscall::cap_delete(log_handover_send);
        destroy_partial_child(process_handle, ipc_buf);
        return None;
    };

    // devmgr-registry query cap: a SEND on devmgr's registry endpoint
    // tokened with REGISTRY_QUERY_AUTHORITY so logd can resolve the serial
    // driver via `QUERY_SERIAL_DEVICE`. logd's serial output is mediated by
    // that driver; it holds no UART hardware authority. A zero registry
    // endpoint yields zero, and logd then buffers received log lines in
    // memory until the driver becomes resolvable.
    let devmgr_registry_query = if devmgr_registry_ep != 0
    {
        syscall::cap_derive_token(
            devmgr_registry_ep,
            syscall::RIGHTS_SEND,
            ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY,
        )
        .unwrap_or(0)
    }
    else
    {
        0
    };

    if !start_process(
        process_handle,
        ipc_buf,
        "phase 2: logd started; serving bootstrap",
        "phase 2: logd START_PROCESS failed",
    )
    {
        let _ = syscall::cap_delete(log_recv);
        let _ = syscall::cap_delete(log_handover_send);
        let _ = syscall::cap_delete(procmgr_death_auth);
        if devmgr_registry_query != 0
        {
            let _ = syscall::cap_delete(devmgr_registry_query);
        }
        return None;
    }

    if !serve(
        bootstrap_ep,
        child_token,
        ipc_buf,
        true,
        &[
            log_recv,
            log_handover_send,
            procmgr_death_auth,
            devmgr_registry_query,
        ],
        &[],
        "logd: bootstrap round failed",
    )
    {
        return None;
    }

    Some(thread_cap)
}

// ── RTC + timed spawn pipeline ──────────────────────────────────────────────

/// Pack a short ASCII name into IPC data words (`pack_name` shape matches
/// `svcmgr::read_tail_name_from_msg`). Returns the word count used.
fn pack_svc_name(name: &[u8], out: &mut [u64; 2]) -> usize
{
    for (i, &b) in name.iter().enumerate()
    {
        out[i / 8] |= u64::from(b) << ((i % 8) * 8);
    }
    name.len().div_ceil(8)
}

/// Publish `(name, send_cap)` to svcmgr via `PUBLISH_ENDPOINT`. `publish_cap`
/// MUST carry `svcmgr_labels::PUBLISH_AUTHORITY` in its token (init mints
/// such caps locally from the un-tokened source it owns on svcmgr's service
/// endpoint). Returns `true` on `svcmgr_errors::SUCCESS`.
fn svcmgr_publish(publish_cap: u32, name: &[u8], send_cap: u32, ipc_buf: *mut u64) -> bool
{
    if publish_cap == 0 || send_cap == 0 || name.is_empty() || name.len() > 16
    {
        return false;
    }
    let mut words = [0u64; 2];
    let word_count = pack_svc_name(name, &mut words);

    let mut builder =
        IpcMessage::builder(svcmgr_labels::PUBLISH_ENDPOINT | ((name.len() as u64) << 16))
            .cap(send_cap);
    for (i, &w) in words.iter().take(word_count).enumerate()
    {
        builder = builder.word(i, w);
    }
    let request = builder.build();

    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(publish_cap, &request, ipc_buf) };
    matches!(reply, Ok(r) if r.label == ipc::svcmgr_errors::SUCCESS)
}

/// Common service-endpoint + RECV-derivation setup for a timed spawn.
/// Init keeps the source slot to mint per-publish SENDs; the child
/// receives a RECV-rights derivation.
fn create_service_endpoint_pair() -> Option<(u32, u32)>
{
    let source = syscall::cap_create_endpoint(crate::endpoint_slab()).ok()?;
    let Ok(recv_cap) = syscall::cap_derive(source, syscall::RIGHTS_RECEIVE)
    else
    {
        let _ = syscall::cap_delete(source);
        return None;
    };
    Some((source, recv_cap))
}

/// Walk + `CREATE_FROM_FILE` for one binary path. Returns
/// `(process_handle, thread_cap, child_token)`; caller owns the thread
/// cap (e.g. for svcmgr `REGISTER_SERVICE`) and is responsible for
/// `destroy_partial_child` on any subsequent failure.
///
/// `policy` and `cwd` are forwarded to `configure_child_namespace`.
/// Service helpers that use this path (e.g. timed) pass `NsPolicy::None`
/// because they do not touch the filesystem after `_start`.
#[allow(clippy::too_many_arguments)]
fn walk_and_create_from_file(
    path: &[u8],
    procmgr_ep: u32,
    bootstrap_ep: u32,
    system_root_cap: u32,
    init_self_cspace: u32,
    policy: NsPolicy,
    cwd: Option<(&[u8], u64)>,
    ipc_buf: *mut u64,
) -> Option<(u32, u32, u64)>
{
    let walked = walk::walk_to_file(system_root_cap, path, 0xFFFF, ipc_buf)?;
    let (tokened_creator, child_token) = derive_tokened_creator(bootstrap_ep)?;
    let create_msg = IpcMessage::builder(procmgr_labels::CREATE_FROM_FILE)
        .word(0, walked.size)
        .cap(walked.file_cap)
        .cap(tokened_creator)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(procmgr_ep, &create_msg, ipc_buf) }.ok()?;
    if reply.label != 0
    {
        return None;
    }
    let reply_caps = reply.caps();
    if reply_caps.len() < 2
    {
        return None;
    }
    let process_handle = reply_caps[0];
    let thread_cap = reply_caps[1];
    if !configure_child_namespace(
        process_handle,
        system_root_cap,
        init_self_cspace,
        policy,
        cwd,
        ipc_buf,
    )
    {
        let _ = syscall::cap_delete(thread_cap);
        return None;
    }
    Some((process_handle, thread_cap, child_token))
}

/// Spawn `/services/timed` and serve its single bootstrap round. Returns
/// the init-owned service-endpoint source cap; init derives a SEND
/// from it for the `timed` publish.
/// Timed-side result of [`create_and_start_timed`].
///
/// `service_ep` is the init-owned service-endpoint source cap (used
/// to derive the SEND init publishes as `timed`). `thread_cap` is
/// timed's main thread in init's `CSpace`, registered with svcmgr so
/// the supervisor can bind death-notification.
pub struct TimedSpawn
{
    pub service_ep: u32,
    pub thread_cap: u32,
}

pub fn create_and_start_timed(
    procmgr_ep: u32,
    bootstrap_ep: u32,
    devmgr_registry_ep: u32,
    system_root_cap: u32,
    init_self_cspace: u32,
    ipc_buf: *mut u64,
) -> Option<TimedSpawn>
{
    let (svc_source, svc_recv) = create_service_endpoint_pair()?;

    // timed resolves the RTC via devmgr's QUERY_RTC_DEVICE on a
    // REGISTRY_QUERY_AUTHORITY-tokened SEND copy of devmgr's registry
    // endpoint, then serves GET_WALL_TIME. No filesystem access.
    let Ok(devmgr_registry_copy) = syscall::cap_derive_token(
        devmgr_registry_ep,
        syscall::RIGHTS_SEND,
        ipc::devmgr_labels::REGISTRY_QUERY_AUTHORITY,
    )
    else
    {
        let _ = syscall::cap_delete(svc_recv);
        let _ = syscall::cap_delete(svc_source);
        log("timed: devmgr registry token derive failed");
        return None;
    };

    let Some((process_handle, thread_cap, child_token)) = walk_and_create_from_file(
        b"/services/timed",
        procmgr_ep,
        bootstrap_ep,
        system_root_cap,
        init_self_cspace,
        NsPolicy::None,
        None,
        ipc_buf,
    )
    else
    {
        let _ = syscall::cap_delete(devmgr_registry_copy);
        let _ = syscall::cap_delete(svc_recv);
        let _ = syscall::cap_delete(svc_source);
        log("timed: walk + CREATE_FROM_FILE failed");
        return None;
    };

    if !start_process(
        process_handle,
        ipc_buf,
        "phase 3: timed started; serving bootstrap",
        "phase 3: timed START_PROCESS failed",
    )
    {
        let _ = syscall::cap_delete(devmgr_registry_copy);
        let _ = syscall::cap_delete(svc_recv);
        let _ = syscall::cap_delete(svc_source);
        let _ = syscall::cap_delete(thread_cap);
        destroy_partial_child(process_handle, ipc_buf);
        return None;
    }

    if !serve(
        bootstrap_ep,
        child_token,
        ipc_buf,
        true,
        &[svc_recv, devmgr_registry_copy],
        &[],
        "timed: bootstrap round failed",
    )
    {
        // Best-effort delete: serve_round may have transferred caps before
        // failing. Child has been started; cannot destroy safely. It will
        // exit on the receive-side failure and procmgr will reap.
        let _ = syscall::cap_delete(svc_recv);
        let _ = syscall::cap_delete(devmgr_registry_copy);
        let _ = syscall::cap_delete(svc_source);
        let _ = syscall::cap_delete(thread_cap);
        return None;
    }

    Some(TimedSpawn {
        service_ep: svc_source,
        thread_cap,
    })
}

/// Phase 3 sub-step: hand devmgr a least-privilege
/// `/services/drivers/` subtree cap so it can lazily walk + spawn
/// on-disk driver binaries (today: the per-arch RTC).
///
/// Walks `system_root_cap` to `/services/drivers/` at `LOOKUP | READ`
/// rights, then sends `devmgr_labels::SET_DRIVERS_DIR` on a fresh
/// `INIT_BIND_AUTHORITY`-tokened copy of `devmgr_registry_ep` (only
/// init holds this verb bit; the `REGISTRY_QUERY_AUTHORITY`-only copy
/// published to svcmgr cannot send this label).
///
/// devmgr's handler is ack-only: it stashes the cap and replies
/// SUCCESS immediately. No driver walk or spawn happens in the
/// handshake's blocking window — those fire lazily on the first
/// `QUERY_RTC_DEVICE`. Init is not in the critical path of any
/// driver spawn.
///
/// Best-effort: any failure (walk fails, devmgr replies a non-SUCCESS
/// code, transport error) is logged and Phase 3 continues. The
/// system boots without a wallclock; timed sees `NO_DEVICE` and
/// degrades to its no-RTC path.
fn set_drivers_dir_on_devmgr(devmgr_registry_ep: u32, system_root_cap: u32, ipc_buf: *mut u64)
{
    if devmgr_registry_ep == 0 || system_root_cap == 0
    {
        log("phase 3: SET_DRIVERS_DIR skipped (no devmgr or no system root)");
        return;
    }

    // Attenuated rights: only what devmgr needs to walk into a
    // subdirectory and read file contents. Visibility-gating bits are
    // intentionally omitted; the namespace server intersects per hop.
    let rights = u64::from(namespace_protocol::rights::LOOKUP | namespace_protocol::rights::READ);
    let Some(drivers_dir) =
        walk::walk_to_dir(system_root_cap, b"/services/drivers", rights, ipc_buf)
    else
    {
        log("phase 3: SET_DRIVERS_DIR walk to /services/drivers failed; RTC unavailable");
        return;
    };

    // `ipc::ipc_call` requires SEND+GRANT on the endpoint cap when the
    // message carries caps (`drivers_dir` here); use
    // `RIGHTS_SEND_GRANT`. The `devmgr.registry` cap init publishes for
    // other services to look up deliberately omits the GRANT bit so
    // client callers cannot transfer caps in queries; init's own
    // privileged copy includes it for this single transfer.
    let Ok(init_bind_ep) = syscall::cap_derive_token(
        devmgr_registry_ep,
        syscall::RIGHTS_SEND_GRANT,
        ipc::devmgr_labels::INIT_BIND_AUTHORITY,
    )
    else
    {
        log("phase 3: SET_DRIVERS_DIR INIT_BIND_AUTHORITY derive failed; RTC unavailable");
        let _ = syscall::cap_delete(drivers_dir);
        return;
    };

    let msg = IpcMessage::builder(ipc::devmgr_labels::SET_DRIVERS_DIR)
        .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
        .cap(drivers_dir)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let result = unsafe { ipc::ipc_call(init_bind_ep, &msg, ipc_buf) };
    let _ = syscall::cap_delete(init_bind_ep);

    match result
    {
        Ok(reply) if reply.label == ipc::devmgr_errors::SUCCESS =>
        {
            // Kernel transferred `drivers_dir` to devmgr; nothing
            // for init to clean up.
            log("phase 3: SET_DRIVERS_DIR handshake ok");
        }
        Ok(_reply) =>
        {
            // Devmgr replied an error after the kernel transferred
            // the cap. Per the SET_DRIVERS_DIR contract, devmgr's
            // error paths release the delivered cap themselves.
            log("phase 3: SET_DRIVERS_DIR rejected; RTC unavailable");
        }
        Err(_) =>
        {
            // ipc_call returned before the kernel committed the
            // transfer; the source slot still owns `drivers_dir`
            // and must be released.
            let _ = syscall::cap_delete(drivers_dir);
            log("phase 3: SET_DRIVERS_DIR ipc_call error; RTC unavailable");
        }
    }
}

/// Phase 3 sub-step: spawn timed and publish it as `timed`. The RTC
/// driver itself is loaded by devmgr from the on-disk rootfs inside
/// the [`set_drivers_dir_on_devmgr`] handshake (above), between
/// devmgr's `ipc_reply` and its next `ipc_recv`; by the time `timed`
/// queries [`ipc::devmgr_labels::QUERY_RTC_DEVICE`] against the
/// `REGISTRY_QUERY_AUTHORITY`-tokened copy of `devmgr_registry_ep`
/// delivered in its bootstrap round, devmgr already holds `rtc_ep`
/// (or the sticky-failure state and replies `NO_DEVICE`). Init's
/// PUBLISH_AUTHORITY-tokened cap is derived from `svcmgr_service_ep`
/// (the un-tokened source init already owns). All failures are
/// logged; the function never aborts phase 3 — a degraded wall-clock
/// leaves `SystemTime::now()` returning `UNIX_EPOCH` but the rest of
/// svctest still runs.
pub fn bring_up_timed(
    procmgr_ep: u32,
    bootstrap_ep: u32,
    svcmgr_service_ep: u32,
    devmgr_registry_ep: u32,
    system_root_cap: u32,
    init_self_cspace: u32,
    ipc_buf: *mut u64,
) -> Option<u32>
{
    // RIGHTS_SEND_GRANT (not bare SEND): PUBLISH_ENDPOINT carries the
    // service's SEND cap in the message, and the IPC kernel requires the
    // GRANT bit on the caller's send-cap to transfer caps.
    let Ok(publish_cap) = syscall::cap_derive_token(
        svcmgr_service_ep,
        syscall::RIGHTS_SEND_GRANT,
        svcmgr_labels::PUBLISH_AUTHORITY,
    )
    else
    {
        log("phase 3: timed PUBLISH_AUTHORITY derive failed");
        return None;
    };

    let Some(timed_spawn) = create_and_start_timed(
        procmgr_ep,
        bootstrap_ep,
        devmgr_registry_ep,
        system_root_cap,
        init_self_cspace,
        ipc_buf,
    )
    else
    {
        let _ = syscall::cap_delete(publish_cap);
        return None;
    };

    let Ok(timed_publish_send) = syscall::cap_derive(timed_spawn.service_ep, syscall::RIGHTS_SEND)
    else
    {
        log("phase 3: timed publish SEND derive failed");
        let _ = syscall::cap_delete(timed_spawn.thread_cap);
        let _ = syscall::cap_delete(publish_cap);
        return None;
    };
    if !svcmgr_publish(publish_cap, b"timed", timed_publish_send, ipc_buf)
    {
        log("phase 3: timed publish failed");
        let _ = syscall::cap_delete(timed_publish_send);
        let _ = syscall::cap_delete(timed_spawn.thread_cap);
        let _ = syscall::cap_delete(publish_cap);
        return None;
    }
    log("phase 3: timed published");

    let _ = syscall::cap_delete(publish_cap);
    Some(timed_spawn.thread_cap)
}
