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

// ── Helpers ─────────────────────────────────────────────────────────────────

fn derive_tokened_creator(bootstrap_ep: u32) -> Option<(u32, u64)>
{
    let token = NEXT_BOOTSTRAP_TOKEN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let tokened = syscall::cap_derive_token(bootstrap_ep, syscall::RIGHTS_SEND, token).ok()?;
    Some((tokened, token))
}

/// Issue `procmgr_labels::CONFIGURE_NAMESPACE` on a freshly-created
/// (suspended) child, handing it a `cap_copy` of init's seed
/// system-root cap. On any failure the partial child is destroyed
/// (`DESTROY_PROCESS` on `process_handle`, then `cap_delete`) so a
/// false return tells callers the handle is no longer usable. Callers
/// holding additional caps from the same CREATE reply (e.g. a separate
/// thread cap) remain responsible for releasing those.
fn configure_child_namespace(
    process_handle: u32,
    system_root_cap: u32,
    init_self_cspace: u32,
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
    let ns_msg = IpcMessage::builder(procmgr_labels::CONFIGURE_NAMESPACE)
        .cap(ns_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(process_handle, &ns_msg, ipc_buf) };
    // The kernel transferred the cap on the IPC; release init's source slot.
    let _ = syscall::cap_delete(ns_cap);
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
#[allow(clippy::too_many_lines)]
pub fn create_devmgr_with_caps(
    info: &InitInfo,
    procmgr_ep: u32,
    bootstrap_ep: u32,
    registry_ep: u32,
    ipc_buf: *mut u64,
)
{
    let devmgr_frame_cap = info.module_frame_base + 1;

    let Some((tokened_creator, child_token)) = derive_tokened_creator(bootstrap_ep)
    else
    {
        log("devmgr: token derivation failed");
        return;
    };

    // caps: [module, creator]. No stdio pipes — devmgr reaches the
    // system log via the discovery cap procmgr installs in ProcessInfo.
    let create_msg = IpcMessage::builder(procmgr_labels::CREATE_PROCESS)
        .cap(devmgr_frame_cap)
        .cap(tokened_creator)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_ep, &create_msg, ipc_buf) })
    else
    {
        log("devmgr: CREATE_PROCESS ipc_call failed");
        return;
    };
    if reply.label != 0
    {
        log("devmgr: CREATE_PROCESS failed");
        return;
    }

    let reply_caps = reply.caps();
    if reply_caps.is_empty()
    {
        log("devmgr: CREATE_PROCESS reply missing caps");
        return;
    }
    let process_handle = reply_caps[0];

    let hw = collect_hw_caps(info);

    // log + procmgr are auto-delivered via ProcessInfo; only the devmgr-
    // specific caps traverse this bootstrap protocol.
    let _ = procmgr_ep;
    let Ok(registry_copy) = syscall::cap_derive(registry_ep, syscall::RIGHTS_ALL)
    else
    {
        log("devmgr: registry cap derive failed");
        return;
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
        return;
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
        return;
    }

    // Helper: does any content remain after this point?
    let has_module = info.module_frame_count > 3;
    let remaining_apertures = hw.aperture_count > 0;
    let remaining_acpi = hw.acpi_region_count > 0;

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

        let is_last = batch_end == hw.aperture_count;
        let done_here = is_last && !remaining_acpi && !has_module;

        if !serve(
            bootstrap_ep,
            child_token,
            ipc_buf,
            done_here,
            &caps[..batch_count],
            &data[..2 + batch_count * 2],
            "devmgr: bootstrap aperture round failed",
        )
        {
            return;
        }
        if done_here
        {
            return;
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

        let is_last = batch_end == hw.acpi_region_count;
        let done_here = is_last && !has_module;

        if !serve(
            bootstrap_ep,
            child_token,
            ipc_buf,
            done_here,
            &caps[..batch_count],
            &data[..2 + batch_count * 2],
            "devmgr: bootstrap ACPI region round failed",
        )
        {
            return;
        }
        if done_here
        {
            return;
        }
        idx = batch_end;
    }

    // ── Module round (virtio-blk = module 3) ────────────────────────────
    if has_module
    {
        let module_cap = info.module_frame_base + 3;
        let Ok(module_copy) = syscall::cap_derive(module_cap, syscall::RIGHTS_ALL)
        else
        {
            log("devmgr: module cap derive failed");
            return;
        };

        let _ = serve(
            bootstrap_ep,
            child_token,
            ipc_buf,
            true,
            &[module_copy],
            &[kind::MODULE, 1],
            "devmgr: bootstrap module round failed",
        );
    }
    else if !remaining_apertures && !remaining_acpi
    {
        // All three kinds empty and R1 didn't mark done — close the
        // stream with an empty terminal round so devmgr's loop exits.
        let _ = serve(
            bootstrap_ep,
            child_token,
            ipc_buf,
            true,
            &[],
            &[kind::MODULE, 0],
            "devmgr: bootstrap terminal round failed",
        );
    }
}

// ── pwrmgr creation ─────────────────────────────────────────────────────────

/// Walk `/bin/pwrmgr`, create the process, transfer platform shutdown
/// caps via bootstrap rounds, and start it.
///
/// Returns the service-endpoint slot init owns (the RECV side stays with
/// pwrmgr; init keeps the source for deriving tokened SENDs to
/// authorized consumers). Returns `None` on any failure; partial state
/// is torn down before returning.
///
/// Bootstrap layout (matches `services/pwrmgr/src/caps.rs`):
/// * Round 1 (≤2 caps, 2 data words):
///   - caps\[0\] = pwrmgr's service endpoint (derived copy).
///   - caps\[1\] = arch authority cap (`IoPortRange` on x86-64,
///     `SbiControl` on RISC-V). Omitted when absent.
///   - data\[0\] = presence bitmap (bit 0 = arch cap present).
///   - data\[1\] = `PWRMGR_LABELS_VERSION`.
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
) -> Option<u32>
{
    let walked = walk::walk_to_file(system_root_cap, b"/bin/pwrmgr", ipc_buf)?;

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
    // CREATE_FROM_FILE returns (process_handle, thread_cap). pwrmgr is
    // not currently registered with svcmgr for death monitoring, so the
    // thread cap is released here to avoid accumulating in init's
    // CSpace.
    if reply_caps.len() >= 2
    {
        let _ = syscall::cap_delete(reply_caps[1]);
    }

    if !configure_child_namespace(process_handle, system_root_cap, init_self_cspace, ipc_buf)
    {
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
        return None;
    };
    let Ok(service_copy) = syscall::cap_derive(pwrmgr_service_ep, syscall::RIGHTS_ALL)
    else
    {
        log("pwrmgr: service endpoint derive failed");
        let _ = syscall::cap_delete(pwrmgr_service_ep);
        destroy_partial_child(process_handle, ipc_buf);
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
                return None;
            }
            idx = batch_end;
        }
    }

    Some(pwrmgr_service_ep)
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
)
{
    let vfsd_frame_cap = info.module_frame_base + 2;

    let Some((tokened_creator, child_token)) = derive_tokened_creator(bootstrap_ep)
    else
    {
        log("vfsd: token derivation failed");
        return;
    };

    let create_msg = IpcMessage::builder(procmgr_labels::CREATE_PROCESS)
        .cap(vfsd_frame_cap)
        .cap(tokened_creator)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_ep, &create_msg, ipc_buf) })
    else
    {
        log("vfsd: CREATE_PROCESS ipc_call failed");
        return;
    };
    if reply.label != 0
    {
        log("vfsd: CREATE_PROCESS failed");
        return;
    }

    let reply_caps = reply.caps();
    if reply_caps.is_empty()
    {
        log("vfsd: CREATE_PROCESS reply missing caps");
        return;
    }
    let process_handle = reply_caps[0];

    let Ok(service_copy) = syscall::cap_derive(spawn.vfsd_service_ep, syscall::RIGHTS_ALL)
    else
    {
        return;
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
        return;
    };

    if !start_process(
        process_handle,
        ipc_buf,
        "vfsd started; serving bootstrap",
        "vfsd: START_PROCESS failed",
    )
    {
        return;
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
        return;
    }

    // Round 2: fatfs module.
    let fatfs_cap = if info.module_frame_count > 4
    {
        syscall::cap_derive(info.module_frame_base + 4, syscall::RIGHTS_ALL).unwrap_or(0)
    }
    else
    {
        0
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
}

// ── svcmgr / procmgr coordination ───────────────────────────────────────────

/// Create svcmgr from `/bin/svcmgr` via `CREATE_FROM_FILE` and install
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
    let walked = walk::walk_to_file(system_root_cap, b"/bin/svcmgr", ipc_buf)?;

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

    if !configure_child_namespace(process_handle, system_root_cap, init_self_cspace, ipc_buf)
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

/// Load `/bin/crasher` via `CREATE_FROM_FILE` (suspended), install init's
/// seed namespace cap on the child, and return `(process_handle,
/// thread_cap, child_token)`. Svcmgr restarts via its own VFS-restart
/// path using the namespace cap delivered through `ProcessInfo`.
pub fn create_crasher_suspended_from_file(
    procmgr_ep: u32,
    bootstrap_ep: u32,
    system_root_cap: u32,
    init_self_cspace: u32,
    ipc_buf: *mut u64,
) -> Option<(u32, u32, u64)>
{
    let walked = walk::walk_to_file(system_root_cap, b"/bin/crasher", ipc_buf)?;

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
        log("phase 3: crasher CREATE_FROM_FILE failed");
        return None;
    };
    if reply.label != 0
    {
        log("phase 3: crasher CREATE_FROM_FILE error");
        return None;
    }

    let reply_caps = reply.caps();
    if reply_caps.len() < 2
    {
        log("phase 3: crasher reply missing caps");
        return None;
    }

    let process_handle = reply_caps[0];
    let thread_cap = reply_caps[1];

    if !configure_child_namespace(process_handle, system_root_cap, init_self_cspace, ipc_buf)
    {
        // configure_child_namespace destroyed process_handle on failure;
        // release the thread cap that was extracted in the same scope.
        let _ = syscall::cap_delete(thread_cap);
        return None;
    }

    log("phase 3: crasher created (suspended) from /bin/crasher");
    Some((process_handle, thread_cap, child_token))
}

/// Load `/bin/usertest` via `CREATE_FROM_FILE`, install init's seed
/// namespace cap on the child, start it, and serve a terminal bootstrap
/// round carrying the fatfs root cap and two SEND caps on pwrmgr's
/// service endpoint.
///
/// usertest exits cleanly on completion and is not registered with
/// svcmgr. log + procmgr + system-root caps arrive via `ProcessInfo`;
/// the bootstrap round carries:
/// * `caps[0]` — a tokened SEND on fatfs's namespace endpoint at
///   `NodeId::ROOT` for the `ns_phase` direct-driver tests. Zero when
///   vfsd was unable to mint one; the receiving phase logs and skips
///   assertions in that case.
/// * `caps[1]` — a `SHUTDOWN_AUTHORITY`-tokened SEND on pwrmgr's
///   service endpoint. usertest invokes
///   `pwrmgr_labels::SHUTDOWN` through this cap on the success path so
///   QEMU exits cleanly. Zero when pwrmgr was not started; usertest's
///   shutdown phase skips when zero.
/// * `caps[2]` — a SEND on pwrmgr's service endpoint without the
///   `SHUTDOWN_AUTHORITY` token bit. usertest's
///   `pwrmgr_cap_deny_phase` calls `SHUTDOWN` through this cap and
///   asserts the reply is `pwrmgr_errors::UNAUTHORIZED`. Zero when
///   pwrmgr was not started; the phase skips when zero.
#[allow(clippy::too_many_arguments)]
pub fn create_and_run_usertest(
    procmgr_ep: u32,
    bootstrap_ep: u32,
    system_root_cap: u32,
    init_self_cspace: u32,
    fatfs_root_cap: u32,
    pwrmgr_auth_cap: u32,
    pwrmgr_noauth_cap: u32,
    ipc_buf: *mut u64,
)
{
    let Some(walked) = walk::walk_to_file(system_root_cap, b"/bin/usertest", ipc_buf)
    else
    {
        log("phase 3: usertest walk failed");
        return;
    };

    let Some((tokened_creator, child_token)) = derive_tokened_creator(bootstrap_ep)
    else
    {
        let _ = syscall::cap_delete(walked.file_cap);
        return;
    };

    // Hand usertest a minimal argv + env so its args/env assertions have
    // real content to verify. argv: two NUL-terminated entries. env: two
    // `KEY=VALUE` NUL-terminated entries.
    let argv: &[u8] = b"usertest\0run\0";
    let argv_count: u32 = 2;
    let argv_bytes = argv.len();
    let argv_words = argv_bytes.div_ceil(8);

    let env_blob: &[u8] = b"SERAPH_TEST=1\0SERAPH_MODE=boot\0";
    let env_count: u32 = 2;
    let env_bytes = env_blob.len();
    let env_words = env_bytes.div_ceil(8);

    let label = procmgr_labels::CREATE_FROM_FILE
        | ((argv_bytes as u64) << 32)
        | ((u64::from(argv_count)) << 48)
        | ((u64::from(env_count)) << 56);
    let argv_word_offset: usize = 1;
    let env_len_word_offset = argv_word_offset + argv_words;
    let env_blob_word_offset = env_len_word_offset + 1;
    let data_count = 1 + argv_words + 1 + env_words;
    let msg = IpcMessage::builder(label)
        .word(0, walked.size)
        .bytes(argv_word_offset, argv)
        .word(env_len_word_offset, env_bytes as u64)
        .bytes(env_blob_word_offset, env_blob)
        .word_count(data_count)
        .cap(walked.file_cap)
        .cap(tokened_creator)
        .build();

    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_ep, &msg, ipc_buf) })
    else
    {
        log("phase 3: usertest CREATE_FROM_FILE failed");
        return;
    };
    if reply.label != 0
    {
        log("phase 3: usertest CREATE_FROM_FILE error");
        return;
    }

    let reply_caps = reply.caps();
    if reply_caps.is_empty()
    {
        return;
    }
    let process_handle = reply_caps[0];
    if reply_caps.len() >= 2
    {
        let _ = syscall::cap_delete(reply_caps[1]);
    }

    if !configure_child_namespace(process_handle, system_root_cap, init_self_cspace, ipc_buf)
    {
        return;
    }

    if !start_process(
        process_handle,
        ipc_buf,
        "phase 3: usertest started",
        "phase 3: usertest START_PROCESS failed",
    )
    {
        return;
    }

    // Slot convention: caps[0] = fatfs root, caps[1] = pwrmgr
    // authority, caps[2] = pwrmgr no-authority. The system-root cap
    // arrives through `ProcessInfo.system_root_cap` (set via
    // `CONFIGURE_NAMESPACE` above); std exposes it via
    // `std::os::seraph::root_dir_cap()`.
    let _ = serve(
        bootstrap_ep,
        child_token,
        ipc_buf,
        true,
        &[fatfs_root_cap, pwrmgr_auth_cap, pwrmgr_noauth_cap],
        &[],
        "phase 3: usertest bootstrap failed",
    );
}

/// Start crasher and serve its bootstrap with `[svcmgr_ep]`.
///
/// `svcmgr_service_ep` is the same cap that svcmgr will re-inject from the
/// restart bundle under the name `"svcmgr"`. Providing it on first boot as
/// well keeps the cap layout identical across first-boot and restart paths.
/// The log endpoint is delivered via `ProcessInfo`, not this round.
pub fn start_and_bootstrap_crasher(
    process_handle: u32,
    child_token: u64,
    bootstrap_ep: u32,
    svcmgr_service_ep: u32,
    ipc_buf: *mut u64,
) -> bool
{
    if !start_process(
        process_handle,
        ipc_buf,
        "phase 3: crasher started",
        "phase 3: crasher START_PROCESS failed",
    )
    {
        return false;
    }

    let svcmgr_copy = if svcmgr_service_ep != 0
    {
        syscall::cap_derive(svcmgr_service_ep, syscall::RIGHTS_SEND).unwrap_or(0)
    }
    else
    {
        0
    };

    serve(
        bootstrap_ep,
        child_token,
        ipc_buf,
        true,
        &[svcmgr_copy],
        &[],
        "phase 3: crasher bootstrap failed",
    )
}

/// One service's registration data, passed to `register_service`.
///
/// Two restart sources are supported:
///   - Module-loaded: pass `module_cap` (frame cap holding the ELF), leave
///     `vfs_path` empty. svcmgr restarts via `CREATE_PROCESS`.
///   - VFS-loaded: pass `vfs_path` (e.g. `b"/bin/crasher"`), leave
///     `module_cap` zero. svcmgr re-walks its own `root_dir_cap` to
///     the path on every restart and uses `CREATE_FROM_FILE`.
pub struct ServiceRegistration<'a>
{
    pub name: &'a [u8],
    pub restart_policy: u8,
    pub criticality: u8,
    pub thread_cap: u32,
    pub module_cap: u32,
    /// Optional extra named cap for svcmgr's restart bundle. If both
    /// `bundle_name` is non-empty and `bundle_cap != 0`, the cap will be
    /// re-injected into every restart of this service under the given name.
    pub bundle_name: &'a [u8],
    pub bundle_cap: u32,
    /// VFS path for restart via svcmgr-side walk + `CREATE_FROM_FILE`.
    /// Empty for module-loaded
    /// services. Mutually exclusive with `module_cap` at the protocol level
    /// (presence is signalled by a non-zero `vfs_path_len` in the label).
    pub vfs_path: &'a [u8],
}

/// Register a service with svcmgr via `REGISTER_SERVICE`.
///
/// Label layout:
///   bits [0..16]  = opcode
///   bits [16..32] = `name_len`
///   bits [32..48] = `vfs_path_len` (0 = module-loaded, >0 = VFS-loaded)
///
/// Data layout (in order):
///   word 0:                        `SVCMGR_LABELS_VERSION` (handshake)
///   word 1:                        `restart_policy`
///   word 2:                        `criticality`
///   words 3..:                     name bytes (`name_words`)
///   word `bundle_name_len_word`:   `bundle_name_len`
///   words ..:                      `bundle_name` bytes (`bundle_name_words`)
///   words ..:                      `vfs_path` bytes (`vfs_path_words`; only
///                                  when `vfs_path_len` > 0)
///
/// Cap layout depends on the load mode:
///   module-loaded (`vfs_path_len` == 0): [thread, module, optional bundle]
///   VFS-loaded    (`vfs_path_len`  > 0): [thread, optional bundle]
pub fn register_service(svcmgr_ep: u32, ipc_buf: *mut u64, reg: &ServiceRegistration)
{
    let name_words = reg.name.len().div_ceil(8);

    let vfs_loaded = !reg.vfs_path.is_empty();
    let vfs_path_len = if vfs_loaded { reg.vfs_path.len() } else { 0 };
    let vfs_path_words = vfs_path_len.div_ceil(8);

    // Bundle-name tail: [bundle_name_len, bundle_name_words...] packed after
    // the service name. Zero if no bundle cap is being sent.
    // word 0 holds SVCMGR_LABELS_VERSION; restart_policy/criticality occupy
    // words 1 and 2; the name starts at word 3.
    let bundle_name_len_word = 3 + name_words;
    let has_restart_source = reg.module_cap != 0 || vfs_loaded;
    let include_bundle = has_restart_source
        && reg.bundle_cap != 0
        && !reg.bundle_name.is_empty()
        && reg.bundle_name.len() <= 16;
    let bundle_name_len = if include_bundle
    {
        reg.bundle_name.len()
    }
    else
    {
        0
    };
    let bundle_name_words = bundle_name_len.div_ceil(8);
    let vfs_path_word = bundle_name_len_word + 1 + bundle_name_words;

    let data_count = vfs_path_word + vfs_path_words;
    let label = svcmgr_labels::REGISTER_SERVICE
        | ((reg.name.len() as u64) << 16)
        | ((vfs_path_len as u64) << 32);

    let mut builder = IpcMessage::builder(label)
        .word(0, u64::from(ipc::SVCMGR_LABELS_VERSION))
        .word(1, u64::from(reg.restart_policy))
        .word(2, u64::from(reg.criticality))
        .bytes(3, reg.name)
        .word(bundle_name_len_word, bundle_name_len as u64);
    if bundle_name_len > 0
    {
        builder = builder.bytes(
            bundle_name_len_word + 1,
            &reg.bundle_name[..bundle_name_len],
        );
    }
    if vfs_path_len > 0
    {
        builder = builder.bytes(vfs_path_word, reg.vfs_path);
    }
    builder = builder.word_count(data_count);

    if reg.thread_cap != 0
    {
        builder = builder.cap(reg.thread_cap);
    }
    if !vfs_loaded && reg.module_cap != 0
    {
        builder = builder.cap(reg.module_cap);
    }
    if include_bundle && let Ok(derived) = syscall::cap_derive(reg.bundle_cap, syscall::RIGHTS_SEND)
    {
        builder = builder.cap(derived);
    }

    let msg = builder.build();
    // SAFETY: ipc_buf is the caller's registered IPC buffer.
    match unsafe { ipc::ipc_call(svcmgr_ep, &msg, ipc_buf) }
    {
        Ok(reply) if reply.label == 0 =>
        {}
        _ => log("phase 3: REGISTER_SERVICE failed"),
    }
}

// ── Phase 3 orchestration ───────────────────────────────────────────────────

/// Phase 3: create svcmgr from VFS, register services, start crasher, handover.
// clippy::too_many_lines: svcmgr handover is a single transaction that owns
// the in-flight tokens for svcmgr and crasher processes; the partial-state
// unwind on any failure (svcmgr creation fails, crasher creation fails,
// registration fails, HANDOVER_COMPLETE fails) must see every token in
// scope. Factoring into helpers requires threading every token through each,
// which regresses readability.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub fn phase3_svcmgr_handover(
    info: &InitInfo,
    procmgr_ep: u32,
    bootstrap_ep: u32,
    system_root_cap: u32,
    fatfs_root_cap: u32,
    ipc_buf: *mut u64,
    init_logd_thread_cap: u32,
    init_ipc_buf_cap: u32,
) -> !
{
    let init_self_cspace = info.cspace_cap;

    let Ok(svcmgr_service_ep) = syscall::cap_create_endpoint(crate::endpoint_slab())
    else
    {
        log("phase 3: cannot create svcmgr endpoint");
        idle_loop();
    };
    let Ok(svcmgr_bootstrap_ep) = syscall::cap_create_endpoint(crate::endpoint_slab())
    else
    {
        log("phase 3: cannot create svcmgr bootstrap endpoint");
        idle_loop();
    };

    log("phase 3: loading svcmgr from /bin/svcmgr");
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

    let crasher = create_crasher_suspended_from_file(
        procmgr_ep,
        bootstrap_ep,
        system_root_cap,
        init_self_cspace,
        ipc_buf,
    );

    log("phase 3: registering services with svcmgr");

    if let Some((crasher_handle, crasher_thread, crasher_token)) = crasher
    {
        register_service(
            svcmgr_service_ep,
            ipc_buf,
            &ServiceRegistration {
                name: b"crasher",
                restart_policy: 0, // POLICY_ALWAYS
                criticality: 1,    // CRITICALITY_NORMAL
                thread_cap: crasher_thread,
                module_cap: 0,
                bundle_name: b"svcmgr",
                bundle_cap: svcmgr_service_ep,
                vfs_path: b"/bin/crasher",
            },
        );

        start_and_bootstrap_crasher(
            crasher_handle,
            crasher_token,
            bootstrap_ep,
            svcmgr_service_ep,
            ipc_buf,
        );
    }

    // Spawn pwrmgr before usertest so we can hand usertest a tokened
    // SEND on pwrmgr's service endpoint. usertest invokes
    // `pwrmgr_labels::SHUTDOWN` through that cap on the success path so
    // naked `xtask run` exits cleanly when the test suite finishes.
    let pwrmgr_service_ep = create_and_start_pwrmgr(
        info,
        procmgr_ep,
        bootstrap_ep,
        system_root_cap,
        init_self_cspace,
        ipc_buf,
    );
    let (pwrmgr_auth_cap, pwrmgr_noauth_cap) = if let Some(ep) = pwrmgr_service_ep
    {
        let auth = if let Ok(c) = syscall::cap_derive_token(
            ep,
            syscall::RIGHTS_SEND,
            ipc::pwrmgr_labels::SHUTDOWN_AUTHORITY,
        )
        {
            c
        }
        else
        {
            log("phase 3: pwrmgr SHUTDOWN_AUTHORITY derive failed");
            0
        };
        // No-authority twin used by usertest's `pwrmgr_cap_deny_phase`
        // to verify the SHUTDOWN gate rejects callers without the
        // `SHUTDOWN_AUTHORITY` token bit. Tokenized with a non-AUTHORITY
        // sentinel (`1`) so the gate fails the
        // `msg.token & SHUTDOWN_AUTHORITY != 0` check, AND so usertest
        // cannot subsequently call `cap_derive_token` on this cap to
        // mint a privileged twin — `sys_cap_derive_token` rejects
        // sources with `src_token != 0`. Plain `cap_derive` would
        // produce an un-tokened cap that usertest could re-tokenize
        // with any value (including `SHUTDOWN_AUTHORITY`), defeating
        // the very gate this test is supposed to exercise.
        let noauth = if let Ok(c) = syscall::cap_derive_token(ep, syscall::RIGHTS_SEND, 1)
        {
            c
        }
        else
        {
            log("phase 3: pwrmgr no-auth derive failed");
            0
        };
        (auth, noauth)
    }
    else
    {
        log("phase 3: pwrmgr not available; naked xtask run will not exit cleanly");
        (0, 0)
    };

    // Spawn usertest (run-once test driver; no svcmgr registration).
    create_and_run_usertest(
        procmgr_ep,
        bootstrap_ep,
        system_root_cap,
        init_self_cspace,
        fatfs_root_cap,
        pwrmgr_auth_cap,
        pwrmgr_noauth_cap,
        ipc_buf,
    );

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

    // Donatable Frame caps: segments + stack + InitInfo region + IPC
    // buffer. Other init-owned Frame caps (endpoint slab, leftover
    // FrameAlloc tails) fall to the CSpace cascade — they end up in
    // the kernel buddy rather than memmgr's pool.
    let seg = info.segment_frame_base..info.segment_frame_base + info.segment_frame_count;
    let stack =
        info.init_stack_frame_base..info.init_stack_frame_base + info.init_stack_frame_count;
    let inf = info.init_info_frame_base..info.init_info_frame_base + info.init_info_frame_count;

    let mut donate: [u32; 32] = [0; 32];
    let mut n = 0usize;
    for slot in seg.chain(stack).chain(inf)
    {
        if n < donate.len()
        {
            donate[n] = slot;
            n += 1;
        }
    }
    if init_ipc_buf_cap != 0 && n < donate.len()
    {
        donate[n] = init_ipc_buf_cap;
        n += 1;
    }

    let chunk_size = syscall_abi::MSG_CAP_SLOTS_MAX;
    let mut i = 0usize;
    while i < n
    {
        let end = (i + chunk_size).min(n);
        let mut builder = IpcMessage::builder(procmgr_labels::REGISTER_INIT_TEARDOWN).word(0, 0);
        for &slot in &donate[i..end]
        {
            builder = builder.cap(slot);
        }
        let msg = builder.build();
        // SAFETY: ipc_buf is registered; procmgr_ep carries SEND|GRANT.
        let _ = unsafe { ipc::ipc_call(procmgr_ep, &msg, ipc_buf) };
        i = end;
    }

    // Signal the cap stream is closed. Procmgr arms the death-EQ
    // observer; the next event with INIT_REAP_CORRELATOR triggers the
    // reap. (Done by this point — REGISTER_INIT_TEARDOWN's first round
    // already bound the EQ.)
    let done = IpcMessage::new(procmgr_labels::INIT_TEARDOWN_DONE);
    // SAFETY: ipc_buf is registered.
    let _ = unsafe { ipc::ipc_call(procmgr_ep, &done, ipc_buf) };
}

// ── logd spawn ──────────────────────────────────────────────────────────────

/// Spawn real-logd from `/bin/logd` at the end of Phase 2, immediately
/// after the root mount completes. Init transfers:
///
/// * a RECV cap on the master log endpoint (so logd becomes the
///   receive-side; init-logd terminates as part of the handover);
/// * a SEND cap on the same endpoint (single-use, for the
///   `HANDOVER_PULL` IPC to init-logd);
/// * a tokened SEND cap on procmgr carrying
///   `procmgr_labels::DEATH_EQ_AUTHORITY` (for `REGISTER_DEATH_EQ`);
/// * an arch-specific serial-authority cap (`IoPortRange` on x86-64,
///   `SbiControl` on RISC-V) so logd can write directly to the UART
///   for its own diagnostics and the per-sender log lines it
///   receives. Logd cannot route its diagnostics through
///   `seraph::log!` because it IS the log receiver.
///
/// Returns `true` on successful spawn + bootstrap; `false` on any
/// failure (logged at fault; init continues without real-logd, with
/// init-logd running indefinitely until init's process is otherwise
/// reaped).
// too_many_lines: one transactional spawn path; splitting would push
// most of the body into helpers and obscure the cap-flow sequencing.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn create_and_start_logd(
    info: &InitInfo,
    procmgr_ep: u32,
    procmgr_service_ep_source: u32,
    bootstrap_ep: u32,
    log_ep: u32,
    system_root_cap: u32,
    init_self_cspace: u32,
    ipc_buf: *mut u64,
) -> bool
{
    let Some(walked) = walk::walk_to_file(system_root_cap, b"/bin/logd", ipc_buf)
    else
    {
        log("logd: walk /bin/logd failed");
        return false;
    };

    let Some((tokened_creator, child_token)) = derive_tokened_creator(bootstrap_ep)
    else
    {
        log("logd: tokened creator derive failed");
        return false;
    };

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
        return false;
    };
    if reply.label != 0
    {
        log("logd: CREATE_FROM_FILE error");
        return false;
    }
    let reply_caps = reply.caps();
    if reply_caps.is_empty()
    {
        log("logd: CREATE_FROM_FILE reply missing caps");
        return false;
    }
    let process_handle = reply_caps[0];
    // CREATE_FROM_FILE returns (process_handle, thread_cap); logd
    // is svcmgr-registered for restart in a follow-up PR. Drop the
    // thread cap for now.
    if reply_caps.len() >= 2
    {
        let _ = syscall::cap_delete(reply_caps[1]);
    }

    if !configure_child_namespace(process_handle, system_root_cap, init_self_cspace, ipc_buf)
    {
        return false;
    }

    // Derive the three bootstrap caps logd needs.
    let Ok(log_recv) = syscall::cap_derive(log_ep, syscall::RIGHTS_ALL)
    else
    {
        log("logd: log_ep RECV derive failed");
        destroy_partial_child(process_handle, ipc_buf);
        return false;
    };
    let Ok(log_handover_send) = syscall::cap_derive(log_ep, syscall::RIGHTS_SEND)
    else
    {
        log("logd: log_ep SEND derive failed");
        let _ = syscall::cap_delete(log_recv);
        destroy_partial_child(process_handle, ipc_buf);
        return false;
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
        return false;
    };

    // Arch-specific serial-authority cap. Both `cap_derive(RIGHTS_ALL)`
    // mirror pwrmgr's pattern (`services/init/src/service.rs::
    // create_and_start_pwrmgr`). On absent archs the source slot is
    // zero; we pass zero through and logd silently disables its serial
    // path (received log lines still buffer in memory).
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
        "phase 2: logd started; serving bootstrap",
        "phase 2: logd START_PROCESS failed",
    )
    {
        let _ = syscall::cap_delete(log_recv);
        let _ = syscall::cap_delete(log_handover_send);
        let _ = syscall::cap_delete(procmgr_death_auth);
        if arch_cap_copy != 0
        {
            let _ = syscall::cap_delete(arch_cap_copy);
        }
        return false;
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
            arch_cap_copy,
        ],
        &[],
        "logd: bootstrap round failed",
    )
    {
        return false;
    }

    true
}
