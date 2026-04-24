// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// init/src/service.rs

//! Service creation helpers for init.
//!
//! Creates suspended child processes via procmgr IPC (`CREATE_PROCESS` /
//! `CREATE_FROM_VFS`), starts them, then serves their bootstrap requests on
//! init's bootstrap endpoint to deliver their per-service capability set.

use crate::bootstrap::NEXT_BOOTSTRAP_TOKEN;
use crate::idle_loop;
use crate::logging::{derive_log_stdio_pair, log};
use init_protocol::{CapType, InitInfo};
use ipc::{IpcMessage, procmgr_labels, svcmgr_labels};

/// Returns the number of u64 words `path` fills when packed little-endian.
fn path_word_count(path: &[u8]) -> usize
{
    path.len().min(ipc::MAX_PATH_LEN).div_ceil(8)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn derive_tokened_creator(bootstrap_ep: u32) -> Option<(u32, u64)>
{
    let token = NEXT_BOOTSTRAP_TOKEN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let tokened = syscall::cap_derive_token(bootstrap_ep, syscall::RIGHTS_SEND, token).ok()?;
    Some((tokened, token))
}

/// Issue `CONFIGURE_STDIO` on a suspended child's `process_handle`,
/// installing the given stdout/stderr/stdin caps. Zero slots are omitted
/// (trailing zeros only — the kernel rejects null slot indices in a cap
/// list). Returns true on success.
fn configure_stdio(
    process_handle: u32,
    ipc_buf: *mut u64,
    stdout: u32,
    stderr: u32,
    stdin: u32,
    context: &str,
) -> bool
{
    let mut builder = IpcMessage::builder(procmgr_labels::CONFIGURE_STDIO);
    if stdout != 0
    {
        builder = builder.cap(stdout);
        if stderr != 0
        {
            builder = builder.cap(stderr);
            if stdin != 0
            {
                builder = builder.cap(stdin);
            }
        }
    }
    let msg = builder.build();
    // SAFETY: ipc_buf is caller's registered IPC buffer.
    match unsafe { ipc::ipc_call(process_handle, &msg, ipc_buf) }
    {
        Ok(reply) if reply.label == 0 => true,
        _ =>
        {
            log(context);
            false
        }
    }
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

    // caps: [module, creator]. Stdio configured via CONFIGURE_STDIO below.
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

    // CONFIGURE_STDIO: install a matched stdout+stderr pair on the
    // suspended child so devmgr's log lines appear under its registered
    // display name. No stdin for devmgr.
    let (stdout, stderr) = derive_log_stdio_pair();
    configure_stdio(
        process_handle,
        ipc_buf,
        stdout,
        stderr,
        0,
        "devmgr: CONFIGURE_STDIO failed",
    );

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
    let Ok(registry_copy) = syscall::cap_derive(spawn.registry_ep, syscall::RIGHTS_SEND)
    else
    {
        return;
    };

    let (stdout, stderr) = derive_log_stdio_pair();
    configure_stdio(
        process_handle,
        ipc_buf,
        stdout,
        stderr,
        0,
        "vfsd: CONFIGURE_STDIO failed",
    );

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

/// Send `SET_VFSD_ENDPOINT` to procmgr so it can do VFS-based ELF loading.
pub fn send_vfsd_endpoint_to_procmgr(procmgr_ep: u32, vfsd_ep: u32, ipc_buf: *mut u64)
{
    let Ok(vfsd_copy) = syscall::cap_derive(vfsd_ep, syscall::RIGHTS_SEND_GRANT)
    else
    {
        log("phase 3: failed to derive vfsd endpoint");
        return;
    };
    let msg = IpcMessage::builder(procmgr_labels::SET_VFSD_EP)
        .cap(vfsd_copy)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    match unsafe { ipc::ipc_call(procmgr_ep, &msg, ipc_buf) }
    {
        Ok(reply) if reply.label == 0 => log("phase 3: vfsd endpoint sent to procmgr"),
        _ => log("phase 3: SET_VFSD_ENDPOINT failed"),
    }
}

/// Create svcmgr from VFS (`/bin/svcmgr`) via `CREATE_FROM_VFS`.
///
/// Returns `(process_handle, child_token)` on success.
pub fn create_svcmgr_from_vfs(
    procmgr_ep: u32,
    bootstrap_ep: u32,
    ipc_buf: *mut u64,
) -> Option<(u32, u64)>
{
    let path: &[u8] = b"/bin/svcmgr";

    let (tokened_creator, child_token) = derive_tokened_creator(bootstrap_ep)?;

    // Path bytes start at word 0.
    let label = procmgr_labels::CREATE_FROM_VFS | ((path.len() as u64) << 16);
    let msg = IpcMessage::builder(label)
        .bytes(0, path)
        .cap(tokened_creator)
        .build();

    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_ep, &msg, ipc_buf) })
    else
    {
        log("phase 3: CREATE_FROM_VFS ipc_call failed");
        return None;
    };
    if reply.label != 0
    {
        log("phase 3: CREATE_FROM_VFS failed");
        return None;
    }

    let reply_caps = reply.caps();
    if reply_caps.is_empty()
    {
        log("phase 3: svcmgr reply missing caps");
        return None;
    }

    Some((reply_caps[0], child_token))
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
    let (stdout, stderr) = derive_log_stdio_pair();
    configure_stdio(
        process_handle,
        ipc_buf,
        stdout,
        stderr,
        0,
        "phase 3: svcmgr CONFIGURE_STDIO failed",
    );

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

/// Create crasher from its boot module (suspended).
/// Returns `(process_handle, thread_cap, module_cap, child_token)`.
pub fn create_crasher_suspended(
    info: &InitInfo,
    procmgr_ep: u32,
    bootstrap_ep: u32,
    ipc_buf: *mut u64,
) -> Option<(u32, u32, u32, u64)>
{
    if info.module_frame_count < 6
    {
        log("phase 3: no crasher module available");
        return None;
    }

    let crasher_frame_cap = info.module_frame_base + 5;
    let frame_for_procmgr = syscall::cap_derive(crasher_frame_cap, syscall::RIGHTS_ALL).ok()?;

    let (tokened_creator, child_token) = derive_tokened_creator(bootstrap_ep)?;

    let msg = IpcMessage::builder(procmgr_labels::CREATE_PROCESS)
        .cap(frame_for_procmgr)
        .cap(tokened_creator)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_ep, &msg, ipc_buf) })
    else
    {
        log("phase 3: crasher CREATE_PROCESS failed");
        return None;
    };
    if reply.label != 0
    {
        log("phase 3: crasher CREATE_PROCESS error");
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

    log("phase 3: crasher created (suspended)");
    Some((process_handle, thread_cap, crasher_frame_cap, child_token))
}

/// Create usertest from its boot module (suspended), start it, and serve an
/// empty terminal bootstrap round. usertest exits cleanly on completion and
/// is not registered with svcmgr. log + procmgr caps arrive via
/// `ProcessInfo`, so the round carries no caps.
pub fn create_and_run_usertest(
    info: &InitInfo,
    procmgr_ep: u32,
    bootstrap_ep: u32,
    ipc_buf: *mut u64,
)
{
    if info.module_frame_count < 7
    {
        return;
    }
    let module_frame = info.module_frame_base + 6;
    let Ok(frame_for_procmgr) = syscall::cap_derive(module_frame, syscall::RIGHTS_ALL)
    else
    {
        return;
    };

    let Some((tokened_creator, child_token)) = derive_tokened_creator(bootstrap_ep)
    else
    {
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

    // Layout: words 0..argv_words = argv blob, next word = env_bytes
    // header, next env_words = env blob.
    let label = procmgr_labels::CREATE_PROCESS
        | ((argv_bytes as u64) << 32)
        | ((u64::from(argv_count)) << 48)
        | ((u64::from(env_count)) << 56);
    let data_count = argv_words + 1 + env_words;
    let msg = IpcMessage::builder(label)
        .bytes(0, argv)
        .word(argv_words, env_bytes as u64)
        .bytes(argv_words + 1, env_blob)
        .word_count(data_count)
        .cap(frame_for_procmgr)
        .cap(tokened_creator)
        .build();

    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_ep, &msg, ipc_buf) })
    else
    {
        return;
    };
    if reply.label != 0
    {
        return;
    }

    let reply_caps = reply.caps();
    if reply_caps.is_empty()
    {
        return;
    }
    let process_handle = reply_caps[0];

    let (stdout, stderr) = derive_log_stdio_pair();
    configure_stdio(
        process_handle,
        ipc_buf,
        stdout,
        stderr,
        0,
        "phase 3: usertest CONFIGURE_STDIO failed",
    );

    if !start_process(
        process_handle,
        ipc_buf,
        "phase 3: usertest started",
        "phase 3: usertest START_PROCESS failed",
    )
    {
        return;
    }

    let _ = serve(
        bootstrap_ep,
        child_token,
        ipc_buf,
        true,
        &[],
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
    let (stdout, stderr) = derive_log_stdio_pair();
    configure_stdio(
        process_handle,
        ipc_buf,
        stdout,
        stderr,
        0,
        "phase 3: crasher CONFIGURE_STDIO failed",
    );

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
}

/// Register a service with svcmgr via `REGISTER_SERVICE`.
pub fn register_service(svcmgr_ep: u32, ipc_buf: *mut u64, reg: &ServiceRegistration)
{
    let name_words = reg.name.len().div_ceil(8);

    // Bundle-name tail: [bundle_name_len, bundle_name_words...] packed after
    // the service name. Zero if no bundle cap is being sent.
    let bundle_name_len_word = 2 + name_words;
    let include_bundle = reg.module_cap != 0
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

    let data_count = bundle_name_len_word + 1 + bundle_name_words;
    let label = svcmgr_labels::REGISTER_SERVICE | ((reg.name.len() as u64) << 16);

    let mut builder = IpcMessage::builder(label)
        .word(0, u64::from(reg.restart_policy))
        .word(1, u64::from(reg.criticality))
        .bytes(2, reg.name)
        .word(bundle_name_len_word, bundle_name_len as u64);
    if bundle_name_len > 0
    {
        builder = builder.bytes(
            bundle_name_len_word + 1,
            &reg.bundle_name[..bundle_name_len],
        );
    }
    builder = builder.word_count(data_count);

    if reg.thread_cap != 0
    {
        builder = builder.cap(reg.thread_cap);
    }
    if reg.module_cap != 0
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

/// Create `/bin/hello` via `CREATE_FROM_VFS`, start it, serve an empty
/// bootstrap round. Tier-2 sanity demo — no caps beyond what `ProcessInfo`
/// auto-delivers.
pub fn create_and_run_hello(procmgr_ep: u32, bootstrap_ep: u32, ipc_buf: *mut u64)
{
    let path: &[u8] = b"/bin/hello";

    let Some((tokened_creator, child_token)) = derive_tokened_creator(bootstrap_ep)
    else
    {
        return;
    };

    let label = procmgr_labels::CREATE_FROM_VFS | ((path.len() as u64) << 16);
    let word_count = path_word_count(path);
    let msg = IpcMessage::builder(label)
        .bytes(0, path)
        .word_count(word_count)
        .cap(tokened_creator)
        .build();

    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_ep, &msg, ipc_buf) })
    else
    {
        log("phase 3: hello CREATE_FROM_VFS failed");
        return;
    };
    if reply.label != 0
    {
        log("phase 3: hello CREATE_FROM_VFS error");
        return;
    }

    let reply_caps = reply.caps();
    if reply_caps.is_empty()
    {
        return;
    }
    let process_handle = reply_caps[0];

    // Tier-2 binaries don't speak the bootstrap protocol — `child_token`
    // and `tokened_creator` are unused on the child side. Skip the serve
    // round; init would otherwise block on a REQUEST that never comes.
    let _ = child_token;

    let (stdout, stderr) = derive_log_stdio_pair();
    configure_stdio(
        process_handle,
        ipc_buf,
        stdout,
        stderr,
        0,
        "phase 3: hello CONFIGURE_STDIO failed",
    );

    let _ = start_process(
        process_handle,
        ipc_buf,
        "phase 3: hello started",
        "phase 3: hello START_PROCESS failed",
    );
}

/// Create `/bin/stdiotest` via `CREATE_FROM_VFS` with a stdin endpoint init
/// holds the SEND side of, then push a probe payload through stdin so the
/// child's `read_line` returns. Exercises the full spawner-writes →
/// child-reads → child-writes-stdout cycle end-to-end.
pub fn create_and_run_stdiotest(procmgr_ep: u32, bootstrap_ep: u32, ipc_buf: *mut u64)
{
    let path: &[u8] = b"/bin/stdiotest";

    let Ok(stdin_ep) = syscall::cap_create_endpoint()
    else
    {
        log("phase 3: stdiotest cannot create stdin endpoint");
        return;
    };

    // RECV side: handed to the child as its stdin cap.
    let Ok(stdin_recv) = syscall::cap_derive(stdin_ep, syscall::RIGHTS_RECEIVE)
    else
    {
        log("phase 3: stdiotest cannot derive stdin RECV");
        return;
    };
    // SEND side: kept by init for writing the probe payload.
    let Ok(stdin_send) = syscall::cap_derive(stdin_ep, syscall::RIGHTS_SEND)
    else
    {
        log("phase 3: stdiotest cannot derive stdin SEND");
        return;
    };

    let Some((tokened_creator, child_token)) = derive_tokened_creator(bootstrap_ep)
    else
    {
        return;
    };

    let label = procmgr_labels::CREATE_FROM_VFS | ((path.len() as u64) << 16);
    let word_count = path_word_count(path);
    let msg = IpcMessage::builder(label)
        .bytes(0, path)
        .word_count(word_count)
        .cap(tokened_creator)
        .build();

    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(reply) = (unsafe { ipc::ipc_call(procmgr_ep, &msg, ipc_buf) })
    else
    {
        log("phase 3: stdiotest CREATE_FROM_VFS failed");
        return;
    };
    if reply.label != 0
    {
        log("phase 3: stdiotest CREATE_FROM_VFS error");
        return;
    }

    let reply_caps = reply.caps();
    if reply_caps.is_empty()
    {
        return;
    }
    let process_handle = reply_caps[0];

    // Tier-2 binary: skip the bootstrap serve round (see hello).
    let _ = child_token;

    // CONFIGURE_STDIO with all three caps (stdout + stderr tokened pair,
    // plus the stdin RECV cap init just derived).
    let (stdout, stderr) = derive_log_stdio_pair();
    configure_stdio(
        process_handle,
        ipc_buf,
        stdout,
        stderr,
        stdin_recv,
        "phase 3: stdiotest CONFIGURE_STDIO failed",
    );

    if !start_process(
        process_handle,
        ipc_buf,
        "phase 3: stdiotest started",
        "phase 3: stdiotest START_PROCESS failed",
    )
    {
        return;
    }

    // Push the probe payload. Synchronous IPC: blocks until the child reaches
    // `stdin().read_line(..)`. After `ipc_call` returns, the child has the
    // bytes and will print its result on stdout.
    let payload = b"hello seraph\n";
    write_stream_bytes(stdin_send, ipc_buf, payload);

    // Cap hygiene: the stdin SEND cap has done its single job.
    let _ = syscall::cap_delete(stdin_send);
}

/// Send `bytes` on `cap` using the same `STREAM_BYTES` wire protocol that
/// ruststd's stdio path speaks. Used by init to push stdiotest's stdin
/// payload. Mirrors `init::logging::ipc_log` but exposed here so callers
/// outside the log path can write to byte-stream caps.
fn write_stream_bytes(cap: u32, ipc_buf: *mut u64, bytes: &[u8])
{
    if bytes.is_empty()
    {
        return;
    }
    let mut offset = 0;
    while offset < bytes.len()
    {
        let chunk_len = (bytes.len() - offset).min(syscall_abi::MSG_DATA_WORDS_MAX * 8);
        let label = ipc::stream_labels::STREAM_BYTES | ((chunk_len as u64 & 0xFFFF) << 16);
        let msg = IpcMessage::builder(label)
            .bytes(0, &bytes[offset..offset + chunk_len])
            .build();
        // SAFETY: ipc_buf is caller's registered IPC buffer.
        let _ = unsafe { ipc::ipc_call(cap, &msg, ipc_buf) };
        offset += chunk_len;
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
#[allow(clippy::too_many_lines)]
pub fn phase3_svcmgr_handover(
    info: &InitInfo,
    procmgr_ep: u32,
    bootstrap_ep: u32,
    vfsd_service_ep: u32,
    ipc_buf: *mut u64,
) -> !
{
    let _ = info;

    send_vfsd_endpoint_to_procmgr(procmgr_ep, vfsd_service_ep, ipc_buf);

    let Ok(svcmgr_service_ep) = syscall::cap_create_endpoint()
    else
    {
        log("phase 3: cannot create svcmgr endpoint");
        idle_loop();
    };
    let Ok(svcmgr_bootstrap_ep) = syscall::cap_create_endpoint()
    else
    {
        log("phase 3: cannot create svcmgr bootstrap endpoint");
        idle_loop();
    };

    log("phase 3: loading svcmgr from /bin/svcmgr");
    let Some((svcmgr_handle, svcmgr_token)) =
        create_svcmgr_from_vfs(procmgr_ep, bootstrap_ep, ipc_buf)
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

    let crasher = create_crasher_suspended(info, procmgr_ep, bootstrap_ep, ipc_buf);

    log("phase 3: registering services with svcmgr");

    if let Some((crasher_handle, crasher_thread, crasher_module, crasher_token)) = crasher
    {
        register_service(
            svcmgr_service_ep,
            ipc_buf,
            &ServiceRegistration {
                name: b"crasher",
                restart_policy: 0, // POLICY_ALWAYS
                criticality: 1,    // CRITICALITY_NORMAL
                thread_cap: crasher_thread,
                module_cap: crasher_module,
                bundle_name: b"svcmgr",
                bundle_cap: svcmgr_service_ep,
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

    // Spawn usertest (run-once test driver; no svcmgr registration).
    create_and_run_usertest(info, procmgr_ep, bootstrap_ep, ipc_buf);

    // Cap-oblivious tier-2 demos: hello (write-only) and stdiotest (full
    // stdin→process→stdout cycle, fed by init).
    create_and_run_hello(procmgr_ep, bootstrap_ep, ipc_buf);
    create_and_run_stdiotest(procmgr_ep, bootstrap_ep, ipc_buf);

    let handover_msg = IpcMessage::new(svcmgr_labels::HANDOVER_COMPLETE);
    // SAFETY: ipc_buf is caller's registered IPC buffer.
    match unsafe { ipc::ipc_call(svcmgr_service_ep, &handover_msg, ipc_buf) }
    {
        Ok(reply) if reply.label == 0 => log("phase 3: handover complete"),
        _ => log("phase 3: handover failed"),
    }

    log("main thread exiting, log thread continues");
    syscall::thread_exit();
}
