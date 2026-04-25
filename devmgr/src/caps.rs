// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// devmgr/src/caps.rs

//! Bootstrap cap acquisition for devmgr.
//!
//! Receives raw firmware-access caps and an MMIO aperture list from init,
//! plus the root Interrupt range cap. Parsing (MCFG → ECAM, MADT/DTB →
//! IRQ routing) happens later in `devmgr::firmware`; this module owns
//! only the IPC handshake.

use std::os::seraph::StartupInfo;

/// Maximum MMIO apertures this devmgr receives from init. Matches init's
/// `MAX_APERTURE_CAPS`.
pub const MAX_APERTURES: usize = 32;

/// Maximum ACPI reclaimable-region Frame caps. Matches init's
/// `MAX_ACPI_REGION_CAPS`.
pub const MAX_ACPI_REGIONS: usize = 8;

/// An MMIO aperture cap with its physical range.
#[derive(Clone, Copy)]
pub struct Aperture
{
    pub slot: u32,
    pub base: u64,
    pub size: u64,
}

impl Aperture
{
    pub const fn empty() -> Self
    {
        Self {
            slot: 0,
            base: 0,
            size: 0,
        }
    }
}

/// An ACPI reclaimable-region Frame cap with its physical range.
#[derive(Clone, Copy)]
pub struct AcpiRegion
{
    pub slot: u32,
    pub base: u64,
    pub size: u64,
}

impl AcpiRegion
{
    pub const fn empty() -> Self
    {
        Self {
            slot: 0,
            base: 0,
            size: 0,
        }
    }
}

/// Round kind discriminator on post-R1 bootstrap rounds. Mirrors
/// `init/src/service.rs::kind`.
pub mod kind
{
    pub const MODULE: u64 = 1;
    pub const APERTURE: u64 = 2;
    pub const ACPI_REGION: u64 = 3;
}

/// Presence-bitmap bits on R1's `data[0]`. Mirrors
/// `init/src/service.rs::present`.
mod present
{
    pub const IRQ_RANGE: u64 = 1 << 0;
    pub const RSDP: u64 = 1 << 1;
    pub const DTB: u64 = 1 << 2;
}

pub struct DevmgrCaps
{
    // Authority caps from init.
    pub irq_range_cap: u32,
    pub rsdp_frame_cap: u32,
    pub rsdp_page_base: u64,
    pub dtb_frame_cap: u32,
    pub dtb_page_base: u64,
    pub dtb_size: u64,

    // MMIO aperture list — devmgr owns these and splits per-device.
    pub apertures: [Aperture; MAX_APERTURES],
    pub aperture_count: usize,

    // ACPI reclaimable-region Frame caps.
    pub acpi_regions: [AcpiRegion; MAX_ACPI_REGIONS],
    pub acpi_region_count: usize,

    // From StartupInfo / endpoints.
    pub procmgr_ep: u32,
    pub registry_ep: u32,
    pub self_bootstrap_ep: u32,
    pub self_aspace: u32,

    // Driver module caps.
    pub driver_module_slots: [u32; 8],
    pub driver_module_count: usize,
}

impl DevmgrCaps
{
    pub fn new(info: &StartupInfo) -> Self
    {
        Self {
            irq_range_cap: 0,
            rsdp_frame_cap: 0,
            rsdp_page_base: 0,
            dtb_frame_cap: 0,
            dtb_page_base: 0,
            dtb_size: 0,
            apertures: [Aperture::empty(); MAX_APERTURES],
            aperture_count: 0,
            acpi_regions: [AcpiRegion::empty(); MAX_ACPI_REGIONS],
            acpi_region_count: 0,
            procmgr_ep: info.procmgr_endpoint,
            registry_ep: 0,
            self_bootstrap_ep: 0,
            self_aspace: info.self_aspace,
            driver_module_slots: [0; 8],
            driver_module_count: 0,
        }
    }
}

// ── Bootstrap plan layout (init → devmgr) ──────────────────────────────────
//
// Round 1 (variable, 1..=4 caps, 4 data words)
//   caps[0] = registry_ep
//   caps[1..] = optional authority caps in this order, per presence bitmap:
//               IRQ_RANGE, RSDP, DTB (only present ones included)
//   data[0] = presence bitmap (bit 0=IRQ, 1=RSDP, 2=DTB)
//   data[1] = rsdp_page_base (valid if RSDP bit set)
//   data[2] = dtb_page_base  (valid if DTB bit set)
//   data[3] = dtb_size       (valid if DTB bit set)
//
// Round 2+ (variable, ≤4 caps, up to 10 data words)
//   data[0] = round kind (APERTURE / ACPI_REGION / MODULE)
//   data[1] = count of caps in this round
//   data[2..] = kind-specific payload:
//     APERTURE / ACPI_REGION → (base, size) pairs per cap
//     MODULE → no payload
//   Terminal round has `done = true`.
//
// log_ep + procmgr_ep arrive via ProcessInfo / StartupInfo, not this protocol.

/// Round 1: the authority-cap handshake. Caps after `registry_ep` appear
/// in the order `IRQ_RANGE`, `RSDP`, `DTB`, restricted to those present
/// in the bitmap at `data[0]`.
fn bootstrap_round1(creator: u32, ipc_buf: *mut u64, caps: &mut DevmgrCaps) -> Option<()>
{
    // SAFETY: `ipc_buf` is the caller-supplied kernel-registered per-thread IPC buffer page.
    let round1 = unsafe { ipc::bootstrap::request_round(creator, ipc_buf) }.ok()?;
    if round1.cap_count < 1
    {
        return None;
    }
    caps.registry_ep = round1.caps[0];

    let presence = round1.data[0];
    caps.rsdp_page_base = round1.data[1];
    caps.dtb_page_base = round1.data[2];
    caps.dtb_size = round1.data[3];

    let mut idx = 1usize;
    if presence & present::IRQ_RANGE != 0 && idx < round1.cap_count
    {
        caps.irq_range_cap = round1.caps[idx];
        idx += 1;
    }
    if presence & present::RSDP != 0 && idx < round1.cap_count
    {
        caps.rsdp_frame_cap = round1.caps[idx];
        idx += 1;
    }
    if presence & present::DTB != 0 && idx < round1.cap_count
    {
        caps.dtb_frame_cap = round1.caps[idx];
        idx += 1;
    }
    let _ = idx;
    Some(())
}

/// Unpack one aperture-batch round into the aperture array.
fn absorb_aperture_round(
    round_caps: &[u32],
    round_cap_count: usize,
    round_data: &[u64; syscall_abi::MSG_DATA_WORDS_MAX],
    caps: &mut DevmgrCaps,
)
{
    let batch_count = round_data[1] as usize;
    let n = batch_count.min(round_cap_count).min(4);
    for (i, &slot) in round_caps.iter().take(n).enumerate()
    {
        if caps.aperture_count >= caps.apertures.len()
        {
            break;
        }
        caps.apertures[caps.aperture_count] = Aperture {
            slot,
            base: round_data[2 + i * 2],
            size: round_data[3 + i * 2],
        };
        caps.aperture_count += 1;
    }
}

/// Unpack one ACPI-region-batch round.
fn absorb_acpi_region_round(
    round_caps: &[u32],
    round_cap_count: usize,
    round_data: &[u64; syscall_abi::MSG_DATA_WORDS_MAX],
    caps: &mut DevmgrCaps,
)
{
    let batch_count = round_data[1] as usize;
    let n = batch_count.min(round_cap_count).min(4);
    for (i, &slot) in round_caps.iter().take(n).enumerate()
    {
        if caps.acpi_region_count >= caps.acpi_regions.len()
        {
            break;
        }
        caps.acpi_regions[caps.acpi_region_count] = AcpiRegion {
            slot,
            base: round_data[2 + i * 2],
            size: round_data[3 + i * 2],
        };
        caps.acpi_region_count += 1;
    }
}

/// Unpack one module-cap round.
fn absorb_module_round(round_caps: &[u32], round_cap_count: usize, caps: &mut DevmgrCaps)
{
    let n = round_cap_count.min(4);
    for &slot in round_caps.iter().take(n)
    {
        if caps.driver_module_count >= caps.driver_module_slots.len()
        {
            break;
        }
        caps.driver_module_slots[caps.driver_module_count] = slot;
        caps.driver_module_count += 1;
    }
}

/// Drive the post-R1 bootstrap rounds until init marks the stream done.
fn bootstrap_rounds(creator: u32, ipc_buf: *mut u64, caps: &mut DevmgrCaps) -> Option<()>
{
    loop
    {
        // SAFETY: `ipc_buf` is the caller-supplied kernel-registered per-thread IPC buffer page.
        let round = unsafe { ipc::bootstrap::request_round(creator, ipc_buf) }.ok()?;
        let round_kind = round.data[0];
        match round_kind
        {
            kind::APERTURE =>
            {
                absorb_aperture_round(&round.caps, round.cap_count, &round.data, caps);
            }
            kind::ACPI_REGION =>
            {
                absorb_acpi_region_round(&round.caps, round.cap_count, &round.data, caps);
            }
            kind::MODULE => absorb_module_round(&round.caps, round.cap_count, caps),
            _ =>
            {}
        }
        if round.done
        {
            return Some(());
        }
    }
}

/// Pull devmgr's initial cap set from init via multi-round bootstrap.
pub fn bootstrap_caps(info: &StartupInfo, ipc_buf: *mut u64) -> Option<DevmgrCaps>
{
    let mut caps = DevmgrCaps::new(info);
    let creator = info.creator_endpoint;
    if creator == 0
    {
        return None;
    }

    bootstrap_round1(creator, ipc_buf, &mut caps)?;
    bootstrap_rounds(creator, ipc_buf, &mut caps)?;

    caps.self_bootstrap_ep = syscall::cap_create_endpoint().ok()?;

    Some(caps)
}
