// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// pwrmgr/src/caps.rs

//! Bootstrap cap acquisition for pwrmgr.
//!
//! Pwrmgr receives the platform shutdown caps from init in a multi-round
//! bootstrap exchange on its `creator_endpoint`. The exact shape mirrors
//! the devmgr handshake (`services/devmgr/src/caps.rs`):
//!
//! * Round 1 (auth caps + presence bitmap, 2 caps + 2 data words):
//!     - caps\[0\] = pwrmgr's service endpoint (RECV; the SHUTDOWN/REBOOT
//!       receive end)
//!     - caps\[1\] = arch-specific authority cap (`IoPortRange` on x86-64,
//!       `SbiControl` on RISC-V). Zero on architectures that have no
//!       second cap.
//!     - data\[0\] = presence bitmap (bit 0 = arch cap present)
//!     - data\[1\] = caller's compiled `PWRMGR_LABELS_VERSION`
//!     - `done = true` on RISC-V (no further rounds); `done = false` on
//!       x86-64 when ACPI region rounds follow.
//!
//! * Round 2..N (x86-64 only): ACPI region Frame caps, ≤4 per round.
//!     - caps\[..\] = ACPI region Frame caps (one entry per region)
//!     - data\[0\] = round kind (`kind::ACPI_REGION`)
//!     - data\[1\] = batch count
//!     - data\[2..\] = (`phys_base`, `size`) pairs per region
//!     - terminal round has `done = true`.

use std::os::seraph::StartupInfo;

/// Maximum number of ACPI reclaimable-region Frame caps pwrmgr accepts.
/// Matches `init/src/service.rs::MAX_ACPI_REGION_CAPS` and
/// `devmgr/src/caps.rs::MAX_ACPI_REGIONS`. RISC-V never populates these
/// regions but the storage stays unconditional so the bootstrap
/// protocol shape is arch-agnostic.
pub const MAX_ACPI_REGIONS: usize = 8;

/// One ACPI region cap with its physical range. Populated only on
/// x86-64; the fields are read by the ACPI S5 walk.
#[derive(Clone, Copy)]
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub struct AcpiRegion
{
    pub slot: u32,
    pub phys_base: u64,
    pub size: u64,
}

impl AcpiRegion
{
    pub const fn empty() -> Self
    {
        Self {
            slot: 0,
            phys_base: 0,
            size: 0,
        }
    }
}

/// Round-kind discriminator on post-R1 bootstrap rounds. Mirrors
/// `init/src/service.rs::kind::ACPI_REGION`.
pub mod kind
{
    pub const ACPI_REGION: u64 = 3;
}

/// Presence-bitmap bits on R1's `data[0]`. Tells pwrmgr whether the
/// arch-specific authority cap (caps[1]) is populated.
mod present
{
    pub const ARCH_CAP: u64 = 1 << 0;
}

pub struct PwrmgrCaps
{
    pub service_ep: u32,
    /// `IoPortRange` cap on x86-64; `SbiControl` on RISC-V; zero if the
    /// kernel did not mint one for this platform.
    pub arch_cap: u32,
    /// ACPI reclaimable-region Frame caps. Populated only on x86-64.
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    pub acpi_regions: [AcpiRegion; MAX_ACPI_REGIONS],
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    pub acpi_region_count: usize,
    /// Caller's own `AddressSpace` cap; the ACPI walk uses it to
    /// `mem_map` each region read-only. Unused on RISC-V.
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    pub self_aspace: u32,
}

impl PwrmgrCaps
{
    pub fn new(info: &StartupInfo) -> Self
    {
        Self {
            service_ep: 0,
            arch_cap: 0,
            acpi_regions: [AcpiRegion::empty(); MAX_ACPI_REGIONS],
            acpi_region_count: 0,
            self_aspace: info.self_aspace,
        }
    }
}

fn bootstrap_round1(creator: u32, ipc_buf: *mut u64, caps: &mut PwrmgrCaps) -> Option<bool>
{
    // SAFETY: `ipc_buf` is the caller-supplied kernel-registered per-thread IPC buffer page.
    let r1 = unsafe { ipc::bootstrap::request_round(creator, ipc_buf) }.ok()?;
    if r1.cap_count < 1
    {
        return None;
    }
    caps.service_ep = r1.caps[0];

    let presence = r1.data[0];
    if presence & present::ARCH_CAP != 0 && r1.cap_count >= 2
    {
        caps.arch_cap = r1.caps[1];
    }

    let caller_version = r1.data[1] as u32;
    if caller_version != ipc::PWRMGR_LABELS_VERSION
    {
        std::os::seraph::log!(
            "PWRMGR_LABELS_VERSION mismatch: caller={} expected {}",
            u64::from(caller_version),
            u64::from(ipc::PWRMGR_LABELS_VERSION)
        );
        return None;
    }

    Some(r1.done)
}

fn absorb_acpi_region_round(
    round_caps: &[u32],
    round_cap_count: usize,
    round_data: &[u64; syscall_abi::MSG_DATA_WORDS_MAX],
    caps: &mut PwrmgrCaps,
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
            phys_base: round_data[2 + i * 2],
            size: round_data[3 + i * 2],
        };
        caps.acpi_region_count += 1;
    }
}

fn bootstrap_rounds(creator: u32, ipc_buf: *mut u64, caps: &mut PwrmgrCaps) -> Option<()>
{
    loop
    {
        // SAFETY: `ipc_buf` is the caller-supplied kernel-registered per-thread IPC buffer page.
        let round = unsafe { ipc::bootstrap::request_round(creator, ipc_buf) }.ok()?;
        if round.data[0] == kind::ACPI_REGION
        {
            absorb_acpi_region_round(&round.caps, round.cap_count, &round.data, caps);
        }
        if round.done
        {
            return Some(());
        }
    }
}

/// Drive the full bootstrap exchange from init.
pub fn bootstrap_caps(info: &StartupInfo, ipc_buf: *mut u64) -> Option<PwrmgrCaps>
{
    let mut caps = PwrmgrCaps::new(info);
    let creator = info.creator_endpoint;
    if creator == 0
    {
        return None;
    }

    let r1_done = bootstrap_round1(creator, ipc_buf, &mut caps)?;
    if !r1_done
    {
        bootstrap_rounds(creator, ipc_buf, &mut caps)?;
    }
    Some(caps)
}
