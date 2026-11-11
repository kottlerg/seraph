// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/caps.rs

//! Bootstrap cap acquisition for devmgr.
//!
//! Receives raw firmware-access caps and an MMIO aperture list from init,
//! plus a full-rights derivation of the root Interrupt range cap. Parsing
//! (MCFG / DTB → ECAM, FADT → `PM1a`) happens later in the `devmgr-firmware`
//! crate; this module owns only the IPC handshake.

use firmware::resource::SpanTable;
use std::os::seraph::StartupInfo;

/// An ACPI reclaimable-region Memory cap with its physical range.
#[derive(Clone, Copy)]
pub struct AcpiRegion
{
    pub slot: u64,
    pub base: u64,
    pub size: u64,
}

/// Framebuffer geometry forwarded by init (originally from the
/// bootloader's GOP query). Stored unboxed; `physical_base == 0` is the
/// "no framebuffer" sentinel.
#[derive(Clone, Copy)]
pub struct FbInfoRaw
{
    pub physical_base: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: u8,
}

/// Round kind discriminator on post-R1 bootstrap rounds. Mirrors
/// `init/src/service.rs::kind`.
pub mod kind
{
    pub const MODULE: u64 = 1;
    pub const APERTURE: u64 = 2;
    pub const ACPI_REGION: u64 = 3;
    /// Round carrying the svcmgr publish-authority cap and the arch
    /// shutdown-authority cap (a full-rights `IoPort` derivation on
    /// x86-64, a Reset + Suspend `SbiControl` derivation on RISC-V).
    /// One-shot, always terminal.
    pub const SVCMGR_BUNDLE: u64 = 4;
    /// Round carrying bootloader-discovered framebuffer geometry
    /// (`physical_base`, `width`, `height`, `stride`, `pixel_format`).
    /// Zero caps; data words `[kind, physical_base, w|h<<32,
    /// stride|format<<32]`. Skipped (and devmgr's `fb_info` stays
    /// `None`) when no framebuffer is present.
    pub const FRAMEBUFFER_INFO: u64 = 5;
    /// Cap-less round carrying `(base, size)` pairs, one per extent of RAM
    /// memmgr pools (now or at init's reap): data words `[kind, count,
    /// base, size, ...]`. Read into [`DevmgrCaps::pooled`].
    pub const RAM_EXTENT: u64 = 6;
}

/// Presence-bitmap bits on R1's `data[0]`. Mirrors
/// `init/src/service.rs::present`.
mod present
{
    pub const IRQ_RANGE: u64 = 1 << 0;
    pub const RSDP: u64 = 1 << 1;
    pub const DTB: u64 = 1 << 2;
}

/// The firmware-table authority devmgr reads after bootstrap and never changes:
/// the RSDP and DTB Memory caps and their locations, the ACPI reclaimable
/// regions, devmgr's own address space cap the tables are mapped into, and the
/// arch authority caps. Shared by `Arc` with the registry's worker threads,
/// which serve `QUERY_ACPI_TABLE` and `QUERY_SHUTDOWN_DEVICE` from it.
pub struct Firmware
{
    pub rsdp_memory_cap: u64,
    pub rsdp_page_base: u64,
    pub dtb_memory_cap: u64,
    pub dtb_page_base: u64,
    pub dtb_size: u64,

    // ACPI reclaimable-region Memory caps.
    pub acpi_regions: Vec<AcpiRegion>,

    /// Arch authority caps from the `SVCMGR_BUNDLE` round: the full-rights
    /// `IoPort` on x86-64, the Reset + Suspend `SbiControl` on RISC-V (see
    /// `arch::current::ArchCaps`).
    pub arch: crate::arch::current::ArchCaps,

    /// devmgr's own address space cap, a copy of [`DevmgrCaps::self_aspace`].
    pub self_aspace: u64,
}

impl Firmware
{
    fn new(self_aspace: u64) -> Self
    {
        Self {
            rsdp_memory_cap: 0,
            rsdp_page_base: 0,
            dtb_memory_cap: 0,
            dtb_page_base: 0,
            dtb_size: 0,
            acpi_regions: Vec::new(),
            arch: crate::arch::current::ArchCaps::empty(),
            self_aspace,
        }
    }
}

pub struct DevmgrCaps
{
    // Authority caps from init.
    pub irq_range_cap: u64,

    /// The firmware-table state, set once bootstrap ends.
    pub firmware: std::sync::Arc<Firmware>,

    // MMIO aperture caps — devmgr owns these and carves per-device caps
    // out of them, keeping every remainder.
    pub apertures: SpanTable<u64>,

    /// The `Mmio` cap of every scanned ECAM window, kept apart from the
    /// apertures so no BAR carve can reach configuration space: devmgr
    /// carves from it the configuration page of each `VirtIO` function it
    /// spawns a driver for, through which it clears the function's Bus
    /// Master Enable when it withdraws the driver.
    pub config_space: SpanTable<u64>,

    /// The ECAM windows `config_space` holds, to locate a function's
    /// configuration page (`firmware::pci::function_config_phys`).
    pub ecam_windows: Vec<firmware::EcamLocation>,

    /// The `(base, size)` of every extent of RAM memmgr pools, from init's
    /// [`kind::RAM_EXTENT`] rounds, against which a device's firmware-reserved
    /// ranges are checked; `None` once an extent could not be recorded, so the
    /// set is not known in full.
    pub pooled: Option<Vec<(u64, u64)>>,

    // From StartupInfo / endpoints.
    pub procmgr_ep: u64,
    pub registry_ep: u64,
    pub self_bootstrap_ep: u64,
    pub self_aspace: u64,

    /// The boot modules init forwards, untagged, in delivery order: every
    /// module of the boot bundle outside init's bootstrap set, the driver
    /// modules and the platform description tables.
    /// [`crate::decls::classify_modules`] takes them and tells each by its
    /// content. Each is the module cap and the module's size in bytes, which
    /// the cap, covering whole pages, does not give.
    pub modules: Vec<(u64, u64)>,

    // SEND cap on svcmgr's service endpoint with `PUBLISH_AUTHORITY`
    // badged on. Reserved for devmgr-initiated publications (who
    // publishes the active names: `docs/process-lifecycle.md`
    // § Init → remaining services).
    pub svcmgr_publish_cap: u64,

    /// Bootloader-discovered framebuffer geometry, or `None` when no
    /// framebuffer is present. Populated from init's
    /// [`kind::FRAMEBUFFER_INFO`] bootstrap round.
    pub fb_info: Option<FbInfoRaw>,

    /// devmgr's DMA endpoint and the thread serving it, from which each
    /// DMA-capable device's driver is given its DMA capability; `None` until
    /// `main` starts it, before the first driver spawn.
    pub dma: Option<crate::dma::DmaService>,

    /// The remapping units the IOMMU driver programs and the client devmgr
    /// calls it through; `None` when DMA runs unconfined (no unit, no driver
    /// module, or a driver that did not report ready).
    pub iommu: Option<std::sync::Arc<crate::iommu::Iommu>>,
}

impl DevmgrCaps
{
    pub fn new(info: &StartupInfo) -> Self
    {
        Self {
            irq_range_cap: 0,
            firmware: std::sync::Arc::new(Firmware::new(info.self_aspace)),
            apertures: SpanTable::new(),
            config_space: SpanTable::new(),
            ecam_windows: Vec::new(),
            pooled: Some(Vec::new()),
            procmgr_ep: info.procmgr_endpoint,
            registry_ep: 0,
            self_bootstrap_ep: 0,
            self_aspace: info.self_aspace,
            modules: Vec::new(),
            svcmgr_publish_cap: 0,
            fb_info: None,
            dma: None,
            iommu: None,
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
// Round 2+ (variable, ≤4 caps, up to MSG_DATA_WORDS_MAX data words)
//   data[0] = round kind (APERTURE / ACPI_REGION / RAM_EXTENT / MODULE /
//             FRAMEBUFFER_INFO / SVCMGR_BUNDLE)
//   APERTURE / ACPI_REGION / MODULE / SVCMGR_BUNDLE:
//     data[1] = count of caps in this round
//     data[2..] = kind-specific payload:
//       APERTURE / ACPI_REGION → (base, size) pairs per cap
//       MODULE → one word per cap, the module's size in bytes; each cap
//         is one boot module, untagged
//       SVCMGR_BUNDLE → no payload; one or two caps (publish, optional
//         arch shutdown); the terminal round
//   RAM_EXTENT: zero caps; data[1] = count of (base, size) pairs,
//     data[2..] = the pairs, one per extent of RAM memmgr pools
//   FRAMEBUFFER_INFO: zero caps; data[1] = physical_base,
//     data[2] = width | height << 32, data[3] = stride | format << 32
//   Terminal round has `done = true`.
//
// log_ep + procmgr_ep arrive via ProcessInfo / StartupInfo, not this protocol.

/// Round 1: the authority-cap handshake. Caps after `registry_ep` appear
/// in the order `IRQ_RANGE`, `RSDP`, `DTB`, restricted to those present
/// in the bitmap at `data[0]`.
fn bootstrap_round1(
    creator: u64,
    ipc_buf: *mut u64,
    caps: &mut DevmgrCaps,
    firmware: &mut Firmware,
) -> Option<()>
{
    // SAFETY: `ipc_buf` is the caller-supplied kernel-registered per-thread IPC buffer page.
    let round1 = unsafe { ipc::bootstrap::request_round(creator, ipc_buf) }.ok()?;
    if round1.cap_count < 1
    {
        return None;
    }
    caps.registry_ep = round1.caps[0];

    let presence = round1.data[0];
    firmware.rsdp_page_base = round1.data[1];
    firmware.dtb_page_base = round1.data[2];
    firmware.dtb_size = round1.data[3];

    let mut idx = 1usize;
    if presence & present::IRQ_RANGE != 0 && idx < round1.cap_count
    {
        caps.irq_range_cap = round1.caps[idx];
        idx += 1;
    }
    if presence & present::RSDP != 0 && idx < round1.cap_count
    {
        firmware.rsdp_memory_cap = round1.caps[idx];
        idx += 1;
    }
    if presence & present::DTB != 0 && idx < round1.cap_count
    {
        firmware.dtb_memory_cap = round1.caps[idx];
        idx += 1;
    }
    let _ = idx;
    Some(())
}

/// Unpack one aperture-batch round into the aperture table. The `.min(4)` is
/// `MSG_CAP_SLOTS_MAX`, the caps one round carries; init sends more rounds
/// for more apertures. An aperture the table cannot record (an empty range,
/// or the table cannot grow) is logged and its cap released.
fn absorb_aperture_round(
    round_caps: &[u64],
    round_cap_count: usize,
    round_data: &[u64; syscall_abi::MSG_DATA_WORDS_MAX],
    caps: &mut DevmgrCaps,
)
{
    let batch_count = usize::try_from(round_data[1]).unwrap_or(usize::MAX);
    let n = batch_count.min(round_cap_count).min(4);
    for (i, &slot) in round_caps.iter().take(n).enumerate()
    {
        if slot == 0
        {
            continue;
        }
        let base = round_data[2 + i * 2];
        let size = round_data[3 + i * 2];
        if caps.apertures.insert(slot, base, size) != Ok(true)
        {
            std::os::seraph::log!(
                "aperture {:#x}+{:#x} not recorded (empty range or no memory); released",
                base,
                size
            );
            let _ = syscall::cap_delete(slot);
        }
    }
}

/// Unpack one ACPI-region-batch round. The `.min(4)` is `MSG_CAP_SLOTS_MAX`,
/// the caps one round carries. A region the list cannot grow to hold is
/// logged and its cap released.
fn absorb_acpi_region_round(
    round_caps: &[u64],
    round_cap_count: usize,
    round_data: &[u64; syscall_abi::MSG_DATA_WORDS_MAX],
    firmware: &mut Firmware,
)
{
    let batch_count = usize::try_from(round_data[1]).unwrap_or(usize::MAX);
    let n = batch_count.min(round_cap_count).min(4);
    for (i, &slot) in round_caps.iter().take(n).enumerate()
    {
        if slot == 0
        {
            continue;
        }
        let base = round_data[2 + i * 2];
        let size = round_data[3 + i * 2];
        if firmware.acpi_regions.try_reserve(1).is_err()
        {
            std::os::seraph::log!(
                "ACPI region {:#x}+{:#x} not recorded (no memory); released",
                base,
                size
            );
            let _ = syscall::cap_delete(slot);
            continue;
        }
        firmware.acpi_regions.push(AcpiRegion { slot, base, size });
    }
}

/// Unpack one RAM-extent round into [`DevmgrCaps::pooled`]: `data[1]` pairs
/// follow, bounded by the words the round carries. An extent the list cannot
/// grow to hold is logged and leaves the set unknown (`None`), so every device
/// with a firmware-reserved range is refused rather than checked against part
/// of it.
fn absorb_ram_extent_round(
    round_data: &[u64; syscall_abi::MSG_DATA_WORDS_MAX],
    data_words: usize,
    caps: &mut DevmgrCaps,
)
{
    let count = usize::try_from(round_data[1]).unwrap_or(usize::MAX);
    let n = count.min(data_words.min(round_data.len()).saturating_sub(2) / 2);
    let Some(pooled) = caps.pooled.as_mut()
    else
    {
        return;
    };
    if pooled.try_reserve(n).is_err()
    {
        std::os::seraph::log!("pooled RAM extents not recorded (no memory)");
        caps.pooled = None;
        return;
    }
    for i in 0..n
    {
        pooled.push((round_data[2 + i * 2], round_data[3 + i * 2]));
    }
}

/// Unpack one module-cap round: each cap is one boot module, untagged, and
/// `data[2 + i]` is the size in bytes of the module of cap `i`. The `.min(4)`
/// is `MSG_CAP_SLOTS_MAX`, the caps one round carries. A module whose size
/// the round does not carry, or that the list cannot grow to hold, is logged
/// and its cap released: a retained module cap pins init's donated pool run.
fn absorb_module_round(
    round_caps: &[u64],
    round_cap_count: usize,
    round_data: &[u64; syscall_abi::MSG_DATA_WORDS_MAX],
    round_data_words: usize,
    caps: &mut DevmgrCaps,
)
{
    let n = round_cap_count.min(4);
    let sizes = &round_data[..round_data_words.min(round_data.len())];
    for (i, &slot) in round_caps.iter().take(n).enumerate()
    {
        if slot == 0
        {
            continue;
        }
        let Some(&bytes) = sizes.get(2 + i)
        else
        {
            std::os::seraph::log!("boot module without its size; released");
            let _ = syscall::cap_delete(slot);
            continue;
        };
        if caps.modules.try_reserve(1).is_err()
        {
            std::os::seraph::log!("boot module not recorded (no memory); released");
            let _ = syscall::cap_delete(slot);
            continue;
        }
        caps.modules.push((slot, bytes));
    }
}

/// Unpack one framebuffer-info round. Zero caps; data words carry the
/// geometry. A `physical_base == 0` leaves `caps.fb_info = None`.
// The round packs two fields per data word (`w | h << 32`,
// `stride | format << 32`); the truncating casts extract each field.
#[allow(clippy::cast_possible_truncation)]
fn absorb_framebuffer_info_round(
    round_data: &[u64; syscall_abi::MSG_DATA_WORDS_MAX],
    caps: &mut DevmgrCaps,
)
{
    let physical_base = round_data[1];
    if physical_base == 0
    {
        caps.fb_info = None;
        return;
    }
    let wh = round_data[2];
    let sf = round_data[3];
    caps.fb_info = Some(FbInfoRaw {
        physical_base,
        width: wh as u32,
        height: (wh >> 32) as u32,
        stride: sf as u32,
        pixel_format: (sf >> 32) as u8,
    });
}

/// Drive the post-R1 bootstrap rounds until init marks the stream done.
fn bootstrap_rounds(
    creator: u64,
    ipc_buf: *mut u64,
    caps: &mut DevmgrCaps,
    firmware: &mut Firmware,
) -> Option<()>
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
                absorb_acpi_region_round(&round.caps, round.cap_count, &round.data, firmware);
            }
            kind::RAM_EXTENT =>
            {
                absorb_ram_extent_round(&round.data, round.data_words, caps);
            }
            kind::MODULE =>
            {
                absorb_module_round(
                    &round.caps,
                    round.cap_count,
                    &round.data,
                    round.data_words,
                    caps,
                );
            }
            kind::FRAMEBUFFER_INFO =>
            {
                absorb_framebuffer_info_round(&round.data, caps);
            }
            kind::SVCMGR_BUNDLE =>
            {
                // caps[0] = svcmgr publish-authority cap (always present;
                //           a zero slot indicates init's derive failed and
                //           is treated as a bootstrap fatal).
                // caps[1] = arch shutdown-authority cap: full-rights
                //           IoPort derivation on x86-64, Reset+Suspend
                //           SbiControl derivation on RISC-V. Same slot
                //           either way; `arch::current::ArchCaps`
                //           stores it.
                if round.cap_count < 1 || round.caps[0] == 0
                {
                    return None;
                }
                caps.svcmgr_publish_cap = round.caps[0];
                if round.cap_count >= 2 && round.caps[1] != 0
                {
                    firmware.arch.absorb_shutdown_authority(round.caps[1]);
                }
            }
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
    let mut firmware = Firmware::new(info.self_aspace);
    let creator = info.creator_endpoint;
    if creator == 0
    {
        return None;
    }

    bootstrap_round1(creator, ipc_buf, &mut caps, &mut firmware)?;
    bootstrap_rounds(creator, ipc_buf, &mut caps, &mut firmware)?;

    caps.self_bootstrap_ep =
        std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |slab| {
            syscall::cap_create_endpoint(slab).ok()
        })?;

    caps.firmware = std::sync::Arc::new(firmware);

    Some(caps)
}
