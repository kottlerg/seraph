// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/arch/riscv64/mod.rs

//! RISC-V arch-dispatch surface for devmgr.

use ipc::IpcMessage;

use crate::caps::DevmgrCaps;
use crate::{carve_subrange, reply_status};
use firmware::EcamLocation;

/// Arch-specific authority caps devmgr holds after bootstrap.
pub struct ArchCaps
{
    // Steady-state holder of the platform power-state SBI authority: a
    // Reset + Suspend `SbiControl` cap from init, which is reaped. devmgr
    // serves pwrmgr a Reset-only derivation on `QUERY_SHUTDOWN_DEVICE`;
    // Suspend is held against a future path. devmgr itself never forwards
    // an SBI call — it only holds and brokers the cap.
    sbi_control_cap: u32,
}

impl ArchCaps
{
    /// No authority held; filled by [`Self::absorb_shutdown_authority`].
    pub const fn empty() -> Self
    {
        Self { sbi_control_cap: 0 }
    }

    /// Store the `SVCMGR_BUNDLE` round's shutdown-authority cap: on RISC-V,
    /// the Reset + Suspend `SbiControl` derivation.
    pub fn absorb_shutdown_authority(&mut self, cap: u32)
    {
        self.sbi_control_cap = cap;
    }
}

/// Platform-default ECAM when neither ACPI MCFG nor a DTB exposes one.
///
/// The QEMU `virt` machine has a stable, well-known PCI ECAM at
/// `[0x3000_0000, 0x4000_0000)` for buses 0..=255. Some EDK2 builds
/// shipped with distro packages (Ubuntu's `qemu-efi-riscv64`, observed
/// on CI) publish ACPI but omit MCFG and do not re-expose the `OpenSBI`
/// DTB through the UEFI configuration table, leaving both discovery
/// paths empty. Falling back to the QEMU virt constants here keeps
/// devmgr functional on those firmware builds. New RISC-V hardware that
/// diverges from QEMU virt will need real `_CRS` parsing or a DTB
/// published by its firmware — replace this stub at that point.
// The `Option` return is the dispatch surface's shape: `discover_ecams`
// chains it after two fallible firmware probes, and the x86-64 arm has
// no default to return.
#[allow(clippy::unnecessary_wraps)]
pub fn platform_default_ecam() -> Option<EcamLocation>
{
    Some(EcamLocation {
        phys_base: 0x3000_0000,
        size: 0x1000_0000,
        segment: 0,
        start_bus: 0,
        end_bus: 255,
    })
}

/// On-rootfs name of the platform RTC driver (QEMU `virt` goldfish-RTC),
/// relative to the `/services/drivers/` subtree cap. Hardcoded pending
/// #165 (manifest-driven discovery).
pub const RTC_DRIVER_NAME: &[u8] = b"goldfish-rtc";

/// PLIC source of the QEMU `virt` NS16550, the serial driver's UART.
/// Platform-static and hardcoded on the same basis as
/// [`carve_uart_authority`], pending #165 (data-driven device binding).
pub const UART_IRQ: u32 = 10;

/// GSI for a PCI function whose config-space IRQ line is unset, from its
/// `INTx` pin and device number: the QEMU `virt` PCI host's swizzle onto
/// PLIC sources 32..=35 (firmware leaves the IRQ line 0 there). Returns
/// `None` for a pin outside `INTA`..=`INTD` (1..=4).
pub fn intx_fallback_gsi(pin: u8, dev: u8) -> Option<u32>
{
    if (1..=4).contains(&pin)
    {
        return Some(32 + ((u32::from(pin) - 1 + u32::from(dev)) % 4));
    }
    None
}

/// Carve the NS16550 `Mmio` out of the aperture covering the UART
/// MMIO window.
///
/// The window is the QEMU `virt` NS16550 at `[0x1000_0000, 0x1000_1000)` —
/// a fixed part of the QEMU virt machine model, the same basis on which
/// [`platform_default_ecam`] and the seeded goldfish-RTC aperture are
/// identified. The bootloader independently discovers this base via ACPI
/// SPCR for its early console; replacing this constant with forwarded
/// SPCR/`_CRS` discovery is #165. Returns `None` when no aperture covers
/// the window or the split fails.
pub fn carve_uart_authority(caps: &mut DevmgrCaps) -> Option<u32>
{
    carve_subrange(caps, 0x1000_0000, 0x1000)
}

/// The data word the RTC driver's bootstrap round carries: none. No-op on
/// riscv64: the goldfish RTC counts nanoseconds since the epoch, so it has
/// no century register for firmware to name.
pub fn rtc_bootstrap_word(_caps: &DevmgrCaps) -> Option<u64>
{
    None
}

/// Carve the platform RTC's hardware-authority cap: the QEMU `virt`
/// goldfish-RTC page at `0x101000`. The base is platform-static and
/// hardcoded pending #165, which replaces all such hardcoded per-driver
/// knowledge with DTB `compatible = "google,goldfish-rtc"` driven
/// discovery. Returns `None` when no aperture covers the page or the split
/// fails.
pub fn carve_rtc_authority(caps: &mut DevmgrCaps) -> Option<u32>
{
    carve_subrange(caps, 0x0010_1000, 0x1000)
}

/// Reply to an authorised, version-checked `QUERY_SHUTDOWN_DEVICE` with
/// pwrmgr's shutdown actuator cap: a Reset-only `SbiControl` derivation
/// (`msg` is unused; the request carries no RISC-V parameter). Replies
/// `NO_DEVICE` when devmgr holds no `SbiControl` cap and
/// `INVALID_REQUEST` when the derivation fails.
pub fn reply_shutdown_device(caps: &DevmgrCaps, _msg: &IpcMessage, ipc_buf: *mut u64)
{
    if caps.arch.sbi_control_cap == 0
    {
        reply_status(ipc::devmgr_errors::NO_DEVICE, ipc_buf);
        return;
    }
    // pwrmgr needs only system reset (SRST); attenuate to the minimum.
    let Ok(sbi) = syscall::cap_derive(caps.arch.sbi_control_cap, syscall::RIGHTS_SBI_RESET)
    else
    {
        reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
        return;
    };
    let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
        .cap(sbi)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    if unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_err()
    {
        let _ = syscall::cap_delete(sbi);
    }
}
