// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/arch/x86_64/mod.rs

//! x86-64 arch-dispatch surface for devmgr.

use ipc::IpcMessage;

use crate::caps::DevmgrCaps;
use crate::reply_status;
use crate::tables::{locate_table_by_sig, with_acpi_table};
use firmware::EcamLocation;

/// Arch-specific authority caps devmgr holds after bootstrap.
pub struct ArchCaps
{
    // Full-rights derivation of init's root `IoPort` cap, delivered as the
    // `SVCMGR_BUNDLE` round's shutdown-authority cap. devmgr derives
    // per-driver narrow copies for ISA peripherals (CMOS RTC at ports
    // 0x70-0x71; COM1 at 0x3F8-0x3FF for serial) and, on
    // `QUERY_SHUTDOWN_DEVICE`, the PM1a + 8042-reset ports for pwrmgr.
    ioport_cap: u32,
}

impl ArchCaps
{
    /// No authority held; filled by [`Self::absorb_shutdown_authority`].
    pub const fn empty() -> Self
    {
        Self { ioport_cap: 0 }
    }

    /// Store the `SVCMGR_BUNDLE` round's shutdown-authority cap: on x86-64,
    /// the full-rights `IoPort` derivation.
    pub fn absorb_shutdown_authority(&mut self, cap: u32)
    {
        self.ioport_cap = cap;
    }
}

/// Platform-default ECAM when neither ACPI MCFG nor a DTB exposes one.
///
/// Returns `None`: no x86-64 machine model fixes an ECAM base the way QEMU
/// `virt` does on RISC-V, so there is no default to fall back to;
/// `discover_ecams` yields no window and `main` halts the boot, surfacing the
/// missing firmware table explicitly.
pub fn platform_default_ecam() -> Option<EcamLocation>
{
    None
}

/// On-rootfs name of the platform RTC driver (legacy MC146818 CMOS),
/// relative to the `/services/drivers/` subtree cap. Hardcoded pending
/// #165 (manifest-driven discovery).
pub const RTC_DRIVER_NAME: &[u8] = b"cmos-rtc";

/// ISA IRQ line of COM1, the serial driver's UART. Platform-static and
/// hardcoded on the same basis as [`carve_uart_authority`], pending #165
/// (data-driven device binding).
pub const UART_IRQ: u32 = 4;

/// GSI for a PCI function whose config-space IRQ line is unset, from its
/// `INTx` pin and device number.
///
/// Returns `None`: on x86-64 the firmware programs the IRQ line, and
/// routing an unprogrammed `INTx` pin to a GSI needs the ACPI `_PRT`,
/// which devmgr does not parse; there is no fixed swizzle to fall back to.
pub fn intx_fallback_gsi(_pin: u8, _dev: u8) -> Option<u32>
{
    None
}

/// Carve the COM1 `IoPort` (`0x3F8`..=`0x3FF`) out of devmgr's
/// full-rights `IoPort` cap. Returns `None` when devmgr holds no `IoPort`
/// cap or a derive or split fails.
pub fn carve_uart_authority(caps: &mut DevmgrCaps) -> Option<u32>
{
    ioport_carve(caps.arch.ioport_cap, 0x3F8, 8)
}

/// Carve the platform RTC's hardware-authority cap: the legacy MC146818
/// ports at ISA `0x70`..=`0x71`. The base is platform-static and hardcoded
/// pending #165, which replaces all such hardcoded per-driver knowledge
/// with ACPI `_HID` (`PNP0B00`) driven discovery. Returns `None` when
/// devmgr holds no `IoPort` cap or a derive or split fails.
pub fn carve_rtc_authority(caps: &mut DevmgrCaps) -> Option<u32>
{
    ioport_carve(caps.arch.ioport_cap, 0x70, 2)
}

/// The data word the RTC driver's bootstrap round carries: the CMOS RAM
/// index of the century register the FADT's `CENTURY` field names, or 0
/// when the FADT names none or cannot be read. The cmos driver reads the
/// century from that register, and with 0 falls back to its fixed
/// century.
// unnecessary_wraps: the arch-dispatch signature is shared with riscv64,
// whose RTC takes no bootstrap word and returns `None`.
#[allow(clippy::unnecessary_wraps)]
pub fn rtc_bootstrap_word(caps: &DevmgrCaps) -> Option<u64>
{
    let index = locate_table_by_sig(caps, *b"FACP")
        .and_then(|fadt| with_acpi_table(caps, fadt, firmware::acpi::fadt_century_index));
    Some(index.map_or(0, u64::from))
}

/// Reply to an authorised, version-checked `QUERY_SHUTDOWN_DEVICE` with
/// pwrmgr's shutdown actuator caps: a narrow `IoPort` over the
/// caller-supplied `PM1a` control port (`msg` word 1) plus the 8042 reset
/// port. Replies `INVALID_REQUEST` when word 1 is not the FADT's
/// `PM1a_CNT_BLK`, and `NO_DEVICE` when the FADT field cannot be read or
/// either carve fails.
pub fn reply_shutdown_device(caps: &DevmgrCaps, msg: &IpcMessage, ipc_buf: *mut u64)
{
    // 8042 KBC command port — the 1-byte reset register pwrmgr pulses
    // for reboot.
    const KBC_COMMAND_PORT: u16 = 0x64;
    // pwrmgr computes the PM1a control port from the FADT; devmgr checks
    // it against its own read of the same field so the request cannot
    // name any other port.
    let Some(pm1a) = locate_table_by_sig(caps, *b"FACP")
        .and_then(|fadt| with_acpi_table(caps, fadt, firmware::acpi::fadt_pm1a_cnt_blk))
    else
    {
        reply_status(ipc::devmgr_errors::NO_DEVICE, ipc_buf);
        return;
    };
    if msg.word(1) != u64::from(pm1a)
    {
        reply_status(ipc::devmgr_errors::INVALID_REQUEST, ipc_buf);
        return;
    }
    let Some(pm1a_cap) = ioport_carve(caps.arch.ioport_cap, pm1a, 2)
    else
    {
        reply_status(ipc::devmgr_errors::NO_DEVICE, ipc_buf);
        return;
    };
    let Some(kbc_cap) = ioport_carve(caps.arch.ioport_cap, KBC_COMMAND_PORT, 1)
    else
    {
        let _ = syscall::cap_delete(pm1a_cap);
        reply_status(ipc::devmgr_errors::NO_DEVICE, ipc_buf);
        return;
    };
    let reply = IpcMessage::builder(ipc::devmgr_errors::SUCCESS)
        .cap(pm1a_cap)
        .cap(kbc_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    if unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_err()
    {
        let _ = syscall::cap_delete(pm1a_cap);
        let _ = syscall::cap_delete(kbc_cap);
    }
}

/// Carve a narrow `IoPort` of `count` ports starting at `base` out of
/// devmgr's full-rights `IoPort` cap (`source_cap`) via two `ioport_split`
/// calls. Returns the narrow slot, or `None` when `source_cap` is zero,
/// `base + count` overflows, or a derive or split fails; every unused slab
/// is deleted. `cap_derive`-copies the source so it stays intact for
/// further carves.
fn ioport_carve(source_cap: u32, base: u16, count: u16) -> Option<u32>
{
    if source_cap == 0
    {
        return None;
    }
    let upper_split_at = base.checked_add(count)?;
    let working = syscall::cap_derive(source_cap, syscall::RIGHTS_ALL).ok()?;
    let Ok((lower_unused, upper)) = syscall::ioport_split(working, base)
    else
    {
        let _ = syscall::cap_delete(working);
        return None;
    };
    let _ = syscall::cap_delete(lower_unused);
    let Ok((narrow, upper_unused)) = syscall::ioport_split(upper, upper_split_at)
    else
    {
        let _ = syscall::cap_delete(upper);
        return None;
    };
    let _ = syscall::cap_delete(upper_unused);
    Some(narrow)
}
