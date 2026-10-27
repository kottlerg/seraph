// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/arch/x86_64/mod.rs

//! x86-64 arch-dispatch surface for devmgr.

use ipc::IpcMessage;

use crate::caps::DevmgrCaps;
use crate::firmware::EcamLocation;
use crate::reply_status;

/// Arch-specific authority caps devmgr holds after bootstrap.
pub struct ArchCaps
{
    // Full-rights derivation of init's root `IoPort` cap, delivered as the
    // `SVCMGR_BUNDLE` round's shutdown-authority cap. devmgr derives
    // per-driver narrow copies for ISA peripherals (CMOS RTC at ports
    // 0x70-0x71; COM1 at 0x3F8-0x3FF for serial) and, on
    // `QUERY_SHUTDOWN_DEVICE`, the PM1a + 8042-reset ports for pwrmgr.
    ioport_root_cap: u32,
}

impl ArchCaps
{
    pub const fn empty() -> Self
    {
        Self { ioport_root_cap: 0 }
    }

    /// Store the `SVCMGR_BUNDLE` round's shutdown-authority cap: on x86-64,
    /// the full-rights `IoPort` derivation.
    pub fn absorb_shutdown_authority(&mut self, cap: u32)
    {
        self.ioport_root_cap = cap;
    }
}

/// Platform-default ECAM when neither ACPI MCFG nor a DTB exposes one.
///
/// Returns `None`: no x86-64 machine model fixes an ECAM base the way QEMU
/// `virt` does on RISC-V, so there is no default to fall back to;
/// `discover_ecam` yields `None` and `main` halts the boot, surfacing the
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
/// hardcoded on the same basis as [`carve_uart_authority`], pending the
/// data-driven (ACPI/DTB) device-binding follow-up.
pub const UART_IRQ: u32 = 4;

/// Carve the COM1 `IoPort` (`0x3F8`..=`0x3FF`) out of devmgr's
/// full-rights `IoPort` cap.
pub fn carve_uart_authority(caps: &mut DevmgrCaps) -> Option<u32>
{
    ioport_carve(caps.arch.ioport_root_cap, 0x3F8, 8)
}

/// Carve the platform RTC's hardware-authority cap: the legacy MC146818
/// ports at ISA `0x70`..=`0x71`. The base is platform-static and hardcoded
/// pending #165, which replaces all such hardcoded per-driver knowledge
/// with ACPI `_HID` (`PNP0B00`) driven discovery.
pub fn carve_rtc_authority(caps: &mut DevmgrCaps) -> Option<u32>
{
    ioport_carve(caps.arch.ioport_root_cap, 0x70, 2)
}

/// Reply to an authorised, version-checked `QUERY_SHUTDOWN_DEVICE` with
/// pwrmgr's shutdown actuator caps: a narrow `IoPort` over the
/// caller-supplied `PM1a` control port (`msg` word 1) plus the 8042 reset
/// port. Replies `NO_DEVICE` when either carve fails, including a word 1
/// that is not a 16-bit port number.
pub fn reply_shutdown_device(caps: &DevmgrCaps, msg: &IpcMessage, ipc_buf: *mut u64)
{
    // 8042 KBC command port — the 1-byte reset register pwrmgr pulses
    // for reboot. The PM1a control port is FADT-derived, so pwrmgr
    // computes it and passes it here; devmgr only carves.
    const KBC_COMMAND_PORT: u16 = 0x64;
    let Ok(pm1a) = u16::try_from(msg.word(1))
    else
    {
        reply_status(ipc::devmgr_errors::NO_DEVICE, ipc_buf);
        return;
    };
    let Some(pm1a_cap) = ioport_carve(caps.arch.ioport_root_cap, pm1a, 2)
    else
    {
        reply_status(ipc::devmgr_errors::NO_DEVICE, ipc_buf);
        return;
    };
    let Some(kbc_cap) = ioport_carve(caps.arch.ioport_root_cap, KBC_COMMAND_PORT, 1)
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
/// devmgr's full-rights `IoPort` cap via two `ioport_split` calls. Returns
/// the narrow slot; the unused slabs are deleted, except that an
/// overflowing `base + count` leaks the derived working cap (#446). `cap_derive`-copies the
/// source so it stays intact for further carves. `root_cap` is that
/// full-rights cap.
fn ioport_carve(root_cap: u32, base: u16, count: u16) -> Option<u32>
{
    if root_cap == 0
    {
        return None;
    }
    let working = syscall::cap_derive(root_cap, syscall::RIGHTS_ALL).ok()?;
    let upper_split_at = base.checked_add(count)?;
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
