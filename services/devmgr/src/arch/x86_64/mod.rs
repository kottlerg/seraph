// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/arch/x86_64/mod.rs

//! x86-64 arch-dispatch surface for devmgr.

use crate::firmware::EcamLocation;

/// Platform-default ECAM when neither ACPI MCFG nor a DTB exposes one.
///
/// Returns `None`: no x86-64 machine model fixes an ECAM base the way QEMU
/// `virt` does on RISC-V, so there is no default to fall back to; the
/// caller halts the boot and the missing firmware table is surfaced
/// explicitly.
pub fn platform_default_ecam() -> Option<EcamLocation>
{
    None
}
