// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// vfsd/src/role_guids.rs

//! Compile-time selection of the Seraph root partition GPT type-GUID.
//!
//! [`boot_protocol::role_guids`] mints both arch-specific root GUIDs.
//! vfsd is compiled for exactly one arch, so the constant resolves
//! statically here and the MOUNT handler can refer to a single
//! [`SERAPH_ROOT`] symbol without arch-conditional code at the call site.

/// The Seraph root partition type-GUID for vfsd's compile-time arch.
#[cfg(target_arch = "x86_64")]
pub const SERAPH_ROOT: [u8; 16] = boot_protocol::role_guids::SERAPH_ROOT_X86_64;

/// The Seraph root partition type-GUID for vfsd's compile-time arch.
#[cfg(target_arch = "riscv64")]
pub const SERAPH_ROOT: [u8; 16] = boot_protocol::role_guids::SERAPH_ROOT_RISCV64;

/// The standard EFI System Partition type-GUID
/// (`c12a7328-f81f-11d2-ba4b-00a0c93ec93b`), in on-disk byte order. Used
/// to auto-mount `/esp` after root.
pub const EFI_SYSTEM_PARTITION: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];
