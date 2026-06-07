// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// abi/boot-protocol/src/role_guids.rs

//! Seraph-minted GPT partition type GUIDs for role-based partition discovery.
//!
//! Each constant is a 16-byte array in the on-disk GPT layout (little-endian
//! for the first three fields, big-endian for the last two — the same byte
//! ordering [`uuid::Uuid::to_bytes_le`] produces). Direct byte comparison
//! against a GPT entry's type-GUID field is therefore correct without
//! conversion; producers (xtask) reconstruct a `uuid::Uuid` via
//! [`uuid::Uuid::from_bytes_le`].
//!
//! Root partitions are arch-distinguished following the Discoverable
//! Partitions Specification convention: a single disk image may carry both
//! an `x86_64` and a `riscv64` root; the bootloader and vfsd select by
//! their own compile-time `target_arch`. The data partition GUID is
//! arch-neutral.
//!
//! Each value is a freshly minted v4 UUID with no extra structure encoded.

/// Type-GUID for the Seraph root partition on `x86_64`.
///
/// UUID: `f93eb1e8-a095-49fc-91a4-1f9799b8e327`.
pub const SERAPH_ROOT_X86_64: [u8; 16] = [
    0xe8, 0xb1, 0x3e, 0xf9, 0x95, 0xa0, 0xfc, 0x49, 0x91, 0xa4, 0x1f, 0x97, 0x99, 0xb8, 0xe3, 0x27,
];

/// Type-GUID for the Seraph root partition on `riscv64`.
///
/// UUID: `95770abd-c9ab-4277-8b13-b548176b4a96`.
pub const SERAPH_ROOT_RISCV64: [u8; 16] = [
    0xbd, 0x0a, 0x77, 0x95, 0xab, 0xc9, 0x77, 0x42, 0x8b, 0x13, 0xb5, 0x48, 0x17, 0x6b, 0x4a, 0x96,
];

/// Type-GUID for a Seraph data partition (arch-neutral).
///
/// UUID: `036dcef6-d862-4242-93f8-4757a8b333de`. Consumed by vfsd's
/// `/data` auto-mount (DPS-style: the type GUID is the mount point).
pub const SERAPH_DATA: [u8; 16] = [
    0xf6, 0xce, 0x6d, 0x03, 0x62, 0xd8, 0x42, 0x42, 0x93, 0xf8, 0x47, 0x57, 0xa8, 0xb3, 0x33, 0xde,
];
