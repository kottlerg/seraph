// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/src/arch/x86_64/mod.rs

//! x86-64 architecture-specific constants.

/// ELF machine type procmgr will accept when loading user binaries.
pub const EXPECTED_ELF_MACHINE: u16 = elf::EM_X86_64;

/// Architecture a signed image procmgr loads must be signed for
/// (docs/signing.md § Signed Attributes).
pub const SIGNED_ARCH: objsig::Arch = objsig::Arch::X86_64;
