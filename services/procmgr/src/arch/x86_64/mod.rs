// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// procmgr/src/arch/x86_64/mod.rs

//! x86-64 architecture-specific constants.

/// ELF machine type procmgr will accept when loading user binaries.
pub const EXPECTED_ELF_MACHINE: u16 = elf::EM_X86_64;
