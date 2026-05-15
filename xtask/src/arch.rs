// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! arch.rs
//!
//! Supported target architectures and their per-arch constants (target triples,
//! EFI filenames, QEMU binary names).

use std::fmt;

use clap::ValueEnum;

/// Supported build/run target architectures.
///
/// Add a new variant here (and fill in each `match`) to support a new arch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Arch
{
    /// x86-64 (Intel/AMD 64-bit)
    #[value(name = "x86_64")]
    X86_64,

    /// RISC-V 64-bit
    #[value(name = "riscv64")]
    Riscv64,
}

impl Arch
{
    /// Rust target triple for the kernel and low-level userspace binaries.
    ///
    /// Used by the kernel itself and for userspace components that bootstrap
    /// std (init, procmgr) or that deliberately stay on core+alloc (ktest).
    /// `"os": "none"` on this triple — std is not available.
    pub fn kernel_target_triple(self) -> &'static str
    {
        match self
        {
            Arch::X86_64 => "x86_64-seraph-none",
            Arch::Riscv64 => "riscv64imac-seraph-none",
        }
    }

    /// Rust target triple for std-enabled userspace binaries.
    ///
    /// Distinct from `kernel_target_triple` because `"os": "seraph"` enables
    /// `std::sys::seraph` via `-Z build-std`. Services compiled against this
    /// triple depend on the patched rust-src tree materialised by xtask.
    pub fn user_target_triple(self) -> &'static str
    {
        match self
        {
            Arch::X86_64 => "x86_64-seraph",
            Arch::Riscv64 => "riscv64a23-seraph",
        }
    }

    /// Rust target triple for the UEFI bootloader.
    pub fn boot_target_triple(self) -> &'static str
    {
        match self
        {
            Arch::X86_64 => "x86_64-unknown-uefi",
            Arch::Riscv64 => "riscv64imac-seraph-uefi",
        }
    }

    /// UEFI fallback bootloader filename placed at EFI/BOOT/<name>.
    ///
    /// This is the path UEFI firmware searches when no explicit boot entry exists.
    pub fn boot_efi_filename(self) -> &'static str
    {
        match self
        {
            Arch::X86_64 => "BOOTX64.EFI",
            Arch::Riscv64 => "BOOTRISCV64.EFI",
        }
    }

    /// QEMU system binary for this architecture.
    pub fn qemu_binary(self) -> &'static str
    {
        match self
        {
            Arch::X86_64 => "qemu-system-x86_64",
            Arch::Riscv64 => "qemu-system-riscv64",
        }
    }
}

impl fmt::Display for Arch
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            Arch::X86_64 => write!(f, "x86_64"),
            Arch::Riscv64 => write!(f, "riscv64"),
        }
    }
}
