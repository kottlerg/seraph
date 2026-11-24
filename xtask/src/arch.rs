// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/arch.rs

//! Supported target architectures and their per-arch constants (target triples,
//! EFI filenames, QEMU binary names).

use std::fmt;

crate::argparse::value_enum! {
    /// Supported build/run target architectures.
    ///
    /// Add a new variant here (and fill in each `match`) to support a new arch.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Arch
    {
        /// x86-64 (Intel/AMD 64-bit)
        #[value(name = "x86_64")]
        X86_64,

        /// RISC-V 64-bit
        #[value(name = "riscv64")]
        Riscv64,
    }
}

impl Arch
{
    /// Rust target triple for the kernel.
    ///
    /// `"os": "none"`, `relocation-model: pic`, `ET_DYN` output — the kernel
    /// is a static-PIE image; the bootloader chooses its load bias (KASLR,
    /// #252) and applies the `RELATIVE` relocations before handoff.
    pub fn kernel_target_triple(self) -> &'static str
    {
        match self
        {
            Arch::X86_64 => "x86_64-seraph-none",
            Arch::Riscv64 => "riscv64imac-seraph-none",
        }
    }

    /// Rust target triple for low-level (no-std) userspace binaries: init,
    /// ktest, memmgr.
    ///
    /// A PIE copy of `kernel_target_triple`'s spec (`relocation-model: pic`,
    /// `ET_DYN` output) so these images load at a randomized base (#39).
    pub fn lowlevel_user_target_triple(self) -> &'static str
    {
        match self
        {
            Arch::X86_64 => "x86_64-seraph-lowuser",
            Arch::Riscv64 => "riscv64imac-seraph-lowuser",
        }
    }

    /// Rust target triple for std-enabled userspace binaries.
    ///
    /// Distinct from the no-std triples because `"os": "seraph"` enables
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

    /// The kernel's linker script, relative to the project root.
    ///
    /// `cargo xtask build` passes it to the kernel's link as `-T`, and
    /// `core/kernel/src/main.rs` includes it, so that a change to it
    /// rebuilds the kernel (docs/build-system.md § Custom Targets).
    pub fn kernel_linker_script(self) -> &'static str
    {
        match self
        {
            Arch::X86_64 => "core/kernel/linker/x86_64.ld",
            Arch::Riscv64 => "core/kernel/linker/riscv64.ld",
        }
    }

    /// The bootloader's linker script, relative to the project root, where
    /// its target needs one: the riscv64 PE/COFF pipeline's. The x86-64
    /// bootloader links with the layout of the built-in
    /// `x86_64-unknown-uefi` target.
    ///
    /// `cargo xtask build` passes it to the bootloader's link as `-T`,
    /// and `core/boot/src/main.rs` includes it, so that a change to it
    /// rebuilds the bootloader (docs/build-system.md § Custom Targets).
    pub fn boot_linker_script(self) -> Option<&'static str>
    {
        match self
        {
            Arch::X86_64 => None,
            Arch::Riscv64 => Some("core/boot/linker/riscv64-uefi.ld"),
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
