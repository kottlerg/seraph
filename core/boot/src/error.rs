// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/error.rs

//! Bootloader error type.
//!
//! Fallible boot-sequence operations return `Result<T, BootError>`. An error
//! that reaches the top-level handler in `main.rs` is printed by
//! [`fatal_error`] and the bootloader halts; a caller that treats a failure
//! as optional (the `\EFI\seraph\nokaslr` knob lookup, where a failed open
//! means the knob is absent) handles it locally.

use crate::bprintln;

/// All error conditions that can occur during the boot sequence.
///
/// String payloads are `&'static str` because the bootloader has no allocator.
#[derive(Debug)]
pub enum BootError
{
    /// A required UEFI protocol was not found.
    ProtocolNotFound(&'static str),

    /// A UEFI call returned an unexpected status code.
    ///
    /// The `usize` is the raw `EFI_STATUS` value.
    UefiError(usize),

    /// A required file was not found on the ESP.
    FileNotFound(&'static str),

    /// The kernel or init ELF failed validation.
    InvalidElf(&'static str),

    /// An ELF segment has both writable and executable permissions (W^X violation).
    WxViolation,

    /// A physical memory allocation failed.
    OutOfMemory,

    /// `ExitBootServices` failed: a non-stale-key status, a failed map-key
    /// re-query, or a stale key on every one of the bounded retry attempts
    /// (`uefi::exit_boot_services`).
    ExitBootServicesFailed,

    /// The bootstrap.bundle file is empty, malformed, or violates an
    /// internal invariant (no `init` entry, duplicate names, etc.). A missing
    /// file surfaces as [`BootError::FileNotFound`].
    ///
    /// The `&'static str` payload describes the specific bundle error.
    InvalidBundle(&'static str),

    /// No RISC-V paging mode the kernel supports passed the satp write-probe.
    /// Sv39 is the platform minimum (docs/platform-requirements.md), so this
    /// only fires on hardware below the RVA23 baseline. Constructed only by
    /// the riscv64 negotiation path; x86-64 builds never produce it.
    #[allow(dead_code)]
    PagingModeUnsupported,
}

impl From<elf::ElfError> for BootError
{
    fn from(err: elf::ElfError) -> Self
    {
        let s = match err
        {
            elf::ElfError::TooSmall => "file too small to contain ELF header",
            elf::ElfError::BadMagic => "bad ELF magic number",
            elf::ElfError::Not64Bit => "ELF is not 64-bit (ELFCLASS64 required)",
            elf::ElfError::NotLittleEndian => "ELF is not little-endian (ELFDATA2LSB required)",
            elf::ElfError::BadVersion => "ELF ident version is not EV_CURRENT",
            elf::ElfError::NotExecutable => "ELF type is not ET_EXEC",
            elf::ElfError::WrongMachine =>
            {
                "ELF machine type does not match bootloader architecture"
            }
            elf::ElfError::BadPhentsize => "e_phentsize does not match sizeof(Elf64_Phdr)",
            elf::ElfError::NoSegments => "ELF has no program headers",
            elf::ElfError::PhdrTableOverflow => "program header table extends beyond end of file",
            elf::ElfError::SegmentOverflow => "LOAD segment file data extends beyond end of file",
            elf::ElfError::MalformedDynamic => "PT_DYNAMIC or .rela.dyn table is malformed",
            elf::ElfError::UnsupportedRelocation => "image carries relocations other than RELATIVE",
            elf::ElfError::RelocOutOfBounds => "relocation target outside loaded segments",
        };
        BootError::InvalidElf(s)
    }
}

impl BootError
{
    /// Return the variant-specific detail string, if any.
    pub fn detail(&self) -> Option<&'static str>
    {
        match self
        {
            BootError::ProtocolNotFound(s)
            | BootError::FileNotFound(s)
            | BootError::InvalidElf(s)
            | BootError::InvalidBundle(s) => Some(s),
            _ => None,
        }
    }

    /// Return a short, human-readable description of the error.
    ///
    /// Used by the fatal error handler to print a boot failure message before
    /// halting. Intentionally terse — no `fmt` infrastructure, no allocations.
    pub fn message(&self) -> &'static str
    {
        match self
        {
            BootError::ProtocolNotFound(_) => "required UEFI protocol not found",
            BootError::UefiError(_) => "UEFI call returned an error status",
            BootError::FileNotFound(_) => "required file not found on ESP",
            BootError::InvalidElf(_) => "kernel ELF validation failed",
            BootError::WxViolation => "ELF segment has writable+executable permissions (W^X)",
            BootError::OutOfMemory => "physical memory allocation failed",
            BootError::ExitBootServicesFailed => "ExitBootServices failed after retries",
            BootError::InvalidBundle(_) => "bootstrap.bundle is malformed or missing",
            BootError::PagingModeUnsupported =>
            {
                "no supported RISC-V paging mode (Sv39 is the platform minimum)"
            }
        }
    }
}

impl core::fmt::Display for BootError
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        f.write_str(self.message())?;
        if let Some(detail) = self.detail()
        {
            write!(f, ": {detail}")?;
        }
        if let BootError::UefiError(code) = self
        {
            write!(f, ": status={code:#018x}")?;
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    // ── message() coverage ────────────────────────────────────────────────────

    /// Every variant must return a non-empty message string.
    #[test]
    fn all_variants_have_nonempty_message()
    {
        let variants: &[BootError] = &[
            BootError::ProtocolNotFound("p"),
            BootError::UefiError(0xDEAD),
            BootError::FileNotFound("f"),
            BootError::InvalidElf("e"),
            BootError::WxViolation,
            BootError::OutOfMemory,
            BootError::ExitBootServicesFailed,
            BootError::InvalidBundle("b"),
            BootError::PagingModeUnsupported,
        ];
        for v in variants
        {
            assert!(!v.message().is_empty(), "empty message for {:?}", v);
        }
    }

    // ── detail() — variants with string payloads return Some ─────────────────

    #[test]
    fn protocol_not_found_detail_returns_payload()
    {
        assert_eq!(BootError::ProtocolNotFound("proto").detail(), Some("proto"));
    }

    #[test]
    fn file_not_found_detail_returns_payload()
    {
        assert_eq!(
            BootError::FileNotFound("file.efi").detail(),
            Some("file.efi")
        );
    }

    #[test]
    fn invalid_elf_detail_returns_payload()
    {
        assert_eq!(
            BootError::InvalidElf("bad magic").detail(),
            Some("bad magic")
        );
    }

    #[test]
    fn invalid_bundle_detail_returns_payload()
    {
        assert_eq!(
            BootError::InvalidBundle("missing init").detail(),
            Some("missing init")
        );
    }

    // ── detail() — variants without string payloads return None ──────────────

    #[test]
    fn no_payload_variants_detail_returns_none()
    {
        let no_detail: &[BootError] = &[
            BootError::UefiError(1),
            BootError::WxViolation,
            BootError::OutOfMemory,
            BootError::ExitBootServicesFailed,
        ];
        for v in no_detail
        {
            assert!(v.detail().is_none(), "expected None detail for {:?}", v);
        }
    }
}

/// Print a fatal boot error message via the console and halt.
///
/// Never returns.
pub fn fatal_error(err: &BootError) -> !
{
    bprintln!("SERAPH BOOT FATAL: {err}");
    loop
    {
        core::hint::spin_loop(); // halt; no recovery from fatal boot error
    }
}

#[cfg(not(test))]
use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> !
{
    // Image relocations are applied before any Rust code runs (by the firmware
    // PE loader on x86-64; by the `_start` self-relocation loop on riscv64, per
    // core/boot/docs/riscv-uefi-boot.md § Relocation: static-PIE
    // self-relocation), so core::fmt is safe here: print the full PanicInfo
    // (location + message).
    bprintln!("SERAPH BOOT PANIC: {info}");
    loop
    {
        core::hint::spin_loop(); // halt; panics are unrecoverable in the bootloader
    }
}
