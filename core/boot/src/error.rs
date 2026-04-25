// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/error.rs

//! Bootloader error type.
//!
//! All fallible operations in the bootloader return `Result<T, BootError>`.
//! Every error is fatal; the top-level handler in `main.rs` prints the message
//! and halts. There is no recovery path.

/// All error conditions that can occur during the boot sequence.
///
/// String payloads are `&'static str` because the bootloader has no allocator.
/// The console printing path accepts only `&'static str` and ASCII literals.
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

    /// The kernel ELF failed validation.
    InvalidElf(&'static str),

    /// An ELF segment has both writable and executable permissions (W^X violation).
    WxViolation,

    /// A physical memory allocation failed.
    OutOfMemory,

    /// `ExitBootServices` failed even after one retry with a refreshed map key.
    ExitBootServicesFailed,

    /// The boot configuration file is missing, malformed, or contains invalid values.
    ///
    /// The `&'static str` payload describes the specific configuration error.
    InvalidConfig(&'static str),
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
            | BootError::InvalidConfig(s) => Some(s),
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
            BootError::ExitBootServicesFailed => "ExitBootServices failed after retry",
            BootError::InvalidConfig(_) => "boot configuration error",
        }
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
            BootError::InvalidConfig("c"),
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
    fn invalid_config_detail_returns_payload()
    {
        assert_eq!(
            BootError::InvalidConfig("missing key").detail(),
            Some("missing key")
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
/// Uses `console_write_str` / `console_write_hex64` directly to avoid
/// vtable dispatch. On RISC-V the PE `.reloc` section is currently empty,
/// so vtable-based formatting (`bprintln!("{}", err)`) would fault;
/// direct writes are safe on both architectures.
///
/// Never returns.
pub fn fatal_error(err: &BootError) -> !
{
    // SAFETY: console is initialized by init_serial() at bootloader entry.
    unsafe {
        crate::console::console_write_str("SERAPH BOOT FATAL: ");
        crate::console::console_write_str(err.message());
        if let Some(detail) = err.detail()
        {
            crate::console::console_write_str(": ");
            crate::console::console_write_str(detail);
        }
        if let BootError::UefiError(code) = err
        {
            crate::console::console_write_str(": status=");
            crate::console::console_write_hex64(*code as u64);
        }
        crate::console::console_write_str("\r\n");
    }
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
    // Print location if available. The panic message is a core::fmt::Arguments
    // value, which requires vtable dispatch to print — omit it to avoid faulting
    // on RISC-V where PE relocations are not yet generated. The file:line is
    // sufficient to locate the panic in source.
    // SAFETY: console is initialized by init_serial() at bootloader entry.
    unsafe {
        crate::console::console_write_str("SERAPH BOOT PANIC");
        if let Some(loc) = info.location()
        {
            crate::console::console_write_str(": ");
            crate::console::console_write_str(loc.file());
            crate::console::console_write_str(":");
            crate::console::console_write_dec32(loc.line());
        }
        crate::console::console_write_str("\r\n");
    }
    loop
    {
        core::hint::spin_loop(); // halt; panics are unrecoverable in the bootloader
    }
}
