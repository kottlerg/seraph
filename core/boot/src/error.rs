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
    /// the riscv64 negotiation path.
    #[cfg_attr(
        all(target_arch = "x86_64", not(test)),
        expect(
            dead_code,
            reason = "only the riscv64 paging negotiation constructs it; the x86-64 build has no \
                      constructor, and the host tests construct every variant"
        )
    )]
    PagingModeUnsupported,

    /// The final map's buffer could hold more descriptors than the entry array
    /// step 6 sized, on every one of the `MEM_MAP_ATTEMPTS` runs of steps 6
    /// and 7, the slack doubling each time. The `usize` is the last attempt's
    /// buffer reach (`uefi::map_buffer_descriptor_reach`).
    MemoryMapKeptGrowing(usize),

    /// The firmware's memory map violates the UEFI contract (a descriptor size
    /// below `EFI_MEMORY_DESCRIPTOR`'s). The `&'static str` payload names the
    /// violation.
    InvalidMemoryMap(&'static str),

    /// Step 9 had more entries to record than the reclaim array's page holds
    /// (`MAX_RECLAIM_RANGES`); the bootloader's compile-time count of the
    /// entries it records (`MAX_RECLAIM_ENTRIES`) is wrong.
    ReclaimRangesOverflow,

    /// A range the initial page tables map runs past the end of the address
    /// space, or an address selects no slot of a translation table
    /// (`paging::MapError::AddressRange`).
    MapAddressRange,

    /// The trust store built into the bootloader does not parse
    /// (docs/signing.md § Trust Store).
    TrustStore(objsig::StoreError),

    /// The verifier refused the kernel or a bundle entry
    /// (docs/signing.md § Verifier Discipline): `object` is the name it was
    /// verified under, `refusal` why.
    SignatureRefused
    {
        /// The kernel's or the bundle entry's name.
        object: ObjectName,
        /// The verifier's refusal.
        refusal: objsig::Refusal,
    },

    /// The machine's security floor, in firmware storage, is above the floor
    /// of the trust store built into this bootloader: the machine has booted
    /// a newer one (docs/signing.md § Rollback Floor).
    FloorAboveStore
    {
        /// The machine's floor.
        machine: u32,
        /// The floor of this bootloader's trust store.
        carried: u32,
    },

    /// The security floor variable has another length or other attributes
    /// than the bootloader writes (docs/signing.md § Rollback Floor).
    FloorMalformed(crate::rollback::Malformed),
}

/// The name of an object the verifier refused, copied, so a [`BootError`]
/// does not borrow the buffer the object was read into. A name longer than
/// [`ObjectName::CAPACITY`] is cut at it, and printed with `...` after the
/// cut.
#[derive(Clone, Copy, Debug)]
pub struct ObjectName
{
    bytes: [u8; Self::CAPACITY],
    len: usize,
    cut: bool,
}

impl ObjectName
{
    /// The longest name kept. Every name a build gives an object fits; a
    /// copy of the bundle entry name's full width
    /// (`boot_protocol::BOOT_MODULE_NAME_LEN`) would make every
    /// `Result<_, BootError>` of the bootloader carry a quarter-kilobyte
    /// error, to print a name no build makes whole.
    pub const CAPACITY: usize = 64;

    /// A copy of `name`, cut at [`Self::CAPACITY`] bytes.
    pub fn new(name: &[u8]) -> Self
    {
        let mut bytes = [0u8; Self::CAPACITY];
        let len = name.len().min(Self::CAPACITY);
        for (out, &byte) in bytes.iter_mut().zip(name)
        {
            *out = byte;
        }
        Self {
            bytes,
            len,
            cut: name.len() > Self::CAPACITY,
        }
    }

    /// The name's bytes.
    pub fn as_bytes(&self) -> &[u8]
    {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

impl core::fmt::Display for ObjectName
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match core::str::from_utf8(self.as_bytes())
        {
            Ok(name) => f.write_str(name)?,
            Err(_) => f.write_str("<a name that is not UTF-8>")?,
        }
        if self.cut
        {
            f.write_str("...")?;
        }
        Ok(())
    }
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
            elf::ElfError::NotExecutable => "ELF type is not ET_EXEC or ET_DYN",
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
            | BootError::InvalidBundle(s)
            | BootError::InvalidMemoryMap(s) => Some(s),
            BootError::UefiError(_)
            | BootError::WxViolation
            | BootError::OutOfMemory
            | BootError::ExitBootServicesFailed
            | BootError::PagingModeUnsupported
            | BootError::MemoryMapKeptGrowing(_)
            | BootError::ReclaimRangesOverflow
            | BootError::MapAddressRange
            | BootError::TrustStore(_)
            | BootError::SignatureRefused { .. }
            | BootError::FloorAboveStore { .. }
            | BootError::FloorMalformed(_) => None,
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
            BootError::InvalidElf(_) => "ELF validation failed",
            BootError::WxViolation => "ELF segment has writable+executable permissions (W^X)",
            BootError::OutOfMemory => "physical memory allocation failed",
            BootError::ExitBootServicesFailed => "ExitBootServices failed after retries",
            BootError::InvalidBundle(_) => "bootstrap.bundle is malformed or missing",
            BootError::PagingModeUnsupported =>
            {
                "no supported RISC-V paging mode (Sv39 is the platform minimum)"
            }
            BootError::MemoryMapKeptGrowing(_) =>
            {
                "memory map kept outgrowing the entry array across the step 6 and 7 retries"
            }
            BootError::InvalidMemoryMap(_) => "UEFI memory map violates the UEFI contract",
            BootError::ReclaimRangesOverflow => "reclaim_ranges overflow (MAX_RECLAIM_ENTRIES)",
            BootError::MapAddressRange => "a range to map runs past the end of the address space",
            BootError::TrustStore(_) => "the trust store built into the bootloader does not parse",
            BootError::SignatureRefused { .. } => "signature verification refused",
            BootError::FloorAboveStore { .. } =>
            {
                "this bootloader is older than the machine's security floor"
            }
            BootError::FloorMalformed(_) => "the security floor variable is malformed",
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
        if let BootError::MemoryMapKeptGrowing(reach) = self
        {
            write!(f, ": a buffer of {reach} descriptors on the last attempt")?;
        }
        if let BootError::TrustStore(err) = self
        {
            write!(f, ": {err:?}")?;
        }
        if let BootError::SignatureRefused { object, refusal } = self
        {
            write!(f, ": {object}: {refusal:?}")?;
        }
        if let BootError::FloorAboveStore { machine, carried } = self
        {
            write!(f, ": machine floor {machine}, trust store floor {carried}")?;
        }
        if let BootError::FloorMalformed(how) = self
        {
            write!(f, ": {how}")?;
        }
        Ok(())
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
            BootError::MemoryMapKeptGrowing(1),
            BootError::InvalidMemoryMap("m"),
            BootError::ReclaimRangesOverflow,
            BootError::MapAddressRange,
            BootError::TrustStore(objsig::StoreError::Magic),
            BootError::SignatureRefused {
                object: ObjectName::new(b"kernel"),
                refusal: objsig::Refusal::Untrusted,
            },
            BootError::FloorAboveStore {
                machine: 2,
                carried: 1,
            },
            BootError::FloorMalformed(crate::rollback::Malformed::Length(0)),
        ];
        for v in variants
        {
            assert!(!v.message().is_empty(), "empty message for {v:?}");
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

    // Defect caught: an InvalidMemoryMap whose payload, which names the UEFI
    // contract violation, does not reach the fatal handler's message.
    #[test]
    fn invalid_memory_map_detail_returns_payload()
    {
        assert_eq!(
            BootError::InvalidMemoryMap("descriptor size below EFI_MEMORY_DESCRIPTOR").detail(),
            Some("descriptor size below EFI_MEMORY_DESCRIPTOR")
        );
    }

    // Defect caught: a refusal whose fatal line does not name the object and
    // the check it failed, which a boot log reader needs to tell a tampered
    // image from an untrusted one.
    #[test]
    fn a_signature_refusal_names_the_object_and_the_refusal()
    {
        let err = BootError::SignatureRefused {
            object: ObjectName::new(b"/config/devmgr/platform/qemu-virt.platform"),
            refusal: objsig::Refusal::Failed(objsig::RecordFailure::BodyHash),
        };
        assert_eq!(
            std::format!("{err}"),
            "signature verification refused: /config/devmgr/platform/qemu-virt.platform: \
             Failed(BodyHash)"
        );
        let long = ObjectName::new(&[b'a'; boot_protocol::BOOT_MODULE_NAME_LEN]);
        assert_eq!(long.as_bytes().len(), ObjectName::CAPACITY);
        assert_eq!(
            std::format!("{long}"),
            std::format!("{}...", "a".repeat(ObjectName::CAPACITY))
        );
        let fits = ObjectName::new(b"/config/devmgr/platform/qemu-virt.platform");
        assert_eq!(
            std::format!("{fits}"),
            "/config/devmgr/platform/qemu-virt.platform"
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
            BootError::PagingModeUnsupported,
            BootError::MapAddressRange,
            BootError::TrustStore(objsig::StoreError::Magic),
        ];
        for v in no_detail
        {
            assert!(v.detail().is_none(), "expected None detail for {v:?}");
        }
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
