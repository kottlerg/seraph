// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/riscv/src/regs.rs

//! RISC-V IOMMU registers, commands, and fault records (RISC-V IOMMU
//! Architecture Specification v1.0, chapters "Memory-mapped register
//! interface" and "In-memory queue interface").
//!
//! Every function here is a pure encoding or decoding; the driver performs
//! the volatile register and memory accesses.

// ── Register offsets ──────────────────────────────────────────────────

/// `capabilities` (64-bit, read-only).
pub const CAPABILITIES: usize = 0x00;
/// `fctl`, the features-control register (32-bit).
pub const FCTL: usize = 0x08;
/// `ddtp`, the device-directory-table pointer (64-bit).
pub const DDTP: usize = 0x10;
/// `cqb`, the command-queue base (64-bit).
pub const CQB: usize = 0x18;
/// `cqh`, the command-queue head (32-bit, read-only).
pub const CQH: usize = 0x20;
/// `cqt`, the command-queue tail (32-bit).
pub const CQT: usize = 0x24;
/// `fqb`, the fault-queue base (64-bit).
pub const FQB: usize = 0x28;
/// `fqh`, the fault-queue head (32-bit).
pub const FQH: usize = 0x30;
/// `fqt`, the fault-queue tail (32-bit, read-only).
pub const FQT: usize = 0x34;
/// `cqcsr`, the command-queue control and status register (32-bit).
pub const CQCSR: usize = 0x48;
/// `fqcsr`, the fault-queue control and status register (32-bit).
pub const FQCSR: usize = 0x4c;
/// Bytes of the register set: every register lies in one naturally aligned
/// 4 KiB page.
pub const REGISTER_BYTES: u64 = 0x1000;

// ── capabilities and fctl ─────────────────────────────────────────────

/// The `capabilities` fields the driver uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capability
{
    /// The specification version: major in the high nibble, minor in the
    /// low.
    pub version: u8,
    /// Sv39 first-stage tables are supported.
    pub sv39: bool,
    /// Sv48 first-stage tables are supported.
    pub sv48: bool,
    /// The device-context format the IOMMU reads.
    pub context_format: ContextFormat,
}

/// The device-context format an IOMMU reads, which sets a context's size and
/// so how a device ID splits into directory indexes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextFormat
{
    /// 32-byte contexts, for an IOMMU without `MSI_FLAT`.
    Base,
    /// 64-byte contexts, which add the MSI translation fields, for an IOMMU
    /// with `MSI_FLAT`.
    Extended,
}

impl ContextFormat
{
    /// 64-bit words of one device context.
    #[must_use]
    pub const fn words(self) -> usize
    {
        match self
        {
            Self::Base => 4,
            Self::Extended => 8,
        }
    }

    /// Bits of a device ID that index a leaf directory page (`DDI[0]`): a
    /// page holds 128 base or 64 extended contexts.
    #[must_use]
    pub const fn leaf_bits(self) -> u32
    {
        match self
        {
            Self::Base => 7,
            Self::Extended => 6,
        }
    }
}

impl Capability
{
    /// Decode the `capabilities` register.
    #[must_use]
    pub const fn decode(cap: u64) -> Self
    {
        Self {
            version: (cap & 0xff) as u8,
            sv39: cap & (1 << 9) != 0,
            sv48: cap & (1 << 10) != 0,
            context_format: if cap & (1 << 22) != 0
            {
                ContextFormat::Extended
            }
            else
            {
                ContextFormat::Base
            },
        }
    }

    /// Whether the driver knows the specification version the IOMMU
    /// implements: major version 1.
    #[must_use]
    pub const fn version_supported(&self) -> bool
    {
        self.version >> 4 == 1
    }

    /// The first-stage table format the driver builds for the IOMMU's
    /// domains: Sv48 where offered, else Sv39; `None` when neither is.
    #[must_use]
    pub const fn first_stage(&self) -> Option<FirstStageMode>
    {
        if self.sv48
        {
            Some(FirstStageMode::Sv48)
        }
        else if self.sv39
        {
            Some(FirstStageMode::Sv39)
        }
        else
        {
            None
        }
    }
}

/// `fctl.BE`: the IOMMU accesses its in-memory structures big-endian.
pub const FCTL_BE: u32 = 1 << 0;
/// `fctl.GXL`: guest physical addresses use the 32-bit schemes, which also
/// forces 32-bit first-stage tables.
pub const FCTL_GXL: u32 = 1 << 2;

/// A first-stage page-table format the driver builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirstStageMode
{
    /// Three levels, 39-bit virtual addresses.
    Sv39,
    /// Four levels, 48-bit virtual addresses.
    Sv48,
}

impl FirstStageMode
{
    /// Levels of the page tables.
    #[must_use]
    pub const fn levels(self) -> u32
    {
        match self
        {
            Self::Sv39 => 3,
            Self::Sv48 => 4,
        }
    }

    /// The `iosatp.MODE` encoding.
    #[must_use]
    pub const fn iosatp_mode(self) -> u64
    {
        match self
        {
            Self::Sv39 => 8,
            Self::Sv48 => 9,
        }
    }

    /// The widest IOVA a device may issue, in bits: one less than the
    /// format's virtual-address width, since an address whose top bit is
    /// set is valid only with every bit above it set too (the format's
    /// sign extension), which no zero-extended device address has.
    #[must_use]
    pub const fn width_bits(self) -> u8
    {
        match self
        {
            Self::Sv39 => 38,
            Self::Sv48 => 47,
        }
    }
}

// ── ddtp ──────────────────────────────────────────────────────────────

/// `ddtp.busy`: the IOMMU is still acting on the last write.
pub const DDTP_BUSY: u64 = 1 << 4;
/// `ddtp.iommu_mode`'s field.
const DDTP_MODE_MASK: u64 = 0xf;

/// `ddtp.iommu_mode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DdtMode
{
    /// No inbound transaction is allowed.
    Off = 0,
    /// No translation: every inbound access passes through.
    Bare = 1,
    /// A one-level device directory.
    OneLevel = 2,
    /// A two-level device directory.
    TwoLevel = 3,
    /// A three-level device directory.
    ThreeLevel = 4,
}

impl DdtMode
{
    /// Levels of the device directory a translating mode walks; 0 for Off
    /// and Bare.
    #[must_use]
    pub const fn levels(self) -> u32
    {
        match self
        {
            Self::Off | Self::Bare => 0,
            Self::OneLevel => 1,
            Self::TwoLevel => 2,
            Self::ThreeLevel => 3,
        }
    }

    /// The mode whose device directory is `levels` deep.
    const fn with_levels(levels: u32) -> Self
    {
        match levels
        {
            1 => Self::OneLevel,
            2 => Self::TwoLevel,
            _ => Self::ThreeLevel,
        }
    }
}

/// The `ddtp` value that sets `mode` with the device directory rooted at the
/// page `root_phys`.
#[must_use]
pub const fn ddtp(mode: DdtMode, root_phys: u64) -> u64
{
    ((root_phys >> 12) << 10) | mode as u64
}

/// The `iommu_mode` field of a `ddtp` value.
#[must_use]
pub const fn ddtp_mode(ddtp: u64) -> u64
{
    ddtp & DDTP_MODE_MASK
}

/// Whether a `ddtp` value's mode walks a device directory, so the IOMMU
/// translates.
#[must_use]
pub const fn translating(ddtp: u64) -> bool
{
    let mode = ddtp_mode(ddtp);
    mode >= DdtMode::OneLevel as u64 && mode <= DdtMode::ThreeLevel as u64
}

/// The `ddtp` value that turns the IOMMU Off and keeps the device-directory
/// pointer of `ddtp`, as the specification requires of a change to Off.
#[must_use]
pub const fn ddtp_off(ddtp: u64) -> u64
{
    ddtp & !DDTP_MODE_MASK & !DDTP_BUSY
}

/// The width of the device IDs a device directory `levels` (1 to 3) deep
/// holds, in bits, for contexts of `format`: the leaf index, then 9 bits a
/// level, up to the 24-bit device ID.
#[must_use]
pub const fn device_id_bits(levels: u32, format: ContextFormat) -> u32
{
    let bits = format
        .leaf_bits()
        .saturating_add(levels.saturating_sub(1).saturating_mul(9));
    if bits > 24 { 24 } else { bits }
}

/// Bits of a PCI requester ID: the device IDs a directory must hold for
/// every function of a segment.
pub const PCI_DEVICE_ID_BITS: u32 = 16;

/// The directory modes to try, in order: the shallowest that holds every
/// PCI requester ID first and the deeper ones after it, then the shallower
/// ones that hold only part of them, deepest first. The mode field is WARL,
/// so the driver keeps the first one the IOMMU retains.
#[must_use]
pub fn directory_modes(format: ContextFormat) -> [DdtMode; 3]
{
    let holds_all = |levels: &u32| device_id_bits(*levels, format) >= PCI_DEVICE_ID_BITS;
    let whole = (1..=3).filter(holds_all);
    let part = (1..=3).rev().filter(|levels| !holds_all(levels));
    let mut out = [DdtMode::OneLevel; 3];
    for (slot, levels) in out.iter_mut().zip(whole.chain(part))
    {
        *slot = DdtMode::with_levels(levels);
    }
    out
}

// ── Queues ────────────────────────────────────────────────────────────

/// Commands the command queue holds: one 4 KiB page of 16-byte commands.
/// The driver waits for each batch of commands to complete before the next,
/// so a batch of at most a few commands never fills it.
pub const CQ_ENTRIES: u32 = 256;
/// Records the fault queue holds: one 4 KiB page of 32-byte records. Past it
/// the IOMMU drops faults until the next poll drains the queue.
pub const FQ_ENTRIES: u32 = 128;
/// 64-bit words of one command.
pub const COMMAND_WORDS: usize = 2;
/// 64-bit words of one fault record.
pub const FAULT_RECORD_WORDS: usize = 4;

/// The `cqb` or `fqb` value for a queue of `entries` entries (a power of
/// two from 2) in the page `phys`: the page number, and `LOG2SZ-1`.
#[must_use]
pub const fn queue_base(phys: u64, entries: u32) -> u64
{
    // `entries` is 2 at least, so `log2(entries)` is 1 at least.
    ((phys >> 12) << 10) | (entries.trailing_zeros() as u64).saturating_sub(1)
}

/// `cqcsr.cqen`: the command queue is enabled.
pub const CQCSR_CQEN: u32 = 1 << 0;
/// `cqcsr.cqmf`: a command fetch or a command's memory access faulted.
pub const CQCSR_CQMF: u32 = 1 << 8;
/// `cqcsr.cmd_to`: a command timed out.
pub const CQCSR_CMD_TO: u32 = 1 << 9;
/// `cqcsr.cmd_ill`: an illegal or unsupported command was fetched.
pub const CQCSR_CMD_ILL: u32 = 1 << 10;
/// `cqcsr.cqon`: the command queue is active.
pub const CQCSR_CQON: u32 = 1 << 16;
/// `cqcsr.busy`, and `fqcsr.busy` at the same bit: the IOMMU is still
/// acting on the last write.
pub const CSR_BUSY: u32 = 1 << 17;
/// The `cqcsr` bits that stop the command queue.
pub const CQCSR_ERRORS: u32 = CQCSR_CQMF | CQCSR_CMD_TO | CQCSR_CMD_ILL;
/// `fqcsr.fqen`: the fault queue is enabled.
pub const FQCSR_FQEN: u32 = 1 << 0;
/// `fqcsr.fqmf`: storing a fault record faulted.
pub const FQCSR_FQMF: u32 = 1 << 8;
/// `fqcsr.fqof`: the fault queue overflowed.
pub const FQCSR_FQOF: u32 = 1 << 9;
/// `fqcsr.fqon`: the fault queue is active.
pub const FQCSR_FQON: u32 = 1 << 16;

// ── Commands ──────────────────────────────────────────────────────────

/// One command's two words.
pub type Command = [u64; COMMAND_WORDS];

/// What an `IOTINVAL.VMA` invalidates of the first-stage translations the
/// IOMMU caches (second stage Bare).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Translations
{
    /// Every address space's.
    All,
    /// Every one of the address space `pscid`.
    Domain(u32),
    /// The page at `iova` of the address space `pscid`.
    Page
    {
        /// The address space.
        pscid: u32,
        /// An address in the page.
        iova: u64,
    },
}

/// `IOTINVAL.VMA` over `which`.
#[must_use]
pub const fn iotinval_vma(which: Translations) -> Command
{
    const OPCODE: u64 = 1;
    const AV: u64 = 1 << 10;
    const PSCV: u64 = 1 << 32;
    match which
    {
        Translations::All => [OPCODE, 0],
        Translations::Domain(pscid) => [OPCODE | PSCV | ((pscid as u64) << 12), 0],
        Translations::Page { pscid, iova } => [
            OPCODE | AV | PSCV | ((pscid as u64) << 12),
            (iova >> 12) << 10,
        ],
    }
}

/// What an `IODIR.INVAL_DDT` invalidates of the device directory the IOMMU
/// caches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Directory
{
    /// Every cached entry.
    All,
    /// The device context of the device ID.
    Device(u32),
}

/// `IODIR.INVAL_DDT` over `which`.
#[must_use]
pub const fn iodir_inval_ddt(which: Directory) -> Command
{
    const OPCODE: u64 = 3;
    const DV: u64 = 1 << 33;
    match which
    {
        Directory::All => [OPCODE, 0],
        Directory::Device(id) => [OPCODE | DV | ((id as u64) << 40), 0],
    }
}

/// What an `IOFENCE.C` orders besides the commands before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fence
{
    /// The commands alone.
    Commands,
    /// Also every device read and write the IOMMU processed before it,
    /// committed to the global ordering point (`PR` and `PW`), as reclaiming
    /// memory a device reached needs.
    DeviceAccesses,
}

/// `IOFENCE.C`: its completion, `cqh` passing it, means every command
/// before it has completed.
#[must_use]
pub const fn iofence_c(fence: Fence) -> Command
{
    const OPCODE: u64 = 2;
    const PR_PW: u64 = (1 << 12) | (1 << 13);
    match fence
    {
        Fence::Commands => [OPCODE, 0],
        Fence::DeviceAccesses => [OPCODE | PR_PW, 0],
    }
}

// ── Fault records ─────────────────────────────────────────────────────

/// One fault record caused by an inbound transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultRecord
{
    /// The fault's `CAUSE` code.
    pub cause: u16,
    /// The device ID of the transaction.
    pub device_id: u32,
    /// The transaction's IOVA (`iotval`).
    pub iova: u64,
}

/// Decode a fault record's words; `None` for a record no inbound
/// transaction caused (`TTYP` 0), whose device ID and address mean nothing.
#[must_use]
pub const fn decode_fault(words: [u64; FAULT_RECORD_WORDS]) -> Option<FaultRecord>
{
    let ttyp = (words[0] >> 34) & 0x3f;
    if ttyp == 0
    {
        return None;
    }
    Some(FaultRecord {
        cause: (words[0] & 0xfff) as u16,
        device_id: (words[0] >> 40) as u32,
        iova: words[2],
    })
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn capabilities_decode_the_version_formats_and_context_size()
    {
        // QEMU's riscv-iommu: version 1.0, Sv39/Sv48/Sv57, MSI_FLAT.
        let cap = 0x10 | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 22);
        let c = Capability::decode(cap);
        assert!(c.version_supported());
        assert_eq!(c.first_stage(), Some(FirstStageMode::Sv48));
        assert_eq!(c.context_format, ContextFormat::Extended);
        let sv39_only = Capability::decode(0x10 | (1 << 9));
        assert_eq!(sv39_only.first_stage(), Some(FirstStageMode::Sv39));
        assert_eq!(sv39_only.context_format, ContextFormat::Base);
    }

    #[test]
    fn an_iommu_without_a_known_version_or_table_format_is_not_driven()
    {
        assert!(!Capability::decode(0x20 | (1 << 9)).version_supported());
        assert_eq!(Capability::decode(0x10 | (1 << 8)).first_stage(), None);
    }

    #[test]
    fn ddtp_holds_the_root_page_number_and_the_mode()
    {
        let v = ddtp(DdtMode::ThreeLevel, 0x8020_3000);
        assert_eq!(v, (0x80203 << 10) | 4);
        assert_eq!(ddtp_mode(v), 4);
    }

    #[test]
    fn only_a_directory_mode_translates()
    {
        assert!(translating(ddtp(DdtMode::OneLevel, 0)));
        assert!(translating(ddtp(DdtMode::ThreeLevel, 0)));
        assert!(!translating(ddtp(DdtMode::Bare, 0x8020_3000)));
        assert!(!translating(ddtp(DdtMode::Off, 0x8020_3000)));
    }

    #[test]
    fn turning_off_keeps_the_directory_pointer_and_drops_busy()
    {
        let v = ddtp(DdtMode::TwoLevel, 0x8020_3000) | DDTP_BUSY;
        assert_eq!(ddtp_off(v), 0x80203 << 10);
    }

    #[test]
    fn a_directory_holds_its_leaf_bits_then_nine_a_level_up_to_24()
    {
        assert_eq!(device_id_bits(1, ContextFormat::Base), 7);
        assert_eq!(device_id_bits(2, ContextFormat::Base), 16);
        assert_eq!(device_id_bits(2, ContextFormat::Extended), 15);
        assert_eq!(device_id_bits(3, ContextFormat::Base), 24);
        assert_eq!(device_id_bits(3, ContextFormat::Extended), 24);
    }

    #[test]
    fn the_first_mode_tried_holds_every_pci_requester_id()
    {
        assert_eq!(
            directory_modes(ContextFormat::Base),
            [DdtMode::TwoLevel, DdtMode::ThreeLevel, DdtMode::OneLevel]
        );
        assert_eq!(
            directory_modes(ContextFormat::Extended),
            [DdtMode::ThreeLevel, DdtMode::TwoLevel, DdtMode::OneLevel]
        );
    }

    #[test]
    fn a_queue_base_holds_its_page_and_log2_size_minus_one()
    {
        assert_eq!(queue_base(0x8010_0000, CQ_ENTRIES), (0x80100 << 10) | 7);
        assert_eq!(queue_base(0x8010_1000, FQ_ENTRIES), (0x80101 << 10) | 6);
    }

    #[test]
    fn a_translation_invalidation_carries_its_scope()
    {
        assert_eq!(iotinval_vma(Translations::All), [1, 0]);
        assert_eq!(
            iotinval_vma(Translations::Domain(5)),
            [1 | (1 << 32) | (5 << 12), 0]
        );
        assert_eq!(
            iotinval_vma(Translations::Page {
                pscid: 5,
                iova: 0x12_3456
            }),
            [1 | (1 << 10) | (1 << 32) | (5 << 12), 0x123 << 10]
        );
    }

    #[test]
    fn a_directory_invalidation_names_its_device_when_it_has_one()
    {
        assert_eq!(iodir_inval_ddt(Directory::All), [3, 0]);
        assert_eq!(
            iodir_inval_ddt(Directory::Device(0x28)),
            [3 | (1 << 33) | (0x28 << 40), 0]
        );
    }

    #[test]
    fn a_fence_orders_device_accesses_only_when_asked()
    {
        assert_eq!(iofence_c(Fence::Commands), [2, 0]);
        assert_eq!(iofence_c(Fence::DeviceAccesses), [2 | (3 << 12), 0]);
    }

    #[test]
    fn a_transaction_fault_record_decodes_and_an_event_record_does_not()
    {
        // Write page fault (15), untranslated write (TTYP 3), device 0x28.
        let w0 = 15 | (3 << 34) | (0x28 << 40);
        assert_eq!(
            decode_fault([w0, 0, 0x10_0800, 0]),
            Some(FaultRecord {
                cause: 15,
                device_id: 0x28,
                iova: 0x10_0800,
            })
        );
        // DDT entry not valid (258) keeps its full cause.
        let w0 = 258 | (2 << 34) | (0x10 << 40);
        assert_eq!(decode_fault([w0, 0, 0, 0]).map(|f| f.cause), Some(258));
        assert_eq!(decode_fault([273, 0, 0, 0]), None);
    }
}
