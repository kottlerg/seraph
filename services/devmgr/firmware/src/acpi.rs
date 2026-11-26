// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/acpi.rs

//! What devmgr makes of the ACPI tables: the FADT (`PM1a_CNT_BLK`,
//! `CENTURY`, the DSDT, the fixed register blocks acpid is served,
//! `RESET_REG`, the sleep control and status registers of a hardware-reduced
//! FADT, and the FACS), and the MADT's Interrupt Source Overrides, I/O APICs
//! and interrupt-controller windows. The tables' formats (the RSDP, the SDT
//! header, the XSDT, the MCFG and the MADT's structures) are
//! [`firmware_tables::acpi`]'s.
//!
//! Operates on byte-slice views of ACPI tables — the caller is responsible
//! for mapping the tables into its address space first, and
//! [`table_window`] computes which pages of a region hold one. No alloc.
//! devmgr derives per-device GSIs from the PCI config IRQ line (x86-64) or
//! PCI `INTx` swizzling (RISC-V); the MADT's overrides give each line's
//! trigger and polarity ([`line_mode`]), the `SYS_IRQ_REGISTER` mode word
//! (services/devmgr/docs/pci-enumeration.md).

use syscall_abi::{IRQ_MODE_ACTIVE_LOW, IRQ_MODE_LEVEL};

use firmware_tables::acpi::{
    MADT_ENTRIES_OFF, SDT_HDR_LEN, madt_end, madt_structure, madt_structures, sdt_length,
    sdt_signature,
};
use firmware_tables::bytes::{read_u8, read_u16, read_u32, read_u64};

// ── Layout constants ──────────────────────────────────────────────────

/// FADT `PM1a_CNT_BLK` (ACPI 6.x section 5.2.9): a 32-bit I/O port number.
const FADT_OFF_PM1A_CNT_BLK: usize = 64;
/// FADT `CENTURY` (ACPI 6.x section 5.2.9): the CMOS RAM index of the RTC's
/// century-of-year register, a byte; 0 means the RTC has none.
const FADT_OFF_CENTURY: usize = 108;
/// FADT `DSDT` (ACPI 6.x section 5.2.9): the DSDT's 32-bit physical address.
const FADT_OFF_DSDT: usize = 40;
/// FADT `X_DSDT`: the DSDT's 64-bit physical address, which a non-zero value
/// gives in place of `DSDT`.
const FADT_OFF_X_DSDT: usize = 140;
/// FADT `FIRMWARE_CTRL`: the FACS's 32-bit physical address.
const FADT_OFF_FIRMWARE_CTRL: usize = 36;
/// FADT `SMI_CMD`: the 32-bit port of the SMI command register.
const FADT_OFF_SMI_CMD: usize = 48;
/// FADT `ACPI_ENABLE`: the byte written to `SMI_CMD` to enter ACPI mode.
const FADT_OFF_ACPI_ENABLE: usize = 52;
/// FADT `PM1a_EVT_BLK`: the 32-bit port of the `PM1a` event block.
const FADT_OFF_PM1A_EVT_BLK: usize = 56;
/// FADT `GPE0_BLK`: the 32-bit port of the GPE0 block.
const FADT_OFF_GPE0_BLK: usize = 80;
/// FADT `PM1_EVT_LEN`: the PM1 event block's length in bytes.
const FADT_OFF_PM1_EVT_LEN: usize = 88;
/// FADT `PM1_CNT_LEN`: the PM1 control block's length in bytes.
const FADT_OFF_PM1_CNT_LEN: usize = 89;
/// FADT `GPE0_BLK_LEN`: the GPE0 block's length in bytes.
const FADT_OFF_GPE0_BLK_LEN: usize = 92;
/// FADT `Flags`: a 32-bit field.
const FADT_OFF_FLAGS: usize = 112;
/// FADT `Flags` bit `RESET_REG_SUP`: `RESET_REG` is supported.
const FADT_FLAG_RESET_REG_SUP: u32 = 1 << 10;
/// FADT `RESET_REG`: a 12-byte Generic Address Structure (space ID, bit
/// width, bit offset, access size, then the 64-bit address).
const FADT_OFF_RESET_REG: usize = 116;
/// FADT `RESET_VALUE`: the byte written to `RESET_REG`.
const FADT_OFF_RESET_VALUE: usize = 128;
/// FADT `X_FIRMWARE_CTRL`: the FACS's 64-bit physical address, which a
/// non-zero value gives in place of `FIRMWARE_CTRL`.
const FADT_OFF_X_FIRMWARE_CTRL: usize = 132;
/// FADT `SCI_INT`: the 16-bit system vector the SCI is wired to, an ISA
/// IRQ on a PC.
const FADT_OFF_SCI_INT: usize = 46;
/// FADT `Flags` bit `HW_REDUCED_ACPI`: the platform implements no fixed
/// hardware, the SCI among it.
const FADT_FLAG_HW_REDUCED_ACPI: u32 = 1 << 20;
/// Generic Address Structure space ID of the memory space.
const GAS_SPACE_MEMORY: u8 = 0;
/// Generic Address Structure space ID of the I/O space.
const GAS_SPACE_IO: u8 = 1;
/// Generic Address Structure access size of a byte access; 0 is the
/// undefined access size, which leaves the access to the register's width.
const GAS_ACCESS_BYTE: u8 = 1;
/// FADT `SLEEP_CONTROL_REG` (ACPI 6.5 § 5.2.9): a 12-byte Generic Address
/// Structure, used on a hardware-reduced platform.
const FADT_OFF_SLEEP_CONTROL_REG: usize = 244;
/// FADT `SLEEP_STATUS_REG`: a 12-byte Generic Address Structure, used on a
/// hardware-reduced platform.
const FADT_OFF_SLEEP_STATUS_REG: usize = 256;
/// The bytes of a Generic Address Structure.
const GAS_LEN: usize = 12;
/// The ports past the last I/O port.
const IO_PORT_END: u64 = 0x1_0000;
/// The bytes of the FACS that hold its fields up to the reserved tail: the
/// length ACPI 6.5 § 5.2.10 requires at least.
pub const FACS_MIN_LEN: u64 = 64;
/// MADT structure type of an I/O APIC (section 5.2.12.3).
const MADT_TYPE_IO_APIC: u8 = 1;
/// Length of an I/O APIC structure: type, length, I/O APIC ID, reserved (u8
/// each), address (u32), GSI base (u32).
const MADT_IO_APIC_LEN: usize = 12;
/// MADT structure type of a Local APIC Address Override (section 5.2.12.8):
/// the local APIC's 64-bit address at offset 4, in place of the header's.
const MADT_TYPE_LAPIC_OVERRIDE: u8 = 5;
/// Length of a Local APIC Address Override.
const MADT_LAPIC_OVERRIDE_LEN: usize = 12;
/// MADT structure type of a RISC-V hart's interrupt controller (RINTC,
/// section 5.2.12.20): flags (u32, bit 0 enabled) at offset 4, its IMSIC
/// interrupt file's address (u64) at 24 and size (u32) at 32.
const MADT_TYPE_RINTC: u8 = 0x18;
/// MADT structure type of a RISC-V APLIC (section 5.2.12.22): its address
/// (u64) at offset 24 and size (u32) at 32.
const MADT_TYPE_APLIC: u8 = 0x1A;
/// Length of a RINTC or APLIC structure that carries its address and size.
const MADT_RISCV_WINDOW_LEN: usize = 36;
/// The bytes devmgr takes a local APIC or I/O APIC register window to span.
const APIC_WINDOW_BYTES: u64 = 0x1000;
/// MADT structure type of an Interrupt Source Override (section 5.2.12.5).
const MADT_TYPE_SOURCE_OVERRIDE: u8 = 2;
/// Length of an Interrupt Source Override: type, length, bus, source (u8
/// each), GSI (u32), MPS INTI flags (u16).
const MADT_SOURCE_OVERRIDE_LEN: usize = 10;

// ── RSDP / XSDT walkers ───────────────────────────────────────────────

// ── FADT → CENTURY ─────────────────────────────────────────────────────

/// Read the FADT's `CENTURY` field: the CMOS RAM index of the RTC's
/// century register.
///
/// Returns `None` if the signature isn't `FACP`, the table (bounded by its
/// reported length and the slice) does not reach the field, or the field is
/// zero, which the specification reserves for an RTC with no century
/// register.
#[must_use]
pub fn fadt_century_index(fadt_bytes: &[u8]) -> Option<u8>
{
    if sdt_signature(fadt_bytes) != *b"FACP"
    {
        return None;
    }
    let total_len = (sdt_length(fadt_bytes)? as usize).min(fadt_bytes.len());
    let index = *fadt_bytes.get(..total_len)?.get(FADT_OFF_CENTURY)?;
    if index == 0 { None } else { Some(index) }
}

// ── FADT → DSDT ────────────────────────────────────────────────────────

/// Read the physical address of the DSDT from the FADT: `X_DSDT` when the
/// table reaches it and it is non-zero, else the 32-bit `DSDT` field (ACPI
/// 6.x section 5.2.9).
///
/// Returns `None` if the signature isn't `FACP`, the table (bounded by its
/// reported length and the slice) reaches neither field, or both are zero.
#[must_use]
pub fn fadt_dsdt_phys(fadt_bytes: &[u8]) -> Option<u64>
{
    if sdt_signature(fadt_bytes) != *b"FACP"
    {
        return None;
    }
    let total_len = (sdt_length(fadt_bytes)? as usize).min(fadt_bytes.len());
    if total_len >= FADT_OFF_X_DSDT + 8
    {
        let x_dsdt = read_u64(fadt_bytes, FADT_OFF_X_DSDT);
        if x_dsdt != 0
        {
            return Some(x_dsdt);
        }
    }
    if total_len < FADT_OFF_DSDT + 4
    {
        return None;
    }
    let dsdt = u64::from(read_u32(fadt_bytes, FADT_OFF_DSDT));
    if dsdt == 0 { None } else { Some(dsdt) }
}

// ── FADT → fixed register blocks, FACS ─────────────────────────────────

/// One of the FADT's fixed register blocks in the I/O space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FadtBlock
{
    /// `PM1a_EVT_BLK`, `PM1_EVT_LEN` ports.
    Pm1aEvt,
    /// `PM1a_CNT_BLK`, `PM1_CNT_LEN` ports.
    Pm1aCnt,
    /// `GPE0_BLK`, `GPE0_BLK_LEN` ports.
    Gpe0,
    /// `SMI_CMD`, one port, with `ACPI_ENABLE`.
    SmiCmd,
}

/// Where a [`FadtBlock`] lies: its first port, its port count, and the value
/// the FADT gives with it (`ACPI_ENABLE` for [`FadtBlock::SmiCmd`], else 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoBlock
{
    pub port: u16,
    pub count: u16,
    pub value: u8,
}

/// Read where the FADT places `block` (ACPI 6.5 § 5.2.9).
///
/// Returns `None` if the signature isn't `FACP`, the table (bounded by its
/// reported length and the slice) does not reach the fields, the port is
/// zero or past 0xFFFF, the block's length is zero or runs past 0xFFFF, or
/// the FADT sets `HW_REDUCED_ACPI` (OSPM ignores the fixed-hardware fields
/// then, ACPI 6.5 § 5.2.9).
#[must_use]
pub fn fadt_io_block(fadt_bytes: &[u8], block: FadtBlock) -> Option<IoBlock>
{
    if sdt_signature(fadt_bytes) != *b"FACP"
    {
        return None;
    }
    let total_len = (sdt_length(fadt_bytes)? as usize).min(fadt_bytes.len());
    let table = fadt_bytes.get(..total_len)?;
    let byte = |off: usize| table.get(off).copied();
    let dword = |off: usize| {
        table
            .get(off..off.checked_add(4)?)
            .map(|_| read_u32(table, off))
    };
    if dword(FADT_OFF_FLAGS).is_some_and(|flags| flags & FADT_FLAG_HW_REDUCED_ACPI != 0)
    {
        return None;
    }
    let (port, count, value) = match block
    {
        FadtBlock::Pm1aEvt => (
            u64::from(dword(FADT_OFF_PM1A_EVT_BLK)?),
            byte(FADT_OFF_PM1_EVT_LEN)?,
            0,
        ),
        FadtBlock::Pm1aCnt => (
            u64::from(dword(FADT_OFF_PM1A_CNT_BLK)?),
            byte(FADT_OFF_PM1_CNT_LEN)?,
            0,
        ),
        FadtBlock::Gpe0 => (
            u64::from(dword(FADT_OFF_GPE0_BLK)?),
            byte(FADT_OFF_GPE0_BLK_LEN)?,
            0,
        ),
        FadtBlock::SmiCmd => (
            u64::from(dword(FADT_OFF_SMI_CMD)?),
            1,
            byte(FADT_OFF_ACPI_ENABLE)?,
        ),
    };
    let port = u16::try_from(port).ok().filter(|&p| p != 0)?;
    let count = u16::from(count);
    // A zero count has no last port; a block whose last port is past 0xFFFF
    // is not one the I/O space holds.
    count
        .checked_sub(1)
        .and_then(|last| port.checked_add(last))?;
    Some(IoBlock { port, count, value })
}

/// One of the two registers a hardware-reduced platform enters a sleep state
/// through (ACPI 6.5 § 4.8.3.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SleepRegister
{
    /// `SLEEP_CONTROL_REG`: `SLP_TYPx` and `SLP_EN` are written to it.
    Control,
    /// `SLEEP_STATUS_REG`: `WAK_STS` is cleared in it.
    Status,
}

/// Where a byte register of the FADT lies, a [`SleepRegister`] or
/// `RESET_REG`: its space and its address, a port in the I/O space or a
/// physical address in the memory space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedRegister
{
    pub space: crate::acpid::Space,
    pub address: u64,
}

/// Read where the FADT places `register` (ACPI 6.5 § 5.2.9 and § 4.8.3.7).
///
/// Returns `None` if the signature isn't `FACP`, the table (bounded by its
/// reported length and the slice) does not reach the register's Generic
/// Address Structure or `Flags`, `HW_REDUCED_ACPI` is clear (the field is
/// used only on a hardware-reduced platform), or the structure is not the
/// 8-bit register the specification defines: a space other than memory or
/// I/O, a bit width other than 8, a non-zero bit offset, an access size other
/// than undefined or byte, a zero address, or a port past 0xFFFF.
#[must_use]
pub fn fadt_sleep_register(fadt_bytes: &[u8], register: SleepRegister) -> Option<FixedRegister>
{
    if sdt_signature(fadt_bytes) != *b"FACP"
    {
        return None;
    }
    let total_len = (sdt_length(fadt_bytes)? as usize).min(fadt_bytes.len());
    let table = fadt_bytes.get(..total_len)?;
    let flags = table
        .get(FADT_OFF_FLAGS..FADT_OFF_FLAGS + 4)
        .map(|_| read_u32(table, FADT_OFF_FLAGS))?;
    if flags & FADT_FLAG_HW_REDUCED_ACPI == 0
    {
        return None;
    }
    let off = match register
    {
        SleepRegister::Control => FADT_OFF_SLEEP_CONTROL_REG,
        SleepRegister::Status => FADT_OFF_SLEEP_STATUS_REG,
    };
    byte_register(table.get(off..)?.first_chunk::<GAS_LEN>()?)
}

/// The FADT's `RESET_REG` and the `RESET_VALUE` written to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetRegister
{
    pub register: FixedRegister,
    pub value: u8,
}

/// Read the FADT's `RESET_REG` and `RESET_VALUE` (ACPI 6.5 § 5.2.9 and
/// § 4.8.4.6), in the memory or the I/O space, on a platform that is
/// hardware-reduced or not.
///
/// Returns `None` if the signature isn't `FACP`, the table (bounded by its
/// reported length and the slice) does not reach `RESET_VALUE`,
/// `RESET_REG_SUP` is clear, or the structure names no register acpid can
/// write one byte to. In the I/O space that is a zero port or one past
/// 0xFFFF: the bit width, the bit offset and the access size are not read,
/// as ACPICA's `AcpiReset` writes an I/O `RESET_REG` as one byte whatever
/// they say, since firmware is known to give them wrong. In the memory space
/// it is a structure that is not the 8-bit register the specification
/// defines, as [`fadt_sleep_register`] refuses one. A `RESET_REG` in any
/// other space, the PCI configuration space among them, which the
/// specification also allows, is refused.
#[must_use]
pub fn fadt_reset_register(fadt_bytes: &[u8]) -> Option<ResetRegister>
{
    if sdt_signature(fadt_bytes) != *b"FACP"
    {
        return None;
    }
    let total_len = (sdt_length(fadt_bytes)? as usize).min(fadt_bytes.len());
    let table = fadt_bytes.get(..total_len)?;
    let value = *table.get(FADT_OFF_RESET_VALUE)?;
    if read_u32(table, FADT_OFF_FLAGS) & FADT_FLAG_RESET_REG_SUP == 0
    {
        return None;
    }
    let gas = table.get(FADT_OFF_RESET_REG..)?.first_chunk::<GAS_LEN>()?;
    let register = if gas[0] == GAS_SPACE_IO
    {
        let address = read_u64(gas, 4);
        if address == 0 || address >= IO_PORT_END
        {
            return None;
        }
        FixedRegister {
            space: crate::acpid::Space::Io,
            address,
        }
    }
    else
    {
        byte_register(gas)?
    };
    Some(ResetRegister { register, value })
}

/// The register a Generic Address Structure `gas` places, when it is a byte
/// register: the memory or the I/O space, a bit width of 8, a bit offset of
/// 0, an access size undefined or byte, a non-zero address, and a port no
/// higher than 0xFFFF.
fn byte_register(gas: &[u8; GAS_LEN]) -> Option<FixedRegister>
{
    let &[space_id, bit_width, bit_offset, access, ..] = gas;
    let space = match space_id
    {
        GAS_SPACE_MEMORY => crate::acpid::Space::Memory,
        GAS_SPACE_IO => crate::acpid::Space::Io,
        _ => return None,
    };
    if bit_width != 8 || bit_offset != 0 || !(access == 0 || access == GAS_ACCESS_BYTE)
    {
        return None;
    }
    let address = read_u64(gas, 4);
    if address == 0 || (space == crate::acpid::Space::Io && address >= IO_PORT_END)
    {
        return None;
    }
    Some(FixedRegister { space, address })
}

/// Read the physical address of the FACS from the FADT: `X_FIRMWARE_CTRL`
/// when the table reaches it and it is non-zero, else `FIRMWARE_CTRL`.
///
/// Returns `None` if the signature isn't `FACP`, the table reaches neither
/// field, or both are zero (a hardware-reduced platform has no FACS).
#[must_use]
pub fn fadt_facs_phys(fadt_bytes: &[u8]) -> Option<u64>
{
    if sdt_signature(fadt_bytes) != *b"FACP"
    {
        return None;
    }
    let total_len = (sdt_length(fadt_bytes)? as usize).min(fadt_bytes.len());
    if total_len >= FADT_OFF_X_FIRMWARE_CTRL + 8
    {
        let x = read_u64(fadt_bytes, FADT_OFF_X_FIRMWARE_CTRL);
        if x != 0
        {
            return Some(x);
        }
    }
    if total_len < FADT_OFF_FIRMWARE_CTRL + 4
    {
        return None;
    }
    let facs = u64::from(read_u32(fadt_bytes, FADT_OFF_FIRMWARE_CTRL));
    if facs == 0 { None } else { Some(facs) }
}

/// Read the FADT's `SCI_INT`, the interrupt the SCI is wired to (ACPI 6.5
/// § 5.2.9): an ISA IRQ, which the MADT's overrides map to its GSI
/// ([`sci_gsi`]).
///
/// Returns `None` if the signature isn't `FACP`, the table (bounded by its
/// reported length and the slice) does not reach `Flags`, `HW_REDUCED_ACPI`
/// is set (such a platform signals its events through other interrupts and
/// leaves `SCI_INT` unused), or `SCI_INT` is 0, the PIT's line on a PC,
/// which no SCI is wired to.
#[must_use]
pub fn fadt_sci_int(fadt_bytes: &[u8]) -> Option<u16>
{
    if sdt_signature(fadt_bytes) != *b"FACP"
    {
        return None;
    }
    let total_len = (sdt_length(fadt_bytes)? as usize).min(fadt_bytes.len());
    let table = fadt_bytes.get(..total_len)?;
    let flags = table
        .get(FADT_OFF_FLAGS..FADT_OFF_FLAGS + 4)
        .map(|_| read_u32(table, FADT_OFF_FLAGS))?;
    if flags & FADT_FLAG_HW_REDUCED_ACPI != 0
    {
        return None;
    }
    let sci = table
        .get(FADT_OFF_SCI_INT..FADT_OFF_SCI_INT + 2)
        .map(|_| read_u16(table, FADT_OFF_SCI_INT))?;
    if sci == 0 { None } else { Some(sci) }
}

/// The GSI the SCI wired to `SCI_INT` `sci_int` is delivered on: the GSI of
/// the first override in `overrides` whose source is `sci_int`, else
/// `sci_int` itself, as an ISA IRQ no override names is identity-mapped
/// (ACPI 6.5 § 5.2.12.5). The line's mode is its GSI's
/// ([`line_mode`]): an override's trigger and polarity, else level and
/// active-low, which is also the SCI's own default (ACPI 6.5 § 5.2.9, a
/// sharable, level, active-low interrupt).
#[must_use]
pub fn sci_gsi(overrides: impl IntoIterator<Item = SourceOverride>, sci_int: u16) -> u32
{
    overrides
        .into_iter()
        .find(|o| u16::from(o.source) == sci_int)
        .map_or(u32::from(sci_int), |o| o.gsi)
}

// ── MCFG → ECAM ────────────────────────────────────────────────────────

// ── MADT → interrupt source overrides ──────────────────────────────────

/// One MADT Interrupt Source Override (ACPI 6.x section 5.2.12.5): ISA IRQ
/// `source` is delivered on `gsi`, with the trigger and polarity its MPS INTI
/// `flags` give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceOverride
{
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}

/// The Interrupt Source Override of the MADT structure of type `kind` and
/// length `len` at `at`; `None` for a structure of another type or one
/// shorter than an override's 10 bytes.
pub(crate) fn madt_source_override(
    madt_bytes: &[u8],
    kind: u8,
    at: usize,
    len: usize,
) -> Option<SourceOverride>
{
    (kind == MADT_TYPE_SOURCE_OVERRIDE && len >= MADT_SOURCE_OVERRIDE_LEN).then(|| SourceOverride {
        source: read_u8(madt_bytes, at.saturating_add(3)),
        gsi: read_u32(madt_bytes, at.saturating_add(4)),
        flags: read_u16(madt_bytes, at.saturating_add(8)),
    })
}

/// The I/O APIC of the MADT structure of type `kind` and length `len` at
/// `at`; `None` for a structure of another type or one shorter than an I/O
/// APIC's 12 bytes.
pub(crate) fn madt_io_apic(madt_bytes: &[u8], kind: u8, at: usize, len: usize) -> Option<IoApic>
{
    (kind == MADT_TYPE_IO_APIC && len >= MADT_IO_APIC_LEN).then(|| IoApic {
        id: read_u8(madt_bytes, at.saturating_add(2)),
        gsi_base: read_u32(madt_bytes, at.saturating_add(8)),
    })
}

/// The register window, `(base, length)`, of the interrupt controller the
/// MADT structure of type `kind` and length `len` at `at` describes, as
/// [`madt_interrupt_controllers`] lists them; `None` for a structure that
/// describes none, or a window of a zero base or length.
pub(crate) fn madt_controller_window(
    madt_bytes: &[u8],
    kind: u8,
    at: usize,
    len: usize,
) -> Option<(u64, u64)>
{
    let field = |off: usize| at.saturating_add(off);
    match kind
    {
        MADT_TYPE_IO_APIC if len >= MADT_IO_APIC_LEN =>
        {
            Some((u64::from(read_u32(madt_bytes, field(4))), APIC_WINDOW_BYTES))
        }
        MADT_TYPE_LAPIC_OVERRIDE if len >= MADT_LAPIC_OVERRIDE_LEN =>
        {
            Some((read_u64(madt_bytes, field(4)), APIC_WINDOW_BYTES))
        }
        MADT_TYPE_RINTC
            if len >= MADT_RISCV_WINDOW_LEN && read_u32(madt_bytes, field(4)) & 1 != 0 =>
        {
            Some((
                read_u64(madt_bytes, field(24)),
                u64::from(read_u32(madt_bytes, field(32))),
            ))
        }
        MADT_TYPE_APLIC if len >= MADT_RISCV_WINDOW_LEN => Some((
            read_u64(madt_bytes, field(24)),
            u64::from(read_u32(madt_bytes, field(32))),
        )),
        _ => None,
    }
    .filter(|&(base, length)| base != 0 && length != 0)
}

/// The local APIC's register window the MADT header gives, `(address,
/// length)`; `None` for a zero address.
pub(crate) fn madt_header_window(madt_bytes: &[u8]) -> Option<(u64, u64)>
{
    let address = u64::from(read_u32(madt_bytes, SDT_HDR_LEN));
    (address != 0).then_some((address, APIC_WINDOW_BYTES))
}

/// Iterate the MADT's Interrupt Source Overrides.
///
/// Returns `None` for a table that is not a MADT, and ends at a malformed
/// structure, as `madt_structures` does. A source override shorter than its
/// 10 bytes is skipped.
#[must_use]
pub fn madt_source_overrides(madt_bytes: &[u8])
-> Option<impl Iterator<Item = SourceOverride> + '_>
{
    Some(
        madt_structures(madt_bytes)?
            .filter_map(|(kind, at, len)| madt_source_override(madt_bytes, kind, at, len)),
    )
}

/// One MADT I/O APIC structure (ACPI 6.x section 5.2.12.3): the I/O APIC
/// with ID `id` delivers the GSIs from `gsi_base` on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoApic
{
    pub id: u8,
    pub gsi_base: u32,
}

/// Iterate the MADT's I/O APICs.
///
/// Returns `None` for a table that is not a MADT, and ends at a malformed
/// structure, as `madt_structures` does. An I/O APIC structure shorter than
/// its 12 bytes is skipped.
#[must_use]
pub fn madt_io_apics(madt_bytes: &[u8]) -> Option<impl Iterator<Item = IoApic> + '_>
{
    Some(
        madt_structures(madt_bytes)?
            .filter_map(|(kind, at, len)| madt_io_apic(madt_bytes, kind, at, len)),
    )
}

/// The register windows, `(base, length)`, of the interrupt controllers the
/// MADT describes, which the kernel programs: the local APIC (the header's
/// address, and an override's), each I/O APIC, each enabled hart's IMSIC
/// interrupt file, and each APLIC. Zero addresses and lengths are left out.
///
/// Returns `None` for a table that is not a MADT, and ends at a malformed
/// structure, as `madt_structures` does.
#[must_use]
pub fn madt_interrupt_controllers(
    madt_bytes: &[u8],
) -> Option<impl Iterator<Item = (u64, u64)> + '_>
{
    let windows = madt_structures(madt_bytes)?
        .filter_map(|(kind, at, len)| madt_controller_window(madt_bytes, kind, at, len));
    Some(madt_header_window(madt_bytes).into_iter().chain(windows))
}

/// The I/O APIC of `io_apics` that delivers `gsi`: the one with the highest
/// GSI base at or below it, since each I/O APIC delivers a contiguous run of
/// GSIs from its base, and the runs do not overlap. `None` when every base
/// lies above `gsi`.
#[must_use]
pub fn io_apic_for(io_apics: impl IntoIterator<Item = IoApic>, gsi: u32) -> Option<IoApic>
{
    io_apics
        .into_iter()
        .filter(|a| a.gsi_base <= gsi)
        .max_by_key(|a| a.gsi_base)
}

/// Whether the MADT's structures run, each of length 2 or more, exactly to the
/// table's end (its reported length bounded by the slice), so
/// [`madt_source_overrides`] read every override the table holds. `false` too
/// for a table that is not a MADT.
#[must_use]
pub fn madt_well_formed(madt_bytes: &[u8]) -> bool
{
    let Some(end) = madt_end(madt_bytes)
    else
    {
        return false;
    };
    let mut off = MADT_ENTRIES_OFF;
    while let Some((_, len)) = madt_structure(madt_bytes, off, end)
    {
        off = off.saturating_add(len);
    }
    off == end
}

/// The `SYS_IRQ_REGISTER` mode of a PCI `INTx` line: level-triggered,
/// active-low, the PCI default, which a line no override names takes.
pub const PCI_INTX_MODE: u64 = IRQ_MODE_LEVEL | IRQ_MODE_ACTIVE_LOW;

/// The `SYS_IRQ_REGISTER` mode of PCI `INTx` line `gsi`: the trigger and
/// polarity of the first override in `overrides` that names it, field by
/// field, with [`PCI_INTX_MODE`]'s for a field the override leaves
/// "conforms to bus" (0) or reserved (2), and [`PCI_INTX_MODE`] when no
/// override names it.
///
/// MPS INTI flags: bits 1:0 are the polarity (1 active-high, 3 active-low),
/// bits 3:2 the trigger mode (1 edge, 3 level).
#[must_use]
pub fn line_mode(overrides: impl IntoIterator<Item = SourceOverride>, gsi: u32) -> u64
{
    let Some(found) = overrides.into_iter().find(|o| o.gsi == gsi)
    else
    {
        return PCI_INTX_MODE;
    };
    let polarity = match found.flags & 0b11
    {
        1 => 0,
        3 => IRQ_MODE_ACTIVE_LOW,
        _ => PCI_INTX_MODE & IRQ_MODE_ACTIVE_LOW,
    };
    let trigger = match (found.flags >> 2) & 0b11
    {
        1 => 0,
        3 => IRQ_MODE_LEVEL,
        _ => PCI_INTX_MODE & IRQ_MODE_LEVEL,
    };
    polarity | trigger
}

/// The GSI and `SYS_IRQ_REGISTER` mode of ISA IRQ `irq`, whose device
/// describes it with mode `described` (an ACPI IRQ descriptor's trigger and
/// polarity, edge and active-high when it gives none): the GSI of the first
/// override in `overrides` whose source is `irq`, with that override's trigger
/// and polarity, field by field, `described`'s for a field it leaves
/// "conforms to bus" (0) or reserved (2); `irq` itself and `described` when
/// no override names it (ACPI 6.x section 5.2.12.5).
#[must_use]
pub fn isa_line(
    overrides: impl IntoIterator<Item = SourceOverride>,
    irq: u8,
    described: u64,
) -> (u32, u64)
{
    let Some(found) = overrides.into_iter().find(|o| o.source == irq)
    else
    {
        return (u32::from(irq), described);
    };
    let polarity = match found.flags & 0b11
    {
        1 => 0,
        3 => IRQ_MODE_ACTIVE_LOW,
        _ => described & IRQ_MODE_ACTIVE_LOW,
    };
    let trigger = match (found.flags >> 2) & 0b11
    {
        1 => 0,
        3 => IRQ_MODE_LEVEL,
        _ => described & IRQ_MODE_LEVEL,
    };
    (found.gsi, polarity | trigger)
}

// ── Table mapping window ─────────────────────────────────────────────

/// The page window of a firmware Memory cap that holds one table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableWindow
{
    /// First page of the window, counted from the start of the region.
    pub first_page: u64,
    /// Pages the window spans.
    pub page_count: u64,
    /// Byte offset of the table's start inside the window.
    pub offset: usize,
    /// Bytes of the table the window holds: its length, clamped to the
    /// region's end.
    pub len: usize,
}

/// The pages of a region `[region_base, region_base + region_size)` that
/// hold the `len` bytes of a table at physical address `table_phys`, so a
/// caller maps the table at its own offset instead of the region from its
/// base. The table is clamped to the region's end.
///
/// Returns `None` when `len` or `page_size` is zero, the table does not
/// start inside the region, or the window does not fit a `usize`.
#[must_use]
pub fn table_window(
    region_base: u64,
    region_size: u64,
    table_phys: u64,
    len: u64,
    page_size: u64,
) -> Option<TableWindow>
{
    if len == 0 || page_size == 0
    {
        return None;
    }
    let off = table_phys.checked_sub(region_base)?;
    if off >= region_size
    {
        return None;
    }
    let held = len.min(region_size.saturating_sub(off));
    let first_page = off.checked_div(page_size)?;
    let in_window = off.checked_rem(page_size)?;
    let page_count = in_window.checked_add(held)?.div_ceil(page_size);
    Some(TableWindow {
        first_page,
        page_count,
        offset: usize::try_from(in_window).ok()?,
        len: usize::try_from(held).ok()?,
    })
}

#[cfg(test)]
mod tests
{
    use firmware_tables::acpi::SDT_OFF_LENGTH;

    use super::*;

    /// An SDT of `len` reported bytes with `sig`, backed by `len` bytes.
    fn sdt(sig: [u8; 4], len: u32) -> Vec<u8>
    {
        let mut b = vec![0u8; len as usize];
        b[..4].copy_from_slice(&sig);
        b[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&len.to_le_bytes());
        b
    }

    #[test]
    fn table_deep_in_a_region_maps_a_window_at_its_own_offset()
    {
        // A 64-byte table 2 MiB + 0x10 into a 4 MiB region.
        let w = table_window(0x1000_0000, 4 << 20, 0x1020_0010, 64, 0x1000).unwrap();
        assert_eq!(
            w,
            TableWindow {
                first_page: 0x200,
                page_count: 1,
                offset: 0x10,
                len: 64,
            }
        );
    }

    #[test]
    fn table_straddling_a_page_spans_both_pages()
    {
        let w = table_window(0, 0x10_0000, 0x1FF0, 0x20, 0x1000).unwrap();
        assert_eq!(
            (w.first_page, w.page_count, w.offset, w.len),
            (1, 2, 0xFF0, 0x20)
        );
    }

    #[test]
    fn table_running_past_its_region_is_clamped_to_the_region_end()
    {
        let w = table_window(0x1000, 0x3000, 0x2800, 1 << 30, 0x1000).unwrap();
        assert_eq!(
            (w.first_page, w.page_count, w.offset, w.len),
            (1, 2, 0x800, 0x1800)
        );
    }

    #[test]
    fn table_outside_its_region_or_empty_has_no_window()
    {
        assert!(table_window(0x1000, 0x1000, 0x800, 8, 0x1000).is_none());
        assert!(table_window(0x1000, 0x1000, 0x2000, 8, 0x1000).is_none());
        assert!(table_window(0x1000, 0x1000, 0x1000, 0, 0x1000).is_none());
    }

    fn fadt(len: u32, pm1a: u32) -> Vec<u8>
    {
        let mut b = sdt(*b"FACP", len);
        if b.len() >= FADT_OFF_PM1A_CNT_BLK + 4
        {
            b[FADT_OFF_PM1A_CNT_BLK..FADT_OFF_PM1A_CNT_BLK + 4]
                .copy_from_slice(&pm1a.to_le_bytes());
        }
        b
    }

    /// A FADT whose `CENTURY` byte is `century`, `len` bytes long.
    fn fadt_with_century(len: u32, century: u8) -> Vec<u8>
    {
        let mut b = fadt(len, 0x604);
        if b.len() > FADT_OFF_CENTURY
        {
            b[FADT_OFF_CENTURY] = century;
        }
        b
    }

    #[test]
    fn fadt_yields_its_century_register_index()
    {
        assert_eq!(
            fadt_century_index(&fadt_with_century(244, 0x32)),
            Some(0x32)
        );
    }

    #[test]
    fn fadt_with_no_century_register_or_too_short_yields_none()
    {
        // Zero is the specification's "no century register".
        assert_eq!(fadt_century_index(&fadt_with_century(244, 0)), None);
        // An ACPI 1.0-sized table ending before offset 108.
        assert_eq!(fadt_century_index(&fadt_with_century(108, 0x32)), None);
        let mut other = fadt_with_century(244, 0x32);
        other[0..4].copy_from_slice(b"APIC");
        assert_eq!(fadt_century_index(&other), None);
    }

    /// A MADT holding `structures` (each a type, then its body), with its
    /// reported length covering them all.
    fn madt(structures: &[&[u8]]) -> Vec<u8>
    {
        let body: usize = structures.iter().map(|s| s.len()).sum();
        let len = u32::try_from(MADT_ENTRIES_OFF + body).unwrap();
        let mut b = sdt(*b"APIC", len);
        let mut off = MADT_ENTRIES_OFF;
        for s in structures
        {
            b[off..off + s.len()].copy_from_slice(s);
            off += s.len();
        }
        b
    }

    fn source_override(source: u8, gsi: u32, flags: u16) -> [u8; MADT_SOURCE_OVERRIDE_LEN]
    {
        let mut s = [0u8; MADT_SOURCE_OVERRIDE_LEN];
        s[0] = MADT_TYPE_SOURCE_OVERRIDE;
        s[1] = u8::try_from(MADT_SOURCE_OVERRIDE_LEN).unwrap();
        s[3] = source;
        s[4..8].copy_from_slice(&gsi.to_le_bytes());
        s[8..10].copy_from_slice(&flags.to_le_bytes());
        s
    }

    /// A local APIC structure (type 0, 8 bytes): not an override.
    const LOCAL_APIC: [u8; 8] = [0, 8, 0, 0, 1, 0, 0, 0];

    #[test]
    fn madt_interrupt_controllers_name_every_apic_and_aia_window()
    {
        let mut io_apic = [0u8; MADT_IO_APIC_LEN];
        io_apic[0] = MADT_TYPE_IO_APIC;
        io_apic[1] = 12;
        io_apic[4..8].copy_from_slice(&0xFEC0_0000u32.to_le_bytes());
        let mut over = [0u8; MADT_LAPIC_OVERRIDE_LEN];
        over[0] = MADT_TYPE_LAPIC_OVERRIDE;
        over[1] = 12;
        over[4..12].copy_from_slice(&0x1_FEE0_0000u64.to_le_bytes());
        let riscv = |kind: u8, flags: u32, base: u64, size: u32| {
            let mut s = [0u8; MADT_RISCV_WINDOW_LEN];
            s[0] = kind;
            s[1] = 36;
            s[4..8].copy_from_slice(&flags.to_le_bytes());
            s[24..32].copy_from_slice(&base.to_le_bytes());
            s[32..36].copy_from_slice(&size.to_le_bytes());
            s
        };
        let hart = riscv(MADT_TYPE_RINTC, 1, 0x2800_0000, 0x1000);
        let off = riscv(MADT_TYPE_RINTC, 0, 0x2800_1000, 0x1000);
        let aplic = riscv(MADT_TYPE_APLIC, 0, 0xD00_0000, 0x8000);
        let mut table = madt(&[&LOCAL_APIC, &io_apic, &over, &hart, &off, &aplic]);
        table[SDT_HDR_LEN..SDT_HDR_LEN + 4].copy_from_slice(&0xFEE0_0000u32.to_le_bytes());
        let windows: Vec<_> = madt_interrupt_controllers(&table).unwrap().collect();
        assert_eq!(
            windows,
            [
                (0xFEE0_0000, 0x1000),
                (0xFEC0_0000, 0x1000),
                (0x1_FEE0_0000, 0x1000),
                (0x2800_0000, 0x1000),
                (0xD00_0000, 0x8000),
            ]
        );
        assert!(madt_interrupt_controllers(&sdt(*b"FACP", 64)).is_none());
    }

    // Defect caught: a window of a zero base or length handed to the
    // kernel to program.
    #[test]
    fn madt_interrupt_controllers_leave_out_zero_windows()
    {
        let io_apic = [MADT_TYPE_IO_APIC, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let riscv = |base: u64, size: u32| {
            let mut s = [0u8; MADT_RISCV_WINDOW_LEN];
            s[0] = MADT_TYPE_APLIC;
            s[1] = 36;
            s[24..32].copy_from_slice(&base.to_le_bytes());
            s[32..36].copy_from_slice(&size.to_le_bytes());
            s
        };
        let no_size = riscv(0xD00_0000, 0);
        let no_base = riscv(0, 0x8000);
        let table = madt(&[&io_apic, &no_size, &no_base]);
        assert_eq!(madt_header_window(&table), None);
        assert_eq!(madt_interrupt_controllers(&table).unwrap().count(), 0);
        let at = SDT_HDR_LEN + 8;
        assert_eq!(
            madt_controller_window(&table, MADT_TYPE_IO_APIC, at, 12),
            None
        );
    }

    #[test]
    fn madt_overrides_are_read_past_other_structures()
    {
        let iso0 = source_override(0, 2, 0);
        let override_gsi10 = source_override(10, 10, 0xd);
        let table = madt(&[&LOCAL_APIC, &iso0, &LOCAL_APIC, &override_gsi10]);
        let found: Vec<_> = madt_source_overrides(&table).expect("MADT").collect();
        assert_eq!(
            found,
            vec![
                SourceOverride {
                    source: 0,
                    gsi: 2,
                    flags: 0
                },
                SourceOverride {
                    source: 10,
                    gsi: 10,
                    flags: 0xd
                },
            ]
        );
    }

    /// An I/O APIC structure (type 1, 12 bytes) for `id` at `gsi_base`.
    fn io_apic(id: u8, gsi_base: u32) -> [u8; MADT_IO_APIC_LEN]
    {
        let mut s = [0u8; MADT_IO_APIC_LEN];
        s[0] = MADT_TYPE_IO_APIC;
        s[1] = u8::try_from(MADT_IO_APIC_LEN).unwrap();
        s[2] = id;
        s[4..8].copy_from_slice(&0xfec0_0000u32.to_le_bytes());
        s[8..12].copy_from_slice(&gsi_base.to_le_bytes());
        s
    }

    #[test]
    fn madt_io_apics_are_read_past_other_structures_and_a_short_one_skipped()
    {
        let short = [MADT_TYPE_IO_APIC, 8, 9, 0, 0, 0, 0, 0];
        let iso = source_override(0, 2, 0);
        let table = madt(&[&LOCAL_APIC, &io_apic(0, 0), &iso, &short, &io_apic(2, 24)]);
        let found: Vec<_> = madt_io_apics(&table).expect("MADT").collect();
        assert_eq!(
            found,
            [
                IoApic { id: 0, gsi_base: 0 },
                IoApic {
                    id: 2,
                    gsi_base: 24
                }
            ]
        );
        assert!(madt_io_apics(&sdt(*b"FACP", 64)).is_none());
    }

    #[test]
    fn a_gsi_belongs_to_the_io_apic_with_the_highest_base_at_or_below_it()
    {
        let apics = [
            IoApic {
                id: 2,
                gsi_base: 24,
            },
            IoApic { id: 0, gsi_base: 0 },
        ];
        assert_eq!(io_apic_for(apics, 0).map(|a| a.id), Some(0));
        assert_eq!(io_apic_for(apics, 23).map(|a| a.id), Some(0));
        assert_eq!(io_apic_for(apics, 24).map(|a| a.id), Some(2));
        assert_eq!(io_apic_for(apics, 100).map(|a| a.id), Some(2));
        let high = [IoApic {
            id: 1,
            gsi_base: 16,
        }];
        assert_eq!(io_apic_for(high, 4), None);
    }

    #[test]
    fn a_table_that_is_not_a_madt_is_refused()
    {
        assert!(madt_source_overrides(&sdt(*b"FACP", 64)).is_none());
        // Reported length short of the first structure.
        assert!(madt_source_overrides(&sdt(*b"APIC", 40)).is_none());
        assert!(madt_source_overrides(&[]).is_none());
    }

    #[test]
    fn a_malformed_structure_ends_the_walk_after_the_overrides_before_it()
    {
        let iso = source_override(9, 9, 0xd);
        // A zero-length structure, then an override the walk must not reach.
        let table = madt(&[&iso, &[2, 0], &source_override(11, 11, 0xd)]);
        let found: Vec<_> = madt_source_overrides(&table).expect("MADT").collect();
        assert_eq!(
            found,
            vec![SourceOverride {
                source: 9,
                gsi: 9,
                flags: 0xd
            }]
        );
        // A structure running past the reported length.
        let mut table = madt(&[&iso, &LOCAL_APIC]);
        let last = table.len() - LOCAL_APIC.len();
        table[last + 1] = 200;
        assert_eq!(madt_source_overrides(&table).expect("MADT").count(), 1);
    }

    #[test]
    fn a_source_override_shorter_than_its_ten_bytes_is_skipped()
    {
        let short = [MADT_TYPE_SOURCE_OVERRIDE, 8, 0, 9, 9, 0, 0, 0];
        let table = madt(&[&short, &source_override(10, 10, 0xd)]);
        let found: Vec<_> = madt_source_overrides(&table).expect("MADT").collect();
        assert_eq!(
            found,
            vec![SourceOverride {
                source: 10,
                gsi: 10,
                flags: 0xd
            }]
        );
    }

    #[test]
    fn a_walk_that_reaches_the_tables_end_is_well_formed()
    {
        assert!(madt_well_formed(&madt(&[
            &LOCAL_APIC,
            &source_override(10, 10, 0xd)
        ])));
        assert!(madt_well_formed(&madt(&[])));
    }

    #[test]
    fn a_walk_cut_short_is_not_well_formed()
    {
        let iso = source_override(9, 9, 0xd);
        assert!(!madt_well_formed(&madt(&[&iso, &[2, 0]])));
        let mut table = madt(&[&iso, &LOCAL_APIC]);
        let last = table.len() - LOCAL_APIC.len();
        table[last + 1] = 200;
        assert!(!madt_well_formed(&table));
    }

    #[test]
    fn a_single_trailing_byte_is_not_well_formed_and_ends_both_walks()
    {
        let table = madt(&[&source_override(10, 10, 0xd), &[0]]);
        assert!(!madt_well_formed(&table));
        assert_eq!(madt_source_overrides(&table).expect("MADT").count(), 1);
    }

    #[test]
    fn a_header_short_of_the_first_structure_or_another_table_is_not_well_formed()
    {
        assert!(!madt_well_formed(&sdt(*b"APIC", 40)));
        assert!(!madt_well_formed(&sdt(*b"FACP", 64)));
        assert!(!madt_well_formed(&[]));
    }

    #[test]
    fn a_line_no_override_names_takes_the_pci_default()
    {
        assert_eq!(
            line_mode(
                [SourceOverride {
                    source: 10,
                    gsi: 10,
                    flags: 0xd
                }],
                16
            ),
            PCI_INTX_MODE
        );
        assert_eq!(line_mode([], 11), IRQ_MODE_LEVEL | IRQ_MODE_ACTIVE_LOW);
    }

    #[test]
    fn an_override_gives_the_lines_trigger_and_polarity()
    {
        // QEMU's PCI lines: level, active-high (flags 0xd).
        let iso = |flags| {
            [SourceOverride {
                source: 10,
                gsi: 10,
                flags,
            }]
        };
        assert_eq!(line_mode(iso(0xd), 10), IRQ_MODE_LEVEL);
        // Edge, active-high.
        assert_eq!(line_mode(iso(0b0101), 10), 0);
        // Level, active-low.
        assert_eq!(
            line_mode(iso(0b1111), 10),
            IRQ_MODE_LEVEL | IRQ_MODE_ACTIVE_LOW
        );
        // Edge, active-low.
        assert_eq!(line_mode(iso(0b0111), 10), IRQ_MODE_ACTIVE_LOW);
    }

    #[test]
    fn a_conforming_or_reserved_field_takes_the_pci_default_for_that_field()
    {
        let iso = |flags| {
            [SourceOverride {
                source: 10,
                gsi: 10,
                flags,
            }]
        };
        // Both fields conform: the PCI default.
        assert_eq!(line_mode(iso(0), 10), PCI_INTX_MODE);
        // Polarity active-high, trigger conforms: level from the default.
        assert_eq!(line_mode(iso(0b0001), 10), IRQ_MODE_LEVEL);
        // Polarity reserved, trigger edge: active-low from the default.
        assert_eq!(line_mode(iso(0b0110), 10), IRQ_MODE_ACTIVE_LOW);
    }

    /// A FADT `len` bytes long whose 32-bit `DSDT` field is `dsdt` and whose
    /// `X_DSDT` field, when the table reaches it, is `x_dsdt`.
    fn fadt_with_dsdt(len: u32, dsdt: u32, x_dsdt: u64) -> Vec<u8>
    {
        let mut b = fadt(len, 0x604);
        if b.len() >= FADT_OFF_DSDT + 4
        {
            b[FADT_OFF_DSDT..FADT_OFF_DSDT + 4].copy_from_slice(&dsdt.to_le_bytes());
        }
        if b.len() >= FADT_OFF_X_DSDT + 8
        {
            b[FADT_OFF_X_DSDT..FADT_OFF_X_DSDT + 8].copy_from_slice(&x_dsdt.to_le_bytes());
        }
        b
    }

    #[test]
    fn fadt_dsdt_prefers_a_nonzero_x_dsdt()
    {
        let t = fadt_with_dsdt(276, 0x7FE0_0000, 0x1_7FE0_0000);
        assert_eq!(fadt_dsdt_phys(&t), Some(0x1_7FE0_0000));
        // A zero X_DSDT falls back to the 32-bit field.
        let t = fadt_with_dsdt(276, 0x7FE0_0000, 0);
        assert_eq!(fadt_dsdt_phys(&t), Some(0x7FE0_0000));
        // An ACPI 1.0 FADT that stops before X_DSDT.
        let t = fadt_with_dsdt(116, 0x7FE0_0000, 0x1_7FE0_0000);
        assert_eq!(fadt_dsdt_phys(&t), Some(0x7FE0_0000));
    }

    #[test]
    fn fadt_dsdt_refuses_a_zero_short_or_foreign_table()
    {
        assert_eq!(fadt_dsdt_phys(&fadt_with_dsdt(276, 0, 0)), None);
        // The reported length stops before the DSDT field.
        assert_eq!(fadt_dsdt_phys(&fadt_with_dsdt(42, 0x7FE0_0000, 0)), None);
        // The slice is shorter than the reported length: X_DSDT is not read.
        let mut t = fadt_with_dsdt(276, 0x7FE0_0000, 0x1_7FE0_0000);
        t.truncate(FADT_OFF_X_DSDT + 4);
        assert_eq!(fadt_dsdt_phys(&t), Some(0x7FE0_0000));
        let mut t = fadt_with_dsdt(276, 0x7FE0_0000, 0);
        t[..4].copy_from_slice(b"APIC");
        assert_eq!(fadt_dsdt_phys(&t), None);
    }

    /// A FADT of 276 bytes with QEMU q35's fixed blocks: `PM1a` event 0x600
    /// (4), `PM1a` control 0x604 (2), `GPE0` 0x620 (16), `SMI_CMD` 0xB2 with
    /// `ACPI_ENABLE` 0xF1, `RESET_REG` port 0xCF9 with value 6, FACS at
    /// `facs` in `X_FIRMWARE_CTRL`.
    fn q35_fadt(facs: u64) -> Vec<u8>
    {
        let mut b = fadt(276, 0x604);
        let mut put32 = |off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());
        put32(FADT_OFF_PM1A_EVT_BLK, 0x600);
        put32(FADT_OFF_GPE0_BLK, 0x620);
        put32(FADT_OFF_SMI_CMD, 0xB2);
        put32(FADT_OFF_FLAGS, FADT_FLAG_RESET_REG_SUP);
        b[FADT_OFF_ACPI_ENABLE] = 0xF1;
        b[FADT_OFF_PM1_EVT_LEN] = 4;
        b[FADT_OFF_PM1_CNT_LEN] = 2;
        b[FADT_OFF_GPE0_BLK_LEN] = 16;
        b[FADT_OFF_RESET_REG] = GAS_SPACE_IO;
        b[FADT_OFF_RESET_REG + 1] = 8;
        b[FADT_OFF_RESET_REG + 4..FADT_OFF_RESET_REG + 12].copy_from_slice(&0xCF9u64.to_le_bytes());
        b[FADT_OFF_RESET_VALUE] = 6;
        b[FADT_OFF_X_FIRMWARE_CTRL..FADT_OFF_X_FIRMWARE_CTRL + 8]
            .copy_from_slice(&facs.to_le_bytes());
        b
    }

    #[test]
    fn fadt_gives_each_fixed_io_block()
    {
        let t = q35_fadt(0x7FEB_1000);
        let block = |port, count, value| Some(IoBlock { port, count, value });
        assert_eq!(fadt_io_block(&t, FadtBlock::Pm1aEvt), block(0x600, 4, 0));
        assert_eq!(fadt_io_block(&t, FadtBlock::Pm1aCnt), block(0x604, 2, 0));
        assert_eq!(fadt_io_block(&t, FadtBlock::Gpe0), block(0x620, 16, 0));
        assert_eq!(fadt_io_block(&t, FadtBlock::SmiCmd), block(0xB2, 1, 0xF1));
        assert_eq!(fadt_facs_phys(&t), Some(0x7FEB_1000));
    }

    #[test]
    fn fadt_gives_its_sci_unless_hardware_reduced_zero_or_short()
    {
        let mut t = q35_fadt(0);
        t[FADT_OFF_SCI_INT..FADT_OFF_SCI_INT + 2].copy_from_slice(&9u16.to_le_bytes());
        assert_eq!(fadt_sci_int(&t), Some(9));
        // A vector past the ISA range is read whole.
        t[FADT_OFF_SCI_INT..FADT_OFF_SCI_INT + 2].copy_from_slice(&0x114u16.to_le_bytes());
        assert_eq!(fadt_sci_int(&t), Some(0x114));
        let mut reduced = t.clone();
        let flags = read_u32(&reduced, FADT_OFF_FLAGS) | FADT_FLAG_HW_REDUCED_ACPI;
        reduced[FADT_OFF_FLAGS..FADT_OFF_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(fadt_sci_int(&reduced), None);
        // The reported length stops before Flags.
        let mut short = t.clone();
        short[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&112u32.to_le_bytes());
        assert_eq!(fadt_sci_int(&short), None);
        t[FADT_OFF_SCI_INT..FADT_OFF_SCI_INT + 2].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(fadt_sci_int(&t), None);
        t[..4].copy_from_slice(b"APIC");
        assert_eq!(fadt_sci_int(&t), None);
    }

    #[test]
    fn sci_gsi_follows_the_override_of_its_source_else_is_identity()
    {
        let over = |source, gsi, flags| SourceOverride { source, gsi, flags };
        // QEMU q35: IRQ 0 -> GSI 2, and SCI_INT 9 overridden onto itself,
        // level and active-high.
        let q35 = [over(0, 2, 0), over(9, 9, 0xD)];
        assert_eq!(sci_gsi(q35, 9), 9);
        assert_eq!(line_mode(q35, 9), IRQ_MODE_LEVEL);
        // An override moving the SCI elsewhere; one only targeting its line
        // does not move it.
        assert_eq!(sci_gsi([over(9, 20, 0)], 9), 20);
        assert_eq!(sci_gsi([over(5, 9, 0)], 9), 9);
        // No override: identity, and the SCI's default mode.
        assert_eq!(sci_gsi([], 9), 9);
        assert_eq!(line_mode([], 9), PCI_INTX_MODE);
        assert_eq!(sci_gsi([over(9, 20, 0)], 0x109), 0x109);
    }

    /// A hardware-reduced FADT of 276 bytes whose `SLEEP_CONTROL_REG` and
    /// `SLEEP_STATUS_REG` are the 8-bit registers of `space` at `control`
    /// and `status`. Its fixed blocks and `SMI_CMD` are left as q35's, as
    /// stale fields a hardware-reduced platform's OSPM ignores.
    fn reduced_fadt(space: u8, control: u64, status: u64) -> Vec<u8>
    {
        let mut b = fadt(276, 0x604);
        b[FADT_OFF_PM1A_EVT_BLK..FADT_OFF_PM1A_EVT_BLK + 4]
            .copy_from_slice(&0x600u32.to_le_bytes());
        b[FADT_OFF_GPE0_BLK..FADT_OFF_GPE0_BLK + 4].copy_from_slice(&0x620u32.to_le_bytes());
        b[FADT_OFF_SMI_CMD..FADT_OFF_SMI_CMD + 4].copy_from_slice(&0xB2u32.to_le_bytes());
        b[FADT_OFF_PM1_EVT_LEN] = 4;
        b[FADT_OFF_PM1_CNT_LEN] = 2;
        b[FADT_OFF_GPE0_BLK_LEN] = 16;
        b[FADT_OFF_FLAGS..FADT_OFF_FLAGS + 4]
            .copy_from_slice(&FADT_FLAG_HW_REDUCED_ACPI.to_le_bytes());
        for (off, address) in [
            (FADT_OFF_SLEEP_CONTROL_REG, control),
            (FADT_OFF_SLEEP_STATUS_REG, status),
        ]
        {
            b[off] = space;
            b[off + 1] = 8;
            b[off + 4..off + 12].copy_from_slice(&address.to_le_bytes());
        }
        b
    }

    // Defect caught: a sleep register read from the wrong offset, in the
    // wrong space, or a hardware-reduced FADT served the legacy blocks.
    #[test]
    fn a_hardware_reduced_fadt_gives_its_sleep_registers_in_either_space()
    {
        use crate::acpid::Space;
        let reg = |space, address| Some(FixedRegister { space, address });
        let t = reduced_fadt(GAS_SPACE_MEMORY, 0xFEA0_0200, 0xFEA0_0201);
        assert_eq!(
            fadt_sleep_register(&t, SleepRegister::Control),
            reg(Space::Memory, 0xFEA0_0200)
        );
        assert_eq!(
            fadt_sleep_register(&t, SleepRegister::Status),
            reg(Space::Memory, 0xFEA0_0201)
        );
        for block in [
            FadtBlock::Pm1aEvt,
            FadtBlock::Pm1aCnt,
            FadtBlock::Gpe0,
            FadtBlock::SmiCmd,
        ]
        {
            assert_eq!(fadt_io_block(&t, block), None, "{block:?}");
        }
        assert_eq!(fadt_sci_int(&t), None);
        // The same fields serve the blocks once the flag is clear, so the
        // refusals above are the flag's.
        let mut legacy = t.clone();
        legacy[FADT_OFF_FLAGS..FADT_OFF_FLAGS + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(fadt_io_block(&legacy, FadtBlock::Pm1aCnt).is_some());
        assert!(fadt_io_block(&legacy, FadtBlock::SmiCmd).is_some());
        let t = reduced_fadt(GAS_SPACE_IO, 0x404, 0x405);
        assert_eq!(
            fadt_sleep_register(&t, SleepRegister::Control),
            reg(Space::Io, 0x404)
        );
        assert_eq!(
            fadt_sleep_register(&t, SleepRegister::Status),
            reg(Space::Io, 0x405)
        );
        // The byte access size is accepted as the undefined one is.
        let mut t = reduced_fadt(GAS_SPACE_IO, 0x404, 0x405);
        t[FADT_OFF_SLEEP_CONTROL_REG + 3] = GAS_ACCESS_BYTE;
        assert_eq!(
            fadt_sleep_register(&t, SleepRegister::Control),
            reg(Space::Io, 0x404)
        );
    }

    // Defect caught: a sleep register served from a FADT that is not
    // hardware-reduced, from a field the table does not reach, or one that is
    // not the specification's 8-bit register.
    #[test]
    fn a_sleep_register_is_withheld_unless_reduced_reached_and_well_formed()
    {
        let control = |t: &[u8]| fadt_sleep_register(t, SleepRegister::Control);
        let good = reduced_fadt(GAS_SPACE_MEMORY, 0xFEA0_0200, 0xFEA0_0201);
        assert!(control(&good).is_some());
        // HW_REDUCED_ACPI clear: q35's FADT, and the reduced one with the flag
        // cleared.
        assert_eq!(control(&q35_fadt(0)), None);
        let mut t = good.clone();
        t[FADT_OFF_FLAGS..FADT_OFF_FLAGS + 4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(control(&t), None);
        // The reported length, or the slice, stops inside the structure; an
        // ACPI 5.0 FADT of 268 bytes still reaches both.
        let mut t = good.clone();
        t[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&250u32.to_le_bytes());
        assert_eq!(control(&t), None);
        assert_eq!(control(&good[..250]), None);
        let mut t = good.clone();
        t[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&268u32.to_le_bytes());
        assert!(control(&t).is_some());
        assert!(fadt_sleep_register(&t, SleepRegister::Status).is_some());
        // Each malformed field of the structure.
        let field = |off: usize, v: u8| {
            let mut t = good.clone();
            t[FADT_OFF_SLEEP_CONTROL_REG + off] = v;
            control(&t)
        };
        assert_eq!(field(0, 2), None, "PCI configuration space");
        assert_eq!(field(1, 16), None, "a 16-bit register");
        assert_eq!(field(1, 0), None, "no bit width");
        assert_eq!(field(2, 1), None, "a bit offset");
        assert_eq!(field(3, 2), None, "a word access");
        assert_eq!(
            control(&reduced_fadt(GAS_SPACE_MEMORY, 0, 0xFEA0_0201)),
            None,
            "a zero address"
        );
        assert_eq!(
            control(&reduced_fadt(GAS_SPACE_IO, 0x1_0000, 0x405)),
            None,
            "a port past 0xFFFF"
        );
        let mut t = good;
        t[..4].copy_from_slice(b"APIC");
        assert_eq!(control(&t), None);
    }

    #[test]
    fn fadt_withholds_an_absent_short_or_unsupported_block()
    {
        let mut t = q35_fadt(0);
        // A zero length, a zero port.
        t[FADT_OFF_GPE0_BLK_LEN] = 0;
        assert_eq!(fadt_io_block(&t, FadtBlock::Gpe0), None);
        t[FADT_OFF_SMI_CMD..FADT_OFF_SMI_CMD + 4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(fadt_io_block(&t, FadtBlock::SmiCmd), None);
        // A block that runs past the last port.
        t[FADT_OFF_PM1A_EVT_BLK..FADT_OFF_PM1A_EVT_BLK + 4]
            .copy_from_slice(&0xFFFEu32.to_le_bytes());
        assert_eq!(fadt_io_block(&t, FadtBlock::Pm1aEvt), None);
        // Both FACS fields zero: no FACS.
        assert_eq!(fadt_facs_phys(&t), None);
        // An ACPI 1.0 FADT: no RESET_REG, the 32-bit FACS field.
        let mut old = q35_fadt(0);
        old[FADT_OFF_FIRMWARE_CTRL..FADT_OFF_FIRMWARE_CTRL + 4]
            .copy_from_slice(&0x7FEB_1000u32.to_le_bytes());
        old[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&116u32.to_le_bytes());
        assert_eq!(fadt_reset_register(&old), None);
        assert_eq!(
            fadt_io_block(&old, FadtBlock::Pm1aCnt).map(|b| b.port),
            Some(0x604)
        );
        assert_eq!(fadt_facs_phys(&old), Some(0x7FEB_1000));
        old[..4].copy_from_slice(b"APIC");
        assert_eq!(fadt_io_block(&old, FadtBlock::Pm1aCnt), None);
        assert_eq!(fadt_facs_phys(&old), None);
    }

    /// `fadt` with `RESET_REG_SUP` set and its `RESET_REG` the 8-bit register
    /// of `space` at `address`, with `RESET_VALUE` `value`.
    fn with_reset(mut fadt: Vec<u8>, space: u8, address: u64, value: u8) -> Vec<u8>
    {
        let flags = read_u32(&fadt, FADT_OFF_FLAGS) | FADT_FLAG_RESET_REG_SUP;
        fadt[FADT_OFF_FLAGS..FADT_OFF_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
        fadt[FADT_OFF_RESET_REG..FADT_OFF_RESET_REG + GAS_LEN].fill(0);
        fadt[FADT_OFF_RESET_REG] = space;
        fadt[FADT_OFF_RESET_REG + 1] = 8;
        fadt[FADT_OFF_RESET_REG + 4..FADT_OFF_RESET_REG + 12]
            .copy_from_slice(&address.to_le_bytes());
        fadt[FADT_OFF_RESET_VALUE] = value;
        fadt
    }

    // Defect caught: a RESET_REG in the memory space withheld (a
    // hardware-reduced platform, such as QEMU's microvm, places it there
    // beside its sleep registers), or one read from the wrong offset, in the
    // wrong space, or with the wrong value.
    #[test]
    fn fadt_gives_its_reset_register_in_either_space()
    {
        use crate::acpid::Space;
        let reset = |space, address, value| {
            Some(ResetRegister {
                register: FixedRegister { space, address },
                value,
            })
        };
        // q35: port 0xCF9, value 6.
        assert_eq!(
            fadt_reset_register(&q35_fadt(0)),
            reset(Space::Io, 0xCF9, 6)
        );
        // A hardware-reduced FADT whose RESET_REG is a byte of memory, as
        // microvm's generic event device places it, value 0x42.
        let reduced = with_reset(
            reduced_fadt(GAS_SPACE_MEMORY, 0xFEA0_0200, 0xFEA0_0201),
            GAS_SPACE_MEMORY,
            0xFEA0_0202,
            0x42,
        );
        assert_eq!(
            fadt_reset_register(&reduced),
            reset(Space::Memory, 0xFEA0_0202, 0x42)
        );
        // A memory RESET_REG on a platform that is not hardware-reduced.
        let legacy = with_reset(q35_fadt(0), GAS_SPACE_MEMORY, 0xFED0_0000, 1);
        assert_eq!(
            fadt_reset_register(&legacy),
            reset(Space::Memory, 0xFED0_0000, 1)
        );
        // The byte access size is accepted as the undefined one is.
        let mut t = reduced.clone();
        t[FADT_OFF_RESET_REG + 3] = GAS_ACCESS_BYTE;
        assert_eq!(
            fadt_reset_register(&t),
            reset(Space::Memory, 0xFEA0_0202, 0x42)
        );
        // An I/O RESET_REG is a port whatever its bit width, bit offset and
        // access size, which firmware is known to give wrong.
        for (off, v) in [(1, 16), (1, 0), (2, 1), (3, 2)]
        {
            let mut t = q35_fadt(0);
            t[FADT_OFF_RESET_REG + off] = v;
            assert_eq!(
                fadt_reset_register(&t),
                reset(Space::Io, 0xCF9, 6),
                "field {off} = {v}"
            );
        }
        // An ACPI 2.0 FADT of 129 bytes reaches RESET_VALUE.
        let mut t = reduced;
        t[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&129u32.to_le_bytes());
        assert!(fadt_reset_register(&t).is_some());
    }

    // Defect caught: a RESET_REG served when the FADT does not support it,
    // from a field the table does not reach, at a zero or out-of-range port,
    // or in memory when it is not the specification's 8-bit register.
    #[test]
    fn a_reset_register_is_withheld_unless_supported_reached_and_well_formed()
    {
        let good = with_reset(q35_fadt(0), GAS_SPACE_MEMORY, 0xFEA0_0202, 0x42);
        assert!(fadt_reset_register(&good).is_some());
        // RESET_REG_SUP clear.
        let mut t = good.clone();
        let flags = read_u32(&t, FADT_OFF_FLAGS) & !FADT_FLAG_RESET_REG_SUP;
        t[FADT_OFF_FLAGS..FADT_OFF_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(fadt_reset_register(&t), None);
        // The reported length, or the slice, stops before RESET_VALUE.
        let mut t = good.clone();
        t[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&128u32.to_le_bytes());
        assert_eq!(fadt_reset_register(&t), None);
        assert_eq!(fadt_reset_register(&good[..128]), None);
        // Each malformed field of the structure.
        let field = |off: usize, v: u8| {
            let mut t = good.clone();
            t[FADT_OFF_RESET_REG + off] = v;
            fadt_reset_register(&t)
        };
        assert_eq!(field(0, 2), None, "PCI configuration space");
        assert_eq!(field(1, 16), None, "a 16-bit register");
        assert_eq!(field(1, 0), None, "no bit width");
        assert_eq!(field(2, 1), None, "a bit offset");
        assert_eq!(field(3, 2), None, "a word access");
        assert_eq!(
            fadt_reset_register(&with_reset(q35_fadt(0), GAS_SPACE_MEMORY, 0, 0x42)),
            None,
            "a zero address"
        );
        assert_eq!(
            fadt_reset_register(&with_reset(q35_fadt(0), GAS_SPACE_IO, 0x1_0000, 6)),
            None,
            "a port past 0xFFFF"
        );
        assert_eq!(
            fadt_reset_register(&with_reset(q35_fadt(0), GAS_SPACE_IO, 0, 6)),
            None,
            "a zero port"
        );
        let mut t = good;
        t[..4].copy_from_slice(b"APIC");
        assert_eq!(fadt_reset_register(&t), None);
    }

    #[test]
    fn an_isa_irq_no_override_names_keeps_its_number_and_described_mode()
    {
        let other = [SourceOverride {
            source: 0,
            gsi: 2,
            flags: 0,
        }];
        assert_eq!(isa_line(other, 4, 0), (4, 0));
        assert_eq!(
            isa_line([], 8, IRQ_MODE_ACTIVE_LOW),
            (8, IRQ_MODE_ACTIVE_LOW)
        );
    }

    #[test]
    fn an_isa_override_gives_the_gsi_and_overrides_field_by_field()
    {
        let iso = |flags| {
            [SourceOverride {
                source: 4,
                gsi: 20,
                flags,
            }]
        };
        // Level, active-low.
        assert_eq!(
            isa_line(iso(0b1111), 4, 0),
            (20, IRQ_MODE_LEVEL | IRQ_MODE_ACTIVE_LOW)
        );
        // Edge, active-high, over a described level active-low line.
        assert_eq!(isa_line(iso(0b0101), 4, PCI_INTX_MODE), (20, 0));
        // Both fields conform: the described mode.
        assert_eq!(isa_line(iso(0), 4, IRQ_MODE_LEVEL), (20, IRQ_MODE_LEVEL));
        // Polarity reserved, trigger level: polarity from the description.
        assert_eq!(
            isa_line(iso(0b1110), 4, IRQ_MODE_ACTIVE_LOW),
            (20, IRQ_MODE_LEVEL | IRQ_MODE_ACTIVE_LOW)
        );
        // The first override naming the IRQ wins.
        let two = [
            SourceOverride {
                source: 4,
                gsi: 20,
                flags: 0,
            },
            SourceOverride {
                source: 4,
                gsi: 21,
                flags: 0,
            },
        ];
        assert_eq!(isa_line(two, 4, 0), (20, 0));
    }
}

/// The proofs of the property's checks of the ACPI interpretations
/// (docs/testing.md § Bounded verification). The FADT is read at fixed
/// offsets, so it is proven whole on every input up to its bound. The MADT's
/// interpretations are proven by their steps: the local APIC window of the
/// header, and the override, the I/O APIC and the controller window a
/// structure at any place gives. What lies outside the proofs is the loops
/// that drive the steps: the walks of `madt_source_overrides`,
/// `madt_io_apics`, `madt_interrupt_controllers` and `madt_well_formed`
/// from one structure to the next, and the iterator adapters over them; the
/// fuzz target `devmgr-firmware`, the replay of the checked-in inputs and the
/// unit tests check them. The formats under them are proven in
/// `firmware-tables`.
#[cfg(kani)]
mod proofs
{
    use crate::property::acpi as property;

    /// Every input of at most 269 bytes holds the FADT decoders' contract:
    /// 268 bytes reach `SLEEP_STATUS_REG`, the last field read, so every
    /// field is reached, cut short and refused at every length field. The
    /// loops are the compare of the 4-byte signature and the walks over the
    /// 4 register blocks and the 2 sleep registers.
    #[kani::proof]
    #[kani::unwind(5)]
    fn every_fadt_reads_as_its_fields()
    {
        let bytes: [u8; 269] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::fadt_holds(&bytes[..len]);
    }

    /// Every input of at most 45 bytes holds the MADT header window's
    /// contract: 45 bytes reach an end before, at and past the first
    /// structure, at 44, at every length field. The loop is the compare of
    /// the 4-byte signature.
    #[kani::proof]
    #[kani::unwind(5)]
    fn every_madt_header_gives_its_window()
    {
        let bytes: [u8; 45] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let _ = property::madt_header_holds(&bytes[..len]);
    }

    /// Every MADT structure, at any place of an input of at most 38 bytes
    /// and any end within it, holds its interpretations' contract: the
    /// longest structure decoded, a RINTC or an APLIC, is 36 bytes, so a
    /// structure of every type and length, one past the end and one too
    /// short for its fields are reached. No loop.
    #[kani::proof]
    fn every_madt_structure_decodes_as_its_interpretations()
    {
        let bytes: [u8; 38] = kani::any();
        let len: usize = kani::any();
        let end: usize = kani::any();
        kani::assume(len <= bytes.len() && end <= len);
        let _ = property::madt_structure_decodes(&bytes[..len], kani::any(), end);
    }
}
