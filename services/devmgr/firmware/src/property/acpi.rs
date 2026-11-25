// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/property/acpi.rs

//! The checks of [`crate::acpi`]: the RSDP, an SDT header, the XSDT, the
//! FADT, the MCFG and the MADT, read from ACPI 6.5 § 5.2.

use super::{byte, bytes_at, le16, le32, le64, sdt_length, table};
use crate::EcamLocation;
use crate::acpi::{
    self, FadtBlock, FixedRegister, IoApic, IoBlock, ResetRegister, SleepRegister, SourceOverride,
};
use crate::acpid::Space;

/// Check every ACPI decoder of [`crate::acpi`] on `input`.
pub(crate) fn acpi_holds(input: &[u8])
{
    rsdp_holds(input);
    header_holds(input);
    xsdt_holds(input);
    fadt_holds(input);
    mcfg_holds(input);
    madt_holds(input);
}

// ── RSDP, SDT header, XSDT ──────────────────────────────────────────────────

/// [`acpi::rsdp_xsdt_phys`] gives the `u64` at 24 of an RSDP of at least 36
/// bytes signed `RSD PTR ` of revision 2 or later (the byte at 15), when it
/// is not zero.
pub(crate) fn rsdp_holds(input: &[u8])
{
    let expected = if input.len() >= 36
        && input.get(..8) == Some(b"RSD PTR ".as_slice())
        && byte(input, 15).is_some_and(|revision| revision >= 2)
    {
        le64(input, 24).filter(|&xsdt| xsdt != 0)
    }
    else
    {
        None
    };
    assert_eq!(
        acpi::rsdp_xsdt_phys(input),
        expected,
        "an RSDP judged against its fields"
    );
}

/// [`acpi::sdt_length`], [`acpi::sdt_signature`] and
/// [`acpi::sdt_oem_table_id`] read a header's length (the `u32` at 4 of a
/// 36-byte header, at least 36), its first 4 bytes (zeros when there are
/// fewer), and its OEM table ID (the 8 bytes at 16 of a 36-byte header).
pub(crate) fn header_holds(input: &[u8])
{
    assert_eq!(
        acpi::sdt_length(input).map(|length| length as usize),
        sdt_length(input),
        "a header's length judged against its field"
    );
    assert_eq!(
        acpi::sdt_signature(input),
        bytes_at::<4>(input, 0).unwrap_or([0; 4]),
        "a header's signature judged against its bytes"
    );
    let oem = if input.len() >= 36
    {
        bytes_at::<8>(input, 16)
    }
    else
    {
        None
    };
    assert_eq!(
        acpi::sdt_oem_table_id(input),
        oem,
        "a header's OEM table ID judged against its bytes"
    );
}

/// [`acpi::iter_xsdt_entries`] gives the `u64` entries after the 36-byte
/// header, up to the length the `u32` at 4 reports (0 when unreadable),
/// bounded by the slice, a partial entry at the end left out.
pub(crate) fn xsdt_holds(input: &[u8])
{
    let length = le32(input, 4).map_or(0, |length| length as usize);
    let count = length.min(input.len()).saturating_sub(36) / 8;
    let expected = (0..count).map(|i| {
        i.checked_mul(8)
            .and_then(|at| at.checked_add(36))
            .and_then(|at| le64(input, at))
    });
    assert!(
        acpi::iter_xsdt_entries(input).map(Some).eq(expected),
        "an XSDT's entries judged against its bytes"
    );
}

// ── FADT ────────────────────────────────────────────────────────────────────

/// The FADT's fields, read from the table `input` holds when it is signed
/// `FACP` (its bytes up to its reported length, bounded by the slice); every
/// read is `None` for another table or a field the table does not reach.
struct Fadt<'a>(Option<&'a [u8]>);

impl Fadt<'_>
{
    fn u8(&self, at: usize) -> Option<u8>
    {
        self.0.and_then(|t| byte(t, at))
    }

    fn u16(&self, at: usize) -> Option<u16>
    {
        self.0.and_then(|t| le16(t, at))
    }

    fn u32(&self, at: usize) -> Option<u32>
    {
        self.0.and_then(|t| le32(t, at))
    }

    fn u64(&self, at: usize) -> Option<u64>
    {
        self.0.and_then(|t| le64(t, at))
    }

    fn gas(&self, at: usize) -> Option<[u8; 12]>
    {
        self.0.and_then(|t| bytes_at(t, at))
    }

    /// The 64-bit address at `wide` when it is not zero, else the 32-bit one
    /// at `narrow` when it is not zero.
    fn address(&self, wide: usize, narrow: usize) -> Option<u64>
    {
        self.u64(wide)
            .filter(|&a| a != 0)
            .or_else(|| self.u32(narrow).map(u64::from).filter(|&a| a != 0))
    }

    /// Whether `Flags` (the `u32` at 112) is read and sets `HW_REDUCED_ACPI`
    /// (bit 20).
    fn hardware_reduced(&self) -> Option<bool>
    {
        self.u32(112).map(|flags| flags & (1 << 20) != 0)
    }
}

/// The byte register a Generic Address Structure places: space 0 (memory) or
/// 1 (I/O), a bit width of 8, a bit offset of 0, an access size of 0 or 1, and
/// a non-zero address, a port no higher than 0xFFFF.
fn byte_register(gas: [u8; 12]) -> Option<FixedRegister>
{
    let [space, width, offset, access, ..] = gas;
    let space = match space
    {
        0 => Space::Memory,
        1 => Space::Io,
        _ => return None,
    };
    if width != 8 || offset != 0 || access > 1
    {
        return None;
    }
    let address = le64(&gas, 4)?;
    if address == 0 || (space == Space::Io && address > 0xFFFF)
    {
        return None;
    }
    Some(FixedRegister { space, address })
}

/// Where a FADT places the fixed register block at the `u32` port `port`,
/// with the port count at the byte `count` (one port when `None`) and the
/// value at the byte `value`: `None` on a hardware-reduced FADT, for a
/// field not reached, a zero port or one past 0xFFFF, a zero count, or a
/// block whose last port is past 0xFFFF.
fn io_block(
    fadt: &Fadt<'_>,
    port: usize,
    count: Option<usize>,
    value: Option<usize>,
) -> Option<IoBlock>
{
    if fadt.hardware_reduced() == Some(true)
    {
        return None;
    }
    let port = u16::try_from(fadt.u32(port)?)
        .ok()
        .filter(|&port| port != 0)?;
    let count = match count
    {
        Some(at) => u16::from(fadt.u8(at)?),
        None => 1,
    };
    let value = match value
    {
        Some(at) => fadt.u8(at)?,
        None => 0,
    };
    port.checked_add(count.checked_sub(1)?)?;
    Some(IoBlock { port, count, value })
}

/// The FADT decoders read the fields of ACPI 6.5 § 5.2.9 at their offsets,
/// each within the table, with the refusals each documents.
pub(crate) fn fadt_holds(input: &[u8])
{
    let fadt = Fadt(table(input, *b"FACP"));
    assert_eq!(
        acpi::fadt_century_index(input),
        fadt.u8(108).filter(|&index| index != 0),
        "CENTURY judged against its byte"
    );
    assert_eq!(
        acpi::fadt_dsdt_phys(input),
        fadt.address(140, 40),
        "the DSDT's address judged against X_DSDT and DSDT"
    );
    assert_eq!(
        acpi::fadt_facs_phys(input),
        fadt.address(132, 36),
        "the FACS's address judged against X_FIRMWARE_CTRL and FIRMWARE_CTRL"
    );
    for (block, expected) in [
        (FadtBlock::Pm1aEvt, io_block(&fadt, 56, Some(88), None)),
        (FadtBlock::Pm1aCnt, io_block(&fadt, 64, Some(89), None)),
        (FadtBlock::Gpe0, io_block(&fadt, 80, Some(92), None)),
        (FadtBlock::SmiCmd, io_block(&fadt, 48, None, Some(52))),
    ]
    {
        assert_eq!(
            acpi::fadt_io_block(input, block),
            expected,
            "a fixed register block judged against its fields"
        );
    }
    for (register, at) in [(SleepRegister::Control, 244), (SleepRegister::Status, 256)]
    {
        let expected = if fadt.hardware_reduced() == Some(true)
        {
            fadt.gas(at).and_then(byte_register)
        }
        else
        {
            None
        };
        assert_eq!(
            acpi::fadt_sleep_register(input, register),
            expected,
            "a sleep register judged against its Generic Address Structure"
        );
    }
    let reset = fadt.u8(128).and_then(|value| {
        if fadt.u32(112)? & (1 << 10) == 0
        {
            return None;
        }
        let gas = fadt.gas(116)?;
        let register = if gas.first() == Some(&1)
        {
            let address = le64(&gas, 4).filter(|&a| a != 0 && a <= 0xFFFF)?;
            FixedRegister {
                space: Space::Io,
                address,
            }
        }
        else
        {
            byte_register(gas)?
        };
        Some(ResetRegister { register, value })
    });
    assert_eq!(
        acpi::fadt_reset_register(input),
        reset,
        "RESET_REG judged against its Generic Address Structure and RESET_VALUE"
    );
    let sci = if fadt.hardware_reduced() == Some(false)
    {
        fadt.u16(46).filter(|&sci| sci != 0)
    }
    else
    {
        None
    };
    assert_eq!(
        acpi::fadt_sci_int(input),
        sci,
        "SCI_INT judged against its field"
    );
}

// ── MCFG ────────────────────────────────────────────────────────────────────

/// A window's fields, for a comparison.
fn ecam(window: EcamLocation) -> (u64, u64, u16, u8, u8)
{
    (
        window.phys_base,
        window.size,
        window.segment,
        window.start_bus,
        window.end_bus,
    )
}

/// [`acpi::mcfg_entry_count`] counts the 16-byte allocation entries after
/// the 44 bytes of an MCFG's header and reserved field, up to its reported
/// length bounded by the slice; none for another table. Returns the count.
pub(crate) fn mcfg_count_holds(input: &[u8]) -> usize
{
    let count = table(input, *b"MCFG").map_or(0, |t| t.len().saturating_sub(44) / 16);
    assert_eq!(
        acpi::mcfg_entry_count(input),
        count,
        "an MCFG's entries counted against its length"
    );
    count
}

/// [`acpi::mcfg_entry_ecam`] reads the allocation entry at `at`, which lies
/// in `input`: base (`u64`), segment (`u16`), start and end bus; a window
/// from the start bus's configuration space, 1 MiB per bus, refused for a
/// zero base, an end bus below the start bus, or a window past the 64-bit
/// physical space. Returns the window.
pub(crate) fn mcfg_entry_holds(input: &[u8], at: usize) -> Option<(u64, u64, u16, u8, u8)>
{
    let read = || {
        let base = le64(input, at)?;
        let segment = le16(input, at.checked_add(8)?)?;
        let start = byte(input, at.checked_add(10)?)?;
        let end = byte(input, at.checked_add(11)?)?;
        Some((base, segment, start, end))
    };
    let (base, segment, start, end) = read().unwrap_or_default();
    let expected = (|| {
        if base == 0
        {
            return None;
        }
        let buses = u64::from(end.checked_sub(start)?).checked_add(1)?;
        let size = buses.checked_mul(1 << 20)?;
        let phys_base = base.checked_add(u64::from(start).checked_mul(1 << 20)?)?;
        phys_base.checked_add(size)?;
        Some((phys_base, size, segment, start, end))
    })();
    assert_eq!(
        acpi::mcfg_entry_ecam(input, at).map(ecam),
        expected,
        "an MCFG entry judged against its fields"
    );
    expected
}

/// [`acpi::mcfg_ecams`] yields the window of each entry
/// [`mcfg_entry_holds`] reads one from, in order.
fn mcfg_holds(input: &[u8])
{
    let count = mcfg_count_holds(input);
    let mut windows = acpi::mcfg_ecams(input).map(ecam);
    for i in 0..count
    {
        let at = i.saturating_mul(16).saturating_add(44);
        if let Some(window) = mcfg_entry_holds(input, at)
        {
            assert_eq!(
                windows.next(),
                Some(window),
                "an MCFG's windows out of step"
            );
        }
    }
    assert_eq!(windows.next(), None, "an MCFG window past its entries");
}

// ── MADT ────────────────────────────────────────────────────────────────────

/// [`acpi::madt_end`] ends a MADT's structures at its reported length
/// bounded by the slice, and refuses another table or one whose end does not
/// reach the first structure, at 44; [`acpi::madt_header_window`] gives the
/// local APIC's 32-bit address at 36 and a page, or nothing for a zero
/// address. Returns the end.
pub(crate) fn madt_end_holds(input: &[u8]) -> Option<usize>
{
    let end = table(input, *b"APIC")
        .map(<[u8]>::len)
        .filter(|&end| end >= 44);
    assert_eq!(
        acpi::madt_end(input),
        end,
        "a MADT's end judged against its length"
    );
    if end.is_some()
    {
        assert_eq!(
            acpi::madt_header_window(input),
            le32(input, 36)
                .filter(|&address| address != 0)
                .map(|address| (u64::from(address), 0x1000)),
            "the local APIC's window judged against the header"
        );
    }
    end
}

/// What one MADT structure gives: its length, and the override, the I/O APIC
/// and the controller window it holds.
pub(crate) struct MadtStructure
{
    pub(crate) len: usize,
    pub(crate) source_override: Option<SourceOverride>,
    pub(crate) io_apic: Option<IoApic>,
    pub(crate) window: Option<(u64, u64)>,
}

/// [`acpi::madt_structure`] reads the structure at `off` of a MADT whose
/// structures end at `end`, at most `input`'s length: its type and its
/// length, the bytes at `off` and after it; the walk ends where fewer than 2
/// bytes are left, or at a length under 2 or past `end`. The override, the
/// I/O APIC and the controller window of the structure read as ACPI 6.5
/// § 5.2.12 lays them out, a window of a zero base or length none. Returns
/// them.
pub(crate) fn madt_structure_holds(input: &[u8], off: usize, end: usize) -> Option<MadtStructure>
{
    let read = || {
        if off.checked_add(2)? > end
        {
            return None;
        }
        let kind = byte(input, off)?;
        let len = usize::from(byte(input, off.checked_add(1)?)?);
        (len >= 2 && off.checked_add(len)? <= end).then_some((kind, len))
    };
    let expected = read();
    assert_eq!(
        acpi::madt_structure(input, off, end),
        expected,
        "a MADT structure judged against its header"
    );
    let (kind, len) = expected?;
    let field8 = |at: usize| off.checked_add(at).and_then(|at| byte(input, at));
    let field32 = |at: usize| off.checked_add(at).and_then(|at| le32(input, at));
    let field64 = |at: usize| off.checked_add(at).and_then(|at| le64(input, at));
    let source_override = if kind == 2 && len >= 10
    {
        let flags = off.checked_add(8).and_then(|at| le16(input, at));
        Some(SourceOverride {
            source: field8(3)?,
            gsi: field32(4)?,
            flags: flags?,
        })
    }
    else
    {
        None
    };
    let io_apic = if kind == 1 && len >= 12
    {
        Some(IoApic {
            id: field8(2)?,
            gsi_base: field32(8)?,
        })
    }
    else
    {
        None
    };
    let riscv = || Some((field64(24)?, u64::from(field32(32)?)));
    let window = match kind
    {
        1 if len >= 12 => Some((u64::from(field32(4)?), 0x1000)),
        5 if len >= 12 => Some((field64(4)?, 0x1000)),
        0x18 if len >= 36 && field32(4)? & 1 != 0 => riscv(),
        0x1A if len >= 36 => riscv(),
        _ => None,
    }
    .filter(|&(base, length)| base != 0 && length != 0);
    assert_eq!(
        acpi::madt_source_override(input, kind, off, len),
        source_override,
        "an Interrupt Source Override judged against its fields"
    );
    assert_eq!(
        acpi::madt_io_apic(input, kind, off, len),
        io_apic,
        "an I/O APIC judged against its fields"
    );
    assert_eq!(
        acpi::madt_controller_window(input, kind, off, len),
        window,
        "an interrupt controller's window judged against its fields"
    );
    Some(MadtStructure {
        len,
        source_override,
        io_apic,
        window,
    })
}

/// The MADT decoders give what each structure of the walk from 44 gives, in
/// order, and the table is well formed when the walk ends at its end.
fn madt_holds(input: &[u8])
{
    let Some(end) = madt_end_holds(input)
    else
    {
        assert!(
            acpi::madt_source_overrides(input).is_none()
                && acpi::madt_io_apics(input).is_none()
                && acpi::madt_interrupt_controllers(input).is_none()
                && !acpi::madt_well_formed(input),
            "a table that is not a MADT decoded as one"
        );
        return;
    };
    let decoded = (
        acpi::madt_source_overrides(input),
        acpi::madt_io_apics(input),
        acpi::madt_interrupt_controllers(input),
    );
    assert!(
        decoded.0.is_some() && decoded.1.is_some() && decoded.2.is_some(),
        "a MADT refused"
    );
    let (Some(mut overrides), Some(mut io_apics), Some(mut windows)) = decoded
    else
    {
        return;
    };
    let header = acpi::madt_header_window(input);
    if header.is_some()
    {
        assert_eq!(
            windows.next(),
            header,
            "the local APIC's window out of step"
        );
    }
    let mut off = 44usize;
    while let Some(s) = madt_structure_holds(input, off, end)
    {
        if s.source_override.is_some()
        {
            assert_eq!(
                overrides.next(),
                s.source_override,
                "the overrides out of step"
            );
        }
        if s.io_apic.is_some()
        {
            assert_eq!(io_apics.next(), s.io_apic, "the I/O APICs out of step");
        }
        if let Some(window) = s.window
        {
            assert_eq!(windows.next(), Some(window), "the windows out of step");
        }
        off = off.saturating_add(s.len);
    }
    assert!(
        overrides.next().is_none() && io_apics.next().is_none() && windows.next().is_none(),
        "a MADT structure past the walk's end"
    );
    assert_eq!(
        acpi::madt_well_formed(input),
        off == end,
        "a MADT judged well formed against where its walk ends"
    );
}
