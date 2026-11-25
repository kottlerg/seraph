// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/firmware-tables/src/spcr.rs

//! The ACPI Serial Port Console Redirection table (SPCR): the console UART's
//! interface type, base address, and interrupt, as the Microsoft Serial Port
//! Console Redirection Table specification lays them out. Operates on a
//! caller-mapped byte slice of the table. No alloc.

use crate::acpi::sdt_signature;

/// Smallest SPCR this parser reads.
const SPCR_MIN_LEN: usize = 80;

const SPCR_OFF_INTERFACE: usize = 36;

const SPCR_OFF_SPACE_ID: usize = 40;

const SPCR_OFF_ADDRESS: usize = 44;

const SPCR_OFF_INT_TYPE: usize = 52;

const SPCR_OFF_IRQ: usize = 53;

const SPCR_OFF_GSI: usize = 54;

/// What the SPCR names: the console UART's interface type and base address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spcr
{
    /// The SPCR interface type.
    pub interface: u8,
    /// The UART's register base.
    pub base: SpcrBase,
    /// The UART's interrupt, if the table names one.
    pub interrupt: Option<SpcrInterrupt>,
}

/// Where the UART's registers are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpcrBase
{
    /// A system-memory address.
    Mmio(u64),
    /// A system I/O port base.
    IoPort(u16),
}

/// The UART's interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpcrInterrupt
{
    /// The ISA IRQ number or the GSI / APLIC source.
    pub line: u32,
    /// Whether `line` is an ISA IRQ number (dual-8259).
    pub isa: bool,
}

fn rd_u64(buf: &[u8], off: usize) -> Option<u64>
{
    Some(u64::from_le_bytes(
        buf.get(off..off.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn rd_u32(buf: &[u8], off: usize) -> Option<u32>
{
    Some(u32::from_le_bytes(
        buf.get(off..off.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// Parse an SPCR (signature `SPCR`, length >= 80): the interface type, the
/// base address Generic Address Structure (system memory or system I/O; a
/// zero address is none), and the interrupt (bit 0 of the interrupt type is
/// the dual-8259 ISA IRQ, any of bits 1 to 4 a GSI or APLIC source).
/// An I/O base above 0xFFFF, another space id, a wrong signature, or a short
/// table gives `None`.
#[must_use]
pub fn spcr(table: &[u8]) -> Option<Spcr>
{
    if table.len() < SPCR_MIN_LEN || &sdt_signature(table) != b"SPCR"
    {
        return None;
    }
    let interface = *table.get(SPCR_OFF_INTERFACE)?;
    let address = rd_u64(table, SPCR_OFF_ADDRESS)?;
    if address == 0
    {
        return None;
    }
    let base = match *table.get(SPCR_OFF_SPACE_ID)?
    {
        0 => SpcrBase::Mmio(address),
        1 => SpcrBase::IoPort(u16::try_from(address).ok()?),
        _ => return None,
    };
    let int_type = *table.get(SPCR_OFF_INT_TYPE)?;
    let interrupt = if int_type & 1 != 0
    {
        Some(SpcrInterrupt {
            line: u32::from(*table.get(SPCR_OFF_IRQ)?),
            isa: true,
        })
    }
    else if int_type & 0x1E != 0
    {
        Some(SpcrInterrupt {
            line: rd_u32(table, SPCR_OFF_GSI)?,
            isa: false,
        })
    }
    else
    {
        None
    };
    Some(Spcr {
        interface,
        base,
        interrupt,
    })
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn spcr_bytes() -> Vec<u8>
    {
        let mut t = vec![0u8; 80];
        t[..4].copy_from_slice(b"SPCR");
        t[4..8].copy_from_slice(&80u32.to_le_bytes());
        t[36] = 3;
        t
    }

    #[test]
    fn spcr_memory_base_and_interrupts()
    {
        let mut t = spcr_bytes();
        t[40] = 0;
        t[44..52].copy_from_slice(&0x1000_0000u64.to_le_bytes());
        assert_eq!(
            spcr(&t),
            Some(Spcr {
                interface: 3,
                base: SpcrBase::Mmio(0x1000_0000),
                interrupt: None
            })
        );
        t[52] = 1;
        t[53] = 4;
        assert_eq!(
            spcr(&t).and_then(|s| s.interrupt),
            Some(SpcrInterrupt { line: 4, isa: true })
        );
        for ty in [2u8, 4, 8, 16]
        {
            t[52] = ty;
            t[54..58].copy_from_slice(&33u32.to_le_bytes());
            assert_eq!(
                spcr(&t).and_then(|s| s.interrupt),
                Some(SpcrInterrupt {
                    line: 33,
                    isa: false
                }),
                "type {ty}"
            );
        }
    }

    #[test]
    fn spcr_io_base_and_rejects()
    {
        let mut t = spcr_bytes();
        t[40] = 1;
        t[44..52].copy_from_slice(&0x3F8u64.to_le_bytes());
        assert_eq!(spcr(&t).map(|s| s.base), Some(SpcrBase::IoPort(0x3F8)));
        t[44..52].copy_from_slice(&0x1_0000u64.to_le_bytes());
        assert_eq!(spcr(&t), None);
        t[44..52].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(spcr(&t), None);
        t[40] = 2;
        t[44] = 1;
        assert_eq!(spcr(&t), None);
        t[40] = 0;
        assert!(spcr(&t).is_some());
        assert_eq!(spcr(&t[..79]), None);
        t[..4].copy_from_slice(b"SPCX");
        assert_eq!(spcr(&t), None);
    }
}

/// The proof of the property's check of the SPCR decoder
/// (docs/testing.md § Bounded verification): the decode is one read of
/// fixed fields, proven whole; nothing lies outside the proof.
#[cfg(kani)]
mod proofs
{
    /// Every input of at most 81 bytes holds the SPCR's contract: 81 bytes
    /// reach the length refusal and the acceptance of the 80 bytes it reads.
    /// The loop is the compare of the 4-byte signature.
    #[kani::proof]
    #[kani::unwind(5)]
    fn every_spcr_reads_as_its_fields()
    {
        let bytes: [u8; 81] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        crate::property::spcr::spcr_holds(&bytes[..len]);
    }
}
