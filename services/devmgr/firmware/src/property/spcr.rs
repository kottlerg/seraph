// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/property/spcr.rs

//! The check of [`crate::platform::spcr`]: the Serial Port Console
//! Redirection table's interface type, base address and interrupt, read from
//! the Microsoft Serial Port Console Redirection Table specification.

use super::{byte, le32, le64};
use crate::platform::{self, Spcr, SpcrBase, SpcrInterrupt};

/// [`platform::spcr`] reads a table of signature `SPCR` and at least 80
/// bytes: the interface type at 36, and the base address's Generic Address
/// Structure at 40, its space id 0 (system memory) or 1 (system I/O, an
/// address of at most 16 bits) and its address at 44 not zero; the interrupt
/// type at 52 names the dual-8259 IRQ at 53 by its bit 0, else a GSI at 54 by
/// any of its bits 1 to 4, else no interrupt. Anything else is refused.
pub(crate) fn spcr_holds(input: &[u8])
{
    let read = || {
        if input.len() < 80 || input.get(..4) != Some(b"SPCR".as_slice())
        {
            return None;
        }
        let address = le64(input, 44).filter(|&address| address != 0)?;
        let base = match byte(input, 40)?
        {
            0 => SpcrBase::Mmio(address),
            1 => SpcrBase::IoPort(u16::try_from(address).ok()?),
            _ => return None,
        };
        let interrupt_type = byte(input, 52)?;
        let interrupt = if interrupt_type & 0x01 != 0
        {
            Some(SpcrInterrupt {
                line: u32::from(byte(input, 53)?),
                isa: true,
            })
        }
        else if interrupt_type & 0x1E != 0
        {
            Some(SpcrInterrupt {
                line: le32(input, 54)?,
                isa: false,
            })
        }
        else
        {
            None
        };
        Some(Spcr {
            interface: byte(input, 36)?,
            base,
            interrupt,
        })
    };
    assert_eq!(
        platform::spcr(input),
        read(),
        "an SPCR judged against its fields"
    );
}
