// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/pwrmgr/src/power_off.rs

//! The register the core-death power-off writes, read from acpid's
//! `QUERY_SLEEP` answer (`ipc::acpid_labels::QUERY_SLEEP`): `PM1a_CNT`, or a
//! hardware-reduced platform's `SLEEP_CONTROL_REG` in the I/O or the memory
//! space, with what is written to it. The x86-64 binary binds the port or
//! maps the page at pwrmgr's start and makes the write on a core death.

use ipc::acpid_labels;

/// The size of the page a memory register is mapped in.
pub const PAGE_SIZE: u64 = 0x1000;

/// Where the core-death power-off writes, and what.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target
{
    /// `PM1a_CNT`, the block's first port: [`acpid_labels::pm1_control_writes`]
    /// of `slp_typ`, read-modify-write, two writes.
    Pm1aCnt
    {
        port: u16, slp_typ: u16
    },
    /// `SLEEP_CONTROL_REG` at port `port`: `value`, one byte.
    ControlPort
    {
        port: u16, value: u8
    },
    /// `SLEEP_CONTROL_REG` at physical `address`: `value`, one byte.
    ControlMemory
    {
        address: u64, value: u8
    },
}

impl Target
{
    /// Read the target from `QUERY_SLEEP`'s words: `register` (`data[2]`,
    /// an `acpid_labels::SLEEP_REGISTER_*`), `address` (`data[0]`, the port
    /// or the physical address) and `slp_typ` (`data[1]`). `None` for an
    /// unknown register, a port past 0xFFFF, a zero address, or a sleep type
    /// past [`acpid_labels::SLP_TYP_MAX`].
    #[must_use]
    pub fn from_answer(register: u64, address: u64, slp_typ: u64) -> Option<Self>
    {
        if slp_typ > acpid_labels::SLP_TYP_MAX || address == 0
        {
            return None;
        }
        let slp_typ = u16::try_from(slp_typ).ok()?;
        match register
        {
            acpid_labels::SLEEP_REGISTER_PM1A_CNT => Some(Self::Pm1aCnt {
                port: u16::try_from(address).ok()?,
                slp_typ,
            }),
            acpid_labels::SLEEP_REGISTER_CONTROL_IO => Some(Self::ControlPort {
                port: u16::try_from(address).ok()?,
                value: acpid_labels::sleep_control_value(slp_typ),
            }),
            acpid_labels::SLEEP_REGISTER_CONTROL_MEMORY => Some(Self::ControlMemory {
                address,
                value: acpid_labels::sleep_control_value(slp_typ),
            }),
            _ => None,
        }
    }
}

/// The page of a memory register at physical `address`, and the register's
/// offset in it.
#[must_use]
pub const fn page_and_offset(address: u64) -> (u64, u64)
{
    (address & !(PAGE_SIZE - 1), address & (PAGE_SIZE - 1))
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: an answer read as the wrong register, or the control
    // register given PM1a_CNT's value (or the reverse).
    #[test]
    fn each_register_is_read_with_its_own_value()
    {
        assert_eq!(
            Target::from_answer(acpid_labels::SLEEP_REGISTER_PM1A_CNT, 0x604, 5),
            Some(Target::Pm1aCnt {
                port: 0x604,
                slp_typ: 5
            })
        );
        assert_eq!(
            Target::from_answer(acpid_labels::SLEEP_REGISTER_CONTROL_IO, 0x404, 5),
            Some(Target::ControlPort {
                port: 0x404,
                value: 0x34
            })
        );
        assert_eq!(
            Target::from_answer(acpid_labels::SLEEP_REGISTER_CONTROL_MEMORY, 0xFEA0_0200, 0),
            Some(Target::ControlMemory {
                address: 0xFEA0_0200,
                value: 0x20
            })
        );
    }

    // Defect caught: a malformed answer armed, whose write would reach a port
    // or address acpid did not name, or carry a sleep type past the field.
    #[test]
    fn a_malformed_answer_is_refused()
    {
        let memory = acpid_labels::SLEEP_REGISTER_CONTROL_MEMORY;
        assert_eq!(Target::from_answer(3, 0x404, 5), None);
        assert_eq!(
            Target::from_answer(acpid_labels::SLEEP_REGISTER_CONTROL_IO, 0x1_0000, 5),
            None
        );
        assert_eq!(
            Target::from_answer(acpid_labels::SLEEP_REGISTER_PM1A_CNT, 0x1_0604, 5),
            None
        );
        assert_eq!(Target::from_answer(memory, 0, 5), None);
        assert_eq!(Target::from_answer(memory, 0xFEA0_0200, 8), None);
        assert_eq!(Target::from_answer(memory, 0xFEA0_0200, u64::MAX), None);
    }

    #[test]
    fn a_memory_register_splits_into_its_page_and_offset()
    {
        assert_eq!(page_and_offset(0xFEA0_0201), (0xFEA0_0000, 0x201));
        assert_eq!(page_and_offset(0xFEA0_1000), (0xFEA0_1000, 0));
    }
}
