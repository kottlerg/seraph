// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/rollback.rs

//! The machine's security floor, kept in firmware storage so that a whole
//! older image, its bootloader included, does not boot once a newer trust
//! store has raised the floor ([docs/signing.md](../../../docs/signing.md)
//! § Rollback Floor).
//!
//! The floor is one UEFI variable, [`FLOOR_VARIABLE`] under
//! [`SERAPH_VENDOR_GUID`], non-volatile and reachable by boot services alone:
//! its four bytes are the floor, little-endian. [`read_floor`] reads it right
//! after the trust store parses, before any object is loaded, and refuses this
//! bootloader when the variable is above the store's floor or malformed;
//! [`record_floor`] writes the store's floor once the kernel and every bundle
//! entry have verified, when it is the higher one. Both reach the variable
//! through [`VariableServices`], before `ExitBootServices`, and no variable
//! call follows it
//! ([core/boot/docs/uefi-environment.md](../docs/uefi-environment.md)
//! § Variable Services).

use crate::bprintln;
use crate::error::BootError;
use crate::uefi::{
    EFI_VARIABLE_BOOTSERVICE_ACCESS, EFI_VARIABLE_NON_VOLATILE, EfiStatus, SERAPH_VENDOR_GUID,
    VariableRead, VariableServices,
};

/// `SecurityFloor` as a NUL-terminated UTF-16 variable name.
// rustfmt::skip keeps the UTF-16 code units in rows of five, which rustfmt would
// spread one per line.
#[rustfmt::skip]
pub static FLOOR_VARIABLE: [u16; 14] = [
    b'S' as u16, b'e' as u16, b'c' as u16, b'u' as u16, b'r' as u16,
    b'i' as u16, b't' as u16, b'y' as u16, b'F' as u16, b'l' as u16,
    b'o' as u16, b'o' as u16, b'r' as u16, 0u16,
];

/// The floor variable's attributes, exactly: kept across resets, reachable
/// before `ExitBootServices` alone. A variable that carries any other set was
/// not written by a bootloader, and is malformed.
pub const FLOOR_ATTRIBUTES: u32 = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS;

/// The floor variable's length: one `u32`, little-endian.
pub const FLOOR_LEN: usize = 4;

/// The machine's floor, as the variable gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stored
{
    /// No floor variable exists: the machine's floor is 0.
    Absent,
    /// The machine's floor.
    Floor(u32),
    /// The firmware failed the read with this status: no floor is known.
    Unavailable(EfiStatus),
}

/// How the floor variable is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed
{
    /// It holds this many bytes, not [`FLOOR_LEN`].
    Length(usize),
    /// It carries these attributes, not [`FLOOR_ATTRIBUTES`].
    Attributes(u32),
}

impl core::fmt::Display for Malformed
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match self
        {
            Malformed::Length(len) => write!(f, "{len} bytes, not {FLOOR_LEN}"),
            Malformed::Attributes(attributes) => write!(
                f,
                "attributes {attributes:#x}, not {FLOOR_ATTRIBUTES:#x} (non-volatile, boot services alone)"
            ),
        }
    }
}

/// What the boot does with the floor once every object has verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan
{
    /// The variable already holds the store's floor: write nothing.
    Keep,
    /// Write the store's floor, `to`, which is above the machine's.
    Raise
    {
        to: u32
    },
    /// The variable could not be read: write nothing, and run on the store's
    /// floor.
    Unknown,
}

/// The machine's floor from what `GetVariable` returned into `buffer`.
///
/// # Errors
/// [`Malformed`] when the variable holds another length than [`FLOOR_LEN`]
/// or carries other attributes than [`FLOOR_ATTRIBUTES`].
pub fn decode(read: VariableRead, buffer: [u8; FLOOR_LEN]) -> Result<Stored, Malformed>
{
    match read
    {
        VariableRead::NotFound => Ok(Stored::Absent),
        VariableRead::Failed(status) => Ok(Stored::Unavailable(status)),
        VariableRead::TooLarge { len } => Err(Malformed::Length(len)),
        VariableRead::Found { len, .. } if len != FLOOR_LEN => Err(Malformed::Length(len)),
        VariableRead::Found { attributes, .. } if attributes != FLOOR_ATTRIBUTES =>
        {
            Err(Malformed::Attributes(attributes))
        }
        VariableRead::Found { .. } => Ok(Stored::Floor(u32::from_le_bytes(buffer))),
    }
}

/// Decide what the floor the machine has stored means for a bootloader whose
/// trust store carries the floor `carried`.
///
/// # Errors
/// [`BootError::FloorAboveStore`] when the machine's floor is above
/// `carried`: this bootloader is older than one the machine has run.
pub fn plan(stored: Stored, carried: u32) -> Result<Plan, BootError>
{
    match stored
    {
        Stored::Floor(machine) if machine > carried =>
        {
            Err(BootError::FloorAboveStore { machine, carried })
        }
        Stored::Floor(machine) if machine == carried => Ok(Plan::Keep),
        Stored::Absent | Stored::Floor(_) => Ok(Plan::Raise { to: carried }),
        Stored::Unavailable(_) => Ok(Plan::Unknown),
    }
}

/// What [`record_floor`] did with the floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recorded
{
    /// Nothing was written: the variable already held the store's floor, or
    /// it could not be read.
    Nothing,
    /// The machine's floor was raised to this one.
    Raised(u32),
    /// The firmware refused the write with this status: the boot runs on the
    /// trust store's floor, and the machine keeps the floor it had.
    Refused(EfiStatus),
}

/// Read the machine's floor from `vars` and decide what this boot does with
/// it, for a bootloader whose trust store carries the floor `carried`; log
/// both floors, or the warning of a read the firmware failed.
///
/// # Errors
/// [`BootError::FloorMalformed`] for a malformed variable, and
/// [`BootError::FloorAboveStore`] for a machine's floor above `carried`.
pub fn read_floor(vars: &mut impl VariableServices, carried: u32) -> Result<Plan, BootError>
{
    let mut buffer = [0u8; FLOOR_LEN];
    let read = vars.get(&FLOOR_VARIABLE, &SERAPH_VENDOR_GUID, &mut buffer);
    let stored = decode(read, buffer).map_err(BootError::FloorMalformed)?;
    match stored
    {
        Stored::Absent =>
        {
            bprintln!("[--------] boot: security floor: machine none, trust store {carried}");
        }
        Stored::Floor(machine) =>
        {
            bprintln!("[--------] boot: security floor: machine {machine}, trust store {carried}");
        }
        Stored::Unavailable(status) =>
        {
            bprintln!(
                "[--------] boot: WARNING: the firmware did not read the security floor \
                 (status={status:#018x}); this boot runs on the trust store's floor {carried} \
                 and records none"
            );
        }
    }
    plan(stored, carried)
}

/// Carry out `plan` through `vars` once the kernel and every bundle entry
/// have verified: write the raised floor and log it, or log the one warning
/// of a write the firmware refused, after which the boot runs on the trust
/// store's floor. A refused write does not stop the boot.
pub fn record_floor(vars: &mut impl VariableServices, plan: Plan) -> Recorded
{
    let Plan::Raise { to } = plan
    else
    {
        return Recorded::Nothing;
    };
    match vars.set(
        &FLOOR_VARIABLE,
        &SERAPH_VENDOR_GUID,
        FLOOR_ATTRIBUTES,
        &to.to_le_bytes(),
    )
    {
        Ok(()) =>
        {
            bprintln!("[--------] boot: security floor: machine raised to {to}");
            Recorded::Raised(to)
        }
        Err(status) =>
        {
            bprintln!(
                "[--------] boot: WARNING: the firmware refused the security floor write \
                 (status={status:#018x}); this boot runs on the trust store's floor {to}"
            );
            Recorded::Refused(status)
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::uefi::{EFI_UNSUPPORTED, EfiGuid};

    /// `EFI_DEVICE_ERROR`, a store that failed.
    const DEVICE_ERROR: EfiStatus = 0x8000_0000_0000_0007;

    /// `EFI_VARIABLE_RUNTIME_ACCESS`, which no Seraph variable carries.
    const RUNTIME_ACCESS: u32 = 0x4;

    fn found(len: usize, attributes: u32) -> VariableRead
    {
        VariableRead::Found { len, attributes }
    }

    // Defect caught: a variable of another shape read as a floor (a runtime-
    // reachable variable, which the operating system could have written, or
    // one cut short or padded), or an absent variable read as malformed.
    #[test]
    fn only_four_bytes_under_the_floor_attributes_decode_as_a_floor()
    {
        let two = 2u32.to_le_bytes();
        assert_eq!(
            decode(found(4, FLOOR_ATTRIBUTES), two),
            Ok(Stored::Floor(2))
        );
        assert_eq!(
            decode(VariableRead::NotFound, [0xFF; 4]),
            Ok(Stored::Absent)
        );
        assert_eq!(
            decode(found(4, FLOOR_ATTRIBUTES | RUNTIME_ACCESS), two),
            Err(Malformed::Attributes(FLOOR_ATTRIBUTES | RUNTIME_ACCESS))
        );
        assert_eq!(
            decode(found(4, EFI_VARIABLE_BOOTSERVICE_ACCESS), two),
            Err(Malformed::Attributes(EFI_VARIABLE_BOOTSERVICE_ACCESS))
        );
        assert_eq!(
            decode(found(3, FLOOR_ATTRIBUTES), two),
            Err(Malformed::Length(3))
        );
        assert_eq!(
            decode(VariableRead::TooLarge { len: 8 }, two),
            Err(Malformed::Length(8))
        );
        assert_eq!(
            decode(VariableRead::Failed(EFI_UNSUPPORTED), two),
            Ok(Stored::Unavailable(EFI_UNSUPPORTED))
        );
    }

    // Defect caught: an older bootloader let through, a floor lowered or
    // rewritten on every boot, or a failed read taken as a floor of 0 and
    // written over the one the firmware could not read.
    #[test]
    fn the_plan_refuses_an_older_bootloader_and_raises_only_upward()
    {
        assert!(matches!(
            plan(Stored::Floor(3), 2),
            Err(BootError::FloorAboveStore {
                machine: 3,
                carried: 2
            })
        ));
        assert_eq!(plan(Stored::Floor(2), 2).unwrap(), Plan::Keep);
        assert_eq!(plan(Stored::Floor(1), 2).unwrap(), Plan::Raise { to: 2 });
        assert_eq!(plan(Stored::Absent, 1).unwrap(), Plan::Raise { to: 1 });
        assert_eq!(
            plan(Stored::Unavailable(DEVICE_ERROR), 2).unwrap(),
            Plan::Unknown
        );
    }

    // Defect caught: a fatal line that does not say which floor is above
    // which, or how the variable is malformed, which the owner of a refused
    // machine needs to recover it.
    #[test]
    fn the_refusals_name_both_floors_and_the_malformation()
    {
        assert_eq!(
            std::format!(
                "{}",
                BootError::FloorAboveStore {
                    machine: 2,
                    carried: 1
                }
            ),
            "this bootloader is older than the machine's security floor: machine floor 2, \
             trust store floor 1"
        );
        assert_eq!(
            std::format!("{}", BootError::FloorMalformed(Malformed::Length(7))),
            "the security floor variable is malformed: 7 bytes, not 4"
        );
        assert_eq!(
            std::format!("{}", BootError::FloorMalformed(Malformed::Attributes(7))),
            "the security floor variable is malformed: attributes 0x7, not 0x3 (non-volatile, \
             boot services alone)"
        );
    }

    // Defect caught: a variable name that differs from the documented one, or
    // runs past its NUL, so the bootloader reads one variable and documents
    // another.
    #[test]
    fn the_variable_is_named_security_floor()
    {
        let name: Vec<u16> = "SecurityFloor\0".encode_utf16().collect();
        assert_eq!(FLOOR_VARIABLE.as_slice(), name.as_slice());
    }

    /// `EFI_WRITE_PROTECTED`, a store that refuses the write.
    const WRITE_PROTECTED: EfiStatus = 0x8000_0000_0000_0008;

    /// A variable store in memory, holding at most the floor variable.
    #[derive(Default)]
    struct Store
    {
        /// The floor variable's attributes and bytes, when it exists.
        floor: Option<(u32, Vec<u8>)>,
        /// The status every read fails with, when set.
        read_fails: Option<EfiStatus>,
        /// The status every write is refused with, when set.
        refuses: Option<EfiStatus>,
        /// The writes asked of the store, refused ones included.
        writes: usize,
    }

    impl VariableServices for Store
    {
        fn get(&mut self, name: &[u16], vendor: &EfiGuid, buffer: &mut [u8]) -> VariableRead
        {
            assert!(
                name == FLOOR_VARIABLE.as_slice()
                    && core::ptr::eq(vendor, &raw const SERAPH_VENDOR_GUID)
            );
            if let Some(status) = self.read_fails
            {
                return VariableRead::Failed(status);
            }
            match &self.floor
            {
                None => VariableRead::NotFound,
                Some((_, data)) if data.len() > buffer.len() =>
                {
                    VariableRead::TooLarge { len: data.len() }
                }
                Some((attributes, data)) =>
                {
                    buffer[..data.len()].copy_from_slice(data);
                    VariableRead::Found {
                        len: data.len(),
                        attributes: *attributes,
                    }
                }
            }
        }

        fn set(
            &mut self,
            name: &[u16],
            vendor: &EfiGuid,
            attributes: u32,
            data: &[u8],
        ) -> Result<(), EfiStatus>
        {
            assert!(
                name == FLOOR_VARIABLE.as_slice()
                    && core::ptr::eq(vendor, &raw const SERAPH_VENDOR_GUID)
            );
            self.writes += 1;
            if let Some(status) = self.refuses
            {
                return Err(status);
            }
            self.floor = Some((attributes, data.to_vec()));
            Ok(())
        }

        fn query(&mut self, _attributes: u32) -> Result<crate::uefi::VariableInfo, EfiStatus>
        {
            Err(EFI_UNSUPPORTED)
        }
    }

    /// One boot's floor handling, by a bootloader whose store carries
    /// `carried`, with every object verified.
    fn boot(store: &mut Store, carried: u32) -> Result<Recorded, BootError>
    {
        let plan = read_floor(store, carried)?;
        Ok(record_floor(store, plan))
    }

    // Defect caught: a floor not written on a machine that has none, written
    // again on every boot, not raised by a newer bootloader, or not refusing
    // an older one once raised; or written with attributes that let the
    // operating system reach it.
    #[test]
    fn the_floor_is_written_raised_and_refuses_an_older_bootloader()
    {
        let mut store = Store::default();
        assert_eq!(boot(&mut store, 1).unwrap(), Recorded::Raised(1));
        assert_eq!(store.floor, Some((FLOOR_ATTRIBUTES, vec![1, 0, 0, 0])));
        assert_eq!(boot(&mut store, 1).unwrap(), Recorded::Nothing);
        assert_eq!(store.writes, 1);
        assert_eq!(boot(&mut store, 2).unwrap(), Recorded::Raised(2));
        assert!(matches!(
            boot(&mut store, 1),
            Err(BootError::FloorAboveStore {
                machine: 2,
                carried: 1
            })
        ));
        assert_eq!(store.floor, Some((FLOOR_ATTRIBUTES, vec![2, 0, 0, 0])));
    }

    // Defect caught: a platform whose firmware refuses the write stops the
    // boot, or is taken to have recorded the floor, instead of running on
    // the trust store's floor with the machine's left as it was.
    #[test]
    fn a_refused_write_keeps_the_boot_on_the_trust_stores_floor()
    {
        let mut store = Store {
            refuses: Some(WRITE_PROTECTED),
            ..Store::default()
        };
        assert_eq!(
            boot(&mut store, 1).unwrap(),
            Recorded::Refused(WRITE_PROTECTED)
        );
        assert_eq!(
            boot(&mut store, 2).unwrap(),
            Recorded::Refused(WRITE_PROTECTED)
        );
        assert_eq!(store.floor, None);
    }

    // Defect caught: a floor the firmware could not read overwritten with
    // the store's, which could lower it, or the boot refused for it.
    #[test]
    fn a_floor_the_firmware_cannot_read_is_never_written()
    {
        let mut store = Store {
            floor: Some((FLOOR_ATTRIBUTES, vec![9, 0, 0, 0])),
            read_fails: Some(DEVICE_ERROR),
            ..Store::default()
        };
        assert_eq!(boot(&mut store, 1).unwrap(), Recorded::Nothing);
        assert_eq!(store.writes, 0);
    }

    // Defect caught: a variable the bootloader did not write (one the
    // operating system can reach, or of another length) taken as a floor or
    // overwritten, instead of refusing the boot for the owner to recover.
    #[test]
    fn a_malformed_floor_refuses_the_boot_and_is_left_alone()
    {
        for floor in [
            (FLOOR_ATTRIBUTES | RUNTIME_ACCESS, vec![1, 0, 0, 0]),
            (FLOOR_ATTRIBUTES, vec![1, 0, 0, 0, 0]),
            (FLOOR_ATTRIBUTES, vec![1]),
        ]
        {
            let mut store = Store {
                floor: Some(floor.clone()),
                ..Store::default()
            };
            assert!(matches!(
                boot(&mut store, 1),
                Err(BootError::FloorMalformed(_))
            ));
            assert_eq!((store.floor, store.writes), (Some(floor), 0));
        }
    }
}
