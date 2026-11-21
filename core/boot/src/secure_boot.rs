// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/secure_boot.rs

//! The firmware's UEFI Secure Boot state, read and logged on every boot
//! ([docs/signing.md](../../../docs/signing.md) § Secure Boot).
//!
//! Secure Boot is the firmware's: when the platform enables it, the firmware
//! verifies this bootloader against its db before running it. The bootloader
//! neither needs it nor enforces it
//! ([docs/platform-requirements.md](../../../docs/platform-requirements.md)):
//! it reads the state and reports it. [`read_state`] reads the two variables
//! the UEFI specification defines for it under [`EFI_GLOBAL_VARIABLE_GUID`],
//! `SecureBoot` and, when that is 0, `SetupMode`, through
//! [`VariableServices`] before `ExitBootServices`; [`log_state`] logs one
//! line. Only a well-formed `SecureBoot` of 1 reads as [`State::On`]: one
//! byte, 0 or 1, carrying exactly [`STATE_ATTRIBUTES`], the volatile
//! attributes the firmware creates it with, so a non-volatile copy written
//! by an operating system on firmware without Secure Boot is never taken for
//! the firmware's.

use crate::bprintln;
use crate::uefi::{
    EFI_GLOBAL_VARIABLE_GUID, EFI_VARIABLE_BOOTSERVICE_ACCESS, EFI_VARIABLE_RUNTIME_ACCESS,
    EfiStatus, VariableRead, VariableServices,
};

/// `SecureBoot` as a NUL-terminated UTF-16 variable name: 1 while the
/// firmware verifies the images it runs.
// rustfmt::skip keeps the UTF-16 code units in rows of five, which rustfmt would
// spread one per line.
#[rustfmt::skip]
pub static SECURE_BOOT_VARIABLE: [u16; 11] = [
    b'S' as u16, b'e' as u16, b'c' as u16, b'u' as u16, b'r' as u16,
    b'e' as u16, b'B' as u16, b'o' as u16, b'o' as u16, b't' as u16,
    0u16,
];

/// `SetupMode` as a NUL-terminated UTF-16 variable name: 1 while no
/// platform key is enrolled.
// rustfmt::skip keeps the UTF-16 code units in rows of five, which rustfmt would
// spread one per line.
#[rustfmt::skip]
pub static SETUP_MODE_VARIABLE: [u16; 10] = [
    b'S' as u16, b'e' as u16, b't' as u16, b'u' as u16, b'p' as u16,
    b'M' as u16, b'o' as u16, b'd' as u16, b'e' as u16, 0u16,
];

/// The attributes of both state variables, exactly: reachable by boot and
/// runtime services, and not kept across resets, since the firmware derives
/// them on every boot.
pub const STATE_ATTRIBUTES: u32 = EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;

/// The Secure Boot state of this boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State
{
    /// The firmware verifies the images it runs: it verified this
    /// bootloader.
    On,
    /// The firmware runs images unverified, for this reason.
    Off(Off),
    /// `SecureBoot` is malformed or could not be read: the state is unknown,
    /// and is never taken as [`State::On`].
    Unknown(Malformed),
}

/// Why Secure Boot is off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Off
{
    /// No `SecureBoot` variable exists: the firmware does not implement
    /// Secure Boot.
    NotImplemented,
    /// The firmware is in setup mode: no platform key is enrolled.
    SetupMode,
    /// Keys are enrolled, and the platform has verification disabled.
    NotEnforced,
    /// `SecureBoot` is 0, and `SetupMode` says no more, for this reason.
    SetupModeUnknown(Malformed),
}

/// How a state variable could not be taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed
{
    /// The firmware failed the read with this status.
    Unreadable(EfiStatus),
    /// It holds this many bytes, not one.
    Length(usize),
    /// It carries these attributes, not [`STATE_ATTRIBUTES`].
    Attributes(u32),
    /// Its byte is this value, neither 0 nor 1.
    Value(u8),
    /// It does not exist, where the variable read before it says it should.
    Absent,
}

impl core::fmt::Display for Malformed
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match self
        {
            Malformed::Unreadable(status) => write!(f, "the read failed (status={status:#018x})"),
            Malformed::Length(len) => write!(f, "{len} bytes, not 1"),
            Malformed::Attributes(attributes) => write!(
                f,
                "attributes {attributes:#x}, not {STATE_ATTRIBUTES:#x} (boot and runtime services, \
                 volatile)"
            ),
            Malformed::Value(value) => write!(f, "value {value}, not 0 or 1"),
            Malformed::Absent => write!(f, "absent"),
        }
    }
}

/// One state variable from what `GetVariable` returned into `byte`: its
/// value, or `None` when it does not exist.
///
/// # Errors
/// [`Malformed`] for a failed read, another length than one byte, other
/// attributes than [`STATE_ATTRIBUTES`], or a value other than 0 or 1.
pub fn decode_flag(read: VariableRead, byte: u8) -> Result<Option<bool>, Malformed>
{
    match read
    {
        VariableRead::NotFound => Ok(None),
        VariableRead::Failed(status) => Err(Malformed::Unreadable(status)),
        VariableRead::TooLarge { len } => Err(Malformed::Length(len)),
        VariableRead::Found { len, .. } if len != 1 => Err(Malformed::Length(len)),
        VariableRead::Found { attributes, .. } if attributes != STATE_ATTRIBUTES =>
        {
            Err(Malformed::Attributes(attributes))
        }
        VariableRead::Found { .. } => match byte
        {
            0 => Ok(Some(false)),
            1 => Ok(Some(true)),
            other => Err(Malformed::Value(other)),
        },
    }
}

/// The state that `SecureBoot` decoded as `secure_boot` gives, asking
/// `setup_mode` for `SetupMode` only when `SecureBoot` is 0.
pub fn state(
    secure_boot: Result<Option<bool>, Malformed>,
    setup_mode: impl FnOnce() -> Result<Option<bool>, Malformed>,
) -> State
{
    match secure_boot
    {
        Err(why) => State::Unknown(why),
        Ok(None) => State::Off(Off::NotImplemented),
        Ok(Some(true)) => State::On,
        Ok(Some(false)) => match setup_mode()
        {
            Ok(Some(true)) => State::Off(Off::SetupMode),
            Ok(Some(false)) => State::Off(Off::NotEnforced),
            // A firmware that has `SecureBoot` implements `SetupMode` too.
            Ok(None) => State::Off(Off::SetupModeUnknown(Malformed::Absent)),
            Err(why) => State::Off(Off::SetupModeUnknown(why)),
        },
    }
}

/// Read one state variable `name` from `vars`.
fn read_flag(vars: &mut impl VariableServices, name: &[u16]) -> Result<Option<bool>, Malformed>
{
    let mut byte = [0u8; 1];
    let read = vars.get(name, &EFI_GLOBAL_VARIABLE_GUID, &mut byte);
    decode_flag(read, byte[0])
}

/// The Secure Boot state, read from `vars`.
pub fn read_state(vars: &mut impl VariableServices) -> State
{
    let secure_boot = read_flag(vars, &SECURE_BOOT_VARIABLE);
    state(secure_boot, || read_flag(vars, &SETUP_MODE_VARIABLE))
}

/// Log `state` as one line, `boot: Secure Boot: on`, `off (...)` or
/// `unknown (...)`. No state stops the boot.
pub fn log_state(state: State)
{
    match state
    {
        State::On =>
        {
            bprintln!("[--------] boot: Secure Boot: on (the firmware verified this bootloader)");
        }
        State::Off(Off::NotImplemented) =>
        {
            bprintln!("[--------] boot: Secure Boot: off (the firmware does not implement it)");
        }
        State::Off(Off::SetupMode) =>
        {
            bprintln!("[--------] boot: Secure Boot: off (setup mode: no platform key enrolled)");
        }
        State::Off(Off::NotEnforced) =>
        {
            bprintln!("[--------] boot: Secure Boot: off (keys enrolled, verification disabled)");
        }
        State::Off(Off::SetupModeUnknown(why)) =>
        {
            bprintln!("[--------] boot: Secure Boot: off (SetupMode: {why})");
        }
        State::Unknown(why) =>
        {
            bprintln!("[--------] boot: Secure Boot: unknown (SecureBoot: {why})");
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::uefi::{EFI_VARIABLE_NON_VOLATILE, EfiGuid};

    /// `EFI_DEVICE_ERROR`, a store that failed.
    const DEVICE_ERROR: EfiStatus = 0x8000_0000_0000_0007;

    fn found(len: usize, attributes: u32) -> VariableRead
    {
        VariableRead::Found { len, attributes }
    }

    // Defect caught: a state variable of another shape taken as the
    // firmware's (a non-volatile copy an operating system planted on firmware
    // without Secure Boot read as on, or a byte past 1 read as true), or an
    // absent variable read as malformed.
    #[test]
    fn only_one_volatile_byte_of_0_or_1_decodes()
    {
        assert_eq!(decode_flag(found(1, STATE_ATTRIBUTES), 1), Ok(Some(true)));
        assert_eq!(decode_flag(found(1, STATE_ATTRIBUTES), 0), Ok(Some(false)));
        assert_eq!(decode_flag(VariableRead::NotFound, 1), Ok(None));
        let planted = STATE_ATTRIBUTES | EFI_VARIABLE_NON_VOLATILE;
        assert_eq!(
            decode_flag(found(1, planted), 1),
            Err(Malformed::Attributes(planted))
        );
        assert_eq!(
            decode_flag(found(1, STATE_ATTRIBUTES), 2),
            Err(Malformed::Value(2))
        );
        assert_eq!(
            decode_flag(found(0, STATE_ATTRIBUTES), 1),
            Err(Malformed::Length(0))
        );
        assert_eq!(
            decode_flag(VariableRead::TooLarge { len: 4 }, 1),
            Err(Malformed::Length(4))
        );
        assert_eq!(
            decode_flag(VariableRead::Failed(DEVICE_ERROR), 1),
            Err(Malformed::Unreadable(DEVICE_ERROR))
        );
    }

    // Defect caught: an unknown or malformed SecureBoot taken as on, SetupMode
    // read when SecureBoot already settles the state, the two off states
    // confused, or a missing SetupMode logged as one of zero bytes.
    #[test]
    fn only_secure_boot_1_is_on()
    {
        let unread = || -> Result<Option<bool>, Malformed> { panic!("SetupMode read") };
        assert_eq!(state(Ok(Some(true)), unread), State::On);
        assert_eq!(state(Ok(None), unread), State::Off(Off::NotImplemented));
        assert_eq!(
            state(Err(Malformed::Value(7)), unread),
            State::Unknown(Malformed::Value(7))
        );
        assert_eq!(
            state(Ok(Some(false)), || Ok(Some(true))),
            State::Off(Off::SetupMode)
        );
        assert_eq!(
            state(Ok(Some(false)), || Ok(Some(false))),
            State::Off(Off::NotEnforced)
        );
        assert_eq!(
            state(Ok(Some(false)), || Err(Malformed::Unreadable(DEVICE_ERROR))),
            State::Off(Off::SetupModeUnknown(Malformed::Unreadable(DEVICE_ERROR)))
        );
        // A missing SetupMode is told apart from one of zero bytes.
        assert_eq!(
            state(Ok(Some(false)), || Ok(None)),
            State::Off(Off::SetupModeUnknown(Malformed::Absent))
        );
        assert_ne!(Malformed::Absent, Malformed::Length(0));
    }

    // Defect caught: a variable name that differs from the specification's,
    // or runs past its NUL, so the bootloader reads a variable no firmware
    // sets and reports every machine as without Secure Boot.
    #[test]
    fn the_variables_are_the_specifications()
    {
        let secure: Vec<u16> = "SecureBoot\0".encode_utf16().collect();
        let setup: Vec<u16> = "SetupMode\0".encode_utf16().collect();
        assert_eq!(SECURE_BOOT_VARIABLE.as_slice(), secure.as_slice());
        assert_eq!(SETUP_MODE_VARIABLE.as_slice(), setup.as_slice());
    }

    /// The firmware's two state variables in memory, each its attributes and
    /// bytes when it exists.
    struct Firmware
    {
        secure_boot: Option<(u32, Vec<u8>)>,
        setup_mode: Option<(u32, Vec<u8>)>,
    }

    impl VariableServices for Firmware
    {
        fn get(&mut self, name: &[u16], vendor: &EfiGuid, buffer: &mut [u8]) -> VariableRead
        {
            assert!(core::ptr::eq(vendor, &raw const EFI_GLOBAL_VARIABLE_GUID));
            let variable = if name == SECURE_BOOT_VARIABLE.as_slice()
            {
                &self.secure_boot
            }
            else
            {
                assert_eq!(name, SETUP_MODE_VARIABLE.as_slice());
                &self.setup_mode
            };
            match variable
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

        fn set(&mut self, _: &[u16], _: &EfiGuid, _: u32, _: &[u8]) -> Result<(), EfiStatus>
        {
            panic!("the Secure Boot state is read, never written");
        }
    }

    fn flag(value: u8) -> (u32, Vec<u8>)
    {
        (STATE_ATTRIBUTES, vec![value])
    }

    // Defect caught: the state read from other variables, under another GUID,
    // or into a buffer that lets a longer variable through.
    #[test]
    fn read_state_reads_the_firmwares_variables()
    {
        let mut on = Firmware {
            secure_boot: Some(flag(1)),
            setup_mode: Some(flag(0)),
        };
        assert_eq!(read_state(&mut on), State::On);
        let mut setup = Firmware {
            secure_boot: Some(flag(0)),
            setup_mode: Some(flag(1)),
        };
        assert_eq!(read_state(&mut setup), State::Off(Off::SetupMode));
        let mut none = Firmware {
            secure_boot: None,
            setup_mode: None,
        };
        assert_eq!(read_state(&mut none), State::Off(Off::NotImplemented));
        let mut long = Firmware {
            secure_boot: Some((STATE_ATTRIBUTES, vec![1, 0])),
            setup_mode: Some(flag(0)),
        };
        assert_eq!(read_state(&mut long), State::Unknown(Malformed::Length(2)));
    }
}
