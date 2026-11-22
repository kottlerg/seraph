// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/acpid_labels.rs

//! IPC labels for acpid's power surface, which pwrmgr calls.
//!
//! acpid runs the firmware's AML and holds the FADT's fixed register blocks
//! and the SCI (`services/acpid/README.md`), so the ACPI sleep and reset
//! sequences run in it and the fixed events reach the OS through it: pwrmgr,
//! the power policy, reaches them through a SEND badged
//! [`acpid_labels::POWER_AUTHORITY`](crate::acpid_labels::POWER_AUTHORITY) (`acpid.power`). Every request carries
//! the caller's compiled [`super::ACPID_LABELS_VERSION`] in `data[0]`.
//! The handler checks the label first, then the badge, then the version,
//! then the argument.

/// Enter a sleep state: write `SLP_TYP` and then `SLP_TYP | SLP_EN` to
/// `PM1a_CNT`, the `SLP_TYP` read from the state's `\_Sx_` package,
/// after `\_PTS` of the state when the tables define it and after
/// acpid disables the events it armed but the power button and clears
/// every event status. On a hardware-reduced platform, which has no
/// `PM1a_CNT`, write [`SLEEP_STATUS_WAK_STS`] to the FADT's
/// `SLEEP_STATUS_REG` when devmgr serves it, then
/// [`sleep_control_value`] to its `SLEEP_CONTROL_REG` (ACPI 6.5
/// § 4.8.3.7), after `\_PTS` as above.
///
/// Request: `data[0]` = the version; `data[1]` = the state, of which
/// only [`STATE_S5`] (soft-off) is served. On the success path the
/// platform powers off and no reply arrives; a
/// [`super::acpid_errors::SUCCESS`] reply means the platform still runs
/// 10 s after the writes, when acpid has enabled its GPEs again, and the
/// caller decides how long to wait.
/// Replies [`super::acpid_errors::INVALID_REQUEST`] for another state and
/// [`super::acpid_errors::NO_DEVICE`] when the platform has neither
/// `PM1a_CNT` nor `SLEEP_CONTROL_REG`, the tables no usable `\_S5_`,
/// or no AML loaded (always on RISC-V, whose platforms power off through
/// SBI).
pub const SLEEP: u64 = 1;
/// Reset the platform: write the FADT's `RESET_VALUE` to its
/// `RESET_REG`.
///
/// Request: `data[0]` = the version. On the success path the machine
/// resets and no reply arrives; a [`super::acpid_errors::SUCCESS`]
/// reply means the write returned and the platform still runs. Replies
/// [`super::acpid_errors::NO_DEVICE`] when acpid holds no `RESET_REG`:
/// devmgr serves none, in the memory or the I/O space, or acpid cannot bind
/// its port or map its page (always on RISC-V).
pub const RESET: u64 = 2;
/// Wait for a power event: acpid holds the call until one is pending,
/// with no bound, then replies with every event pending.
///
/// Request: `data[0]` = the version. Reply
/// ([`super::acpid_errors::SUCCESS`]): `data[0]` = the events, a mask of
/// [`EVENT_POWER_BUTTON`]. An event is consumed by the reply that
/// delivers it; one whose reply cannot be delivered (the caller died) is
/// kept for the next `WAIT_EVENT`, and one acpid had not delivered when
/// it died stays latched in the hardware and is delivered by the restarted
/// acpid, unless a `SLEEP` that returned cleared its status first. One caller waits at a time: a `WAIT_EVENT` that arrives while
/// another waits takes its place, and the earlier one is replied
/// [`super::acpid_errors::SUPERSEDED`]. Replies
/// [`super::acpid_errors::NO_DEVICE`] when acpid has no event to wait
/// for: devmgr served it no SCI or no `PM1a` event block, or the FADT
/// declares no fixed power button (always on RISC-V).
pub const WAIT_EVENT: u64 = 3;

/// Hand the caller what it needs to enter a sleep state itself, with no
/// further call on acpid: a derivation of acpid's capability over the
/// register [`SLEEP`] writes, and the state's `SLP_TYPa`, read from its
/// `\_Sx_` package at this request. The caller writes
/// [`pm1_control_writes`]'s two values to `PM1a_CNT`, or
/// [`sleep_control_value`] to `SLEEP_CONTROL_REG` on a hardware-reduced
/// platform, without the `\_PTS`, the quiescing of the events and the
/// clearing of `WAK_STS` that [`SLEEP`] runs first: pwrmgr's power-off on
/// the death of a core service, which may call no service
/// (`docs/supervision.md` § Core Set and System Death).
///
/// Request: `data[0]` = the version; `data[1]` = the state, of which
/// only [`STATE_S5`] is served. Reply ([`super::acpid_errors::SUCCESS`]):
/// `caps[0]` = the capability, derived from acpid's on every call: a
/// `Use`-only `IoPort` over the `PM1a_CNT` block or over
/// `SLEEP_CONTROL_REG`'s port, or an `Mmio` with `RIGHTS_MMIO_MAP` and
/// `RIGHTS_MMIO_WRITE` over the page that holds `SLEEP_CONTROL_REG`;
/// `data[0]` = the register's port, the block's first one for
/// `PM1a_CNT`, or its physical address; `data[1]` = the state's
/// `SLP_TYPa`, at most [`SLP_TYP_MAX`]; `data[2]` = which register,
/// [`SLEEP_REGISTER_PM1A_CNT`], [`SLEEP_REGISTER_CONTROL_IO`] or
/// [`SLEEP_REGISTER_CONTROL_MEMORY`]. Replies
/// [`super::acpid_errors::INVALID_REQUEST`] for another state, and
/// [`super::acpid_errors::NO_DEVICE`] when [`SLEEP`] would, or when the
/// derivation fails.
pub const QUERY_SLEEP: u64 = 4;

/// [`QUERY_SLEEP`]'s register: `PM1a_CNT`, a 16-bit I/O-port register.
pub const SLEEP_REGISTER_PM1A_CNT: u64 = 0;
/// [`QUERY_SLEEP`]'s register: `SLEEP_CONTROL_REG`, an 8-bit register in
/// the I/O space.
pub const SLEEP_REGISTER_CONTROL_IO: u64 = 1;
/// [`QUERY_SLEEP`]'s register: `SLEEP_CONTROL_REG`, an 8-bit register in
/// the memory space.
pub const SLEEP_REGISTER_CONTROL_MEMORY: u64 = 2;

/// [`SLEEP`]'s and [`QUERY_SLEEP`]'s state argument for S5, soft-off.
pub const STATE_S5: u64 = 5;

/// `PM1_CNT` bit 13, `SLP_EN`: the write that sets it enters the state
/// `SLP_TYP` names.
pub const SLP_EN: u16 = 1 << 13;

/// The position of `PM1_CNT`'s three-bit `SLP_TYP` field (bits 12:10).
const SLP_TYP_SHIFT: u16 = 10;

/// The largest `SLP_TYP`, the field being three bits wide.
pub const SLP_TYP_MAX: u64 = 7;

/// The two values written to `PM1a_CNT`, which reads `current`, to enter
/// the state of `SLP_TYPa` `slp_typ`: `SLP_TYP` with
/// `SLP_EN` clear, then with it set, every other bit kept. `slp_typ` is at
/// most [`SLP_TYP_MAX`]; higher bits are dropped. acpid's [`SLEEP`] and
/// the holder of a [`QUERY_SLEEP`] answer both write them.
#[must_use]
pub const fn pm1_control_writes(current: u16, slp_typ: u16) -> [u16; 2]
{
    let field = 0b111 << SLP_TYP_SHIFT;
    let typed = (current & !(field | SLP_EN)) | ((slp_typ << SLP_TYP_SHIFT) & field);
    [typed, typed | SLP_EN]
}

/// `SLEEP_CONTROL_REG` bit 5, `SLP_EN` (ACPI 6.5 § 4.8.3.7): the write
/// that sets it enters the state the register's `SLP_TYPx` field names.
pub const SLEEP_CONTROL_SLP_EN: u8 = 1 << 5;

/// The position of `SLEEP_CONTROL_REG`'s three-bit `SLP_TYPx` field
/// (bits 4:2).
const SLEEP_CONTROL_TYP_SHIFT: u16 = 2;

/// `SLEEP_STATUS_REG` bit 7, `WAK_STS`: set by the platform on a wake
/// event, cleared by writing 1.
pub const SLEEP_STATUS_WAK_STS: u8 = 1 << 7;

/// The one value written to `SLEEP_CONTROL_REG` to enter the state of
/// `SLP_TYPa` `slp_typ`: `SLP_TYPx` and `SLP_EN` together, the
/// reserved bits 0, 1, 6 and 7 clear. `slp_typ` is at most
/// [`SLP_TYP_MAX`]; higher bits are dropped. acpid's [`SLEEP`] and the
/// holder of a [`QUERY_SLEEP`] answer both write it.
#[must_use]
pub const fn sleep_control_value(slp_typ: u16) -> u8
{
    let field = 0b111 << SLEEP_CONTROL_TYP_SHIFT;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the field is bits 4:2, so the masked value fits a byte"
    )]
    let typed = ((slp_typ << SLEEP_CONTROL_TYP_SHIFT) & field) as u8;
    typed | SLEEP_CONTROL_SLP_EN
}

/// [`WAIT_EVENT`]'s event bit: the fixed power button was pressed
/// (`PWRBTN_STS`).
pub const EVENT_POWER_BUTTON: u64 = 1;

/// Authority bit in the acpid-service-endpoint badge's high u64 bit, set
/// on `acpid.power`. Without it [`SLEEP`], [`QUERY_SLEEP`], [`RESET`] and
/// [`WAIT_EVENT`] reply [`super::acpid_errors::UNAUTHORIZED`].
pub const POWER_AUTHORITY: u64 = 1u64 << 63;

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a write that loses SCI_EN or another bit, keeps a stale
    // SLP_TYP or SLP_EN, or lets an oversized type spill out of its field.
    #[test]
    fn pm1_writes_set_slp_typ_then_slp_en_and_keep_the_other_bits()
    {
        // SCI_EN (bit 0) and a stale SLP_TYP and SLP_EN.
        assert_eq!(pm1_control_writes(0x3C01, 0), [0x0001, 0x2001]);
        assert_eq!(pm1_control_writes(0x0001, 5), [0x1401, 0x3401]);
        assert_eq!(pm1_control_writes(0x0000, 7), [0x1C00, 0x3C00]);
        // A value past the field is cut to it.
        assert_eq!(pm1_control_writes(0x0000, 0xF), [0x1C00, 0x3C00]);
    }

    // Defect caught: SLP_TYPx at the wrong bits, SLP_EN missing, or an
    // oversized type spilling into SLP_EN or the reserved bits.
    #[test]
    fn sleep_control_value_is_slp_typ_in_bits_4_to_2_with_slp_en()
    {
        assert_eq!(sleep_control_value(0), 0x20);
        assert_eq!(sleep_control_value(5), 0x34);
        assert_eq!(sleep_control_value(7), 0x3C);
        // A value past the field is cut to it.
        assert_eq!(sleep_control_value(0xF), 0x3C);
        assert_eq!(sleep_control_value(0xFFFF), 0x3C);
        assert_eq!(SLEEP_STATUS_WAK_STS, 0x80);
    }
}
