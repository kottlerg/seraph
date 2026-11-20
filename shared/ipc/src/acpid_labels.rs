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
/// every event status.
///
/// Request: `data[0]` = the version; `data[1]` = the state, of which
/// only [`STATE_S5`] (soft-off) is served. On the success path the
/// platform powers off and no reply arrives; a
/// [`super::acpid_errors::SUCCESS`] reply means the platform still runs
/// 10 s after the writes, when acpid has enabled its GPEs again, and the
/// caller decides how long to wait.
/// Replies [`super::acpid_errors::INVALID_REQUEST`] for another state and
/// [`super::acpid_errors::NO_DEVICE`] when the platform has no
/// `PM1a_CNT`, the tables no usable `\_S5_`, or no AML loaded (always
/// on RISC-V, whose platforms power off through SBI).
pub const SLEEP: u64 = 1;
/// Reset the platform: write the FADT's `RESET_VALUE` to its
/// `RESET_REG`.
///
/// Request: `data[0]` = the version. On the success path the machine
/// resets and no reply arrives; a [`super::acpid_errors::SUCCESS`]
/// reply means the write returned and the platform still runs. Replies
/// [`super::acpid_errors::NO_DEVICE`] when the FADT places no
/// `RESET_REG` in the I/O space (always on RISC-V).
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
/// further call on acpid: a derivation of the `IoPort` over `PM1a_CNT`,
/// and the state's `SLP_TYPa`, read from its `\_Sx_` package at this
/// request. The caller writes [`pm1_control_writes`]'s two values to
/// `PM1a_CNT`, without the `\_PTS` and the quiescing of the events that
/// [`SLEEP`] runs first: pwrmgr's power-off on the death of a core
/// service, which may call no service (`docs/supervision.md` § Core Set
/// and System Death).
///
/// Request: `data[0]` = the version; `data[1]` = the state, of which
/// only [`STATE_S5`] is served. Reply ([`super::acpid_errors::SUCCESS`]):
/// `caps[0]` = an `IoPort` over the `PM1a_CNT` block, derived from
/// acpid's on every call; `data[0]` = the block's first port; `data[1]` =
/// the state's `SLP_TYPa`, at most [`SLP_TYP_MAX`]. Replies
/// [`super::acpid_errors::INVALID_REQUEST`] for another state, and
/// [`super::acpid_errors::NO_DEVICE`] when [`SLEEP`] would, or when the
/// derivation fails.
pub const QUERY_SLEEP: u64 = 4;

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

/// [`WAIT_EVENT`]'s event bit: the fixed power button was pressed
/// (`PWRBTN_STS`).
pub const EVENT_POWER_BUTTON: u64 = 1;

/// Authority bit in the acpid-service-endpoint badge's high u64 bit, set
/// on `acpid.power`. Without it [`SLEEP`], [`RESET`] and [`WAIT_EVENT`]
/// reply [`super::acpid_errors::UNAUTHORIZED`].
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
}
