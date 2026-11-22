// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/rtc_labels.rs

//! IPC labels for RTC chip drivers (`services/drivers/cmos`,
//! `services/drivers/goldfish-rtc`, and future per-board chip drivers).
//!
//! Every RTC driver implements exactly one operation: return the current
//! wall-clock time, as `u64` microseconds since the Unix epoch. devmgr
//! owns the per-board RTC and hands clients a
//! [`READ_AUTHORITY`](crate::rtc_labels::READ_AUTHORITY)-badged SEND via
//! [`devmgr_labels::QUERY_DEVICE`](crate::devmgr_labels::QUERY_DEVICE) on the `rtc` class. `timed` is the sole client
//! today: it resolves the SEND once at startup, computes
//! `offset = rtc_us - kernel_monotonic_us`, and serves
//! [`timed_labels::GET_WALL_TIME`](crate::timed_labels::GET_WALL_TIME) thereafter without further driver IPC.
//!
//! **Acquisition path**: the RTC driver binary lives on the rootfs disk
//! under `/services/drivers/` and is loaded by devmgr from there. svcmgr
//! walks its system root to `/services/drivers/` and hands devmgr a
//! `LOOKUP | READ | READDIR`-attenuated subtree cap via
//! [`devmgr_labels::SET_DRIVERS_DIR`](crate::devmgr_labels::SET_DRIVERS_DIR); devmgr replies before any spawn
//! work. No step names an RTC driver: in the drivers-directory pass, on
//! devmgr's control thread while its registry workers go on serving,
//! devmgr binds the driver whose declaration (`rtc` class) matches the
//! RTC's platform device record (`PNP0B00`, `PNP0B01` or `PNP0B02` on
//! x86-64, the `google,goldfish-rtc` key on RISC-V), spawns it through
//! [`procmgr_labels::CREATE_FROM_FILE`](crate::procmgr_labels::CREATE_FROM_FILE), and delivers the record's
//! hardware authority cap (ISA `IoPort` for CMOS; MMIO aperture for
//! goldfish-rtc) through the bootstrap protocol. An `rtc`
//! [`devmgr_labels::QUERY_DEVICE`](crate::devmgr_labels::QUERY_DEVICE) that would find no driver waits until
//! the pass and its settle are done. Each spawn is attempted once per boot,
//! with two exceptions: devmgr's restart of a served driver that dies, which
//! it serves at the class's next ordinal
//! (`services/devmgr/docs/responsibilities.md` § Driver Restart), and its
//! bounded retry of a create procmgr refused with `IO_ERROR` or
//! `OUT_OF_MEMORY` (§ Create retry there), so the RTC at ordinal 0 need not
//! last the boot, and a first create's failure need not be final. A client finds the RTC as it finds
//! any driver of its class, by probing the ordinals
//! ([`first_device`](crate::first_device)): the ordinal of a driver that died replies
//! [`devmgr_errors::WITHDRAWN`](crate::devmgr_errors::WITHDRAWN), and an
//! ordinal past the last served driver replies
//! [`devmgr_errors::NO_DEVICE`](crate::devmgr_errors::NO_DEVICE), whose retry
//! rule is `NO_DEVICE`'s. RTC drivers are **not** carried in the boot bundle.
//!
//! Adding a new RTC chip is a matter of writing a driver crate that
//! answers this single label and binding it through devmgr's per-board
//! discovery path under the `rtc` class; clients reach it via the same
//! `rtc` class SEND. `timed` itself never sees the chip-specific details.

/// Request the current wall-clock time.
///
/// Wire format: empty body (no data words, no caps). Reply:
/// `data[0]` is `u64` microseconds since the Unix epoch. Reply
/// label carries a status code in the lower 16 bits. Caller's
/// badge must carry [`READ_AUTHORITY`] (devmgr stamps it on every
/// SEND its `rtc` class `QUERY_DEVICE` replies carry); the driver replies
/// [`rtc_errors::UNAUTHORIZED`] otherwise.
pub const RTC_GET_EPOCH_TIME: u64 = 1;

/// Authority bit in the RTC-service-endpoint badge's high u64 bit.
/// Set on caps devmgr mints in response to [`devmgr_labels::QUERY_DEVICE`]
/// on the `rtc` class; gates [`RTC_GET_EPOCH_TIME`].
/// A verb ("may read"), not an identity. Shares the same `1 << 63`
/// bit position as [`serial_labels::WRITE_AUTHORITY`] and
/// [`fb_labels::WRITE_AUTHORITY`]. The cmos / goldfish-rtc drivers
/// enforce the bit at the service loop, as the serial driver enforces
/// its bits (defence-in-depth alongside the upstream gate: only a
/// holder of the `rtc` class SEND reaches the driver through devmgr).
pub const READ_AUTHORITY: u64 = 1u64 << 63;
