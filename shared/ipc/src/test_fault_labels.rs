// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/test_fault_labels.rs

//! The `test-fault` fixture driver's service labels and roles
//! (services/drivers/test-fault/README.md).
//!
//! devmgr binds the fixture to QEMU's `pci-testdev` functions (PCI `1b36:0005`)
//! only through [`devmgr_labels::BIND_DRIVERS`](crate::devmgr_labels::BIND_DRIVERS), since it is installed outside
//! `/services/drivers/`. Each instance takes its role from the resource list
//! devmgr delivers it: a function with no BAR 2 serves; one whose BAR 2 is
//! [`HANG_BAR_BYTES`] long holds [`HOLD_BYTES`] and never reports ready; one
//! whose BAR 2 is [`ORPHAN_BAR_BYTES`] long holds [`HOLD_BYTES`] and fails its
//! bootstrap's terminal round, so devmgr destroys it mid-bootstrap; one whose
//! BAR 2 is [`DIE_BAR_BYTES`] long exits before its next bootstrap request, so
//! devmgr abandons the bind while it waits for that request. A serving
//! instance answers [`FAULT_PING`] with `SUCCESS`, [`FAULT_EXIT`] with `SUCCESS`
//! before it receives nothing more and exits once [`FAULT_EXIT_DELAY_MS`] has
//! passed, and [`FAULT_WORKER`] with `SUCCESS` before it receives nothing more
//! and a thread of its own faults once that delay has passed, so a call sent on
//! the endpoint after either reply stays queued until devmgr withdraws the dead
//! fixture. Every request carries no data; no badge bit is checked.

/// Length of the BAR 2 (QEMU `membar=4K`) of a function whose fixture
/// holds [`HOLD_BYTES`] and never reports ready.
pub const HANG_BAR_BYTES: u64 = 4 << 10;
/// Length of the BAR 2 (QEMU `membar=8K`) of a function whose fixture
/// holds [`HOLD_BYTES`] and fails its bootstrap's terminal round.
pub const ORPHAN_BAR_BYTES: u64 = 8 << 10;
/// Length of the BAR 2 (QEMU `membar=16K`) of a function whose fixture
/// exits once that BAR's round arrives, before its next bootstrap request.
pub const DIE_BAR_BYTES: u64 = 16 << 10;
/// Bytes a hanging or orphaned fixture holds until devmgr destroys it, so
/// a harness sees the destruction as their return to memmgr's free pool
/// (4 MiB, well above the pool's incidental movement in a test boot).
pub const HOLD_BYTES: usize = 4 << 20;
/// Reply `SUCCESS`.
pub const FAULT_PING: u64 = 1;
/// Reply `SUCCESS`, then exit after [`FAULT_EXIT_DELAY_MS`] without
/// receiving again.
pub const FAULT_EXIT: u64 = 2;
/// Reply `SUCCESS`, then receive nothing more and start a thread that
/// takes a terminal fault after [`FAULT_EXIT_DELAY_MS`], while the main
/// thread lives on: the death of a driver whose worker thread faults.
pub const FAULT_WORKER: u64 = 3;
/// How long the fixture waits between its `FAULT_EXIT` reply and its
/// exit, so the caller's next call is queued before the fixture dies.
pub const FAULT_EXIT_DELAY_MS: u64 = 200;
