// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/crashd_errors.rs

//! Error replies from crashd's live-core endpoint
//! ([`crate::crashd_labels`]).

/// Request handled.
pub const SUCCESS: u64 = 0;
/// The badge does not carry [`crate::crashd_labels::LIVE_CORE_AUTHORITY`].
pub const UNAUTHORIZED: u64 = 1;
/// The name block is missing, empty or too long, or `caps[0]` is not an
/// endpoint capability holding `SEND`.
pub const INVALID_ARGUMENT: u64 = 2;
/// No live process carries the name, or it ended before its snapshot or
/// before crashd could read its declarations after it.
pub const NOT_FOUND: u64 = 3;
/// Memory is short: memmgr's pressure level reads `CRITICAL`, or crashd,
/// holding faults declined for want of memory, holds one or reads memmgr's
/// draw room short. A core's buffers and file writes would need pages, so
/// crashd writes none.
pub const MEMORY_CRITICAL: u64 = 4;
/// procmgr refused the snapshot, or the attach crashd makes after it to read
/// the process's declarations (`NOT_ATTACHABLE` when the process declared
/// itself undebuggable since the capture); `data[0]` carries its label
/// (services/procmgr/docs/ipc-interface.md § Label 33: `SNAPSHOT`, § Label
/// 20: `ATTACH_PROCESS`).
pub const SNAPSHOT_REFUSED: u64 = 5;
/// The core was not written: the core directory, its budget, or a write
/// failed. A `.part` file may remain until the next core.
pub const NOT_WRITTEN: u64 = 6;
/// The request passed its bound (services/crashd/docs/operation.md § Bounds)
/// before the core was written.
pub const TIMED_OUT: u64 = 7;
/// Unknown label on crashd's live-core endpoint.
pub const UNKNOWN_OPCODE: u64 = 8;
/// The process declared that no core of it is written (procmgr's
/// `DECLARE_NO_CORE`): before the request, and crashd asked for no snapshot,
/// or during it, and crashd released its snapshot before the reply.
pub const NO_CORE: u64 = 9;
