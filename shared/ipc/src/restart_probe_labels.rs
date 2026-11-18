// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/restart_probe_labels.rs

//! The service labels of the `crasher` fixture's `worker-fault` role, and of
//! its `boot-fault` role once an instance lives through its bootstrap
//! (services/crasher/README.md), through which svctest checks that svcmgr
//! restarts a supervised service whose worker thread faults, and one whose
//! instance died before its bootstrap request.
//!
//! The fixture serves them on the endpoint of the name its recipe provides:
//! [`NAME`] for `worker-fault`, `crasher.boot` for `boot-fault`. Every
//! request carries no data; no badge bit is checked.

/// The name the `worker-fault` recipe provides
/// (`rootfs/config/svcmgr/tests/crasher-worker.svc`).
pub const NAME: &[u8] = b"crasher.worker";
/// Reply `SUCCESS` with data word 0 the instance's nonce: a random value
/// the process draws once at startup, so a caller tells two instances
/// apart.
pub const PROBE_INSTANCE: u64 = 1;
/// Reply `SUCCESS`, then receive nothing more and start a thread that
/// takes a terminal fault after [`FAULT_DELAY_MS`] while the main thread
/// lives on.
pub const PROBE_FAULT_WORKER: u64 = 2;
/// How long the fixture's worker thread waits before it faults, so the
/// caller's next call is queued before the fixture dies.
pub const FAULT_DELAY_MS: u64 = 200;
/// The reply label of a handled request.
pub const SUCCESS: u64 = 0;
/// The reply label of a request with an unknown label.
pub const UNKNOWN_OPCODE: u64 = 1;
