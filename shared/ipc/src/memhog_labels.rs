// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/memhog_labels.rs

//! The `memhog` fixture's service labels (services/fixtures/service-modes/README.md#memhog): a
//! supervised service that fills memmgr's pool up to the system reserve on
//! request and holds it until it is stopped, which svctest's `oom` phase
//! drives the out-of-memory policy service with.
//!
//! The fixture serves them on the endpoint of the name its recipe provides,
//! [`NAME`]. No badge bit is checked.

/// The name the fixture's recipe provides
/// (`rootfs/config/svcmgr/tests/memhog.svc`).
pub const NAME: &[u8] = b"memhog.ctl";
/// Reply [`SUCCESS`] with data word 0 the instance's nonce, a random
/// value the process draws once at startup, so a caller tells two
/// instances apart, and data word 1 the pages the instance has taken by
/// [`HOG`]: 0 for an idle instance.
pub const PROBE: u64 = 1;
/// Take what memmgr can still promise a process outside the system
/// reserve, through the heap and then by one-page grants, until nothing
/// is left and the pressure level has read `CRITICAL` for 500 ms; then
/// reply [`SUCCESS`] with data word 0 the pages taken, and keep taking
/// back what other processes free, every 10 ms, until the process dies.
/// [`NOT_CRITICAL`] when the level does not settle within 30 s; what was
/// taken is kept. A repeat fills again from what is held and replies the
/// same way. The fill and its times are `shared/mem-fill`'s.
pub const HOG: u64 = 2;
/// The reply label of a handled request.
pub const SUCCESS: u64 = 0;
/// The reply label of a request with an unknown label.
pub const UNKNOWN_OPCODE: u64 = 1;
/// The reply label of a [`HOG`] whose level did not settle at
/// `CRITICAL`, or that could not read the level.
pub const NOT_CRITICAL: u64 = 2;
