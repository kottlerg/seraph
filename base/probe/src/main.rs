// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// base/probe/src/main.rs

//! Phase-1 verification probe for the new `seraph::log!` infrastructure.
//!
//! Drives the new path end-to-end without touching the legacy stdout
//! stream:
//! 1. `seraph::log::register_name(b"probe")` issues a
//!    `STREAM_REGISTER_NAME` over the freshly lazy-acquired tokened
//!    SEND cap (acquired from the discovery cap installed in this
//!    process's `ProcessInfo` at create time, via `GET_LOG_CAP`).
//! 2. `seraph::log!("probe message")` formats one line and emits it
//!    via `STREAM_BYTES` on the same cached cap.
//!
//! Observing `[probe] probe message` in the boot log alongside the
//! synthetic `[init-logd] token=N registered name='probe'` line proves the
//! discovery → tokened → register/write chain works.

#![feature(restricted_std)]

fn main()
{
    std::os::seraph::log::register_name(b"probe");
    std::os::seraph::log!("probe message");
}
