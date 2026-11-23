// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/bench/src/lib.rs

//! What every Seraph benchmark shares: the counters it reads around a
//! measured operation ([`Counters`]), the samples it records and their
//! summary ([`Samples`], [`Summary`]), and the one result line it reports,
//! with the parser a comparison reads it back with ([`Report`],
//! [`parse_line`]). `shared/bench/README.md` specifies the line.
//!
//! `no_std`, no allocation, no dependency. The architecture-specific counter
//! reads live under `arch/`.

#![cfg_attr(not(test), no_std)]

mod arch;
mod counters;
mod line;
mod stats;

pub use arch::current::ARCH;
pub use counters::{Counters, EVENT_SLOTS, Reading};
pub use line::{
    LineError, ParseError, Parsed, RESERVED_KEYS, Report, TAG, Unit, Value, parse_line,
};
pub use stats::{Samples, Summary, summarize};
