// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/bench/src/lib.rs

//! What every Seraph benchmark shares: the counters it reads around a
//! measured operation ([`Counters`]), the samples it records and their
//! summary ([`Samples`], [`Summary`]), and the one result line it reports,
//! with the parser a comparison reads it back with ([`Report`],
//! [`parse_line`]), and the windows of a window row ([`WindowShape`]).
//! `shared/bench/README.md` specifies the line.
//!
//! `no_std`, no allocation, no dependency. The architecture-specific counter
//! reads live under `arch/`, built with the default `counters` feature; a
//! reader of result lines on any host builds without it.

#![cfg_attr(not(test), no_std)]

#[cfg(feature = "counters")]
mod arch;
#[cfg(feature = "counters")]
mod counters;
mod line;
mod stats;
mod window;

#[cfg(feature = "counters")]
pub use arch::current::ARCH;
#[cfg(feature = "counters")]
pub use counters::{Counters, EVENT_SLOTS, Reading};
pub use line::{
    IDLE_HALTS, LineError, ParseError, Parsed, RESERVED_KEYS, Report, TAG, Unit, Value, parse_line,
};
pub use stats::{Samples, Summary, summarize};
pub use window::{HALTED, MOVED, WINDOW_OPS, WINDOW_OPS_KEY, WindowEnd, WindowShape, WindowTally};
