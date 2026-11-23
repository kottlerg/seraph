// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/engine/src/lib.rs

//! Seraph's in-tree coverage-guided fuzzing engine.
//!
//! A fuzz target is a host binary of `xtask/fuzz/targets` whose `main` hands a
//! [`Target`] to [`main`]. `cargo xtask fuzz` builds the targets with
//! `SanitizerCoverage` on every crate but this one: inline 8-bit edge
//! counters, their PC table, and compare tracing. This crate defines the
//! callbacks that instrumentation calls ([`cov`], [`cmp`]), and, since it is
//! not instrumented itself, they cannot recurse.
//!
//! A run is AFL-style: a queue of inputs that reached new coverage (edge
//! counters in hit-count buckets, [`corpus`]), each mutated by havoc and
//! splice with a dictionary of the constants the target compares against and
//! input-to-state replacement ([`mutate`]), every choice drawn from one
//! seeded generator ([`rng`]), so a run of a fixed execution count from a
//! fixed seed is reproducible. The property runs under a panic catch whose
//! location is the crash's deduplication key ([`exec`]); a supervising parent
//! process catches the endings no catch can (a signal, an `AddressSanitizer`
//! error, the allocation cap of [`cap`], the per-input time limit,
//! [`supervise`]). A crash is minimized ([`minimize`]) and written with its
//! report ([`report`]), and the run exits non-zero.
//!
//! xtask/README.md § `cargo xtask fuzz` gives the command and the files;
//! docs/testing.md § Fuzzing the tier and its rules.

pub mod args;
pub mod cap;
pub mod cmp;
pub mod corpus;
pub mod cov;
pub mod exec;
pub mod fuzz;
pub mod minimize;
pub mod mutate;
pub mod report;
pub mod rng;
pub mod supervise;

pub use cap::CappedAlloc;

/// The exit status of a run that found a failing input and reported it.
pub const EXIT_FAILED: i32 = 1;

/// The exit status of a run that could not be made: a bad command line, an
/// uninstrumented build, a directory it could not write.
pub const EXIT_ERROR: i32 = 2;

/// The exit status of a child process that reported its crash itself.
pub const EXIT_REPORTED: i32 = 70;

/// The heap of a fuzz target: the system allocator held to the allocation
/// cap. Only an instrumented build, which only `cargo xtask fuzz` makes, sets
/// `fuzzing`, so no other binary that links this crate is capped.
#[cfg(fuzzing)]
#[global_allocator]
static ALLOCATOR: CappedAlloc = CappedAlloc::new(cap::DEFAULT_CAP);

/// A fuzz target.
pub struct Target
{
    /// The target's name: its binary's, and its working directory's under
    /// `target/xtask/fuzz/`.
    pub name: &'static str,
    /// The directory, relative to the project root, of its checked-in inputs
    /// (`seeds/` and `regressions/`): `<crate>/fuzz/<target>`. `None` for a
    /// planted target of the self-test, which starts from the empty input.
    pub inputs: Option<&'static str>,
    /// The longest input the mutator makes.
    pub max_len: usize,
    /// The property: a function that panics when the input breaks the
    /// contract of the code under test.
    pub property: fn(&[u8]),
}

/// Run `target` as the command line asks (`args`) and exit: 0 when the
/// property held for every input, [`EXIT_FAILED`] when an input failed and
/// was reported, [`EXIT_ERROR`] when the run could not be made.
pub fn main(target: &Target) -> !
{
    let status = match args::parse(std::env::args_os().skip(1))
    {
        Ok(options) => run(target, &options),
        Err(message) =>
        {
            eprintln!("fuzz: {}: {message}", target.name);
            EXIT_ERROR
        }
    };
    std::process::exit(status)
}

/// Run `target` as `options` ask and return the exit status.
fn run(target: &Target, options: &args::Options) -> i32
{
    match &options.mode
    {
        args::Mode::Replay(file) => fuzz::replay(target, file),
        args::Mode::Minimize => fuzz::minimize_corpus(target, options),
        args::Mode::Fuzz(budget) =>
        {
            if std::env::var_os(supervise::ROLE).is_some()
            {
                fuzz::fuzz(target, options, *budget)
            }
            else
            {
                supervise::supervise(target, options)
            }
        }
    }
}
