// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/cmdline.rs

//! Compile-time ktest configuration.
//!
//! The boot protocol carries no kernel command line, so every ktest run
//! uses the same [`KtestConfig::DEFAULT`] baked in at build time. The
//! defaults are picked for CI: every tier runs, the VM auto-shuts down
//! on completion, and shutdown is immediate. To preserve QEMU for
//! interactive inspection (or trim the tier set for a focused run),
//! edit [`KtestConfig::DEFAULT`] and `cargo xtask build -p ktest`.

/// When to perform system shutdown after tests complete. `Pass` and
/// `Never` are not used by [`KtestConfig::DEFAULT`] but are the
/// configurable surface — flipping `DEFAULT.shutdown_policy` to either
/// value (and rebuilding ktest) is the supported operator escape hatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ShutdownPolicy
{
    /// Shut down regardless of test outcome.
    Always,
    /// Shut down only if all tests passed.
    Pass,
    /// Never shut down (halt in place).
    Never,
}

/// ktest configuration. Baked in at compile time.
#[allow(clippy::struct_excessive_bools)]
pub struct KtestConfig
{
    pub shutdown_policy: ShutdownPolicy,
    pub timeout_secs: u32,
    pub run_unit: bool,
    pub run_integration: bool,
    pub run_stress: bool,
    pub run_bench: bool,
    pub bench_iters: u32,
}

impl KtestConfig
{
    /// Compile-time configuration baked into every ktest build.
    /// CI-friendly: full coverage, exit immediately on completion.
    pub const DEFAULT: KtestConfig = KtestConfig {
        shutdown_policy: ShutdownPolicy::Always,
        timeout_secs: 0,
        run_unit: true,
        run_integration: true,
        run_stress: true,
        run_bench: true,
        bench_iters: 1000,
    };
}
