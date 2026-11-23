// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/cmdline.rs

//! Compile-time ktest configuration.
//!
//! The boot protocol carries no kernel command line, so every ktest run
//! uses the configuration baked in at build time, [`KtestConfig::BUILT`]:
//! [`KtestConfig::DEFAULT`], or [`KtestConfig::BENCH`] in a build with the
//! `bench-only` feature (`cargo xtask build --ktest-bench-only`). The
//! defaults are picked for CI: every tier runs, the VM auto-shuts down
//! on completion, and shutdown is immediate. To preserve QEMU for
//! interactive inspection (or trim the tier set for a focused run),
//! edit [`KtestConfig::DEFAULT`], run `cargo xtask build --component ktest`,
//! then `cargo xtask mkdisk --harness ktest` so the boot bundle
//! carries the rebuilt binary.

/// When to perform system shutdown after tests complete. `Pass` and
/// `Never` are not used by [`KtestConfig::DEFAULT`] but are the
/// configurable surface — flipping `DEFAULT.shutdown_policy` to either
/// value (then rebuilding ktest and recomposing the ktest bundle) is the
/// supported operator escape hatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    dead_code,
    reason = "`Pass` and `Never` are the operator-configurable surface; `KtestConfig::DEFAULT` \
              constructs only `Always`"
)]
pub enum ShutdownPolicy
{
    /// Shut down regardless of test outcome.
    Always,
    /// Shut down only if all tests passed.
    Pass,
    /// Never shut down; the harness thread exits after printing results.
    Never,
}

/// ktest configuration. Baked in at compile time.
#[expect(
    clippy::struct_excessive_bools,
    reason = "the four `run_*` fields are independent per-tier toggles, not an encoded state"
)]
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
        // A smoke run: each benchmark runs and logs its line, which no
        // functional boot compares; the benchmark image (`BENCH`) measures.
        bench_iters: 8,
    };

    /// The benchmark image's configuration: Tier 3 alone, each benchmark at
    /// the most samples it records (`bench::MAX_ITERS`), for a run whose
    /// result lines are compared (`core/ktest/README.md` § Tier 3).
    pub const BENCH: KtestConfig = KtestConfig {
        run_unit: false,
        run_integration: false,
        run_stress: false,
        bench_iters: crate::bench::MAX_ITERS,
        ..Self::DEFAULT
    };

    /// The configuration this build runs: [`KtestConfig::BENCH`] with the
    /// `bench-only` feature, [`KtestConfig::DEFAULT`] without it.
    pub const BUILT: KtestConfig = if cfg!(feature = "bench-only")
    {
        Self::BENCH
    }
    else
    {
        Self::DEFAULT
    };
}
