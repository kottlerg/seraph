// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/cmdline.rs

//! Compile-time ktest configuration.
//!
//! The boot protocol carries no kernel command line, so every ktest run
//! uses the configuration baked in at build time, [`KtestConfig::BUILT`]:
//! [`KtestConfig::DEFAULT`]; [`KtestConfig::BENCH`] in a build with the
//! `bench-only` feature (`cargo xtask build --ktest-bench-only`); or
//! [`KtestConfig::SELECTED`] in a build whose environment sets
//! `SERAPH_KTEST_ONLY` (`cargo xtask build --ktest-only`). The
//! defaults are picked for CI: every tier runs, the VM auto-shuts down
//! on completion, and shutdown is immediate. To preserve QEMU for
//! interactive inspection (or trim the tier set),
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
    /// The comma-separated name prefixes of the tests a focused build runs,
    /// `None` in a build that runs every test of its tiers
    /// ([`KtestConfig::selects`]).
    pub selection: Option<&'static str>,
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
        selection: None,
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

    /// A focused build's configuration: [`KtestConfig::DEFAULT`] running only
    /// the tests whose names start with one of the comma-separated prefixes of
    /// the build environment's `SERAPH_KTEST_ONLY`, and no benchmark, since a
    /// benchmark is not a named test; `None` in a build whose environment does
    /// not set the variable. `cargo xtask build` sets it from `--ktest-only`
    /// and clears it otherwise, and rustc records the read, so cargo rebuilds
    /// ktest when the value changes.
    pub const SELECTED: Option<KtestConfig> = match option_env!("SERAPH_KTEST_ONLY")
    {
        Some(selection) => Some(KtestConfig {
            run_bench: false,
            selection: Some(selection),
            ..Self::DEFAULT
        }),
        None => None,
    };

    /// The configuration this build runs: [`KtestConfig::BENCH`] with the
    /// `bench-only` feature, else [`KtestConfig::SELECTED`] in a focused
    /// build, else [`KtestConfig::DEFAULT`].
    pub const BUILT: KtestConfig = if cfg!(feature = "bench-only")
    {
        Self::BENCH
    }
    else
    {
        match Self::SELECTED
        {
            Some(selected) => selected,
            None => Self::DEFAULT,
        }
    };

    /// Whether the test named `name` runs: every test without a selection,
    /// and with one, a test whose name starts with one of its prefixes.
    #[must_use]
    pub fn selects(&self, name: &str) -> bool
    {
        self.selection
            .is_none_or(|selection| selection.split(',').any(|prefix| name.starts_with(prefix)))
    }
}
