// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/mod.rs

//! Re-exports all subcommand modules.

pub mod build;
pub mod clean;
pub mod compose_bundle;
pub mod hook;
pub mod issue;
pub mod ktest_timing;
pub mod lint_docs;
pub mod mkdisk;
pub mod orch;
pub mod pr_check;
pub mod review;
pub mod run;
pub mod run_parallel;
pub mod symbolize;
pub mod test;
pub mod test_crash_report;
pub mod test_debug_port;
pub mod test_gdb;
pub mod test_kaslr;
pub mod test_logd_reclaim;
pub mod test_map_redo;
pub mod test_terminal;
pub mod test_vmgenid;
