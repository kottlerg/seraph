// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/mod.rs

//! Re-exports all subcommand modules.

pub mod build;
pub mod capture_acpi;
pub mod clean;
pub mod compare_images;
pub mod crypto_vectors;
pub mod hook;
pub mod host;
pub mod issue;
pub mod ktest_timing;
pub mod lint_docs;
pub mod mkdisk;
pub mod orch;
pub mod pr_check;
pub mod release_scope;
pub mod review;
pub mod run;
pub mod symbolize;
pub mod test;
pub mod test_cet;
pub mod test_core_death;
pub mod test_crash_report;
pub mod test_debug_port;
pub mod test_gdb;
pub mod test_hotplug;
pub mod test_kaslr;
pub mod test_log_level;
pub mod test_map_redo;
pub mod test_powerbutton;
pub mod test_reboot;
pub mod test_signing;
pub mod test_terminal;
pub mod test_tpm;
pub mod test_vmgenid;
pub mod test_wedge;
