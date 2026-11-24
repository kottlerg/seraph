// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/path-account-plugin/src/lib.rs

//! The recorder of `cargo xtask path-account trace`'s userspace rows: a QEMU
//! TCG plugin that counts every instruction a guest of one vCPU executes, by
//! address, between consecutive user-mode reads of the cycle counter, and
//! records each read's value, without stopping the guest.
//!
//! A stop of the guest (a gdbstub breakpoint or step) under icount moves
//! the virtual clock to the next timer deadline, so a
//! window stepped through the gdbstub does not run the instructions the
//! benchmark measured. A plugin's callbacks run inside the translated code
//! and leave the instruction count untouched.
//!
//! The crate is the plugin, the `cdylib` QEMU loads with `-plugin`
//! ([`qemu`]'s callbacks over [`recorder::Recorder`]), and the record it
//! writes ([`record`]), through which xtask reads it back.

pub mod class;
#[cfg(target_os = "linux")]
mod qemu;
pub mod record;
pub mod recorder;
