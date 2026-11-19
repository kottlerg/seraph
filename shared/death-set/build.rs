// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/death-set/build.rs

//! Cargo build script: declares `target_os = "seraph"` an expected cfg value.
//! The crate's `DeathSet` is compiled only for seraph, and its overflow watch
//! everywhere, so the host builds of its tests, and of the services' tests
//! that drive its model, read that cfg; the host's `rustc` does not know the
//! seraph target's operating system and would otherwise report the cfg as
//! unexpected.

fn main()
{
    println!("cargo::rustc-check-cfg=cfg(target_os, values(\"seraph\"))");
}
