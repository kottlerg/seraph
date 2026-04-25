// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/build.rs

// Cargo build script: selects the kernel linker script for the active target.

fn main()
{
    // SAFETY: Cargo guarantees these environment variables exist during build
    #[allow(clippy::unwrap_used)]
    let target = std::env::var("TARGET").unwrap();
    #[allow(clippy::unwrap_used)]
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    // Only apply the kernel linker script for bare-metal targets. The host
    // target (e.g. x86_64-unknown-linux-gnu) is used during `cargo test` and
    // must not be linked with the kernel linker script.
    //
    // Our bare-metal triples end in "-none": x86_64-seraph-none,
    // riscv64gc-seraph-none. The host triple does not.
    if !target.ends_with("-none") && !target.contains("-none-")
    {
        return;
    }

    let linker_script = if target.starts_with("x86_64")
    {
        format!("{manifest_dir}/linker/x86_64.ld")
    }
    else if target.starts_with("riscv64")
    {
        format!("{manifest_dir}/linker/riscv64.ld")
    }
    else
    {
        // Unknown bare-metal target — no linker script; let the linker default.
        return;
    };

    println!("cargo:rustc-link-arg=-T{linker_script}");
    println!("cargo:rerun-if-changed={linker_script}");
    println!("cargo:rerun-if-changed=build.rs");
}
