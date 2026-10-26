// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/build.rs

//! Cargo build script: passes the RISC-V UEFI linker script to the linker.

fn main()
{
    // Cargo sets both variables for every build script it runs; their
    // absence is a cargo defect with no recoverable state.
    #[allow(clippy::unwrap_used)]
    let target = std::env::var("TARGET").unwrap();
    #[allow(clippy::unwrap_used)]
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rerun-if-changed=build.rs");

    // Only the RISC-V PE/COFF pipeline links against a script. The x86-64
    // bootloader uses the built-in `x86_64-unknown-uefi` target, and the host
    // target (`cargo test`, clippy) must not be linked with it.
    if target != "riscv64imac-seraph-uefi"
    {
        return;
    }

    // A build-script link arg reaches the linker once, by an absolute path
    // that holds from any working directory; a `.cargo/config.toml` entry is
    // joined with every parent directory's config (a checkout nested under
    // another), which would hand the linker the script twice.
    let linker_script = format!("{manifest_dir}/linker/riscv64-uefi.ld");
    println!("cargo:rustc-link-arg=-T{linker_script}");
    println!("cargo:rerun-if-changed={linker_script}");
}
