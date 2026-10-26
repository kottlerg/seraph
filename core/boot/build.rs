// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/build.rs

//! Cargo build script: passes the RISC-V UEFI linker script to the linker.

fn main()
{
    // Cargo sets both for every build script it runs; without them there is
    // nothing to emit, and the riscv64 link then fails on the missing script.
    let (Ok(target), Ok(manifest_dir)) =
        (std::env::var("TARGET"), std::env::var("CARGO_MANIFEST_DIR"))
    else
    {
        return;
    };

    println!("cargo:rerun-if-changed=build.rs");

    // Only the RISC-V PE/COFF pipeline links against a script. The x86-64
    // bootloader uses the built-in `x86_64-unknown-uefi` target, and the host
    // target (`cargo test`, clippy) must not be linked with it. The triple is
    // the one `Arch::boot_target_triple` in xtask names; rename both together.
    if target != "riscv64imac-seraph-uefi"
    {
        return;
    }

    // Emitted here, not in `.cargo/config.toml`; docs/build-system.md
    // § Custom Targets says why.
    let linker_script = format!("{manifest_dir}/linker/riscv64-uefi.ld");
    println!("cargo:rustc-link-arg=-T{linker_script}");
    println!("cargo:rerun-if-changed={linker_script}");
}
