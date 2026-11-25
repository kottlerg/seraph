// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/targets/src/bin/virtio-core.rs

//! The fuzz target of the `VirtIO` decoders of device-written memory
//! (`services/drivers/virtio/core`): its property `virtio_core_holds` over
//! inputs read as the script of a split virtqueue's life and as the operands
//! of a configuration read.

#[cfg(fuzzing)]
fn main()
{
    fuzz_engine::main(&fuzz_engine::Target {
        name: "virtio-core",
        inputs: Some("services/drivers/virtio/core/fuzz/virtio-core"),
        // A script of this many bytes holds a hundred and more operations,
        // enough to fill a queue of a few descriptors, complete it, and wrap
        // a ring index from a start near the wrap (the start is the script's
        // own); the configuration reads take the first 118.
        max_len: 1024,
        property: virtio_core::property::virtio_core_holds,
    })
}

#[cfg(not(fuzzing))]
fn main()
{
    eprintln!("a fuzz target runs only as `cargo xtask fuzz` builds it");
    std::process::exit(2);
}
