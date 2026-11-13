// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/hello/tester/src/main.rs

//! Per-program tester for `/programs/hello`. Spawns it with a piped stdout,
//! asserts the expected line appears, and asserts a clean exit. See
//! [docs/testing.md](../../../docs/testing.md) for the protocol.

#![expect(
    clippy::expect_used,
    reason = "a per-program tester is test code, where unwrap and expect are permitted \
              (docs/coding-standards.md § Error Handling): a failed spawn, read, or wait must \
              abort the tester, and the panic's non-zero exit is its FAIL verdict"
)]
#![warn(clippy::allow_attributes, clippy::allow_attributes_without_reason)]
#![warn(clippy::multiple_unsafe_ops_per_block)]
#![warn(
    clippy::fn_params_excessive_bools,
    clippy::large_stack_frames,
    clippy::significant_drop_tightening,
    clippy::volatile_composites,
    clippy::wildcard_enum_match_arm
)]
#![cfg_attr(
    not(test),
    warn(
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::string_slice,
        clippy::unreachable,
        clippy::unwrap_in_result
    )
)]

use std::io::Read;
use std::process::{Command, Stdio};

const EXPECTED_LINE: &str = "hello from seraph userspace";

fn main()
{
    let mut child = Command::new("/programs/hello")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn /programs/hello");

    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut bytes = Vec::new();
    stdout
        .read_to_end(&mut bytes)
        .expect("read /programs/hello stdout");

    let status = child.wait().expect("wait /programs/hello");
    let out = String::from_utf8_lossy(&bytes);

    let line_present = out.lines().any(|l| l.contains(EXPECTED_LINE));
    if !line_present
    {
        println!("[hello-tester] FAIL expected line missing: {EXPECTED_LINE:?}");
        println!("[hello-tester] captured stdout: {out:?}");
        std::process::exit(1);
    }
    if !status.success()
    {
        println!("[hello-tester] FAIL non-zero exit: {:?}", status.code());
        std::process::exit(2);
    }

    println!("[hello-tester] PASS");
}
