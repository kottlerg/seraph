// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fixtures/spawn-target/src/main.rs

//! svctest's known-good spawn target: the image its procmgr, memmgr,
//! budget, process-tree, pipe and namespace phases create, spawn, read and
//! look up (services/fixtures/spawn-target/README.md).
//!
//! With no argument, or any argument but `narrow`, it prints
//! [`LINE`] to its stdout and exits 0. With `narrow`, it checks the
//! creator policy of its own signing role: as a program, which may start
//! programs only (docs/signing.md § Signature Policy in procmgr), its start
//! of a service image must be refused `PermissionDenied`. It exits 0 when
//! it is, and non-zero, after a line naming what happened, when it is not.

use std::process::Command;

/// The line the default mode prints.
const LINE: &str = "spawn-target ran";

/// A service image a program may not start: the restart-path fixture,
/// which only crashes if it does start.
const SERVICE_IMAGE: &str = "/tests/fixtures/crasher";

/// Exit code: the start of [`SERVICE_IMAGE`] failed, but not as refused.
const EXIT_OTHER_ERROR: i32 = 3;

/// Exit code: the start of [`SERVICE_IMAGE`] succeeded.
const EXIT_STARTED: i32 = 4;

fn main()
{
    if std::env::args().nth(1).as_deref() == Some("narrow")
    {
        narrow();
    }
    println!("{LINE}");
}

/// Try to start [`SERVICE_IMAGE`] and exit by the outcome.
fn narrow()
{
    match Command::new(SERVICE_IMAGE).spawn()
    {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            println!("refused: {e}");
        }
        Err(e) =>
        {
            println!("starting {SERVICE_IMAGE}: {e}, not PermissionDenied");
            std::process::exit(EXIT_OTHER_ERROR);
        }
        Ok(mut started) =>
        {
            let _ = started.kill();
            println!("started the service {SERVICE_IMAGE}");
            std::process::exit(EXIT_STARTED);
        }
    }
}
