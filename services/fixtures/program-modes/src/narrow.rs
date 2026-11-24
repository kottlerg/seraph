// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fixtures/program-modes/src/narrow.rs

//! The `narrow` mode: a check of the creator policy of this binary's own
//! signing role. As a program, which may start programs only
//! (docs/signing.md § Signature Policy in procmgr), its start of a service
//! image must be refused `PermissionDenied`. It prints a line and returns
//! when it is, and exits non-zero, after a line naming what happened, when it
//! is not.
//!
//! Driven by `services/svctest`'s `procmgr_program_narrowing` phase.

use std::process::Command;

/// A service image a program may not start: svctest's shared service
/// fixture, which, started with no mode, logs that and exits.
const SERVICE_IMAGE: &str = "/tests/fixtures/service-modes";

/// Exit code: the start of [`SERVICE_IMAGE`] failed, but not as refused.
const EXIT_OTHER_ERROR: i32 = 3;

/// Exit code: the start of [`SERVICE_IMAGE`] succeeded.
const EXIT_STARTED: i32 = 4;

/// Try to start [`SERVICE_IMAGE`] and exit by the outcome.
pub fn main()
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
