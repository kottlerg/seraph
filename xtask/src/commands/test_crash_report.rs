// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test_crash_report.rs

//! Crash-report test: the crash service's report blocks in a boot's saved
//! serial log, checked by [`crate::crash_check`], the check
//! `cargo xtask run --crash-reports` makes on each passing run's log.

use crate::error::{Context as _, Result};

use crate::cli::TestCrashReportArgs;
use crate::crash_check::{Verdict, check_log};
use crate::util::step;

pub fn run(args: &TestCrashReportArgs) -> Result<()>
{
    step(&format!(
        "crash report test: reading {}",
        args.log.display()
    ));
    let bytes =
        std::fs::read(&args.log).with_context(|| format!("reading {}", args.log.display()))?;
    match check_log(&String::from_utf8_lossy(&bytes), args.expect)
        .with_context(|| format!("checking {}", args.log.display()))?
    {
        Verdict::Pass(count) => step(&format!(
            "crash report test: PASS ({count} report block(s), every one well-formed)"
        )),
        Verdict::Skipped(outcome) => step(&format!(
            "crash report test: SKIPPED (the boot's run outcome is {outcome}, a \
             host-emulator crash; nothing to check)"
        )),
    }
    Ok(())
}
