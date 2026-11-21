// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/shutdown/mod.rs

//! Shutdown case: the machine shuts down for each cause, one boot each, and
//! each boot passes on one assertion: QMP's `SHUTDOWN` event gives the
//! cause's reason, and QEMU exits on its own (it runs with `-no-reboot`, so a
//! reset ends it too).
//!
//! - `reboot` ([`reboot`]): the `reboot` fixture's `REBOOT` resets the
//!   machine, reason `guest-reset`.
//! - `power-button` ([`power_button`], `x86_64` only): a press of the ACPI
//!   power button over QMP powers it off, reason `guest-shutdown`.
//! - `memmgr`, `procmgr`, `procmgr-reaper`, `svcmgr`, `devmgr`, `vfsd`,
//!   `logd` ([`core_death`]): the death of that core or critical service,
//!   made from outside the guest, powers it off, reason `guest-shutdown`.
//!
//! The causes run in that order, each whatever another's outcome, and the
//! case fails naming the causes that failed. A pure runner: requires a
//! populated sysroot with the default boot set (terminal and shell) packed.

mod core_death;
mod power_button;
mod reboot;

use crate::error::{Result, bail};

use crate::argparse::ValueEnum as _;
use crate::cli::ShutdownCause;
use crate::commands::test::cases::CaseArgs;
use crate::context::Context;
use crate::qemu::validate_sysroot_for_launch;
use crate::util::step;

use core_death::Target;

pub fn run(ctx: &Context, args: &CaseArgs) -> Result<()>
{
    validate_sysroot_for_launch(ctx, args.arch)?;
    // Held until the case returns, after its last QEMU has exited: one boot
    // at a time.
    let _host = crate::host_lock::admit_boot(ctx, &args.host, args.cpus, 1)?;
    let mut failed = Vec::new();
    for &cause in &args.causes
    {
        step(&format!("shutdown case: {}", cause.name()));
        let result = match cause
        {
            ShutdownCause::Reboot => reboot::run(ctx, args),
            ShutdownCause::PowerButton => power_button::run(ctx, args),
            ShutdownCause::Memmgr => core_death::run(ctx, args, Target::Memmgr),
            ShutdownCause::Procmgr => core_death::run(ctx, args, Target::Procmgr),
            ShutdownCause::ProcmgrReaper => core_death::run(ctx, args, Target::ProcmgrReaper),
            ShutdownCause::Svcmgr => core_death::run(ctx, args, Target::Svcmgr),
            ShutdownCause::Devmgr => core_death::run(ctx, args, Target::Devmgr),
            ShutdownCause::Vfsd => core_death::run(ctx, args, Target::Vfsd),
            ShutdownCause::Logd => core_death::run(ctx, args, Target::Logd),
        };
        match result
        {
            Ok(()) => step(&format!("shutdown case: {}: PASS", cause.name())),
            Err(e) =>
            {
                eprintln!("shutdown case: {}: FAIL: {e:#}", cause.name());
                failed.push(cause.name());
            }
        }
    }
    if !failed.is_empty()
    {
        bail!("shutdown case: FAIL for {}", failed.join(", "));
    }
    let passed: Vec<String> = args.causes.iter().map(|cause| cause.name()).collect();
    step(&format!(
        "shutdown case: PASS ({}: each shut the machine down as it should)",
        passed.join(", ")
    ));
    Ok(())
}
