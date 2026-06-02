// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Stress: FPU + scheduler-migration churn.
//!
//! Runs the cross-CPU FPU preservation pattern (`unit::fpu::
//! preempt_isolation_cross_cpu`) in a tight loop. Each iteration:
//!
//! 1. Mints a fresh thread, pins to CPU 0.
//! 2. Child loads `PATTERN_A` into the entire extended-state register file
//!    (`xmm0..xmm15` on `x86_64`; `f0..f31` on `riscv64`).
//! 3. Child becomes `fpu_owner` of CPU 0, blocks on a notification.
//! 4. Parent flips affinity to CPU 1 and wakes the child.
//! 5. Child resumes (potentially on CPU 1), captures register file,
//!    asserts no mismatch.
//!
//! The single-cycle version of this test (in `unit/fpu.rs`) catches the
//! commit-`bd22687` regression on cold caches; this stress version
//! exercises ~100 cycles to widen the race window for any residual
//! eager-save / lazy-restore inconsistency under load.
//!
//! Skipped when `cpu_count < 2` (UP boot has nothing to migrate across).

use syscall_abi::SystemInfoType;

use crate::{TestContext, TestResult};

const CYCLES: u32 = 100;

pub fn run(ctx: &TestContext) -> TestResult
{
    let cpus = syscall::system_info(SystemInfoType::CpuCount as u64)
        .map_err(|_| "stress::fpu_migration_churn: system_info(CpuCount) failed")?;
    if cpus < 2
    {
        crate::log("ktest: stress::fpu_migration_churn SKIP (requires SMP)");
        return Ok(());
    }

    for i in 0..CYCLES
    {
        crate::unit::fpu::preempt_isolation_cross_cpu(ctx).map_err(|_| {
            // Log which iteration failed so failures are bisectable on the
            // boot log.
            crate::log_u64(
                "stress::fpu_migration_churn: failure at iter=",
                u64::from(i),
            );
            "stress::fpu_migration_churn: preempt_isolation_cross_cpu failed in churn"
        })?;
    }
    Ok(())
}
