// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/sbi_gating.rs

//! Integration: `SYS_SBI_CALL` extension gating (RISC-V).
//!
//! Verifies the two layers of the `SbiControl` gate defined in
//! [capability-model.md](../../../../docs/capability-model.md) § `SbiControl` (RISC-V only),
//! without triggering an actual firmware action (SRST would reset the machine):
//!
//! 1. **Kernel floor** — TIME and HSM are rejected even when the cap holds
//!    every sanctioned right.
//! 2. **Per-extension rights** — SRST through a cap derived without `SBI_RESET`
//!    is rejected, so no reset occurs.
//!
//! The positive SRST path (cap holds `SBI_RESET`) is exercised by the harness's
//! own `sbi_shutdown` at end of run.

use crate::{TestContext, TestResult};

/// SBI Timer extension ID (kernel-reserved: scheduler timer).
#[cfg(target_arch = "riscv64")]
const SBI_EXT_TIME: u64 = 0x5449_4D45;

/// SBI Hart State Management extension ID (kernel-reserved: hart lifecycle).
#[cfg(target_arch = "riscv64")]
const SBI_EXT_HSM: u64 = 0x0048_534D;

/// SBI System Reset extension ID (sanctioned, requires `SBI_RESET`).
#[cfg(target_arch = "riscv64")]
const SBI_EXT_SRST: u64 = 0x5352_5354;

#[cfg(target_arch = "riscv64")]
pub fn run(ctx: &TestContext) -> TestResult
{
    use syscall::{cap_delete, cap_derive, sbi_call};
    use syscall_abi::SyscallError;

    crate::log("sbi_gating: starting");

    if ctx.sbi_control_cap == 0
    {
        return Err("sbi_gating: missing SbiControl cap");
    }

    // ── Kernel floor: reserved extension never forwardable ───────────────────
    if sbi_call(ctx.sbi_control_cap, SBI_EXT_TIME, 0, 0, 0, 0)
        != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("sbi_gating: TIME (reserved) should be rejected with InvalidArgument");
    }

    // ── Kernel floor: a second reserved extension, same rejection ────────────
    if sbi_call(ctx.sbi_control_cap, SBI_EXT_HSM, 0, 0, 0, 0)
        != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("sbi_gating: HSM (reserved) should be rejected with InvalidArgument");
    }

    // ── Per-extension rights: SRST without SBI_RESET is denied, no reset ──────
    let no_rights =
        cap_derive(ctx.sbi_control_cap, 0).map_err(|_| "sbi_gating: cap_derive(0) failed")?;
    let denied = sbi_call(no_rights, SBI_EXT_SRST, 0, 0, 0, 0);
    let _ = cap_delete(no_rights);
    if denied != Err(SyscallError::InsufficientRights as i64)
    {
        return Err("sbi_gating: SRST without SBI_RESET should fail with InsufficientRights");
    }

    Ok(())
}

/// SBI does not exist on this architecture; nothing to gate. Signature matches
/// the RISC-V arm so `run_integration_test!` registers uniformly.
#[cfg(not(target_arch = "riscv64"))]
// unnecessary_wraps: the signature matches the riscv64 `run` so
// `run_integration_test!` registers both arms uniformly.
#[allow(clippy::unnecessary_wraps)]
pub fn run(_ctx: &TestContext) -> TestResult
{
    Ok(())
}
