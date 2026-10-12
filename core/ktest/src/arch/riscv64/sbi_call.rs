// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/riscv64/sbi_call.rs

//! Tier 1 (RISC-V): `SYS_SBI_CALL` forwards to the SBI firmware.

use crate::{TestContext, TestResult};

/// `sbi_call(sbi_control_cap, EID=0x10, FID=0, …)` reads the SBI spec version.
/// Verifies the call path: the kernel forwards to SBI and returns a plausible
/// version (major in `0..=3`).
pub fn get_spec_version(ctx: &TestContext) -> TestResult
{
    // EID_BASE = 0x10, FID_GET_SPEC_VERSION = 0 per the SBI base extension.
    let version = syscall::sbi_call(ctx.sbi_control_cap, 0x10, 0, 0, 0, 0)
        .map_err(|_| "hw::sbi_call_get_spec_version: sbi_call returned error")?;
    let major = version >> 24;
    if major > 3
    {
        return Err("hw::sbi_call_get_spec_version: implausible SBI major version");
    }
    Ok(())
}
