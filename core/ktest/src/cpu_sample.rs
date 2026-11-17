// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/cpu_sample.rs

//! The CPUs a case checks when it repeats one check on CPU after CPU: every
//! CPU up to [`EVERY_CPU_MAX`]; past it, the first [`LOW_CPUS`] (the BSP and
//! the first APs) and [`SAMPLED_CPUS`] spread evenly over the rest, the last
//! CPU among them.
//!
//! The per-CPU state such a case checks is set by one bring-up path on the BSP
//! and another shared by every AP, so a per-CPU miss is a bring-up-path defect
//! the BSP/AP split and the two ends of the index range expose; checking every
//! CPU at the widest boundary runs costs minutes of oversubscribed scheduling
//! for no path the sample misses.

/// Up to this many CPUs, every CPU is checked. Like [`LOW_CPUS`], a test
/// fixture: it bounds only how many CPUs a case visits on a wide boot.
const EVERY_CPU_MAX: u32 = 16;

/// Past [`EVERY_CPU_MAX`], the lowest CPUs checked: CPU 0 (the BSP) and the
/// first APs.
const LOW_CPUS: u32 = 8;

/// Past [`EVERY_CPU_MAX`], the CPUs checked above [`LOW_CPUS`], spread evenly
/// from CPU `LOW_CPUS` to the last CPU.
const SAMPLED_CPUS: u32 = EVERY_CPU_MAX - LOW_CPUS;

/// How many of `cpus` CPUs a case checks: `cpus` itself up to
/// [`EVERY_CPU_MAX`], else `EVERY_CPU_MAX`.
pub fn count(cpus: u32) -> u32
{
    cpus.min(EVERY_CPU_MAX)
}

/// The `k`th CPU checked of `cpus` (`k < count(cpus)`): `k` itself up to
/// [`EVERY_CPU_MAX`] CPUs; past it, CPU `k` for the first [`LOW_CPUS`], then
/// [`SAMPLED_CPUS`] CPUs evenly spaced from `LOW_CPUS` to `cpus - 1`.
///
/// # Errors
///
/// A fixed message when `k` or `cpus` puts the sample out of range.
pub fn checked_cpu(k: u32, cpus: u32) -> Result<u32, &'static str>
{
    if cpus <= EVERY_CPU_MAX || k < LOW_CPUS
    {
        return Ok(k);
    }
    // `cpus - 1 - LOW_CPUS` >= SAMPLED_CPUS - 1 here, so the samples are
    // distinct; the last is `cpus - 1`.
    let j = u64::from(
        k.checked_sub(LOW_CPUS)
            .ok_or("cpu_sample: sampled CPU index out of range")?,
    );
    let span = u64::from(
        cpus.checked_sub(1)
            .and_then(|last| last.checked_sub(LOW_CPUS))
            .ok_or("cpu_sample: CPU span out of range")?,
    );
    let offset = j
        .checked_mul(span)
        .and_then(|spaced| spaced.checked_div(u64::from(SAMPLED_CPUS - 1)))
        .ok_or("cpu_sample: CPU offset overflows")?;
    u32::try_from(offset)
        .ok()
        .and_then(|o| LOW_CPUS.checked_add(o))
        .ok_or("cpu_sample: sampled CPU out of range")
}
