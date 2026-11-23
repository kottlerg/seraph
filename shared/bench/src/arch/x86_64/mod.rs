// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/bench/src/arch/x86_64/mod.rs

//! x86-64 counter reads.

/// The architecture's name in the result line's `arch=` column.
pub const ARCH: &str = "x86_64";

/// Read the timestamp counter with `rdtsc`.
///
/// Ring 3 may execute `rdtsc` while `CR4.TSD` is clear, which the Seraph
/// kernel keeps on every CPU and a hosted OS keeps for its processes. The
/// counter ticks at a constant rate on a CPU with an invariant TSC, so a
/// delta is reference cycles, not core cycles.
#[expect(
    clippy::inline_always,
    reason = "the counter read must be inlined to keep call overhead out of the measured region"
)]
#[inline(always)]
pub fn cycles() -> u64
{
    let lo: u32;
    let hi: u32;
    // SAFETY: `rdtsc` is a user-mode instruction while `CR4.TSD` is clear
    // (above), and touches only EAX and EDX. preserves_flags: `rdtsc` does not
    // modify RFLAGS.
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem, preserves_flags),
        );
    }
    (u64::from(hi) << 32) | u64::from(lo)
}

#[cfg(test)]
mod tests
{
    use super::cycles;

    #[test]
    fn cycles_does_not_go_backwards()
    {
        let first = cycles();
        let second = cycles();
        assert!(second >= first);
    }
}
