// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/bench/src/arch/x86_64/mod.rs

//! x86-64 counter reads.

/// The architecture's name in the result line's `arch=` column.
pub const ARCH: &str = "x86_64";

/// Read the timestamp counter with `rdtsc`, between two `lfence`s.
///
/// Ring 3 may execute `rdtsc` while `CR4.TSD` is clear, which the Seraph
/// kernel keeps on every CPU and a hosted OS keeps for its processes. The
/// counter ticks at a constant rate on a CPU with an invariant TSC, so a
/// delta is reference cycles, not core cycles.
///
/// The read bounds the code around it on both levels. The compiler sees it
/// read and write memory, so it keeps every load and store on the side of
/// the read the program puts it. The `lfence` before `rdtsc` holds the
/// read until every earlier instruction has completed, and the one after
/// holds every later instruction until the read has, as the Intel SDM's
/// `RDTSC` entry gives, and AMD's processors on which `lfence` is
/// dispatch-serializing.
#[expect(
    clippy::inline_always,
    reason = "the counter read must be inlined to keep call overhead out of the measured region"
)]
#[inline(always)]
pub fn cycles() -> u64
{
    let lo: u32;
    let hi: u32;
    // SAFETY: `lfence` and `rdtsc` are user-mode instructions, the latter
    // while `CR4.TSD` is clear (above); they write only EAX and EDX, and
    // access no memory. preserves_flags: neither modifies RFLAGS. The block
    // omits `nomem` on purpose: the compiler then keeps memory accesses on
    // their side of the read (above).
    unsafe {
        core::arch::asm!(
            "lfence",
            "rdtsc",
            "lfence",
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags),
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
