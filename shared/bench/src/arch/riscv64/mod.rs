// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/bench/src/arch/riscv64/mod.rs

//! RISC-V counter reads.

/// The architecture's name in the result line's `arch=` column.
pub const ARCH: &str = "riscv64";

/// Read the hart's `cycle` counter with `csrr cycle`.
///
/// U-mode may read `cycle` while `scounteren.CY` is set, which the Seraph
/// kernel sets on every hart. No two harts' counters are kept in step, so
/// only two reads on one hart compare.
///
/// The compiler sees the read read and write memory, so it keeps every load
/// and store on the side of the read the program puts it. The read returns
/// the hart's cycle count where the hart executes it, and two reads on one
/// hart are ordered with each other. No other order holds: RISC-V defines no
/// fence that orders a counter read with the execution of the instructions
/// around it, so an out-of-order hart may read `cycle` before earlier
/// instructions complete or after later ones begin.
#[expect(
    clippy::inline_always,
    reason = "the counter read must be inlined to keep call overhead out of the measured region"
)]
#[inline(always)]
pub fn cycles() -> u64
{
    let c: u64;
    // SAFETY: `cycle` is readable from U-mode while `scounteren.CY` is set
    // (above); the read writes only the output register and accesses no
    // memory. The block omits `nomem` on purpose: the compiler then keeps
    // memory accesses on their side of the read (above).
    unsafe {
        core::arch::asm!(
            "csrr {}, cycle",
            out(reg) c,
            options(nostack),
        );
    }
    c
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
