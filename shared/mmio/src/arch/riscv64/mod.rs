// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/mmio/src/arch/riscv64.rs

//! RISC-V MMIO ordering barriers.
//!
//! All three primitives emit a single `fence` instruction with no operands
//! beyond the predecessor/successor set. Inline assembly uses
//! `options(nostack, preserves_flags)` — the fence touches no registers and
//! has no stack side effects — but intentionally omits `nomem` so the
//! compiler continues to treat the barrier as having memory side effects and
//! does not reorder normal loads/stores across it.

/// RISC-V `fence w,o`: prior main-memory writes ordered before subsequent
/// I/O-region writes.
#[allow(clippy::inline_always)]
#[inline(always)]
pub fn dma_to_mmio_barrier()
{
    // SAFETY: the fence instruction has no operands and no register side
    // effects beyond the ordering it imposes; safe from any privilege level.
    unsafe {
        core::arch::asm!("fence w,o", options(nostack, preserves_flags));
    }
}

/// RISC-V `fence o,o`: prior I/O-region writes ordered before subsequent
/// I/O-region writes.
#[allow(clippy::inline_always)]
#[inline(always)]
pub fn mmio_to_mmio_barrier()
{
    // SAFETY: the fence instruction has no operands and no register side
    // effects beyond the ordering it imposes; safe from any privilege level.
    unsafe {
        core::arch::asm!("fence o,o", options(nostack, preserves_flags));
    }
}

/// RISC-V `fence i,r`: prior I/O-region reads ordered before subsequent
/// main-memory reads.
#[allow(clippy::inline_always)]
#[inline(always)]
pub fn mmio_to_dma_barrier()
{
    // SAFETY: the fence instruction has no operands and no register side
    // effects beyond the ordering it imposes; safe from any privilege level.
    unsafe {
        core::arch::asm!("fence i,r", options(nostack, preserves_flags));
    }
}
