// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/vtd/src/arch/x86_64/mod.rs

//! x86-64 cache flushing for a remapping unit whose page walks do not snoop
//! the processor caches (`ECAP.C` clear).

/// Bytes one `CLFLUSH` writes back: the cache-line size every x86-64
/// processor reports for it (`CPUID.01H:EBX[15:8]` = 8, in 8-byte units).
const LINE: u64 = 64;

/// Write back and invalidate every cache line of `len` bytes from `va`, then
/// fence, so the unit's next read of them from memory sees every store made
/// before the call.
///
/// # Safety
/// `va..va + len` must be mapped in the calling process.
pub unsafe fn flush(va: u64, len: u64)
{
    // A mapped range ends below `u64::MAX`, so neither sum saturates.
    let end = va.saturating_add(len);
    let mut line = va & !(LINE - 1);
    while line < end
    {
        // SAFETY: the caller guarantees the range is mapped, and `line` lies
        // in it or in the line that holds its first byte, which is mapped
        // with it; `CLFLUSH` reads and writes no Rust object.
        unsafe { core::arch::x86_64::_mm_clflush(line as *const u8) };
        line = line.saturating_add(LINE);
    }
    // SAFETY: `MFENCE` has no operands and orders the flushes above before
    // every later load and store, the register writes that start the
    // invalidation included.
    unsafe { core::arch::x86_64::_mm_mfence() };
}
