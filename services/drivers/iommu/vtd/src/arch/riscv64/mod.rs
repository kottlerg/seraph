// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/vtd/src/arch/riscv64/mod.rs

//! The riscv64 side of the VT-d driver's arch-dispatch surface. VT-d units
//! exist only on x86-64 platforms and xtask builds the driver for x86-64
//! alone, so on riscv64 the surface is defined for completeness and does
//! nothing.

/// No-op on riscv64: no VT-d unit exists on a RISC-V platform, so no table
/// write is ever read by one and nothing needs flushing.
///
/// # Safety
/// None beyond the x86-64 contract it mirrors: `va..va + len` must be
/// mapped in the calling process.
pub unsafe fn flush(va: u64, len: u64)
{
    let _ = (va, len);
}
