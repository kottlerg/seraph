// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/mmio/src/arch/x86_64/mod.rs

//! `x86_64` MMIO ordering barriers.
//!
//! All three primitives are no-ops. `x86_64` TSO orders all stores from one
//! core in program order, and `SYS_MMIO_MAP` mappings are strong-uncacheable
//! (see `core/kernel/docs/syscalls.md` § `SYS_MMIO_MAP`), which further forces
//! serialised access to device registers. No explicit fence instruction is required at
//! any of the MMIO/DMA transitions this crate covers.

/// No-op on x86-64: TSO + uncacheable MMIO already order prior memory writes
/// before subsequent MMIO writes; no explicit fence required.
// inline_always: a barrier is one fence (or nothing) that must sit inline at the
// access it orders; an out-of-line call would cost more than the fence itself.
#[allow(clippy::inline_always)]
#[inline(always)]
pub fn dma_to_mmio_barrier() {}

/// No-op on x86-64: TSO + uncacheable MMIO already serialise MMIO writes in
/// program order; no explicit fence required.
// inline_always: a barrier is one fence (or nothing) that must sit inline at the
// access it orders; an out-of-line call would cost more than the fence itself.
#[allow(clippy::inline_always)]
#[inline(always)]
pub fn mmio_to_mmio_barrier() {}

/// No-op on x86-64: TSO + uncacheable MMIO already order prior MMIO reads
/// before subsequent memory reads; no explicit fence required.
// inline_always: a barrier is one fence (or nothing) that must sit inline at the
// access it orders; an out-of-line call would cost more than the fence itself.
#[allow(clippy::inline_always)]
#[inline(always)]
pub fn mmio_to_dma_barrier() {}
