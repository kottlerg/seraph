// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/mmio/src/arch/x86_64/mod.rs

//! `x86_64` MMIO ordering barriers.
//!
//! All three primitives are no-ops. `x86_64` TSO orders all stores from one
//! core in program order, and the project's MMIO mappings (`SYS_MMIO_MAP`)
//! are strongly uncacheable (PCD|PWT), which further forces serialised
//! access to device registers. No explicit fence instruction is required at
//! any of the MMIO/DMA transitions this crate covers.

/// TSO + uncacheable MMIO already order prior memory writes before
/// subsequent MMIO writes; no explicit fence required.
#[allow(clippy::inline_always)]
#[inline(always)]
pub fn dma_to_mmio_barrier() {}

/// TSO + uncacheable MMIO already serialise MMIO writes in program order;
/// no explicit fence required.
#[allow(clippy::inline_always)]
#[inline(always)]
pub fn mmio_to_mmio_barrier() {}

/// TSO + uncacheable MMIO already order prior MMIO reads before subsequent
/// memory reads; no explicit fence required.
#[allow(clippy::inline_always)]
#[inline(always)]
pub fn mmio_to_dma_barrier() {}
