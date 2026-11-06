// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/mm/icache.rs

//! Instruction-fetch coherence for user code written through a data path.
//!
//! A frame's bytes reach it through stores: a loader's writable mapping, the
//! kernel's relocation of init's image, or `SYS_THREAD_WRITE_MEM`'s write
//! through the direct map. On RISC-V instruction fetch is not coherent with
//! those stores, so [`sync_user_code`] runs before code so written can run:
//! where each executable mapping is established (`SYS_MEM_MAP`,
//! `SYS_MEM_PROTECT`, init's segments in Phase 9) and after each write of an
//! executable page. The rule is in docs/memory-model.md § Instruction-Fetch
//! Coherence; the placements and why they suffice are in
//! core/kernel/docs/memory-internals.md § Instruction-Fetch Synchronisation.

use core::sync::atomic::{AtomicU64, Ordering};

/// Every [`sync_user_code`] since boot, which
/// `SYS_SYSTEM_INFO(InstructionCacheSyncs)` reports so a test can check that
/// a path synchronised: under emulation a missing sync does not fail.
static SYNCS: AtomicU64 = AtomicU64::new(0);

/// Make instruction fetch on every CPU see every store made before the call
/// (`arch::current::cpu::sync_instruction_fetch`), and count it.
///
/// Called in syscall or boot context with no lock held: on RISC-V the remote
/// half is a blocking firmware call that waits for every hart.
#[cfg(not(test))]
pub fn sync_user_code()
{
    SYNCS.fetch_add(1, Ordering::Relaxed);
    crate::arch::current::cpu::sync_instruction_fetch();
}

/// The number of [`sync_user_code`] calls since boot.
pub fn sync_count() -> u64
{
    SYNCS.load(Ordering::Relaxed)
}
