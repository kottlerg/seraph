// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/shadow_stack.rs

//! Kernel shadow stacks on riscv64: off. The kernel's Zicfiss support waits
//! for a toolchain that emits the shadow-stack instructions
//! (core/kernel/docs/return-address-integrity.md § Direction), so
//! [`enabled`] is false, no CPU keeps a shadow-stack page ([`CPU_PAGES`] is
//! 0), and a Thread slot carries none (`sched::thread_slot`). The interface
//! is the x86-64 module's, so the architecture-neutral callers
//! (`sched::init_per_cpu_storage`, Phase 5, AP bring-up, Thread creation) are
//! the ones the riscv64 support will use.

/// Pages each CPU keeps for its shadow stacks: none.
pub const CPU_PAGES: usize = 0;

/// The shadow-stack state a thread's `SavedState` would carry; riscv64's
/// `SavedState` carries none, and [`init_stack`] is never reached.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ShadowStack
{
    /// Address the thread's next switch-in restores its shadow stack from.
    pub ssp: u64,
    /// Address of the thread's supervisor token.
    pub token: u64,
}

/// Whether shadow stacks are on: never on riscv64.
pub const fn enabled() -> bool
{
    false
}

/// The idle thread's [`ShadowStack`] in the CPU pages at `base`: none.
pub const fn idle_stack(_base: u64) -> ShadowStack
{
    ShadowStack { ssp: 0, token: 0 }
}

/// Decide whether the kernel runs on shadow stacks: it does not.
///
/// # Safety
/// None needed; the signature matches the x86-64 function's.
pub unsafe fn decide() {}

/// Lay out a CPU's shadow-stack pages: unreached, as [`CPU_PAGES`] is 0.
///
/// # Safety
/// None needed; the signature matches the x86-64 function's.
pub unsafe fn init_cpu_pages(_base: u64, _idle_entry: u64) {}

/// Lay out a thread's shadow stack: unreached, as [`enabled`] is false.
///
/// # Safety
/// None needed; the signature matches the x86-64 function's.
pub unsafe fn init_stack(_page: u64, _entry: u64) -> ShadowStack
{
    ShadowStack::default()
}

/// Point the CPU at a thread's shadow stack: nothing to do.
///
/// # Safety
/// None needed; the signature matches the x86-64 function's.
pub unsafe fn load_thread_token(_token: u64) {}

/// Prepare the boot CPU's shadow stack: nothing to do.
///
/// # Safety
/// None needed; the signature matches the x86-64 function's.
#[cfg(not(test))]
pub unsafe fn prepare_boot_cpu(_allocator: &mut crate::mm::BuddyAllocator, _cpu_pages: u64) {}

/// Prepare an AP's shadow stack: nothing to do.
///
/// # Safety
/// None needed; the signature matches the x86-64 function's.
pub unsafe fn prepare_ap(_cpu_pages: u64) {}

/// Turn shadow stacks on for this CPU: nothing to do.
///
/// # Safety
/// None needed; the signature matches the x86-64 function's.
pub unsafe fn enable() {}
