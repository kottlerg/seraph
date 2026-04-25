// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Gregory Kottler <me@gregorykottler.com>

// kernel/src/mm/tlb_shootdown.rs

//! TLB shootdown protocol for cross-CPU page table invalidation.
//!
//! When a CPU modifies page tables (unmap, protect) for an address space
//! active on other CPUs, those CPUs must invalidate their cached TLB entries.
//! This module implements the synchronous shootdown protocol using IPIs.
//!
//! # Protocol
//!
//! 1. The initiating CPU stores the target address space root physical address
//!    in `TLB_SHOOTDOWN.root_phys`.
//! 2. It stores a bitmask of CPUs that must acknowledge in `pending_cpus`.
//! 3. It sends TLB shootdown IPIs to all target CPUs.
//! 4. Each target CPU receives the IPI, flushes its TLB, and clears its bit
//!    in `pending_cpus`.
//! 5. The initiating CPU spins until `pending_cpus` becomes zero.
//!
//! Only one shootdown can be in progress at a time (serialized by
//! `SHOOTDOWN_LOCK`).
//!
//! # Interrupt safety
//!
//! `shootdown()` temporarily enables interrupts during the spin-wait so that
//! target CPUs executing syscalls (with IF=0/SIE=0) can receive the IPI, and
//! so this CPU can service incoming shootdown IPIs from concurrent initiators.
//! Preemption is prevented by the caller via `preempt_disable()`.
//!
//! # Memory ordering
//!
//! - **Release** on `root_phys` and `pending_cpus` stores ensures remote CPUs
//!   see the correct root address before handling the IPI.
//! - **Acquire** on `pending_cpus` loads ensures the initiator sees all bit
//!   clears from remote CPUs.
//! - **Release** on remote CPU bit clears ensures TLB flush completes before
//!   the initiator proceeds.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// TLB shootdown request state.
///
/// The initiating CPU stores the target address space root, the virtual address
/// to invalidate, and the pending CPU mask, then sends IPIs and spins until all
/// acknowledge.
pub struct TlbShootdownRequest
{
    /// Physical address of root page table to flush (0 = flush all address spaces).
    pub root_phys: AtomicU64,

    /// Virtual address to invalidate. `u64::MAX` means full flush.
    pub flush_va: AtomicU64,

    /// Bitmask of CPUs that must acknowledge before initiator proceeds.
    /// Bit N set = CPU N must execute invlpg/sfence.vma and clear its bit.
    pub pending_cpus: AtomicU64,
}

/// Global TLB shootdown request state.
///
/// Only one shootdown can be in progress at a time (serialized by
/// `SHOOTDOWN_LOCK`).
pub static TLB_SHOOTDOWN: TlbShootdownRequest = TlbShootdownRequest {
    root_phys: AtomicU64::new(0),
    flush_va: AtomicU64::new(u64::MAX),
    pending_cpus: AtomicU64::new(0),
};

/// Serialization lock for TLB shootdown initiation.
///
/// Only one CPU may be setting up a shootdown (writing `root_phys`, `pending_cpus`,
/// sending IPIs) at a time. This prevents two concurrent initiators from
/// corrupting each other's global state.
///
/// This lock does NOT disable interrupts. Interrupt management is handled
/// by `shootdown()` itself. The IPI handler never acquires this lock.
static SHOOTDOWN_LOCK: AtomicBool = AtomicBool::new(false);

/// Acquire the shootdown serialization lock.
///
/// Simple CAS spin. Must be called with interrupts enabled (the caller
/// enables them before acquiring) so incoming shootdown IPIs from the
/// current holder can be serviced, preventing mutual deadlock.
#[inline]
fn shootdown_lock()
{
    while SHOOTDOWN_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        while SHOOTDOWN_LOCK.load(Ordering::Relaxed)
        {
            core::hint::spin_loop();
        }
    }
}

/// Release the shootdown serialization lock.
#[inline]
fn shootdown_unlock()
{
    SHOOTDOWN_LOCK.store(false, Ordering::Release);
}

/// Initiate a TLB shootdown for an address space on target CPUs.
///
/// Spins until all target CPUs acknowledge by clearing their bit in `pending_cpus`.
///
/// # Contract
/// - Caller must have called `preempt_disable()` before this function.
/// - `root_phys` must be a valid page table root physical address or 0 for full flush.
/// - `cpu_mask` bits must correspond to online CPUs only.
///
/// # Safety
/// Caller must ensure `root_phys` and `cpu_mask` are valid as described above.
// Used by AddressSpace::map_page, unmap_page, protect_page.
#[allow(dead_code)]
pub unsafe fn shootdown(root_phys: u64, cpu_mask: u64, virt: u64)
{
    if cpu_mask == 0
    {
        return; // No remote CPUs active
    }

    debug_assert!(
        crate::percpu::preemption_disabled(),
        "shootdown: caller must call preempt_disable() first"
    );

    // Enable interrupts for the duration of shootdown. This allows:
    // 1. Target CPUs in syscalls (IF=0/SIE=0) to receive our IPI when they
    //    temporarily enable interrupts in their own shootdown or lock spin.
    // 2. Us to receive incoming shootdown IPIs from another CPU that is
    //    simultaneously initiating a shootdown targeting us (mutual shootdown).
    //
    // Preemption is disabled by the caller, so timer_tick() will not call
    // schedule() even though interrupts are enabled.
    //
    // SAFETY: save_and_disable_interrupts is valid at ring 0 / S-mode.
    let saved_int = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
    // SAFETY: IDT / trap vector is installed; enabling interrupts is safe at
    // ring 0 / S-mode. Preemption is disabled by the caller.
    unsafe { crate::arch::current::interrupts::enable() };

    // Serialize access to the global shootdown state.
    shootdown_lock();

    // SAFETY: Release ordering ensures root_phys, flush_va, and cpu_mask
    // are visible to remote CPUs before the IPI arrives.
    TLB_SHOOTDOWN.root_phys.store(root_phys, Ordering::Release);
    TLB_SHOOTDOWN.flush_va.store(virt, Ordering::Release);
    TLB_SHOOTDOWN
        .pending_cpus
        .store(cpu_mask, Ordering::Release);

    // Fence: ensure pending_cpus is globally visible before sending IPIs.
    // On RISC-V (RVWMO), the Release store orders it after prior stores on
    // this hart, but other harts may not see it until it propagates through
    // the memory system. The SBI ecall that sends the IPI is not a memory
    // fence, so a remote hart's handler could read stale pending_cpus = 0.
    // The SeqCst fence drains the store buffer on real hardware. On x86-64
    // (TSO) this is a no-op.
    core::sync::atomic::fence(Ordering::SeqCst);

    // Helper: send IPIs to all CPUs with bits set in `mask`.
    let cpu_count = crate::sched::CPU_COUNT.load(Ordering::Relaxed);
    let send_ipis = |mask: u64| {
        for cpu in 0..cpu_count
        {
            if (mask & (1u64 << cpu)) != 0
            {
                // Translate logical CPU → hardware ID (APIC ID / hart ID).
                // SAFETY: cpu is in [0, cpu_count), all online CPUs;
                // apic_id_for returns the hardware ID for the logical CPU.
                let hw_id = unsafe { crate::percpu::apic_id_for(cpu as usize) };
                // SAFETY: hw_id is a valid hardware ID for an online CPU.
                unsafe {
                    crate::arch::current::interrupts::send_tlb_shootdown_ipi(hw_id);
                }
            }
        }
    };

    // Initial IPI volley.
    send_ipis(cpu_mask);

    // Spin until all target CPUs acknowledge.
    //
    // Interrupts are enabled (set above), so we can receive and service
    // incoming TLB shootdown IPIs from other CPUs while we wait. The IPI
    // handler acquires no locks — only atomic operations and TLB flush.
    //
    // On QEMU TCG single-thread, this spin can stall if the target hart
    // doesn't get scheduled. The IPI re-send on each iteration ensures
    // that a lost SSIP edge is recovered as soon as QEMU switches to
    // the target hart.
    while TLB_SHOOTDOWN.pending_cpus.load(Ordering::Acquire) != 0
    {
        core::hint::spin_loop();
        // Re-send to any CPUs that haven't acknowledged.
        send_ipis(TLB_SHOOTDOWN.pending_cpus.load(Ordering::Acquire));
    }

    shootdown_unlock();

    // Restore original interrupt state.
    // SAFETY: saved_int is from save_and_disable_interrupts on this CPU.
    unsafe {
        crate::arch::current::cpu::restore_interrupts(saved_int);
    }
}
