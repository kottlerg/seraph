// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Gregory Kottler <me@gregorykottler.com>

// kernel/src/mm/tlb_shootdown.rs

//! TLB shootdown protocol for cross-CPU page table invalidation.
//!
//! When a CPU rewrites a leaf page-table entry in a way that could strand a
//! dangerous stale TLB entry on other CPUs sharing the address space — an
//! unmap, a permission narrowing, or a frame replacement — those CPUs must
//! invalidate their cached translation. Fresh maps and permission widenings
//! issue no shootdown: any stale entry only triggers a spurious fault the
//! page-fault handler resolves by re-walking the live PTE. The caller
//! classifies each rewrite ([`MapOutcome`](crate::mm::paging::MapOutcome)) and
//! enters this module only for the synchronous cases. This module implements
//! that protocol using IPIs.
//!
//! # Protocol
//!
//! Each CPU owns one request slot in `TLB_REQUESTS`, indexed by its logical CPU
//! id. A CPU blocks until its own shootdown completes, so it has at most one
//! outstanding request — the slot is never shared between concurrent shootdowns
//! and needs no lock.
//!
//! 1. The initiating CPU writes the target root, the virtual address, and the
//!    set of CPUs that must acknowledge into *its own* slot.
//! 2. It sends TLB shootdown IPIs to those CPUs.
//! 3. Each target CPU ([`service_shootdowns`]) scans every slot; for any slot
//!    whose `pending_cpus` still contains its bit, it flushes the requested VA
//!    and clears its bit.
//! 4. The initiator spins until its own slot's `pending_cpus` becomes empty.
//!
//! There is no global serialization: initiators on different CPUs touch
//! different slots, so concurrent shootdowns — even on the same address space —
//! proceed in parallel.
//!
//! # The acknowledgement bit is the liveness badge
//!
//! A target acts on a slot only when it observes its own bit set in that slot's
//! `pending_cpus` (Acquire). The owning CPU sets those bits (Release) only after
//! writing `root_phys`/`flush_va`, so a target that sees its bit also sees the
//! matching root and VA. A slot with all bits clear is idle; a stray or re-sent
//! IPI that finds no bit set for the receiver does nothing. Because a slot is a
//! fixed location (not a transient descriptor) and is reused only by its owner
//! after the previous shootdown has fully drained, a late IPI can never observe
//! a torn or stale request.
//!
//! # Interrupt safety
//!
//! `shootdown()` temporarily enables interrupts during the spin-wait so that
//! target CPUs executing syscalls (with IF=0/SIE=0) can receive the IPI, and so
//! this CPU can service incoming shootdown IPIs from another CPU concurrently
//! targeting it (mutual shootdown). Preemption is prevented by the caller via
//! `preempt_disable()`.
//!
//! # Memory ordering
//!
//! - **Release** on the `root_phys`/`flush_va`/`pending_cpus` stores, followed
//!   by a `SeqCst` fence, ensures remote CPUs see the request before the IPI
//!   arrives (the SBI ecall that delivers a RISC-V IPI is not itself a fence).
//! - **Acquire** on a slot's `pending_cpus` (the handler's bit test, the
//!   initiator's emptiness poll) pairs with that Release, so a CPU that sees its
//!   bit also sees the matching root and VA.
//! - **Release** on a remote CPU's bit clear ensures its TLB flush completes
//!   before the initiator observes the acknowledgement.

use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};

use crate::cpu_mask::{AtomicCpuMask, CpuMask};
use crate::sched::MAX_CPUS;

/// Per-CPU TLB shootdown request slot.
///
/// Written only by its owning CPU (the initiator); other CPUs only clear their
/// own acknowledgement bit in `pending_cpus`.
struct TlbShootdownRequest
{
    /// Physical address of the root page table to flush (0 = full flush).
    root_phys: AtomicU64,

    /// Virtual address to invalidate. `u64::MAX` means full flush.
    flush_va: AtomicU64,

    /// Hardware address-space tag (PCID / ASID) the invalidation targets, or `0`
    /// for the untagged path. When non-zero the target CPU invalidates the
    /// `(tag, va)` entry regardless of the tag it currently has loaded, so a CPU
    /// that has switched to a different space since the snapshot still flushes
    /// the right translation.
    tag: AtomicU16,

    /// CPUs that must still acknowledge this request. A set bit is both the
    /// "CPU N must flush" instruction and this request's per-target liveness
    /// badge (see module docs).
    pending_cpus: AtomicCpuMask,
}

impl TlbShootdownRequest
{
    const fn new() -> Self
    {
        Self {
            root_phys: AtomicU64::new(0),
            flush_va: AtomicU64::new(u64::MAX),
            tag: AtomicU16::new(0),
            pending_cpus: AtomicCpuMask::new(),
        }
    }
}

/// One request slot per logical CPU, indexed by initiator CPU id.
///
/// ~80 bytes per slot; sized to `MAX_CPUS` so it needs no runtime allocation
/// and is available from the first shootdown onward (including boot-time
/// identity-map teardown, which runs before any heap-backed per-CPU storage is
/// guaranteed).
static TLB_REQUESTS: [TlbShootdownRequest; MAX_CPUS] =
    [const { TlbShootdownRequest::new() }; MAX_CPUS];

/// Whether any CPU currently has a shootdown awaiting acknowledgement.
///
/// The softlockup watchdog uses this to defer to the shootdown's own bounded
/// escalation (NMI backtrace / panic in `wait_for_ack`) rather than dump on a
/// stall that is really a slow ack.
pub fn any_pending() -> bool
{
    let n = (crate::sched::CPU_COUNT.load(Ordering::Relaxed) as usize).min(MAX_CPUS);
    TLB_REQUESTS
        .iter()
        .take(n)
        .any(|r| !r.pending_cpus.is_empty(Ordering::Acquire))
}

/// Service every shootdown request that names this CPU.
///
/// Called from each arch's TLB-shootdown IPI handler. Scans all live slots and,
/// for each whose `pending_cpus` contains `my_cpu`, flushes the requested VA
/// (or the whole TLB) and clears this CPU's bit. Idempotent: a re-sent or stray
/// IPI that finds no matching bit does nothing.
///
/// # Safety
/// Must run in IPI-handler context on the CPU identified by `my_cpu`
/// (ring 0 / S-mode), where issuing TLB flushes is valid.
pub unsafe fn service_shootdowns(my_cpu: usize)
{
    let n = (crate::sched::CPU_COUNT.load(Ordering::Relaxed) as usize).min(MAX_CPUS);
    for req in TLB_REQUESTS.iter().take(n)
    {
        // Acquire: pairs with the initiator's Release store of pending_cpus, so
        // seeing our bit also makes the matching root/va visible below.
        if !req.pending_cpus.test_cpu(my_cpu, Ordering::Acquire)
        {
            continue;
        }
        let va = req.flush_va.load(Ordering::Acquire);
        let root = req.root_phys.load(Ordering::Acquire);
        let tag = req.tag.load(Ordering::Acquire);
        // Both `flush_va == u64::MAX` and `root_phys == 0` are full-flush
        // sentinels per shootdown()'s contract; either alone selects flush_tlb_all.
        // A non-zero `tag` targets that PCID/ASID specifically (the initiating
        // space may no longer be the tag loaded on this CPU); `tag == 0` is the
        // untagged path. A non-zero tag only exists when tagging is enabled, so
        // the tagged primitive's precondition holds.
        // SAFETY: caller guarantees IPI-handler context; the flush primitives are
        // valid at ring 0 / S-mode. A per-VA flush preserves global kernel
        // entries that a full flush would discard.
        unsafe {
            if va == u64::MAX || root == 0
            {
                crate::arch::current::paging::flush_tlb_all();
            }
            else if tag != 0
            {
                crate::arch::current::paging::flush_page_tagged(va, tag);
            }
            else
            {
                crate::arch::current::paging::flush_page(va);
            }
        }
        // Release: the flush above is visible before the initiator observes the
        // acknowledgement.
        req.pending_cpus.clear_cpu(my_cpu, Ordering::Release);
    }
}

/// Initiate a TLB shootdown for an address space on target CPUs.
///
/// Spins until all target CPUs acknowledge by clearing their bit in this CPU's
/// request slot.
///
/// # Contract
/// - Caller must have called `preempt_disable()` before this function.
/// - `root_phys` must be a valid page table root physical address or 0 for full flush.
/// - `cpus` must contain only online CPU indices and exclude the current CPU.
/// - `tag` is the hardware address-space tag (PCID / ASID) to invalidate, or `0`
///   for the untagged path. A non-zero `tag` must imply tagging is enabled.
///
/// # Safety
/// Caller must ensure `root_phys` and `cpus` are valid as described above.
// Used by AddressSpace::map_page, unmap_page, protect_page.
#[allow(dead_code)]
pub unsafe fn shootdown(root_phys: u64, cpus: &CpuMask, virt: u64, tag: u16)
{
    if cpus.is_empty()
    {
        return; // No remote CPUs active
    }

    debug_assert!(
        crate::percpu::preemption_disabled(),
        "shootdown: caller must call preempt_disable() first"
    );

    // Enable interrupts for the duration of the wait. This allows:
    // 1. Target CPUs in syscalls (IF=0/SIE=0) to receive our IPI when they next
    //    enable interrupts.
    // 2. Us to service incoming shootdown IPIs from another CPU simultaneously
    //    targeting us (mutual shootdown).
    //
    // Preemption is disabled by the caller, so timer_tick() will not call
    // schedule() even though interrupts are enabled.
    //
    // SAFETY: save_and_disable_interrupts is valid at ring 0 / S-mode.
    let saved_int = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
    // SAFETY: trap vectors are installed; enabling interrupts is safe at ring 0
    // / S-mode. Preemption is disabled by the caller.
    unsafe { crate::arch::current::interrupts::enable() };

    // This CPU's own request slot. No lock: the slot is owned by this CPU and
    // the previous shootdown drained it (pending_cpus empty) before we returned.
    let me = crate::arch::current::cpu::current_cpu() as usize;
    let req = &TLB_REQUESTS[me];

    // Publish the request. Release ordering pairs with the Acquire bit test in
    // service_shootdowns; the SeqCst fence below makes the stores globally
    // visible before the IPI.
    req.root_phys.store(root_phys, Ordering::Release);
    req.flush_va.store(virt, Ordering::Release);
    req.tag.store(tag, Ordering::Release);
    req.pending_cpus.store(cpus, Ordering::Release);

    // Drain the store buffer so a remote handler cannot read a stale slot. On
    // RISC-V (RVWMO) the Release stores order this hart's writes but do not
    // force global visibility before the SBI ecall that sends the IPI (not a
    // fence); the SeqCst fence does. On x86-64 (TSO) this is a no-op.
    core::sync::atomic::fence(Ordering::SeqCst);

    // Helper: send IPIs to every CPU in `mask`.
    let send_ipis = |mask: &CpuMask| {
        for cpu in mask.iter()
        {
            // Translate logical CPU → hardware ID (APIC ID / hart ID).
            // SAFETY: cpu is an online CPU index from the caller's mask;
            // apic_id_for returns the hardware ID for the logical CPU.
            let hw_id = unsafe { crate::percpu::apic_id_for(cpu) };
            // SAFETY: hw_id is a valid hardware ID for an online CPU.
            unsafe {
                crate::arch::current::interrupts::send_tlb_shootdown_ipi(hw_id);
            }
        }
    };

    // Initial IPI volley.
    send_ipis(cpus);

    // TSC-bounded ack wait with re-send + NMI-backtrace escalation. See
    // arch::current::interrupts::wait_for_ack and the IPI Watchdog Ladder
    // subsection in docs/scheduling-internals.md. The resend closure re-fires
    // only to CPUs whose bit is still set in our slot, so a dropped IPI recovers
    // without retransmitting to acks-in-flight. target_cpu is the lowest-numbered
    // target; it drives the Phase-C NMI backtrace and Phase-D panic message only.
    let target_cpu = cpus.first().unwrap_or(0);
    // Relaxed: a stale snapshot only causes a redundant IPI to a CPU that has
    // already acked, which is idempotent. The real synchronisation edge is the
    // Acquire poll in the cond closure below.
    let resend = || send_ipis(&req.pending_cpus.snapshot(Ordering::Relaxed));
    // SAFETY: caller invariants (preempt-disabled, IF=1) are upheld by the
    // save_and_disable_interrupts + enable() sequence above.
    unsafe {
        crate::arch::current::interrupts::wait_for_ack(
            || req.pending_cpus.is_empty(Ordering::Acquire),
            &crate::arch::current::interrupts::IpiWaitCtx {
                op_name: "tlb-shootdown",
                target_cpu,
                resend: &resend,
            },
        );
    }

    // The slot is now drained (pending_cpus empty) and stays idle until this
    // CPU's next shootdown reuses it — no explicit teardown is required.

    // Restore original interrupt state.
    // SAFETY: saved_int is from save_and_disable_interrupts on this CPU.
    unsafe {
        crate::arch::current::cpu::restore_interrupts(saved_int);
    }
}
