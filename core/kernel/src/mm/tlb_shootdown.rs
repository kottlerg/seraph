// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/mm/tlb_shootdown.rs

//! TLB shootdown protocol for cross-CPU page table invalidation.
//!
//! The caller classifies each leaf rewrite
//! ([`MapOutcome`](crate::mm::paging::MapOutcome)) and enters this module only
//! for the synchronous cases, per `core/kernel/docs/memory-internals.md` § SMP TLB
//! Shootdown. This module implements that protocol using IPIs.
//!
//! # Protocol
//!
//! The protocol is defined in `core/kernel/docs/memory-internals.md` § SMP TLB
//! Shootdown. Each CPU owns one request slot in the `cpu_count`-sized request
//! slab ([`init_storage`]), indexed by its logical CPU id; [`shootdown_range`] is the initiator side and
//! [`service_shootdowns`] the target side.
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
//!   arrives on RISC-V (the SBI ecall that delivers the IPI is not itself a
//!   fence). On x86-64 that ordering comes from the IPI send:
//!   `apic_send_icr` fences ahead of the non-serializing x2APIC ICR write, and
//!   x86 store ordering keeps the xAPIC ICR store after earlier stores.
//! - **Acquire** on a slot's `pending_cpus` (the handler's bit test, the
//!   initiator's emptiness poll) pairs with that Release, so a CPU that sees its
//!   bit also sees the matching root and VA.
//! - **Release** on a remote CPU's bit clear ensures its TLB flush completes
//!   before the initiator observes the acknowledgement.

use core::sync::atomic::{AtomicPtr, AtomicU16, AtomicU64, Ordering};

use crate::cpu_mask::{AtomicCpuMask, MaskSource};

/// Largest span (in 4 KiB pages) invalidated per-page rather than by full
/// flush. Each per-VA invalidation walks the TLB's tags, while a full flush
/// costs one refill of the CPU's working set — above a few dozen pages the
/// refill is cheaper (Linux's x86 `tlb_single_page_flush_ceiling` analogue
/// is 33). Callers with larger spans use the full-flush sentinel.
pub const RANGE_FLUSH_CEILING_PAGES: usize = 32;

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

    /// Number of consecutive 4 KiB pages to invalidate starting at
    /// `flush_va` (ignored on the full-flush sentinel path). A count above
    /// 1 makes the handler use the arch batched-invalidation window
    /// (riscv64 Svinval; on x86-64 a per-page `invlpg`, or INVPCID for a tagged
    /// request).
    page_count: AtomicU64,

    /// Hardware address-space tag (PCID / ASID) the invalidation targets, or `0`
    /// for the untagged path. When non-zero the target CPU invalidates the
    /// `(tag, va)` entry regardless of the tag it currently has loaded, so a CPU
    /// that has switched to a different space since the snapshot still flushes
    /// the right translation. `u16` holds every hardware tag: x86-64 PCIDs are
    /// 12 bits and RISC-V ASIDs at most 16 (`satp.ASID`).
    tag: AtomicU16,

    /// CPUs that must still acknowledge this request. A set bit is both the
    /// "CPU N must flush" instruction and this request's per-target liveness
    /// badge (see module docs).
    pending_cpus: AtomicCpuMask,
}

/// The TLB-shootdown request slab: one [`TlbShootdownRequest`] per CPU.
const TLB_REQUESTS_SLAB: crate::sched::PerCpuSlab =
    crate::sched::PerCpuSlab::of::<TlbShootdownRequest>("TLB_REQUESTS");
const _: () = assert!(
    TLB_REQUESTS_SLAB.sized_at_every_width(),
    "TLB_REQUESTS slab overflows"
);

impl TlbShootdownRequest
{
    const fn new() -> Self
    {
        Self {
            root_phys: AtomicU64::new(0),
            flush_va: AtomicU64::new(u64::MAX),
            page_count: AtomicU64::new(1),
            tag: AtomicU16::new(0),
            pending_cpus: AtomicCpuMask::unattached(),
        }
    }
}

/// Base of the request slab: one slot per booted CPU, indexed by initiator CPU
/// id. Null until [`init_storage`] (Phase 4); no shootdown targets another CPU
/// before the APs start in Phase 8.
static TLB_REQUESTS_PTR: AtomicPtr<TlbShootdownRequest> = AtomicPtr::new(core::ptr::null_mut());

/// Allocate the request slab and its acknowledgement-set words for
/// `cpu_count` CPUs and publish it. Called once from `percpu::init_storage`
/// (Phase 4), on the BSP, before any AP starts, after the mask width is set
/// (`cpu_mask::set_boot_cpu_count`).
///
/// Each request's `pending_cpus` is a view over its own run of
/// [`crate::cpu_mask::mask_words`] words in a second slab, `cpu_count` runs in
/// all, so the acknowledgement sets cost `cpu_count * cpu_count / 8` bytes,
/// paid for the CPUs this boot has.
pub fn init_storage(cpu_count: usize, allocator: &mut crate::mm::BuddyAllocator)
{
    let base = crate::sched::alloc_per_cpu_slab::<TlbShootdownRequest>(
        TLB_REQUESTS_SLAB,
        cpu_count,
        allocator,
    );
    let words_per_cpu = crate::cpu_mask::mask_words();
    let words = crate::sched::alloc_per_cpu_slab::<AtomicU64>(
        crate::sched::TLB_PENDING_CPUS_SLAB.with_elems_per_cpu(words_per_cpu),
        cpu_count,
        allocator,
    );
    for cpu in 0..cpu_count
    {
        let mut req = TlbShootdownRequest::new();
        // The run's first word is inside the slab of cpu_count * words_per_cpu
        // words, so the product never wraps.
        // SAFETY: the words slab holds `words_per_cpu` words per CPU, so this
        // CPU's run lies inside it.
        let run = unsafe { words.add(cpu.wrapping_mul(words_per_cpu)) };
        // SAFETY: run is this CPU's `words_per_cpu`-word run of the words
        // slab, which belongs to this request alone, for the kernel's life.
        req.pending_cpus = unsafe { AtomicCpuMask::attach(run, words_per_cpu) };
        // SAFETY: the slab covers cpu_count slots, so cpu's slot lies inside it.
        let slot = unsafe { base.add(cpu) };
        // SAFETY: slot is a slab slot that nothing reads before the Release
        // publication below.
        unsafe { core::ptr::write(slot, req) };
    }
    TLB_REQUESTS_PTR.store(base, Ordering::Release);
}

/// The request slots of every booted CPU; empty before [`init_storage`].
fn requests() -> &'static [TlbShootdownRequest]
{
    let base = TLB_REQUESTS_PTR.load(Ordering::Acquire);
    if base.is_null()
    {
        return &[];
    }
    // CPU_COUNT is stored (Phase 4, `sched::init_storage`) before the slab is
    // allocated and published.
    let n = crate::sched::CPU_COUNT.load(Ordering::Relaxed) as usize;
    // SAFETY: the slab holds CPU_COUNT initialised slots for the kernel's life.
    unsafe { core::slice::from_raw_parts(base, n) }
}

/// Whether any CPU currently has a shootdown awaiting acknowledgement.
///
/// The softlockup watchdog uses this to defer to the shootdown's own bounded
/// escalation (NMI backtrace / panic in `wait_for_ack`) rather than dump on a
/// stall that is really a slow ack.
pub fn any_pending() -> bool
{
    requests()
        .iter()
        .any(|r| !r.pending_cpus.is_empty(Ordering::Acquire))
}

/// Service every shootdown request that names this CPU.
///
/// Called from each arch's TLB-shootdown IPI handler. Scans all live slots and,
/// for each whose `pending_cpus` contains `my_cpu`, flushes the requested VA,
/// VA range, or the whole TLB, then clears this CPU's bit. Idempotent: a
/// re-sent or stray IPI that finds no matching bit does nothing.
///
/// Range requests (`page_count > 1`) from every matched slot share one arch
/// batched-invalidation window (riscv64 Svinval bracket), so a service pass
/// that finds several queued ranges pays the two window fences once.
///
/// Acknowledgement bits are cleared only after the batch window closes, for
/// every request kind (`core/kernel/docs/memory-internals.md` § SMP TLB
/// Shootdown). A pending bit set in an already-scanned slot after the scan is
/// handled by the initiator's resend ladder.
///
/// # Safety
/// Must run in IPI-handler context on the CPU identified by `my_cpu`
/// (ring 0 / S-mode), where issuing TLB flushes is valid.
pub unsafe fn service_shootdowns(my_cpu: usize)
{
    let slots = requests();
    // Slot indexes serviced since the last acknowledgement, at most
    // ACK_BATCH: a full batch closes the batch window and acknowledges
    // them, so the stack holds a fixed list whatever the CPU count.
    let mut serviced = [0u32; ACK_BATCH];
    let mut serviced_len = 0usize;
    let mut batch_open = false;
    for (slot, req) in slots.iter().enumerate()
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
        let pages = req.page_count.load(Ordering::Acquire);
        // Both `flush_va == u64::MAX` and `root_phys == 0` are full-flush
        // sentinels per shootdown_range()'s contract; either alone selects
        // flush_tlb_all. A non-zero `tag` targets that PCID/ASID specifically
        // (the initiating space may no longer be the tag loaded on this CPU);
        // `tag == 0` is the untagged path. A non-zero tag only exists when
        // tagging is enabled, so the tagged primitives' precondition holds.
        // The caller guarantees IPI-handler context, and the flush primitives
        // are valid at ring 0 / S-mode. A per-VA flush preserves global kernel
        // entries that a full flush would discard.
        if va == u64::MAX || root == 0
        {
            // SAFETY: IPI-handler context at ring 0 / S-mode (caller contract).
            unsafe { crate::arch::current::paging::flush_tlb_all() };
        }
        else if pages <= 1
        {
            if tag != 0
            {
                // SAFETY: IPI-handler context at ring 0 / S-mode (caller
                // contract); a non-zero tag means tagging is enabled.
                unsafe { crate::arch::current::paging::flush_page_tagged(va, tag) };
            }
            else if root == crate::mm::paging::kernel_root_table_pa()
            {
                // A kernel mapping: cached under every address space
                // this CPU has run.
                // SAFETY: IPI-handler context at ring 0 / S-mode (caller
                // contract).
                unsafe { crate::arch::current::paging::flush_kernel_page(va) };
            }
            else
            {
                // SAFETY: IPI-handler context at ring 0 / S-mode (caller
                // contract).
                unsafe { crate::arch::current::paging::flush_page(va) };
            }
        }
        else
        {
            if !batch_open
            {
                // SAFETY: IPI-handler context at ring 0 / S-mode (caller
                // contract).
                unsafe { crate::arch::current::paging::inval_batch_begin() };
                batch_open = true;
            }
            for p in 0..pages
            {
                // The initiator's range lies in the address space
                // (`shootdown_range`), so no page's address wraps.
                let pva = va.wrapping_add(p.wrapping_mul(crate::mm::PAGE_SIZE as u64));
                if tag != 0
                {
                    // SAFETY: IPI-handler context at ring 0 / S-mode (caller
                    // contract); a non-zero tag means tagging is enabled.
                    unsafe { crate::arch::current::paging::inval_page_tagged(pva, tag) };
                }
                else
                {
                    // SAFETY: IPI-handler context at ring 0 / S-mode (caller
                    // contract).
                    unsafe { crate::arch::current::paging::inval_page(pva) };
                }
            }
        }

        // serviced_len < ACK_BATCH here: it is reset on reaching it below.
        if let Some(entry) = serviced.get_mut(serviced_len)
        {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "slot < cpu_count <= MAX_CPUS, which fits u32"
            )]
            {
                *entry = slot as u32;
            }
            serviced_len = serviced_len.saturating_add(1);
        }
        if serviced_len == ACK_BATCH
        {
            // SAFETY: IPI-handler context (caller contract).
            unsafe { acknowledge(slots, &serviced, my_cpu, &mut batch_open) };
            serviced_len = 0;
        }
    }
    // serviced_len <= ACK_BATCH, so the prefix always exists.
    let pending = serviced.get(..serviced_len).unwrap_or(&[]);
    // SAFETY: IPI-handler context (caller contract).
    unsafe { acknowledge(slots, pending, my_cpu, &mut batch_open) };
}

/// Slots [`service_shootdowns`] services before it acknowledges them.
const ACK_BATCH: usize = 64;

/// Close the batched-invalidation window if open, then clear `my_cpu`'s
/// acknowledgement bit in each serviced slot.
///
/// # Safety
/// IPI-handler context on `my_cpu`, as for [`service_shootdowns`].
unsafe fn acknowledge(
    slots: &[TlbShootdownRequest],
    serviced: &[u32],
    my_cpu: usize,
    batch_open: &mut bool,
)
{
    if *batch_open
    {
        // SAFETY: paired with the inval_batch_begin in service_shootdowns;
        // IPI-handler context.
        unsafe { crate::arch::current::paging::inval_batch_end() };
        *batch_open = false;
    }
    // Release: every flush before this call — including the just-closed batch
    // window — is visible before any initiator observes its acknowledgement.
    // Every serviced value is the index of a slot of `slots`.
    for req in serviced.iter().filter_map(|&slot| slots.get(slot as usize))
    {
        req.pending_cpus.clear_cpu(my_cpu, Ordering::Release);
    }
}

/// Initiate a single-address TLB shootdown for an address space on target
/// CPUs. Delegates to [`shootdown_range`] with a one-page range.
///
/// # Contract / Safety
/// As [`shootdown_range`].
pub unsafe fn shootdown(root_phys: u64, targets: &MaskSource<'_>, virt: u64, tag: u16)
{
    // SAFETY: contract propagates verbatim.
    unsafe { shootdown_range(root_phys, targets, virt, 1, tag) };
}

/// Initiate a TLB shootdown of `pages` consecutive 4 KiB pages starting at
/// `virt` for an address space on target CPUs.
///
/// Spins until all target CPUs acknowledge by clearing their bit in this CPU's
/// request slot.
///
/// # Contract
/// - Caller must have called `preempt_disable()` before this function.
/// - `root_phys` must be a valid page table root physical address or 0 for full flush.
///   A single-page request (`pages` 1) on the kernel root
///   (`mm::paging::kernel_root_table_pa`) with `tag` 0 names a kernel mapping:
///   each target drops its translation in every address space
///   (`flush_kernel_page`). No caller sends a range on the kernel root.
/// - `virt == u64::MAX` (or `root_phys == 0`) requests a full flush; `pages`
///   is ignored on that path.
/// - `pages` must be at least 1 and small enough that the per-page handler
///   loop stays cheap — callers cap ranges at
///   [`RANGE_FLUSH_CEILING_PAGES`] and use the full-flush sentinel above it.
/// - `targets` must name only online CPU indices; the current CPU is left out
///   of them here.
/// - `tag` is the hardware address-space tag (PCID / ASID) to invalidate, or `0`
///   for the untagged path. A non-zero `tag` must imply tagging is enabled.
///
/// # Safety
/// Caller must ensure `root_phys` and `targets` are valid as described above.
pub unsafe fn shootdown_range(
    root_phys: u64,
    targets: &MaskSource<'_>,
    virt: u64,
    pages: u64,
    tag: u16,
)
{
    let me = crate::arch::current::cpu::current_cpu() as usize;
    // A target set beyond this CPU means the APs are up, so the slab exists.
    let Some(req) = requests().get(me)
    else
    {
        return; // Before the slab: no remote CPU is running yet.
    };
    if !req.pending_cpus.fill_would_be_nonempty(targets, me)
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

    // `req` is this CPU's own request slot. No lock: the slot is owned by
    // this CPU and the previous shootdown drained it (pending_cpus empty)
    // before we returned.

    // Publish the request. Release ordering pairs with the Acquire bit test in
    // service_shootdowns; the stores are globally visible before the IPI by
    // the SeqCst fence below on RISC-V and by `apic_send_icr`'s ordering on
    // x86-64.
    req.root_phys.store(root_phys, Ordering::Release);
    req.flush_va.store(virt, Ordering::Release);
    req.page_count.store(pages.max(1), Ordering::Release);
    req.tag.store(tag, Ordering::Release);
    req.pending_cpus.fill_from(targets, me, Ordering::Release);

    // Drain the store buffer so a remote handler cannot read a stale slot. On
    // RISC-V (RVWMO) the Release stores order this hart's writes but do not
    // force global visibility before the SBI ecall that sends the IPI (not a
    // fence); the SeqCst fence does. On x86-64 it is an `mfence`, but a WRMSR
    // is not ordered by it alone; the x2APIC send path fences again itself
    // (`apic_send_icr`).
    core::sync::atomic::fence(Ordering::SeqCst);

    // Helper: send IPIs to every CPU in `mask`.
    let send_ipis = |mask: &AtomicCpuMask| {
        for cpu in mask.iter(Ordering::Relaxed)
        {
            // Translate logical CPU → hardware ID (APIC ID / hart ID).
            // SAFETY: cpu is an online CPU index from the target set;
            // apic_id_for returns the hardware ID for the logical CPU.
            let hw_id = unsafe { crate::percpu::apic_id_for(cpu) };
            // SAFETY: hw_id is a valid hardware ID for an online CPU.
            unsafe {
                crate::arch::current::interrupts::send_tlb_shootdown_ipi(hw_id);
            }
        }
    };

    // The lowest-numbered target, for the watchdog's diagnostics only: a CPU
    // already servicing another initiator's request may acknowledge this one
    // before the read, which only moves the diagnostic to the next target.
    let target_cpu = req.pending_cpus.first(Ordering::Relaxed).unwrap_or(0);

    // Initial IPI volley, to the target set just published.
    send_ipis(&req.pending_cpus);

    // TSC-bounded ack wait with re-send + NMI-backtrace escalation. See
    // arch::current::interrupts::wait_for_ack and the IPI Watchdog Ladder
    // section in core/kernel/docs/scheduling-internals.md. The resend closure re-fires
    // only to CPUs whose bit is still set in our slot, so a dropped IPI recovers
    // without retransmitting to acks-in-flight. target_cpu is the lowest-numbered
    // target; it drives the Phase-C NMI backtrace and Phase-D panic message only.
    // Relaxed: a stale snapshot only causes a redundant IPI to a CPU that has
    // already acked, which is idempotent. The real synchronisation edge is the
    // Acquire poll in the cond closure below.
    let resend = || send_ipis(&req.pending_cpus);
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
