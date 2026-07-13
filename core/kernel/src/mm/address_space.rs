// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/mm/address_space.rs

//! User-mode address space management (Phase 9).
//!
//! An [`AddressSpace`] owns one root page table (PML4 on x86-64, the
//! negotiated-mode root
//! on RISC-V). Intermediate page table frames are allocated from the buddy
//! allocator on demand.
//!
//! `INIT_STACK_PAGES` is defined in the `init-protocol` ABI crate and
//! re-exported here. Init's bootstrap virtual addresses (the `InitInfo` page and
//! stack top) are the kernel's per-boot choice via [`choose_init_layout`], not
//! ABI constants.
//!
//! ## Kernel mapping inheritance
//! `new_user` copies kernel PML4 entries [256..512] from the currently active
//! page table root into the new user PML4, so kernel memory is reachable from
//! user address spaces without per-process kernel mapping maintenance.
//!
//! On RISC-V the equivalent root entries are 256–511 of the negotiated
//! mode's root table — the kernel half starts at root entry 256 in every
//! mode.
//!
//! ## Concurrency
//!
//! Page table modifications (`map_page`, `unmap_page`, `protect_page`) edit the
//! leaf PTE under the per-address-space `pt_lock`, then RELEASE `pt_lock`
//! before issuing the synchronous TLB shootdown ([`shootdown_remote`]). Holding
//! `pt_lock` across the shootdown's cross-CPU IPI ack-wait would serialize every
//! concurrent map/unmap on the address space behind that latency — a convoy /
//! priority-inversion under load. The committed PTE plus the immutable
//! `root_phys` are all the shootdown reads, so it runs without `pt_lock`.
//!
//! The shootdown itself is lock-free — each CPU publishes into its own request
//! slot — so `pt_lock` nests with no shootdown lock. The only lock the PTE edit
//! nests under `pt_lock` is the PT-frame source
//! (`pt_lock` → `FRAME_ALLOC_LOCK` on the heap-backed path).
//!
//! ## Operation-class shootdown elision
//!
//! The remote shootdown is issued only when the leaf-PTE rewrite can strand a
//! *dangerous* stale entry on another CPU. The arch mapping primitives classify
//! each rewrite as a [`MapOutcome`](crate::mm::paging::MapOutcome):
//!
//! - **Fresh map** (no prior mapping) and **permission widen** (same frame, new
//!   rights ⊇ prior) skip the remote shootdown. No remote CPU can hold a stale
//!   entry that grants more than the live PTE, so the worst case is a spurious
//!   fault the page-fault handler resolves against the live PTE and retries.
//! - **Replace** (different frame, or a permission *narrow*) keeps the
//!   synchronous shootdown: a stale entry would alias a freed/reused frame or
//!   cache over-broad rights — a correctness violation the retry cannot mask.
//!
//! `unmap_page` is always a Replace-equivalent and stays synchronous. The local
//! flush runs unconditionally regardless of class.
//!
//! Fresh/Widen safety rests on the spurious-fault retry (Widen) and on x86-64 not
//! caching not-present entries (Fresh) — not on the context-switch TLB flush — so
//! it is unaffected by a future PCID/ASID-tagged regime.
//!
//! `pt_lock` does NOT disable interrupts (shootdown needs them enabled).
//! `preempt_disable()` is held across the whole edit-then-shootdown sequence:
//! it satisfies the shootdown protocol's same-CPU invariant and ensures the
//! mapping is fully TLB-coherent before the operation returns.
//!
//! [`shootdown_remote`]: AddressSpace::shootdown_remote

// cast_possible_truncation: u64→usize page count arithmetic; bounded by address space size.
#![allow(clippy::cast_possible_truncation)]

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};

use boot_protocol::{InitSegment, SegmentFlags};

use crate::cpu_mask::{AtomicCpuMask, CpuMask};
use crate::mm::paging::phys_to_virt;
use crate::mm::{BuddyAllocator, PAGE_SIZE};

// Init stack page count is part of the init protocol ABI; the init VA layout
// (info page + stack top) is the kernel's per-boot choice, not an ABI constant.
pub use init_protocol::INIT_STACK_PAGES;
use process_layout::{INIT_INFO_WINDOW, INIT_STACK_GUARD_WINDOW};

/// Degraded-fallback base of the read-only `InitInfo` region mapped into init,
/// used only when the entropy pool is unavailable at the layout draw. The
/// region spans up to `INIT_INFO_MAX_PAGES` contiguous pages from this address.
pub const DEFAULT_INIT_INFO_VA: u64 = 0x3F_FFFF_5000;

/// Degraded-fallback top of init's user stack. `INIT_STACK_PAGES` pages map
/// immediately below, with one unmapped guard page beneath them.
pub const DEFAULT_INIT_STACK_TOP: u64 = 0x3F_FFFF_E000;

/// Bootstrap virtual addresses the kernel chooses for the init process.
///
/// The `InitInfo` page address is delivered to init in its entry register; the
/// stack top becomes init's initial stack pointer. Neither is an ABI constant,
/// so the kernel may vary them per-boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitLayout
{
    /// Base VA of the read-only `InitInfo` region.
    pub init_info_va: u64,
    /// Top of init's user stack.
    pub init_stack_top: u64,
}

/// Cached init layout for this boot. `init_info_va == 0` means not yet drawn
/// (a real `InitInfo` VA is never 0). Init is a singleton, and two boot phases
/// read its layout — the `InitInfo` mapping in Phase 9 and the user trap-frame
/// build in `sched::enter` — so the random draw is made once and cached to
/// keep both readers in agreement.
static INIT_LAYOUT_INFO_VA: AtomicU64 = AtomicU64::new(0);
static INIT_LAYOUT_STACK_TOP: AtomicU64 = AtomicU64::new(0);

/// Build init's layout from 16 bytes of entropy: the LE `u64` at `[0..8]`
/// draws the `InitInfo` base from `INIT_INFO_WINDOW`, the one at `[8..16]`
/// draws the stack guard page from `INIT_STACK_GUARD_WINDOW`, and the stack
/// top sits `INIT_STACK_PAGES` mapped pages above the guard (the guard page
/// itself stays unmapped below the stack base).
fn init_layout_from_entropy(entropy: [u8; 16]) -> InitLayout
{
    let mut word = [0_u8; 8];
    word.copy_from_slice(&entropy[0..8]);
    let init_info_va = INIT_INFO_WINDOW.pick(u64::from_le_bytes(word));
    word.copy_from_slice(&entropy[8..16]);
    let guard = INIT_STACK_GUARD_WINDOW.pick(u64::from_le_bytes(word));
    InitLayout {
        init_info_va,
        init_stack_top: guard + (1 + INIT_STACK_PAGES as u64) * PAGE_SIZE as u64,
    }
}

/// Draw init's layout for this boot (ASLR, #39).
///
/// Requires the entropy pool (seeded in Phase 5, before the first caller in
/// Phase 9); if it is somehow unavailable the layout degrades to the
/// deterministic `DEFAULT_INIT_*` addresses with a console warning, matching
/// the entropy subsystem's graceful-degradation stance.
#[cfg(not(test))]
fn draw_init_layout() -> InitLayout
{
    if crate::entropy::is_seeded()
    {
        let mut entropy = [0_u8; 16];
        crate::entropy::fill_bytes(&mut entropy);
        return init_layout_from_entropy(entropy);
    }
    crate::kprintln!("[mm] entropy unavailable; init layout falls back to defaults");
    InitLayout {
        init_info_va: DEFAULT_INIT_INFO_VA,
        init_stack_top: DEFAULT_INIT_STACK_TOP,
    }
}

/// Host-test stand-in: the real draw path needs the `cfg(not(test))` entropy
/// subsystem. A fixed pattern keeps the cache logic testable.
#[cfg(test)]
fn draw_init_layout() -> InitLayout
{
    init_layout_from_entropy([0xA5; 16])
}

/// Return the init process's bootstrap VA layout for this boot, drawing it on
/// the first call and returning the cached value thereafter.
///
/// The analogue of `process-layout`'s `choose_process_layout` for the
/// kernel→init handover. The drawing call must remain the Phase 9 boot-thread
/// call — the entropy draw is not interrupt-safe. Safe to call from the single
/// boot thread across boot phases; not intended for concurrent use.
#[must_use]
pub fn choose_init_layout() -> InitLayout
{
    let cached = INIT_LAYOUT_INFO_VA.load(Ordering::Relaxed);
    if cached != 0
    {
        return InitLayout {
            init_info_va: cached,
            init_stack_top: INIT_LAYOUT_STACK_TOP.load(Ordering::Relaxed),
        };
    }

    let layout = draw_init_layout();
    INIT_LAYOUT_STACK_TOP.store(layout.init_stack_top, Ordering::Relaxed);
    INIT_LAYOUT_INFO_VA.store(layout.init_info_va, Ordering::Relaxed);
    layout
}

// ── AddressSpace ──────────────────────────────────────────────────────────────

/// A user-mode virtual address space.
///
/// Owns the physical frame of the root page table. Intermediate frames
/// allocated during mapping are tracked implicitly through the page table
/// structure; they are returned to the per-AS pool on region teardown
/// ([`unmap_region_pooled`](Self::unmap_region_pooled)) and reclaimed wholesale
/// at address-space death.
pub struct AddressSpace
{
    /// Physical address of the root page table frame (PML4 / RISC-V root).
    pub root_phys: u64,
    /// Virtual address of the root frame (via the direct physical map).
    pub root_virt: u64,
    /// Set of CPUs currently running threads in this address space.
    ///
    /// CPU N present = CPU N has this AS active, TLB may contain cached entries.
    /// Updated on every context switch by the scheduler; queried by TLB
    /// shootdown to determine which CPUs need IPIs.
    active_cpus: AtomicCpuMask,
    /// Lock serializing page table modifications (map/unmap/protect).
    ///
    /// Simple CAS spin lock — does NOT disable interrupts (shootdown needs
    /// IF=1 to deliver IPIs). Preemption is prevented by caller's
    /// `preempt_disable()`.
    pt_lock: AtomicBool,
    /// Hardware address-space tag (x86-64 PCID / RISC-V ASID), or `0` when
    /// untagged (unclaimed, or the full-flush fallback when tagging is
    /// unavailable). Claimed lazily on first `activate` from
    /// [`crate::mm::tag_allocator`]. Written only under the tag-pool lock
    /// (by the owner's own claim or by eviction); read lock-free by `activate`.
    // dead_code: the tag fields are accessed only on `#[cfg(not(test))]` paths
    // (activate / shootdown / destroy), so host-test builds see them as unread.
    #[allow(dead_code)]
    pub(crate) tag: AtomicU16,
    /// The global allocator generation stamped when this space claimed its
    /// current `tag`. Globally unique per claim; distinguishes this space's
    /// claim on a tag from any later space that reuses the same tag value, so a
    /// per-CPU generation check flushes a tag before its first use under a new
    /// owner.
    #[allow(dead_code)] // see `tag`
    pub(crate) tag_gen: AtomicU64,
    /// Bumped on every Replace-class modification (`unmap`, permission narrow).
    /// A CPU switched away from this space compares its last-synced value
    /// against this on reactivation and flushes the tag if it lags, catching
    /// unmaps it missed while it was elsewhere.
    #[allow(dead_code)] // see `tag`
    pub(crate) tlb_gen: AtomicU64,
    /// Observers to notify when a thread in this address space takes a
    /// *terminal* fault (no handler bound, or handler replied `KILL`).
    ///
    /// Mirrors the per-thread `ThreadControlBlock::death_observers` set: each
    /// observer pairs an `EventQueueState` post target with a caller-chosen
    /// `correlator`, and the kernel posts the packed payload
    /// `(correlator as u64) << 32 | (exit_reason & 0xFFFF_FFFF)` on a terminal
    /// fault. procmgr binds one at process creation so a worker thread's fatal
    /// fault drives the process teardown cascade; the kernel only *notifies*,
    /// it never enumerates or terminates threads. Normal `thread_exit` does
    /// NOT post to these observers. Entries past `death_observer_count` are
    /// invalid.
    death_observers:
        [crate::sched::thread::DeathObserver; crate::sched::thread::MAX_DEATH_OBSERVERS],
    /// Number of populated entries in `death_observers`
    /// (`0..=MAX_DEATH_OBSERVERS`).
    death_observer_count: u8,
    /// Serialises `death_observers`/`death_observer_count` and the retained
    /// terminal-fault state below against a concurrent bind
    /// (`sys_aspace_bind_notification`) and the terminal-fault post
    /// (`post_aspace_death_notification`) — the address-space analogue of a
    /// thread's `sched_lock` role for `ThreadControlBlock::death_observers`.
    death_lock: crate::sync::Spinlock,
    /// Set when a thread in this address space takes a terminal fault. A later
    /// bind onto an already-faulted space delivers `terminal_fault_reason` to
    /// the new observer instead of dropping the event — the address-space
    /// analogue of retaining a thread's `exit_reason` past death. First fault
    /// wins; subsequent faults do not overwrite.
    terminal_faulted: bool,
    /// Retained terminal-fault reason (`EXIT_FAULT_BASE + vector`), valid when
    /// `terminal_faulted`.
    terminal_fault_reason: u64,
}

// SAFETY: All mutable state is protected by pt_lock (page tables), death_lock
// (death observers + retained terminal-fault state), or atomic operations
// (active_cpus). Safe to share across threads and CPUs.
unsafe impl Send for AddressSpace {}
// SAFETY: pt_lock serializes page table modifications; death_lock serializes the
// death-observer set; active_cpus is atomic.
unsafe impl Sync for AddressSpace {}

impl AddressSpace
{
    /// Acquire the page table modification lock.
    ///
    /// On the contended path, enables interrupts while spinning so that
    /// incoming TLB shootdown IPIs from the lock holder can be serviced.
    /// Caller must have called `preempt_disable()` first.
    #[cfg(not(test))]
    #[inline]
    fn pt_lock(&self)
    {
        // Fast path: uncontended.
        if self
            .pt_lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }

        // Contended path: enable interrupts while spinning so the lock
        // holder's shootdown IPI can be delivered to this CPU. Without
        // this, the holder spins forever on pending_cpus waiting for us
        // to ack, while we spin forever on pt_lock waiting for the holder.
        // Preemption is disabled by the caller, so timer_tick() will not
        // call schedule().
        //
        // SAFETY: save_and_disable_interrupts is valid at ring 0 / S-mode.
        let saved = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
        // SAFETY: IDT / trap vector is installed; enabling interrupts is safe
        // at ring 0 / S-mode. Preemption is disabled by the caller.
        unsafe { crate::arch::current::interrupts::enable() };

        loop
        {
            while self.pt_lock.load(Ordering::Relaxed)
            {
                core::hint::spin_loop();
            }
            if self
                .pt_lock
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }

        // SAFETY: restoring previously saved interrupt state.
        unsafe { crate::arch::current::cpu::restore_interrupts(saved) };
    }

    /// Release the page table modification lock.
    #[cfg(not(test))]
    #[inline]
    fn pt_unlock(&self)
    {
        self.pt_lock.store(false, Ordering::Release);
    }

    /// Shoot down the TLB entry for `virt` on every other CPU that currently
    /// has this address space active.
    ///
    /// Run OUTSIDE `pt_lock` (the caller must have released it): the leaf PTE
    /// is already committed, so holding `pt_lock` across the synchronous IPI
    /// ack-wait would needlessly serialize every concurrent map/unmap on this
    /// address space behind cross-CPU latency. The shootdown only reads the
    /// immutable `root_phys` and the active-CPU mask, so it needs no PT lock.
    ///
    /// The current CPU is excluded from the mask; the caller performs the
    /// local invalidation under `pt_lock`. The caller MUST still hold
    /// `preempt_disable()` — the shootdown protocol requires it, and keeping
    /// it held until the shootdown returns makes the mapping fully TLB-coherent
    /// before the syscall returns.
    #[cfg(not(test))]
    #[inline]
    fn shootdown_remote(&self, virt: u64)
    {
        // This is the Replace-class path (unmap / frame-replace / permission
        // narrow). Reading `self.tag` is safe without the pool lock: the current
        // CPU is running this space (it is performing the modification), so the
        // space is active and cannot be selected as an eviction victim, so its
        // tag is stable here.
        let tag = self.tag.load(Ordering::Acquire);

        if crate::mm::tag_allocator::tagging_enabled()
        {
            // Bump the per-space TLB generation so a CPU that was switched away
            // (and is therefore NOT in active_cpus, so gets no IPI below) flushes
            // this tag on its next reactivation. The SeqCst fence is the A-side
            // of the INV-3 unmap-race Dekker: it orders the bump before the
            // active-CPU snapshot, pairing with the fence in `activate`. Together
            // they guarantee that for any CPU caching this space, either it is in
            // the snapshot (gets an IPI) or it observes the bumped tlb_gen on
            // reactivation. Never neither.
            self.tlb_gen.fetch_add(1, Ordering::Release);
            core::sync::atomic::fence(Ordering::SeqCst);
        }

        let mut remote_cpus = self.active_cpu_mask();
        let current = crate::arch::current::cpu::current_cpu() as usize;
        remote_cpus.clear(current);
        if !remote_cpus.is_empty()
        {
            // SAFETY: root_phys is a valid page table root; remote_cpus
            // contains only online CPUs (enforced by scheduler); the caller
            // holds preempt_disable() and no longer holds pt_lock.
            unsafe {
                crate::mm::tlb_shootdown::shootdown(self.root_phys, &remote_cpus, virt, tag);
            }
        }
    }

    /// Allocate a new, empty user address space.
    ///
    /// 1. Allocates one frame from `allocator` for the root page table.
    /// 2. Zeros the frame.
    /// 3. Copies kernel-half entries (indices 256–511) from the current
    ///    hardware page table root so the kernel is reachable from this space.
    ///
    /// # Panics
    /// Calls `crate::fatal` if the buddy allocator is exhausted.
    ///
    /// # Safety
    /// Must be called after Phase 3 (page tables active) and Phase 4 (heap active).
    /// The current CPU's page table root must be the kernel's root table.
    #[cfg(not(test))]
    pub unsafe fn new_user(allocator: &mut BuddyAllocator) -> Self
    {
        // Allocate one 4 KiB frame (order 0) for the root page table.
        let root_phys = allocator
            .alloc(0)
            .unwrap_or_else(|| crate::fatal("address_space::new_user: out of memory for root PT"));

        let root_virt = phys_to_virt(root_phys);

        // Zero the frame (page table entries are 0 = not-present by default).
        // SAFETY: root_virt is a valid, exclusively-owned kernel virtual address
        // mapped RW in the direct physical map; write_bytes stays within PAGE_SIZE bounds.
        unsafe {
            core::ptr::write_bytes(root_virt as *mut u8, 0, PAGE_SIZE);
        }

        // Copy kernel-half root entries (indices 256–511, the kernel half in
        // every paging mode) from the current
        // active page table root so the kernel stays accessible from user mode.
        //
        // On x86-64: read CR3 for the current PML4 physical address.
        // On RISC-V: read satp for the current root physical address.
        // SAFETY: root_virt is valid and page-aligned; copy_kernel_entries
        // reads the current root and copies 256 u64 entries within bounds.
        unsafe {
            Self::copy_kernel_entries(root_virt);
        }

        Self {
            root_phys,
            root_virt,
            active_cpus: AtomicCpuMask::new(),
            pt_lock: AtomicBool::new(false),
            tag: AtomicU16::new(0),
            tag_gen: AtomicU64::new(0),
            tlb_gen: AtomicU64::new(0),
            death_observers: [crate::sched::thread::DeathObserver::empty();
                crate::sched::thread::MAX_DEATH_OBSERVERS],
            death_observer_count: 0,
            death_lock: crate::sync::Spinlock::new(),
            terminal_faulted: false,
            terminal_fault_reason: 0,
        }
    }

    /// Allocate a fresh user address space backed by a caller-supplied root
    /// page-table frame.
    ///
    /// Used by the typed-memory retype path (`sys_cap_create_aspace`): the
    /// caller pops a page from the `AddressSpaceObject`'s growth pool and
    /// passes its physical address here. This function:
    /// 1. Zeroes the frame.
    /// 2. Copies the kernel-half PT entries (indices 256-511) from the
    ///    currently active root.
    /// 3. Returns an [`AddressSpace`] wrapping the supplied frame.
    ///
    /// # Safety
    /// `root_phys` must be a freshly-allocated, page-aligned 4 KiB physical
    /// frame mapped in the kernel direct map and not aliased anywhere.
    /// Phase 3 (page tables) and Phase 4 (heap) must already be active.
    #[cfg(not(test))]
    pub unsafe fn new_user_with_root(root_phys: u64) -> Self
    {
        let root_virt = phys_to_virt(root_phys);

        // SAFETY: caller's contract.
        unsafe {
            core::ptr::write_bytes(root_virt as *mut u8, 0, PAGE_SIZE);
        }

        // SAFETY: root_virt is valid and page-aligned.
        unsafe {
            Self::copy_kernel_entries(root_virt);
        }

        Self {
            root_phys,
            root_virt,
            active_cpus: AtomicCpuMask::new(),
            pt_lock: AtomicBool::new(false),
            tag: AtomicU16::new(0),
            tag_gen: AtomicU64::new(0),
            tlb_gen: AtomicU64::new(0),
            death_observers: [crate::sched::thread::DeathObserver::empty();
                crate::sched::thread::MAX_DEATH_OBSERVERS],
            death_observer_count: 0,
            death_lock: crate::sync::Spinlock::new(),
            terminal_faulted: false,
            terminal_fault_reason: 0,
        }
    }

    /// Copy entries 256–511 from the currently active page table root into
    /// the new user page table at `new_root_virt`.
    ///
    /// # Safety
    /// Both the current root and `new_root_virt` must be valid, 4 KiB-aligned
    /// kernel virtual addresses mapped R/W in the direct physical map.
    #[cfg(not(test))]
    unsafe fn copy_kernel_entries(new_root_virt: u64)
    {
        use crate::arch::current::paging::read_root_phys;

        // SAFETY: read_root_phys reads CR3/satp; caller contract ensures paging is active.
        let current_root_phys = unsafe { read_root_phys() };
        let current_root_virt = phys_to_virt(current_root_phys);

        // Each entry is 8 bytes; entries 256–511 start at byte offset 2048.
        let src = (current_root_virt + 2048) as *const u64;
        let dst = (new_root_virt + 2048) as *mut u64;

        // SAFETY: both src and dst are valid kernel virtual addresses within
        // 4 KiB page table frames; the 256 u64 copy (2048 bytes) stays within bounds.
        unsafe {
            core::ptr::copy_nonoverlapping(src, dst, 256);
        }
    }

    /// Bind a terminal-fault observer, or — if this address space has already
    /// terminal-faulted — return the retained reason for the caller to deliver
    /// to the new observer immediately.
    ///
    /// The address-space analogue of `sys_thread_bind_notification`'s
    /// retained-delivery branch. Serialises on `death_lock` against the
    /// terminal-fault post ([`crate::sched::post_aspace_death_notification`]),
    /// so a fault concurrent with a bind is delivered exactly once and never
    /// dropped — closing the bind-after-fault window for an observer bound after
    /// the space was already running.
    ///
    /// Returns `Ok(None)` if the observer was appended, `Ok(Some(reason))` if
    /// the space already faulted (caller posts `reason` to `eq`), or `Err(())`
    /// if the observer array is full.
    ///
    /// # Safety
    /// `this` must be a valid `AddressSpace` pointer. The caller must NOT hold
    /// `death_lock`.
    #[cfg(not(test))]
    pub unsafe fn bind_or_retained(
        this: *mut Self,
        eq: *mut crate::ipc::event_queue::EventQueueState,
        correlator: u32,
    ) -> Result<Option<u64>, ()>
    {
        // SAFETY: this validated by caller; lock_raw is paired with an
        // unlock_raw on every path.
        let saved = unsafe { (*this).death_lock.lock_raw() };
        // SAFETY: terminal_faulted/terminal_fault_reason read under death_lock.
        let (faulted, reason) =
            unsafe { ((*this).terminal_faulted, (*this).terminal_fault_reason) };
        if faulted
        {
            // SAFETY: paired with the lock_raw above.
            unsafe { (*this).death_lock.unlock_raw(saved) };
            return Ok(Some(reason));
        }
        // SAFETY: lock held; the append stays within MAX_DEATH_OBSERVERS.
        let result = unsafe {
            let count = (*this).death_observer_count as usize;
            if count >= crate::sched::thread::MAX_DEATH_OBSERVERS
            {
                Err(())
            }
            else
            {
                (*this).death_observers[count] =
                    crate::sched::thread::DeathObserver { eq, correlator };
                (*this).death_observer_count = (count + 1) as u8;
                Ok(None)
            }
        };
        // SAFETY: paired with the lock_raw above.
        unsafe { (*this).death_lock.unlock_raw(saved) };
        result
    }

    /// Record a terminal fault (first fault wins) and snapshot the observer set
    /// under `death_lock`. The terminal-fault post path posts to the returned
    /// snapshot outside the lock; recording the reason lets a later
    /// `bind_or_retained` deliver it to an observer bound after the fault.
    ///
    /// # Safety
    /// `this` must be a valid `AddressSpace` pointer. The caller must NOT hold
    /// `death_lock`.
    #[cfg(not(test))]
    pub unsafe fn record_fault_and_snapshot(
        this: *mut Self,
        reason: u64,
    ) -> (
        [crate::sched::thread::DeathObserver; crate::sched::thread::MAX_DEATH_OBSERVERS],
        usize,
    )
    {
        // SAFETY: this validated by caller; the observer array is Copy, so it is
        // snapshotted by value with no reference taken into the address space.
        unsafe {
            let saved = (*this).death_lock.lock_raw();
            if !(*this).terminal_faulted
            {
                (*this).terminal_faulted = true;
                (*this).terminal_fault_reason = reason;
            }
            let snapshot = (*this).death_observers;
            let count = (*this).death_observer_count as usize;
            (*this).death_lock.unlock_raw(saved);
            (snapshot, count)
        }
    }

    /// Map `virt` → `phys` as a 4 KiB page with the given permission flags.
    ///
    /// Acquires `pt_lock`, draws missing intermediate page-table frames
    /// from [`crate::mm::kernel_pt_pool`] (seeded at Phase 7), flushes the local
    /// TLB, and sends remote TLB shootdown IPIs only when the rewrite can strand
    /// a dangerous stale entry (see the module's elision note). A fresh map into
    /// a previously-unmapped VA skips the remote shootdown.
    ///
    /// Used by:
    /// - [`map_segment`](Self::map_segment) and direct kernel callers
    ///   (Phase 9 init bootstrap, `sys_mmio_map` for legacy MMIO mappings)
    ///   — PT pages come from `kernel_pt_pool`.
    /// - For userspace `sys_mem_map` against a retype-backed AS, see
    ///   [`map_page_pooled`](Self::map_page_pooled).
    ///
    /// # Safety
    /// `virt` must be in the user half (< `0x8000_0000_0000`). `phys` must be
    /// a valid 4 KiB-aligned physical address.
    #[cfg(not(test))]
    pub unsafe fn map_page(
        &self,
        virt: u64,
        phys: u64,
        flags: crate::mm::paging::PageFlags,
    ) -> Result<(), ()>
    {
        use crate::arch::current::paging::{flush_page, map_user_page};

        crate::percpu::preempt_disable();
        self.pt_lock();

        // Intermediate page table frames are drawn from
        // `mm::kernel_pt_pool` (seeded once at Phase 7 with `POOL_SEED_PAGES`
        // from the pristine buddy). No buddy lock is taken on this path; the
        // shootdown below is the only inter-CPU synchronisation cost.
        // SAFETY: contract passed to caller; root_virt is valid; virt is
        // in user range; phys is a valid 4 KiB-aligned physical address.
        let Ok(outcome) = (unsafe { map_user_page(self.root_virt, virt, phys, flags) })
        else
        {
            self.pt_unlock();
            crate::percpu::preempt_enable();
            return Err(());
        };

        // Local TLB invalidation for the mapped page, under pt_lock. The
        // current CPU does not IPI itself.
        // SAFETY: virt is a valid user virtual address.
        unsafe {
            flush_page(virt);
        }

        // Drop pt_lock BEFORE the (conditional) synchronous remote shootdown so
        // concurrent map/unmap on this address space need not wait behind our
        // IPI ack-wait. preempt stays disabled, so any shootdown completes (full
        // TLB coherence) before this returns. A fresh map or a permission widen
        // strands no dangerous stale entry, so it skips the remote shootdown and
        // relies on the spurious-fault retry path. See `shootdown_remote` and
        // [`MapOutcome`](crate::mm::paging::MapOutcome).
        self.pt_unlock();
        if outcome.needs_remote_shootdown()
        {
            self.shootdown_remote(virt);
        }
        crate::percpu::preempt_enable();

        Ok(())
    }

    /// Pooled variant of [`map_page`]: draws intermediate PT frames from
    /// the supplied [`AddressSpaceObject`](crate::cap::object::AddressSpaceObject)'s
    /// growth pool instead of the kernel buddy.
    ///
    /// The `aso` MUST wrap *this* `AddressSpace`. `sys_mem_map` enforces this
    /// implicitly because it resolves both via the same capability.
    ///
    /// # Safety
    /// Same contract as [`map_page`].
    #[cfg(not(test))]
    pub unsafe fn map_page_pooled(
        &self,
        virt: u64,
        phys: u64,
        flags: crate::mm::paging::PageFlags,
        aso: &crate::cap::object::AddressSpaceObject,
    ) -> Result<(), ()>
    {
        use crate::arch::current::paging::{flush_page, map_user_page_pooled};

        crate::percpu::preempt_disable();
        self.pt_lock();

        // SAFETY: caller's contract; aso pairs with this AS.
        let Ok(outcome) = (unsafe { map_user_page_pooled(self.root_virt, virt, phys, flags, aso) })
        else
        {
            self.pt_unlock();
            crate::percpu::preempt_enable();
            return Err(());
        };

        // Local TLB invalidation under pt_lock; conditional remote shootdown
        // after unlock (fresh map / widen elide it — see `map_page`).
        // SAFETY: virt is a valid user virtual address.
        unsafe {
            flush_page(virt);
        }

        self.pt_unlock();
        if outcome.needs_remote_shootdown()
        {
            self.shootdown_remote(virt);
        }
        crate::percpu::preempt_enable();

        Ok(())
    }

    /// Map each page of an ELF LOAD `segment` into this address space.
    ///
    /// Permissions are derived from `segment.flags`:
    /// - `Read`        → R-- (readable, not writable, not executable)
    /// - `ReadWrite`   → RW- (readable, writable; W^X: not executable)
    /// - `ReadExecute` → R-X (readable, executable; W^X: not writable)
    ///
    /// Physical addresses come from `segment.phys_addr`, mapped sequentially
    /// in 4 KiB increments across `segment.size` bytes (rounded up to pages).
    ///
    /// # Safety
    /// `segment` must be a valid, bootloader-provided `InitSegment`.
    #[cfg(not(test))]
    pub unsafe fn map_segment(&self, segment: &InitSegment) -> Result<(), ()>
    {
        let flags = match segment.flags
        {
            SegmentFlags::Read => crate::mm::paging::PageFlags {
                readable: true,
                writable: false,
                executable: false,
                uncacheable: false,
            },
            SegmentFlags::ReadWrite => crate::mm::paging::PageFlags {
                readable: true,
                writable: true,
                executable: false,
                uncacheable: false,
            },
            SegmentFlags::ReadExecute => crate::mm::paging::PageFlags {
                readable: true,
                writable: false,
                executable: true,
                uncacheable: false,
            },
        };

        // Align virt and phys down to 4 KiB page boundaries for page table
        // mapping. The in-page offset is preserved implicitly: the CPU adds
        // (virt_addr & 0xFFF) to the physical frame address at access time.
        //
        // Example: virt_addr=0x201120 (off=0x120), phys_addr=0x1e1a6120
        //   → map virtual page 0x201000 → physical frame 0x1e1a6000
        //   → CPU translates 0x201120 → 0x1e1a6000 + 0x120 = 0x1e1a6120 ✓
        //
        // page_count includes the in-page offset so a segment that crosses a
        // page boundary gets enough pages mapped.
        let in_page_off = (segment.virt_addr & 0xFFF) as usize;
        let page_count = (in_page_off + segment.size as usize)
            .div_ceil(PAGE_SIZE)
            .max(1);
        let virt_base = segment.virt_addr & !0xFFF_u64; // page-aligned virtual
        let phys_base = segment.phys_addr & !0xFFF_u64; // page-aligned physical frame
        for i in 0..page_count
        {
            let virt = virt_base + (i * PAGE_SIZE) as u64;
            let phys = phys_base + (i * PAGE_SIZE) as u64;
            // SAFETY: segment is bootloader-provided; caller's safety contract.
            unsafe {
                self.map_page(virt, phys, flags)?;
            }
        }
        Ok(())
    }

    /// Remove the mapping for a single 4 KiB page at `virt`.
    ///
    /// If `virt` is not mapped, this is a no-op (safe to call redundantly).
    /// Does not free intermediate page table frames; the reclaiming region path
    /// is [`unmap_region_pooled`](Self::unmap_region_pooled). Invalidates TLB
    /// entries on all CPUs where this address space is active.
    ///
    /// # Safety
    /// `virt` must be in the user half. Caller must not access `virt` after
    /// this call; the TLB entry is invalidated.
    #[cfg(not(test))]
    pub unsafe fn unmap_page(&self, virt: u64)
    {
        use crate::arch::current::paging::{flush_page, unmap_user_page};

        crate::percpu::preempt_disable();
        self.pt_lock();

        // Remove the mapping via arch-specific page table walk.
        // SAFETY: root_virt is valid; virt is in user range (caller's contract).
        unsafe { unmap_user_page(self.root_virt, virt) };

        // Local TLB invalidation for the unmapped page, under pt_lock. The
        // current CPU does not IPI itself.
        // SAFETY: virt is a valid user virtual address.
        unsafe {
            flush_page(virt);
        }

        // Drop pt_lock BEFORE the synchronous remote shootdown so concurrent
        // map/unmap on this address space need not wait behind our IPI
        // ack-wait. preempt stays disabled, so the unmap is fully TLB-coherent
        // before this returns (the page's frame is owned by its Memory cap and
        // is not reclaimed here, so no early-reuse hazard). See
        // `shootdown_remote`.
        self.pt_unlock();
        self.shootdown_remote(virt);
        crate::percpu::preempt_enable();
    }

    /// Unmap `page_count` pages from `[virt_base, ..)` and reclaim every
    /// intermediate page table the cleared span leaves empty back to `aso`'s
    /// growth pool (crediting `pt_growth_budget_bytes`). Returns the number of
    /// page-table frames reclaimed.
    ///
    /// Drives `SYS_MEM_UNMAP` with `MEM_UNMAP_RECLAIM_PTS` (memmgr region
    /// teardown). Unlike the per-page [`unmap_page`](Self::unmap_page), it tears
    /// the whole span down under a single `pt_lock` hold and a single coarse TLB
    /// + paging-structure-cache shootdown.
    ///
    /// `aso` MUST wrap *this* `AddressSpace`; `sys_mem_unmap` enforces this by
    /// resolving both from the same capability.
    ///
    /// # Safety
    /// `virt_base` must be page-aligned and the span `[virt_base, virt_base +
    /// page_count * PAGE_SIZE)` must lie in the user half (caller validates).
    #[cfg(not(test))]
    pub unsafe fn unmap_region_pooled(
        &self,
        virt_base: u64,
        page_count: usize,
        aso: &crate::cap::object::AddressSpaceObject,
    ) -> usize
    {
        use crate::arch::current::paging::{flush_tlb_all, unmap_user_region_pooled};

        crate::percpu::preempt_disable();
        self.pt_lock();

        // Clear every leaf in the span and free each now-empty, aso-owned
        // intermediate table back to the pool.
        // SAFETY: root_virt is valid; aso wraps this AS; the span is user-range
        // (caller's contract); pt_lock is held.
        let freed = unsafe { unmap_user_region_pooled(self.root_virt, virt_base, page_count, aso) };

        // ONE coarse shootdown for the whole teardown, performed UNDER pt_lock
        // (the per-VA `unmap_page` drops the lock first for throughput; here it
        // must stay held). A freed PT frame is poppable only via `alloc_pt_page`,
        // which runs under THIS `pt_lock`, so no other CPU reuses a just-freed
        // frame until we release — by then every CPU's TLB + paging-structure
        // cache is clean. The contended `pt_lock` path enables interrupts while
        // spinning, so a remote CPU waiting on this lock still services and acks
        // our IPI: no deadlock.
        // INV-3 Dekker A-side: bump tlb_gen and fence BEFORE snapshotting
        // active_cpus (the same order as `shootdown_remote`). This guarantees
        // that for any CPU caching this space, either it is in the snapshot
        // below (gets the IPI) or it observes the bumped tlb_gen on its next
        // reactivation (flushes the tag then). Snapshotting first would leave a
        // CPU that activates concurrently in neither cover. The same argument
        // covers both invalidation shapes below: spans at or under
        // RANGE_FLUSH_CEILING_PAGES issue an untagged per-page range flush
        // (batched: riscv64 Svinval bracket), larger spans a full flush. The
        // untagged range is as correct as the untagged full flush — a remote
        // target still has this space's tag loaded, and per-VA invalidation
        // covers the paging-structure caches for the freed intermediate frames
        // on both architectures (invlpg / sfence-family VA forms invalidate
        // non-leaf entries for that VA too).
        if crate::mm::tag_allocator::tagging_enabled()
        {
            self.tlb_gen.fetch_add(1, Ordering::Release);
            core::sync::atomic::fence(Ordering::SeqCst);
        }
        let current = crate::arch::current::cpu::current_cpu() as usize;
        let ranged = page_count <= crate::mm::tlb_shootdown::RANGE_FLUSH_CEILING_PAGES;
        // Only CPUs that run this AS cache its translations — the kernel edits
        // these page tables through the direct map, never by loading this root.
        // The caller is normally memmgr, which does not run the target AS, so
        // the local flush is usually skipped.
        if self.active_cpus.test_cpu(current, Ordering::Acquire)
        {
            if ranged
            {
                use crate::arch::current::paging::{
                    inval_batch_begin, inval_batch_end, inval_page,
                };
                // SAFETY: ring 0 / S-mode; per-VA invalidations bracketed by
                // the batch window; clears TLB + PS-cache entries for every
                // VA in the span.
                unsafe {
                    inval_batch_begin();
                    for i in 0..page_count
                    {
                        inval_page(virt_base + (i * crate::mm::PAGE_SIZE) as u64);
                    }
                    inval_batch_end();
                }
            }
            else
            {
                // SAFETY: ring 0 / S-mode; full flush clears TLB + PS-caches.
                unsafe { flush_tlb_all() };
            }
        }
        let mut remote = self.active_cpu_mask();
        remote.clear(current);
        if !remote.is_empty()
        {
            if ranged
            {
                // SAFETY: root_phys is a valid root; remote excludes current;
                // preempt is held and pt_lock no-pop invariant holds; tag 0 is
                // the untagged path (see the INV-3 block above for why that is
                // sufficient here).
                unsafe {
                    crate::mm::tlb_shootdown::shootdown_range(
                        self.root_phys,
                        &remote,
                        virt_base,
                        page_count as u64,
                        0,
                    );
                }
            }
            else
            {
                // virt = u64::MAX routes the remote handler to flush_tlb_all()
                // (ignores tag) — correct even cross-AS where this AS's tag is
                // not stable on the current CPU.
                // SAFETY: as the range branch; tag unused on this path.
                unsafe {
                    crate::mm::tlb_shootdown::shootdown(self.root_phys, &remote, u64::MAX, 0);
                }
            }
        }

        self.pt_unlock();
        crate::percpu::preempt_enable();
        freed
    }

    /// Change the permission flags on an existing 4 KiB leaf mapping at `virt`.
    ///
    /// Returns `Err(PagingError::NotMapped)` if `virt` is not mapped.
    /// Caller is responsible for W^X and rights validation before calling.
    /// Invalidates TLB entries on all CPUs where this address space is active.
    ///
    /// # Safety
    /// `virt` must be in the user half and currently mapped.
    #[cfg(not(test))]
    pub unsafe fn protect_page(
        &self,
        virt: u64,
        flags: crate::mm::paging::PageFlags,
    ) -> Result<(), crate::mm::paging::PagingError>
    {
        use crate::arch::current::paging::{flush_page, protect_user_page};

        crate::percpu::preempt_disable();
        self.pt_lock();

        // Change protection bits via arch-specific page table walk.
        // SAFETY: root_virt is valid; virt is in user range (caller's contract).
        let outcome = match unsafe { protect_user_page(self.root_virt, virt, flags) }
        {
            Ok(outcome) => outcome,
            Err(e) =>
            {
                self.pt_unlock();
                crate::percpu::preempt_enable();
                return Err(e);
            }
        };

        // Local TLB invalidation for the protected page, under pt_lock. The
        // current CPU does not IPI itself.
        // SAFETY: virt is a valid user virtual address.
        unsafe {
            flush_page(virt);
        }

        // Drop pt_lock BEFORE the (conditional) synchronous remote shootdown so
        // concurrent map/unmap on this address space need not wait behind our
        // IPI ack-wait. preempt stays disabled, so any shootdown is fully
        // TLB-coherent before this returns. A permission *widen* strands only a
        // re-walkable stale entry and skips the remote shootdown; a *narrow*
        // leaves over-broad rights cached and stays synchronous. See
        // `shootdown_remote` and [`MapOutcome`](crate::mm::paging::MapOutcome).
        self.pt_unlock();
        if outcome.needs_remote_shootdown()
        {
            self.shootdown_remote(virt);
        }
        crate::percpu::preempt_enable();

        Ok(())
    }

    /// Translate a user virtual address to its mapped physical address.
    ///
    /// Performs a read-only page table walk. Returns `Some((phys_addr,
    /// raw_pte_bits))` if the page is present at every level, or `None`
    /// if the address is not mapped.
    ///
    /// The page-alignment of `virt` is not enforced here; the caller is
    /// responsible for aligning to `PAGE_SIZE` before calling if desired.
    #[cfg(not(test))]
    pub fn query_page(&self, virt: u64) -> Option<(u64, u64)>
    {
        use crate::arch::current::paging::translate_user_page;
        // SAFETY: root_virt is the direct-map VA of a valid root page table.
        unsafe { translate_user_page(self.root_virt, virt) }
    }

    /// Activate this address space on the current CPU.
    ///
    /// With tagging disabled this writes the page-table root with a full TLB
    /// flush (x86-64 CR3 write; RISC-V `satp` + `sfence.vma`). With tagging
    /// enabled it loads the root under this space's hardware tag **without**
    /// flushing, then flushes only that tag if a per-CPU generation check shows
    /// the tag was reissued to a different space or accrued unmaps while this
    /// CPU was switched away.
    ///
    /// The caller (scheduler / first user entry) MUST have marked this CPU
    /// active on this space (`mark_active_on_cpu`) before calling, both so the
    /// space cannot be selected as its own eviction victim and so the INV-3
    /// fence below has an active-bit store to order against.
    ///
    /// # Safety
    /// Must be called at ring 0 / S-mode. After this call, all virtual
    /// addresses are resolved through this address space's page tables.
    #[cfg(not(test))]
    pub unsafe fn activate(&self)
    {
        use crate::arch::current::paging::{activate, activate_tagged, flush_tag};
        use crate::mm::tag_allocator;

        if !tag_allocator::tagging_enabled()
        {
            // SAFETY: caller's contract; root_phys is a valid page table root.
            unsafe {
                activate(self.root_phys);
            }
            return;
        }

        // INV-3: the scheduler published this CPU's active bit (Release) before
        // calling. This fence orders that store before the tag/generation reads
        // below, forming the B-side of the unmap and eviction Dekker exclusions
        // (paired with the SeqCst fences in `unmap_page`/`protect_page` and in
        // `tag_allocator::claim`'s eviction). Without it a CPU could miss an
        // unmap that did not IPI it and later run a stale tagged translation.
        core::sync::atomic::fence(Ordering::SeqCst);

        let mut tag = self.tag.load(Ordering::Acquire);
        if tag == 0
        {
            tag = tag_allocator::claim(self);
        }
        // `claim` never returns 0 when tagging is enabled (the enablement gate
        // keeps usable tags > cpu_count, so a tag is always available). This
        // defensive full-flush is unreachable; it exists so a logic error can
        // never run a user space under tag 0 (which would mix tags across the
        // space and miss a shootdown).
        if tag == 0
        {
            debug_assert!(tag != 0, "claim returned 0 with tagging enabled");
            // SAFETY: caller's contract; root_phys is a valid root.
            unsafe {
                activate(self.root_phys);
            }
            crate::percpu::record_ctxsw_flush(false);
            return;
        }

        let tag_gen = self.tag_gen.load(Ordering::Acquire);
        let tlb_gen = self.tlb_gen.load(Ordering::Acquire);

        // Load the tagged page tables without flushing — the optimization.
        // SAFETY: tagging enabled ⇒ CR4.PCIDE set / ASID width > 0; root_phys is
        // a valid root mapping current code, stack, and the direct map.
        unsafe {
            activate_tagged(self.root_phys, tag);
        }

        // Per-CPU generation check: flush this tag iff it was reissued to a
        // different space (owner_gen mismatch) or this space accrued unmaps
        // while this CPU was switched away (synced_tlb_gen lag).
        let cpu = crate::arch::current::cpu::current_cpu() as usize;
        // SAFETY: tagging enabled ⇒ the per-CPU slab is initialised; cpu is the
        // current CPU and < cpu_count; tag < num_tags.
        let (owner_gen, synced) = unsafe { tag_allocator::tag_state(cpu, tag) };
        if owner_gen != tag_gen || synced < tlb_gen
        {
            // SAFETY: ring 0 / S-mode; tagging enabled.
            unsafe {
                flush_tag(tag);
                tag_allocator::set_tag_state(cpu, tag, tag_gen, tlb_gen);
            }
            crate::percpu::record_ctxsw_flush(false);
        }
        else
        {
            crate::percpu::record_ctxsw_flush(true);
        }
    }

    /// Mark this address space as active on a CPU.
    ///
    /// Called during context switch when switching TO this address space.
    /// Sets bit `cpu` in the `active_cpus` bitmask.
    ///
    /// # Memory Ordering
    /// Uses Release ordering: ensures all prior address space setup (page
    /// table modifications, mappings) is visible to other CPUs before marking
    /// active, so TLB shootdown sees a consistent view when it queries
    /// `active_cpu_mask`.
    pub fn mark_active_on_cpu(&self, cpu: u32)
    {
        // SAFETY: Release ordering ensures prior address space setup (page
        // table modifications) is visible before we mark it active for TLB
        // shootdown purposes. The set_cpu is atomic; no data race on the mask.
        self.active_cpus.set_cpu(cpu as usize, Ordering::Release);
    }

    /// Mark this address space as inactive on a CPU.
    ///
    /// Called during context switch when switching FROM this address space.
    /// Clears bit `cpu` in the `active_cpus` bitmask.
    ///
    /// # Memory Ordering
    /// Uses Release ordering: ensures all TLB-dependent operations complete
    /// before clearing the active bit, so concurrent shootdowns see the correct
    /// mask (a CPU remains active until it has fully switched away).
    pub fn mark_inactive_on_cpu(&self, cpu: u32)
    {
        // SAFETY: Release ordering ensures all TLB-dependent operations
        // complete before we mark inactive, so TLB shootdowns see the correct
        // mask. The clear_cpu is atomic; no data race on the mask.
        self.active_cpus.clear_cpu(cpu as usize, Ordering::Release);
    }

    /// Get the bitmask of CPUs with this address space active.
    ///
    /// Used by TLB shootdown to determine which CPUs need IPIs.
    /// Bit N set = CPU N is currently running threads in this address space.
    ///
    /// # Memory Ordering
    /// Uses Acquire ordering: ensures we observe all prior `mark_active_on_cpu`
    /// calls from other CPUs, giving an accurate snapshot of which CPUs have
    /// cached TLB entries for this address space.
    pub(crate) fn active_cpu_mask(&self) -> CpuMask
    {
        // SAFETY: Acquire ordering ensures we see all mark_active calls from
        // other CPUs. The snapshot is per-word atomic; no data race on the mask.
        self.active_cpus.snapshot(Ordering::Acquire)
    }
}

#[cfg(test)]
mod init_layout_tests
{
    use process_layout::{INIT_INFO_WINDOW, INIT_STACK_GUARD_WINDOW, LAYOUT_VA_CEILING};

    use super::*;

    #[test]
    fn entropy_draw_is_aligned_in_window_and_disjoint()
    {
        for pattern in [[0x00_u8; 16], [0xFF; 16], [0xA5; 16], [0x5A; 16]]
        {
            let layout = init_layout_from_entropy(pattern);
            let page = PAGE_SIZE as u64;

            assert!(INIT_INFO_WINDOW.contains(layout.init_info_va));
            assert_eq!(layout.init_stack_top % page, 0);
            let stack_reserve = (1 + INIT_STACK_PAGES as u64) * page;
            let guard = layout.init_stack_top - stack_reserve;
            assert!(INIT_STACK_GUARD_WINDOW.contains(guard));
            assert!(layout.init_stack_top < LAYOUT_VA_CEILING);

            // InitInfo region (INIT_INFO_MAX_PAGES) vs stack reservation
            // (guard + INIT_STACK_PAGES): disjoint for every draw.
            let info_end = layout.init_info_va + init_protocol::INIT_INFO_MAX_PAGES as u64 * page;
            assert!(info_end <= guard);
        }
    }

    #[test]
    fn choose_init_layout_caches_first_draw()
    {
        let first = choose_init_layout();
        assert_eq!(choose_init_layout(), first);
    }
}
