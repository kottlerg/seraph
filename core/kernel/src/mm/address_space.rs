// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/mm/address_space.rs

//! User-mode address space management.
//!
//! An [`AddressSpace`] owns one root page table (the boot depth's PML4 or
//! PML5 on x86-64, the negotiated-mode root on RISC-V). Intermediate page table frames are
//! drawn on demand from the wrapper object's page pool on the pooled map
//! path, or from the kernel page-table pool (`mm::kernel_pt_pool`) on the
//! kernel-direct path.
//!
//! `INIT_STACK_PAGES` is defined in the `init-protocol` ABI crate and
//! re-exported here. Init's bootstrap virtual addresses (the `InitInfo` page and
//! stack top) are the kernel's per-boot choice via [`choose_init_layout`], not
//! ABI constants.
//!
//! ## Kernel mapping inheritance
//! `new_user_with_root` copies kernel root entries [256..512] (PML4 or PML5 entries
//! on x86-64, by boot depth) from the currently active page table root into the
//! new user root, so kernel memory is reachable from user address spaces without
//! per-process kernel mapping maintenance.
//!
//! On RISC-V the equivalent root entries are 256–511 of the negotiated
//! mode's root table — the kernel half starts at root entry 256 in every
//! mode.
//!
//! ## Concurrency
//!
//! The per-page edits (`map_page`, `unmap_page`, `protect_page`) edit the leaf
//! PTE under the per-address-space `pt_lock` and release it before the remote
//! shootdown ([`shootdown_remote`]); the shootdown is skipped for Fresh and Widen
//! rewrites ([`MapOutcome`](crate::mm::paging::MapOutcome)). Region teardown
//! ([`unmap_region_pooled`](AddressSpace::unmap_region_pooled)) is the exception:
//! it holds `pt_lock` across its one coarse shootdown, plus one span
//! invalidation under `pt_lock` each time the cleared frames overflow the
//! frame-map release batch, so that no CPU can reuse a just-freed page-table
//! frame before every TLB and paging-structure cache is clean. The protocol and
//! the classification are defined in `core/kernel/docs/memory-internals.md`
//! § SMP TLB Shootdown. The only lock that nests under `pt_lock` is the
//! PT-frame source: the wrapper's pool lock on the pooled path, the kernel
//! page-table pool lock on the kernel-direct path. The local flush runs
//! unconditionally regardless of class.
//!
//! Fresh/Widen safety rests on the spurious-fault retry (Widen) and on x86-64 not
//! caching not-present entries (Fresh) — not on the context-switch TLB flush — so
//! it holds unchanged under PCID/ASID tagging.
//!
//! `pt_lock` does NOT disable interrupts (shootdown needs them enabled).
//! `preempt_disable()` is held across the whole edit-then-shootdown sequence:
//! it satisfies the shootdown protocol's same-CPU invariant and ensures the
//! mapping is fully TLB-coherent before the operation returns.
//!
//! [`shootdown_remote`]: AddressSpace::shootdown_remote

use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};

use boot_protocol::{InitSegment, SegmentFlags};

use crate::cpu_mask::{AtomicCpuMask, MaskSource};
use crate::mm::PAGE_SIZE;
use crate::mm::paging::phys_to_virt;
use syscall::SyscallError;

// Init stack page count is part of the init protocol ABI; the init VA layout
// (info page + stack top) is the kernel's per-boot choice, not an ABI constant.
pub use init_protocol::INIT_STACK_PAGES;
use process_layout::{INIT_INFO_WINDOW, INIT_STACK_GUARD_WINDOW, STACK_GUARD_PAGES};

/// Degraded-fallback base of the read-only `InitInfo` region mapped into init,
/// used only when the entropy pool is unavailable at the layout draw. The
/// region spans up to `INIT_INFO_MAX_PAGES` contiguous pages from this address,
/// which end at the lowest of the fallback stack's guard pages. A fixed VA below
/// the 256 GiB Sv39 user top, so the fallback is valid on both architectures;
/// it bounds no count.
pub const DEFAULT_INIT_INFO_VA: u64 = DEFAULT_INIT_STACK_TOP
    - INIT_STACK_RESERVE
    - init_protocol::INIT_INFO_MAX_PAGES as u64 * PAGE_SIZE as u64;

/// Degraded-fallback top of init's user stack. `INIT_STACK_PAGES` pages map
/// immediately below, with `STACK_GUARD_PAGES` unmapped guard pages beneath
/// them. A fixed VA below the 256 GiB Sv39 user top, like
/// `DEFAULT_INIT_INFO_VA`.
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
/// (a real `InitInfo` VA is never 0). Init is a singleton, and two Phase 9
/// readers use its layout — `kernel_entry` (the `InitInfo` and stack mappings
/// and init's entry argument) and the user trap-frame build in `sched::enter` —
/// so the random draw is made once and cached to keep both readers in agreement.
static INIT_LAYOUT_INFO_VA: AtomicU64 = AtomicU64::new(0);
static INIT_LAYOUT_STACK_TOP: AtomicU64 = AtomicU64::new(0);

/// Bytes from the lowest of init's stack guard pages to its stack top: the
/// `STACK_GUARD_PAGES` guard pages, as below every other placed userspace
/// stack (docs/build-system.md § Custom Targets gives the span they cover),
/// and the `INIT_STACK_PAGES` stack pages above them.
const INIT_STACK_RESERVE: u64 =
    (STACK_GUARD_PAGES as u64 + INIT_STACK_PAGES as u64) * PAGE_SIZE as u64;

// The highest guard's stack top stays below the layout ceiling, so the stack
// top `init_layout_from_entropy` derives never saturates.
const _: () = assert!(
    INIT_STACK_GUARD_WINDOW.end() <= process_layout::LAYOUT_VA_CEILING - INIT_STACK_RESERVE
);

/// Build init's layout from 16 bytes of entropy: the LE `u64` at `[0..8]`
/// draws the `InitInfo` base from `INIT_INFO_WINDOW`, the one at `[8..16]`
/// draws the lowest stack guard page from `INIT_STACK_GUARD_WINDOW`, and the
/// stack top sits `STACK_GUARD_PAGES` guard pages and `INIT_STACK_PAGES` mapped
/// pages above it (the guard pages stay unmapped below the stack base).
fn init_layout_from_entropy(entropy: [u8; 16]) -> InitLayout
{
    let mut word = [0u8; 8];
    word.copy_from_slice(&entropy[0..8]);
    let init_info_va = INIT_INFO_WINDOW.pick(u64::from_le_bytes(word));
    word.copy_from_slice(&entropy[8..16]);
    let guard = INIT_STACK_GUARD_WINDOW.pick(u64::from_le_bytes(word));
    InitLayout {
        init_info_va,
        init_stack_top: guard.saturating_add(INIT_STACK_RESERVE),
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
        let mut entropy = [0u8; 16];
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
/// structure; their source and reclaim (pool-drawn nodes return to the per-AS
/// pool via [`unmap_region_pooled`](Self::unmap_region_pooled) and with the
/// donations at destruction, kernel-pool nodes are never returned) are
/// defined in `core/kernel/docs/memory-internals.md` § Page Table Node Ownership.
pub struct AddressSpace
{
    /// Physical address of the root page table frame (PML4 or PML5 / RISC-V root).
    pub root_phys: u64,
    /// Virtual address of the root frame (via the direct physical map).
    pub root_virt: u64,
    /// Set of CPUs currently running threads in this address space.
    ///
    /// CPU N present = CPU N has this AS active, TLB may contain cached entries.
    /// Updated on every context switch by the scheduler; queried by TLB
    /// shootdown to determine which CPUs need IPIs. A view over the words
    /// right after this struct in its wrapper page
    /// ([`attach_active_cpus`](Self::attach_active_cpus)).
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
    /// (by the owner's own claim or by eviction); read lock-free by `activate`
    /// (a 0 sends it to the locked claim) and by `shootdown_remote` (a revoked
    /// tag is harmless: core/kernel/docs/memory-internals.md § SMP TLB
    /// Shootdown). The teardown's `tag_allocator::free_tag` reads it under the
    /// lock, so an eviction cannot hand the dying space's tag to another space
    /// between the read and the free (see the `tag_allocator` § Concurrency).
    /// `u16` holds every hardware tag: x86-64 PCIDs are 12 bits and RISC-V
    /// ASIDs at most 16 (`satp.ASID`).
    pub(crate) tag: AtomicU16,
    /// The global allocator generation stamped when this space claimed its
    /// current `tag`. Globally unique per claim; distinguishes this space's
    /// claim on a tag from any later space that reuses the same tag value, so a
    /// per-CPU generation check flushes a tag before its first use under a new
    /// owner. A `u64` cannot wrap: at one claim per nanosecond it lasts over 500
    /// years.
    pub(crate) tag_gen: AtomicU64,
    /// Bumped (when tagging is enabled) on every Replace-class modification
    /// (unmap, remap to a different frame, permission narrow).
    /// A CPU switched away from this space compares its last-synced value
    /// against this on reactivation and flushes the tag if it lags, catching
    /// unmaps it missed while it was elsewhere.
    /// A `u64` cannot wrap: at one modification per nanosecond it lasts over 500
    /// years.
    pub(crate) tlb_gen: AtomicU64,
    /// Observers to notify when a thread in this address space takes a
    /// terminal fault: a chain of death-observer nodes, each drawn from the
    /// observing queue's pool at bind and carrying its caller-chosen
    /// `correlator` (mirroring `ThreadControlBlock::death_observers`).
    /// Semantics are defined in `docs/capability-model.md` § "Kill process"
    /// pattern and `core/kernel/docs/syscalls.md` §
    /// `SYS_ASPACE_BIND_NOTIFICATION`. Owned by `death_lock`.
    death_observers: crate::sched::thread::DeathObserverChain,
    /// Serialises `death_observers` and the retained
    /// terminal-fault state below against a concurrent bind
    /// (`sys_aspace_bind_notification`) and the terminal-fault record
    /// (`record_aspace_terminal_fault`) — the address-space analogue of a
    /// thread's `sched_lock` role for `ThreadControlBlock::death_observers`.
    /// Those three fields are bare under the exception of
    /// docs/coding-standards.md § Concurrency, with this lock as their owner
    /// (core/kernel/docs/memory-internals.md § Address Space Objects).
    death_lock: crate::sync::Spinlock,
    /// Set when a thread in this address space takes a terminal fault. A later
    /// bind onto an already-faulted space delivers `terminal_fault_reason` to
    /// the new observer instead of dropping the event — the address-space
    /// analogue of retaining a thread's `exit_reason` past death. First fault
    /// wins; subsequent faults do not overwrite. Owned by `death_lock`.
    terminal_faulted: bool,
    /// Retained terminal-fault reason (`EXIT_FAULT_BASE + vector`), valid when
    /// `terminal_faulted`. Owned by `death_lock`.
    terminal_fault_reason: u64,
}

// SAFETY: All mutable state is protected by pt_lock (page tables), death_lock
// (death observers + retained terminal-fault state), or atomic operations
// (active_cpus). Safe to share across threads and CPUs.
unsafe impl Send for AddressSpace {}
// SAFETY: pt_lock serializes page table modifications; death_lock serializes the
// death-observer set; active_cpus is atomic.
unsafe impl Sync for AddressSpace {}

/// Whether a `SYS_THREAD_WRITE_MEM` may write a page the thread's leaf makes
/// read-only, such as its text: the call's `THREAD_MEM_TEXT` flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextWrite
{
    /// `THREAD_MEM_TEXT` set: a read-only page whose leaf grants write or
    /// execute and whose frame is mapped once takes the write.
    Permitted,
    /// `THREAD_MEM_TEXT` clear: a read-only page refuses the write.
    Refused,
}

/// The direction and buffer of an [`AddressSpace::copy_user_bytes`].
pub enum UserCopy<'a>
{
    /// Read the range into the buffer.
    Read(&'a mut [u8]),
    /// Write the buffer into the range.
    Write
    {
        /// The bytes to write.
        src: &'a [u8],
        /// Whether a read-only page may be written.
        text: TextWrite,
    },
}

/// One page's share of a byte range: the page's base VA, the byte offset in
/// the page, the offset in the caller's buffer, and the byte count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageSpan
{
    /// Page-aligned VA of the page.
    pub page: u64,
    /// Offset of the first byte in the page.
    pub in_page: usize,
    /// Offset of the first byte in the buffer.
    pub offset: usize,
    /// Bytes in this page.
    pub len: usize,
}

/// The pages `[va, va + len)` covers, in order, each with its share of the
/// range. The caller has checked that the range does not wrap; one that would
/// is cut at the end of the address space.
pub fn page_spans(va: u64, len: usize) -> impl Iterator<Item = PageSpan>
{
    const OFFSET_MASK: u64 = PAGE_SIZE as u64 - 1;
    let mut cursor = va;
    let end = va.saturating_add(len as u64);
    core::iter::from_fn(move || {
        if cursor >= end
        {
            return None;
        }
        let base = cursor & !OFFSET_MASK;
        // A saturated page end is past `end`, so the minimum is `end`.
        let next = base.saturating_add(PAGE_SIZE as u64).min(end);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "each value is below PAGE_SIZE or len. `va <= cursor < next`, so neither \
                      difference wraps"
        )]
        let span = PageSpan {
            page: base,
            in_page: (cursor & OFFSET_MASK) as usize,
            offset: cursor.wrapping_sub(va) as usize,
            len: next.wrapping_sub(cursor) as usize,
        };
        cursor = next;
        Some(span)
    })
}

/// The addresses of the `page_count` pages from page-aligned `base`, in order;
/// `None` when the span passes the end of the address space.
fn span_pages(base: u64, page_count: usize) -> Option<core::iter::StepBy<core::ops::Range<u64>>>
{
    let end = (page_count as u64)
        .checked_mul(PAGE_SIZE as u64)
        .and_then(|bytes| base.checked_add(bytes))?;
    Some((base..end).step_by(PAGE_SIZE))
}

/// Whether `SYS_THREAD_READ_MEM` and `SYS_THREAD_WRITE_MEM` may copy a page
/// whose user leaf grants `leaf` and names the frame at `phys`, through the
/// direct map, which covers RAM below `ram_top`.
///
/// The leaf must be write-back: an uncacheable leaf is device memory, which
/// `SYS_MMIO_MAP` installs and no permission change turns write-back, so a
/// write-back leaf names normal memory (a Memory capability's frame, or RAM
/// the kernel mapped for init). The frame must also lie below `ram_top`: a
/// Memory capability over firmware memory, such as the ACPI RSDP page, maps
/// write-back and may lie above RAM, where the direct map does not reach.
///
/// # Errors
/// `InvalidAddress`: the leaf is uncacheable, or the frame is at or above
/// `ram_top`.
pub fn thread_mem_page_check(
    leaf: crate::mm::paging::PageFlags,
    phys: u64,
    ram_top: u64,
) -> Result<(), SyscallError>
{
    if leaf.uncacheable || phys.saturating_add(PAGE_SIZE as u64) > ram_top
    {
        return Err(SyscallError::InvalidAddress);
    }
    Ok(())
}

/// Whether `SYS_THREAD_WRITE_MEM` may write a page whose user leaf grants
/// `leaf` and records `grant`, with `text` as the call's flag gives it;
/// `mappings` counts the frame's user leaf mappings and is read only for a
/// read-only leaf.
///
/// A writable leaf takes any write, as a store of the thread would. A
/// read-only one, such as text, needs `text`; a grant of write or execute,
/// so that the capability that mapped it let its holder change or run what
/// it holds, which a Map-only capability (a firmware table, a page lent
/// read-only) does not; and its frame mapped exactly once: the frame of a
/// read-only page mapped elsewhere too may be another process's text or
/// data, which the write would change through this thread's capability.
///
/// # Errors
/// - `InsufficientRights`: the leaf is read-only and `text` is
///   [`TextWrite::Refused`], or its grant holds neither write nor execute.
/// - `InvalidState`: the leaf is read-only and the frame has another mapping.
pub fn thread_mem_write_check(
    leaf: crate::mm::paging::PageFlags,
    grant: crate::mm::paging::LeafGrant,
    text: TextWrite,
    mappings: impl FnOnce() -> u64,
) -> Result<(), SyscallError>
{
    if leaf.writable
    {
        return Ok(());
    }
    if text == TextWrite::Refused || !(grant.writable || grant.executable)
    {
        return Err(SyscallError::InsufficientRights);
    }
    if mappings() != 1
    {
        return Err(SyscallError::InvalidState);
    }
    Ok(())
}

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
        // narrow).
        if crate::mm::tag_allocator::tagging_enabled()
        {
            // Bump the per-space TLB generation, then fence before the active-CPU
            // snapshot: the initiator side of the tlb_gen / active_cpus Dekker
            // exclusion with the fence in `activate` (see
            // core/kernel/docs/memory-internals.md § SMP TLB Shootdown). The
            // fence also orders the caller's PTE store before the tag read below.
            self.tlb_gen.fetch_add(1, Ordering::Release);
            core::sync::atomic::fence(Ordering::SeqCst);
        }

        let remote_cpus = MaskSource::Mask(&self.active_cpus, Ordering::Acquire);
        // `self.tag` is read without the pool lock, after the fence, and the
        // caller need not be running this space (cross-AS edits by procmgr /
        // memmgr), so the read can race eviction. A revoked tag it carries is
        // harmless: eviction needs the space inactive everywhere, so a CPU
        // in the snapshot reactivated it under a fresh claim, which flushed
        // that new tag and walks the PTE the fence published (proof:
        // core/kernel/docs/memory-internals.md § SMP TLB Shootdown). With
        // tagging disabled the tag is always 0.
        let tag = self.tag.load(Ordering::Acquire);
        // SAFETY: root_phys is a valid page table root; remote_cpus
        // names only online CPUs (enforced by scheduler), and the
        // shootdown leaves this CPU out of it; the caller holds
        // preempt_disable() and no longer holds pt_lock. An empty target
        // set returns at once.
        unsafe {
            crate::mm::tlb_shootdown::shootdown(self.root_phys, &remote_cpus, virt, tag);
        }
    }

    /// Allocate a fresh user address space backed by a caller-supplied root
    /// page-table frame.
    ///
    /// Used by both typed-memory creation paths (`sys_cap_create_aspace` and the
    /// Phase 9 `boot_retype_aspace`): the caller passes page 1 of the
    /// create-time slab (page 0 is the wrapper page, the rest seed the
    /// page-table pool; see `core/kernel/docs/memory-internals.md` § Lifecycle).
    /// This function:
    /// 1. Zeroes the frame.
    /// 2. Copies the kernel-half PT entries (indices 256-511) from the
    ///    currently active root.
    /// 3. Returns an [`AddressSpace`] wrapping the supplied frame.
    ///
    /// # Safety
    /// `root_phys` must be a freshly-allocated, page-aligned 4 KiB physical
    /// frame mapped in the kernel direct map and not aliased anywhere.
    /// Phase 3 (page tables) must already be active.
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
            active_cpus: AtomicCpuMask::unattached(),
            pt_lock: AtomicBool::new(false),
            tag: AtomicU16::new(0),
            tag_gen: AtomicU64::new(0),
            tlb_gen: AtomicU64::new(0),
            death_observers: crate::sched::thread::DeathObserverChain::new(),
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

        // Entries 256–511 are the upper half of each root's 512 entries.
        let src = (current_root_virt as *const u64).wrapping_add(256);
        let dst = (new_root_virt as *mut u64).wrapping_add(256);

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
    /// terminal-fault record ([`crate::sched::record_aspace_terminal_fault`]),
    /// so a fault concurrent with a bind is delivered exactly once and never
    /// dropped — closing the bind-after-fault window for an observer bound after
    /// the space was already running.
    ///
    /// Returns `Ok(None)` if `node` was linked, holding a reference on `eq`
    /// that the address space's teardown releases
    /// ([`Self::take_death_observers`]); `Ok(Some(reason))` if the space
    /// already faulted (the caller posts `reason` to `eq` and returns `node`
    /// to its pool; no reference is taken); `Err(OutOfMemory)` if `node` is
    /// null (the queue had no free node) and the space has not faulted; or
    /// `Err(QuotaExceeded)` if `eq`'s reference count is at its limit.
    ///
    /// # Safety
    /// `this` must be a valid `AddressSpace` pointer and `eq` a live
    /// `EventQueueObject` the caller pins for the call; `node` must be null or
    /// a node of `eq`'s pool on no list. The caller must NOT hold
    /// `death_lock`.
    #[cfg(not(test))]
    pub unsafe fn bind_or_retained(
        this: *mut Self,
        eq: *mut crate::cap::object::EventQueueObject,
        node: *mut crate::sched::thread::DeathObserver,
        correlator: u64,
    ) -> Result<Option<u64>, syscall::SyscallError>
    {
        // SAFETY: this validated by caller.
        let death_lock = unsafe { &(*this).death_lock };
        // SAFETY: lock_raw is paired with an unlock_raw on every path.
        let saved = unsafe { death_lock.lock_raw() };
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access reads a terminal-fault field of this, which the held death_lock \
                      serialises"
        )]
        // SAFETY: terminal_faulted/terminal_fault_reason read under death_lock.
        let (faulted, reason) =
            unsafe { ((*this).terminal_faulted, (*this).terminal_fault_reason) };
        let result = if faulted
        {
            Ok(Some(reason))
        }
        else if node.is_null()
        {
            Err(syscall::SyscallError::OutOfMemory)
        }
        else
        {
            // The binding's reference is checked against REF_COUNT_LIMIT, as
            // the thread bind's is, and taken while the caller's pin holds
            // `eq`.
            // SAFETY: eq is a live EventQueueObject the caller pins (contract).
            let referenced = unsafe { (*eq).header.try_inc_ref() };
            referenced.map(|()| {
                // SAFETY: node is eq's and unlinked (contract); death_lock is
                // held.
                unsafe { (*node).correlator = correlator };
                // SAFETY: this validated by caller; death_observers is
                // serialised by the held death_lock.
                let chain = unsafe { &mut (*this).death_observers };
                // SAFETY: node is valid and on no list (contract), and the
                // reference just taken keeps its queue, which holds it, alive
                // for its membership; death_lock is held.
                unsafe { chain.push(node) };
                None
            })
        };
        // SAFETY: paired with the lock_raw above.
        unsafe { death_lock.unlock_raw(saved) };
        result
    }

    /// Record a terminal fault (first fault wins) and return the first node of
    /// the observer chain, read under `death_lock`. The terminal-fault post
    /// walks the chain from it outside the lock, after the faulting thread's
    /// `Exited` commit (a linked node's links never change until the teardown
    /// takes the chain); recording the reason lets `retained_terminal_fault`
    /// read it back and a later `bind_or_retained` deliver it to an observer
    /// bound after the fault, and stops any further link.
    ///
    /// # Safety
    /// `this` must be a valid `AddressSpace` pointer. The caller must NOT hold
    /// `death_lock`.
    #[cfg(not(test))]
    pub unsafe fn record_fault_and_snapshot(
        this: *mut Self,
        reason: u64,
    ) -> *mut crate::sched::thread::DeathObserver
    {
        // SAFETY: this validated by caller.
        let death_lock = unsafe { &(*this).death_lock };
        // SAFETY: lock_raw paired with the unlock_raw below.
        let saved = unsafe { death_lock.lock_raw() };
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access is to a terminal-fault field or the observer chain of this, \
                      which the held death_lock serialises"
        )]
        // SAFETY: this validated by caller; fields read and written under
        // death_lock.
        let first = unsafe {
            if !(*this).terminal_faulted
            {
                (*this).terminal_faulted = true;
                (*this).terminal_fault_reason = reason;
            }
            (*this).death_observers.first()
        };
        // SAFETY: paired with the lock_raw above.
        unsafe { death_lock.unlock_raw(saved) };
        first
    }

    /// The retained terminal-fault reason (`EXIT_FAULT_BASE + vector`), or
    /// `None` while no thread of this address space has taken a terminal
    /// fault. Read under `death_lock`, so it never sees the flag without its
    /// reason. Backs `SYS_CAP_INFO`'s `CAP_INFO_ASPACE_TERMINAL_FAULT`.
    ///
    /// # Safety
    /// `this` must be a valid `AddressSpace` pointer. The caller must NOT hold
    /// `death_lock`.
    #[cfg(not(test))]
    pub unsafe fn retained_terminal_fault(this: *const Self) -> Option<u64>
    {
        // SAFETY: this validated by caller.
        let death_lock = unsafe { &(*this).death_lock };
        // SAFETY: lock_raw paired with the unlock_raw below.
        let saved = unsafe { death_lock.lock_raw() };
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access reads a terminal-fault field of this, which the held death_lock \
                      serialises"
        )]
        // SAFETY: this validated by caller; fields read under death_lock.
        let retained = unsafe {
            (*this)
                .terminal_faulted
                .then_some((*this).terminal_fault_reason)
        };
        // SAFETY: paired with the lock_raw above.
        unsafe { death_lock.unlock_raw(saved) };
        retained
    }

    /// Empty the observer chain for the address space's teardown, returning
    /// its first node; the caller now owns every node reachable from it and
    /// the `EventQueueObject` reference each holds, and MUST return each node
    /// and release each reference.
    ///
    /// # Safety
    /// `this` must be a valid `AddressSpace` whose teardown is running: no
    /// capability, binding, or bound thread reaches it any more, so no bind
    /// or terminal-fault post can race the call. The caller must NOT hold
    /// `death_lock`.
    #[cfg(not(test))]
    pub unsafe fn take_death_observers(this: *mut Self)
    -> *mut crate::sched::thread::DeathObserver
    {
        // SAFETY: this is valid (contract).
        let death_lock = unsafe { &(*this).death_lock };
        // SAFETY: lock_raw paired with the unlock_raw below; death_lock is
        // taken for the field-ownership rule though nothing can contend it
        // here.
        let saved = unsafe { death_lock.lock_raw() };
        // SAFETY: this is valid; the chain is taken under death_lock.
        let taken = unsafe { (*this).death_observers.take() };
        // SAFETY: paired with the lock_raw above.
        unsafe { death_lock.unlock_raw(saved) };
        taken
    }

    /// Map `virt` → `phys` as a 4 KiB page with the given permission flags,
    /// whose [`LeafGrant`](crate::mm::paging::LeafGrant) is those flags: no
    /// capability installed the leaf, so no permission change widens it.
    ///
    /// Acquires `pt_lock`, draws missing intermediate page-table frames
    /// from [`crate::mm::kernel_pt_pool`] (seeded at Phase 7), flushes the local
    /// TLB, and sends remote TLB shootdown IPIs only when the rewrite can strand
    /// a dangerous stale entry (see the module's Concurrency note and
    /// `core/kernel/docs/memory-internals.md` § SMP TLB Shootdown). A fresh map into
    /// a previously-unmapped VA skips the remote shootdown.
    ///
    /// Used by:
    /// - [`map_segment`](Self::map_segment) and the Phase 9 init bootstrap
    ///   (image, `InitInfo`, stack) — PT pages come from `kernel_pt_pool`.
    /// - The map syscalls go through [`map_page_pooled`](Self::map_page_pooled):
    ///   every address space records its create-time donation before it is
    ///   published (`AddressSpaceObject::require_create_donation`).
    ///
    /// # Safety
    /// `virt` must be in the user half of the active paging mode (see
    /// `docs/memory-model.md` § Virtual Address Space Layout). `phys` must be
    /// a valid 4 KiB-aligned physical address.
    #[cfg(not(test))]
    pub unsafe fn map_page(
        &self,
        virt: u64,
        phys: u64,
        flags: crate::mm::paging::PageFlags,
    ) -> Result<(), ()>
    {
        use crate::arch::current::paging::{flush_page, map_user_page, translate_user_page};

        // Count the new leaf before it is installed
        // (core/kernel/docs/memory-internals.md § Frame Map Table).
        crate::mm::frame_map::raise(phys)?;
        crate::percpu::preempt_disable();
        self.pt_lock();

        // SAFETY: root_virt is valid; virt is in user range; pt_lock is held,
        // so the translation sees the leaf the map below replaces.
        let prior = unsafe { translate_user_page(self.root_virt, virt) }.map(|(p, _)| p);
        // Intermediate page table frames are drawn from
        // `mm::kernel_pt_pool` (seeded once at Phase 7 with `POOL_SEED_PAGES`
        // from the pristine buddy). No buddy lock is taken on this path; the
        // pool lock nests under `pt_lock` (see the module's Concurrency note).
        let grant = crate::mm::paging::LeafGrant::of(flags);
        // SAFETY: contract passed to caller; root_virt is valid; virt is
        // in user range; phys is a valid 4 KiB-aligned physical address.
        let Ok(outcome) = (unsafe { map_user_page(self.root_virt, virt, phys, flags, grant) })
        else
        {
            self.pt_unlock();
            crate::percpu::preempt_enable();
            crate::mm::frame_map::lower(phys);
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
        if let Some(prior) = prior
        {
            crate::mm::frame_map::lower(prior);
        }

        Ok(())
    }

    /// Pooled variant of [`map_page`]: draws intermediate PT frames from
    /// the supplied [`AddressSpaceObject`](crate::cap::object::AddressSpaceObject)'s
    /// growth pool instead of the kernel page-table pool, and records `grant`,
    /// the Write and Execute rights of the capability the map syscall named,
    /// in the leaf.
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
        grant: crate::mm::paging::LeafGrant,
        aso: &crate::cap::object::AddressSpaceObject,
    ) -> Result<(), ()>
    {
        use crate::arch::current::paging::{flush_page, map_user_page_pooled, translate_user_page};

        // Count the new leaf before it is installed, as `map_page` does.
        crate::mm::frame_map::raise(phys)?;
        crate::percpu::preempt_disable();
        self.pt_lock();

        // SAFETY: as in `map_page`.
        let prior = unsafe { translate_user_page(self.root_virt, virt) }.map(|(p, _)| p);
        // SAFETY: caller's contract; aso pairs with this AS.
        let Ok(outcome) =
            (unsafe { map_user_page_pooled(self.root_virt, virt, phys, flags, grant, aso) })
        else
        {
            self.pt_unlock();
            crate::percpu::preempt_enable();
            crate::mm::frame_map::lower(phys);
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
        if let Some(prior) = prior
        {
            crate::mm::frame_map::lower(prior);
        }

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
    /// # Errors
    /// `Err` when a page fails to map, or when the segment's virtual or
    /// physical pages pass the end of the address space.
    ///
    /// # Safety
    /// `segment` must be a valid, bootloader-provided `InitSegment`.
    #[cfg(not(test))]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the u64→usize in-page offset (at most 0xFFF) and segment size (an init ELF \
                  segment, bounded by the user address-space size) feed the page-count arithmetic"
    )]
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
        // A segment whose pages pass the end of the address space is
        // malformed, and fails.
        let in_page_off = (segment.virt_addr & 0xFFF) as usize;
        let page_count = in_page_off
            .checked_add(segment.size as usize)
            .ok_or(())?
            .div_ceil(PAGE_SIZE)
            .max(1);
        let virt_base = segment.virt_addr & !0xFFFu64; // page-aligned virtual
        let phys_base = segment.phys_addr & !0xFFFu64; // page-aligned physical frame
        let virts = span_pages(virt_base, page_count).ok_or(())?;
        let physes = span_pages(phys_base, page_count).ok_or(())?;
        for (virt, phys) in virts.zip(physes)
        {
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
        use crate::arch::current::paging::{flush_page, translate_user_page, unmap_user_page};

        crate::percpu::preempt_disable();
        self.pt_lock();

        // SAFETY: root_virt is valid; virt is in user range (caller's
        // contract); pt_lock is held, so this is the leaf the unmap clears.
        let prior = unsafe { translate_user_page(self.root_virt, virt) }.map(|(p, _)| p);
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
        // Every CPU has dropped the leaf, so the frame's count may fall
        // (core/kernel/docs/memory-internals.md § Frame Map Table).
        if let Some(prior) = prior
        {
            crate::mm::frame_map::lower(prior);
        }
    }

    /// Unmap each of the `page_count` pages from `virt_base` that still maps
    /// the matching page of the physical span from `phys_base`, leaving any
    /// page the user has since unmapped or remapped to other memory in place,
    /// then invalidate the span's TLB entries on every CPU that runs this
    /// address space. Returns the number of pages unmapped.
    ///
    /// Withdraws a `SYS_MMIO_MAP` mapping when its `Mmio` object is freed
    /// (`MmioObject::withdraw_mappings`). Intermediate page tables stay, as with
    /// [`unmap_page`](Self::unmap_page). The span takes one invalidation, per
    /// page up to `RANGE_FLUSH_CEILING_PAGES` and a full flush above, issued
    /// after `pt_lock` is released, and one more under `pt_lock` each time the
    /// cleared frames overflow the frame-map release batch
    /// ([`batch_cleared_frame`](Self::batch_cleared_frame)); the unmapped frames
    /// are device memory the kernel never reallocates, so no reuse waits on the
    /// shootdown.
    ///
    /// # Safety
    /// The span `[virt_base, virt_base + page_count * PAGE_SIZE)` must lie in
    /// the user half and `virt_base` must be page-aligned.
    #[cfg(not(test))]
    pub unsafe fn unmap_region_if_phys(
        &self,
        virt_base: u64,
        page_count: usize,
        phys_base: u64,
    ) -> usize
    {
        use crate::arch::current::paging::{translate_user_page, unmap_user_page};

        // A physical span past the end of the address space maps nowhere; the
        // virtual one is in the user half (contract).
        let (Some(virts), Some(physes)) = (
            span_pages(virt_base, page_count),
            span_pages(phys_base, page_count),
        )
        else
        {
            return 0;
        };
        if page_count == 0
        {
            return 0;
        }

        crate::percpu::preempt_disable();
        self.pt_lock();
        let mut unmapped = 0usize;
        let mut batch = crate::mm::frame_map::ReleaseBatch::new();
        for (virt, phys) in virts.zip(physes)
        {
            // SAFETY: root_virt is valid; virt is in user range (caller's
            // contract); pt_lock is held, so the translation and the unmap see
            // the same entry.
            let mapped = unsafe { translate_user_page(self.root_virt, virt) };
            if mapped.is_some_and(|(p, _)| p == phys)
            {
                // SAFETY: as for the translation above, under the same
                // pt_lock hold.
                unsafe { unmap_user_page(self.root_virt, virt) };
                // At most page_count, so the count never saturates.
                unmapped = unmapped.saturating_add(1);
                self.batch_cleared_frame(&mut batch, phys, virt_base, page_count);
            }
        }
        self.pt_unlock();
        if unmapped != 0
        {
            self.invalidate_unmapped_span(virt_base, page_count);
        }
        crate::percpu::preempt_enable();
        batch.release_into(&crate::mm::frame_map::FRAME_MAP);
        unmapped
    }

    /// Add the frame of a leaf just cleared from the span `[virt_base, +
    /// page_count pages)` to `batch`, whose counts are lowered once the
    /// clearing walk's TLB invalidation completes
    /// (core/kernel/docs/memory-internals.md § Frame Map Table). A full batch is
    /// first drained behind an invalidation of the whole span on every CPU that
    /// runs this address space, which covers every leaf cleared so far.
    ///
    /// Must run with preemption disabled.
    #[cfg(not(test))]
    fn batch_cleared_frame(
        &self,
        batch: &mut crate::mm::frame_map::ReleaseBatch,
        phys: u64,
        virt_base: u64,
        page_count: usize,
    )
    {
        if !batch.push(phys)
        {
            self.invalidate_unmapped_span(virt_base, page_count);
            batch.release_into(&crate::mm::frame_map::FRAME_MAP);
            let _ = batch.push(phys);
        }
    }

    /// Lower the frame-map count of every frame this address space's user half
    /// still maps (core/kernel/docs/memory-internals.md § Frame Map Table).
    /// Leaves the page tables as they are.
    ///
    /// Run by the `AddressSpace` teardown once no CPU has the space loaded and
    /// every bound thread is stopped, so no leaf can be used again: the tag is
    /// flushed before any later space runs under it.
    ///
    /// # Safety
    /// The address space is being reclaimed: no CPU has it active, no thread
    /// can run in it, and nothing maps or unmaps in it any more.
    #[cfg(not(test))]
    pub unsafe fn release_mapped_frames(&self)
    {
        // SAFETY: root_virt is this space's valid root; nothing modifies its
        // tables during the walk (contract).
        unsafe {
            crate::arch::current::paging::for_each_user_leaf(self.root_virt, &mut |phys| {
                crate::mm::frame_map::lower(phys);
            });
        }
    }

    /// Invalidate the TLB entries of `[virt_base, + page_count pages)` on this
    /// CPU, if it runs this address space, and on every other CPU that does,
    /// after leaf entries in the span were cleared. It covers the cleared
    /// leaves' translations only: a caller that freed page tables owns the
    /// paging-structure-cache flush (`unmap_region_pooled`'s closing coarse
    /// shootdown). Per page up to `RANGE_FLUSH_CEILING_PAGES`, a full flush
    /// above.
    ///
    /// Must run with preemption disabled.
    #[cfg(not(test))]
    fn invalidate_unmapped_span(&self, virt_base: u64, page_count: usize)
    {
        use crate::arch::current::paging::{
            flush_tlb_all, inval_batch_begin, inval_batch_end, inval_page,
        };

        // Initiator side of the tlb_gen / active_cpus Dekker exclusion, as in
        // `shootdown_remote` (core/kernel/docs/memory-internals.md § SMP TLB
        // Shootdown).
        if crate::mm::tag_allocator::tagging_enabled()
        {
            self.tlb_gen.fetch_add(1, Ordering::Release);
            core::sync::atomic::fence(Ordering::SeqCst);
        }
        // The span's pages when it is flushed page by page; a span that passes
        // the end of the address space, which no caller passes, takes the full
        // flush.
        let ranged = span_pages(virt_base, page_count)
            .filter(|_| page_count <= crate::mm::tlb_shootdown::RANGE_FLUSH_CEILING_PAGES);
        let current = crate::arch::current::cpu::current_cpu() as usize;
        if self.active_cpus.test_cpu(current, Ordering::Acquire)
        {
            if let Some(pages) = ranged.clone()
            {
                // SAFETY: ring 0 / S-mode; opens the batch window the per-VA
                // invalidations below are bracketed by.
                unsafe { inval_batch_begin() };
                for virt in pages
                {
                    // SAFETY: ring 0 / S-mode, inside the batch window; it
                    // clears a cleared leaf's translation, and a caller that
                    // freed page tables flushes the paging-structure caches
                    // itself (rustdoc above).
                    unsafe { inval_page(virt) };
                }
                // SAFETY: ring 0 / S-mode; closes the batch window opened
                // above.
                unsafe { inval_batch_end() };
            }
            else
            {
                // SAFETY: ring 0 / S-mode; a full flush clears every
                // translation.
                unsafe { flush_tlb_all() };
            }
        }
        let remote = MaskSource::Mask(&self.active_cpus, Ordering::Acquire);
        if ranged.is_some()
        {
            // SAFETY: root_phys is a valid root; the shootdown leaves current
            // out of remote and returns at once when nothing else is active;
            // preemption is disabled (contract). Tag 0 is the untagged path,
            // correct cross-AS (see the Dekker exclusion above).
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
            // SAFETY: as the range branch; the full-flush sentinel ignores the
            // tag, correct cross-AS.
            unsafe { crate::mm::tlb_shootdown::shootdown(self.root_phys, &remote, u64::MAX, 0) };
        }
    }

    /// Unmap `page_count` pages from `[virt_base, ..)` and reclaim every
    /// intermediate page table the cleared span leaves empty back to `aso`'s
    /// growth pool (crediting `pt_growth_budget_bytes`). Returns the number of
    /// page-table frames reclaimed.
    ///
    /// Drives `SYS_MEM_UNMAP` with `MEM_UNMAP_RECLAIM_PTS` (memmgr region
    /// teardown). Unlike the per-page [`unmap_page`](Self::unmap_page), it tears
    /// the whole span down under a single `pt_lock` hold and a single coarse
    /// TLB and paging-structure-cache shootdown, plus one span invalidation
    /// under `pt_lock` each time the cleared frames overflow the frame-map
    /// release batch (core/kernel/docs/memory-internals.md § Frame Map Table).
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

        if page_count == 0
        {
            return 0;
        }

        crate::percpu::preempt_disable();
        self.pt_lock();

        // Clear every leaf in the span and free each now-empty intermediate
        // table whose parent entry carries the pooled-table bit back to the
        // pool, batching each cleared frame for its frame-map release.
        let mut batch = crate::mm::frame_map::ReleaseBatch::new();
        // SAFETY: root_virt is valid; aso wraps this AS; the span is user-range
        // (caller's contract); pt_lock is held.
        let freed = unsafe {
            unmap_user_region_pooled(self.root_virt, virt_base, page_count, aso, &mut |phys| {
                self.batch_cleared_frame(&mut batch, phys, virt_base, page_count);
            })
        };

        // ONE coarse shootdown closes the teardown (the batch drains add span
        // invalidations, also under pt_lock), performed UNDER pt_lock
        // (the per-VA `unmap_page` drops the lock first for throughput; here it
        // must stay held). A freed PT frame is poppable only via `alloc_pt_page`,
        // which runs under THIS `pt_lock`, so no other CPU reuses a just-freed
        // frame until we release — by then every CPU's TLB + paging-structure
        // cache is clean. The contended `pt_lock` path enables interrupts while
        // spinning, so a remote CPU waiting on this lock still services and acks
        // our IPI: no deadlock.
        // Initiator side of the tlb_gen / active_cpus Dekker exclusion (see
        // core/kernel/docs/memory-internals.md § SMP TLB Shootdown): bump tlb_gen
        // and fence BEFORE snapshotting active_cpus (the same order as
        // `shootdown_remote`). This guarantees that for any CPU caching this
        // space, either it is in the snapshot below (gets the IPI) or it observes
        // the bumped tlb_gen on its next reactivation (flushes the tag then).
        // Snapshotting first would leave a CPU that activates concurrently in
        // neither cover. The same argument covers both invalidation shapes below:
        // spans at or under `RANGE_FLUSH_CEILING_PAGES` issue an untagged
        // per-page range flush (batched: riscv64 Svinval bracket), larger spans a
        // full flush. The range form is used only when it also clears the
        // paging-structure caches for any table frame the teardown freed: always
        // where a per-VA invalidation drops them (`VA_INVAL_DROPS_TABLE_CACHES`,
        // x86-64 `invlpg`), otherwise only when no table was freed. A RISC-V
        // VA-form fence need only drop leaf entries, so a freed table frame there
        // takes the full flush.
        if crate::mm::tag_allocator::tagging_enabled()
        {
            self.tlb_gen.fetch_add(1, Ordering::Release);
            core::sync::atomic::fence(Ordering::SeqCst);
        }
        let current = crate::arch::current::cpu::current_cpu() as usize;
        // The span's pages when it is flushed page by page; a span that passes
        // the end of the address space, outside the contract, takes the full
        // flush.
        let ranged = span_pages(virt_base, page_count).filter(|_| {
            page_count <= crate::mm::tlb_shootdown::RANGE_FLUSH_CEILING_PAGES
                && (freed == 0 || crate::arch::current::paging::VA_INVAL_DROPS_TABLE_CACHES)
        });
        // Only CPUs that run this AS cache its translations — the kernel edits
        // these page tables through the direct map, never by loading this root.
        // The caller is normally memmgr, which does not run the target AS, so
        // the local flush is usually skipped.
        if self.active_cpus.test_cpu(current, Ordering::Acquire)
        {
            if let Some(pages) = ranged.clone()
            {
                use crate::arch::current::paging::{
                    inval_batch_begin, inval_batch_end, inval_page,
                };
                // SAFETY: ring 0 / S-mode; opens the batch window the per-VA
                // invalidations below are bracketed by.
                unsafe { inval_batch_begin() };
                for virt in pages
                {
                    // SAFETY: ring 0 / S-mode, inside the batch window; clears
                    // the TLB entries for virt, and the paging-structure-cache
                    // entries too where `VA_INVAL_DROPS_TABLE_CACHES`;
                    // elsewhere `ranged` implies no table was freed.
                    unsafe { inval_page(virt) };
                }
                // SAFETY: ring 0 / S-mode; closes the batch window opened
                // above.
                unsafe { inval_batch_end() };
            }
            else
            {
                // SAFETY: ring 0 / S-mode; full flush clears TLB + PS-caches.
                unsafe { flush_tlb_all() };
            }
        }
        let remote = MaskSource::Mask(&self.active_cpus, Ordering::Acquire);
        if ranged.is_some()
        {
            // SAFETY: root_phys is a valid root; the shootdown leaves
            // current out of remote and returns at once when nothing else
            // is active;
            // preempt is held and pt_lock no-pop invariant holds; tag 0 is
            // the untagged path (see the Dekker exclusion comment above for
            // why that is sufficient here).
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

        self.pt_unlock();
        crate::percpu::preempt_enable();
        // The shootdown above covers every leaf the walk cleared.
        batch.release_into(&crate::mm::frame_map::FRAME_MAP);
        freed
    }

    /// Change the permission flags on an existing 4 KiB leaf mapping at `virt`.
    ///
    /// Returns `Err(PagingError::NotMapped)` if `virt` is not mapped, and
    /// `Err(PagingError::NotGranted)`, changing nothing, if `flags` asks for
    /// write or execute beyond the leaf's
    /// [`LeafGrant`](crate::mm::paging::LeafGrant); the check and the rewrite
    /// run under `pt_lock`. Caller is responsible for W^X and the rights of
    /// the capability the call names.
    /// Flushes the local TLB; a permission narrow also shoots down every other
    /// CPU where this address space is active, while a widen skips the remote
    /// shootdown (`core/kernel/docs/memory-internals.md` § SMP TLB Shootdown).
    ///
    /// # Safety
    /// `virt` must be in the user half. It need not be mapped: a concurrent
    /// unmap can remove the page at any time, and the mapping is checked
    /// under `pt_lock` as described above.
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

    /// Copy between the user range `[va, va + len)` of this address space and
    /// a kernel buffer through the kernel's direct map, for
    /// `SYS_THREAD_READ_MEM` and `SYS_THREAD_WRITE_MEM`; `len` is the
    /// buffer's. All or nothing: under `pt_lock` every page of the range is
    /// checked first, then copied, so an unmap or remap, which takes the same
    /// lock, cannot run between the check and the copy, and the frames stay
    /// mapped (and so unfreed) until the copy ends.
    ///
    /// Each page must be mapped by a 4 KiB user leaf of normal memory below
    /// the top of RAM ([`thread_mem_page_check`]); a
    /// write needs the leaf writable, or [`TextWrite::Permitted`] with a
    /// grant of write or execute and the frame mapped once
    /// ([`thread_mem_write_check`]). The thread's own access
    /// rights do not gate a read, so an execute-only page reads. A write's
    /// caller synchronises instruction fetch afterwards, whatever the leaves
    /// grant: a writable page's frame may be mapped executable elsewhere.
    ///
    /// # Errors
    /// - `InvalidAddress`: a page is unmapped, mapped by no 4 KiB user leaf,
    ///   device memory (an uncacheable leaf; its frame need not be RAM the
    ///   direct map covers), or a frame at or above the top of RAM.
    /// - `InsufficientRights`, `InvalidState`: a write the leaf refuses
    ///   ([`thread_mem_write_check`]).
    ///
    /// # Safety
    /// The address space must stay allocated for the call (the caller holds
    /// a reference on its object), and `[va, va + len)` must lie in the user
    /// half. The caller holds no `pt_lock` and no lock a shootdown IPI's
    /// handler takes.
    #[cfg(not(test))]
    pub unsafe fn copy_user_bytes(
        &self,
        va: u64,
        mut copy: UserCopy<'_>,
    ) -> Result<(), SyscallError>
    {
        use crate::arch::current::paging::{translate_user_page, user_leaf_flags, user_leaf_grant};

        let (len, write) = match &copy
        {
            UserCopy::Read(dst) => (dst.len(), None),
            UserCopy::Write { src, text } => (src.len(), Some(*text)),
        };
        let ram_top = crate::mm::init::ram_top();
        crate::percpu::preempt_disable();
        self.pt_lock();
        let checked = (|| {
            for span in page_spans(va, len)
            {
                // SAFETY: root_virt is the valid root; pt_lock is held, so no
                // concurrent walk edits the tables.
                let (phys, pte) = unsafe { translate_user_page(self.root_virt, span.page) }
                    .ok_or(SyscallError::InvalidAddress)?;
                let flags = user_leaf_flags(pte).ok_or(SyscallError::InvalidAddress)?;
                thread_mem_page_check(flags, phys, ram_top)?;
                if let Some(text) = write
                {
                    thread_mem_write_check(flags, user_leaf_grant(pte), text, || {
                        crate::mm::frame_map::mappings_in(phys, PAGE_SIZE as u64)
                    })?;
                }
            }
            Ok(())
        })();
        if checked.is_ok()
        {
            for span in page_spans(va, len)
            {
                // SAFETY: as above; the check pass found every page mapped
                // under this hold, so the translation repeats.
                let Some((phys, _)) = (unsafe { translate_user_page(self.root_virt, span.page) })
                else
                {
                    continue;
                };
                let frame = phys_to_virt(phys) as *mut u8;
                // The check pass found the frame's leaf write-back and the
                // frame below the top of RAM (thread_mem_page_check). A
                // write-back user leaf names normal memory (a Memory
                // capability's frame, or RAM the kernel mapped for init):
                // SYS_MMIO_MAP installs device frames uncacheable, and
                // protect_user_page keeps a leaf's memory type. The direct map
                // covers every frame below the top of RAM but the kernel's
                // stack guard pages, which no user leaf maps, so `frame` is a
                // mapped write-back alias of it. The frame is mapped in this
                // space, which pt_lock keeps mapped and so unfreed;
                // in_page + n <= PAGE_SIZE, and the buffer offset + n <= len,
                // by page_spans.
                match &mut copy
                {
                    UserCopy::Read(dst) =>
                    {
                        // SAFETY: in_page < PAGE_SIZE (page_spans), so the
                        // offset stays in the frame's page.
                        let from = unsafe { frame.add(span.in_page) };
                        // SAFETY: offset + n <= len, the buffer's length
                        // (page_spans), so the offset stays in dst.
                        let to = unsafe { dst.as_mut_ptr().add(span.offset) };
                        // SAFETY: from is n readable bytes of the mapped,
                        // unfreed write-back frame and to n writable bytes of
                        // dst (above).
                        unsafe { core::ptr::copy_nonoverlapping(from.cast_const(), to, span.len) };
                    }
                    UserCopy::Write { src, .. } =>
                    {
                        // SAFETY: offset + n <= len, the buffer's length
                        // (page_spans), so the offset stays in src.
                        let from = unsafe { src.as_ptr().add(span.offset) };
                        // SAFETY: in_page < PAGE_SIZE (page_spans), so the
                        // offset stays in the frame's page.
                        let to = unsafe { frame.add(span.in_page) };
                        // SAFETY: from is n readable bytes of src and to n
                        // writable bytes of the mapped, unfreed write-back
                        // frame (above).
                        unsafe { core::ptr::copy_nonoverlapping(from, to, span.len) };
                    }
                }
            }
        }
        self.pt_unlock();
        crate::percpu::preempt_enable();
        checked
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
    /// space cannot be selected as its own eviction victim and so the Dekker
    /// fence below has an active-bit store to order against (see
    /// `core/kernel/docs/memory-internals.md` § Context Switch TLB Handling).
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

        // The scheduler published this CPU's active bit (Release) before calling.
        // This fence orders that store before the tag/generation reads below,
        // forming the activate side of the unmap and eviction Dekker exclusions
        // (paired with the SeqCst fences in `shootdown_remote`,
        // `unmap_region_pooled`, and `tag_allocator::claim`'s eviction; see
        // core/kernel/docs/memory-internals.md § SMP TLB Shootdown). Without it a
        // CPU could miss an unmap that did not IPI it and later run a stale
        // tagged translation.
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
            unsafe { flush_tag(tag) };
            // SAFETY: as for tag_state above: the per-CPU slab is initialised;
            // cpu is the current CPU and < cpu_count; tag < num_tags.
            unsafe { tag_allocator::set_tag_state(cpu, tag, tag_gen, tlb_gen) };
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
    /// active, so TLB shootdown sees a consistent view when it reads the set.
    pub fn mark_active_on_cpu(&self, cpu: u32)
    {
        // Release ordering ensures prior address space setup (page
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
        // Release ordering ensures all TLB-dependent operations
        // complete before we mark inactive, so TLB shootdowns see the correct
        // mask. The clear_cpu is atomic; no data race on the mask.
        self.active_cpus.clear_cpu(cpu as usize, Ordering::Release);
    }

    /// Whether no CPU has this address space active.
    ///
    /// # Memory Ordering
    /// Uses Acquire ordering: ensures we observe all prior `mark_inactive_on_cpu`
    /// calls from other CPUs, so an empty result means every CPU has switched
    /// away.
    pub(crate) fn inactive_everywhere(&self) -> bool
    {
        self.active_cpus.is_empty(Ordering::Acquire)
    }

    /// Point the active-CPU set of the address space at `this` at the
    /// [`crate::cpu_mask::mask_words`] words right after it, and empty it.
    ///
    /// It takes a raw pointer, not `&mut self`: the words lie past the struct,
    /// so the pointer to them must carry the wrapper page's provenance, which a
    /// reference to the struct alone does not.
    ///
    /// # Safety
    /// `this` points to an initialised `AddressSpace` that lies in its wrapper
    /// page with nothing after it, so the page holds the words
    /// ([`ACTIVE_CPU_WORDS_FIT`]); `this` is derived from the page's own
    /// pointer, so its provenance covers the whole page; nothing else
    /// references the address space; called once, before any CPU marks the
    /// space active.
    pub(crate) unsafe fn attach_active_cpus(this: *mut Self)
    {
        // SAFETY: caller contract: one past the struct is still inside the
        // wrapper page, whose provenance `this` carries, and is the first of
        // the words reserved for this set; it is 8-byte aligned (the struct's
        // alignment and size are multiples of 8, asserted with
        // ACTIVE_CPU_WORDS_FIT).
        let after = unsafe { this.add(1) }.cast::<AtomicU64>();
        // SAFETY: caller contract: `this` is valid, so the projection stays in
        // its allocation.
        let field = unsafe { core::ptr::addr_of_mut!((*this).active_cpus) };
        // SAFETY: caller contract: the mask_words() words at `after` lie in the
        // wrapper page, 8-byte aligned (above), and belong to this set alone.
        let mask = unsafe { AtomicCpuMask::attach(after, crate::cpu_mask::mask_words()) };
        // SAFETY: caller contract: `this` is valid for writes and nothing else
        // references it.
        unsafe { field.write(mask) };
    }
}

/// Whether an address space's wrapper page holds, after the `AddressSpaceObject`
/// that starts it, the `AddressSpace` and its active-CPU set at the widest
/// boot, `MAX_CPUS` CPUs.
pub(crate) const ACTIVE_CPU_WORDS_FIT: bool = core::mem::size_of::<
    crate::cap::object::AddressSpaceObject,
>() + core::mem::size_of::<AddressSpace>()
    + crate::cpu_mask::MAX_MASK_WORDS * core::mem::size_of::<AtomicU64>()
    <= PAGE_SIZE
    && core::mem::align_of::<AddressSpace>() >= core::mem::align_of::<AtomicU64>()
    && core::mem::size_of::<AddressSpace>().is_multiple_of(core::mem::align_of::<AtomicU64>());

const _: () = assert!(
    ACTIVE_CPU_WORDS_FIT,
    "the AddressSpace wrapper page cannot hold the active-CPU set at MAX_CPUS"
);

#[cfg(test)]
mod active_cpu_words_tests
{
    use super::*;

    // Defect caught: an AddressSpace or wrapper object that grows until the
    // active-CPU set at the widest boot no longer fits the wrapper page, so
    // the set's words overrun the page.
    #[test]
    fn the_wrapper_page_holds_the_address_space_and_its_set_at_max_cpus()
    {
        let used = core::mem::size_of::<crate::cap::object::AddressSpaceObject>()
            + core::mem::size_of::<AddressSpace>()
            + crate::cpu_mask::words_for(crate::sched::MAX_CPUS)
                * core::mem::size_of::<AtomicU64>();
        assert!(used <= PAGE_SIZE, "{used} bytes of the wrapper page");
    }
}

#[cfg(test)]
mod thread_mem_tests
{
    use super::*;

    // Defect caught: a split that loses a byte at a page boundary, gives a
    // span past its page, or misplaces it in the buffer, so a copy reads or
    // writes beyond a frame or leaves part of the range uncopied.
    #[test]
    fn page_spans_cover_the_range_once_and_stay_in_their_pages()
    {
        let page = PAGE_SIZE as u64;
        let spans: Vec<PageSpan> = page_spans(page + 10, 20).collect();
        assert_eq!(
            spans,
            [PageSpan {
                page,
                in_page: 10,
                offset: 0,
                len: 20
            }]
        );
        let spans: Vec<PageSpan> = page_spans(2 * page - 3, PAGE_SIZE).collect();
        assert_eq!(
            spans,
            [
                PageSpan {
                    page,
                    in_page: PAGE_SIZE - 3,
                    offset: 0,
                    len: 3
                },
                PageSpan {
                    page: 2 * page,
                    in_page: 0,
                    offset: 3,
                    len: PAGE_SIZE - 3
                },
            ]
        );
        let spans: Vec<PageSpan> = page_spans(3 * page, PAGE_SIZE).collect();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].len, PAGE_SIZE);
        assert_eq!(page_spans(page, 0).count(), 0);
        // A range past the end of the address space stops at its end.
        let spans: Vec<PageSpan> = page_spans(u64::MAX - 1, 4).collect();
        assert_eq!(
            spans,
            [PageSpan {
                page: !(page - 1),
                in_page: PAGE_SIZE - 2,
                offset: 0,
                len: 1
            }]
        );
    }

    // Defect caught: a page list that misses or repeats a page, or one that
    // wraps past the end of the address space into low addresses.
    #[test]
    fn span_pages_lists_each_page_once_and_refuses_a_wrapping_span()
    {
        let page = PAGE_SIZE as u64;
        let pages: Vec<u64> = span_pages(4 * page, 3).unwrap().collect();
        assert_eq!(pages, [4 * page, 5 * page, 6 * page]);
        assert_eq!(span_pages(page, 0).unwrap().count(), 0);
        assert!(span_pages(!(page - 1), 1).is_none());
        assert!(span_pages(0, usize::MAX).is_none());
    }

    // Defect caught: a text write that skips the flag or the shared-frame
    // check would let a debugger change another process's text through a
    // frame both map, and a check run on writable pages would refuse a
    // write to shared memory the thread could make itself.
    #[test]
    fn a_read_only_page_takes_a_write_only_with_text_and_one_mapping()
    {
        let leaf = |writable| crate::mm::paging::PageFlags {
            readable: true,
            writable,
            executable: !writable,
            uncacheable: false,
        };
        let rx = crate::mm::paging::LeafGrant {
            writable: false,
            executable: true,
        };
        let check = |writable, text, mappings: u64| {
            thread_mem_write_check(leaf(writable), rx, text, || mappings)
        };
        thread_mem_write_check(leaf(true), rx, TextWrite::Refused, || unreachable!()).unwrap();
        assert_eq!(
            check(false, TextWrite::Refused, 1),
            Err(SyscallError::InsufficientRights)
        );
        check(false, TextWrite::Permitted, 1).unwrap();
        assert_eq!(
            check(false, TextWrite::Permitted, 2),
            Err(SyscallError::InvalidState)
        );
        assert_eq!(
            check(false, TextWrite::Permitted, 0),
            Err(SyscallError::InvalidState)
        );
    }

    // Defect caught (#869): a text write that took any read-only page mapped
    // once would let a holder of a thread's CONTROL rewrite a firmware table
    // (ACPI, the RSDP, the DTB) that its process maps through a Map-only
    // capability, though no capability grants a write to it; and one that
    // asked for write alone would refuse every breakpoint in text a process
    // loader mapped through an Execute-bearing, Write-less capability.
    #[test]
    fn a_text_write_needs_a_grant_of_write_or_execute()
    {
        use crate::mm::paging::LeafGrant;
        let read_only = crate::mm::paging::PageFlags {
            readable: true,
            writable: false,
            executable: false,
            uncacheable: false,
        };
        let check = |grant| thread_mem_write_check(read_only, grant, TextWrite::Permitted, || 1);
        assert_eq!(
            check(LeafGrant::default()),
            Err(SyscallError::InsufficientRights)
        );
        for grant in [
            LeafGrant {
                writable: true,
                executable: false,
            },
            LeafGrant {
                writable: false,
                executable: true,
            },
            LeafGrant {
                writable: true,
                executable: true,
            },
        ]
        {
            assert!(check(grant).is_ok(), "{grant:?}");
        }
        // The grant is read before the mapping count, as the flag is, so a
        // Map-only page mapped elsewhere too reports the missing right.
        assert_eq!(
            thread_mem_write_check(
                read_only,
                LeafGrant::default(),
                TextWrite::Permitted,
                || unreachable!()
            ),
            Err(SyscallError::InsufficientRights)
        );
        // A writable leaf needs no grant: its own rights let the thread
        // store there.
        let writable = crate::mm::paging::PageFlags {
            writable: true,
            ..read_only
        };
        thread_mem_write_check(
            writable,
            LeafGrant::default(),
            TextWrite::Refused,
            || unreachable!(),
        )
        .unwrap();
    }

    // Defect caught: a copy that took a device leaf for RAM, or a frame above
    // the top of RAM for one the direct map covers, would read or write
    // device registers through a write-back alias, or take a kernel page
    // fault on an address the direct map leaves unmapped.
    #[test]
    fn a_copy_takes_only_a_write_back_page_below_the_top_of_ram()
    {
        let page = PAGE_SIZE as u64;
        let leaf = |uncacheable| crate::mm::paging::PageFlags {
            readable: true,
            writable: true,
            executable: false,
            uncacheable,
        };
        let top = 16 * page;
        thread_mem_page_check(leaf(false), 15 * page, top).unwrap();
        assert_eq!(
            thread_mem_page_check(leaf(true), page, top),
            Err(SyscallError::InvalidAddress)
        );
        assert_eq!(
            thread_mem_page_check(leaf(false), top, top),
            Err(SyscallError::InvalidAddress)
        );
        assert_eq!(
            thread_mem_page_check(leaf(false), !(page - 1), top),
            Err(SyscallError::InvalidAddress)
        );
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
        for pattern in [[0x00u8; 16], [0xFF; 16], [0xA5; 16], [0x5A; 16]]
        {
            let layout = init_layout_from_entropy(pattern);
            let page = PAGE_SIZE as u64;

            assert!(INIT_INFO_WINDOW.contains(layout.init_info_va));
            assert_eq!(layout.init_stack_top % page, 0);
            // The lowest guard page is the window's draw, with
            // STACK_GUARD_PAGES guard pages between it and the stack base.
            let stack_reserve = (u64::from(STACK_GUARD_PAGES) + INIT_STACK_PAGES as u64) * page;
            let guard = layout.init_stack_top - stack_reserve;
            assert!(INIT_STACK_GUARD_WINDOW.contains(guard));
            assert!(layout.init_stack_top < LAYOUT_VA_CEILING);

            // InitInfo region (INIT_INFO_MAX_PAGES) vs stack reservation
            // (the guard pages + INIT_STACK_PAGES): disjoint for every draw.
            let info_end = layout.init_info_va + init_protocol::INIT_INFO_MAX_PAGES as u64 * page;
            assert!(info_end <= guard);
        }
    }

    // Defect caught: a fallback InitInfo region that, at the protocol's page
    // ceiling, runs into the fallback stack's guard pages or down into the
    // fixed image zone.
    #[test]
    fn fallback_info_region_fits_between_the_image_zone_and_the_stack_guard()
    {
        let page = PAGE_SIZE as u64;
        let guard = DEFAULT_INIT_STACK_TOP
            - (u64::from(STACK_GUARD_PAGES) + INIT_STACK_PAGES as u64) * page;
        let info_end = DEFAULT_INIT_INFO_VA + init_protocol::INIT_INFO_MAX_PAGES as u64 * page;
        assert!(info_end <= guard);
        const { assert!(DEFAULT_INIT_INFO_VA >= process_layout::FIXED_IMAGE_ZONE_END) };
        assert_eq!(DEFAULT_INIT_INFO_VA % page, 0);
    }

    #[test]
    fn choose_init_layout_caches_first_draw()
    {
        let first = choose_init_layout();
        assert_eq!(choose_init_layout(), first);
    }
}
