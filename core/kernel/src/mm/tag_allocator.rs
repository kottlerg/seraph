// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/mm/tag_allocator.rs

//! Hardware address-space tag (PCID / ASID) allocator.
//!
//! Each user [`AddressSpace`](crate::mm::address_space::AddressSpace) that runs
//! on a CPU claims a hardware tag so a context switch can load its page tables
//! without flushing the TLB. Tags are a finite resource (x86-64 PCID is 12-bit;
//! RISC-V ASID width is implementation-defined), so this module owns a global
//! pool that hands out tags `1..num_tags` (tag `0` is reserved for the
//! kernel/idle context and the full-flush fallback) and evicts the
//! least-recently-claimed tag when the pool is exhausted.
//!
//! # Coherence model
//!
//! Two generation counters keep tagged TLBs coherent without flushing on every
//! switch (see the `AddressSpace` field docs and `AddressSpace::activate`):
//!
//! - `alloc_gen` is a global monotonic counter; each claim stamps the claiming
//!   space's `tag_gen` with a unique value. A CPU records, per tag, the
//!   `tag_gen` it last synced; when it loads a tag whose recorded `tag_gen`
//!   differs, the tag was reissued to a different space and the CPU flushes it.
//!   This is the cross-CPU invalidation-before-reissue guarantee.
//! - `tlb_gen` (per space) is bumped on every unmap / permission-narrow; a CPU
//!   that was switched away flushes the tag on reactivation if its synced value
//!   lags.
//!
//! # Concurrency (INV-1 / INV-4)
//!
//! `AddressSpace.tag` is written only by the owner's own claim or by eviction,
//! both under `TAG_POOL_LOCK`. While eviction holds the lock it is the *sole*
//! writer of any space's `tag`; the only concurrent access is `activate`'s
//! lock-free read. A racing `activate` that reads `tag == 0` falls into
//! [`claim`], which blocks on the lock, so it cannot load the evicted tag. The
//! `SeqCst` fence between revoking a victim's tag and reading its active-CPU
//! mask is the eviction-side half of the Dekker exclusion with `activate`.

/// Maximum number of tags the pool tracks. The configured count is
/// `NUM_TAGS = min(hardware tags, TAG_CAP, slab-fit limit)` (see [`enable`]),
/// sized from the hardware at boot, so this is just an upper bound on the static
/// pool arrays and the per-CPU tag-state slab stride. Set to the x86-64 PCID
/// maximum (4096) so all PCIDs are usable; RISC-V uses its detected ASID count.
/// Memory: the pool's `owners`/`claimed_at` arrays are `TAG_CAP * 8` bytes each
/// (~64 KiB total, in BSS), and the per-CPU slab is `NUM_TAGS * 16` bytes per
/// CPU. `enable` additionally caps `NUM_TAGS` so the single slab allocation
/// (`cpu_count * NUM_TAGS * 16`) fits the buddy's largest block, trimming the
/// tag count on high-CPU-count machines instead of overflowing the allocator.
pub const TAG_CAP: usize = 4096;

/// Number of `u64` words in the in-use bitmap.
const BITMAP_WORDS: usize = TAG_CAP / 64;

// ── Pure pool state ────────────────────────────────────────────────────────────

/// The tag pool's pure bookkeeping: which tags are in use, who owns each, and
/// when each was claimed. Separated from the global glue so it can be unit
/// tested without a live `AddressSpace`.
struct TagPool
{
    /// Bit `t` set ⇒ tag `t` is in use. Tag 0 is never allocated.
    in_use: [u64; BITMAP_WORDS],
    /// Owner token per tag (an `*const AddressSpace` as `usize`; `0` = free).
    owners: [usize; TAG_CAP],
    /// `alloc_gen` value stamped when each tag was last claimed (`0` = free).
    /// Unique per claim, so it doubles as the least-recently-claimed key.
    claimed_at: [u64; TAG_CAP],
    /// Number of usable tags; tags `1..num_tags` may be allocated.
    num_tags: usize,
    /// Monotonic claim counter; never reused (64-bit).
    alloc_gen: u64,
}

impl TagPool
{
    // large_stack_arrays: this is the initializer for the `static mut TAG_POOL`,
    // so the TAG_CAP-sized arrays live in BSS, not on the stack. The only stack
    // instantiation is in the host unit tests, whose stacks are ample.
    #[allow(clippy::large_stack_arrays)]
    const fn new() -> Self
    {
        Self {
            in_use: [0; BITMAP_WORDS],
            owners: [0; TAG_CAP],
            claimed_at: [0; TAG_CAP],
            num_tags: 0,
            alloc_gen: 0,
        }
    }

    /// Set the number of usable tags (clamped to `[0, TAG_CAP]`).
    fn configure(&mut self, num_tags: usize)
    {
        self.num_tags = num_tags.min(TAG_CAP);
    }

    /// Allocate the next unique claim generation.
    fn next_gen(&mut self) -> u64
    {
        self.alloc_gen += 1;
        self.alloc_gen
    }

    fn is_used(&self, tag: u16) -> bool
    {
        let t = tag as usize;
        self.in_use[t / 64] & (1u64 << (t % 64)) != 0
    }

    /// First free tag in `1..num_tags`, or `None` if the pool is full.
    // cast_possible_truncation: t < num_tags <= TAG_CAP <= u16::MAX.
    #[allow(clippy::cast_possible_truncation)]
    fn find_free(&self) -> Option<u16>
    {
        (1..self.num_tags)
            .map(|t| t as u16)
            .find(|&tag| !self.is_used(tag))
    }

    /// The in-use tag with the smallest `claimed_at` strictly greater than
    /// `floor`, with that `claimed_at`. Used to iterate eviction candidates
    /// least-recently-claimed first while skipping candidates already tried.
    // cast_possible_truncation: t < num_tags <= TAG_CAP <= u16::MAX.
    #[allow(clippy::cast_possible_truncation)]
    fn oldest_used_above(&self, floor: u64) -> Option<(u16, u64)>
    {
        let mut best: Option<(u16, u64)> = None;
        for t in 1..self.num_tags
        {
            let tag = t as u16;
            if !self.is_used(tag)
            {
                continue;
            }
            let at = self.claimed_at[t];
            if at <= floor
            {
                continue;
            }
            if best.is_none_or(|(_, b)| at < b)
            {
                best = Some((tag, at));
            }
        }
        best
    }

    /// Record `tag` as claimed by `owner` at generation `claim_gen`.
    fn record(&mut self, tag: u16, owner: usize, claim_gen: u64)
    {
        let t = tag as usize;
        self.in_use[t / 64] |= 1u64 << (t % 64);
        self.owners[t] = owner;
        self.claimed_at[t] = claim_gen;
    }

    /// Return `tag` to the free pool.
    fn clear(&mut self, tag: u16)
    {
        let t = tag as usize;
        self.in_use[t / 64] &= !(1u64 << (t % 64));
        self.owners[t] = 0;
        self.claimed_at[t] = 0;
    }
}

// ── Global pool, lock, and per-CPU state (kernel-only) ──────────────────────────

#[cfg(not(test))]
pub use glue::*;

#[cfg(not(test))]
mod glue
{
    use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

    use super::{TAG_CAP, TagPool};
    use crate::mm::address_space::AddressSpace;

    /// The global tag pool. Accessed only through [`with_tag_pool`].
    // SAFETY: all access is serialised by TAG_POOL_LOCK via with_tag_pool.
    static mut TAG_POOL: TagPool = TagPool::new();

    /// Spin-lock protecting [`TAG_POOL`].
    static TAG_POOL_LOCK: AtomicBool = AtomicBool::new(false);

    /// Whether hardware tagging is enabled (PCID/ASID detected and configured).
    static TAGGING_ENABLED: AtomicBool = AtomicBool::new(false);

    /// Number of usable tags once enabled (lock-free mirror of
    /// `TagPool::num_tags`); also the per-CPU tag-state slab stride.
    static NUM_TAGS: AtomicUsize = AtomicUsize::new(0);

    fn acquire_tag_pool_lock()
    {
        let mut spins = 0u64;
        while TAG_POOL_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spins += 1;
            if spins > 500_000
            {
                crate::kprintln!("[tag_alloc] DEADLOCK after {}k spins", spins / 1000);
                loop
                {
                    core::hint::spin_loop();
                }
            }
            core::hint::spin_loop();
        }
    }

    fn release_tag_pool_lock()
    {
        TAG_POOL_LOCK.store(false, Ordering::Release);
    }

    /// Call `f` with exclusive access to the tag pool.
    fn with_tag_pool<F, R>(f: F) -> R
    where
        F: FnOnce(&mut TagPool) -> R,
    {
        acquire_tag_pool_lock();
        // SAFETY: we hold TAG_POOL_LOCK; no concurrent pool access is possible.
        let result = f(unsafe { &mut *core::ptr::addr_of_mut!(TAG_POOL) });
        release_tag_pool_lock();
        result
    }

    /// Whether tagged TLBs are active. When `false`, `activate` uses the
    /// full-flush fallback and behaves exactly as the untagged kernel did.
    #[inline]
    pub fn tagging_enabled() -> bool
    {
        TAGGING_ENABLED.load(Ordering::Acquire)
    }

    /// The number of usable tags (`0` when tagging is disabled).
    #[inline]
    pub fn num_tags() -> usize
    {
        NUM_TAGS.load(Ordering::Acquire)
    }

    // ── Per-CPU tag state ───────────────────────────────────────────────────────

    /// Per-CPU, per-tag synchronisation record. Written only by the owning CPU
    /// in its own `activate`, so plain (non-atomic) access is correct.
    #[repr(C)]
    pub struct TagState
    {
        /// `tag_gen` of the space this CPU last loaded under this tag. A
        /// mismatch with the space's current `tag_gen` means the tag was
        /// reissued and the CPU must flush it.
        pub owner_gen: u64,
        /// `tlb_gen` this CPU last synced for this tag; a lag means unmaps
        /// occurred while this CPU was switched away.
        pub synced_tlb_gen: u64,
    }

    /// Base of the per-CPU tag-state slab (`cpu_count * NUM_TAGS` records,
    /// row-major by CPU). Null until [`enable`] runs.
    static PER_CPU_TAG_STATE: AtomicPtr<TagState> = AtomicPtr::new(core::ptr::null_mut());

    /// Pointer to `(cpu, tag)`'s [`TagState`].
    ///
    /// # Safety
    /// `cpu < cpu_count` and `tag < num_tags()`; [`enable`] must have run. The
    /// returned record is owned exclusively by `cpu`.
    #[inline]
    unsafe fn tag_state_ptr(cpu: usize, tag: u16) -> *mut TagState
    {
        let base = PER_CPU_TAG_STATE.load(Ordering::Acquire);
        debug_assert!(!base.is_null(), "tag_state_ptr: slab not initialised");
        let stride = NUM_TAGS.load(Ordering::Relaxed);
        // SAFETY: caller guarantees cpu < cpu_count and tag < num_tags, so the
        // index is within the cpu_count * stride slab.
        unsafe { base.add(cpu * stride + tag as usize) }
    }

    /// Read `(cpu, tag)`'s synchronisation record as `(owner_gen, synced)`.
    ///
    /// # Safety
    /// Tagging enabled, `cpu < cpu_count`, `tag < num_tags()`, and `cpu` is the
    /// current CPU (single-writer invariant).
    #[inline]
    pub unsafe fn tag_state(cpu: usize, tag: u16) -> (u64, u64)
    {
        // SAFETY: caller's contract.
        let p = unsafe { tag_state_ptr(cpu, tag) };
        // SAFETY: p is this CPU's own record; no other CPU writes it.
        unsafe { ((*p).owner_gen, (*p).synced_tlb_gen) }
    }

    /// Update `(cpu, tag)`'s synchronisation record.
    ///
    /// # Safety
    /// Same contract as [`tag_state`].
    #[inline]
    pub unsafe fn set_tag_state(cpu: usize, tag: u16, owner_gen: u64, synced_tlb_gen: u64)
    {
        // SAFETY: caller's contract.
        let p = unsafe { tag_state_ptr(cpu, tag) };
        // SAFETY: p is this CPU's own record; no other CPU writes it.
        unsafe {
            (*p).owner_gen = owner_gen;
            (*p).synced_tlb_gen = synced_tlb_gen;
        }
    }

    // ── Enablement ──────────────────────────────────────────────────────────────

    /// Configure the pool for `hw_tags` hardware tags and enable tagging,
    /// allocating the per-CPU tag-state slab for `cpu_count` CPUs.
    ///
    /// Call once on the BSP, before any AP runs a user thread. `hw_tags` is the
    /// hardware tag count (`1 << PCID/ASID width`), clamped to [`TAG_CAP`].
    ///
    /// Tagging is enabled only when the **usable** tag count (`n - 1`; tag 0 is
    /// reserved) strictly exceeds `cpu_count`. This is load-bearing for
    /// correctness, not just efficiency: at most `cpu_count` tags are active at
    /// any instant, so `usable > cpu_count` guarantees a free-or-inactive tag
    /// always exists and [`claim`] never has to run a user space untagged. A
    /// user space under tag 0 while another CPU runs it under a real tag would
    /// mix tags across the space and miss a shootdown. Where the hardware tag
    /// field is too narrow (e.g. a 1-bit RISC-V ASID), tagging stays disabled
    /// and the full-flush fallback remains in effect.
    ///
    /// # Safety
    /// Must run once on the BSP after the frame allocator is live (Phase 5),
    /// before any CPU performs a tagged activate. `allocator` must be the live
    /// frame allocator (exclusive access during this call).
    pub unsafe fn enable(
        hw_tags: usize,
        cpu_count: usize,
        allocator: &mut crate::mm::BuddyAllocator,
    )
    {
        // The per-CPU tag-state slab is one `cpu_count * n * size_of::<TagState>()`
        // allocation, which must fit the buddy's largest single block
        // (`2^MAX_ORDER` pages). Cap `n` so it always does — on a high-CPU-count
        // machine this trims the tag count (down to the `< cpu_count + 2` gate,
        // where tagging disables) rather than overflowing the allocator at boot.
        let max_slab_bytes = (1usize << crate::mm::buddy::MAX_ORDER) * crate::mm::PAGE_SIZE;
        let max_fit = max_slab_bytes / (cpu_count.max(1) * core::mem::size_of::<TagState>());
        let n = hw_tags.min(TAG_CAP).min(max_fit);
        // Usable tags are `1..n` (n - 1 of them); require strictly more than the
        // CPU count so claim always succeeds (see the doc above).
        if n < cpu_count + 2
        {
            return;
        }

        // Zero-filled slab: owner_gen 0 never matches a real tag_gen, so the
        // first activate of any tag on any CPU flushes it.
        let bytes = cpu_count * n * core::mem::size_of::<TagState>();
        let slab =
            crate::sched::alloc_zeroed_slab::<TagState>(bytes, allocator, "PER_CPU_TAG_STATE");
        PER_CPU_TAG_STATE.store(slab, Ordering::Release);

        with_tag_pool(|pool| pool.configure(n));
        NUM_TAGS.store(n, Ordering::Release);
        TAGGING_ENABLED.store(true, Ordering::Release);
    }

    // ── Claim / free ────────────────────────────────────────────────────────────

    /// Claim a tag for `as_ref`, allocating or evicting as needed.
    ///
    /// Returns a usable tag in `1..num_tags`; it never returns 0 while tagging
    /// is enabled (the enablement gate guarantees a free-or-inactive tag always
    /// exists). Stamps `as_ref.tag_gen` and publishes `as_ref.tag`.
    ///
    /// The current CPU must already be marked active on `as_ref` (the scheduler
    /// does this before `activate`), so this space cannot be chosen as its own
    /// eviction victim.
    pub fn claim(as_ref: &AddressSpace) -> u16
    {
        with_tag_pool(|pool| {
            // Idempotent: a concurrent activate on another CPU may have claimed
            // for this space already.
            let cur = as_ref.tag.load(Ordering::Acquire);
            if cur != 0
            {
                return cur;
            }

            let owner = core::ptr::from_ref(as_ref) as usize;

            if let Some(t) = pool.find_free()
            {
                let claim_gen = pool.next_gen();
                pool.record(t, owner, claim_gen);
                as_ref.tag_gen.store(claim_gen, Ordering::Relaxed);
                as_ref.tag.store(t, Ordering::Release);
                return t;
            }

            // Pool full: evict the least-recently-claimed space whose tag is not
            // currently active on any CPU (INV-4). The enablement gate keeps the
            // usable tag count strictly above `cpu_count`, and active spaces are
            // bounded by the CPU count, so an inactive in-use tag always exists.
            // claim therefore never returns 0 when tagging is enabled — no user
            // space ever runs untagged. The outer loop retries the scan to ride
            // out the transient case where a candidate activates between
            // selection and the active check (the least-recently-claimed tag is
            // almost always inactive, so the first pass succeeds in practice).
            let mut spins = 0u64;
            loop
            {
                let mut floor = 0u64;
                while let Some((victim_tag, victim_at)) = pool.oldest_used_above(floor)
                {
                    let victim = pool.owners[victim_tag as usize] as *const AddressSpace;
                    // INV-1: under the pool lock we are the sole writer of any tag.
                    // SAFETY: the victim is a live AddressSpace — its tag was
                    // claimed under this lock and free_tag() (called before the
                    // space is dropped) also takes this lock, so the pointer is
                    // valid here.
                    unsafe {
                        (*victim).tag.store(0, Ordering::Release);
                    }
                    // INV-3 eviction-race Dekker: the revoke (store) is ordered
                    // before the active-mask read (load), pairing with activate's
                    // fence.
                    core::sync::atomic::fence(Ordering::SeqCst);
                    // SAFETY: victim is a live AddressSpace (see above).
                    let active_empty = unsafe { (*victim).active_cpu_mask().is_empty() };
                    if active_empty
                    {
                        // Safe to reuse: the victim is not running this tag. Other
                        // CPUs that cached it while switched away are flushed
                        // lazily by the owner_gen check on their next load of it.
                        let claim_gen = pool.next_gen();
                        pool.record(victim_tag, owner, claim_gen);
                        as_ref.tag_gen.store(claim_gen, Ordering::Relaxed);
                        as_ref.tag.store(victim_tag, Ordering::Release);
                        return victim_tag;
                    }

                    // Victim is (or just became) active and may be running this
                    // tag. Restore its claim (sole writer, INV-1) and try the
                    // next-oldest. A transient tag-0 window on a *consistently*
                    // tagged active space is harmless: its shootdowns degrade to
                    // current-PCID invalidation, which is correct because all its
                    // active CPUs share the same loaded tag.
                    // SAFETY: victim is a live AddressSpace (see above).
                    unsafe {
                        (*victim).tag.store(victim_tag, Ordering::Release);
                    }
                    floor = victim_at;
                }

                // A whole pass found every in-use tag transiently active. Given
                // the gate this is a rare race, not exhaustion; retry. The guard
                // mirrors the frame-allocator deadlock guard and fires only if
                // the gate invariant is somehow violated.
                spins += 1;
                if spins > 10_000_000
                {
                    crate::fatal("tag_allocator: eviction found no inactive victim");
                }
            }
        })
    }

    /// Return `tag` to the pool when an address space is destroyed.
    ///
    /// No TLB flush is issued: a CPU that cached this tag is flushed lazily by
    /// the `owner_gen` check the next time it loads the tag for whatever space
    /// claims it next.
    pub fn free_tag(tag: u16)
    {
        if tag == 0
        {
            return;
        }
        with_tag_pool(|pool| pool.clear(tag));
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn find_free_skips_tag_zero_and_used()
    {
        let mut pool = TagPool::new();
        pool.configure(4); // tags 1..4 usable
        assert_eq!(pool.find_free(), Some(1));
        let g = pool.next_gen();
        pool.record(1, 0x1000, g);
        assert_eq!(pool.find_free(), Some(2));
        let g = pool.next_gen();
        pool.record(2, 0x2000, g);
        let g = pool.next_gen();
        pool.record(3, 0x3000, g);
        assert_eq!(pool.find_free(), None); // tags 1,2,3 used; 0 reserved
    }

    #[test]
    fn gen_is_monotonic_and_unique()
    {
        let mut pool = TagPool::new();
        assert_eq!(
            (pool.next_gen(), pool.next_gen(), pool.next_gen()),
            (1, 2, 3)
        );
    }

    #[test]
    fn oldest_used_above_orders_by_claim_generation()
    {
        let mut pool = TagPool::new();
        pool.configure(4);
        // Claim 1, then 3, then 2 — claim order, not tag order, sets age.
        let g = pool.next_gen();
        pool.record(1, 0x1, g); // gen 1
        let g = pool.next_gen();
        pool.record(3, 0x3, g); // gen 2
        let g = pool.next_gen();
        pool.record(2, 0x2, g); // gen 3
        // Oldest is tag 1 (gen 1), then tag 3 (gen 2), then tag 2 (gen 3).
        let (t0, a0) = pool.oldest_used_above(0).unwrap();
        assert_eq!(t0, 1);
        let (t1, a1) = pool.oldest_used_above(a0).unwrap();
        assert_eq!(t1, 3);
        let (t2, _) = pool.oldest_used_above(a1).unwrap();
        assert_eq!(t2, 2);
    }

    #[test]
    fn clear_returns_tag_to_free_pool()
    {
        let mut pool = TagPool::new();
        pool.configure(3);
        let g = pool.next_gen();
        pool.record(1, 0x1, g);
        let g = pool.next_gen();
        pool.record(2, 0x2, g);
        assert_eq!(pool.find_free(), None);
        pool.clear(1);
        assert_eq!(pool.find_free(), Some(1));
        assert!(!pool.is_used(1));
    }

    #[test]
    fn configure_clamps_to_cap()
    {
        let mut pool = TagPool::new();
        pool.configure(TAG_CAP * 4);
        assert_eq!(pool.num_tags, TAG_CAP);
    }
}
