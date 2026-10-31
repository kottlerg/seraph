// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/mm/tag_allocator.rs

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
//! Each claim stamps the claiming space's `tag_gen` with a unique `alloc_gen`, and each
//! space's `tlb_gen` tracks its Replace-class rewrites. Together they keep tagged TLBs
//! coherent without a per-switch flush, as defined in docs/memory-model.md § TLB
//! Management (see also `AddressSpace::activate`).
//!
//! # Concurrency
//!
//! `AddressSpace.tag` is written only by the owner's own claim or by eviction,
//! both under `TAG_POOL_LOCK`. While eviction holds the lock it is the *sole*
//! writer of any space's `tag`. Outside the lock the pool and the fields agree:
//! the pool records space `S` as the owner of tag `t` exactly when `S.tag == t`.
//! Two readers load `tag` without the lock:
//!
//! - `AddressSpace::activate`: a racing `activate` that reads `tag == 0` falls
//!   into [`claim`], which blocks on the lock, so it cannot load the evicted tag.
//!   The `SeqCst` fence between revoking a victim's tag and reading its
//!   active-CPU mask is the eviction-side half of the Dekker exclusion with
//!   `activate`.
//! - `AddressSpace::shootdown_remote`: a revoked tag the request carries is
//!   harmless, because eviction needs the space inactive everywhere (proof:
//!   core/kernel/docs/memory-internals.md § SMP TLB Shootdown).
//!
//! The `AddressSpace` teardown (`dealloc_object`, core/kernel/src/cap/object.rs)
//! does not read `tag` itself: an eviction can move the dying space's tag to
//! another space between such a read and the free, so [`free_tag`] re-reads the
//! tag under the lock and frees it only while the pool still records the dying
//! space as its owner.

/// Most hardware tags any supported CPU provides: RISC-V `satp.ASID` is 16 bits
/// wide (x86-64 PCIDs are 12). Every tag fits the `u16` that
/// `AddressSpace.tag` and the shootdown request carry, so this is a hardware
/// bound, not a pool size: `enable` sizes the pool to the probed count.
pub const MAX_HW_TAGS: usize = 1 << 16;

/// Bytes the per-CPU tag-state records may take in total
/// (`cpu_count * tags * size_of::<TagState>()`). `enable` trims the tag count
/// to fit, down to the gate below which tagging stays off. It is a cost budget,
/// not a capacity: a claim always succeeds (it evicts the least-recently-claimed
/// inactive tag), so fewer tags only means more evictions and tag flushes.
/// 8 MiB keeps every tag of a 12-bit PCID on up to 128 CPUs.
pub const TAG_STATE_BUDGET_BYTES: usize = 8 * 1024 * 1024;

/// Bytes of pool storage [`TagPool::over`] needs for `num_tags` tags: the
/// in-use bitmap, then the owner and claim-generation arrays.
#[must_use]
pub const fn pool_storage_bytes(num_tags: usize) -> usize
{
    num_tags.div_ceil(64) * 8 + num_tags * 8 + num_tags * 8
}

// ── Pure pool state ────────────────────────────────────────────────────────────

/// The tag pool's pure bookkeeping: which tags are in use, who owns each, and
/// when each was claimed. Separated from the global glue so it can be unit
/// tested without a live `AddressSpace`. Its arrays live in storage sized to
/// the configured tag count ([`TagPool::over`]); the pool before `enable` has
/// none.
struct TagPool
{
    /// Bit `t` set means tag `t` is in use. Tag 0 is never allocated.
    in_use: &'static mut [u64],
    /// Owner badge per tag (an `*const AddressSpace` as `usize`; `0` = free).
    owners: &'static mut [usize],
    /// `alloc_gen` value stamped when each tag was last claimed (`0` = free).
    /// Unique per claim, so it doubles as the least-recently-claimed key.
    claimed_at: &'static mut [u64],
    /// Number of usable tags; tags `1..num_tags` may be allocated.
    num_tags: usize,
    /// Monotonic claim counter; never reused (64-bit). A `u64` cannot wrap: at
    /// one claim per nanosecond it lasts over 500 years.
    alloc_gen: u64,
}

impl TagPool
{
    /// The pool before `enable`: no tags, no storage.
    const fn new() -> Self
    {
        Self {
            in_use: &mut [],
            owners: &mut [],
            claimed_at: &mut [],
            num_tags: 0,
            alloc_gen: 0,
        }
    }

    /// A pool of `num_tags` tags (clamped to [`MAX_HW_TAGS`]) over the zeroed
    /// `storage`, which must hold at least [`pool_storage_bytes`]`(num_tags)`
    /// bytes; `None` when it does not.
    fn over(storage: &'static mut [u64], num_tags: usize) -> Option<Self>
    {
        let n = num_tags.min(MAX_HW_TAGS);
        if storage.len() * 8 < pool_storage_bytes(n)
        {
            return None;
        }
        let (in_use, rest) = storage.split_at_mut(n.div_ceil(64));
        let (owners, rest) = rest.split_at_mut(n);
        let (claimed_at, _) = rest.split_at_mut(n);
        // SAFETY: `owners` is `n` initialised (zeroed) u64s, exclusively
        // borrowed for 'static; `usize` has the size and alignment of `u64` on
        // every 64-bit target, and zero is a valid `usize`.
        let owners =
            unsafe { core::slice::from_raw_parts_mut(owners.as_mut_ptr().cast::<usize>(), n) };
        Some(Self {
            in_use,
            owners,
            claimed_at,
            num_tags: n,
            alloc_gen: 0,
        })
    }

    /// Allocate the next unique claim generation.
    fn next_gen(&mut self) -> u64
    {
        self.alloc_gen += 1;
        self.alloc_gen
    }

    /// Whether `tag` is in use. A tag past the pool, every tag of the pool
    /// before `enable` (which has no storage), is not.
    fn is_used(&self, tag: u16) -> bool
    {
        let t = tag as usize;
        t < self.num_tags && self.in_use[t / 64] & (1u64 << (t % 64)) != 0
    }

    /// First free tag in `1..num_tags`, or `None` if the pool is full. Scans the
    /// bitmap a word at a time, so a nearly full pool of 2^16 tags costs 1024
    /// word reads, not 65536 bit tests.
    // cast_possible_truncation: t < num_tags <= MAX_HW_TAGS, so t <= u16::MAX.
    #[allow(clippy::cast_possible_truncation)]
    fn find_free(&self) -> Option<u16>
    {
        self.in_use.iter().enumerate().find_map(|(w, &word)| {
            // Tag 0 is reserved: its bit always reads as used.
            let word = if w == 0 { word | 1 } else { word };
            let t = w * 64 + (!word).trailing_zeros() as usize;
            (word != u64::MAX && t < self.num_tags).then_some(t as u16)
        })
    }

    /// The in-use tag with the smallest `claimed_at` strictly greater than
    /// `floor`, with that `claimed_at`. Used to iterate eviction candidates
    /// least-recently-claimed first while skipping candidates already tried.
    // cast_possible_truncation: t < num_tags <= MAX_HW_TAGS, so t <= u16::MAX.
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

    /// Return `tag` to the free pool if `owner` still holds it, and report
    /// whether it did. A tag eviction has reissued to another space is left as
    /// recorded, so a release by a space that lost its tag cannot free the new
    /// owner's live tag; tag 0 (an untagged space) is never in use. `tag` must
    /// be below `num_tags` (every `AddressSpace.tag` value comes from the pool).
    fn release(&mut self, tag: u16, owner: usize) -> bool
    {
        let t = tag as usize;
        if !self.is_used(tag) || self.owners[t] != owner
        {
            return false;
        }
        self.in_use[t / 64] &= !(1u64 << (t % 64));
        self.owners[t] = 0;
        self.claimed_at[t] = 0;
        true
    }
}

/// The tag count [`enable`](glue::enable) configures for `hw_tags` hardware
/// tags on `cpu_count` CPUs, or `None` when tagging stays off.
///
/// Usable tags are `1..n`; tagging needs strictly more of them than CPUs, so a
/// claim always finds an inactive victim (core/kernel/docs/memory-internals.md
/// § Context Switch TLB Handling). Within that gate the count is trimmed so the
/// per-CPU tag state fits [`TAG_STATE_BUDGET_BYTES`], but never below the gate:
/// the budget costs flushes, never the tagged path.
#[must_use]
pub fn tag_count(hw_tags: usize, cpu_count: usize) -> Option<usize>
{
    let cpus = cpu_count.max(1);
    let hw = hw_tags.min(MAX_HW_TAGS);
    let gate = cpus + 2;
    if hw < gate
    {
        return None;
    }
    let fit = TAG_STATE_BUDGET_BYTES / (cpus * TAG_STATE_BYTES);
    Some(hw.min(fit).max(gate))
}

/// Size of one per-CPU, per-tag record (`TagState`: two `u64` generations).
const TAG_STATE_BYTES: usize = 16;

// ── Global pool, lock, and per-CPU state (kernel-only) ──────────────────────────

#[cfg(not(test))]
pub use glue::*;

#[cfg(not(test))]
mod glue
{
    use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

    use super::{TagPool, tag_count};
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

    /// Spin until `TAG_POOL_LOCK` is taken, halting if it stays held past
    /// [`crate::bounded_wait::DEADLOCK_BUDGET_US`] of elapsed time.
    fn acquire_tag_pool_lock()
    {
        let acquired = crate::bounded_wait::spin_until(
            || {
                TAG_POOL_LOCK
                    .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            },
            crate::arch::current::timer::elapsed_us,
            crate::bounded_wait::DEADLOCK_BUDGET_US,
        );
        if !acquired
        {
            crate::fatal("tag_allocator: TAG_POOL_LOCK held past the deadlock budget");
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
    /// full-flush fallback on every address-space switch.
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
    /// (in `AddressSpace::activate`, and on x86-64 in `first_entry_to_user`), so
    /// plain (non-atomic) access is correct.
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
    /// hardware tag count (`1 << PCID/ASID width`); the pool takes the count
    /// [`tag_count`] derives from it.
    ///
    /// Tagging is enabled only when the usable tag count (`n - 1`; tag 0 is
    /// reserved) strictly exceeds `cpu_count`, so [`claim`] never runs a user space
    /// untagged (core/kernel/docs/memory-internals.md § Context Switch TLB
    /// Handling). Where the hardware tag field is too narrow (e.g. a 1-bit RISC-V
    /// ASID), tagging stays disabled and the full-flush fallback remains in effect.
    ///
    /// # Safety
    /// Must run once on the BSP during Phase 5 (core/kernel/docs/initialization.md
    /// § Phase 5: Architecture Hardware Initialisation), before any CPU performs a
    /// tagged activate. `allocator` must be the live frame allocator (exclusive
    /// access during this call).
    pub unsafe fn enable(
        hw_tags: usize,
        cpu_count: usize,
        allocator: &mut crate::mm::BuddyAllocator,
    )
    {
        let Some(n) = tag_count(hw_tags, cpu_count)
        else
        {
            return;
        };

        // Zero-filled slab: owner_gen 0 never matches a real tag_gen, so the
        // first activate of any tag on any CPU flushes it.
        let bytes = cpu_count * n * core::mem::size_of::<TagState>();
        let slab =
            crate::sched::alloc_zeroed_slab::<TagState>(bytes, allocator, "PER_CPU_TAG_STATE");
        PER_CPU_TAG_STATE.store(slab, Ordering::Release);

        // The pool's arrays, sized to `n` tags; zeroed, so every tag starts free.
        let pool_bytes = super::pool_storage_bytes(n);
        let storage = crate::sched::alloc_zeroed_slab::<u64>(pool_bytes, allocator, "TAG_POOL");
        // SAFETY: the slab is `pool_bytes` zeroed, 8-byte-aligned bytes owned
        // by the tag pool for the kernel's lifetime.
        let storage = unsafe { core::slice::from_raw_parts_mut(storage, pool_bytes / 8) };
        let pool = TagPool::over(storage, n)
            .unwrap_or_else(|| crate::fatal("tag_allocator: pool storage too small"));
        with_tag_pool(|p| *p = pool);
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
            // currently active on any CPU. The enablement gate in [`enable`] guarantees
            // such a tag exists (core/kernel/docs/memory-internals.md § Context Switch
            // TLB Handling). The outer loop retries the scan to ride out a candidate
            // activating between selection and the active check (the least-recently-
            // claimed tag is almost always inactive, so the first pass succeeds in
            // practice).
            let mut timer =
                crate::bounded_wait::WaitTimer::start(crate::arch::current::timer::elapsed_us());
            loop
            {
                let mut floor = 0u64;
                while let Some((victim_tag, victim_at)) = pool.oldest_used_above(floor)
                {
                    let victim = pool.owners[victim_tag as usize] as *const AddressSpace;
                    // Under the pool lock this path is the sole writer of any space's `tag`.
                    // SAFETY: the victim is a live AddressSpace — the pool
                    // records an owner only while that space holds the tag, and
                    // free_tag() (called before the space is dropped) clears the
                    // record under this lock, so the pointer is valid here.
                    unsafe {
                        (*victim).tag.store(0, Ordering::Release);
                    }
                    // Eviction-side half of the Dekker exclusion with `AddressSpace::activate`
                    // (core/kernel/docs/memory-internals.md § Context Switch TLB Handling): the
                    // revoke (store) is ordered before the active-mask read (load), pairing with
                    // activate's fence.
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
                    // tag. Restore its claim (this path is the sole writer under the pool lock)
                    // and try the next-oldest. A transient tag-0 window on a *consistently*
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
                // the gate this is a rare race, not exhaustion; retry. The bound
                // is elapsed time, as for the pool lock, and fires only if the
                // gate invariant is somehow violated.
                if timer.elapsed(crate::arch::current::timer::elapsed_us())
                    >= crate::bounded_wait::DEADLOCK_BUDGET_US
                {
                    crate::fatal("tag_allocator: eviction found no inactive victim");
                }
                core::hint::spin_loop();
            }
        })
    }

    /// Return `as_ref`'s tag, if it still holds one, to the pool when the
    /// address space is destroyed.
    ///
    /// The tag is read under the pool lock, not by the caller: an eviction on
    /// another CPU can reissue an inactive dying space's tag to a different
    /// space, and only the pool's owner record says whether the tag is still
    /// this space's to free (`TagPool::release`). After this returns the pool
    /// records no tag for `as_ref`, so eviction never dereferences it again.
    ///
    /// No TLB flush is issued: a CPU that cached this tag is flushed lazily by
    /// the `owner_gen` check the next time it loads the tag for whatever space
    /// claims it next.
    pub fn free_tag(as_ref: &AddressSpace)
    {
        let owner = core::ptr::from_ref(as_ref) as usize;
        with_tag_pool(|pool| {
            pool.release(as_ref.tag.load(Ordering::Acquire), owner);
        });
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    /// A pool of `n` tags over leaked, zeroed host storage.
    fn pool_of(n: usize) -> TagPool
    {
        let words = pool_storage_bytes(n).div_ceil(8);
        let storage: &'static mut [u64] = Vec::leak(vec![0u64; words]);
        TagPool::over(storage, n).unwrap()
    }

    #[test]
    fn find_free_skips_tag_zero_and_used()
    {
        let mut pool = pool_of(4); // tags 1..4 usable
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
        let mut pool = pool_of(2);
        assert_eq!(
            (pool.next_gen(), pool.next_gen(), pool.next_gen()),
            (1, 2, 3)
        );
    }

    #[test]
    fn oldest_used_above_orders_by_claim_generation()
    {
        let mut pool = pool_of(4);
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
    fn release_by_owner_returns_tag_to_free_pool()
    {
        let mut pool = pool_of(3);
        let g = pool.next_gen();
        pool.record(1, 0x1, g);
        let g = pool.next_gen();
        pool.record(2, 0x2, g);
        assert_eq!(pool.find_free(), None);
        assert!(pool.release(1, 0x1));
        assert_eq!(pool.find_free(), Some(1));
        assert!(!pool.is_used(1));
    }

    // Defect caught: a dying space whose tag eviction reissued to another space
    // freeing that space's live tag, so a third claim shares it.
    #[test]
    fn release_by_non_owner_leaves_tag_recorded()
    {
        let mut pool = pool_of(3);
        let g = pool.next_gen();
        pool.record(1, 0xA, g);
        // Eviction reissues tag 1 from space 0xA to space 0xB.
        let g = pool.next_gen();
        pool.record(1, 0xB, g);
        assert!(!pool.release(1, 0xA));
        assert!(pool.is_used(1));
        assert_eq!(pool.owners[1], 0xB);
        assert_eq!(pool.claimed_at[1], g);
    }

    // Defect caught: a hidden fixed pool size (the former 4096) clipping a
    // 16-bit ASID space, or a word scan that stops at the first full word.
    #[test]
    fn a_pool_sized_past_4096_hands_out_its_high_tags()
    {
        let n = MAX_HW_TAGS;
        let mut pool = pool_of(n);
        for t in 1..n - 1
        {
            let tag = u16::try_from(t).unwrap();
            pool.record(tag, t, 1);
        }
        assert_eq!(pool.find_free(), u16::try_from(n - 1).ok());
        pool.record(u16::try_from(n - 1).unwrap(), 1, 1);
        assert_eq!(pool.find_free(), None);
    }

    // Defect caught: an address-space teardown on a boot with tagging off
    // (no PCID under TCG) indexing the storage-less pool.
    #[test]
    fn the_pool_before_enable_releases_nothing_and_holds_no_tag()
    {
        let mut pool = TagPool::new();
        assert!(!pool.release(0, 0x1000));
        assert!(!pool.is_used(5));
        assert_eq!(pool.find_free(), None);
    }

    #[test]
    fn storage_smaller_than_the_tag_count_needs_is_refused()
    {
        let storage: &'static mut [u64] = Vec::leak(vec![0u64; 4]);
        assert!(TagPool::over(storage, 4096).is_none());
    }

    #[test]
    fn tag_count_needs_more_usable_tags_than_cpus()
    {
        // 4 CPUs need 6 tags (5 usable after tag 0).
        assert_eq!(tag_count(5, 4), None);
        assert_eq!(tag_count(6, 4), Some(6));
    }

    #[test]
    fn tag_count_trims_to_the_budget_but_never_below_the_gate()
    {
        // 4 CPUs, a 16-bit ASID: every tag fits the 8 MiB budget.
        assert_eq!(tag_count(1 << 16, 4), Some(1 << 16));
        // 512 CPUs, 12-bit PCID: the budget fits 1024 tags per CPU.
        assert_eq!(tag_count(4096, 512), Some(1024));
        // 2048 CPUs: the budget fits 256, below the gate, so the gate wins.
        assert_eq!(tag_count(1 << 16, 2048), Some(2050));
    }
}
