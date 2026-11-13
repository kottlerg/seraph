// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/cap/cspace.rs

//! Capability space implementation.
//!
//! A [`CSpace`] is a hybrid radix of [`CapabilitySlot`]s: an inline root of
//! leaf [`CSpacePage`] pointers (`direct`) plus root pointers to one, two, or
//! three levels of pool-allocated [`DirPage`]s (`indirect`, `double`,
//! `triple`), capped at [`MAX_SLOTS_STRUCTURAL`]. The layout, lookup cost, and
//! capacity bounds are specified in core/kernel/docs/capability-internals.md
//! § Storage: Hybrid Radix Directory and docs/capability-model.md
//! § Address-space and `CSpace` growth budgets.
//!
//! ## Free list
//!
//! Freed slots sit on an intrusive doubly-linked free list encoded in the
//! slots themselves (core/kernel/src/cap/slot.rs, `CapabilitySlot::set_next_free`);
//! see core/kernel/docs/capability-internals.md § Free Slot Tracking.
//!
//! ## IPC receive reserve
//!
//! General allocations ([`CSpace::allocate_slot`] and the inserts built on
//! it) leave the last [`IPC_RECV_RESERVE`] free slots untouched; only IPC
//! capability transfer ([`CSpace::allocate_transfer_slot`]) takes them. See
//! core/kernel/docs/capability-internals.md § IPC Receive Reserve.
//!
//! ## Growth
//!
//! Leaves are allocated on demand by [`CSpace::grow`] behind the `next_leaf`
//! cursor; growth order and the directory pages are specified in
//! core/kernel/docs/capability-internals.md § Storage: Hybrid Radix
//! Directory.

#![expect(
    clippy::cast_possible_truncation,
    reason = "usize→u32 slot index bounded by MAX_SLOTS_STRUCTURAL"
)]

// `alloc` is needed by the host-test stubs (CSpace::grow heap fallback,
// CSpace::Drop heap reclaim, dummy-object factory). Production CSpace is
// retype-pool-backed end-to-end and needs no `alloc` crate.
#[cfg(test)]
extern crate alloc;

#[cfg(test)]
use alloc::boxed::Box;
use core::num::{NonZeroU32, NonZeroUsize};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, Ordering};

use super::object::{CSpaceKernelObject, KernelObjectHeader, MemoryObject};
use super::slot::{CSpaceId, CapTag, CapabilitySlot, Rights};
use crate::arch::nospec;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Slots per `CSpace` leaf page (56 × 72 B = 4032 B, fitting one 4 KiB pool
/// page); see core/kernel/docs/capability-internals.md § Storage: Hybrid
/// Radix Directory for the sizing constraints.
pub const L2_SIZE: usize = 56;

/// Free slots kept back from general allocations for IPC capability
/// transfer: one message's worth, so a `CSpace` whose general slots are
/// exhausted still receives a cap-bearing message (core/kernel/docs/capability-internals.md
/// § IPC Receive Reserve).
pub const IPC_RECV_RESERVE: usize = syscall::CSPACE_IPC_RECV_RESERVE as usize;

// The ABI publishes the slots a slot-page backs for userspace funding
// arithmetic (`CSPACE_SLOTS_PER_PAGE`); the leaf layout must match it.
const _: () = assert!(L2_SIZE as u64 == syscall::CSPACE_SLOTS_PER_PAGE);

/// Inline root pointers to leaf pages (the direct region). The four inline
/// regions together are the `CSpace`'s fixed root of 256 pointers; each
/// region past the direct one reaches its leaves through one more level of
/// pool-allocated directory pages
/// (core/kernel/docs/capability-internals.md § Storage: Hybrid Radix
/// Directory).
const L1_DIRECT: usize = 128;

/// Inline root pointers to level-1 directory pages (the indirect region),
/// each naming `DIR_FANOUT` leaves.
const L1_INDIRECT: usize = 64;

/// Inline root pointers to level-2 directory pages (the double-indirect
/// region), each naming `DIR_FANOUT` level-1 directory pages.
const L1_DOUBLE: usize = 63;

/// Inline root pointers to level-3 directory pages (the triple-indirect
/// region), each naming `DIR_FANOUT` level-2 directory pages. One entry
/// carries the ceiling to the handle's index field.
const L1_TRIPLE: usize = 1;

/// Pointers per pool-allocated directory page (one 4 KiB page of 8-byte
/// pointers).
const DIR_FANOUT: usize = crate::mm::PAGE_SIZE / core::mem::size_of::<*mut CSpacePage>();

/// First leaf of the indirect region.
const INDIRECT_BASE: usize = L1_DIRECT;

/// First leaf of the double-indirect region.
const DOUBLE_BASE: usize = INDIRECT_BASE + L1_INDIRECT * DIR_FANOUT;

/// First leaf of the triple-indirect region.
const TRIPLE_BASE: usize = DOUBLE_BASE + L1_DOUBLE * DIR_FANOUT * DIR_FANOUT;

/// Leaves the root's four regions can address.
const GEOMETRY_LEAVES: usize = TRIPLE_BASE + L1_TRIPLE * DIR_FANOUT * DIR_FANOUT * DIR_FANOUT;

/// Leaf pages a `CSpace` can ever hold: the whole leaves the cap handle's
/// 32-bit index field addresses, or fewer if the root's regions address
/// fewer.
const MAX_LEAVES: usize = {
    let field_leaves = (1usize << syscall::CAP_INDEX_BITS) / L2_SIZE;
    if GEOMETRY_LEAVES < field_leaves
    {
        GEOMETRY_LEAVES
    }
    else
    {
        field_leaves
    }
};

/// The directory's structural slot ceiling; see
/// core/kernel/docs/capability-internals.md § Storage: Hybrid Radix
/// Directory for the bound's role.
pub const MAX_SLOTS_STRUCTURAL: usize = MAX_LEAVES * L2_SIZE;

// Every slot index must fit in the cap handle's 32-bit index field; the rest
// of the handle carries the per-slot generation. The directory reaches the
// field, so the field, not the directory, bounds a `CSpace`; a ceiling past
// the field would truncate indices — trip at compile time instead.
const _: () = assert!(MAX_SLOTS_STRUCTURAL <= (1usize << syscall::CAP_INDEX_BITS));

// The root of 256 pointers is the `CSpace`'s inline size; a region split that
// grows it would grow every `CSpace` wrapper.
const _: () = assert!(L1_DIRECT + L1_INDIRECT + L1_DOUBLE + L1_TRIPLE == 256);

// The leaf cursor is a u32; the ceiling must fit it.
const _: () = assert!(MAX_LEAVES <= u32::MAX as usize);

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by `CSpace` operations.
#[derive(Debug, PartialEq, Eq)]
pub enum CapError
{
    /// The directory is full: every leaf up to `MAX_LEAVES` is populated and no
    /// free slot remains (the structural ceiling; see docs/capability-model.md
    /// § Address-space and `CSpace` growth budgets).
    OutOfSlots,
    /// The slot-page pool was exhausted while growing (see
    /// docs/capability-model.md § Address-space and `CSpace` growth budgets).
    /// (Host-test heap path: heap allocation failed.)
    PoolExhausted,
    /// The provided slot index is out of range or unmapped.
    InvalidIndex,
    /// Mapping request violates the W^X constraint (both writable and executable).
    WxViolation,
}

/// The one canonical `CapError` → `SyscallError` mapping. Every syscall-path
/// consumer routes through this so the two `CSpace` growth bounds
/// (docs/capability-model.md § Address-space and `CSpace` growth budgets)
/// reach userspace uniformly (#366).
impl From<CapError> for syscall::SyscallError
{
    fn from(e: CapError) -> Self
    {
        match e
        {
            CapError::OutOfSlots => Self::QuotaExceeded,
            CapError::PoolExhausted => Self::OutOfMemory,
            CapError::InvalidIndex => Self::InvalidArgument,
            CapError::WxViolation => Self::WxViolation,
        }
    }
}

// ── CSpacePage ────────────────────────────────────────────────────────────────

/// One page of capability slots.
///
/// Popped from the owning `CSpaceKernelObject`'s growth pool (host tests
/// box one). All-zeros is a valid initial state (every slot is null).
#[repr(C)]
struct CSpacePage
{
    slots: [CapabilitySlot; L2_SIZE],
}

// CSpacePage MUST fit in a single 4 KiB page — `alloc_slot_page` returns
// `PAGE_SIZE`-aligned bytes and the kernel casts that to `*mut CSpacePage`
// expecting one struct per allocation. A regression that grows
// `CapabilitySlot` beyond the headroom would overflow the pool page silently;
// the assertion makes that a build error.
const _: () = assert!(
    core::mem::size_of::<CSpacePage>() <= crate::mm::PAGE_SIZE,
    "CSpacePage exceeds PAGE_SIZE — reduce L2_SIZE or shrink CapabilitySlot"
);

// ── Directory pages ───────────────────────────────────────────────────────────

/// One pool-allocated directory page: `DIR_FANOUT` pointers to the next level
/// down, leaf pages for a [`DirLeaves`] page, directory pages for the levels
/// above it. Every entry names that level's sentinel in the initial state,
/// set by [`CSpace::grow`] before the page is published; no entry is null.
/// Entries are write-once while the `CSpace` is live: published with Release
/// by [`CSpace::grow`], read with Acquire by the lock-free lookup path.
#[repr(C)]
struct DirPage<T>
{
    entries: [AtomicPtr<T>; DIR_FANOUT],
}

/// A level-1 directory page: `DIR_FANOUT` leaf pointers.
type DirLeaves = DirPage<CSpacePage>;
/// A level-2 directory page: `DIR_FANOUT` level-1 directory pointers.
type DirLevel2 = DirPage<DirLeaves>;
/// A level-3 directory page: `DIR_FANOUT` level-2 directory pointers.
type DirLevel3 = DirPage<DirLevel2>;

// A directory page occupies exactly one page — `grow` pops one pool page per
// directory page and casts it wholesale. Every level has the same layout.
const _: () = assert!(core::mem::size_of::<DirLeaves>() == crate::mm::PAGE_SIZE);

// The triple region's root entries cover the leaves up to the ceiling, so
// the masked lookup's root index stays inside `triple`.
const _: () = assert!(MAX_LEAVES <= GEOMETRY_LEAVES && MAX_LEAVES > TRIPLE_BASE);

// ── Sentinel pages ────────────────────────────────────────────────────────────

/// The leaf every unallocated leaf pointer names: all slots `Null`, never
/// written. It holds no interior mutability, so it is placed in read-only
/// data and a stray write through it faults.
///
/// With it, a leaf pointer the lookup path loads is never null, so the path
/// carries no null test whose misprediction could dereference a null leaf;
/// the masked fallback of [`CSpace::leaf_ptr`] resolves here too
/// (core/kernel/docs/capability-internals.md § Speculative-Execution
/// Hardening).
// SAFETY: all-zero bytes are a valid `CSpacePage` (every slot `Null`, with
// `None` object and derivation links), the state a freshly zeroed pool page
// has.
static SENTINEL_LEAF: CSpacePage = unsafe { core::mem::MaybeUninit::zeroed().assume_init() };

/// The level-1 directory every unallocated level-1 pointer names: each entry
/// names [`SENTINEL_LEAF`]. Never written; its entries are atomics only
/// because a live directory page's are.
static SENTINEL_DIR: DirLeaves = DirPage {
    entries: [const { AtomicPtr::new(sentinel_leaf()) }; DIR_FANOUT],
};

/// The level-2 directory every unallocated level-2 pointer names: each entry
/// names [`SENTINEL_DIR`]. Never written.
static SENTINEL_DIR2: DirLevel2 = DirPage {
    entries: [const { AtomicPtr::new(sentinel_dir()) }; DIR_FANOUT],
};

/// The level-3 directory every unallocated level-3 pointer names: each entry
/// names [`SENTINEL_DIR2`]. Never written.
static SENTINEL_DIR3: DirLevel3 = DirPage {
    entries: [const { AtomicPtr::new(sentinel_dir2()) }; DIR_FANOUT],
};

/// [`SENTINEL_LEAF`] as the pointer type a leaf entry holds. Nothing writes
/// through it: [`CSpace::slot_mut`] refuses it, and a grow publishes a fresh
/// page in its place.
const fn sentinel_leaf() -> *mut CSpacePage
{
    (&raw const SENTINEL_LEAF).cast_mut()
}

/// [`SENTINEL_DIR`] as the pointer type a level-1 entry holds. Its entries
/// are never stored to: a grow under it publishes a fresh directory page
/// first.
const fn sentinel_dir() -> *mut DirLeaves
{
    (&raw const SENTINEL_DIR).cast_mut()
}

/// [`SENTINEL_DIR2`] as the pointer type a level-2 entry holds; never stored
/// to, as [`sentinel_dir`].
const fn sentinel_dir2() -> *mut DirLevel2
{
    (&raw const SENTINEL_DIR2).cast_mut()
}

/// [`SENTINEL_DIR3`] as the pointer type a level-3 entry holds; never stored
/// to, as [`sentinel_dir`].
const fn sentinel_dir3() -> *mut DirLevel3
{
    (&raw const SENTINEL_DIR3).cast_mut()
}

/// A page type a root or directory entry names, with the sentinel an entry
/// names while the page is unallocated.
trait Unallocated
{
    /// The sentinel of this level.
    fn sentinel() -> *mut Self;
}

impl Unallocated for CSpacePage
{
    fn sentinel() -> *mut Self
    {
        sentinel_leaf()
    }
}

impl Unallocated for DirLeaves
{
    fn sentinel() -> *mut Self
    {
        sentinel_dir()
    }
}

impl Unallocated for DirLevel2
{
    fn sentinel() -> *mut Self
    {
        sentinel_dir2()
    }
}

impl Unallocated for DirLevel3
{
    fn sentinel() -> *mut Self
    {
        sentinel_dir3()
    }
}

/// Load entry `i` of the root region or directory page `entries` with
/// `order`; an index past the entries, which no caller passes (each reduces
/// its index below the entries' count), reads as unallocated: the level's
/// sentinel.
fn load_at<T: Unallocated>(entries: &[AtomicPtr<T>], i: usize, order: Ordering) -> *mut T
{
    entries
        .get(i)
        .map_or_else(T::sentinel, |entry| entry.load(order))
}

/// Load entry `i` of directory page `dir` with Acquire, pairing with the
/// Release publication in [`CSpace::grow`]; see [`load_at`].
///
/// # Safety
/// `dir` names a live directory page of a `CSpace` or a static sentinel.
unsafe fn load_entry<T: Unallocated>(dir: *mut DirPage<T>, i: usize) -> *mut T
{
    // SAFETY: the caller's contract.
    load_at(unsafe { &(*dir).entries }, i, Ordering::Acquire)
}

/// The regions of a `CSpace` root, in leaf order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Region
{
    /// Leaves named by the root itself.
    Direct,
    /// Leaves under one level of directory pages.
    Indirect,
    /// Leaves under two levels of directory pages.
    Double,
    /// Leaves under three levels of directory pages.
    Triple,
}

/// The region holding `leaf`, and the leaf's index relative to the region's
/// first leaf. A leaf past the ceiling falls in the triple region; callers
/// bound it by `MAX_LEAVES`.
const fn region_of(leaf: usize) -> (Region, usize)
{
    if let Some(rel) = leaf.checked_sub(TRIPLE_BASE)
    {
        (Region::Triple, rel)
    }
    else if let Some(rel) = leaf.checked_sub(DOUBLE_BASE)
    {
        (Region::Double, rel)
    }
    else if let Some(rel) = leaf.checked_sub(INDIRECT_BASE)
    {
        (Region::Indirect, rel)
    }
    else
    {
        (Region::Direct, leaf)
    }
}

/// The regions past the direct one as `(first leaf, end leaf, directory
/// levels)`, the end clamped to the ceiling.
const DEEP_REGIONS: [(usize, usize, u32); 3] = [
    (INDIRECT_BASE, DOUBLE_BASE, 1),
    (DOUBLE_BASE, TRIPLE_BASE, 2),
    (TRIPLE_BASE, MAX_LEAVES, 3),
];

// ── CSpace ────────────────────────────────────────────────────────────────────

/// A capability space: a growable indexed collection of capability slots.
///
/// Slots are identified by a `u32` index. Slot 0 is permanently null. Indices
/// are stable for the lifetime of the capability they hold.
///
/// To add a capability: call [`insert_cap`][CSpace::insert_cap].
/// To look up a slot: call [`slot`][CSpace::slot] or [`slot_mut`][CSpace::slot_mut].
///
/// ## Concurrency and memory ordering
///
/// State is split between the `CSpace` spinlock and `DERIVATION_LOCK`;
/// directory and leaf pointers are write-once and Release-published by
/// [`grow`][Self::grow], so [`slot`][Self::slot] serves lock-free readers
/// (the transfer pre-validation and the capability-tree syscalls' unlocked
/// pre-checks, which dereference no object). A syscall that uses the object
/// a handle names reads the slot under this `CSpace`'s lock instead, and pins
/// the object there (`syscall::pin_slot`). The full
/// contract is in core/kernel/docs/capability-internals.md § Storage: Hybrid
/// Radix Directory.
pub struct CSpace
{
    id: CSpaceId,
    /// Direct region: inline pointers to the first `L1_DIRECT` leaf
    /// pages. [`SENTINEL_LEAF`] = unallocated; never null. Pages come from
    /// the retype pool (or the host heap in the test stub — the `kobj` field
    /// discriminates: null =
    /// heap, Drop Box-frees each page; non-null = retype pool,
    /// `dealloc_object(CSpaceObj)` reclaims donations wholesale).
    direct: [AtomicPtr<CSpacePage>; L1_DIRECT],
    /// Indirect region: inline pointers to pool-allocated level-1 directory
    /// pages, each fanning out to `DIR_FANOUT` further leaves.
    /// [`SENTINEL_DIR`] = unallocated; never null.
    indirect: [AtomicPtr<DirLeaves>; L1_INDIRECT],
    /// Double-indirect region: inline pointers to level-2 directory pages.
    /// [`SENTINEL_DIR2`] = unallocated; never null.
    double: [AtomicPtr<DirLevel2>; L1_DOUBLE],
    /// Triple-indirect region: inline pointers to level-3 directory pages.
    /// [`SENTINEL_DIR3`] = unallocated; never null.
    triple: [AtomicPtr<DirLevel3>; L1_TRIPLE],
    /// Grow cursor: leaves `0..next_leaf` are allocated (contiguously);
    /// `next_leaf` is the next leaf `grow` will materialise. A `u32` holds it:
    /// a compile-time assert bounds `MAX_LEAVES` by `u32::MAX`.
    next_leaf: u32,
    /// Total usable slots allocated across all pages (excludes slot 0).
    allocated_slots: usize,
    /// Slot-page pool exhaustions seen by `grow`, for the throttled
    /// diagnostic (logged at powers of two). A wrapping diagnostic counter;
    /// it bounds no capacity.
    pool_exhaustions: u32,
    /// Head of the intrusive free list; None if no free slots.
    ///
    /// Slot 0 is permanently null and never placed on the free list, so the
    /// head index is always non-zero when present — encoded in the type.
    free_head: Option<NonZeroU32>,
    /// Tail of the intrusive free list; None if no free slots. `grow`
    /// appends a new leaf's slots here, so the slots a general allocation
    /// leaves free for the IPC receive reserve are handed out before the new
    /// leaf's and allocation order stays ascending across a grow.
    free_tail: Option<NonZeroU32>,
    /// Number of slots currently on the free list (for O(1) `pre_allocate`).
    free_count: usize,
    /// Protects concurrent access to all `CSpace` state: the grow cursor, the
    /// counters, and the free list above are bare fields owned by this lock,
    /// under the exception of docs/coding-standards.md § Concurrency
    /// (core/kernel/docs/capability-internals.md § Storage: Hybrid Radix
    /// Directory records it).
    pub(crate) lock: crate::sync::Spinlock,
    /// Pool source for new slot and directory pages (pop from
    /// `CSpaceKernelObject::alloc_slot_page`); null only in the host-test
    /// stub, which boxes pages instead. Set once via [`Self::set_kobj`]
    /// right after construction.
    kobj: AtomicPtr<CSpaceKernelObject>,
    /// Host-test stand-in for a finite slot-page pool: the heap pages the
    /// test stub may still allocate, or `None` for unbounded.
    #[cfg(test)]
    test_page_budget: Option<usize>,
}

// SAFETY: page pointers are write-once, Release-published after full
// initialisation, and never freed while the CSpace is live; all other state
// is mutated only under `self.lock` (or single-threaded refcount-0
// teardown). Lock-free readers use Acquire loads.
unsafe impl Send for CSpace {}
// SAFETY: see Send impl above.
unsafe impl Sync for CSpace {}

impl CSpace
{
    /// Create an empty `CSpace`. No pages are allocated until the first slot
    /// is requested. The pool source defaults to null (the host-test heap
    /// path); call [`Self::set_kobj`] to switch to a retype pool.
    pub fn new(id: CSpaceId) -> Self
    {
        Self {
            id,
            direct: core::array::from_fn(|_| AtomicPtr::new(sentinel_leaf())),
            indirect: core::array::from_fn(|_| AtomicPtr::new(sentinel_dir())),
            double: core::array::from_fn(|_| AtomicPtr::new(sentinel_dir2())),
            triple: core::array::from_fn(|_| AtomicPtr::new(sentinel_dir3())),
            next_leaf: 0,
            allocated_slots: 0,
            pool_exhaustions: 0,
            free_head: None,
            free_tail: None,
            free_count: 0,
            lock: crate::sync::Spinlock::new(),
            kobj: AtomicPtr::new(core::ptr::null_mut()),
            #[cfg(test)]
            test_page_budget: None,
        }
    }

    /// Wire this `CSpace` to a `CSpaceKernelObject`'s slot-page pool.
    ///
    /// MUST be called before any `grow()` if the `CSpace` is retype-backed.
    /// Calling on a `CSpace` that has already grown via the host-test heap path
    /// produces a mixed-allocation directory and is a kernel bug.
    pub fn set_kobj(&self, kobj: *mut CSpaceKernelObject)
    {
        self.kobj.store(kobj, Ordering::Release);
    }

    /// Read the wrapping [`CSpaceKernelObject`] pointer wired by
    /// [`set_kobj`]. Returns `None` for the host-test stub `CSpace`s that
    /// never wire a wrapper. Phase 9 uses this to insert init's `CSpace` cap
    /// without re-allocating a fresh wrapper.
    pub fn kobj_ptr(&self) -> Option<*mut CSpaceKernelObject>
    {
        let p = self.kobj.load(Ordering::Acquire);
        if p.is_null() { None } else { Some(p) }
    }

    /// Bound the host-test stub's heap pages to `pages`, standing in for a
    /// finite slot-page pool.
    #[cfg(test)]
    pub(crate) fn set_test_page_budget(&mut self, pages: usize)
    {
        self.test_page_budget = Some(pages);
    }

    /// Return this `CSpace`'s unique identifier.
    pub fn id(&self) -> CSpaceId
    {
        self.id
    }

    /// Allocate a free slot index for a general insert, growing the `CSpace`
    /// if needed.
    ///
    /// Leaves [`IPC_RECV_RESERVE`] free slots behind: when fewer than
    /// `IPC_RECV_RESERVE + 1` slots are free and the `CSpace` cannot grow,
    /// it fails with the grow's error even though reserved slots remain.
    /// Returns [`CapError::OutOfSlots`] if the directory is structurally
    /// full, or [`CapError::PoolExhausted`] if the slot-page pool has no
    /// page left. The returned slot is cleared to null; callers must
    /// populate it.
    ///
    /// The returned index is always non-zero (slot 0 is reserved).
    pub fn allocate_slot(&mut self) -> Result<NonZeroU32, CapError>
    {
        self.pre_allocate(IPC_RECV_RESERVE + 1)?;
        self.pop_free_slot()
    }

    /// Allocate a free slot index for an IPC capability transfer, taking
    /// a reserved slot when no other is free.
    ///
    /// Errors as [`Self::allocate_slot`], reached only once every free slot,
    /// the reserve included, is taken and the `CSpace` cannot grow.
    pub fn allocate_transfer_slot(&mut self) -> Result<NonZeroU32, CapError>
    {
        self.pre_allocate(1)?;
        self.pop_free_slot()
    }

    /// Pop the free list's head. The caller has made the list non-empty.
    fn pop_free_slot(&mut self) -> Result<NonZeroU32, CapError>
    {
        let idx = self.free_head.ok_or(CapError::OutOfSlots)?;

        // Read next_free through a shared borrow, then drop it before the
        // mutable borrow so the borrow checker is satisfied.
        let next = {
            let slot = self.slot(idx.get()).ok_or(CapError::InvalidIndex)?;
            // The free-time guard prevents an occupied slot from ever entering
            // the list; this catches any other corruption source before we hand
            // the slot out, so `allocate_slot` never returns an occupied slot.
            debug_assert!(
                slot.is_on_free_list(),
                "allocate_slot popped a slot not on the free list"
            );
            slot.next_free()
        };

        self.free_head = next;
        if next.is_none()
        {
            self.free_tail = None;
        }
        if let Some(new_head) = next
            && let Some(head_slot) = self.slot_mut(new_head.get())
        {
            head_slot.set_prev_free_link(None);
        }
        // Clear the slot (removes free-list encoding) but keep the per-slot
        // generation that `free_slot` left, so the minted cap handle's
        // generation matches the slot the recipient will resolve (#349).
        let slot = self.slot_mut(idx.get()).ok_or(CapError::InvalidIndex)?;
        slot.clear_keep_generation();
        // The popped slot was counted free, so the count does not saturate.
        self.free_count = self.free_count.saturating_sub(1);
        Ok(idx)
    }

    /// Allocate one zeroed backing page for a leaf or directory page.
    ///
    /// Production `CSpace`s are always retype-backed (root via
    /// `boot_retype_cspace`, userspace via `sys_cap_create_cspace`) and pop
    /// from the wrapper's pool; the host-test stub allocates from the heap.
    /// `T` must be a page-sized-or-smaller type whose all-zeros bit pattern
    /// is a valid value (both `CSpacePage` and every `DirPage` are).
    fn alloc_zeroed_page<T>(&mut self) -> Result<NonNull<T>, CapError>
    {
        const {
            assert!(
                core::mem::size_of::<T>() <= crate::mm::PAGE_SIZE,
                "alloc_zeroed_page: T exceeds one pool page"
            );
        }
        let kobj_ptr = self.kobj.load(Ordering::Acquire);
        #[cfg(not(test))]
        {
            debug_assert!(
                !kobj_ptr.is_null(),
                "CSpace::alloc_zeroed_page: production CSpace must be retype-backed"
            );
            // SAFETY: kobj_ptr is the wrapper that owns this CSpace; its
            // pool was seeded at retype time.
            let Some(phys) = (unsafe { (*kobj_ptr).alloc_slot_page() })
            else
            {
                // Logged at powers of two (the #365 pattern): a userspace
                // loop retrying an insert, a reply, or a transfer into a
                // pool-starved CSpace reaches this under the derivation
                // lock, and a console write per attempt must not serialise
                // behind it.
                self.pool_exhaustions = self.pool_exhaustions.wrapping_add(1);
                let occurrence = self.pool_exhaustions;
                if occurrence.is_power_of_two()
                {
                    crate::kprintln!(
                        "cspace {}: slot-page pool exhausted (allocated={} occurrence={})",
                        self.id,
                        self.allocated_slots,
                        occurrence
                    );
                }
                return Err(CapError::PoolExhausted);
            };
            let virt = crate::mm::paging::phys_to_virt(phys);
            // SAFETY: pool returns page-aligned, freshly-zeroed pages mapped
            // in the kernel direct map; T fits one page and is zero-valid.
            Ok(unsafe { NonNull::new_unchecked(virt as *mut T) })
        }
        #[cfg(test)]
        {
            if kobj_ptr.is_null()
            {
                if let Some(left) = self.test_page_budget.as_mut()
                {
                    if *left == 0
                    {
                        return Err(CapError::PoolExhausted);
                    }
                    *left -= 1;
                }
                // Test stub: no retype machinery, allocate via the host
                // heap.
                // SAFETY: the caller's T is zero-valid per the contract.
                let boxed = Box::new(unsafe { core::mem::zeroed::<T>() });
                Ok(Box::into_non_null(boxed))
            }
            else
            {
                Err(CapError::PoolExhausted)
            }
        }
    }

    /// Allocate a directory page whose every entry names `child` (the empty
    /// state; no entry is ever null), not yet published.
    fn new_dir<T>(&mut self, child: *mut T) -> Result<*mut DirPage<T>, CapError>
    {
        let dir: NonNull<DirPage<T>> = self.alloc_zeroed_page()?;
        // SAFETY: dir points at an exclusively-owned page not yet published
        // to any reader.
        for entry in unsafe { &dir.as_ref().entries }
        {
            entry.store(child, Ordering::Relaxed);
        }
        Ok(dir.as_ptr())
    }

    /// The directory page root entry `i` of the region `root` picks names,
    /// materialised and published first when the entry names `sentinel`.
    /// The Release publication pairs with the lookup path's Acquire, so a
    /// lock-free reader never observes an entry before its initialisation.
    /// An index past the region, which `ensure_leaf_dir` never passes (it
    /// reduces each below its region's root entries), is
    /// [`CapError::InvalidIndex`].
    fn root_dir<T>(
        &mut self,
        root: fn(&Self) -> &[AtomicPtr<DirPage<T>>],
        i: usize,
        sentinel: *mut DirPage<T>,
        child: *mut T,
    ) -> Result<*mut DirPage<T>, CapError>
    {
        let current = root(self)
            .get(i)
            .ok_or(CapError::InvalidIndex)?
            .load(Ordering::Relaxed);
        if current != sentinel
        {
            return Ok(current);
        }
        let dir = self.new_dir(child)?;
        if let Some(entry) = root(self).get(i)
        {
            entry.store(dir, Ordering::Release);
        }
        Ok(dir)
    }

    /// The directory page entry `i` of `parent` names, materialised and
    /// published first when the entry names `sentinel`, as [`Self::root_dir`].
    ///
    /// An index past the page, which no caller passes (each reduces it below
    /// `DIR_FANOUT`), is [`CapError::InvalidIndex`].
    ///
    /// # Safety
    /// `parent` is a live, published directory page of this `CSpace` (never a
    /// sentinel), and the caller holds this `CSpace`'s lock.
    unsafe fn child_dir<T>(
        &mut self,
        parent: *mut DirPage<DirPage<T>>,
        i: usize,
        sentinel: *mut DirPage<T>,
        child: *mut T,
    ) -> Result<*mut DirPage<T>, CapError>
    {
        // SAFETY: the caller's contract; the page is pool memory, not part of
        // `self`, so the borrow of `self` below does not alias it.
        let entry = unsafe { &(*parent).entries }
            .get(i)
            .ok_or(CapError::InvalidIndex)?;
        let current = entry.load(Ordering::Relaxed);
        if current != sentinel
        {
            return Ok(current);
        }
        let dir = self.new_dir(child)?;
        entry.store(dir, Ordering::Release);
        Ok(dir)
    }

    /// The level-1 directory page above `leaf`, a leaf past the direct
    /// region, with every missing directory page above it materialised top
    /// level first. A page materialised here stays published if a lower one,
    /// or the leaf, then fails to allocate: already paid for, it serves the
    /// next grow.
    fn ensure_leaf_dir(&mut self, leaf: usize) -> Result<*mut DirLeaves, CapError>
    {
        const F2: usize = DIR_FANOUT * DIR_FANOUT;
        const F3: usize = F2 * DIR_FANOUT;
        let (region, rel) = region_of(leaf);
        match region
        {
            Region::Direct => Err(CapError::InvalidIndex),
            Region::Indirect => self.root_dir(
                |cs| &cs.indirect,
                rel / DIR_FANOUT,
                sentinel_dir(),
                sentinel_leaf(),
            ),
            Region::Double =>
            {
                let dir2 =
                    self.root_dir(|cs| &cs.double, rel / F2, sentinel_dir2(), sentinel_dir())?;
                // SAFETY: dir2 is the live level-2 page just ensured, under
                // this CSpace's lock (grow's caller holds it).
                unsafe {
                    self.child_dir(
                        dir2,
                        (rel / DIR_FANOUT) % DIR_FANOUT,
                        sentinel_dir(),
                        sentinel_leaf(),
                    )
                }
            }
            Region::Triple =>
            {
                let dir3 =
                    self.root_dir(|cs| &cs.triple, rel / F3, sentinel_dir3(), sentinel_dir2())?;
                // SAFETY: dir3 is the live page just ensured, under this CSpace's lock (grow's
                // caller holds it).
                let dir2 = unsafe {
                    self.child_dir(
                        dir3,
                        (rel / F2) % DIR_FANOUT,
                        sentinel_dir2(),
                        sentinel_dir(),
                    )
                }?;
                // SAFETY: dir2 is the live page just ensured, under this CSpace's lock (grow's
                // caller holds it).
                unsafe {
                    self.child_dir(
                        dir2,
                        (rel / DIR_FANOUT) % DIR_FANOUT,
                        sentinel_dir(),
                        sentinel_leaf(),
                    )
                }
            }
        }
    }

    /// Whether the level-`level` directory page above `leaf` (1 the page of
    /// leaf pointers, up to the region's depth) is materialised. `leaf` is
    /// below `MAX_LEAVES`.
    fn dir_exists(&self, leaf: usize, level: u32) -> bool
    {
        const F2: usize = DIR_FANOUT * DIR_FANOUT;
        const F3: usize = F2 * DIR_FANOUT;
        let (region, rel) = region_of(leaf);
        // SAFETY (each `load_entry`): every entry names a live directory page
        // of the next level or that level's sentinel, and each index is
        // reduced below DIR_FANOUT; a walk through a sentinel reads only
        // sentinels.
        match region
        {
            Region::Direct => false,
            Region::Indirect =>
            {
                load_at(&self.indirect, rel / DIR_FANOUT, Ordering::Relaxed) != sentinel_dir()
            }
            Region::Double =>
            {
                let dir2 = load_at(&self.double, rel / F2, Ordering::Relaxed);
                if level >= 2
                {
                    return dir2 != sentinel_dir2();
                }
                // SAFETY: see above.
                unsafe { load_entry(dir2, (rel / DIR_FANOUT) % DIR_FANOUT) != sentinel_dir() }
            }
            Region::Triple =>
            {
                let dir3 = load_at(&self.triple, rel / F3, Ordering::Relaxed);
                if level >= 3
                {
                    return dir3 != sentinel_dir3();
                }
                // SAFETY: see above.
                let dir2 = unsafe { load_entry(dir3, (rel / F2) % DIR_FANOUT) };
                if level == 2
                {
                    return dir2 != sentinel_dir2();
                }
                // SAFETY: see above.
                unsafe { load_entry(dir2, (rel / DIR_FANOUT) % DIR_FANOUT) != sentinel_dir() }
            }
        }
    }

    /// Grow the `CSpace` by one leaf page.
    ///
    /// Materialises leaf `next_leaf` (and, past the direct region, every
    /// missing directory page above it), threads its slots onto the free list,
    /// publishes it, and advances the cursor; slot 0 in the first leaf is
    /// skipped. Failure behaviour follows core/kernel/docs/capability-internals.md
    /// § Storage: Hybrid Radix Directory.
    fn grow(&mut self) -> Result<(), CapError>
    {
        let leaf_idx = self.next_leaf as usize;
        if leaf_idx >= MAX_LEAVES
        {
            return Err(CapError::OutOfSlots);
        }

        // Past the direct region: ensure every directory page above the leaf
        // exists, top level first.
        let leaf_dir = if leaf_idx < INDIRECT_BASE
        {
            None
        }
        else
        {
            Some(self.ensure_leaf_dir(leaf_idx)?)
        };

        let mut page_nn: NonNull<CSpacePage> = self.alloc_zeroed_page()?;
        // SAFETY: page_nn points at an exclusively-owned, zeroed CSpacePage
        // not yet published to any reader.
        let page = unsafe { page_nn.as_mut() };

        // Thread the leaf's slots onto the free list BEFORE publication so
        // the Release store below orders the initialised slot bytes ahead
        // of pointer visibility. The leaf is below `MAX_LEAVES`, so its slot
        // indices are below `MAX_SLOTS_STRUCTURAL` and nothing here saturates.
        let base = leaf_idx.saturating_mul(L2_SIZE);
        let start_slot = usize::from(leaf_idx == 0);
        // Append the leaf's slots, ascending, after the current tail. The
        // free slots a general allocation leaves for the IPC receive reserve
        // are therefore handed out before the new leaf's, so allocation stays
        // in ascending index order across a grow (a run of consecutive
        // inserts gets consecutive indices, as `InitInfo`'s contiguous
        // Memory-cap ranges require). The predecessor links make
        // `remove_from_free_list` O(1).
        let old_tail = self.free_tail;
        let mut prev = old_tail;
        let mut first: Option<NonZeroU32> = None;
        let mut new_free = 0usize;
        let mut slots = page
            .slots
            .iter_mut()
            .zip(base..)
            .skip(start_slot)
            .peekable();
        while let Some((slot, index)) = slots.next()
        {
            // `index >= 1`: `start_slot` skips slot 0 of the first leaf. A
            // zero index (unreachable) is left off the list — fail closed —
            // rather than threaded as some other slot.
            debug_assert!(index >= 1, "grow: slot 0 must not be threaded");
            let Some(idx) = NonZeroU32::new(index as u32)
            else
            {
                continue;
            };
            let next = slots
                .peek()
                .and_then(|&(_, next)| NonZeroU32::new(next as u32));
            slot.set_next_free(next);
            slot.set_prev_free_link(prev);
            prev = Some(idx);
            first.get_or_insert(idx);
            new_free = new_free.saturating_add(1);
        }
        match old_tail
        {
            // The old tail lives in an already-published page, reached via
            // slot_mut.
            Some(tail) =>
            {
                if let Some(tail_slot) = self.slot_mut(tail.get())
                {
                    tail_slot.set_next_free_link(first);
                }
            }
            None => self.free_head = first,
        }
        self.free_tail = prev;

        // Publish. The entry exists: a leaf with no level-1 page is below
        // `INDIRECT_BASE`, the direct region's length, and a leaf's entry in
        // its level-1 page is its region-relative index modulo the fan-out
        // (`region_of`).
        let entry = match leaf_dir
        {
            None => self.direct.get(leaf_idx),
            Some(dir) =>
            {
                let (_, rel) = region_of(leaf_idx);
                // SAFETY: a real level-1 directory page, ensured above under
                // the same lock (never a sentinel); directory pages are
                // write-once and never freed while the CSpace lives.
                unsafe { (*dir).entries.get(rel % DIR_FANOUT) }
            }
        };
        if let Some(entry) = entry
        {
            entry.store(page_nn.as_ptr(), Ordering::Release);
        }

        // The cursor stays at most `MAX_LEAVES`, which fits a u32, and the
        // slot counts at most `MAX_SLOTS_STRUCTURAL`: none saturates.
        self.next_leaf = self.next_leaf.saturating_add(1);
        self.allocated_slots = self.allocated_slots.saturating_add(new_free);
        self.free_count = self.free_count.saturating_add(new_free);
        Ok(())
    }

    /// Resolve a leaf index to its page pointer: the leaf's page when it is
    /// allocated, [`SENTINEL_LEAF`] when it is unallocated or out of range.
    ///
    /// The region branches choose among the four regions' walks, and each
    /// walk bounds its own region-relative index as data
    /// (`nospec::index_mask`) before any load and selects the sentinel when
    /// that bound fails, so no misprediction of a region branch addresses an
    /// entry past its array, and the masked fallback reaches no leaf but the
    /// sentinel. The loaded pointers are never null (unallocated entries name
    /// the sentinels), so no null test sits on the path. The deepest walk,
    /// the triple-indirect region's, makes three dependent directory loads
    /// before the leaf.
    ///
    /// Acquire loads at each level pair with [`grow`][Self::grow]'s Release
    /// publications, so a non-sentinel result points at a fully-initialised
    /// page (see the struct's memory-ordering contract).
    fn leaf_ptr(&self, leaf_idx: usize) -> *mut CSpacePage
    {
        const F2: usize = DIR_FANOUT * DIR_FANOUT;
        const F3: usize = F2 * DIR_FANOUT;
        // SAFETY (every `load_entry` below): a root or directory entry is
        // never null: it names a directory page of the next level down
        // (write-once, Release-published after its entries were set, never
        // freed while the CSpace is live) or that level's static sentinel,
        // and each entry index is reduced below `DIR_FANOUT` or masked below
        // its region's span.
        if leaf_idx < INDIRECT_BASE
        {
            let in_range = nospec::index_mask(leaf_idx, L1_DIRECT);
            let page = load_at(&self.direct, leaf_idx & in_range, Ordering::Acquire);
            nospec::select_ptr(in_range, page, sentinel_leaf())
        }
        else if leaf_idx < DOUBLE_BASE
        {
            let rel = leaf_idx.wrapping_sub(INDIRECT_BASE);
            let in_range = nospec::index_mask(rel, L1_INDIRECT * DIR_FANOUT);
            let rel = rel & in_range;
            let dir = load_at(&self.indirect, rel / DIR_FANOUT, Ordering::Acquire);
            // SAFETY: see above.
            let page = unsafe { load_entry(dir, rel % DIR_FANOUT) };
            nospec::select_ptr(in_range, page, sentinel_leaf())
        }
        else if leaf_idx < TRIPLE_BASE
        {
            let rel = leaf_idx.wrapping_sub(DOUBLE_BASE);
            let in_range = nospec::index_mask(rel, L1_DOUBLE * F2);
            let rel = rel & in_range;
            let dir2 = load_at(&self.double, rel / F2, Ordering::Acquire);
            // SAFETY: see above.
            let dir = unsafe { load_entry(dir2, (rel / DIR_FANOUT) % DIR_FANOUT) };
            // SAFETY: see above.
            let page = unsafe { load_entry(dir, rel % DIR_FANOUT) };
            nospec::select_ptr(in_range, page, sentinel_leaf())
        }
        else
        {
            // Bounded by the ceiling, not the region's span: no leaf at or
            // past MAX_LEAVES is ever grown, and the const assert beside
            // `DirPage` keeps the root index inside `triple`.
            let rel = leaf_idx.wrapping_sub(TRIPLE_BASE);
            let in_range = nospec::index_mask(rel, MAX_LEAVES - TRIPLE_BASE);
            let rel = rel & in_range;
            let dir3 = load_at(&self.triple, rel / F3, Ordering::Acquire);
            // SAFETY: see above.
            let dir2 = unsafe { load_entry(dir3, (rel / F2) % DIR_FANOUT) };
            // SAFETY: see above.
            let dir = unsafe { load_entry(dir2, (rel / DIR_FANOUT) % DIR_FANOUT) };
            // SAFETY: see above.
            let page = unsafe { load_entry(dir, rel % DIR_FANOUT) };
            nospec::select_ptr(in_range, page, sentinel_leaf())
        }
    }

    /// Look up a slot by index. Returns `None` if the index is out of range
    /// or the backing page has not been allocated.
    ///
    /// The `None` decision follows the loads: on whichever path reaches the
    /// slot read, the page is a live leaf of this `CSpace` or the all-`Null`
    /// sentinel.
    pub fn slot(&self, index: u32) -> Option<&CapabilitySlot>
    {
        let idx = index as usize;
        let page = self.leaf_ptr(idx / L2_SIZE);
        if page == sentinel_leaf()
        {
            return None;
        }
        // SAFETY: page is a live leaf (not the sentinel, checked above); leaf
        // pages are never freed or moved while the CSpace is live;
        // CapabilitySlot is repr(C) and the page bytes belong to this CSpace.
        // Content races are defended by tag/generation checks at every
        // resolution site.
        let page = unsafe { &*page };
        page.slots.get(idx % L2_SIZE)
    }

    /// Mutable variant of [`slot`][Self::slot]. Never returns a slot of the
    /// sentinel leaf.
    pub fn slot_mut(&mut self, index: u32) -> Option<&mut CapabilitySlot>
    {
        let idx = index as usize;
        let page = self.leaf_ptr(idx / L2_SIZE);
        if page == sentinel_leaf()
        {
            return None;
        }
        // SAFETY: same as `slot`; `&mut self` comes from the holder of
        // whichever lock domain guards the fields being written (see the
        // struct's concurrency contract). The sentinel, which is shared and
        // read-only, is refused above.
        let page = unsafe { &mut *page };
        page.slots.get_mut(idx % L2_SIZE)
    }

    /// Number of allocated leaf pages; leaves `0..leaf_count()` are exactly
    /// the allocated ones (the grow cursor keeps them contiguous).
    ///
    /// Used by the pre-unregister derivation drain in
    /// `dealloc_object(CSpaceObj)` to bound its walk of the dying `CSpace`.
    pub(crate) fn leaf_count(&self) -> usize
    {
        self.next_leaf as usize
    }

    /// Pool pages a grow to cover `index`'s leaf would consume: the
    /// missing leaves plus the missing directory pages over that span, at
    /// every level. Zero when the covering leaf already exists; also zero for
    /// an out-of-range index (the placement path rejects it instead).
    ///
    /// Growth is contiguous, so over the span only the directory pages above
    /// the next leaf can already exist (published by a grow that then failed
    /// lower down); the count is arithmetic per level, with one probe each.
    ///
    /// Callers use this to fail a doomed explicit placement fast, before
    /// any pool page is consumed.
    pub(crate) fn pages_to_cover(&self, index: u32) -> u64
    {
        let target_leaf = index as usize / L2_SIZE;
        let next = self.next_leaf as usize;
        if target_leaf < next || target_leaf >= MAX_LEAVES
        {
            return 0;
        }
        // Every count below is of leaves or directory pages under
        // `MAX_LEAVES`, with `next <= target_leaf` and `base <= first <= last`
        // in each region: none saturates.
        let mut pages = (target_leaf.saturating_sub(next) as u64).saturating_add(1);
        for (base, end, depth) in DEEP_REGIONS
        {
            let first = next.max(base);
            let last = target_leaf.min(end.saturating_sub(1));
            if first > last
            {
                continue;
            }
            for level in 1..=depth
            {
                // The leaves one directory page of this level spans; never
                // zero.
                let Some(span) = NonZeroUsize::new(DIR_FANOUT.pow(level))
                else
                {
                    continue;
                };
                let spanned = (last.saturating_sub(base) / span)
                    .saturating_sub(first.saturating_sub(base) / span)
                    .saturating_add(1);
                let present = usize::from(self.dir_exists(first, level));
                pages = pages.saturating_add(spanned.saturating_sub(present) as u64);
            }
        }
        pages
    }

    /// Grow toward covering `index`'s leaf, materialising at most
    /// `max_leaves` leaves in this call. Returns `Ok(true)` once the
    /// covering leaf exists. Lets the explicit-placement syscall path
    /// pre-grow in bounded batches under only this `CSpace`'s lock,
    /// keeping each interrupts-off hold constant-sized.
    /// An `index` beyond the structural ceiling is clamped to the last leaf: the
    /// caller never passes one (`pages_to_cover` reports zero pages for it, and
    /// `insert_cap_at` rejects it), so the clamp only keeps this function total.
    pub(crate) fn grow_toward(&mut self, index: u32, max_leaves: usize) -> Result<bool, CapError>
    {
        let target_leaf = (index as usize / L2_SIZE).min(MAX_LEAVES - 1);
        let mut grown = 0usize;
        while (self.next_leaf as usize) <= target_leaf
        {
            if grown >= max_leaves
            {
                return Ok(false);
            }
            self.grow()?;
            // Below `max_leaves`, checked above: does not saturate.
            grown = grown.saturating_add(1);
        }
        Ok(true)
    }

    /// Return a slot to the free list and clear its contents.
    ///
    /// Silently ignores an out-of-range, unmapped, or zero index.
    ///
    /// Callers freeing an occupied slot MUST hold `DERIVATION_LOCK` around
    /// the free (in addition to this `CSpace`'s spinlock): the derivation
    /// code's occupancy gate (`resolve_slot_mut`) relies on
    /// occupied-to-free transitions being excluded while it holds that
    /// lock.
    ///
    /// Rejects a double-free of any slot (head, interior, or tail) via
    /// [`CapabilitySlot::is_on_free_list`]; see
    /// core/kernel/docs/capability-internals.md § Free Slot Tracking.
    pub fn free_slot(&mut self, index: u32)
    {
        let Some(nz_index) = NonZeroU32::new(index)
        else
        {
            return;
        };
        let old_head = self.free_head;
        let Some(slot) = self.slot_mut(index)
        else
        {
            return;
        };
        if slot.is_on_free_list()
        {
            #[cfg(not(test))]
            crate::kprintln!(
                "free_slot: double-free index={} ignored (already on free list)",
                index
            );
            return;
        }
        if slot.tag == CapTag::Memory
            && let Some(object) = slot.object
        {
            // SAFETY: an occupied slot holds a reference on its object, so the
            // Memory object it names is live, and its fill counted it.
            unsafe { MemoryObject::note_slot_released(object) };
        }
        // Bump the per-slot generation before returning the slot to the free
        // list (the legitimate-free path only — the double-free guard above
        // returns without bumping). Every outstanding handle to the prior
        // occupant now carries a stale generation and fails lookup_cap (#349).
        slot.bump_generation();
        slot.set_next_free(old_head);
        self.free_head = Some(nz_index);
        if old_head.is_none()
        {
            self.free_tail = Some(nz_index);
        }
        if let Some(old_head_idx) = old_head
            && let Some(old_head_slot) = self.slot_mut(old_head_idx.get())
        {
            old_head_slot.set_prev_free_link(Some(nz_index));
        }
        // At most the allocated slots: does not saturate.
        self.free_count = self.free_count.saturating_add(1);
    }

    /// Allocate a slot, populate it with the given capability, and return the
    /// slot index.
    ///
    /// The returned index is always non-zero (inherited from `allocate_slot`).
    pub fn insert_cap(
        &mut self,
        tag: CapTag,
        rights: Rights,
        object: NonNull<KernelObjectHeader>,
    ) -> Result<NonZeroU32, CapError>
    {
        let index = self.allocate_slot()?;
        self.fill_slot(index, tag, rights, object)?;
        Ok(index)
    }

    /// [`insert_cap`](Self::insert_cap) for an IPC capability transfer: the
    /// slot comes from [`allocate_transfer_slot`](Self::allocate_transfer_slot),
    /// so the IPC receive reserve is available to it.
    pub fn insert_cap_transfer(
        &mut self,
        tag: CapTag,
        rights: Rights,
        object: NonNull<KernelObjectHeader>,
    ) -> Result<NonZeroU32, CapError>
    {
        let index = self.allocate_transfer_slot()?;
        self.fill_slot(index, tag, rights, object)?;
        Ok(index)
    }

    /// Populate the just-allocated slot `index` with a fresh, unlinked cap,
    /// counting it on a Memory object ([`MemoryObject::slot_count`]).
    ///
    /// `object` is the live object the caller hands the slot's reference to,
    /// as for every insert.
    fn fill_slot(
        &mut self,
        index: NonZeroU32,
        tag: CapTag,
        rights: Rights,
        object: NonNull<KernelObjectHeader>,
    ) -> Result<(), CapError>
    {
        let slot = self.slot_mut(index.get()).ok_or(CapError::InvalidIndex)?;
        slot.tag = tag;
        slot.rights = rights;
        slot.badge = 0;
        slot.object = Some(object);
        slot.deriv_parent = None;
        slot.deriv_first_child = None;
        slot.deriv_next_sibling = None;
        slot.deriv_prev_sibling = None;
        if tag == CapTag::Memory
        {
            // SAFETY: the inserting caller hands this slot a reference on the
            // live object, which a Memory tag names as a MemoryObject.
            unsafe { MemoryObject::note_slot_filled(object) };
        }
        Ok(())
    }

    /// Encode the cap handle (per-slot generation + slot index) for `index`.
    ///
    /// Call right after inserting a cap at `index`, under the `CSpace` lock, to
    /// build the handle returned to userspace. Reads the slot's current
    /// generation and packs it with the index per [`syscall::cap_handle_encode`];
    /// a never-recycled slot has generation 0, so the handle equals the bare
    /// index. Returns the bare index if the slot is somehow absent.
    pub fn cap_handle(&self, index: NonZeroU32) -> u64
    {
        let generation = self
            .slot(index.get())
            .map_or(0, super::slot::CapabilitySlot::generation);
        syscall::cap_handle_encode(index.get(), generation)
    }

    /// Allocate a slot, populate it, and return the encoded cap handle.
    ///
    /// Convenience over [`insert_cap`](Self::insert_cap) +
    /// [`cap_handle`](Self::cap_handle) for the common mint path: the
    /// generation read happens under the same `&mut self` the caller already
    /// holds the `CSpace` lock for, so no separate locked read is needed.
    pub fn insert_cap_handle(
        &mut self,
        tag: CapTag,
        rights: Rights,
        object: NonNull<KernelObjectHeader>,
    ) -> Result<u64, CapError>
    {
        self.insert_cap_slot_and_handle(tag, rights, object)
            .map(|(_, handle)| handle)
    }

    /// [`insert_cap`](Self::insert_cap) returning the slot index and the
    /// handle minted under the same `&mut self`: for callers that link the
    /// new slot (they need the index) and return the handle to userspace,
    /// which must be read before the `CSpace` lock is released — a later
    /// read could carry the generation of a sibling's refill of the slot.
    pub fn insert_cap_slot_and_handle(
        &mut self,
        tag: CapTag,
        rights: Rights,
        object: NonNull<KernelObjectHeader>,
    ) -> Result<(NonZeroU32, u64), CapError>
    {
        let index = self.insert_cap(tag, rights, object)?;
        Ok((index, self.cap_handle(index)))
    }

    /// [`insert_cap`](Self::insert_cap) with the tag derived from the typed
    /// rights argument, so a mint site cannot pair a tag with another type's
    /// rights. Use for static mints; dynamic restamp paths (copy/move/derive)
    /// keep the untyped API.
    pub fn insert_cap_typed<K: super::slot::CapKind>(
        &mut self,
        rights: super::slot::TypedRights<K>,
        object: NonNull<KernelObjectHeader>,
    ) -> Result<NonZeroU32, CapError>
    {
        self.insert_cap(K::TAG, rights.erase(), object)
    }

    /// [`insert_cap_handle`](Self::insert_cap_handle) with the tag derived
    /// from the typed rights argument; see
    /// [`insert_cap_typed`](Self::insert_cap_typed).
    pub fn insert_cap_handle_typed<K: super::slot::CapKind>(
        &mut self,
        rights: super::slot::TypedRights<K>,
        object: NonNull<KernelObjectHeader>,
    ) -> Result<u64, CapError>
    {
        self.insert_cap_handle(K::TAG, rights.erase(), object)
    }

    /// Grow the `CSpace` until at least `min_free` slots are free without a
    /// further grow. The IPC paths call it before a transfer, whose inserts
    /// may take the [`IPC_RECV_RESERVE`]; the general allocation path calls
    /// it with the reserve added.
    pub fn pre_allocate(&mut self, min_free: usize) -> Result<(), CapError>
    {
        while self.free_count < min_free
        {
            self.grow()?;
        }
        Ok(())
    }

    /// Remove a specific slot index from the free list.
    ///
    /// Returns `true` if the index was found and removed, `false` if not on the list.
    ///
    /// O(1) through the predecessor link (see
    /// core/kernel/docs/capability-internals.md § Free Slot Tracking). Called by
    /// `insert_cap_at` explicit placement under the `CSpace` spinlock.
    pub fn remove_from_free_list(&mut self, target: u32) -> bool
    {
        let Some(target_nz) = NonZeroU32::new(target)
        else
        {
            return false;
        };
        let (prev, next) = match self.slot(target)
        {
            Some(slot) if slot.is_on_free_list() => (slot.prev_free(), slot.next_free()),
            _ => return false,
        };
        debug_assert_eq!(
            prev.is_none(),
            self.free_head == Some(target_nz),
            "free-list head/prev disagreement"
        );
        match prev
        {
            None => self.free_head = next,
            Some(p) =>
            {
                if let Some(prev_slot) = self.slot_mut(p.get())
                {
                    prev_slot.set_next_free_link(next);
                }
            }
        }
        if let Some(n) = next
            && let Some(next_slot) = self.slot_mut(n.get())
        {
            next_slot.set_prev_free_link(prev);
        }
        if next.is_none()
        {
            self.free_tail = prev;
        }
        // The slot was counted free: does not saturate.
        self.free_count = self.free_count.saturating_sub(1);
        // Drop the free-list marker so the unlinked slot is canonical
        // off-list (same state as an `allocate_slot` pop). Keep the
        // generation so a cap later placed here via insert_cap_at carries
        // the recycled slot's generation (#349).
        if let Some(slot) = self.slot_mut(target)
        {
            slot.clear_keep_generation();
        }
        true
    }

    /// Insert a capability at a caller-chosen slot index.
    ///
    /// Used by `SYS_CAP_COPY`'s explicit-slot path (non-zero destination slot)
    /// to place a cap at a well-known index (e.g., init populating a child's
    /// `CSpace`). The target slot must currently be Null.
    ///
    /// # Errors
    ///
    /// - [`CapError::InvalidIndex`] — index is 0, out of range, or occupied.
    /// - [`CapError::PoolExhausted`] — slot-page pool empty during grow,
    ///   including the grow that keeps [`IPC_RECV_RESERVE`] free slots
    ///   behind the placement.
    /// - [`CapError::OutOfSlots`] — the directory is structurally full with
    ///   no more than the reserve free.
    pub fn insert_cap_at(
        &mut self,
        index: u32,
        tag: CapTag,
        rights: Rights,
        object: core::ptr::NonNull<KernelObjectHeader>,
    ) -> Result<(), CapError>
    {
        if index == 0
        {
            return Err(CapError::InvalidIndex); // slot 0 is permanently null
        }

        // Reject indices beyond the directory's structural ceiling.
        //
        // Below the ceiling, the grow loop that follows allocates every
        // intermediate page up to the chosen index — bounded by the
        // destination CSpace's donated pool, which is the intended bound:
        // whoever funded that pool pays for the intervening pages.
        if index as usize >= MAX_SLOTS_STRUCTURAL
        {
            return Err(CapError::InvalidIndex);
        }

        // Ensure the leaf covering this index is allocated. Leaves are
        // contiguous behind the grow cursor, so every intermediate leaf up
        // to the target is materialised on the way. Syscall paths pre-grow
        // in bounded batches (`pre_grow_for_explicit_slot`) before taking
        // the heavyweight locks, so this loop is a zero-iteration backstop
        // for them (`sys_cap_copy` and `sys_cap_move`, the only syscall
        // callers; the host tests drive this loop directly).
        let leaf_idx = index as usize / L2_SIZE;
        while (self.next_leaf as usize) <= leaf_idx
        {
            self.grow()?;
        }

        // Verify slot is currently Null (free).
        {
            let slot = self.slot(index).ok_or(CapError::InvalidIndex)?;
            if !slot.is_null()
            {
                return Err(CapError::InvalidIndex);
            }
        }

        // An explicit placement is a general allocation: it takes a free slot
        // only while the IPC receive reserve stays free behind it.
        self.pre_allocate(IPC_RECV_RESERVE + 1)?;

        // Remove from free list (may or may not be on it if page was just grown).
        self.remove_from_free_list(index);

        let index = NonZeroU32::new(index).ok_or(CapError::InvalidIndex)?;
        self.fill_slot(index, tag, rights, object)
    }

    /// Count the number of non-null (occupied) slots.
    ///
    /// O(1): derived from `allocated_slots - free_count`.
    pub fn populated_count(&self) -> usize
    {
        // Every free slot is an allocated one.
        self.allocated_slots.saturating_sub(self.free_count)
    }

    /// Total usable slots allocated across all pages (excludes slot 0).
    ///
    /// Used by `SYS_CAP_INFO`'s `CAP_INFO_CSPACE_CAPACITY` handler, which
    /// reports the currently-backed capacity: this count plus what the
    /// remaining growth-budget pages would add.
    pub fn allocated_slots(&self) -> usize
    {
        self.allocated_slots
    }

    /// Call `f` for each non-null slot's kernel object pointer.
    ///
    /// Used by `dealloc_object(CSpaceObj)` to dec-ref all objects before
    /// the `CSpace` pages are freed. Skips slot 0 (permanently null) and
    /// unallocated pages.
    pub fn for_each_object<F>(&self, mut f: F)
    where
        F: FnMut(NonNull<KernelObjectHeader>),
    {
        for leaf_idx in 0..self.next_leaf as usize
        {
            let page = self.leaf_ptr(leaf_idx);
            if page != sentinel_leaf()
            {
                // SAFETY: page is a live leaf owned by this CSpace (not the
                // sentinel, checked above) and not aliased outside the lock.
                let page = unsafe { &*page };
                let start = usize::from(leaf_idx == 0);
                for slot in page.slots.iter().skip(start)
                {
                    if slot.tag != CapTag::Null
                        && let Some(obj) = slot.object
                    {
                        f(obj);
                    }
                }
            }
        }
    }
}

impl Drop for CSpace
{
    /// Production `CSpace` is always retype-backed: pages live inside donations
    /// tracked by [`CSpaceKernelObject`] which `dealloc_object(CSpaceObj)`
    /// reclaims wholesale via `retype_free`. Drop is a no-op so we don't
    /// double-free pool pages through the global allocator.
    ///
    /// The host-test stubs allocate `CSpace` directly without wiring a
    /// `kobj`; in that build, Drop reconstructs each leaked `Box` to return
    /// pages to the host heap so unit tests do not leak.
    fn drop(&mut self)
    {
        #[cfg(test)]
        {
            if self.kobj.load(Ordering::Acquire).is_null()
            {
                for entry in &self.direct
                {
                    let p = entry.swap(sentinel_leaf(), Ordering::AcqRel);
                    if p != sentinel_leaf()
                    {
                        // SAFETY: test stub: p came from Box::into_raw via
                        // alloc_zeroed_page's heap branch.
                        unsafe { drop(Box::from_raw(p)) };
                    }
                }
                // Every non-sentinel entry came from Box::into_raw via
                // alloc_zeroed_page's heap branch (the `free_*` contract).
                for entry in &self.indirect
                {
                    // SAFETY: see above.
                    unsafe { free_dir_leaves(entry.swap(sentinel_dir(), Ordering::AcqRel)) };
                }
                for entry in &self.double
                {
                    // SAFETY: see above.
                    unsafe { free_dir_level2(entry.swap(sentinel_dir2(), Ordering::AcqRel)) };
                }
                for entry in &self.triple
                {
                    let dir3 = entry.swap(sentinel_dir3(), Ordering::AcqRel);
                    if dir3 == sentinel_dir3()
                    {
                        continue;
                    }
                    // SAFETY: see above.
                    let entries = unsafe { &(*dir3).entries };
                    for e in entries
                    {
                        // SAFETY: see above.
                        unsafe { free_dir_level2(e.swap(sentinel_dir2(), Ordering::AcqRel)) };
                    }
                    // SAFETY: see above.
                    drop(unsafe { Box::from_raw(dir3) });
                }
            }
        }
    }
}

/// Host-test heap reclaim of a level-1 directory page and its leaves; a
/// sentinel is left alone.
///
/// # Safety
/// `dir` and every non-sentinel entry came from `Box::into_raw` and are
/// owned by the dropping `CSpace`.
#[cfg(test)]
unsafe fn free_dir_leaves(dir: *mut DirLeaves)
{
    if dir == sentinel_dir()
    {
        return;
    }
    // SAFETY: the caller's contract: `dir` came from `Box::into_raw` and is owned by the dropping
    // `CSpace`.
    let entries = unsafe { &(*dir).entries };
    for leaf in entries
    {
        let p = leaf.swap(sentinel_leaf(), Ordering::AcqRel);
        if p != sentinel_leaf()
        {
            // SAFETY: the caller's contract: every non-sentinel entry came from `Box::into_raw`
            // and is owned by the dropping `CSpace`.
            drop(unsafe { Box::from_raw(p) });
        }
    }
    // SAFETY: the caller's contract: `dir` came from `Box::into_raw` and is owned by the dropping
    // `CSpace`; its entries are freed above.
    drop(unsafe { Box::from_raw(dir) });
}

/// Host-test heap reclaim of a level-2 directory page and everything under
/// it; a sentinel is left alone.
///
/// # Safety
/// As [`free_dir_leaves`].
#[cfg(test)]
unsafe fn free_dir_level2(dir: *mut DirLevel2)
{
    if dir == sentinel_dir2()
    {
        return;
    }
    // SAFETY: the caller's contract: `dir` came from `Box::into_raw` and is owned by the dropping
    // `CSpace`.
    let entries = unsafe { &(*dir).entries };
    for e in entries
    {
        // SAFETY: the caller's contract: every non-sentinel entry came from `Box::into_raw` and is
        // owned by the dropping `CSpace`.
        unsafe { free_dir_leaves(e.swap(sentinel_dir(), Ordering::AcqRel)) };
    }
    // SAFETY: the caller's contract: `dir` came from `Box::into_raw` and is owned by the dropping
    // `CSpace`; its entries are freed above.
    drop(unsafe { Box::from_raw(dir) });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::cap::object::{KernelObjectHeader, ObjectType};
    use crate::cap::slot::MemRights;
    use core::ptr::NonNull;

    /// Construct a dummy `NonNull`<KernelObjectHeader> backed by a leaked Box
    /// so tests don't need unsafe pointer arithmetic.
    fn dummy_object() -> NonNull<KernelObjectHeader>
    {
        let obj = Box::new(MemoryObject {
            header: KernelObjectHeader::new(ObjectType::Memory),
            base: 0,
            size: 0x1000,
            available_bytes: core::sync::atomic::AtomicU64::new(0),
            owns_memory: core::sync::atomic::AtomicBool::new(false),
            allocator: crate::cap::retype::RetypeAllocator::new_inline(),
            lock: core::sync::atomic::AtomicU32::new(0),
            slot_count: core::sync::atomic::AtomicU32::new(0),
        });
        let raw = Box::into_raw(obj).cast::<KernelObjectHeader>();
        // SAFETY: Box::into_raw never returns null.
        unsafe { NonNull::new_unchecked(raw) }
    }

    #[test]
    fn new_cspace_is_empty()
    {
        let cs = CSpace::new(0);
        assert_eq!(cs.populated_count(), 0);
        assert_eq!(cs.allocated_slots, 0);
    }

    #[test]
    fn slot_zero_is_null()
    {
        let mut cs = CSpace::new(0);
        // Force page 0 to be allocated by requesting slot 1.
        let _idx = cs.allocate_slot().unwrap();
        // Slot 0 must exist and be null.
        let s = cs.slot(0).expect("slot 0 should exist after grow");
        assert!(s.is_null());
    }

    #[test]
    fn allocate_and_lookup_round_trip()
    {
        let mut cs = CSpace::new(0);
        let obj = dummy_object();
        let idx = cs
            .insert_cap_typed(MemRights::MAP | MemRights::WRITE, obj)
            .unwrap();
        let slot = cs.slot(idx.get()).unwrap();
        assert_eq!(slot.tag, CapTag::Memory);
        assert!(slot.rights.contains(MemRights::MAP.erase()));
        assert!(slot.rights.contains(MemRights::WRITE.erase()));
        assert_eq!(slot.object, Some(obj));
    }

    #[test]
    fn growth_across_l2_boundary()
    {
        // Allocate L2_SIZE - 1 slots (page 0 has 55 usable slots after skipping 0).
        let mut cs = CSpace::new(0);
        let mut indices = Vec::new();
        for _ in 0..(L2_SIZE - 1)
        {
            indices.push(cs.allocate_slot().unwrap());
        }
        // Next allocation must cross into page 1.
        let idx = cs.allocate_slot().unwrap();
        assert!(
            idx.get() as usize >= L2_SIZE,
            "expected index in page 1 or beyond"
        );
        assert!(!indices.contains(&idx));
    }

    #[test]
    fn free_and_reallocate()
    {
        let mut cs = CSpace::new(0);
        let idx1 = cs.allocate_slot().unwrap();
        cs.free_slot(idx1.get());
        // After freeing, the next allocate should return the same index.
        let idx2 = cs.allocate_slot().unwrap();
        assert_eq!(idx1, idx2, "freed slot should be reused");
    }

    #[test]
    fn pool_exhaustion_is_distinct()
    {
        // A retype-backed CSpace (non-null kobj) with no pool page left
        // fails grow with PoolExhausted, not the structural OutOfSlots.
        // The test-mode grow path returns before dereferencing the kobj
        // pointer, so a dangling marker stands in for a real wrapper.
        let mut cs = CSpace::new(0);
        cs.set_kobj(NonNull::dangling().as_ptr());
        let err = cs.allocate_slot().unwrap_err();
        assert_eq!(err, CapError::PoolExhausted);
    }

    #[test]
    fn write_execute_cap_allowed()
    {
        let mut cs = CSpace::new(0);
        let obj = dummy_object();
        let slot = cs
            .insert_cap_typed(MemRights::WRITE | MemRights::EXECUTE, obj)
            .expect("WRITE|EXECUTE cap should be allowed at cap level");
        let s = cs.slot(slot.get()).unwrap();
        assert!(
            s.rights
                .contains((MemRights::WRITE | MemRights::EXECUTE).erase())
        );
    }

    #[test]
    fn pre_allocate_succeeds()
    {
        let mut cs = CSpace::new(0);
        cs.pre_allocate(10).unwrap();
        assert!(cs.free_count >= 10);
    }

    #[test]
    fn populated_count_tracks_inserts()
    {
        let mut cs = CSpace::new(0);
        assert_eq!(cs.populated_count(), 0);
        let obj = dummy_object();
        cs.insert_cap_typed(MemRights::MAP, obj).unwrap();
        assert_eq!(cs.populated_count(), 1);
    }

    #[test]
    fn free_list_prioritized_over_new_slots()
    {
        // Allocate 3 slots; free the first; verify next alloc reuses it rather
        // than consuming a brand-new slot beyond the current high-water mark.
        let mut cs = CSpace::new(0);
        let s1 = cs.allocate_slot().unwrap();
        let s2 = cs.allocate_slot().unwrap();
        let s3 = cs.allocate_slot().unwrap();

        cs.free_slot(s1.get());

        // Must return s1 (from free list), not a fresh slot past s3.
        let s4 = cs.allocate_slot().unwrap();
        assert_eq!(
            s4, s1,
            "free list entry must be reused before consuming new slot space"
        );
        assert_ne!(
            s4.get(),
            s3.get() + 1,
            "should not allocate a brand-new slot when free list is non-empty"
        );
        let _ = (s2, s3);
    }

    #[test]
    fn populated_count_accurate_after_repeated_inserts()
    {
        // populated_count must increment by exactly 1 for each successful insert.
        let mut cs = CSpace::new(0);
        let obj = dummy_object();

        for expected in 1..=5usize
        {
            cs.insert_cap_typed(MemRights::MAP, obj).unwrap();
            assert_eq!(
                cs.populated_count(),
                expected,
                "populated_count should be {expected} after {expected} inserts"
            );
        }
    }

    #[test]
    fn insert_cap_at_grows_to_high_index()
    {
        // Placing a cap at index 200 (page 3) on a fresh CSpace must grow
        // every intermediate page and land the cap at exactly that slot.
        let mut cs = CSpace::new(0);
        let obj = dummy_object();
        cs.insert_cap_at(200, CapTag::Memory, MemRights::MAP.erase(), obj)
            .expect("insert_cap_at(200) on a fresh CSpace failed");
        let slot = cs.slot(200).expect("slot 200 unmapped after insert");
        assert_eq!(slot.tag, CapTag::Memory);
        assert_eq!(slot.object, Some(obj));
        // Pages 0..=3 allocated: 55 + 3 * 56 usable slots.
        assert_eq!(cs.allocated_slots, (L2_SIZE - 1) + 3 * L2_SIZE);
        assert_eq!(cs.populated_count(), 1);
    }

    #[test]
    fn memory_slot_count_follows_every_fill_and_free()
    {
        // Every insert path fills through one helper that counts the slots
        // naming a Memory object, and a free uncounts it, so a split can tell
        // whether another slot shares the object; a refused insert counts
        // nothing.
        let count = |obj: NonNull<KernelObjectHeader>| {
            // SAFETY: dummy_object leaks a live MemoryObject with the header
            // at offset 0.
            unsafe {
                (*obj.as_ptr().cast::<MemoryObject>())
                    .slot_count
                    .load(Ordering::Relaxed)
            }
        };
        let mut cs = CSpace::new(0);
        let obj = dummy_object();
        let a = cs
            .insert_cap(CapTag::Memory, MemRights::MAP.erase(), obj)
            .unwrap();
        cs.insert_cap_at(9, CapTag::Memory, MemRights::MAP.erase(), obj)
            .unwrap();
        let c = cs
            .insert_cap_transfer(CapTag::Memory, MemRights::MAP.erase(), obj)
            .unwrap();
        assert!(
            cs.insert_cap_at(9, CapTag::Memory, MemRights::MAP.erase(), obj)
                .is_err()
        );
        assert_eq!(count(obj), 3);
        cs.free_slot(a.get());
        cs.free_slot(9);
        assert_eq!(count(obj), 1);
        cs.free_slot(9);
        assert_eq!(count(obj), 1, "a double free must not uncount");
        cs.free_slot(c.get());
        assert_eq!(count(obj), 0);
    }

    #[test]
    fn insert_cap_at_rejects_out_of_range_indices()
    {
        let mut cs = CSpace::new(0);
        let obj = dummy_object();
        let err = cs
            .insert_cap_at(
                MAX_SLOTS_STRUCTURAL as u32,
                CapTag::Memory,
                MemRights::MAP.erase(),
                obj,
            )
            .unwrap_err();
        assert_eq!(err, CapError::InvalidIndex);
        let err = cs
            .insert_cap_at(0, CapTag::Memory, MemRights::MAP.erase(), obj)
            .unwrap_err();
        assert_eq!(err, CapError::InvalidIndex);
        assert_eq!(cs.allocated_slots, 0, "rejected inserts must not grow");
    }

    #[test]
    fn insert_cap_at_rejects_occupied_slot()
    {
        let mut cs = CSpace::new(0);
        let obj = dummy_object();
        cs.insert_cap_at(5, CapTag::Memory, MemRights::MAP.erase(), obj)
            .expect("first insert at slot 5 failed");
        let err = cs
            .insert_cap_at(5, CapTag::Memory, MemRights::MAP.erase(), obj)
            .unwrap_err();
        assert_eq!(err, CapError::InvalidIndex, "occupied slot must reject");
        assert_eq!(cs.populated_count(), 1, "the live cap must be untouched");
    }

    #[test]
    fn structural_ceiling_returns_out_of_slots()
    {
        // Filling all 4.29G slots is not host-viable (~290 GiB of pages);
        // force the grow cursor to the ceiling instead — with an empty free
        // list, the next allocation's grow must fail with the structural
        // OutOfSlots, not PoolExhausted.
        let mut cs = CSpace::new(0);
        cs.next_leaf = MAX_LEAVES as u32;
        let err = cs.allocate_slot().unwrap_err();
        assert_eq!(err, CapError::OutOfSlots);
    }

    #[test]
    fn growth_crosses_direct_indirect_boundary()
    {
        // Exhaust the direct region (128 leaves x 56 slots, minus reserved
        // slot 0), then verify the next allocation materialises the first
        // indirect leaf — directory page included — and that slots on both
        // sides of the boundary round-trip.
        let mut cs = CSpace::new(0);
        let direct_slots = L1_DIRECT * L2_SIZE - 1;
        let mut last_direct = 0u32;
        for i in 0..direct_slots
        {
            // Transfer allocations take every free slot, the reserve
            // included, so the direct region fills exactly.
            let idx = cs
                .allocate_transfer_slot()
                .unwrap_or_else(|e| panic!("direct-region allocation {i} failed: {e:?}"));
            last_direct = idx.get();
        }
        assert!(
            (last_direct as usize) < L1_DIRECT * L2_SIZE,
            "direct region overflowed early"
        );
        assert_eq!(cs.next_leaf as usize, L1_DIRECT);

        // Crossing allocation: leaf 128, the first indirect leaf.
        let obj = dummy_object();
        let idx = cs
            .insert_cap_typed(MemRights::MAP, obj)
            .expect("first indirect-region insert failed");
        assert!(
            idx.get() as usize >= L1_DIRECT * L2_SIZE,
            "expected an index in the indirect region"
        );
        let slot = cs.slot(idx.get()).expect("indirect slot unmapped");
        assert_eq!(slot.tag, CapTag::Memory);
        assert_eq!(slot.object, Some(obj));

        // A direct-region slot still resolves after the boundary crossing.
        assert!(cs.slot(1).is_some(), "direct-region slot lost");

        // Deep explicit placement drives the cursor further into the
        // indirect region through the same contiguous-grow path.
        cs.insert_cap_at(8000, CapTag::Memory, MemRights::MAP.erase(), obj)
            .expect("insert_cap_at(8000) failed");
        let deep = cs.slot(8000).expect("slot 8000 unmapped");
        assert_eq!(deep.object, Some(obj));
        assert_eq!(cs.next_leaf as usize, 8000 / L2_SIZE + 1);
        assert_eq!(cs.populated_count(), direct_slots + 2);
    }

    #[test]
    fn pages_to_cover_counts_leaves_and_dir_pages()
    {
        let mut cs = CSpace::new(0);
        // Fresh CSpace, direct-region target: leaves only.
        assert_eq!(cs.pages_to_cover(0), 1, "slot 0 needs leaf 0");
        assert_eq!(cs.pages_to_cover((L2_SIZE - 1) as u32), 1);
        assert_eq!(cs.pages_to_cover((3 * L2_SIZE) as u32), 4, "leaves 0..=3");
        // First indirect target: all 129 leaves plus one directory page.
        assert_eq!(
            cs.pages_to_cover((L1_DIRECT * L2_SIZE) as u32),
            (L1_DIRECT + 1) as u64 + 1
        );
        // Out of range: zero (the placement path rejects instead).
        assert_eq!(cs.pages_to_cover(MAX_SLOTS_STRUCTURAL as u32), 0);
        // Already covered after an allocation.
        cs.allocate_slot().unwrap();
        assert_eq!(cs.pages_to_cover(1), 0);
        // Second target under an already-materialised directory page costs
        // only the missing leaves.
        cs.insert_cap_at(
            (L1_DIRECT * L2_SIZE) as u32,
            CapTag::Memory,
            MemRights::MAP.erase(),
            dummy_object(),
        )
        .expect("indirect placement failed");
        assert_eq!(
            cs.pages_to_cover(((L1_DIRECT + 2) * L2_SIZE) as u32),
            2,
            "existing dir page must not be re-counted"
        );
    }

    #[test]
    fn grow_toward_batches_and_completes()
    {
        let mut cs = CSpace::new(0);
        // Target leaf 9 with a 4-leaf batch: two partial calls, then done.
        let target = (9 * L2_SIZE) as u32;
        assert!(!cs.grow_toward(target, 4).unwrap());
        assert_eq!(cs.leaf_count(), 4);
        assert!(!cs.grow_toward(target, 4).unwrap());
        assert_eq!(cs.leaf_count(), 8);
        assert!(cs.grow_toward(target, 4).unwrap());
        assert_eq!(cs.leaf_count(), 10);
        // Covered target: immediate true, no growth.
        assert!(cs.grow_toward(target, 0).unwrap());
        assert_eq!(cs.leaf_count(), 10);
    }

    #[test]
    fn remove_from_free_list_all_positions()
    {
        let mut cs = CSpace::new(0);
        // Materialise the first page; free list = slots 1..=55 in order.
        cs.allocate_slot().unwrap();
        cs.free_slot(1);
        let initial_free = cs.free_count;

        // Not on the list: slot 0 (permanently null, never linked) and an
        // out-of-range index.
        assert!(!cs.remove_from_free_list(0));
        assert!(!cs.remove_from_free_list(999_999));

        // Head removal (slot 1 was pushed last, so it is the head).
        assert!(cs.remove_from_free_list(1));
        assert_ne!(cs.free_head, NonZeroU32::new(1));

        // Interior removal.
        assert!(cs.remove_from_free_list(30));
        // Tail removal (slot 55 is the deepest of the original threading).
        assert!(cs.remove_from_free_list(55));
        // Double removal: no longer on the list.
        assert!(!cs.remove_from_free_list(30));
        assert_eq!(cs.free_count, initial_free - 3);

        // Drain exactly the remaining free entries; every pop must be
        // unique and none may be a removed index — proving the doubly-
        // linked splices left a consistent list.
        let mut seen = Vec::new();
        for _ in 0..cs.free_count
        {
            let idx = cs
                .allocate_transfer_slot()
                .expect("free list drained early");
            assert!(!seen.contains(&idx), "duplicate index from free list");
            assert!(
                ![1u32, 30, 55].contains(&idx.get()),
                "removed index resurfaced on the free list"
            );
            seen.push(idx);
        }
        assert!(cs.free_head.is_none());
    }

    #[test]
    fn double_free_non_head_does_not_corrupt_freelist()
    {
        let mut cs = CSpace::new(0);
        let a = cs.allocate_slot().unwrap();
        let b = cs.allocate_slot().unwrap();
        let c = cs.allocate_slot().unwrap();

        // Build a multi-entry free list: head = a -> b -> c -> (rest).
        cs.free_slot(c.get());
        cs.free_slot(b.get());
        cs.free_slot(a.get());
        assert_eq!(cs.free_head, Some(a), "a should be the free-list head");

        let free_before = cs.free_count;
        // Double-free a NON-head slot (b; the head is a). The old head-only
        // guard missed this and spliced b in a second time, cycling the list.
        cs.free_slot(b.get());
        assert_eq!(
            cs.free_count, free_before,
            "non-head double-free must be rejected, not re-pushed"
        );

        // Drain exactly the free list (stopping before allocate_slot would
        // grow a fresh page). A cycle would hand out a duplicate index
        // within these pops; every popped index must be unique.
        let mut seen = Vec::new();
        for _ in 0..free_before
        {
            let idx = cs
                .allocate_transfer_slot()
                .expect("free list drained early");
            assert!(
                !seen.contains(&idx),
                "allocate_slot returned duplicate index {} — free list corrupted",
                idx.get()
            );
            seen.push(idx);
        }
        assert!(
            cs.free_head.is_none(),
            "free list must be empty after draining free_count entries"
        );
    }

    /// A one-leaf `CSpace` whose pool is spent: `L2_SIZE - 1` usable slots.
    fn one_leaf_cspace() -> CSpace
    {
        let mut cs = CSpace::new(0);
        cs.test_page_budget = Some(1);
        cs
    }

    #[test]
    fn general_allocations_stop_at_the_ipc_reserve()
    {
        let mut cs = one_leaf_cspace();
        let general = L2_SIZE - 1 - IPC_RECV_RESERVE;
        for i in 0..general
        {
            cs.allocate_slot()
                .unwrap_or_else(|e| panic!("general allocation {i} failed: {e:?}"));
        }
        assert_eq!(cs.allocate_slot(), Err(CapError::PoolExhausted));
        assert_eq!(cs.free_count, IPC_RECV_RESERVE);
    }

    #[test]
    fn transfer_allocations_take_the_reserve_then_fail()
    {
        let mut cs = one_leaf_cspace();
        while cs.allocate_slot().is_ok()
        {}
        // A receive's pre-allocation is met without growth.
        assert_eq!(cs.pre_allocate(IPC_RECV_RESERVE), Ok(()));
        for i in 0..IPC_RECV_RESERVE
        {
            cs.allocate_transfer_slot()
                .unwrap_or_else(|e| panic!("reserved allocation {i} failed: {e:?}"));
        }
        assert_eq!(cs.allocate_transfer_slot(), Err(CapError::PoolExhausted));
        assert_eq!(cs.pre_allocate(1), Err(CapError::PoolExhausted));
    }

    #[test]
    fn freeing_a_slot_reopens_general_allocation()
    {
        let mut cs = one_leaf_cspace();
        let mut last = None;
        while let Ok(idx) = cs.allocate_slot()
        {
            last = Some(idx);
        }
        let freed = last.expect("at least one general allocation");
        cs.free_slot(freed.get());
        assert_eq!(cs.allocate_slot(), Ok(freed));
    }

    #[test]
    fn explicit_placement_respects_the_ipc_reserve()
    {
        let mut cs = one_leaf_cspace();
        let obj = dummy_object();
        while cs.allocate_slot().is_ok()
        {}
        // Some slot of leaf 0 is still free (a reserved one); placing a cap
        // there is a general allocation and is refused.
        let target = (1..L2_SIZE as u32)
            .find(|&i| cs.slot(i).is_some_and(CapabilitySlot::is_on_free_list))
            .expect("a reserved slot is free");
        assert_eq!(
            cs.insert_cap_at(target, CapTag::Memory, MemRights::MAP.erase(), obj),
            Err(CapError::PoolExhausted)
        );
        assert_eq!(cs.free_count, IPC_RECV_RESERVE);
    }

    #[test]
    fn transfer_insert_fills_a_reserved_slot()
    {
        let mut cs = one_leaf_cspace();
        let obj = dummy_object();
        while cs.allocate_slot().is_ok()
        {}
        let idx = cs
            .insert_cap_transfer(CapTag::Memory, MemRights::MAP.erase(), obj)
            .expect("transfer insert into the reserve");
        let slot = cs.slot(idx.get()).unwrap();
        assert_eq!(slot.tag, CapTag::Memory);
        assert_eq!(slot.object, Some(obj));
        assert_eq!(cs.free_count, IPC_RECV_RESERVE - 1);
    }

    #[test]
    fn general_allocations_stay_ascending_across_a_grow()
    {
        // The reserve makes `allocate_slot` grow while slots are still free;
        // those slots must still be handed out before the new leaf's, so a
        // run of inserts gets consecutive indices across the leaf boundary.
        let mut cs = CSpace::new(0);
        let mut last = cs.allocate_slot().unwrap().get();
        for _ in 0..3 * L2_SIZE
        {
            let idx = cs.allocate_slot().unwrap().get();
            assert_eq!(idx, last + 1, "allocation skipped or reordered an index");
            last = idx;
        }
    }

    #[test]
    fn removing_the_tail_keeps_appends_linked()
    {
        // After the free list's tail is unlinked by an explicit placement, the
        // next grow must append behind the new tail, or the leaf's slots are
        // lost to the list.
        let mut cs = CSpace::new(0);
        cs.allocate_slot().unwrap();
        let tail = cs.free_tail.expect("a non-empty list has a tail");
        assert!(cs.remove_from_free_list(tail.get()));
        let free_before = cs.free_count;
        cs.grow().unwrap();
        assert_eq!(cs.free_count, free_before + L2_SIZE);
        let mut drained = 0;
        while cs.free_count > 0
        {
            cs.allocate_transfer_slot().unwrap();
            drained += 1;
        }
        assert_eq!(drained, free_before + L2_SIZE);
        assert!(cs.free_head.is_none() && cs.free_tail.is_none());
    }

    /// Every byte of the sentinel leaf is zero (every slot `Null`) and every
    /// sentinel-directory entry names the sentinel leaf.
    fn assert_sentinels_pristine()
    {
        // SAFETY: SENTINEL_LEAF is a live static of `size_of::<CSpacePage>()`
        // bytes, read as bytes only.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                (&raw const SENTINEL_LEAF).cast::<u8>(),
                core::mem::size_of::<CSpacePage>(),
            )
        };
        assert!(bytes.iter().all(|&b| b == 0), "sentinel leaf written");
        assert!(
            SENTINEL_DIR
                .entries
                .iter()
                .all(|e| e.load(Ordering::Relaxed) == sentinel_leaf()),
            "sentinel directory written"
        );
        assert!(
            SENTINEL_DIR2
                .entries
                .iter()
                .all(|e| e.load(Ordering::Relaxed) == sentinel_dir()),
            "level-2 sentinel directory written"
        );
        assert!(
            SENTINEL_DIR3
                .entries
                .iter()
                .all(|e| e.load(Ordering::Relaxed) == sentinel_dir2()),
            "level-3 sentinel directory written"
        );
    }

    #[test]
    fn unallocated_and_out_of_range_indices_resolve_nothing()
    {
        let mut cs = CSpace::new(0);
        let probes = [
            0u32,
            1,
            (L1_DIRECT * L2_SIZE - 1) as u32,
            (L1_DIRECT * L2_SIZE) as u32,
            (MAX_SLOTS_STRUCTURAL - 1) as u32,
            MAX_SLOTS_STRUCTURAL as u32,
            u32::MAX,
        ];
        for &i in &probes
        {
            assert!(cs.slot(i).is_none(), "fresh CSpace resolved index {i}");
            assert!(
                cs.slot_mut(i).is_none(),
                "fresh CSpace resolved index {i} mutably"
            );
        }
        cs.allocate_slot().unwrap();
        assert!(cs.slot(0).is_some_and(CapabilitySlot::is_null));
        for &i in &probes[2..]
        {
            assert!(cs.slot(i).is_none(), "one-leaf CSpace resolved index {i}");
            assert!(
                cs.slot_mut(i).is_none(),
                "one-leaf CSpace resolved index {i} mutably"
            );
        }
        assert_sentinels_pristine();
    }

    #[test]
    fn unallocated_leaf_under_a_live_directory_resolves_nothing()
    {
        // Grow one leaf into the indirect region: its directory page is live,
        // and every other entry of that directory names the sentinel leaf.
        let mut cs = CSpace::new(0);
        assert_eq!(
            cs.grow_toward((L1_DIRECT * L2_SIZE) as u32, MAX_LEAVES),
            Ok(true)
        );
        assert_eq!(cs.next_leaf as usize, L1_DIRECT + 1);
        let first_indirect = (L1_DIRECT * L2_SIZE) as u32;
        assert!(cs.slot(first_indirect).is_some());
        let next_leaf = ((L1_DIRECT + 1) * L2_SIZE) as u32;
        let last_in_dir = ((L1_DIRECT + DIR_FANOUT) * L2_SIZE - 1) as u32;
        let next_dir = ((L1_DIRECT + DIR_FANOUT) * L2_SIZE) as u32;
        for i in [next_leaf, last_in_dir, next_dir]
        {
            assert!(cs.slot(i).is_none(), "unallocated index {i} resolved");
            assert!(
                cs.slot_mut(i).is_none(),
                "unallocated index {i} resolved mutably"
            );
        }
        assert_sentinels_pristine();
        drop(cs);
        assert_sentinels_pristine();
    }

    #[test]
    fn leaf_ptr_falls_back_to_the_sentinel()
    {
        let mut cs = CSpace::new(0);
        cs.allocate_slot().unwrap();
        assert_ne!(cs.leaf_ptr(0), sentinel_leaf());
        for leaf in [
            1,
            L1_DIRECT,
            DOUBLE_BASE - 1,
            DOUBLE_BASE,
            TRIPLE_BASE - 1,
            TRIPLE_BASE,
            MAX_LEAVES - 1,
            MAX_LEAVES,
            MAX_LEAVES + 1,
            GEOMETRY_LEAVES,
            usize::MAX,
        ]
        {
            assert_eq!(cs.leaf_ptr(leaf), sentinel_leaf(), "leaf {leaf}");
        }
    }

    /// Pool pages a grow from leaf `from` (the cursor forced there, as if
    /// every leaf below it existed) to cover `index` consumes, read from the
    /// host stub's page budget, and the `pages_to_cover` taken before it.
    fn measured_cover(from: usize, index: u32) -> (u64, u64)
    {
        let mut cs = CSpace::new(0);
        cs.next_leaf = from as u32;
        let budget = 1 << 20;
        cs.set_test_page_budget(budget);
        let predicted = cs.pages_to_cover(index);
        assert_eq!(cs.grow_toward(index, usize::MAX), Ok(true));
        let left = cs.test_page_budget.unwrap();
        (predicted, (budget - left) as u64)
    }

    #[test]
    fn pages_to_cover_matches_the_pages_every_region_crossing_spends()
    {
        let slot = |leaf: usize| (leaf * L2_SIZE) as u32;
        let cases = [
            // Within the indirect region, across a level-1 page boundary.
            (
                INDIRECT_BASE + DIR_FANOUT - 2,
                slot(INDIRECT_BASE + DIR_FANOUT + 1),
            ),
            // Into the double region: its level-2 and level-1 pages.
            (DOUBLE_BASE - 2, slot(DOUBLE_BASE + 1)),
            // Within the double region, across a level-1 page boundary.
            (DOUBLE_BASE + DIR_FANOUT - 1, slot(DOUBLE_BASE + DIR_FANOUT)),
            // Across a level-2 page boundary of the double region.
            (
                DOUBLE_BASE + DIR_FANOUT * DIR_FANOUT - 1,
                slot(DOUBLE_BASE + DIR_FANOUT * DIR_FANOUT),
            ),
            // Into the triple region: all three of its levels.
            (TRIPLE_BASE - 2, slot(TRIPLE_BASE + DIR_FANOUT + 2)),
            // The last leaf under the ceiling.
            (MAX_LEAVES - 3, (MAX_SLOTS_STRUCTURAL - 1) as u32),
        ];
        for (from, index) in cases
        {
            let (predicted, spent) = measured_cover(from, index);
            assert_eq!(predicted, spent, "grow from leaf {from} to index {index}");
        }
    }

    #[test]
    fn deep_region_slots_round_trip_and_lookups_stay_in_their_leaf()
    {
        let obj = dummy_object();
        for base in [DOUBLE_BASE, TRIPLE_BASE, MAX_LEAVES - 1]
        {
            let mut cs = CSpace::new(0);
            cs.next_leaf = base as u32;
            let index = (base * L2_SIZE + 5) as u32;
            cs.insert_cap_at(index, CapTag::Memory, MemRights::MAP.erase(), obj)
                .unwrap_or_else(|e| panic!("placement at leaf {base} failed: {e:?}"));
            assert_eq!(cs.slot(index).and_then(|s| s.object), Some(obj));
            assert!(
                cs.slot(index - 6).is_none(),
                "the leaf below {base} resolved"
            );
            assert!(
                cs.slot(((base + 1) * L2_SIZE) as u32).is_none(),
                "the leaf above {base} resolved"
            );
            assert_eq!(cs.populated_count(), 1);
        }
        assert_sentinels_pristine();
    }

    #[test]
    fn the_ceiling_is_the_last_whole_leaf_of_the_index_field()
    {
        let obj = dummy_object();
        let mut cs = CSpace::new(0);
        cs.next_leaf = (MAX_LEAVES - 1) as u32;
        let last = (MAX_SLOTS_STRUCTURAL - 1) as u32;
        assert_eq!(
            cs.insert_cap_at(last, CapTag::Memory, MemRights::MAP.erase(), obj),
            Ok(())
        );
        for past in [MAX_SLOTS_STRUCTURAL as u32, u32::MAX]
        {
            assert_eq!(
                cs.insert_cap_at(past, CapTag::Memory, MemRights::MAP.erase(), obj),
                Err(CapError::InvalidIndex)
            );
            assert!(
                cs.slot(past).is_none(),
                "index {past} past the ceiling resolved"
            );
        }
        // The last leaf's other slots are free; past them the directory is
        // structurally full.
        while cs.allocate_transfer_slot().is_ok()
        {}
        assert_eq!(cs.allocate_transfer_slot(), Err(CapError::OutOfSlots));
    }

    #[test]
    fn pages_to_cover_counts_published_double_region_directories_once()
    {
        // A grow at the double region's first leaf that runs out after the
        // level-2 page leaves it published: the next cover counts only the
        // level-1 page and the leaf.
        let mut cs = CSpace::new(0);
        cs.next_leaf = DOUBLE_BASE as u32;
        let index = (DOUBLE_BASE * L2_SIZE) as u32;
        assert_eq!(cs.pages_to_cover(index), 3);
        cs.set_test_page_budget(1);
        assert_eq!(cs.grow_toward(index, 1), Err(CapError::PoolExhausted));
        assert_eq!(cs.pages_to_cover(index), 2);
        cs.set_test_page_budget(2);
        assert_eq!(cs.grow_toward(index, 1), Ok(true));
        // From under live level-1 and level-2 pages, a span into the next
        // level-1 page counts its leaves and that one page, as the grow spends.
        let far = ((DOUBLE_BASE + DIR_FANOUT + 1) * L2_SIZE) as u32;
        let predicted = cs.pages_to_cover(far);
        assert_eq!(predicted, (DIR_FANOUT + 2) as u64);
        let budget = 1 << 20;
        cs.set_test_page_budget(budget);
        assert_eq!(cs.grow_toward(far, usize::MAX), Ok(true));
        assert_eq!(predicted, (budget - cs.test_page_budget.unwrap()) as u64);
    }

    #[test]
    fn deep_directory_pages_survive_a_failed_leaf_and_are_not_recharged()
    {
        // At the first triple-region leaf a grow buys three directory pages
        // and the leaf. With only the three, the leaf fails; the pages stay
        // published, so one more page completes the grow.
        let mut cs = CSpace::new(0);
        cs.next_leaf = TRIPLE_BASE as u32;
        let index = (TRIPLE_BASE * L2_SIZE) as u32;
        assert_eq!(cs.pages_to_cover(index), 4);
        cs.set_test_page_budget(3);
        assert_eq!(cs.grow_toward(index, 1), Err(CapError::PoolExhausted));
        assert_eq!(
            cs.pages_to_cover(index),
            1,
            "a published directory page was re-counted"
        );
        assert!(cs.slot(index).is_none());
        cs.set_test_page_budget(1);
        assert_eq!(cs.grow_toward(index, 1), Ok(true));
        assert!(cs.slot(index).is_some());
    }
}
