// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/cap/object.rs

//! Kernel object types backing capability objects.
//!
//! Each struct has a [`KernelObjectHeader`] as its first field at offset 0
//! (`#[repr(C)]`), so a `*mut ConcreteObject` can safely be cast to
//! `*mut KernelObjectHeader` and back.
//!
//! ## Allocation pattern
//!
//! Most kernel objects are *retyped* from a Frame capability with the
//! `Retype` right: the kernel allocates a sub-region inside the Frame's
//! backing memory via [`crate::cap::retype::retype_allocate`], constructs
//! the object in place at the returned offset, and stores the source
//! `FrameObject`'s header pointer in `header.ancestor` so dealloc can
//! reclaim the bytes back to the source cap. Init's bootstrap state
//! (root `CSpace`, init's own `AddressSpace`/`Thread`/`CSpace`) and the
//! Phase-7 boot-time identity wrappers remain heap-allocated for now;
//! they have `header.ancestor == null` and dealloc through the legacy
//! `Box::from_raw` path.
//!
//! Deallocation: read `header.obj_type` from the raw pointer; if
//! `header.ancestor` is null, drop the originating `Box<ConcreteObject>`;
//! otherwise drop the object in place and call `retype_free` against
//! the ancestor `FrameObject`.
//!
//! ## Sizes (verified by tests below)
//!
//! | Type                | Size  |
//! |---------------------|-------|
//! | KernelObjectHeader  | 16 B  |
//! | FrameObject         | 64 B  |
//! | MmioRegionObject    | 40 B  |
//! | InterruptObject     | 24 B  |
//! | IoPortRangeObject   | 24 B  |
//! | SchedControlObject  | 16 B  |
//! | SbiControlObject    | 16 B  |
//! | ThreadObject        | 24 B  |
//! | AddressSpaceObject  | 432 B |
//! | CSpaceKernelObject  | 432 B |
//! | EndpointObject      | 24 B  |
//! | SignalObject        | 24 B  |
//! | EventQueueObject    | 24 B  |
//! | WaitSetObject       | 24 B  |

use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};

// ── ObjectType ────────────────────────────────────────────────────────────────

/// Discriminant for the concrete type behind a `*mut KernelObjectHeader`.
///
/// Used during deallocation to reconstruct the original `Box<ConcreteObject>`.
/// Values must not be renumbered after assignment.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectType
{
    Frame = 0,
    MmioRegion = 1,
    Interrupt = 2,
    IoPortRange = 3,
    SchedControl = 4,
    Thread = 5,
    AddressSpace = 6,
    CSpaceObj = 7,
    Endpoint = 8,
    Signal = 9,
    EventQueue = 10,
    WaitSet = 11,
    SbiControl = 12,
}

// ── KernelObjectHeader ────────────────────────────────────────────────────────

/// Common header at offset 0 of every kernel object.
///
/// The `ref_count` tracks how many capability slots reference this object.
/// When `dec_ref` returns 0, the object has no remaining references and can
/// be freed (future phases will handle deallocation via `obj_type`).
///
/// `ancestor` is a direct pointer to the `FrameObject`'s header from which
/// this object was retyped, or null if heap-allocated (legacy path).
/// Auto-reclaim consults this on `dec_ref → 0` to credit bytes back to the
/// source `FrameObject` and return the chunk to the per-Frame-cap allocator.
///
/// A direct pointer (rather than a `SlotId`) is necessary because the source
/// Frame cap's *slot* may be deleted before all retyped descendants are freed
/// — the `FrameObject` itself stays alive via the refcount bump that retype
/// performs, but the slot index becomes `Null` as soon as `cap_delete` runs
/// on the source. Reclaim must reach the live object regardless of slot
/// state. `SYS_CAP_INFO` exposes ancestor lineage if introspection needs it.
///
/// `#[repr(C)]` with size 16 B, alignment 8. All concrete object structs
/// place this as their first field so pointer casts are safe.
#[repr(C)]
pub struct KernelObjectHeader
{
    /// Reference count; starts at 1 when created.
    pub ref_count: AtomicU32,
    /// Concrete type, for use during deallocation.
    pub obj_type: ObjectType,
    // Padding to reach 8-byte alignment for the ancestor pointer below.
    #[allow(clippy::pub_underscore_fields)]
    pub _pad: [u8; 3],
    /// Pointer to the `FrameObject`'s header this object was retyped from,
    /// or null if allocated via the legacy heap path. Set once at creation,
    /// read at deallocation. `AtomicPtr` for the unforgeable null sentinel
    /// without imposing const-init constraints on construction.
    pub ancestor: AtomicPtr<KernelObjectHeader>,
}

// SAFETY: ancestor is a back-pointer to a kernel object whose lifetime is
// guaranteed by retype's refcount semantics. Send+Sync via the surrounding
// object's existing locking discipline.
unsafe impl Send for KernelObjectHeader {}
// SAFETY: see Send impl above.
unsafe impl Sync for KernelObjectHeader {}

impl KernelObjectHeader
{
    /// Construct a new header with `ref_count = 1` and no ancestor cap.
    ///
    /// Used by the legacy heap-allocation path. The retype primitive uses
    /// [`Self::with_ancestor`] to record the source `FrameObject` for
    /// auto-reclaim.
    pub fn new(obj_type: ObjectType) -> Self
    {
        Self {
            ref_count: AtomicU32::new(1),
            obj_type,
            _pad: [0; 3],
            ancestor: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Construct a new header tagged with the `FrameObject` it was retyped
    /// from.
    ///
    /// Used by the retype primitive. On `dec_ref → 0`, auto-reclaim consults
    /// this pointer to credit bytes back.
    pub fn with_ancestor(obj_type: ObjectType, ancestor: NonNull<KernelObjectHeader>) -> Self
    {
        Self {
            ref_count: AtomicU32::new(1),
            obj_type,
            _pad: [0; 3],
            ancestor: AtomicPtr::new(ancestor.as_ptr()),
        }
    }

    /// Increment the reference count. Call when a new capability slot is
    /// derived pointing to this object.
    pub fn inc_ref(&self)
    {
        self.ref_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the reference count and return the new value.
    ///
    /// Returns 0 when the object has no remaining capability references; the
    /// caller is responsible for freeing the object at that point.
    pub fn dec_ref(&self) -> u32
    {
        let prev = self.ref_count.fetch_sub(1, Ordering::Release);
        debug_assert!(
            prev != 0,
            "dec_ref underflow: obj_type={:?} self={:p} ancestor={:p}",
            self.obj_type,
            self,
            self.ancestor.load(Ordering::Relaxed),
        );
        prev - 1
    }
}

// ── Concrete object types ─────────────────────────────────────────────────────

/// Kernel object for a contiguous physical memory range (Frame capability).
///
/// Invariant: `base` MUST be 4 KiB-aligned and `size` MUST be a positive
/// multiple of `PAGE_SIZE`. `sys_mem_map` (`syscall::mem`) feeds
/// `base + offset` directly into `PageTableEntry::new_page`, which
/// `debug_assert!`s page alignment. `sys_frame_split` preserves the invariant
/// because `split_offset` is validated page-aligned before the tail's
/// `base = parent.base + split_offset` is computed. Producers minting a cap
/// from an external `physical_base` MUST mask down to a page boundary and
/// ceiling-round `size` to whole pages.
#[repr(C)]
pub struct FrameObject
{
    pub header: KernelObjectHeader,
    /// Physical base address of the region. 4 KiB-aligned.
    pub base: u64,
    /// Size of the region in bytes; multiple of `PAGE_SIZE`. Mutable:
    /// `sys_frame_split` shrinks it as a tail child is carved off;
    /// `sys_frame_merge` grows it as a tail child is absorbed back.
    /// Mutations require `lock` in write mode; reads (`sys_mem_map`,
    /// `retype_allocate`) require `lock` in read mode.
    pub size: u64,
    /// Bytes still available to retype into kernel objects, or to map.
    ///
    /// Initialised to `size` for RAM caps minted at boot with `Rights::RETYPE`.
    /// Set to `0` for firmware-table / boot-module / init-segment Frame caps
    /// (those caps don't carry RETYPE rights and never participate in retype
    /// or auto-reclaim — their `available_bytes` is informational only).
    /// `retype_allocate` debits this; `dealloc_object` auto-reclaim credits
    /// it back.
    pub available_bytes: AtomicU64,
    /// `true` if this Frame is responsible for returning `[base, base + size)`
    /// to the buddy allocator on final destruction. Buddy-backed frames set
    /// this at creation. Caps over non-buddy-managed physical memory (MMIO
    /// regions, firmware tables, boot modules, boot-loaded ELF segments)
    /// leave it `false`.
    ///
    /// `sys_frame_split` (Option D) leaves the parent's flag intact; the new
    /// tail child inherits the parent's `owns_memory` so each half buddy-frees
    /// its own `[base, base+size)` range on dealloc. `sys_frame_merge`
    /// clears the absorbed tail's flag (so only the parent — which now
    /// covers the merged range — buddy-frees on its eventual dealloc).
    pub owns_memory: AtomicBool,
    /// Per-Frame-cap retype allocator. Stored inline in kernel-owned memory
    /// so userspace `sys_mem_map` writes against the cap's region cannot
    /// corrupt the metadata. Zero-initialised: `bump_offset = 0` and every
    /// free-list head = `FREE_LIST_END` give the same "fresh cap, all
    /// bytes available" state the lazy install used to produce.
    pub allocator: crate::cap::retype::RetypeAllocator,
    /// Per-cap reader/writer lock guarding mutations of `size` (and the
    /// implicit `[base, base+size)` region they describe).
    ///
    /// Encoding mirrors `cap::derivation::DerivationLock`:
    /// - `0` → unlocked
    /// - `0 < n < u32::MAX` → `n` concurrent readers
    /// - `u32::MAX` → one writer
    ///
    /// Read-locked by `sys_mem_map` and `cap::retype::retype_allocate`
    /// across the validate-and-commit sequence. Write-locked by
    /// `sys_frame_split` and `sys_frame_merge` while the cap's region is
    /// mutated. Lock order against `DERIVATION_LOCK`: derivation-lock outer,
    /// frame-lock inner.
    pub lock: AtomicU32,
}

/// Sentinel encoding a held write lock in [`FrameObject::lock`]. Matches
/// `DerivationLock`'s convention.
#[allow(dead_code)]
const FRAME_WRITE_LOCKED: u32 = u32::MAX;

#[allow(dead_code)]
impl FrameObject
{
    /// Acquire a shared read lock. Spins while a writer holds the lock.
    pub fn read_lock(&self)
    {
        loop
        {
            let cur = self.lock.load(Ordering::Relaxed);
            if cur != FRAME_WRITE_LOCKED
                && self
                    .lock
                    .compare_exchange_weak(cur, cur + 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                break;
            }
            core::hint::spin_loop();
        }
    }

    /// Release a shared read lock previously acquired with [`Self::read_lock`].
    pub fn read_unlock(&self)
    {
        self.lock.fetch_sub(1, Ordering::Release);
    }

    /// Acquire the write lock. Spins until no readers or writers hold it.
    pub fn write_lock(&self)
    {
        loop
        {
            if self
                .lock
                .compare_exchange_weak(0, FRAME_WRITE_LOCKED, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
            core::hint::spin_loop();
        }
    }

    /// Release the write lock previously acquired with [`Self::write_lock`].
    pub fn write_unlock(&self)
    {
        self.lock.store(0, Ordering::Release);
    }
}

/// RAII guard releasing a read lock on a [`FrameObject`] when dropped.
///
/// Used by `sys_mem_map` and `cap::retype::retype_allocate` to ensure the
/// read lock is released on every return path, including `?` short-circuits.
pub struct FrameReadGuard<'a>
{
    frame: &'a FrameObject,
}

impl<'a> FrameReadGuard<'a>
{
    /// Acquire `frame`'s read lock and return the guard. The lock is
    /// released when the guard is dropped.
    pub fn acquire(frame: &'a FrameObject) -> Self
    {
        frame.read_lock();
        Self { frame }
    }
}

impl Drop for FrameReadGuard<'_>
{
    fn drop(&mut self)
    {
        self.frame.read_unlock();
    }
}

/// Kernel object for a memory-mapped I/O region (`MmioRegion` capability).
#[repr(C)]
pub struct MmioRegionObject
{
    pub header: KernelObjectHeader,
    /// Physical base address of the MMIO region.
    pub base: u64,
    /// Size of the MMIO region in bytes.
    pub size: u64,
    /// Flags from the platform resource entry (bit 0: write-combine).
    pub flags: u32,
    // Explicit padding to preserve repr(C) layout.
    #[allow(clippy::pub_underscore_fields)]
    pub _pad: u32,
}

/// Kernel object for a hardware interrupt range (Interrupt capability).
///
/// A cap with `count == 1` is a single-IRQ cap usable with
/// `sys_irq_register` / `sys_irq_ack`. Wider caps are delegatable
/// range authorities: narrow them with `sys_irq_split` before use.
#[repr(C)]
pub struct InterruptObject
{
    pub header: KernelObjectHeader,
    /// First IRQ line in the range (GSI on x86-64, PLIC source on RISC-V).
    pub start: u32,
    /// Number of consecutive IRQ lines covered by the cap.
    pub count: u32,
}

/// Kernel object for an x86-64 I/O port range (`IoPortRange` capability).
#[repr(C)]
pub struct IoPortRangeObject
{
    pub header: KernelObjectHeader,
    /// First port number in the range.
    pub base: u16,
    /// Number of consecutive ports.
    pub size: u16,
    // Explicit padding to preserve repr(C) layout.
    #[allow(clippy::pub_underscore_fields)]
    pub _pad: u32,
}

/// Kernel object for scheduling control authority (`SchedControl` capability).
///
/// There is exactly one `SchedControl` object, created at boot.
#[repr(C)]
pub struct SchedControlObject
{
    pub header: KernelObjectHeader,
}

/// Kernel object for SBI forwarding authority (`SbiControl` capability).
///
/// RISC-V only. There is exactly one `SbiControl` object, created at boot.
/// Grants the holder authority to forward SBI calls through the kernel to
/// M-mode firmware.
#[repr(C)]
pub struct SbiControlObject
{
    pub header: KernelObjectHeader,
}

/// Kernel object for a thread control block (Thread capability).
#[repr(C)]
pub struct ThreadObject
{
    pub header: KernelObjectHeader,
    /// Pointer to the TCB. Heap-allocated for legacy threads; for retype-
    /// backed threads it points inside the same five-page retype slot that
    /// holds the kstack and this wrapper. Discriminated by `header.ancestor`.
    pub tcb: *mut crate::sched::thread::ThreadControlBlock,
}

// SAFETY: ThreadObject is accessed only under the scheduler lock.
unsafe impl Send for ThreadObject {}
// SAFETY: ThreadObject is accessed only under the scheduler lock.
unsafe impl Sync for ThreadObject {}

/// Maximum number of distinct retype-source chunks an `AddressSpaceObject`
/// or `CSpaceKernelObject` may track.
///
/// Each augment-mode call (`cap_create_aspace(frame, target)` /
/// `cap_create_cspace(frame, target)`) consumes one slot. The original
/// create-time chunk also occupies one slot. Sixteen is enough to absorb
/// many augment events without bloating the wrapper struct.
pub const MAX_PT_CHUNKS: usize = 16;

/// Per-chunk record of a retype-allocated multi-page region donated to an
/// `AddressSpaceObject`'s PT pool or a `CSpaceKernelObject`'s slot-page
/// pool.
///
/// At dealloc, every non-vacant slot is fed back to its `ancestor`
/// `FrameObject` via `retype_free`, then the ancestor is `dec_ref`'d.
#[repr(C)]
pub struct PoolChunkSlot
{
    /// `FrameObject` ancestor this chunk was carved from. Null = vacant.
    pub ancestor: AtomicPtr<KernelObjectHeader>,
    /// Byte offset within the ancestor's region.
    pub base_offset: AtomicU64,
    /// Total pages carved (initial + grown).
    pub page_count: AtomicU64,
}

impl PoolChunkSlot
{
    /// Construct a vacant slot (ancestor = null, offset = 0, count = 0).
    #[must_use]
    pub const fn vacant() -> Self
    {
        Self {
            ancestor: AtomicPtr::new(core::ptr::null_mut()),
            base_offset: AtomicU64::new(0),
            page_count: AtomicU64::new(0),
        }
    }
}

/// Kernel object for a user-mode address space (`AddressSpace` capability).
#[repr(C)]
pub struct AddressSpaceObject
{
    pub header: KernelObjectHeader,
    /// Pointer to the `AddressSpace` (heap-allocated; the wrapper's PT pool
    /// is retype-backed but the `AddressSpace` struct itself, holding the
    /// root-PT virtual base and per-arch fields, still lives on the kernel
    /// heap pending a follow-up that retypes init's bootstrap state).
    pub address_space: *mut crate::mm::address_space::AddressSpace,
    /// Bytes available to back new intermediate page-table pages on `mem_map`.
    ///
    /// Seeded at retype time from the source Frame cap's `available_bytes`.
    /// Refilled via augment-mode on `SYS_CAP_CREATE_ASPACE`
    /// (`cap_create_aspace(frame_cap, target_aspace_cap)`). `mem_map` returns
    /// `NoMemory` if a new PT page is needed but the budget is exhausted.
    pub pt_growth_budget_bytes: AtomicU64,
    /// Spinlock guarding `pt_pool_head_phys` and the `pt_chunks` array.
    /// `0` = unlocked, `1` = locked.
    pub pt_pool_lock: AtomicU64,
    /// Head of the intrusive free-list of available PT pages, by physical
    /// address. `0` = empty. Each free page's first 8 bytes hold the
    /// physical address of the next free page (read/written via the
    /// kernel direct map).
    pub pt_pool_head_phys: AtomicU64,
    /// Records of every retype-source chunk donated to this AS. `dealloc`
    /// walks this array and `retype_free`s each chunk wholesale.
    pub pt_chunks: [PoolChunkSlot; MAX_PT_CHUNKS],
}

// SAFETY: AddressSpaceObject is accessed only with proper locks.
unsafe impl Send for AddressSpaceObject {}
// SAFETY: AddressSpaceObject is accessed only with proper locks.
unsafe impl Sync for AddressSpaceObject {}

/// Kernel object for a capability space (`CSpace` capability).
#[repr(C)]
pub struct CSpaceKernelObject
{
    pub header: KernelObjectHeader,
    /// Pointer to the `CSpace` (heap-allocated; the wrapper's slot-page
    /// pool is retype-backed but the `CSpace` directory itself still lives
    /// on the kernel heap pending the follow-up that retypes init's
    /// bootstrap state).
    pub cspace: *mut crate::cap::cspace::CSpace,
    /// Bytes available to back new slot pages when the `CSpace` grows.
    ///
    /// Seeded at retype time from the source Frame cap's `available_bytes`.
    /// Refilled via augment-mode on `SYS_CAP_CREATE_CSPACE`
    /// (`cap_create_cspace(frame_cap, target_cspace_cap)`).
    /// `cspace_grow` returns `NoMemory` if a new slot page is needed but the
    /// budget is exhausted.
    pub cspace_growth_budget_bytes: AtomicU64,
    /// Spinlock guarding `cs_pool_head_phys` and the `cs_chunks` array.
    pub cs_pool_lock: AtomicU64,
    /// Head of the intrusive free-list of available slot pages, by physical
    /// address. `0` = empty.
    pub cs_pool_head_phys: AtomicU64,
    /// Records of every retype-source chunk donated to this `CSpace`.
    pub cs_chunks: [PoolChunkSlot; MAX_PT_CHUNKS],
}

// SAFETY: CSpaceKernelObject is accessed only with proper locks.
unsafe impl Send for CSpaceKernelObject {}
// SAFETY: CSpaceKernelObject is accessed only with proper locks.
unsafe impl Sync for CSpaceKernelObject {}

/// Acquire a pool spinlock (`pt_pool_lock` or `cs_pool_lock`).
#[inline]
#[allow(dead_code)]
fn pool_lock(lock: &AtomicU64)
{
    while lock
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

/// Release a pool spinlock.
#[inline]
#[allow(dead_code)]
fn pool_unlock(lock: &AtomicU64)
{
    lock.store(0, Ordering::Release);
}

/// Pop one page from the pool free-list rooted at `head_phys`. Returns the
/// page's physical address, or `0` if the pool is empty.
///
/// Caller must hold the pool lock.
///
/// # Safety
/// `head_phys` must point at the actual `AtomicU64` head field of a live
/// pool. The free-list link slots in the pages must not be aliased.
#[cfg(not(test))]
#[allow(dead_code)]
unsafe fn pool_pop(head_phys: &AtomicU64) -> u64
{
    let head = head_phys.load(Ordering::Acquire);
    if head == 0
    {
        return 0;
    }
    let virt = crate::mm::paging::phys_to_virt(head);
    // SAFETY: `head` was placed on the list by a prior pool_push and points
    // inside a live retype chunk; its first 8 bytes hold the next link.
    let next = unsafe { core::ptr::read_volatile(virt as *const u64) };
    head_phys.store(next, Ordering::Release);
    head
}

/// Push a page onto the pool free-list. Caller must hold the pool lock and
/// must have ensured the page is no longer in use.
///
/// # Safety
/// `phys` must be page-aligned, within a chunk owned by this pool, and not
/// concurrently aliased.
#[cfg(not(test))]
#[allow(dead_code)]
unsafe fn pool_push(head_phys: &AtomicU64, phys: u64)
{
    let prev = head_phys.load(Ordering::Acquire);
    let virt = crate::mm::paging::phys_to_virt(phys);
    // SAFETY: caller guarantees `phys` is exclusively owned and unaliased.
    unsafe { core::ptr::write_volatile(virt as *mut u64, prev) };
    head_phys.store(phys, Ordering::Release);
}

/// Stamp out a fresh `[PoolChunkSlot; MAX_PT_CHUNKS]` array of vacant slots.
///
/// Used by both `AddressSpaceObject` and `CSpaceKernelObject` constructors.
#[must_use]
pub fn vacant_chunk_slots() -> [PoolChunkSlot; MAX_PT_CHUNKS]
{
    core::array::from_fn(|_| PoolChunkSlot::vacant())
}

impl AddressSpaceObject
{
    /// Test-only heap-backed wrapper with empty pool. Retype-backed wrappers
    /// are constructed in place by `sys_cap_create_aspace` and (for init's
    /// bootstrap AS) by `cap::boot_retype_aspace`.
    #[cfg(test)]
    #[must_use]
    pub fn heap_backed(address_space: *mut crate::mm::address_space::AddressSpace) -> Self
    {
        Self {
            header: KernelObjectHeader::new(ObjectType::AddressSpace),
            address_space,
            pt_growth_budget_bytes: AtomicU64::new(0),
            pt_pool_lock: AtomicU64::new(0),
            pt_pool_head_phys: AtomicU64::new(0),
            pt_chunks: vacant_chunk_slots(),
        }
    }

    /// Pop a free PT page from this AS's pool, charging the growth budget.
    /// Returns the page's physical address, or `None` if the pool is empty.
    #[cfg(not(test))]
    #[allow(dead_code)]
    pub fn alloc_pt_page(&self) -> Option<u64>
    {
        pool_lock(&self.pt_pool_lock);
        // SAFETY: lock held; pt_pool_head_phys points at our atomic head.
        let phys = unsafe { pool_pop(&self.pt_pool_head_phys) };
        pool_unlock(&self.pt_pool_lock);
        if phys == 0
        {
            return None;
        }
        // Debit the growth budget. The free-list link bytes were written
        // when the page was last freed; zero the page now so the caller
        // sees a fresh PT.
        self.pt_growth_budget_bytes
            .fetch_sub(crate::mm::PAGE_SIZE as u64, Ordering::AcqRel);
        let virt = crate::mm::paging::phys_to_virt(phys);
        // SAFETY: the page is now owned by the caller, no aliases.
        unsafe { core::ptr::write_bytes(virt as *mut u8, 0, crate::mm::PAGE_SIZE) };
        Some(phys)
    }

    /// Return a previously-allocated PT page to the pool.
    ///
    /// # Safety
    /// `phys` must come from a prior [`alloc_pt_page`] call on this AS, and
    /// the page must no longer be in use as a page table.
    #[cfg(not(test))]
    #[allow(dead_code)]
    pub unsafe fn free_pt_page(&self, phys: u64)
    {
        pool_lock(&self.pt_pool_lock);
        // SAFETY: lock held; caller's contract guarantees `phys` is owned by
        // this pool and not aliased.
        unsafe { pool_push(&self.pt_pool_head_phys, phys) };
        pool_unlock(&self.pt_pool_lock);
        self.pt_growth_budget_bytes
            .fetch_add(crate::mm::PAGE_SIZE as u64, Ordering::AcqRel);
    }

    /// Record a freshly-retyped chunk and seed its pages onto the pool.
    /// Returns `Err(())` if every chunk slot is occupied.
    ///
    /// # Safety
    /// `ancestor` must be a live `FrameObject`'s header; this call must
    /// follow a successful `retype_allocate(.., page_count * PAGE_SIZE)`
    /// against that ancestor returning `base_offset`. Caller has already
    /// `inc_ref`'d `ancestor`.
    ///
    /// `pool_pages` controls how many of the chunk's pages are seeded onto
    /// the free pool; the remainder are reserved (used for fixed-purpose
    /// allocations like the root PT in create-mode). The chunk slot
    /// always records the *full* `total_pages` so dealloc reclaims the
    /// entire span.
    ///
    /// Pool pages are taken from the *high* end of the chunk; reserved
    /// pages occupy `[base_offset, base_offset + (total_pages - pool_pages) * PAGE_SIZE)`.
    #[cfg(not(test))]
    #[allow(dead_code)]
    pub unsafe fn add_chunk(
        &self,
        ancestor: NonNull<KernelObjectHeader>,
        ancestor_frame_base: u64,
        base_offset: u64,
        total_pages: u64,
        pool_pages: u64,
    ) -> Result<(), ()>
    {
        debug_assert!(pool_pages <= total_pages);
        let p = crate::mm::PAGE_SIZE as u64;
        let reserved = total_pages - pool_pages;
        pool_lock(&self.pt_pool_lock);

        // Find a vacant chunk slot.
        let mut slot_idx = MAX_PT_CHUNKS;
        for (i, slot) in self.pt_chunks.iter().enumerate()
        {
            if slot.ancestor.load(Ordering::Relaxed).is_null()
            {
                slot_idx = i;
                break;
            }
        }
        if slot_idx == MAX_PT_CHUNKS
        {
            pool_unlock(&self.pt_pool_lock);
            return Err(());
        }

        let slot = &self.pt_chunks[slot_idx];
        slot.base_offset.store(base_offset, Ordering::Relaxed);
        slot.page_count.store(total_pages, Ordering::Relaxed);
        // Set ancestor LAST: a non-null ancestor signifies a fully-populated
        // slot.
        slot.ancestor.store(ancestor.as_ptr(), Ordering::Release);

        // Push pool pages in reverse so the lowest address ends up at the
        // head of the free list (purely cosmetic).
        for i in (reserved..total_pages).rev()
        {
            let page_phys = ancestor_frame_base + base_offset + i * p;
            // SAFETY: lock held; chunk was just retyped from `ancestor`.
            unsafe { pool_push(&self.pt_pool_head_phys, page_phys) };
        }

        pool_unlock(&self.pt_pool_lock);
        self.pt_growth_budget_bytes
            .fetch_add(pool_pages * p, Ordering::AcqRel);
        Ok(())
    }
}

impl CSpaceKernelObject
{
    /// Test-only heap-backed wrapper with empty pool. Retype-backed wrappers
    /// are constructed in place by `sys_cap_create_cspace` and (for the
    /// root CSpace) by `cap::boot_retype_cspace`.
    #[cfg(test)]
    #[must_use]
    pub fn heap_backed(cspace: *mut crate::cap::cspace::CSpace) -> Self
    {
        Self {
            header: KernelObjectHeader::new(ObjectType::CSpaceObj),
            cspace,
            cspace_growth_budget_bytes: AtomicU64::new(0),
            cs_pool_lock: AtomicU64::new(0),
            cs_pool_head_phys: AtomicU64::new(0),
            cs_chunks: vacant_chunk_slots(),
        }
    }

    /// Pop a free slot page from this `CSpace`'s pool, charging the growth
    /// budget. Returns the page's physical address, or `None` if empty.
    #[cfg(not(test))]
    #[allow(dead_code)]
    pub fn alloc_slot_page(&self) -> Option<u64>
    {
        pool_lock(&self.cs_pool_lock);
        // SAFETY: lock held.
        let phys = unsafe { pool_pop(&self.cs_pool_head_phys) };
        pool_unlock(&self.cs_pool_lock);
        if phys == 0
        {
            return None;
        }
        self.cspace_growth_budget_bytes
            .fetch_sub(crate::mm::PAGE_SIZE as u64, Ordering::AcqRel);
        let virt = crate::mm::paging::phys_to_virt(phys);
        // SAFETY: page is now exclusively owned by the caller.
        unsafe { core::ptr::write_bytes(virt as *mut u8, 0, crate::mm::PAGE_SIZE) };
        Some(phys)
    }

    /// Record a freshly-retyped chunk and seed its pages onto the pool.
    ///
    /// # Safety
    /// See [`AddressSpaceObject::add_chunk`].
    #[cfg(not(test))]
    #[allow(dead_code)]
    pub unsafe fn add_chunk(
        &self,
        ancestor: NonNull<KernelObjectHeader>,
        ancestor_frame_base: u64,
        base_offset: u64,
        total_pages: u64,
        pool_pages: u64,
    ) -> Result<(), ()>
    {
        debug_assert!(pool_pages <= total_pages);
        let p = crate::mm::PAGE_SIZE as u64;
        let reserved = total_pages - pool_pages;
        pool_lock(&self.cs_pool_lock);

        let mut slot_idx = MAX_PT_CHUNKS;
        for (i, slot) in self.cs_chunks.iter().enumerate()
        {
            if slot.ancestor.load(Ordering::Relaxed).is_null()
            {
                slot_idx = i;
                break;
            }
        }
        if slot_idx == MAX_PT_CHUNKS
        {
            pool_unlock(&self.cs_pool_lock);
            return Err(());
        }

        let slot = &self.cs_chunks[slot_idx];
        slot.base_offset.store(base_offset, Ordering::Relaxed);
        slot.page_count.store(total_pages, Ordering::Relaxed);
        slot.ancestor.store(ancestor.as_ptr(), Ordering::Release);

        for i in (reserved..total_pages).rev()
        {
            let page_phys = ancestor_frame_base + base_offset + i * p;
            // SAFETY: see add_chunk on AddressSpaceObject.
            unsafe { pool_push(&self.cs_pool_head_phys, page_phys) };
        }

        pool_unlock(&self.cs_pool_lock);
        self.cspace_growth_budget_bytes
            .fetch_add(pool_pages * p, Ordering::AcqRel);
        Ok(())
    }
}

/// Kernel object for an IPC endpoint (Endpoint capability).
#[repr(C)]
pub struct EndpointObject
{
    pub header: KernelObjectHeader,
    /// Pointer to the endpoint's mutable state. For retype-backed Endpoints
    /// the state lives inline at `wrapper + 8`; for legacy heap-allocated
    /// Endpoints it points at a separate `Box<EndpointState>`. The
    /// `header.ancestor` discriminant tells the dealloc path which is which.
    pub state: *mut crate::ipc::endpoint::EndpointState,
}

// SAFETY: EndpointObject is accessed only under the scheduler lock.
unsafe impl Send for EndpointObject {}
// SAFETY: EndpointObject is accessed only under the scheduler lock.
unsafe impl Sync for EndpointObject {}

/// Kernel object for a signal (Signal capability).
#[repr(C)]
pub struct SignalObject
{
    pub header: KernelObjectHeader,
    /// Pointer to the signal's mutable state. Inline for retype-backed
    /// Signals, separately heap-allocated for legacy Signals; discriminated
    /// by `header.ancestor`.
    pub state: *mut crate::ipc::signal::SignalState,
}

// SAFETY: SignalObject is accessed only under the scheduler lock.
unsafe impl Send for SignalObject {}
// SAFETY: SignalObject is accessed only under the scheduler lock.
unsafe impl Sync for SignalObject {}

/// Kernel object for an event queue (`EventQueue` capability).
///
/// For retype-backed `EventQueue`s the wrapper, `EventQueueState`, and
/// the ring buffer all live in the same retype slot — the ring is at
/// offset [`crate::cap::retype::EVENT_QUEUE_RING_OFFSET`] from the wrapper
/// base, and the slot is reclaimed wholesale via `retype_free`. Legacy
/// heap-allocated `EventQueue`s keep `EventQueueState` and the ring as
/// separate heap allocations.
#[repr(C)]
pub struct EventQueueObject
{
    pub header: KernelObjectHeader,
    /// Pointer to the event-queue state — inline for retype-backed,
    /// separately heap-allocated for legacy. Discriminated by
    /// `header.ancestor`.
    pub state: *mut crate::ipc::event_queue::EventQueueState,
}

// SAFETY: EventQueueObject is accessed only under the scheduler lock.
unsafe impl Send for EventQueueObject {}
// SAFETY: EventQueueObject is accessed only under the scheduler lock.
unsafe impl Sync for EventQueueObject {}

/// Kernel object for a wait set (`WaitSet` capability).
///
/// `WaitSetState` is the ~480-byte body holding member slots and the ready
/// ring; for retype-backed wait sets it lives inline immediately after the
/// 24-byte wrapper within a single `BIN_512` retype slot. Legacy heap-
/// allocated wait sets keep the state as a separate heap allocation.
#[repr(C)]
pub struct WaitSetObject
{
    pub header: KernelObjectHeader,
    /// Pointer to the wait-set state — inline for retype-backed,
    /// separately heap-allocated for legacy. Discriminated by
    /// `header.ancestor`.
    pub state: *mut crate::ipc::wait_set::WaitSetState,
}

// SAFETY: WaitSetObject is accessed only under the scheduler lock.
unsafe impl Send for WaitSetObject {}
// SAFETY: WaitSetObject is accessed only under the scheduler lock.
unsafe impl Sync for WaitSetObject {}

// ── Object deallocation ───────────────────────────────────────────────────────

/// Free a kernel object whose reference count has just reached zero.
///
/// Dispatches on `obj_type` to reconstruct the original `Box<ConcreteObject>`
/// and drop it, freeing any sub-resources first.
///
/// # Safety
///
/// - `ptr` must be a valid, non-null pointer originally produced by
///   `Box::into_raw` (cast to `*mut KernelObjectHeader`).
/// - The object's reference count must be 0; no other capability slot may
///   reference it.
/// - Must NOT be called with `DERIVATION_LOCK` held, since freeing complex
///   objects (Thread, `AddressSpace`) may acquire the frame-allocator lock.
///
/// # Cascade handling
///
/// Reclaiming a retype-backed object may credit bytes back to its ancestor
/// `FrameObject` and decrement the ancestor's refcount. If the ancestor's
/// refcount reaches zero (transitively, when reclaiming a chain of caps
/// whose only ref was the descendant), the ancestor must also be freed.
/// This is handled via an explicit stack-local worklist driven by this
/// function rather than by recursion: each arm pushes the freshly-orphaned
/// ancestor into the worklist, and the outer loop processes it on the next
/// iteration. Recursion would risk deadlock if a future change introduced a
/// lock above this point.
#[cfg(not(test))]
pub unsafe fn dealloc_object(ptr: core::ptr::NonNull<KernelObjectHeader>)
{
    /// Maximum nested-cascade depth handled. Real-world derivation chains
    /// (memmgr-frame → child-bootstrap split → kernel object) sit at depth
    /// `<= 4`; sixteen is generous headroom that fits on the kernel stack.
    const MAX_CASCADE: usize = 16;

    let mut worklist: [Option<core::ptr::NonNull<KernelObjectHeader>>; MAX_CASCADE] =
        [None; MAX_CASCADE];
    worklist[0] = Some(ptr);
    let mut head: usize = 1;

    while head > 0
    {
        head -= 1;
        let Some(next) = worklist[head]
        else
        {
            continue;
        };
        worklist[head] = None;
        // SAFETY: `next` is a NonNull<KernelObjectHeader> that was either the
        // original caller-supplied pointer or pushed onto the worklist by an
        // ancestor-reclaim arm — both contracts require ref_count == 0 and
        // exclusive ownership at this point.
        unsafe { dealloc_object_one(next, &mut worklist, &mut head) };
    }
}

/// Reclaim one already-zero-refcount object. If the reclaim cascades into
/// the ancestor (`dec_ref` returns 0 against the source `FrameObject`),
/// pushes the ancestor's pointer onto the worklist instead of recursing.
///
/// # Safety
///
/// Same contract as [`dealloc_object`].
// cast_ptr_alignment: every concrete object type is allocated as Box<ConcreteType>,
// which guarantees alignment to align_of::<ConcreteType>(). The NonNull<KernelObjectHeader>
// points to the first field (header at offset 0), so the pointer retains the concrete
// type's alignment even when stored as KernelObjectHeader*.
// too_many_lines: structural dispatch over all object types; splitting further
// would obscure the type hierarchy without reducing complexity.
#[allow(
    clippy::cast_ptr_alignment,
    clippy::too_many_lines,
    clippy::items_after_statements
)]
#[cfg(not(test))]
unsafe fn dealloc_object_one(
    ptr: core::ptr::NonNull<KernelObjectHeader>,
    worklist: &mut [Option<core::ptr::NonNull<KernelObjectHeader>>],
    head: &mut usize,
)
{
    /// Push `anc` onto the cascade worklist. Drops the entry on overflow —
    /// see `MAX_CASCADE` in `dealloc_object`. Overflow is unreachable in
    /// practice for the derivation depths this kernel actually produces;
    /// dropping is preferable to a panic in the dealloc path.
    fn push_ancestor(
        worklist: &mut [Option<core::ptr::NonNull<KernelObjectHeader>>],
        head: &mut usize,
        anc: core::ptr::NonNull<KernelObjectHeader>,
    )
    {
        if *head < worklist.len()
        {
            worklist[*head] = Some(anc);
            *head += 1;
        }
    }

    // SAFETY: ptr is NonNull<KernelObjectHeader>, validated at call site.
    let header = unsafe { ptr.as_ref() };
    match header.obj_type
    {
        // ── Simple objects (no sub-resources) ─────────────────────────────
        ObjectType::Frame =>
        {
            // Return buddy-backed physical memory before freeing the Rust
            // object. `owns_memory` is false for MMIO / firmware / boot
            // module / init-segment caps (the physical memory is not part
            // of the buddy pool at all) and for split originals (ownership
            // was atomically transferred to the children).
            // SAFETY: ptr points to a live FrameObject; single-owner access
            // since refcount reached zero at the call site.
            let (base, size, owned) = unsafe {
                let obj = &*ptr.as_ptr().cast::<FrameObject>();
                (
                    obj.base,
                    obj.size,
                    obj.owns_memory.load(core::sync::atomic::Ordering::Acquire),
                )
            };
            // The lazily-installed retype-allocator metadata lives at offset
            // 0 of the cap's own backing region; freeing the buddy pages
            // below reclaims it wholesale. `RetypeAllocator` has no Drop
            // implementation, so no in-place teardown is required.
            if owned
            {
                // SAFETY: buddy free-range frees the pages we originally
                // allocated from the buddy. Pages are not mapped anywhere
                // once we are here: CSpace teardown on the owning process
                // has already cleared every mapping that referenced them.
                unsafe {
                    crate::mm::with_frame_allocator(|alloc| alloc.free_range(base, size));
                }
            }

            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);
            debug_assert!(
                !ancestor_ptr.is_null(),
                "Frame: every production cap is retype-backed (Phase-7 SEED, sys_frame_split SEED)"
            );
            // Retype-backed body lives inside the ancestor (the seed
            // Frame). Drop in place, return the body bytes to the
            // seed's per-Frame allocator, drop the retype-time lease.
            use crate::cap::retype::retype_free;
            // SAFETY: ancestor_ptr non-null per debug_assert and 4b invariant.
            let ancestor_frame = unsafe { &*ancestor_ptr.cast::<FrameObject>() };
            let body_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let offset = body_phys - ancestor_frame.base;
            // SAFETY: ptr is the in-place FrameObject; refcount 0 — unique access.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<FrameObject>()) };
            retype_free(
                ancestor_frame,
                offset,
                core::mem::size_of::<FrameObject>() as u64,
            );
            let new_rc = ancestor_frame.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: ancestor_ptr non-null.
                let ancestor_nn = unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
                push_ancestor(worklist, head, ancestor_nn);
            }
        }
        ObjectType::MmioRegion =>
        {
            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);
            debug_assert!(
                !ancestor_ptr.is_null(),
                "MmioRegion: every production cap is retype-backed (Phase-7 SEED, sys_mmio_split SEED)"
            );
            use crate::cap::retype::retype_free;
            // SAFETY: ancestor_ptr non-null per debug_assert and 4b invariant.
            let ancestor_frame = unsafe { &*ancestor_ptr.cast::<FrameObject>() };
            let body_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let offset = body_phys - ancestor_frame.base;
            // SAFETY: in-place body; refcount 0 — unique access.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<MmioRegionObject>()) };
            retype_free(
                ancestor_frame,
                offset,
                core::mem::size_of::<MmioRegionObject>() as u64,
            );
            let new_rc = ancestor_frame.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: ancestor_ptr non-null.
                let ancestor_nn = unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
                push_ancestor(worklist, head, ancestor_nn);
            }
        }
        ObjectType::Interrupt =>
        {
            // SAFETY: ptr points to a live InterruptObject; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<InterruptObject>()) };
            let start = obj.start;
            let count = obj.count;

            // Only single-IRQ caps ever register a signal with the routing
            // table and program the controller (sys_irq_register asserts
            // `count == 1`). Range caps are delegation authorities; they
            // have no routing-table footprint to clean up.
            if count == 1
            {
                // SAFETY: single-CPU; disable interrupts to serialise with
                //         dispatch_device_irq (interrupt context).
                unsafe {
                    let saved = crate::arch::current::cpu::save_and_disable_interrupts();
                    crate::irq::unregister(start);
                    crate::arch::current::cpu::restore_interrupts(saved);
                }
                crate::arch::current::interrupts::mask(start);
            }

            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);
            debug_assert!(
                !ancestor_ptr.is_null(),
                "Interrupt: every production cap is retype-backed (Phase-7 SEED, sys_irq_split SEED)"
            );
            use crate::cap::retype::retype_free;
            // SAFETY: ancestor_ptr non-null per 4b invariant.
            let ancestor_frame = unsafe { &*ancestor_ptr.cast::<FrameObject>() };
            let body_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let offset = body_phys - ancestor_frame.base;
            // SAFETY: in-place body; refcount 0 — unique access.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<InterruptObject>()) };
            retype_free(
                ancestor_frame,
                offset,
                core::mem::size_of::<InterruptObject>() as u64,
            );
            let new_rc = ancestor_frame.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: ancestor_ptr non-null.
                let ancestor_nn = unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
                push_ancestor(worklist, head, ancestor_nn);
            }
        }
        ObjectType::IoPortRange =>
        {
            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);
            debug_assert!(
                !ancestor_ptr.is_null(),
                "IoPortRange: every production cap is retype-backed (Phase-7 SEED)"
            );
            use crate::cap::retype::retype_free;
            // SAFETY: ancestor_ptr non-null per 4b invariant.
            let ancestor_frame = unsafe { &*ancestor_ptr.cast::<FrameObject>() };
            let body_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let offset = body_phys - ancestor_frame.base;
            // SAFETY: in-place body; refcount 0 — unique access.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<IoPortRangeObject>()) };
            retype_free(
                ancestor_frame,
                offset,
                core::mem::size_of::<IoPortRangeObject>() as u64,
            );
            let new_rc = ancestor_frame.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: ancestor_ptr non-null.
                let ancestor_nn = unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
                push_ancestor(worklist, head, ancestor_nn);
            }
        }
        ObjectType::SchedControl =>
        {
            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);
            debug_assert!(
                !ancestor_ptr.is_null(),
                "SchedControl: every production cap is retype-backed (Phase-7 SEED)"
            );
            use crate::cap::retype::retype_free;
            // SAFETY: ancestor_ptr non-null per 4b invariant.
            let ancestor_frame = unsafe { &*ancestor_ptr.cast::<FrameObject>() };
            let body_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let offset = body_phys - ancestor_frame.base;
            // SAFETY: in-place body; refcount 0 — unique access.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<SchedControlObject>()) };
            retype_free(
                ancestor_frame,
                offset,
                core::mem::size_of::<SchedControlObject>() as u64,
            );
            let new_rc = ancestor_frame.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: ancestor_ptr non-null.
                let ancestor_nn = unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
                push_ancestor(worklist, head, ancestor_nn);
            }
        }
        ObjectType::SbiControl =>
        {
            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);
            debug_assert!(
                !ancestor_ptr.is_null(),
                "SbiControl: every production cap is retype-backed (Phase-7 SEED)"
            );
            use crate::cap::retype::retype_free;
            // SAFETY: ancestor_ptr non-null per 4b invariant.
            let ancestor_frame = unsafe { &*ancestor_ptr.cast::<FrameObject>() };
            let body_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let offset = body_phys - ancestor_frame.base;
            // SAFETY: in-place body; refcount 0 — unique access.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<SbiControlObject>()) };
            retype_free(
                ancestor_frame,
                offset,
                core::mem::size_of::<SbiControlObject>() as u64,
            );
            let new_rc = ancestor_frame.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: ancestor_ptr non-null.
                let ancestor_nn = unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
                push_ancestor(worklist, head, ancestor_nn);
            }
        }

        // ── Thread ────────────────────────────────────────────────────────
        ObjectType::Thread =>
        {
            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);

            // SAFETY: ptr points to a ThreadObject; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<ThreadObject>()) };
            let tcb = obj.tcb;

            if !tcb.is_null()
            {
                // Remove the TCB from the scheduler's run queue before freeing.
                // Without this, the scheduler could dequeue a freed TCB pointer
                // after this cap_delete completes — a use-after-free that
                // corrupts the slab and/or causes a hang when the scheduler
                // tries to context-switch to garbage state.
                //
                // Must use preferred_cpu (where the thread was last scheduled),
                // NOT select_target_cpu (which load-balances and may return a
                // completely different CPU). The TCB is only in the scheduler
                // of the CPU where it was last enqueued.
                //
                // If the thread is still sched.current on its CPU (actively
                // running or mid-context-switch), we must wait for the context
                // Drain protocol per docs/thread-lifecycle-and-sleep.md
                // § dealloc_object(Thread) Drain Protocol: lock every CPU
                // (preferred_cpu is racy with concurrent enqueue_and_wake),
                // commit Exited, drain queues, snapshot any reply-bound
                // client for wake outside the all-locks region.
                let server_reply_wake: Option<(
                    *mut crate::sched::thread::ThreadControlBlock,
                    u8,
                    usize,
                )>;
                // needless_range_loop: explicit indexing is clearer for scheduler_for(cpu)
                // and saved_flags[cpu] parallel access.
                #[allow(clippy::needless_range_loop)]
                // SAFETY: tcb validated non-null; all scheduler locks are acquired in
                // ascending order to prevent deadlock; lock_raw paired with unlock_raw.
                unsafe {
                    use crate::sched::thread::ThreadState;
                    let cpu_count = crate::sched::CPU_COUNT
                        .load(core::sync::atomic::Ordering::Relaxed)
                        as usize;

                    // Acquire all scheduler locks in ascending CPU order to
                    // prevent ABBA deadlock.
                    let mut saved_flags: [u64; crate::sched::MAX_CPUS] =
                        [0; crate::sched::MAX_CPUS];
                    for cpu in 0..cpu_count
                    {
                        saved_flags[cpu] = crate::sched::scheduler_for(cpu).lock.lock_raw();
                    }

                    // Read priority inside the all-locks region; a concurrent
                    // sys_thread_set_priority would race outside.
                    let prio = (*tcb).priority;

                    // Mark Exited under all locks — no schedule() on any CPU
                    // can see this thread as Ready/Running after this point.
                    (*tcb).state = ThreadState::Exited;

                    // Remove from whichever queue it's actually in.
                    for cpu in 0..cpu_count
                    {
                        crate::sched::scheduler_for(cpu).remove_from_queue(tcb, prio);
                    }

                    // Wake any reply-bound client with Interrupted; otherwise
                    // they would remain BlockedOnReply with a dangling
                    // blocked_on_object pointing at this freed server.
                    // The enqueue is deferred until after the all-locks
                    // release (enqueue_and_wake takes a scheduler.lock).
                    server_reply_wake = {
                        use core::sync::atomic::Ordering;
                        let bound = (*tcb).reply_tcb.load(Ordering::Acquire);
                        if bound.is_null()
                        {
                            None
                        }
                        else if (*tcb)
                            .reply_tcb
                            .compare_exchange(
                                bound,
                                core::ptr::null_mut(),
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                        {
                            (*bound).blocked_on_object = core::ptr::null_mut();
                            (*bound).ipc_state = crate::sched::thread::IpcThreadState::None;
                            (*bound).state = ThreadState::Ready;
                            let trap_frame = (*bound).trap_frame;
                            if !trap_frame.is_null()
                            {
                                (*trap_frame).set_return(syscall::SyscallError::Interrupted as i64);
                            }
                            let bp = (*bound).priority;
                            let bcpu = crate::sched::select_target_cpu(bound);
                            Some((bound, bp, bcpu))
                        }
                        else
                        {
                            // Concurrent cancel beat us.
                            None
                        }
                    };

                    // Check if the thread is actively running (sched.current)
                    // on any CPU.
                    let mut running_on: Option<usize> = None;
                    for cpu in 0..cpu_count
                    {
                        if crate::sched::scheduler_for(cpu).current == tcb
                        {
                            running_on = Some(cpu);
                            break;
                        }
                    }

                    // Release all locks.
                    for cpu in (0..cpu_count).rev()
                    {
                        crate::sched::scheduler_for(cpu)
                            .lock
                            .unlock_raw(saved_flags[cpu]);
                    }

                    // UAF gate: wait for the in-flight switch (if any) to
                    // both move off `tcb` AND publish context_saved=1. The
                    // context_saved spin is unconditional — the all-locks
                    // running_on snapshot can race past schedule()'s
                    // pre-save lock release. See
                    // docs/scheduling-internals.md § Cross-CPU TCB Ownership.
                    if let Some(run_cpu) = running_on
                    {
                        let sched = crate::sched::scheduler_for(run_cpu);
                        while {
                            let s = sched.lock.lock_raw();
                            let still_current = sched.current == tcb;
                            sched.lock.unlock_raw(s);
                            still_current
                        }
                        {
                            core::hint::spin_loop();
                        }
                    }
                    while (*tcb)
                        .context_saved
                        .load(core::sync::atomic::Ordering::Acquire)
                        == 0
                    {
                        core::hint::spin_loop();
                    }
                }

                // Wake the captured reply-bound client outside the all-locks
                // region (enqueue_and_wake takes a scheduler.lock).
                if let Some((bound, bp, bcpu)) = server_reply_wake
                {
                    // SAFETY: bound prepared under all-CPU locks above.
                    unsafe { crate::sched::enqueue_and_wake(bound, bcpu, bp) };
                }

                // Unlink this thread from any IPC object it's blocked on.
                // Without this, a signal/endpoint/event_queue retains a
                // dangling waiter pointer to the freed TCB. A subsequent
                // signal_send would return that pointer, and the caller
                // would enqueue_and_wake a freed TCB — use-after-free.
                // SAFETY: tcb is valid (not yet freed); blocked_on_object
                // and ipc_state are always valid on an initialized TCB.
                unsafe {
                    use crate::sched::thread::IpcThreadState;
                    let blocked_obj = (*tcb).blocked_on_object;
                    if !blocked_obj.is_null()
                    {
                        match (*tcb).ipc_state
                        {
                            IpcThreadState::BlockedOnSignal =>
                            {
                                let sig = blocked_obj.cast::<crate::ipc::signal::SignalState>();
                                // SAFETY: sig is valid; lock serialises with signal_send.
                                let saved = (*sig).lock.lock_raw();
                                if (*sig).waiter == tcb
                                {
                                    (*sig).waiter = core::ptr::null_mut();
                                }
                                (*sig).lock.unlock_raw(saved);
                            }
                            IpcThreadState::BlockedOnSend =>
                            {
                                let ep =
                                    &mut *blocked_obj.cast::<crate::ipc::endpoint::EndpointState>();
                                // SAFETY: ep is valid; lock serialises with endpoint ops.
                                let saved = ep.lock.lock_raw();
                                crate::ipc::endpoint::unlink_from_wait_queue(
                                    tcb,
                                    &mut ep.send_head,
                                    &mut ep.send_tail,
                                );
                                ep.lock.unlock_raw(saved);
                            }
                            IpcThreadState::BlockedOnRecv =>
                            {
                                let ep =
                                    &mut *blocked_obj.cast::<crate::ipc::endpoint::EndpointState>();
                                // SAFETY: ep is valid; lock serialises with endpoint ops.
                                let saved = ep.lock.lock_raw();
                                crate::ipc::endpoint::unlink_from_wait_queue(
                                    tcb,
                                    &mut ep.recv_head,
                                    &mut ep.recv_tail,
                                );
                                ep.lock.unlock_raw(saved);
                            }
                            IpcThreadState::BlockedOnEventQueue =>
                            {
                                let eq =
                                    blocked_obj.cast::<crate::ipc::event_queue::EventQueueState>();
                                // SAFETY: eq is valid; lock serialises with event_queue ops.
                                let saved = (*eq).lock.lock_raw();
                                if (*eq).waiter == tcb
                                {
                                    (*eq).waiter = core::ptr::null_mut();
                                }
                                (*eq).lock.unlock_raw(saved);
                            }
                            IpcThreadState::BlockedOnWaitSet =>
                            {
                                let ws = blocked_obj.cast::<crate::ipc::wait_set::WaitSetState>();
                                // SAFETY: ws is valid; lock serialises with waitset ops.
                                let saved = (*ws).lock.lock_raw();
                                if (*ws).waiter == tcb
                                {
                                    (*ws).waiter = core::ptr::null_mut();
                                }
                                (*ws).lock.unlock_raw(saved);
                            }
                            IpcThreadState::BlockedOnReply =>
                            {
                                // blocked_obj is the server TCB. CAS-clear
                                // the server's reply slot iff this dying
                                // client is still bound — mirror
                                // cancel_ipc_block.
                                use core::sync::atomic::Ordering;
                                let server =
                                    blocked_obj.cast::<crate::sched::thread::ThreadControlBlock>();
                                let _ = (*server).reply_tcb.compare_exchange(
                                    tcb,
                                    core::ptr::null_mut(),
                                    Ordering::AcqRel,
                                    Ordering::Acquire,
                                );
                            }
                            IpcThreadState::None =>
                            {}
                        }
                        (*tcb).blocked_on_object = core::ptr::null_mut();
                    }
                }

                // x86-64: release the per-thread IOPB to SEED if one was
                // bound via `sys_iopb_set`. RISC-V threads never set this
                // field; it stays null and the cleanup is a no-op.
                #[cfg(target_arch = "x86_64")]
                {
                    // SAFETY: tcb validated non-null; iopb field always valid.
                    let iopb_ptr = unsafe { (*tcb).iopb };
                    if !iopb_ptr.is_null()
                    {
                        crate::cap::retype::free_seed_scratch(
                            iopb_ptr.cast::<u8>(),
                            crate::arch::current::gdt::IOPB_SIZE as u64,
                        );
                        // SAFETY: tcb validated non-null.
                        unsafe {
                            (*tcb).iopb = core::ptr::null_mut();
                        }
                    }
                }

                // The per-thread XSAVE / FP-save area is page N+1 of the
                // Thread retype slot (see sys_cap_create_thread layout); it
                // is reclaimed wholesale by `retype_free` below as part of
                // the same slot release, so no separate free is needed.

                // Poison the TCB so any use-after-free reads garbage
                // instead of plausible values.
                // SAFETY: tcb is valid; we are about to free it.
                unsafe {
                    (*tcb).magic = 0;
                    (*tcb).priority = 0xFF;
                }

                // SAFETY: tcb lives in-place inside the retype slot;
                // refcount has reached 0, no scheduler holds it.
                unsafe { core::ptr::drop_in_place(tcb) };
            }

            debug_assert!(
                !ancestor_ptr.is_null(),
                "Thread: every production cap is retype-backed"
            );
            use crate::cap::retype::{dispatch_for, retype_free};
            let raw_bytes = dispatch_for(ObjectType::Thread, 0).map_or(
                (crate::sched::KERNEL_STACK_PAGES as u64 + 2) * crate::mm::PAGE_SIZE as u64,
                |e| e.raw_bytes,
            );
            // SAFETY: ancestor_ptr non-null per 4b invariant.
            let ancestor_frame = unsafe { &*ancestor_ptr.cast::<FrameObject>() };
            // The wrapper sits one full page above the slot's base,
            // immediately after the kstack pages.
            let wrapper_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let kstack_pages_bytes =
                (crate::sched::KERNEL_STACK_PAGES * crate::mm::PAGE_SIZE) as u64;
            let block_phys = wrapper_phys - kstack_pages_bytes;
            let offset = block_phys - ancestor_frame.base;

            // SAFETY: ptr is in-place ThreadObject.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<ThreadObject>()) };

            retype_free(ancestor_frame, offset, raw_bytes);

            let ancestor_nn =
                // SAFETY: ancestor_ptr non-null.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_frame.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: refcount reached 0.
                push_ancestor(worklist, head, ancestor_nn);
            }
        }

        // ── AddressSpace ──────────────────────────────────────────────────
        //
        // All `AddressSpace` objects are retype-backed: init's bootstrap AS
        // lands in a slab from `SEED_FRAME` (Phase 9), and every userspace
        // AS lands in a slab from a Frame cap (`sys_cap_create_aspace`).
        // Both inline `AddressSpace` into the same wrapper page as
        // `AddressSpaceObject`; both record at least one chunk slot covering
        // the wrapper, root PT, and PT growth pool. Reclamation walks the
        // chunk slots and `retype_free`s each one wholesale, then `dec_ref`s
        // the ancestor `FrameObject`.
        ObjectType::AddressSpace =>
        {
            // SAFETY: ptr points at an in-place AddressSpaceObject; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<AddressSpaceObject>()) };
            let as_ptr = obj.address_space;

            if !as_ptr.is_null()
            {
                // No CPU should still have this address space loaded in
                // satp/CR3 when we free its root page table.
                debug_assert!(
                    // SAFETY: as_ptr non-null; active_cpu_mask is an Acquire load.
                    unsafe { (*as_ptr).active_cpu_mask() } == 0,
                    "dealloc AddressSpace: freeing root while active_cpus != 0"
                );

                debug_assert!(
                    !obj.pt_chunks[0].ancestor.load(Ordering::Acquire).is_null(),
                    "dealloc AddressSpace: heap-backed AS reached typed-memory dealloc path"
                );

                // Snapshot every chunk slot into a stack array before
                // freeing — `retype_free` may touch the chunk pages
                // (writing free-list links into them), and the wrapper
                // itself lives in the chunk being reclaimed, so the
                // snapshot must finish before we free.
                let mut snapshot: [(u64, u64, *mut KernelObjectHeader); MAX_PT_CHUNKS] =
                    [(0, 0, core::ptr::null_mut()); MAX_PT_CHUNKS];
                let mut count = 0;
                for slot in &obj.pt_chunks
                {
                    let anc = slot.ancestor.load(Ordering::Acquire);
                    if anc.is_null()
                    {
                        continue;
                    }
                    let off = slot.base_offset.load(Ordering::Relaxed);
                    let pages = slot.page_count.load(Ordering::Relaxed);
                    snapshot[count] = (off, pages, anc);
                    count += 1;
                }

                // Drop in-place objects before reclaiming their storage.
                // `AddressSpace` and `AddressSpaceObject` have no Drop logic
                // today; the explicit calls keep the contract correct if
                // either grows one.
                // SAFETY: as_ptr and obj are about to be reclaimed; no
                // outside reference can outlive the cap deletion that
                // brought us here.
                unsafe {
                    core::ptr::drop_in_place(as_ptr);
                }

                let p = crate::mm::PAGE_SIZE as u64;
                for &(off, pages, anc_ptr) in &snapshot[..count]
                {
                    // SAFETY: anc_ptr was set at chunk recording from a
                    // live FrameObject's header; the inc_ref then is
                    // matched by the dec_ref here.
                    let anc_hdr = unsafe { &*anc_ptr };
                    // Cast to FrameObject for retype_free; the ancestor
                    // is always a Frame (header at offset 0).
                    // cast_ptr_alignment: header at offset 0; FrameObject is repr(C).
                    #[allow(clippy::cast_ptr_alignment)]
                    // SAFETY: anc_ptr was set at chunk recording from a
                    // live FrameObject's header; refcount kept alive
                    // until the dec_ref below.
                    let anc_frame = unsafe { &*anc_ptr.cast::<FrameObject>() };
                    crate::cap::retype::retype_free(anc_frame, off, pages * p);
                    let new_rc = anc_hdr.dec_ref();
                    if new_rc == 0
                    {
                        // SAFETY: refcount reached 0; no live cap holds it.
                        let anc_nn = unsafe { NonNull::new_unchecked(anc_ptr) };
                        push_ancestor(worklist, head, anc_nn);
                    }
                }
            }

            // No separate `Box::from_raw(obj)` — the wrapper lives inside
            // the slab reclaimed above.
        }

        // ── CSpaceObj ─────────────────────────────────────────────────────
        //
        // All `CSpaceKernelObject`s are retype-backed: the root CSpace lands
        // in a slab from `SEED_FRAME` (Phase 7), and every userspace CSpace
        // lands in a slab from a Frame cap (`sys_cap_create_cspace`). Both
        // inline `CSpace` directly into the wrapper page; both record at
        // least one chunk slot covering the wrapper plus the slot-page pool.
        // Reclamation walks the chunk slots and `retype_free`s each one
        // wholesale, then `dec_ref`s the ancestor.
        ObjectType::CSpaceObj =>
        {
            // SAFETY: ptr points at an in-place CSpaceKernelObject; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<CSpaceKernelObject>()) };
            let cs_ptr = obj.cspace;

            debug_assert!(
                !obj.cs_chunks[0].ancestor.load(Ordering::Acquire).is_null(),
                "dealloc CSpaceObj: heap-backed CSpace reached typed-memory dealloc path"
            );

            if !cs_ptr.is_null()
            {
                // SAFETY: cs_ptr non-null; allocated at creation.
                let id = unsafe { (*cs_ptr).id() };
                crate::cap::unregister_cspace(id);

                // Dec-ref all objects referenced by non-null slots.
                // SAFETY: cs_ptr non-null; for_each_object handles iteration.
                unsafe {
                    (*cs_ptr).for_each_object(|obj_ptr| {
                        let hdr = obj_ptr.as_ref();
                        let rc = hdr.dec_ref();
                        if rc == 0
                        {
                            dealloc_object(obj_ptr);
                        }
                    });
                }

                // Drop the inline CSpace before reclaiming its storage; its
                // own `Drop` is a no-op for retype-backed (pool pages flow
                // back through the chunk reclaim below).
                // SAFETY: cs_ptr is about to be reclaimed; no outside
                // reference outlives the cap deletion that brought us here.
                unsafe {
                    core::ptr::drop_in_place(cs_ptr);
                }
            }

            // Snapshot every chunk slot before freeing — `retype_free`
            // touches the chunk pages (writing free-list links), and the
            // wrapper itself lives in the chunk being reclaimed.
            let mut snapshot: [(u64, u64, *mut KernelObjectHeader); MAX_PT_CHUNKS] =
                [(0, 0, core::ptr::null_mut()); MAX_PT_CHUNKS];
            let mut count = 0;
            for slot in &obj.cs_chunks
            {
                let anc = slot.ancestor.load(Ordering::Acquire);
                if anc.is_null()
                {
                    continue;
                }
                let off = slot.base_offset.load(Ordering::Relaxed);
                let pages = slot.page_count.load(Ordering::Relaxed);
                snapshot[count] = (off, pages, anc);
                count += 1;
            }
            let p = crate::mm::PAGE_SIZE as u64;
            for &(off, pages, anc_ptr) in &snapshot[..count]
            {
                // SAFETY: anc_ptr was set at chunk recording.
                let anc_hdr = unsafe { &*anc_ptr };
                // cast_ptr_alignment: header at offset 0; FrameObject repr(C).
                #[allow(clippy::cast_ptr_alignment)]
                // SAFETY: ancestor live until dec_ref below.
                let anc_frame = unsafe { &*anc_ptr.cast::<FrameObject>() };
                crate::cap::retype::retype_free(anc_frame, off, pages * p);
                let new_rc = anc_hdr.dec_ref();
                if new_rc == 0
                {
                    // SAFETY: refcount reached 0.
                    let anc_nn = unsafe { NonNull::new_unchecked(anc_ptr) };
                    push_ancestor(worklist, head, anc_nn);
                }
            }

            // No separate `Box::from_raw(obj)` — the wrapper lives inside
            // the slab reclaimed above.
        }

        // ── Endpoint ──────────────────────────────────────────────────────
        ObjectType::Endpoint =>
        {
            // Distinguish heap-allocated (legacy) Endpoints from retype-backed
            // ones by inspecting `header.ancestor`. Both share the same teardown
            // logic for blocked queues and wait-set linkage; only the final
            // memory-reclaim step differs.
            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);

            // SAFETY: ptr originally points to an EndpointObject; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<EndpointObject>()) };
            let state = obj.state;

            if !state.is_null()
            {
                // Unregister from wait set before freeing state.
                // SAFETY: state validated non-null; EndpointState allocated at creation.
                unsafe {
                    let ep = &mut *state;
                    if !ep.wait_set.is_null()
                    {
                        // cast_ptr_alignment: ep.wait_set stores a type-erased *mut WaitSetState;
                        // the original allocation guarantees the alignment.
                        #[allow(clippy::cast_ptr_alignment)]
                        let ws = ep.wait_set.cast::<crate::ipc::wait_set::WaitSetState>();
                        let _ = crate::ipc::wait_set::waitset_remove(ws, state.cast::<u8>());
                        ep.wait_set = core::ptr::null_mut();
                        ep.wait_set_member_idx = 0;
                    }
                }

                // Drain blocked senders and receivers with a zero return value.
                // They will wake up and resume from sys_ipc_call / sys_ipc_recv,
                // reading a zero-length message (effectively an ObjectGone hint).
                // TODO: set TrapFrame return to SyscallError::ObjectGone when
                // a proper per-thread wakeup error path is added.
                // SAFETY: state validated non-null; wake queue traversal under sched lock.
                unsafe {
                    let ep = &mut *state;
                    // Wake senders. enqueue_and_wake commits the state
                    // transitions under sched.lock; we only detach the
                    // intrusive list pointers here.
                    let mut tcb = ep.send_head;
                    while !tcb.is_null()
                    {
                        let next = (*tcb).ipc_wait_next;
                        (*tcb).ipc_wait_next = None;
                        let prio = (*tcb).priority;
                        let target_cpu = crate::sched::select_target_cpu(tcb);
                        crate::sched::enqueue_and_wake(tcb, target_cpu, prio);
                        tcb = next.unwrap_or(core::ptr::null_mut());
                    }
                    ep.send_head = core::ptr::null_mut();
                    ep.send_tail = core::ptr::null_mut();
                    // Wake receivers.
                    let mut tcb = ep.recv_head;
                    while !tcb.is_null()
                    {
                        let next = (*tcb).ipc_wait_next;
                        (*tcb).ipc_wait_next = None;
                        let prio = (*tcb).priority;
                        let target_cpu = crate::sched::select_target_cpu(tcb);
                        crate::sched::enqueue_and_wake(tcb, target_cpu, prio);
                        tcb = next.unwrap_or(core::ptr::null_mut());
                    }
                    ep.recv_head = core::ptr::null_mut();
                    ep.recv_tail = core::ptr::null_mut();
                }
            }

            debug_assert!(
                !ancestor_ptr.is_null(),
                "Endpoint: every production cap is retype-backed via cap_create_endpoint"
            );
            // Wrapper + state live in-place inside the ancestor Frame cap's
            // region. Drop in place, return the slot to the per-Frame
            // allocator, then dec_ref the ancestor — recursing if it hits zero.
            use crate::cap::retype::{dispatch_for, retype_free};
            // dispatch_for is total over the kernel's retypable types; the
            // Endpoint arm always returns Some. Unwrap-or-fall-through with
            // a fallback raw size keeps the lint quiet without panicking.
            let raw_bytes = dispatch_for(ObjectType::Endpoint, 0).map_or(88, |e| e.raw_bytes);

            // SAFETY: ancestor_ptr is non-null; it was set by `with_ancestor`
            // at retype time and points at the source FrameObject's header.
            // The retype primitive holds a +1 refcount on the FrameObject
            // for the lifetime of every retyped descendant, so the target
            // is still live.
            let ancestor_frame = unsafe { &*ancestor_ptr.cast::<FrameObject>() };

            let header_virt = ptr.as_ptr() as u64;
            let header_phys = crate::mm::paging::virt_to_phys(header_virt);
            let offset = header_phys - ancestor_frame.base;

            // Drop in place. EndpointObject and EndpointState contain only
            // primitive fields and Spinlock; no Drop impl, but the call is
            // explicit for clarity and to keep parity with future types
            // that may require it.
            if !state.is_null()
            {
                // SAFETY: state points into the ancestor Frame cap region;
                // refcount reached 0 so we are the unique accessor.
                unsafe { core::ptr::drop_in_place(state) };
            }
            // SAFETY: ptr is the in-place EndpointObject; unique access.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<EndpointObject>()) };

            // Return the bytes to the per-Frame allocator.
            retype_free(ancestor_frame, offset, raw_bytes);

            // Drop the retype-time refcount lease. If this Frame cap has no
            // remaining slots and no descendants, recurse to free the cap
            // itself; the recursion is bounded by ancestor depth.
            let ancestor_nn =
                // SAFETY: ancestor_ptr is non-null per debug_assert.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_frame.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: refcount reached 0; recursion handles the Frame
                // arm above (which frees the buddy pages and Box).
                push_ancestor(worklist, head, ancestor_nn);
            }
        }

        // ── Signal ────────────────────────────────────────────────────────
        ObjectType::Signal =>
        {
            // Branch on `header.ancestor`: heap-backed (legacy) vs retype-backed.
            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);

            // SAFETY: ptr originally points to a SignalObject; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<SignalObject>()) };
            let state = obj.state;

            if !state.is_null()
            {
                // Clear any IRQ routing table entries that point to this
                // SignalState. A hardware interrupt firing after the signal
                // is freed would otherwise call signal_send on a dead slot.
                // SAFETY: interrupts disabled to serialize with IRQ delivery.
                unsafe {
                    let saved = crate::arch::current::cpu::save_and_disable_interrupts();
                    crate::irq::unregister_signal(state);
                    crate::arch::current::cpu::restore_interrupts(saved);
                }

                // Unregister from wait set BEFORE freeing state. If registered
                // with a wait set, the wait set's member array still holds a
                // source_ptr to this SignalState; failing to remove it causes
                // wait_set_drop to write to freed memory.
                // SAFETY: state validated non-null; SignalState live.
                unsafe {
                    let sig = &mut *state;
                    if !sig.wait_set.is_null()
                    {
                        #[allow(clippy::cast_ptr_alignment)]
                        let ws = sig.wait_set.cast::<crate::ipc::wait_set::WaitSetState>();
                        let _ = crate::ipc::wait_set::waitset_remove(ws, state.cast::<u8>());
                        sig.wait_set = core::ptr::null_mut();
                        sig.wait_set_member_idx = 0;
                    }
                }

                // Wake a blocked waiter with wakeup_value = 0.
                // TODO: return SyscallError::ObjectGone when a proper wakeup
                // error path is available in sys_signal_wait.
                // SAFETY: state validated non-null; waiter TCB still valid.
                unsafe {
                    let sig = &mut *state;
                    let waiter = sig.waiter;
                    if !waiter.is_null()
                    {
                        sig.waiter = core::ptr::null_mut();
                        // wakeup_value=0 = drop semantics; state transitions
                        // committed by enqueue_and_wake.
                        (*waiter).wakeup_value = 0;
                        let prio = (*waiter).priority;
                        let target_cpu = crate::sched::select_target_cpu(waiter);
                        crate::sched::enqueue_and_wake(waiter, target_cpu, prio);
                    }
                }
            }

            debug_assert!(
                !ancestor_ptr.is_null(),
                "Signal: every production cap is retype-backed via cap_create_signal"
            );
            // Wrapper + state are in-place inside the ancestor Frame cap's
            // region.
            use crate::cap::retype::{dispatch_for, retype_free};
            let raw_bytes = dispatch_for(ObjectType::Signal, 0).map_or(120, |e| e.raw_bytes);

            // SAFETY: ancestor_ptr is non-null per debug_assert; the
            // FrameObject is kept alive by the retype-time refcount lease.
            let ancestor_frame = unsafe { &*ancestor_ptr.cast::<FrameObject>() };

            let header_virt = ptr.as_ptr() as u64;
            let header_phys = crate::mm::paging::virt_to_phys(header_virt);
            let offset = header_phys - ancestor_frame.base;

            if !state.is_null()
            {
                // SAFETY: state lives in-place inside the ancestor Frame
                // cap; refcount reached 0 — unique accessor.
                unsafe { core::ptr::drop_in_place(state) };
            }
            // SAFETY: ptr is the in-place SignalObject; unique access.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<SignalObject>()) };

            retype_free(ancestor_frame, offset, raw_bytes);

            // Drop the retype-time refcount lease; recurse on full release.
            let ancestor_nn =
                // SAFETY: ancestor_ptr non-null.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_frame.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: refcount reached 0; recurse to free the Frame.
                push_ancestor(worklist, head, ancestor_nn);
            }
        }

        // ── EventQueue ────────────────────────────────────────────────────
        ObjectType::EventQueue =>
        {
            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);

            // SAFETY: ptr points to an EventQueueObject; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<EventQueueObject>()) };
            let state = obj.state;

            // Read the capacity before any drop; it determines how many
            // bytes belong to the slot (wrapper + state + inline ring).
            let capacity = if state.is_null()
            {
                0u32
            }
            else
            {
                // SAFETY: state non-null; EventQueueState live.
                unsafe { (*state).capacity }
            };

            if !state.is_null()
            {
                // Unregister from wait set before freeing state.
                // SAFETY: state non-null; EventQueueState live.
                unsafe {
                    let eq = &mut *state;
                    if !eq.wait_set.is_null()
                    {
                        #[allow(clippy::cast_ptr_alignment)]
                        let ws = eq.wait_set.cast::<crate::ipc::wait_set::WaitSetState>();
                        let _ = crate::ipc::wait_set::waitset_remove(ws, state.cast::<u8>());
                        eq.wait_set = core::ptr::null_mut();
                        eq.wait_set_member_idx = 0;
                    }
                }

                // Wake any blocked waiter with `ObjectGone`. The inline
                // ring is part of this slot and gets reclaimed below
                // alongside the wrapper + state via `retype_free`.
                // SAFETY: state non-null and live.
                unsafe { crate::ipc::event_queue::event_queue_drop(state) };
            }

            debug_assert!(
                !ancestor_ptr.is_null(),
                "EventQueue: every production cap is retype-backed via cap_create_event_queue"
            );
            use crate::cap::retype::{event_queue_raw_bytes, retype_free};
            let raw_bytes = event_queue_raw_bytes(u64::from(capacity));
            // SAFETY: ancestor_ptr non-null.
            let ancestor_frame = unsafe { &*ancestor_ptr.cast::<FrameObject>() };
            let header_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let offset = header_phys - ancestor_frame.base;

            if !state.is_null()
            {
                // SAFETY: state lives in-place; refcount reached 0.
                unsafe { core::ptr::drop_in_place(state) };
            }
            // SAFETY: ptr is in-place EventQueueObject.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<EventQueueObject>()) };

            retype_free(ancestor_frame, offset, raw_bytes);

            let ancestor_nn =
                // SAFETY: ancestor_ptr non-null.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_frame.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: refcount reached 0.
                push_ancestor(worklist, head, ancestor_nn);
            }
        }

        // ── WaitSet ───────────────────────────────────────────────────────
        ObjectType::WaitSet =>
        {
            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);

            // SAFETY: ptr points to a WaitSetObject; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<WaitSetObject>()) };
            let state = obj.state;

            if !state.is_null()
            {
                // wait_set_drop wakes any blocked waiter and clears every
                // source back-pointer. It does NOT free the state Box itself.
                // SAFETY: state non-null and live.
                unsafe { crate::ipc::wait_set::wait_set_drop(state) };
            }

            debug_assert!(
                !ancestor_ptr.is_null(),
                "WaitSet: every production cap is retype-backed via cap_create_wait_set"
            );
            use crate::cap::retype::{dispatch_for, retype_free};
            let raw_bytes = dispatch_for(ObjectType::WaitSet, 0)
                .map_or(crate::mm::PAGE_SIZE as u64, |e| e.raw_bytes);
            // SAFETY: ancestor_ptr non-null.
            let ancestor_frame = unsafe { &*ancestor_ptr.cast::<FrameObject>() };
            let header_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let offset = header_phys - ancestor_frame.base;

            if !state.is_null()
            {
                // SAFETY: state lives in-place.
                unsafe { core::ptr::drop_in_place(state) };
            }
            // SAFETY: ptr is in-place WaitSetObject.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<WaitSetObject>()) };

            retype_free(ancestor_frame, offset, raw_bytes);

            let ancestor_nn =
                // SAFETY: ancestor_ptr non-null.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_frame.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: refcount reached 0.
                push_ancestor(worklist, head, ancestor_nn);
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use core::mem::{offset_of, size_of};

    // Verify header is at offset 0 in each concrete type — required for safe
    // pointer casts from *mut ConcreteObject to *mut KernelObjectHeader.
    #[test]
    fn frame_object_header_at_offset_zero()
    {
        assert_eq!(offset_of!(FrameObject, header), 0);
    }

    #[test]
    fn mmio_object_header_at_offset_zero()
    {
        assert_eq!(offset_of!(MmioRegionObject, header), 0);
    }

    #[test]
    fn interrupt_object_header_at_offset_zero()
    {
        assert_eq!(offset_of!(InterruptObject, header), 0);
    }

    #[test]
    fn ioport_object_header_at_offset_zero()
    {
        assert_eq!(offset_of!(IoPortRangeObject, header), 0);
    }

    #[test]
    fn sched_control_object_header_at_offset_zero()
    {
        assert_eq!(offset_of!(SchedControlObject, header), 0);
    }

    #[test]
    fn struct_sizes()
    {
        // Header: 4 ref_count + 1 obj_type + 3 pad + 8 ancestor (Option<SlotId>
        // via NonZeroU32 niche) = 16 bytes, alignment 4.
        assert_eq!(size_of::<KernelObjectHeader>(), 16);
        // FrameObject: 16 header + 8 base + 8 size + 8 available_bytes +
        // 1 owns_memory + 7 pad + 40 inline allocator + 4 lock + 4 pad = 96 bytes.
        assert_eq!(size_of::<FrameObject>(), 96);
        // MmioRegionObject: 16 header + 8 base + 8 size + 4 flags + 4 pad = 40.
        assert_eq!(size_of::<MmioRegionObject>(), 40);
        // InterruptObject: 16 header + 4 start + 4 count = 24.
        assert_eq!(size_of::<InterruptObject>(), 24);
        // IoPortRangeObject: 16 header + 2 base + 2 size + 4 pad = 24.
        assert_eq!(size_of::<IoPortRangeObject>(), 24);
        // Wrapper objects: 16 header + 8 ptr = 24.
        assert_eq!(size_of::<SchedControlObject>(), 16);
        assert_eq!(size_of::<SbiControlObject>(), 16);
        assert_eq!(size_of::<ThreadObject>(), 24);
        assert_eq!(size_of::<EndpointObject>(), 24);
        assert_eq!(size_of::<SignalObject>(), 24);
        assert_eq!(size_of::<EventQueueObject>(), 24);
        assert_eq!(size_of::<WaitSetObject>(), 24);
        // PoolChunkSlot: 8 ancestor + 8 base_offset + 8 page_count = 24 B.
        assert_eq!(size_of::<PoolChunkSlot>(), 24);
        // AddressSpaceObject: 16 header + 8 ptr + 8 budget + 8 lock + 8 head
        // + 16 * 24 chunks = 432 B.
        assert_eq!(size_of::<AddressSpaceObject>(), 48 + 24 * MAX_PT_CHUNKS);
        // CSpaceKernelObject: same shape.
        assert_eq!(size_of::<CSpaceKernelObject>(), 48 + 24 * MAX_PT_CHUNKS);
    }

    #[test]
    fn header_ref_count_lifecycle()
    {
        let h = KernelObjectHeader::new(ObjectType::Frame);
        assert_eq!(h.ref_count.load(core::sync::atomic::Ordering::Relaxed), 1);
        h.inc_ref();
        assert_eq!(h.ref_count.load(core::sync::atomic::Ordering::Relaxed), 2);
        let after_dec = h.dec_ref();
        assert_eq!(after_dec, 1);
        let after_dec2 = h.dec_ref();
        assert_eq!(after_dec2, 0);
    }

    #[test]
    fn header_ancestor_default_null()
    {
        let h = KernelObjectHeader::new(ObjectType::Endpoint);
        assert!(
            h.ancestor
                .load(core::sync::atomic::Ordering::Relaxed)
                .is_null()
        );
    }

    #[test]
    fn header_with_ancestor_records_pointer()
    {
        // Use a leaked Box as a stable target — the test only checks pointer
        // equality, not that the target is a live FrameObject.
        let target = Box::into_raw(Box::new(KernelObjectHeader::new(ObjectType::Frame)));
        let nn = unsafe { NonNull::new_unchecked(target) };
        let h = KernelObjectHeader::with_ancestor(ObjectType::Endpoint, nn);
        assert_eq!(
            h.ancestor.load(core::sync::atomic::Ordering::Relaxed),
            target
        );
        // SAFETY: target is the leaked Box from above; reclaim it.
        unsafe { drop(Box::from_raw(target)) };
    }
}
