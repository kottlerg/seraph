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
//! Most kernel objects are *retyped* from a Memory capability with the
//! `Retype` right: the kernel allocates a sub-region inside the Memory cap's
//! backing memory via [`crate::cap::retype::retype_allocate`], constructs
//! the object in place at the returned offset, and stores the source
//! `MemoryObject`'s header pointer in `header.ancestor` so dealloc can
//! reclaim the bytes back to the source cap. Init's bootstrap state
//! (root `CSpace`, init's own `AddressSpace`/`Thread`/`CSpace`) and the
//! Phase-7 boot-time identity wrappers remain heap-allocated for now;
//! they have `header.ancestor == null` and dealloc through the legacy
//! `Box::from_raw` path.
//!
//! Deallocation: read `header.obj_type` from the raw pointer; if
//! `header.ancestor` is null, drop the originating `Box<ConcreteObject>`;
//! otherwise drop the object in place and call `retype_free` against
//! the ancestor `MemoryObject`.
//!
//! ## Sizes (verified by tests below)
//!
//! | Type                | Size  |
//! |---------------------|-------|
//! | KernelObjectHeader  | 16 B  |
//! | MemoryObject         | 64 B  |
//! | MmioObject    | 40 B  |
//! | InterruptObject     | 24 B  |
//! | IoPortObject   | 24 B  |
//! | SchedControlObject  | 24 B  |
//! | SbiControlObject    | 16 B  |
//! | ThreadObject        | 24 B  |
//! | AddressSpaceObject  | 432 B |
//! | CSpaceKernelObject  | 432 B |
//! | EndpointObject      | 24 B  |
//! | NotificationObject        | 24 B  |
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
    Memory = 0,
    Mmio = 1,
    Interrupt = 2,
    IoPort = 3,
    SchedControl = 4,
    Thread = 5,
    AddressSpace = 6,
    CSpaceObj = 7,
    Endpoint = 8,
    Notification = 9,
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
/// `ancestor` is a direct pointer to the `MemoryObject`'s header from which
/// this object was retyped, or null if heap-allocated (legacy path).
/// Auto-reclaim consults this on `dec_ref → 0` to credit bytes back to the
/// source `MemoryObject` and return the chunk to the per-Memory-cap allocator.
///
/// A direct pointer (rather than a `SlotId`) is necessary because the source
/// Memory cap's *slot* may be deleted before all retyped descendants are freed
/// — the `MemoryObject` itself stays alive via the refcount bump that retype
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
    /// Lifecycle flags. See `HDR_FLAG_*` constants. Currently only used to
    /// mark the boot root `CSpace` as undestroyable.
    pub flags: u8,
    // Padding to reach 8-byte alignment for the ancestor pointer below.
    #[allow(clippy::pub_underscore_fields)]
    pub _pad: [u8; 2],
    /// Pointer to the `MemoryObject`'s header this object was retyped from,
    /// or null if allocated via the legacy heap path. Set once at creation,
    /// read at deallocation. `AtomicPtr` for the unforgeable null sentinel
    /// without imposing const-init constraints on construction.
    pub ancestor: AtomicPtr<KernelObjectHeader>,
}

/// `flags` bit: this header belongs to the boot root `CSpace` and MUST NOT
/// be deallocated. `dec_ref` intercepts the `→ 0` transition for these
/// headers and returns 1, keeping the object alive regardless of upstream
/// refcount mismanagement. Stamped in
/// [`crate::cap::boot_retype_cspace`] for the root `CSpace`; never set
/// elsewhere.
pub const HDR_FLAG_IS_ROOT: u8 = 0x01;

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
    /// [`Self::with_ancestor`] to record the source `MemoryObject` for
    /// auto-reclaim.
    pub fn new(obj_type: ObjectType) -> Self
    {
        Self {
            ref_count: AtomicU32::new(1),
            obj_type,
            flags: 0,
            _pad: [0; 2],
            ancestor: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Construct a new header tagged with the `MemoryObject` it was retyped
    /// from.
    ///
    /// Used by the retype primitive. On `dec_ref → 0`, auto-reclaim consults
    /// this pointer to credit bytes back.
    pub fn with_ancestor(obj_type: ObjectType, ancestor: NonNull<KernelObjectHeader>) -> Self
    {
        Self {
            ref_count: AtomicU32::new(1),
            obj_type,
            flags: 0,
            _pad: [0; 2],
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
    ///
    /// Headers carrying [`HDR_FLAG_IS_ROOT`] (the boot root `CSpace`) clamp
    /// at 1 via a CAS loop: when the current count is 1 the operation is a
    /// no-op (returns 1); otherwise it decrements by one. The CAS form
    /// avoids the fetch_sub-then-restore window in which a concurrent dec
    /// would see 0 and underflow. The root `CSpace` lives for kernel
    /// lifetime and never reaches `dealloc_object`, even if upstream
    /// refcount accounting mismanages the ancillary slot/wrapper pair.
    pub fn dec_ref(&self) -> u32
    {
        if (self.flags & HDR_FLAG_IS_ROOT) != 0
        {
            // Root path: CAS the floor in atomically so concurrent decs
            // cannot observe a transient 0.
            let mut cur = self.ref_count.load(Ordering::Relaxed);
            loop
            {
                debug_assert!(
                    cur != 0,
                    "dec_ref underflow on IS_ROOT header: obj_type={:?} self={:p}",
                    self.obj_type,
                    self,
                );
                let new = if cur == 1 { 1 } else { cur - 1 };
                match self.ref_count.compare_exchange_weak(
                    cur,
                    new,
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                {
                    Ok(_) => return new,
                    Err(actual) => cur = actual,
                }
            }
        }

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

/// Kernel object for a contiguous physical memory range (Memory capability).
///
/// Invariant: `base` MUST be 4 KiB-aligned and `size` MUST be a positive
/// multiple of `PAGE_SIZE`. `sys_mem_map` (`syscall::mem`) feeds
/// `base + offset` directly into `PageTableEntry::new_page`, which
/// `debug_assert!`s page alignment. `sys_memory_split` preserves the invariant
/// because `split_offset` is validated page-aligned before the tail's
/// `base = parent.base + split_offset` is computed. Producers minting a cap
/// from an external `physical_base` MUST mask down to a page boundary and
/// ceiling-round `size` to whole pages.
#[repr(C)]
pub struct MemoryObject
{
    pub header: KernelObjectHeader,
    /// Physical base address of the region. 4 KiB-aligned.
    pub base: u64,
    /// Size of the region in bytes; multiple of `PAGE_SIZE`. Mutable:
    /// `sys_memory_split` shrinks it as a tail child is carved off;
    /// `sys_memory_merge` grows it as a tail child is absorbed back.
    /// Mutations require `lock` in write mode; reads (`sys_mem_map`,
    /// `retype_allocate`) require `lock` in read mode.
    pub size: u64,
    /// Bytes still available to retype into kernel objects, or to map.
    ///
    /// Initialised to `size` for RAM caps minted at boot with `Rights::RETYPE`.
    /// Set to `0` for firmware-table / boot-module / init-segment Memory caps
    /// (those caps don't carry RETYPE rights and never participate in retype
    /// or auto-reclaim — their `available_bytes` is informational only).
    /// `retype_allocate` debits this; `dealloc_object` auto-reclaim credits
    /// it back.
    pub available_bytes: AtomicU64,
    /// `true` if this Memory cap is responsible for returning `[base, base + size)`
    /// to the buddy allocator on final destruction. Buddy-backed Memory caps set
    /// this at creation. Caps over non-buddy-managed physical memory (MMIO
    /// regions, firmware tables, boot modules, boot-loaded ELF segments)
    /// leave it `false`.
    ///
    /// `sys_memory_split` (Option D) leaves the parent's flag intact; the new
    /// tail child inherits the parent's `owns_memory` so each half buddy-frees
    /// its own `[base, base+size)` range on dealloc. `sys_memory_merge`
    /// clears the absorbed tail's flag (so only the parent — which now
    /// covers the merged range — buddy-frees on its eventual dealloc).
    pub owns_memory: AtomicBool,
    /// Per-Memory-cap retype allocator. Stored inline in kernel-owned memory
    /// so userspace `sys_mem_map` writes against the cap's region cannot
    /// corrupt the metadata. Zero-initialised: `bump_offset = 0` and every
    /// free-list head = `FREE_LIST_END` give a fresh cap with all bytes
    /// available.
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
    /// `sys_memory_split` and `sys_memory_merge` while the cap's region is
    /// mutated. Lock order against `DERIVATION_LOCK`: derivation-lock outer,
    /// frame-lock inner.
    pub lock: AtomicU32,
}

/// Sentinel encoding a held write lock in [`MemoryObject::lock`]. Matches
/// `DerivationLock`'s convention.
#[allow(dead_code)]
const FRAME_WRITE_LOCKED: u32 = u32::MAX;

#[allow(dead_code)]
impl MemoryObject
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

/// RAII guard releasing a read lock on a [`MemoryObject`] when dropped.
///
/// Used by `sys_mem_map` and `cap::retype::retype_allocate` to ensure the
/// read lock is released on every return path, including `?` short-circuits.
pub struct MemoryReadGuard<'a>
{
    memory: &'a MemoryObject,
}

impl<'a> MemoryReadGuard<'a>
{
    /// Acquire `memory`'s read lock and return the guard. The lock is
    /// released when the guard is dropped.
    pub fn acquire(memory: &'a MemoryObject) -> Self
    {
        memory.read_lock();
        Self { memory }
    }
}

impl Drop for MemoryReadGuard<'_>
{
    fn drop(&mut self)
    {
        self.memory.read_unlock();
    }
}

/// Kernel object for a memory-mapped I/O region (`Mmio` capability).
#[repr(C)]
pub struct MmioObject
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

/// Kernel object for an x86-64 I/O port range (`IoPort` capability).
#[repr(C)]
pub struct IoPortObject
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
/// Carries the priority band `[min, max]` the cap authorises. Holding a
/// `SchedControl` cap whose band covers a level is the authority to assign that
/// level via `SYS_THREAD_SET_PRIORITY`. The root cap (spanning the full
/// userspace range) is minted at boot; narrower bands are produced by
/// `SYS_SCHED_SPLIT`.
#[repr(C)]
pub struct SchedControlObject
{
    pub header: KernelObjectHeader,
    /// Lowest priority level this cap authorises (inclusive).
    pub min: u8,
    /// Highest priority level this cap authorises (inclusive).
    pub max: u8,
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
/// Each augment-mode call (`cap_create_aspace(memory, target)` /
/// `cap_create_cspace(memory, target)`) consumes one slot. The original
/// create-time chunk also occupies one slot. Sixteen is enough to absorb
/// many augment events without bloating the wrapper struct.
pub const MAX_PT_CHUNKS: usize = 16;

/// Per-chunk record of a retype-allocated multi-page region donated to an
/// `AddressSpaceObject`'s PT pool or a `CSpaceKernelObject`'s slot-page
/// pool.
///
/// At dealloc, every non-vacant slot is fed back to its `ancestor`
/// `MemoryObject` via `retype_free`, then the ancestor is `dec_ref`'d.
#[repr(C)]
pub struct PoolChunkSlot
{
    /// `MemoryObject` ancestor this chunk was carved from. Null = vacant.
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
    /// Seeded at retype time from the source Memory cap's `available_bytes`.
    /// Refilled via augment-mode on `SYS_CAP_CREATE_ASPACE`
    /// (`cap_create_aspace(memory_cap, target_aspace_cap)`). `mem_map` returns
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
    /// Seeded at retype time from the source Memory cap's `available_bytes`.
    /// Refilled via augment-mode on `SYS_CAP_CREATE_CSPACE`
    /// (`cap_create_cspace(memory_cap, target_cspace_cap)`).
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
    /// `ancestor` must be a live `MemoryObject`'s header; this call must
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
        ancestor_memory_base: u64,
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
            let page_phys = ancestor_memory_base + base_offset + i * p;
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
        ancestor_memory_base: u64,
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
            let page_phys = ancestor_memory_base + base_offset + i * p;
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

/// Kernel object for a notification (Notification capability).
#[repr(C)]
pub struct NotificationObject
{
    pub header: KernelObjectHeader,
    /// Pointer to the notification's mutable state. Inline for retype-backed
    /// Notifications, separately heap-allocated for legacy Notifications; discriminated
    /// by `header.ancestor`.
    pub state: *mut crate::ipc::notification::NotificationState,
}

// SAFETY: NotificationObject is accessed only under the scheduler lock.
unsafe impl Send for NotificationObject {}
// SAFETY: NotificationObject is accessed only under the scheduler lock.
unsafe impl Sync for NotificationObject {}

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
/// `MemoryObject` and decrement the ancestor's refcount. If the ancestor's
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
    /// (memmgr-memory → child-bootstrap split → kernel object) sit at depth
    /// `<= 4`; the `WaitSet` arm can additionally fan out to
    /// `WAIT_SET_MAX_MEMBERS` (= 16) source headers in one pop when their
    /// final +1 cap-level ref came from wait-set membership, so headroom is
    /// sized to absorb the fan-out plus the wait-set's own ancestor Memory cap.
    /// Thirty-two entries fit comfortably on the kernel stack (256 B).
    const MAX_CASCADE: usize = 32;

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
/// the ancestor (`dec_ref` returns 0 against the source `MemoryObject`),
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
        ObjectType::Memory =>
        {
            // Return buddy-backed physical memory before freeing the Rust
            // object. `owns_memory` is false for MMIO / firmware / boot
            // module / init-segment caps (the physical memory is not part
            // of the buddy pool at all) and for split originals (ownership
            // was atomically transferred to the children). This is the buddy's
            // only reverse path; post-handoff the buddy is sealed (every
            // `owns_memory` cap lives permanently in memmgr's pool), so a live
            // free here trips the seal — see `buddy::free_range`.
            // SAFETY: ptr points to a live MemoryObject; single-owner access
            // since refcount reached zero at the call site.
            let (base, size, owned) = unsafe {
                let obj = &*ptr.as_ptr().cast::<MemoryObject>();
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
                "Memory: every production cap is retype-backed (Phase-7 SEED, sys_memory_split SEED)"
            );
            // Retype-backed body lives inside the ancestor (the seed
            // Memory cap). Drop in place, return the body bytes to the
            // seed's per-Memory allocator, drop the retype-time lease.
            use crate::cap::retype::retype_free;
            // SAFETY: ancestor_ptr non-null per debug_assert and 4b invariant.
            let ancestor_memory = unsafe { &*ancestor_ptr.cast::<MemoryObject>() };
            let body_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let offset = body_phys - ancestor_memory.base;
            // SAFETY: ptr is the in-place MemoryObject; refcount 0 — unique access.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<MemoryObject>()) };
            retype_free(
                ancestor_memory,
                offset,
                core::mem::size_of::<MemoryObject>() as u64,
            );
            let new_rc = ancestor_memory.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: ancestor_ptr non-null.
                let ancestor_nn = unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
                push_ancestor(worklist, head, ancestor_nn);
            }
        }
        ObjectType::Mmio =>
        {
            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);
            debug_assert!(
                !ancestor_ptr.is_null(),
                "Mmio: every production cap is retype-backed (Phase-7 SEED, sys_mmio_split SEED)"
            );
            use crate::cap::retype::retype_free;
            // SAFETY: ancestor_ptr non-null per debug_assert and 4b invariant.
            let ancestor_memory = unsafe { &*ancestor_ptr.cast::<MemoryObject>() };
            let body_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let offset = body_phys - ancestor_memory.base;
            // SAFETY: in-place body; refcount 0 — unique access.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<MmioObject>()) };
            retype_free(
                ancestor_memory,
                offset,
                core::mem::size_of::<MmioObject>() as u64,
            );
            let new_rc = ancestor_memory.header.dec_ref();
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

            // Only single-IRQ caps ever register a notification with the routing
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
            let ancestor_memory = unsafe { &*ancestor_ptr.cast::<MemoryObject>() };
            let body_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let offset = body_phys - ancestor_memory.base;
            // SAFETY: in-place body; refcount 0 — unique access.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<InterruptObject>()) };
            retype_free(
                ancestor_memory,
                offset,
                core::mem::size_of::<InterruptObject>() as u64,
            );
            let new_rc = ancestor_memory.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: ancestor_ptr non-null.
                let ancestor_nn = unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
                push_ancestor(worklist, head, ancestor_nn);
            }
        }
        ObjectType::IoPort =>
        {
            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);
            debug_assert!(
                !ancestor_ptr.is_null(),
                "IoPort: every production cap is retype-backed (Phase-7 SEED)"
            );
            use crate::cap::retype::retype_free;
            // SAFETY: ancestor_ptr non-null per 4b invariant.
            let ancestor_memory = unsafe { &*ancestor_ptr.cast::<MemoryObject>() };
            let body_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let offset = body_phys - ancestor_memory.base;
            // SAFETY: in-place body; refcount 0 — unique access.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<IoPortObject>()) };
            retype_free(
                ancestor_memory,
                offset,
                core::mem::size_of::<IoPortObject>() as u64,
            );
            let new_rc = ancestor_memory.header.dec_ref();
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
            let ancestor_memory = unsafe { &*ancestor_ptr.cast::<MemoryObject>() };
            let body_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let offset = body_phys - ancestor_memory.base;
            // SAFETY: in-place body; refcount 0 — unique access.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<SchedControlObject>()) };
            retype_free(
                ancestor_memory,
                offset,
                core::mem::size_of::<SchedControlObject>() as u64,
            );
            let new_rc = ancestor_memory.header.dec_ref();
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
            let ancestor_memory = unsafe { &*ancestor_ptr.cast::<MemoryObject>() };
            let body_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let offset = body_phys - ancestor_memory.base;
            // SAFETY: in-place body; refcount 0 — unique access.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<SbiControlObject>()) };
            retype_free(
                ancestor_memory,
                offset,
                core::mem::size_of::<SbiControlObject>() as u64,
            );
            let new_rc = ancestor_memory.header.dec_ref();
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
                    usize,
                )>;
                // needless_range_loop: explicit indexing reads clearer for the
                // parallel scheduler_for(cpu) accesses across all CPUs.
                #[allow(clippy::needless_range_loop)]
                // SAFETY: tcb validated non-null; all scheduler locks are acquired in
                // ascending order to prevent deadlock; lock_raw paired with unlock_raw.
                unsafe {
                    use crate::sched::thread::ThreadState;
                    let cpu_count = crate::sched::CPU_COUNT
                        .load(core::sync::atomic::Ordering::Relaxed)
                        as usize;

                    // Acquire (*tcb).sched_lock FIRST (outermost) so the Exited
                    // write serialises with schedule()'s dispatch flip and
                    // enqueue_and_wake/commit on the SAME per-TCB lock (STEP 4/5
                    // data-race fix). Released right after the CPU locks below,
                    // BEFORE the UAF gate (which re-enables interrupts and where a
                    // CPU switching away from `tcb` needs tcb.sched_lock). Order
                    // tcb.sched_lock → CPU locks matches schedule(), so no ABBA.
                    let tcb_sched_saved = (*tcb).sched_lock.lock_raw();

                    // Acquire all scheduler locks in ascending CPU order to
                    // prevent ABBA deadlock. Each CPU's saved interrupt-flag
                    // word is stashed in its own scheduler (under that lock).
                    for cpu in 0..cpu_count
                    {
                        let s = crate::sched::scheduler_for(cpu);
                        s.saved_lock_flags = s.lock.lock_raw();
                    }

                    // Read priority inside the all-locks region.
                    // `sys_thread_set_priority`, `set_state_under_all_locks`,
                    // and this dealloc all observe the same all-CPU-locks
                    // discipline for the Scheduling field group.
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
                            // Distinguish a fault-blocked client (handler death
                            // cancels its in-flight fault → Kill on resume in the
                            // fault helper) from a syscall caller (returns
                            // Interrupted). Read the state before clearing it.
                            let was_fault = (*bound).ipc_state
                                == crate::sched::thread::IpcThreadState::BlockedOnFault;
                            (*bound).blocked_on_object = core::ptr::null_mut();
                            (*bound).ipc_state = crate::sched::thread::IpcThreadState::None;
                            (*bound).state = ThreadState::Ready;
                            if was_fault
                            {
                                (*bound).fault_outcome.store(
                                    crate::ipc::fault::FAULT_OUTCOME_KILL,
                                    Ordering::Release,
                                );
                            }
                            else
                            {
                                let trap_frame = (*bound).trap_frame;
                                if !trap_frame.is_null()
                                {
                                    (*trap_frame)
                                        .set_return(syscall::SyscallError::Interrupted as i64);
                                }
                            }
                            let bcpu = crate::sched::select_target_cpu(bound);
                            Some((bound, bcpu))
                        }
                        else
                        {
                            // Concurrent cancel beat us.
                            None
                        }
                    };

                    // Release all CPU locks, then (*tcb).sched_lock last — BEFORE
                    // the UAF gate, which spins with interrupts ENABLED (holding
                    // an IRQ-disabling sched_lock across it would be inconsistent,
                    // and a CPU switching away from `tcb` must be able to take
                    // tcb.sched_lock).
                    for cpu in (0..cpu_count).rev()
                    {
                        let s = crate::sched::scheduler_for(cpu);
                        s.lock.unlock_raw(s.saved_lock_flags);
                    }
                    (*tcb).sched_lock.unlock_raw(tcb_sched_saved);

                    // UAF gate: a TCB that is `current` on any CPU MUST NOT be
                    // reclaimed until every CPU has switched away from it AND
                    // the in-flight register save has published. Two steps:
                    //
                    //   1. Spin until `tcb` is not `current` on ANY CPU —
                    //      unconditional, across every CPU. A single-CPU wait
                    //      keyed on one all-locks snapshot would be insufficient:
                    //      such a snapshot names at most one CPU and can be stale
                    //      the instant the locks drop (a CPU mid-`schedule()` may
                    //      install or retain `tcb` as `current` after it was
                    //      taken). #207.
                    //   2. Spin until `context_saved == 1`, covering the window
                    //      where a CPU set `current = next` and dropped its lock
                    //      but `switch()` has not yet saved `tcb`'s registers.
                    //
                    // The spins run with interrupts ENABLED and preemption
                    // DISABLED, mirroring `mm::tlb_shootdown::shootdown`. We
                    // enter dealloc from a syscall with `IF=0`; spinning here
                    // with `IF=0` blocks incoming IPIs (FPU flush, TLB
                    // shootdown) targeted at this CPU and deadlocks them.
                    // Enabling IF lets us service those, while `preempt_disable`
                    // keeps the scheduler from migrating us mid-dealloc.
                    crate::percpu::preempt_disable();
                    // SAFETY: ring 0; saved in matching restore below.
                    let saved_int = crate::arch::current::cpu::save_and_disable_interrupts();
                    // SAFETY: ring 0; IDT loaded; preempt disabled.
                    crate::arch::current::interrupts::enable();

                    // Step 1: not `current` on any CPU. Find the (at most one)
                    // CPU still running `tcb`, spin on just that CPU's lock
                    // until it switches away, then re-scan; once a full scan is
                    // clean, no CPU can re-install `tcb` (it is `Exited` and
                    // unlinked from every run queue under the all-locks region).
                    loop
                    {
                        let run_cpu = 'scan: {
                            for cpu in 0..cpu_count
                            {
                                let s = crate::sched::scheduler_for(cpu);
                                let f = s.lock.lock_raw();
                                let is_cur = s.current == tcb;
                                s.lock.unlock_raw(f);
                                if is_cur
                                {
                                    break 'scan Some(cpu);
                                }
                            }
                            None
                        };
                        let Some(run_cpu) = run_cpu
                        else
                        {
                            break;
                        };
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

                    // Step 2: register save published.
                    while (*tcb)
                        .context_saved
                        .load(core::sync::atomic::Ordering::Acquire)
                        == 0
                    {
                        core::hint::spin_loop();
                    }

                    // Restore the caller's interrupt state and preemption.
                    // SAFETY: saved_int from save_and_disable_interrupts above.
                    crate::arch::current::cpu::restore_interrupts(saved_int);
                    crate::percpu::preempt_enable();

                    // After eager FPU save (#108), no fpu_owner sweep is
                    // needed: `nm_handler` only ever names the currently
                    // Running thread on its CPU, and `switch_out_save`
                    // clears the slot on switch-out — so by the time the
                    // not-`current`-anywhere and `context_saved` spins above
                    // have completed, no CPU's owner slot can name this TCB.
                }

                // Wake the captured reply-bound client outside the all-locks
                // region (enqueue_and_wake takes a scheduler.lock).
                if let Some((bound, bcpu)) = server_reply_wake
                {
                    // SAFETY: bound prepared (state=Ready, return value/outcome
                    // set) under all-CPU locks above; enqueue_ready_thread links
                    // it — the gated enqueue_and_wake would coalesce the now-Ready
                    // thread and the orphaned client would hang.
                    unsafe { crate::sched::enqueue_ready_thread(bound, bcpu) };
                }

                // Unlink this thread from any IPC object it's blocked on.
                // Without this, a notification/endpoint/event_queue retains a
                // dangling waiter pointer to the freed TCB. A subsequent
                // notification_send would return that pointer, and the caller
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
                            IpcThreadState::BlockedOnNotification =>
                            {
                                let sig = blocked_obj
                                    .cast::<crate::ipc::notification::NotificationState>();
                                // SAFETY: sig is valid; lock serialises with notification_send.
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
                                // Republish send-queue level (#285-adjacent):
                                // this unlink can empty the queue, and the
                                // wait-set self-heal reads the shadow locklessly.
                                ep.refresh_send_ready();
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
                                // The Acquire-load of reply_tcb synchronises
                                // with endpoint_call/recv's Release publication
                                // of the binding, so the `wake_in_flight = 1`
                                // they stored before it is visible here. If we
                                // win the CAS we cancelled the reply wake — clear
                                // the flag so the gate below does not wait for a
                                // wake that will never fire. If we lose, a reply
                                // is in flight and its enqueue_and_wake clears
                                // the flag; the gate below waits for it (#160).
                                let cancelled = (*server)
                                    .reply_tcb
                                    .compare_exchange(
                                        tcb,
                                        core::ptr::null_mut(),
                                        Ordering::AcqRel,
                                        Ordering::Acquire,
                                    )
                                    .is_ok();
                                if cancelled
                                {
                                    (*tcb).wake_in_flight.store(0, Ordering::Release);
                                }
                            }
                            IpcThreadState::BlockedOnFault =>
                            {
                                // A dying fault-blocked thread: `blocked_obj` is
                                // its handler (server) TCB. CAS-clear the
                                // handler's reply slot so a later reply does not
                                // target this freed faulter. Mirrors
                                // BlockedOnReply; the faulter never resumes, so no
                                // disposition is recorded.
                                use core::sync::atomic::Ordering;
                                let server =
                                    blocked_obj.cast::<crate::sched::thread::ThreadControlBlock>();
                                let cancelled = (*server)
                                    .reply_tcb
                                    .compare_exchange(
                                        tcb,
                                        core::ptr::null_mut(),
                                        Ordering::AcqRel,
                                        Ordering::Acquire,
                                    )
                                    .is_ok();
                                if cancelled
                                {
                                    (*tcb).wake_in_flight.store(0, Ordering::Release);
                                }
                            }
                            IpcThreadState::None =>
                            {}
                        }
                        (*tcb).blocked_on_object = core::ptr::null_mut();
                    }
                }

                // Release this thread's fault-handler binding, if any. The
                // binding held an inc_ref on the endpoint object for its lifetime
                // (see ThreadControlBlock::fault_handler); drop it, and if this
                // was its last reference enqueue the orphaned endpoint on the
                // cascade worklist (rather than recursing into `dealloc_object`,
                // which this function's worklist mechanism exists to avoid). Done
                // after the unlink above (which removed this thread from the
                // endpoint's send queue if it was a queued faulter) so the
                // endpoint dealloc cannot observe this thread still on its queue.
                // SAFETY: tcb valid (not yet freed); fault_handler is atomic; no
                // lock is held here.
                unsafe {
                    let ep = (*tcb)
                        .fault_handler
                        .swap(core::ptr::null_mut(), core::sync::atomic::Ordering::AcqRel);
                    if !ep.is_null() && (*ep).header.dec_ref() == 0
                    {
                        push_ancestor(
                            worklist,
                            head,
                            core::ptr::NonNull::new_unchecked(ep.cast::<KernelObjectHeader>()),
                        );
                    }
                }

                // Wake-in-flight gate (#160): a waker that popped this thread
                // from a wait object (notification/endpoint/event_queue/wait_set)
                // under that object's lock sets `wake_in_flight = 1` before
                // releasing the lock and clears it in `enqueue_and_wake`. The
                // unlink above acquired the same wait-object lock after any
                // such waker released it, so this load cannot miss the set.
                // Spin until the in-flight wake commits, so `retype_free` below
                // cannot free the TCB out from under the waker's pending
                // `enqueue_and_wake` (the residual #117/#160 use-after-free).
                // Interrupts enabled + preemption disabled, mirroring the
                // `context_saved` gate above, so the spin does not block
                // incoming IPIs (FPU flush / TLB shootdown).
                crate::percpu::preempt_disable();
                // SAFETY: ring 0; restored below.
                let wake_saved_int =
                    unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
                // SAFETY: ring 0; IDT loaded; preempt disabled.
                unsafe { crate::arch::current::interrupts::enable() };
                // SAFETY: tcb is valid (not yet freed); wake_in_flight is always
                // valid on an initialized TCB.
                while unsafe {
                    (*tcb)
                        .wake_in_flight
                        .load(core::sync::atomic::Ordering::Acquire)
                } != 0
                {
                    core::hint::spin_loop();
                }
                // SAFETY: wake_saved_int from save_and_disable_interrupts above.
                unsafe { crate::arch::current::cpu::restore_interrupts(wake_saved_int) };
                crate::percpu::preempt_enable();

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
            let ancestor_memory = unsafe { &*ancestor_ptr.cast::<MemoryObject>() };
            // The wrapper sits one full page above the slot's base,
            // immediately after the kstack pages.
            let wrapper_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let kstack_pages_bytes =
                (crate::sched::KERNEL_STACK_PAGES * crate::mm::PAGE_SIZE) as u64;
            let block_phys = wrapper_phys - kstack_pages_bytes;
            let offset = block_phys - ancestor_memory.base;

            // SAFETY: ptr is in-place ThreadObject.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<ThreadObject>()) };

            retype_free(ancestor_memory, offset, raw_bytes);

            let ancestor_nn =
                // SAFETY: ancestor_ptr non-null.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_memory.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: refcount reached 0.
                push_ancestor(worklist, head, ancestor_nn);
            }
        }

        // ── AddressSpace ──────────────────────────────────────────────────
        //
        // All `AddressSpace` objects are retype-backed: init's bootstrap AS
        // lands in a slab from `SEED_MEMORY` (Phase 9), and every userspace
        // AS lands in a slab from a Memory cap (`sys_cap_create_aspace`).
        // Both inline `AddressSpace` into the same wrapper page as
        // `AddressSpaceObject`; both record at least one chunk slot covering
        // the wrapper, root PT, and PT growth pool. Reclamation walks the
        // chunk slots and `retype_free`s each one wholesale, then `dec_ref`s
        // the ancestor `MemoryObject`.
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
                    // SAFETY: as_ptr non-null; active_cpu_mask is an Acquire snapshot.
                    unsafe { (*as_ptr).active_cpu_mask() }.is_empty(),
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

                // Return this space's hardware tag (PCID/ASID) to the pool, if
                // any. No TLB flush is needed: active_cpus is empty (asserted
                // above), and any CPU that cached the tag while switched away is
                // flushed lazily by the generation check the next time it loads
                // the tag for whatever space claims it next.
                // SAFETY: as_ptr is a valid AddressSpace being reclaimed; with
                // active_cpus empty no concurrent activate races this read.
                let tag = unsafe { (*as_ptr).tag.load(Ordering::Acquire) };
                crate::mm::tag_allocator::free_tag(tag);

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
                    // live MemoryObject's header; the inc_ref then is
                    // matched by the dec_ref here.
                    let anc_hdr = unsafe { &*anc_ptr };
                    // Cast to MemoryObject for retype_free; the ancestor
                    // is always a Memory cap (header at offset 0).
                    // cast_ptr_alignment: header at offset 0; MemoryObject is repr(C).
                    #[allow(clippy::cast_ptr_alignment)]
                    // SAFETY: anc_ptr was set at chunk recording from a
                    // live MemoryObject's header; refcount kept alive
                    // until the dec_ref below.
                    let anc_memory = unsafe { &*anc_ptr.cast::<MemoryObject>() };
                    crate::cap::retype::retype_free(anc_memory, off, pages * p);
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
        // in a slab from `SEED_MEMORY` (Phase 7), and every userspace CSpace
        // lands in a slab from a Memory cap (`sys_cap_create_cspace`). Both
        // inline `CSpace` directly into the wrapper page; both record at
        // least one chunk slot covering the wrapper plus the slot-page pool.
        // Reclamation walks the chunk slots and `retype_free`s each one
        // wholesale, then `dec_ref`s the ancestor.
        //
        // Before `unregister_cspace` and the dec_ref cascade run, the
        // derivation tree's external back-links into this dying `CSpace`
        // are scrubbed by [`drain_dying_cspace`]. Combined with the
        // [`SlotId`] epoch check in `lookup_cspace`, this is the
        // defense-in-depth that lets `free_cspace_id` recycle the id
        // safely: foreign slots cannot retain a back-link, and any that
        // somehow slip through fail-fast on epoch mismatch.
        ObjectType::CSpaceObj =>
        {
            // SAFETY: ptr points at an in-place CSpaceKernelObject; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<CSpaceKernelObject>()) };
            let cs_ptr = obj.cspace;

            debug_assert!(
                !obj.cs_chunks[0].ancestor.load(Ordering::Acquire).is_null(),
                "dealloc CSpaceObj: heap-backed CSpace reached typed-memory dealloc path"
            );

            // Captured for the final `free_cspace_id` after the lock release;
            // 0 means "no dying id" (cs_ptr was null), which short-circuits
            // the free-list push below.
            let mut dying_id: crate::cap::slot::CSpaceId = 0;
            let mut needs_free_id = false;

            if !cs_ptr.is_null()
            {
                // SAFETY: cs_ptr non-null; allocated at creation.
                let id = unsafe { (*cs_ptr).id() };
                dying_id = id;
                let dying_epoch = crate::cap::registry_epoch(id);

                // ── Pre-unregister derivation drain ──
                // Hold DERIVATION_LOCK exclusively for the drain + unregister
                // pair only. The drain walks each populated slot, snapshots
                // its outgoing derivation pointers under a brief per-slot
                // &mut, clears them, then splices the corresponding back-
                // links in foreign slots. `unregister_cspace` runs inside
                // the same critical section so any concurrent foreign reader
                // sees a consistent "drained, then absent" transition.
                //
                // The lock MUST be released BEFORE the `for_each_object`
                // dec_ref cascade below: a slot in the dying CSpace may hold
                // a CSpace cap whose dec_ref drives a nested
                // `dealloc_object(CSpaceObj)` call, which would re-enter
                // this same non-recursive lock and deadlock. The drain
                // already removed every foreign back-link before this
                // point, so the dec_ref cascade has no derivation-tree
                // work to do — releasing is safe.
                crate::cap::derivation::DERIVATION_LOCK.write_lock();
                // SAFETY: DERIVATION_LOCK held; cs_ptr uniquely owned at
                // refcount=0; registry entry still live (unregister below).
                unsafe { drain_dying_cspace(cs_ptr, id, dying_epoch) };
                crate::cap::unregister_cspace(id);
                crate::cap::derivation::DERIVATION_LOCK.write_unlock();

                // Dec-ref all objects referenced by non-null slots. Runs
                // without DERIVATION_LOCK so nested CSpaceObj deallocs (a
                // dying CSpace whose slots hold caps to other CSpaces) can
                // acquire it themselves without re-entry.
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

                // Don't recycle id 0 (root CSpace's id). The root is also
                // pinned by HDR_FLAG_IS_ROOT so this branch is unreachable
                // for the root in practice; the guard is defense-in-depth.
                needs_free_id = id != 0;
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
                // cast_ptr_alignment: header at offset 0; MemoryObject repr(C).
                #[allow(clippy::cast_ptr_alignment)]
                // SAFETY: ancestor live until dec_ref below.
                let anc_memory = unsafe { &*anc_ptr.cast::<MemoryObject>() };
                crate::cap::retype::retype_free(anc_memory, off, pages * p);
                let new_rc = anc_hdr.dec_ref();
                if new_rc == 0
                {
                    // SAFETY: refcount reached 0.
                    let anc_nn = unsafe { NonNull::new_unchecked(anc_ptr) };
                    push_ancestor(worklist, head, anc_nn);
                }
            }

            // Recycle the id last, after all of the dying CSpace's storage
            // is reclaimed and DERIVATION_LOCK is released. Bumping the
            // epoch now invalidates any surviving SlotId stamped with the
            // pre-recycle value — subsequent `lookup_cspace` returns None.
            if needs_free_id
            {
                crate::cap::free_cspace_id(dying_id);
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
                // Wait-set membership holds a +1 cap-level ref on the source
                // (see `sys_wait_set_add` / `wait_set_drop`); when an
                // Endpoint reaches dealloc, its refcount is zero, which
                // implies no wait-set member references it, which implies
                // `wait_set` is null. The contract is verified here.
                // SAFETY: state validated non-null; EndpointState allocated at creation.
                let wait_set_clear = unsafe { (*state).wait_set.is_null() };
                debug_assert!(
                    wait_set_clear,
                    "Endpoint dealloc with live wait-set membership — \
                     refcount invariant broken"
                );

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
                        // A queued fault sender (its handler never received) must
                        // kill, not resume, when woken: its resume runs the fault
                        // helper, which reads this disposition. Covers the
                        // unbind-drops-last-ref liveness case (fault-handling.md
                        // § Liveness rule 3).
                        if (*tcb).in_fault_delivery
                        {
                            (*tcb).fault_outcome.store(
                                crate::ipc::fault::FAULT_OUTCOME_KILL,
                                core::sync::atomic::Ordering::Release,
                            );
                        }
                        let target_cpu = crate::sched::select_target_cpu(tcb);
                        crate::sched::enqueue_and_wake(tcb, target_cpu);
                        tcb = next.unwrap_or(core::ptr::null_mut());
                    }
                    ep.send_head = core::ptr::null_mut();
                    ep.send_tail = core::ptr::null_mut();
                    // Keep the send-ready shadow consistent with send_head even
                    // on the dealloc drain path (#285-adjacent).
                    ep.refresh_send_ready();
                    // Wake receivers.
                    let mut tcb = ep.recv_head;
                    while !tcb.is_null()
                    {
                        let next = (*tcb).ipc_wait_next;
                        (*tcb).ipc_wait_next = None;
                        let target_cpu = crate::sched::select_target_cpu(tcb);
                        crate::sched::enqueue_and_wake(tcb, target_cpu);
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
            // Wrapper + state live in-place inside the ancestor Memory cap's
            // region. Drop in place, return the slot to the per-Memory
            // allocator, then dec_ref the ancestor — recursing if it hits zero.
            use crate::cap::retype::{dispatch_for, retype_free};
            // dispatch_for is total over the kernel's retypable types; the
            // Endpoint arm always returns Some. Unwrap-or-fall-through with
            // a fallback raw size keeps the lint quiet without panicking. The
            // fallback mirrors dispatch_for's computed value (24 wrapper +
            // EndpointState) so it cannot drift from the alloc-side size.
            let raw_bytes = dispatch_for(ObjectType::Endpoint, 0).map_or(
                24 + core::mem::size_of::<crate::ipc::endpoint::EndpointState>() as u64,
                |e| e.raw_bytes,
            );

            // SAFETY: ancestor_ptr is non-null; it was set by `with_ancestor`
            // at retype time and points at the source MemoryObject's header.
            // The retype primitive holds a +1 refcount on the MemoryObject
            // for the lifetime of every retyped descendant, so the target
            // is still live.
            let ancestor_memory = unsafe { &*ancestor_ptr.cast::<MemoryObject>() };

            let header_virt = ptr.as_ptr() as u64;
            let header_phys = crate::mm::paging::virt_to_phys(header_virt);
            let offset = header_phys - ancestor_memory.base;

            // Drop in place. EndpointObject and EndpointState contain only
            // primitive fields and Spinlock; no Drop impl, but the call is
            // explicit for clarity and to keep parity with future types
            // that may require it.
            if !state.is_null()
            {
                // SAFETY: state points into the ancestor Memory cap region;
                // refcount reached 0 so we are the unique accessor.
                unsafe { core::ptr::drop_in_place(state) };
            }
            // SAFETY: ptr is the in-place EndpointObject; unique access.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<EndpointObject>()) };

            // Return the bytes to the per-Memory allocator.
            retype_free(ancestor_memory, offset, raw_bytes);

            // Drop the retype-time refcount lease. If this Memory cap has no
            // remaining slots and no descendants, recurse to free the cap
            // itself; the recursion is bounded by ancestor depth.
            let ancestor_nn =
                // SAFETY: ancestor_ptr is non-null per debug_assert.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_memory.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: refcount reached 0; recursion handles the Memory
                // arm above (which frees the buddy pages and Box).
                push_ancestor(worklist, head, ancestor_nn);
            }
        }

        // ── Notification ────────────────────────────────────────────────────────
        ObjectType::Notification =>
        {
            // Branch on `header.ancestor`: heap-backed (legacy) vs retype-backed.
            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);

            // SAFETY: ptr originally points to a NotificationObject; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<NotificationObject>()) };
            let state = obj.state;

            if !state.is_null()
            {
                // Clear any IRQ routing table entries that point to this
                // NotificationState. A hardware interrupt firing after the notification
                // is freed would otherwise call notification_send on a dead slot.
                // SAFETY: interrupts disabled to serialize with IRQ delivery.
                unsafe {
                    let saved = crate::arch::current::cpu::save_and_disable_interrupts();
                    crate::irq::unregister_notification(state);
                    crate::arch::current::cpu::restore_interrupts(saved);
                }

                // Wait-set membership holds a +1 cap-level ref on the source
                // (see `sys_wait_set_add` / `wait_set_drop`); reaching dealloc
                // with `wait_set` still set means the refcount invariant is
                // broken.
                // SAFETY: state validated non-null; NotificationState live.
                let wait_set_clear = unsafe { (*state).wait_set.is_null() };
                debug_assert!(
                    wait_set_clear,
                    "Notification dealloc with live wait-set membership — \
                     refcount invariant broken"
                );

                // Wake a blocked waiter with wakeup_value = 0.
                // TODO: return SyscallError::ObjectGone when a proper wakeup
                // error path is available in sys_notification_wait.
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
                        let target_cpu = crate::sched::select_target_cpu(waiter);
                        crate::sched::enqueue_and_wake(waiter, target_cpu);
                    }
                }
            }

            debug_assert!(
                !ancestor_ptr.is_null(),
                "Notification: every production cap is retype-backed via cap_create_notification"
            );
            // Wrapper + state are in-place inside the ancestor Memory cap's
            // region.
            use crate::cap::retype::{dispatch_for, retype_free};
            let raw_bytes = dispatch_for(ObjectType::Notification, 0).map_or(120, |e| e.raw_bytes);

            // SAFETY: ancestor_ptr is non-null per debug_assert; the
            // MemoryObject is kept alive by the retype-time refcount lease.
            let ancestor_memory = unsafe { &*ancestor_ptr.cast::<MemoryObject>() };

            let header_virt = ptr.as_ptr() as u64;
            let header_phys = crate::mm::paging::virt_to_phys(header_virt);
            let offset = header_phys - ancestor_memory.base;

            if !state.is_null()
            {
                // SAFETY: state lives in-place inside the ancestor Memory
                // cap; refcount reached 0 — unique accessor.
                unsafe { core::ptr::drop_in_place(state) };
            }
            // SAFETY: ptr is the in-place NotificationObject; unique access.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<NotificationObject>()) };

            retype_free(ancestor_memory, offset, raw_bytes);

            // Drop the retype-time refcount lease; recurse on full release.
            let ancestor_nn =
                // SAFETY: ancestor_ptr non-null.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_memory.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: refcount reached 0; recurse to free the Memory cap.
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
                // Wait-set membership holds a +1 cap-level ref on the source
                // (see `sys_wait_set_add` / `wait_set_drop`); reaching dealloc
                // with `wait_set` still set means the refcount invariant is
                // broken.
                // SAFETY: state non-null; EventQueueState live.
                let wait_set_clear = unsafe { (*state).wait_set.is_null() };
                debug_assert!(
                    wait_set_clear,
                    "EventQueue dealloc with live wait-set membership — \
                     refcount invariant broken"
                );

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
            let ancestor_memory = unsafe { &*ancestor_ptr.cast::<MemoryObject>() };
            let header_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let offset = header_phys - ancestor_memory.base;

            if !state.is_null()
            {
                // SAFETY: state lives in-place; refcount reached 0.
                unsafe { core::ptr::drop_in_place(state) };
            }
            // SAFETY: ptr is in-place EventQueueObject.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<EventQueueObject>()) };

            retype_free(ancestor_memory, offset, raw_bytes);

            let ancestor_nn =
                // SAFETY: ancestor_ptr non-null.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_memory.header.dec_ref();
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
                // wait_set_drop wakes any blocked waiter, clears every source
                // back-pointer, and drops the +1 cap-level ref each member
                // held on its source. Any source whose ref drops to zero is
                // returned for cascade-reclaim on this worklist — performed
                // here rather than inside `wait_set_drop` so the source
                // dealloc runs after every source/ws IPC lock has been
                // released (see scheduling-internals.md § Lock Hierarchy).
                // SAFETY: state non-null and live.
                let zeroed = unsafe { crate::ipc::wait_set::wait_set_drop(state) };
                for entry in zeroed.iter().copied().flatten()
                {
                    push_ancestor(worklist, head, entry);
                }
            }

            debug_assert!(
                !ancestor_ptr.is_null(),
                "WaitSet: every production cap is retype-backed via cap_create_wait_set"
            );
            use crate::cap::retype::{dispatch_for, retype_free};
            let raw_bytes = dispatch_for(ObjectType::WaitSet, 0)
                .map_or(crate::mm::PAGE_SIZE as u64, |e| e.raw_bytes);
            // SAFETY: ancestor_ptr non-null.
            let ancestor_memory = unsafe { &*ancestor_ptr.cast::<MemoryObject>() };
            let header_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let offset = header_phys - ancestor_memory.base;

            if !state.is_null()
            {
                // SAFETY: state lives in-place.
                unsafe { core::ptr::drop_in_place(state) };
            }
            // SAFETY: ptr is in-place WaitSetObject.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<WaitSetObject>()) };

            retype_free(ancestor_memory, offset, raw_bytes);

            let ancestor_nn =
                // SAFETY: ancestor_ptr non-null.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_memory.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: refcount reached 0.
                push_ancestor(worklist, head, ancestor_nn);
            }
        }
    }
}

// ── CSpace teardown helpers ──────────────────────────────────────────────────

/// Pre-unregister derivation drain for a dying `CSpace`.
///
/// Iterates each populated slot in `cs_ptr` and splices the slot out of its
/// foreign back-link chains so that, after `unregister_cspace` runs, no
/// foreign slot in any other `CSpace` retains a derivation pointer into the
/// dying one. Combined with the per-id epoch check in
/// `crate::cap::lookup_cspace`, this lets `free_cspace_id` recycle the id
/// safely.
///
/// ## Aliasing avoidance
///
/// PR #136's first recycling attempt hit a release-mode aliasing UB: an
/// outer iteration holding `&CSpacePage` while an inner closure took
/// `&mut CapabilitySlot` to a slot inside the same page. This drain
/// avoids the hazard structurally — no borrow into `cs_ptr` is held
/// across foreign-slot accesses. The per-slot scope is:
///
/// 1. A brief `unsafe { (*cs_ptr).slot_mut(idx) }` produces a
///    `&mut CapabilitySlot` purely to snapshot the four `deriv_*` fields
///    into stack locals and clear them in place. The borrow ends at the
///    block boundary.
/// 2. The foreign-write step calls into [`drain_foreign_back_links`],
///    which only accesses foreign `CSpace`s via fresh
///    `lookup_cspace`/`slot_mut` calls. Intra-cspace siblings/children
///    are short-circuited and never re-borrowed from inside this scope.
///
/// # Safety
///
/// Caller MUST hold `DERIVATION_LOCK` write lock. `cs_ptr` MUST be a valid
/// `CSpace` pointer whose refcount has reached zero (i.e. exclusive
/// ownership). The registry entry for `dying_id` MUST still be live
/// (i.e. `unregister_cspace` has not yet run); the deferred unregister
/// allows the drain itself to splice through `lookup_cspace`.
#[cfg(not(test))]
unsafe fn drain_dying_cspace(
    cs_ptr: *mut crate::cap::cspace::CSpace,
    dying_id: crate::cap::slot::CSpaceId,
    dying_epoch: u32,
)
{
    use crate::cap::cspace::{L1_SIZE, L2_SIZE};
    use crate::cap::slot::{CapTag, SlotId};
    use core::num::NonZeroU32;

    for page_idx in 0..L1_SIZE
    {
        // Presence-test the page without holding a `&CSpace` borrow into
        // the per-slot scope below.
        // SAFETY: cs_ptr is uniquely owned; `page_at` takes `&self` briefly
        // and returns before the borrow can be observed elsewhere.
        if unsafe { (*cs_ptr).page_at(page_idx) }.is_none()
        {
            continue;
        }
        let start = usize::from(page_idx == 0);
        for slot_idx_in_page in start..L2_SIZE
        {
            let global_idx = (page_idx * L2_SIZE + slot_idx_in_page) as u32;
            let Some(global_idx_nz) = NonZeroU32::new(global_idx)
            else
            {
                continue;
            };

            // Step A — local read + clear under a brief per-slot &mut.
            // The borrow ends at the block boundary; the four snapshots
            // are `Copy` and outlive it.
            // SAFETY: cs_ptr is uniquely owned (refcount=0); the &mut
            // produced by slot_mut is the only borrow into this slot for
            // the duration of the block and is dropped before any foreign
            // access.
            let (parent, fc, prev, next, populated) = unsafe {
                if let Some(slot) = (*cs_ptr).slot_mut(global_idx)
                {
                    if slot.tag == CapTag::Null
                    {
                        (None, None, None, None, false)
                    }
                    else
                    {
                        let p = slot.deriv_parent;
                        let c = slot.deriv_first_child;
                        let pr = slot.deriv_prev_sibling;
                        let nx = slot.deriv_next_sibling;
                        slot.deriv_parent = None;
                        slot.deriv_first_child = None;
                        slot.deriv_prev_sibling = None;
                        slot.deriv_next_sibling = None;
                        (p, c, pr, nx, true)
                    }
                }
                else
                {
                    (None, None, None, None, false)
                }
            };
            if !populated
            {
                continue;
            }

            let self_id = SlotId::with_epoch(dying_id, dying_epoch, global_idx_nz);

            // Step B — foreign splice. No borrow into `cs_ptr` is held.
            // SAFETY: DERIVATION_LOCK held; foreign cspaces resolved via
            // registry lookup with epoch validation.
            unsafe {
                drain_foreign_back_links(self_id, dying_id, parent, fc, prev, next);
            }
        }
    }
}

/// Splice `self_id`'s back-references out of foreign `CSpace` slots.
///
/// Intra-cspace back-links (where the back-reference lives in the dying
/// `CSpace` itself) are skipped — those slots are either already cleared
/// by an earlier iteration of [`drain_dying_cspace`] or will be cleared
/// shortly. Their derivation pointers don't matter because the entire
/// dying `CSpace`'s storage is about to be reclaimed.
///
/// For the children walk: a foreign child has its `deriv_parent` nulled
/// (orphaned). Intra-cspace children are skipped for the same reason
/// above. `next_sibling` advancement reads through `slot()` (immutable),
/// which is safe because we never re-enter Step A's `&mut` for the dying
/// `CSpace` inside this function's scope.
///
/// # Safety
///
/// Caller MUST hold `DERIVATION_LOCK` write lock. `dying_id`'s registry
/// entry MUST still be live so `lookup_cspace(dying_id, dying_epoch)`
/// resolves for the intra-cspace child-chain walk.
#[cfg(not(test))]
unsafe fn drain_foreign_back_links(
    self_id: crate::cap::slot::SlotId,
    dying_id: crate::cap::slot::CSpaceId,
    parent: Option<crate::cap::slot::SlotId>,
    first_child: Option<crate::cap::slot::SlotId>,
    prev: Option<crate::cap::slot::SlotId>,
    next: Option<crate::cap::slot::SlotId>,
)
{
    // Parent: if first_child pointed at self_id, redirect to next sibling.
    // (We don't attempt to find a different non-dying child; the next
    // sibling may itself be in dying — that's fine, epoch defense will
    // reject it on the next lookup after `free_cspace_id`.)
    if let Some(p) = parent
        && p.cspace_id != dying_id
        && let Some(parent_cs) = crate::cap::lookup_cspace(p.cspace_id, p.epoch)
    {
        // SAFETY: parent_cs from registry; DERIVATION_LOCK held.
        if let Some(parent_slot) = unsafe { (*parent_cs).slot_mut(p.index.get()) }
            && parent_slot.deriv_first_child == Some(self_id)
        {
            parent_slot.deriv_first_child = next;
        }
    }

    // Prev sibling: splice self_id out of the chain (its next becomes our next).
    if let Some(pr) = prev
        && pr.cspace_id != dying_id
        && let Some(prev_cs) = crate::cap::lookup_cspace(pr.cspace_id, pr.epoch)
    {
        // SAFETY: prev_cs from registry; DERIVATION_LOCK held.
        if let Some(prev_slot) = unsafe { (*prev_cs).slot_mut(pr.index.get()) }
            && prev_slot.deriv_next_sibling == Some(self_id)
        {
            prev_slot.deriv_next_sibling = next;
        }
    }

    // Next sibling: splice self_id out of the chain (its prev becomes our prev).
    if let Some(nx) = next
        && nx.cspace_id != dying_id
        && let Some(next_cs) = crate::cap::lookup_cspace(nx.cspace_id, nx.epoch)
    {
        // SAFETY: next_cs from registry; DERIVATION_LOCK held.
        if let Some(next_slot) = unsafe { (*next_cs).slot_mut(nx.index.get()) }
            && next_slot.deriv_prev_sibling == Some(self_id)
        {
            next_slot.deriv_prev_sibling = prev;
        }
    }

    // Children chain: orphan each foreign child by nulling its
    // deriv_parent. Walk via next_sibling. Intra-cspace children are
    // visited only to read next_sibling and continue the walk.
    let mut cur = first_child;
    while let Some(c) = cur
    {
        let next_in_chain = if c.cspace_id == dying_id
        {
            // Intra-cspace: don't touch (it's being iterated independently).
            // Read next_sibling via immutable `slot()` to advance the walk.
            // SAFETY: lookup returns the dying CSpace's ptr; immutable `&`
            // borrow is exclusive with respect to drain_dying_cspace's
            // per-slot `&mut` because Step A's scope already ended.
            crate::cap::lookup_cspace(c.cspace_id, c.epoch)
                .and_then(|cs| unsafe { (*cs).slot(c.index.get()) })
                .and_then(|s| s.deriv_next_sibling)
        }
        else
        {
            // Foreign: resolve, snapshot next_sibling, null deriv_parent.
            // SAFETY: foreign cspace lookup; DERIVATION_LOCK held.
            crate::cap::lookup_cspace(c.cspace_id, c.epoch).and_then(|cs| unsafe {
                (*cs).slot_mut(c.index.get()).and_then(|slot| {
                    let n = slot.deriv_next_sibling;
                    if slot.deriv_parent == Some(self_id)
                    {
                        slot.deriv_parent = None;
                    }
                    n
                })
            })
        };
        cur = next_in_chain;
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
    fn memory_object_header_at_offset_zero()
    {
        assert_eq!(offset_of!(MemoryObject, header), 0);
    }

    #[test]
    fn mmio_object_header_at_offset_zero()
    {
        assert_eq!(offset_of!(MmioObject, header), 0);
    }

    #[test]
    fn interrupt_object_header_at_offset_zero()
    {
        assert_eq!(offset_of!(InterruptObject, header), 0);
    }

    #[test]
    fn ioport_object_header_at_offset_zero()
    {
        assert_eq!(offset_of!(IoPortObject, header), 0);
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
        // MemoryObject: 16 header + 8 base + 8 size + 8 available_bytes +
        // 1 owns_memory + 7 pad + 40 inline allocator + 4 lock + 4 pad = 96 bytes.
        assert_eq!(size_of::<MemoryObject>(), 96);
        // MmioObject: 16 header + 8 base + 8 size + 4 flags + 4 pad = 40.
        assert_eq!(size_of::<MmioObject>(), 40);
        // InterruptObject: 16 header + 4 start + 4 count = 24.
        assert_eq!(size_of::<InterruptObject>(), 24);
        // IoPortObject: 16 header + 2 base + 2 size + 4 pad = 24.
        assert_eq!(size_of::<IoPortObject>(), 24);
        // SchedControlObject: 16 header + 1 min + 1 max + 6 pad = 24 (8-align).
        assert_eq!(size_of::<SchedControlObject>(), 24);
        assert_eq!(size_of::<SbiControlObject>(), 16);
        assert_eq!(size_of::<ThreadObject>(), 24);
        assert_eq!(size_of::<EndpointObject>(), 24);
        assert_eq!(size_of::<NotificationObject>(), 24);
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
        let h = KernelObjectHeader::new(ObjectType::Memory);
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
        // equality, not that the target is a live MemoryObject.
        let target = Box::into_raw(Box::new(KernelObjectHeader::new(ObjectType::Memory)));
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
