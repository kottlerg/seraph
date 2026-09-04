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
//! Phase-7 boot-time identity wrappers are retyped from the SEED reserve
//! (`boot_retype_*`, `mint_phase7_body`) and carry the SEED ancestor.
//!
//! Deallocation: read `header.obj_type` from the raw pointer, drop the
//! object in place, and call `retype_free` against the ancestor
//! `MemoryObject`; every object has one.
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
//! | ThreadObject        | 32 B  |
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
/// Used during deallocation to select the concrete type's teardown arm.
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
/// When `dec_ref` returns 0, the object has no remaining references and
/// `dealloc_object` frees it, dispatching on `obj_type`.
///
/// `ancestor` is a direct pointer to the `MemoryObject`'s header from which
/// this object was retyped. Auto-reclaim consults this on `dec_ref → 0` to
/// credit bytes back to the source `MemoryObject` and return the chunk to the
/// per-Memory-cap allocator.
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
    /// Pointer to the `MemoryObject`'s header this object was retyped from;
    /// every production object has one (null only in host tests). Set once at
    /// creation, read at deallocation. `AtomicPtr` for the unforgeable null
    /// sentinel without imposing const-init constraints on construction.
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
    /// Used by host tests only; production objects are retyped and use
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
    /// Initialised to `size` for RAM caps minted at boot with `MemRights::RETYPE`.
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
    ///
    /// A contended wait is recorded in the calling CPU's lock-wait
    /// breadcrumb for the softlockup watchdog; the uncontended path
    /// records nothing.
    #[track_caller]
    pub fn read_lock(&self)
    {
        crate::sched::check_lock_hold_preemptible(
            crate::sched::LockKind::MemoryRead,
            core::panic::Location::caller(),
        );
        let mut waiting = false;
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
            if !waiting
            {
                waiting = true;
                crate::sched::lock_wait_enter(
                    crate::sched::LockKind::MemoryRead,
                    core::ptr::from_ref(&self.lock).expose_provenance(),
                );
            }
            core::hint::spin_loop();
        }
        if waiting
        {
            crate::sched::lock_wait_exit();
        }
    }

    /// Release a shared read lock previously acquired with [`Self::read_lock`].
    pub fn read_unlock(&self)
    {
        self.lock.fetch_sub(1, Ordering::Release);
    }

    /// Acquire the write lock. Spins until no readers or writers hold it.
    ///
    /// Contended waits are recorded like [`Self::read_lock`]'s.
    #[track_caller]
    pub fn write_lock(&self)
    {
        crate::sched::check_lock_hold_preemptible(
            crate::sched::LockKind::MemoryWrite,
            core::panic::Location::caller(),
        );
        let mut waiting = false;
        loop
        {
            if self
                .lock
                .compare_exchange_weak(0, FRAME_WRITE_LOCKED, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
            if !waiting
            {
                waiting = true;
                crate::sched::lock_wait_enter(
                    crate::sched::LockKind::MemoryWrite,
                    core::ptr::from_ref(&self.lock).expose_provenance(),
                );
            }
            core::hint::spin_loop();
        }
        if waiting
        {
            crate::sched::lock_wait_exit();
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
    #[track_caller]
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
/// `SchedControl` cap whose band covers a level is the authority to assign
/// that level via `SYS_THREAD_SET_PRIORITY`, or to create a thread at it via
/// `SYS_CAP_CREATE_THREAD`'s priority arguments (creation at the floor,
/// `PRIORITY_MIN`, needs no `SchedControl`). The root cap (spanning the full
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
    /// Pointer to the TCB, inside the same retype slot that holds the kstack
    /// and this wrapper.
    pub tcb: *mut crate::sched::thread::ThreadControlBlock,
    /// Intrusive link for the per-CPU deferred self-teardown reclaim stack
    /// ([`drain_deferred_reclaim`]). Non-null only while this object sits on
    /// that stack — between a thread deleting the last capability to its own
    /// `Thread` object and the off-CPU completion of that free. Null otherwise.
    /// Written only by the owning CPU.
    pub deferred_next: *mut KernelObjectHeader,
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
    /// Pointer to the `AddressSpace`, constructed in place in the wrapper
    /// page immediately after this struct (`sys_cap_create_aspace`,
    /// `boot_retype_aspace`); the PT pool below is retype-backed too.
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
    /// Intrusive link for the per-CPU deferred reclaim stack
    /// ([`drain_deferred_reclaim`]). Non-null only while this object sits on
    /// that stack: the thread that dropped its last capability was itself
    /// bound to it (or was stopped by a concurrent teardown while freeing
    /// it), so the free completes off-CPU. Written only by the owning CPU.
    pub deferred_next: *mut KernelObjectHeader,
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
    /// Pointer to the `CSpace`, constructed in place directly after this
    /// wrapper in the slab's page 0 (the wrapper-page fit is
    /// compile-asserted below).
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
    /// Intrusive link for the per-CPU deferred reclaim stack
    /// ([`drain_deferred_reclaim`]); see `AddressSpaceObject::deferred_next`.
    pub deferred_next: *mut KernelObjectHeader,
}

// The wrapper page hosts the AddressSpaceObject followed by the in-place
// AddressSpace, or the CSpaceKernelObject followed by the inline CSpace
// directory; each pair must fit one page (the construction sites also
// debug-assert the offsets).
const _: () = assert!(
    core::mem::size_of::<AddressSpaceObject>()
        + core::mem::size_of::<crate::mm::address_space::AddressSpace>()
        <= crate::mm::PAGE_SIZE,
);
const _: () = assert!(
    core::mem::size_of::<CSpaceKernelObject>() + core::mem::size_of::<crate::cap::cspace::CSpace>()
        <= crate::mm::PAGE_SIZE,
    "CSpaceKernelObject + CSpace exceed the wrapper page"
);

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

    /// Whether `phys` lies inside one of this AS's retype-source chunks — i.e.
    /// the page was carved from this AS's PT pool (rather than `kernel_pt_pool`
    /// or another allocator).
    ///
    /// The region-reclaim walk consults this before returning a now-empty
    /// intermediate page table via [`free_pt_page`]: only pool-owned pages may
    /// re-enter the pool. Every intermediate PT the walk reaches in a
    /// retype-backed AS is pool-owned; the check defends a heap-backed AS (or
    /// any future non-pooled user mapping) against corrupting the pool's
    /// free-list and budget accounting.
    #[cfg(not(test))]
    pub fn owns_phys(&self, phys: u64) -> bool
    {
        let p = crate::mm::PAGE_SIZE as u64;
        pool_lock(&self.pt_pool_lock);
        let mut owned = false;
        for slot in &self.pt_chunks
        {
            let anc = slot.ancestor.load(Ordering::Acquire);
            if anc.is_null()
            {
                continue;
            }
            // SAFETY: ancestor is published with Release at chunk recording and
            // kept alive by the chunk's inc_ref for the AS's lifetime;
            // MemoryObject.base is immutable after creation.
            // cast_ptr_alignment: header at offset 0; MemoryObject is repr(C).
            #[allow(clippy::cast_ptr_alignment)]
            let base = unsafe { (*anc.cast::<MemoryObject>()).base };
            let start = base + slot.base_offset.load(Ordering::Relaxed);
            let end = start + slot.page_count.load(Ordering::Relaxed) * p;
            if phys >= start && phys < end
            {
                owned = true;
                break;
            }
        }
        pool_unlock(&self.pt_pool_lock);
        owned
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
    /// Pointer to the endpoint's mutable state, inline at `wrapper + 8` in
    /// the same retype slot.
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
    /// Pointer to the notification's mutable state, inline in the same retype
    /// slot.
    pub state: *mut crate::ipc::notification::NotificationState,
}

// SAFETY: NotificationObject is accessed only under the scheduler lock.
unsafe impl Send for NotificationObject {}
// SAFETY: NotificationObject is accessed only under the scheduler lock.
unsafe impl Sync for NotificationObject {}

/// Kernel object for an event queue (`EventQueue` capability).
///
/// The wrapper, `EventQueueState`, and the ring buffer all live in the same
/// retype slot — the ring is at offset
/// [`crate::cap::retype::EVENT_QUEUE_RING_OFFSET`] from the wrapper base,
/// and the slot is reclaimed wholesale via `retype_free`.
#[repr(C)]
pub struct EventQueueObject
{
    pub header: KernelObjectHeader,
    /// Pointer to the event-queue state, inline in the same retype slot.
    pub state: *mut crate::ipc::event_queue::EventQueueState,
}

// SAFETY: EventQueueObject is accessed only under the scheduler lock.
unsafe impl Send for EventQueueObject {}
// SAFETY: EventQueueObject is accessed only under the scheduler lock.
unsafe impl Sync for EventQueueObject {}

/// Kernel object for a wait set (`WaitSet` capability).
///
/// `WaitSetState` is the ~480-byte body holding member slots and the ready
/// ring; it lives inline immediately after the 24-byte wrapper within a single
/// `BIN_512` retype slot.
#[repr(C)]
pub struct WaitSetObject
{
    pub header: KernelObjectHeader,
    /// Pointer to the wait-set state, inline in the same retype slot.
    pub state: *mut crate::ipc::wait_set::WaitSetState,
}

// SAFETY: WaitSetObject is accessed only under the scheduler lock.
unsafe impl Send for WaitSetObject {}
// SAFETY: WaitSetObject is accessed only under the scheduler lock.
unsafe impl Sync for WaitSetObject {}

// ── Object deallocation ───────────────────────────────────────────────────────

/// One-shot guard for [`log_self_teardown`].
#[cfg(not(test))]
static SELF_TEARDOWN_LOGGED: AtomicBool = AtomicBool::new(false);

/// One-shot diagnostic for the self-teardown path (#341). The first time a
/// thread deletes the last capability to its own `Thread` object, `CSpace`,
/// or `AddressSpace` (`what`), log its id, the in-flight userspace
/// instruction pointer, and the syscall number, so the triggering userspace
/// call site can be symbolised from a burn-in log. Bounded to a single line
/// so it never floods the boot log under thread churn.
#[cfg(not(test))]
fn log_self_teardown(tcb: *mut crate::sched::thread::ThreadControlBlock, what: &str)
{
    if SELF_TEARDOWN_LOGGED
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    // SAFETY: tcb is valid here — about to be marked Exited, not yet freed.
    let (tid, tf) = unsafe { ((*tcb).thread_id, (*tcb).trap_frame) };
    if tf.is_null()
    {
        crate::kprintln!(
            "sched: self-teardown deferred reclaim ({what}): tid={tid} (no trap frame)"
        );
        return;
    }
    // SAFETY: tf non-null; it is the caller's saved userspace frame.
    let (rip, nr) = unsafe { ((*tf).instruction_pointer(), (*tf).syscall_nr()) };
    crate::kprintln!(
        "sched: self-teardown deferred reclaim ({what}): tid={tid} user_rip=0x{rip:x} \
         syscall_nr={nr}"
    );
}

/// The intrusive deferred-reclaim link of an object that may be queued on
/// the per-CPU deferred-reclaim stack.
///
/// # Safety
/// `ptr` must be a valid `Thread`, `CSpaceObj`, or `AddressSpace` object.
// cast_ptr_alignment: each concrete object is constructed in place at its own
// alignment; the header sits at offset 0 of every one.
#[allow(clippy::cast_ptr_alignment)]
#[cfg(not(test))]
unsafe fn deferred_link(ptr: NonNull<KernelObjectHeader>) -> *mut *mut KernelObjectHeader
{
    // SAFETY: header at offset 0 of every concrete object; caller contract.
    unsafe {
        match (*ptr.as_ptr()).obj_type
        {
            ObjectType::Thread =>
            {
                core::ptr::addr_of_mut!((*ptr.as_ptr().cast::<ThreadObject>()).deferred_next)
            }
            ObjectType::CSpaceObj =>
            {
                core::ptr::addr_of_mut!((*ptr.as_ptr().cast::<CSpaceKernelObject>()).deferred_next)
            }
            ObjectType::AddressSpace =>
            {
                core::ptr::addr_of_mut!((*ptr.as_ptr().cast::<AddressSpaceObject>()).deferred_next)
            }
            _ => crate::fatal("deferred reclaim: object type carries no link"),
        }
    }
}

/// Push an object whose free cannot complete on this CPU onto the CPU's
/// deferred-reclaim stack.
///
/// A thread deleting the last capability to its own `Thread` object cannot
/// run `dealloc_object`'s drain gate, which spins until the target TCB is no
/// longer `current` on any CPU (#341); a thread deleting the last capability
/// to its own `CSpace` or `AddressSpace` — directly, or through the cascade
/// of another object's teardown — cannot free storage it is executing on
/// (its slot pages, its root page table). In each case the arm marks the
/// thread `Exited`, pushes the object here, and returns; the syscall
/// epilogue then `schedule()`s away and [`drain_deferred_reclaim`] completes
/// the free from a context that is provably not a bound thread.
///
/// # Safety
/// `ptr` is an exclusively-owned `Thread`, `CSpaceObj`, or `AddressSpace`
/// object (refcount 0). For a `Thread`, its TCB is already `Exited` and
/// unlinked from every run queue. `cpu` is the local CPU index
/// (`< MAX_CPUS`) and its scheduler is initialised.
// cast_ptr_alignment: the `*mut u8` head only ever holds an object pointer
// stored by this function (header at offset 0, 8-byte aligned).
#[allow(clippy::cast_ptr_alignment)]
#[cfg(not(test))]
unsafe fn push_deferred_reclaim(cpu: usize, ptr: NonNull<KernelObjectHeader>)
{
    let node = ptr.as_ptr();
    // SAFETY: cpu < MAX_CPUS; scheduler initialised by sched::init.
    let sched = unsafe { crate::sched::scheduler_for(cpu) };
    let slot = &sched.deferred_reclaim_head;
    // SAFETY: ptr is a valid object of a linkable type per contract.
    let link = unsafe { deferred_link(ptr) };
    loop
    {
        let head = slot.load(Ordering::Acquire);
        // SAFETY: node is exclusively owned (refcount 0); the link field is ours.
        unsafe { *link = head.cast::<KernelObjectHeader>() };
        if slot
            .compare_exchange(head, node.cast::<u8>(), Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break;
        }
    }
}

/// Drain this CPU's deferred reclaim stack, completing the free of each
/// queued object (a `Thread`'s TCB, kstack, retype slot, and ancestor
/// cascade; a `CSpace`'s or `AddressSpace`'s bound-thread stop, drain, and
/// storage).
///
/// Called from the syscall epilogue (when the returning thread is alive) and
/// the idle loop — both contexts that are NOT one of the queued dead threads
/// and are bound to none of the queued objects, so re-entering
/// `dealloc_object` runs the normal arm: the Thread arm's `current`-anywhere
/// scan and `context_saved` gate pass on the first iteration, and the
/// `CSpace`/`AddressSpace` arms find their bound threads already `Exited`
/// and off-CPU.
///
/// # Safety
/// Must not run on a thread whose own object is queued here, or that is
/// bound to a queued object; the producer contract guarantees this — a
/// thread that queued an object here is `Exited`, reaches the Exited arm of
/// the syscall epilogue, and `schedule()`s away, never the drain arm.
// cast_ptr_alignment: the `*mut u8` head only ever holds an object pointer
// stored by push_deferred_reclaim (header at offset 0, 8-byte aligned).
#[allow(clippy::cast_ptr_alignment)]
#[cfg(not(test))]
pub unsafe fn drain_deferred_reclaim(cpu: usize)
{
    if cpu >= crate::sched::MAX_CPUS
    {
        return;
    }
    // SAFETY: cpu < MAX_CPUS; scheduler initialised by sched::init.
    let sched = unsafe { crate::sched::scheduler_for(cpu) };
    // Fast path: the stack is empty on virtually every call (self-teardown is
    // rare), so avoid the swap's RMW. Acquire pairs with the push's release CAS.
    if sched
        .deferred_reclaim_head
        .load(Ordering::Acquire)
        .is_null()
    {
        return;
    }
    let mut node = sched
        .deferred_reclaim_head
        .swap(core::ptr::null_mut(), Ordering::AcqRel)
        .cast::<KernelObjectHeader>();
    while !node.is_null()
    {
        // SAFETY: node is an exclusively-owned object pushed by
        // push_deferred_reclaim; the link field is stable until freed.
        let nn = unsafe { NonNull::new_unchecked(node) };
        // SAFETY: nn is a linkable object pushed by push_deferred_reclaim.
        let next = unsafe { *deferred_link(nn) };
        // SAFETY: refcount 0, exclusive ownership; re-enters the object's arm
        // from a context bound to nothing queued here, running the full free.
        unsafe { dealloc_object(nn) };
        node = next;
    }
}

/// Queue `ptr` for off-CPU reclaim because the running thread has been
/// stopped (it is bound to the object, or a concurrent teardown stopped it
/// while this free waited); log the first occurrence.
///
/// Reached only when the running thread is `Exited`, which the idle-loop
/// drain can never be: an idle TCB is unregistered, binds no `CSpace` or
/// address space, and is named by no capability, so no teardown or stop
/// can mark it. Every caller is therefore on the syscall path (a handler,
/// or the epilogue drain), where interrupts are disabled.
///
/// # Safety
/// `ptr` must be a refcount-0 `Thread`, `CSpace`, or `AddressSpace` object
/// referenced by no slot, and the caller must be the running thread with
/// interrupts disabled, so this CPU and its `current` are stable.
#[cfg(not(test))]
unsafe fn defer_self_teardown(ptr: NonNull<KernelObjectHeader>, what: &str)
{
    let this_cpu = crate::arch::current::cpu::current_cpu() as usize;
    // SAFETY: this_cpu < MAX_CPUS; `current` is written only by this CPU at
    // dispatch, and per contract we are that running thread.
    let cur = unsafe { crate::sched::scheduler_for(this_cpu).current };
    // Tripwire for the contract above: the caller observed its own `Exited`
    // state under the scheduler lock, so the read here is stable.
    // SAFETY: cur is this CPU's `current`, valid while installed.
    let cur_exited =
        !cur.is_null() && unsafe { (*cur).state } == crate::sched::thread::ThreadState::Exited;
    debug_assert!(
        cur_exited,
        "defer_self_teardown: running thread is not Exited"
    );
    if !cur.is_null()
    {
        log_self_teardown(cur, what);
    }
    // SAFETY: object exclusively owned (refcount 0) and of a linkable type;
    // queued for off-CPU reclaim on this CPU.
    unsafe { push_deferred_reclaim(this_cpu, ptr) };
}

/// Free a kernel object that no capability slot references: its reference
/// count has reached zero, or it is a fresh body that was never published
/// (see Safety).
///
/// Dispatches on `obj_type` to run the concrete type's teardown in place,
/// freeing any sub-resources first, then returns the object's bytes to its
/// ancestor `MemoryObject`.
///
/// # Safety
///
/// - `ptr` must be the header of a live object constructed in place in
///   retype-backed storage (the header sits at offset 0 of its wrapper).
/// - No capability slot may reference the object: its reference count is 0,
///   or it is a fresh body that was never published (a range split's
///   rollback frees such bodies at their initial count of 1).
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
        // ancestor-reclaim arm — both contracts require that no slot
        // references the object (refcount 0, or a never-published body) and
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
// cast_ptr_alignment: every concrete object is constructed in place at a
// size-class-aligned offset of a page-aligned retype slab (`retype_allocate`),
// which satisfies align_of::<ConcreteType>(). The NonNull<KernelObjectHeader>
// points to the first field (header at offset 0), so the pointer retains the
// concrete type's alignment even when stored as KernelObjectHeader*.
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

            // Self-teardown guard (#341): a thread that deletes the last
            // capability to its OWN Thread object reaches here as the running
            // thread on this CPU. The drain gate below spins until `tcb` is no
            // longer `current` on any CPU — impossible for the running thread on
            // its own CPU (the spin runs with preemption disabled, so it never
            // reschedules), which wedges the CPU. Instead mark `Exited` + drain
            // the run queues (no free), queue the object for off-CPU reclaim,
            // and return: the syscall epilogue observes the `Exited` state and
            // `schedule()`s away, and `drain_deferred_reclaim` re-enters this arm
            // with the thread off-CPU, where the gate passes immediately.
            if !tcb.is_null()
            {
                let this_cpu = crate::arch::current::cpu::current_cpu() as usize;
                // SAFETY: this_cpu < MAX_CPUS; scheduler initialised. Reading our
                // own CPU's `current` needs no lock — only this CPU writes it at
                // dispatch, and we are that running thread.
                let is_self = core::ptr::eq(tcb, unsafe {
                    crate::sched::scheduler_for(this_cpu).current
                });
                if is_self
                {
                    log_self_teardown(tcb, "Thread");
                    // Defensive net. For SYS_CAP_DELETE this is unreachable —
                    // sys_cap_delete refuses a self thread-cap delete before the
                    // dec-ref. It still guards any OTHER dealloc of the running
                    // thread (e.g. a self-targeting cap_revoke): mark Exited +
                    // drain run queues (no free), queue the object for off-CPU
                    // reclaim, and return. The syscall epilogue observes Exited
                    // and schedule()s away; drain_deferred_reclaim completes the
                    // free off-CPU, where the existing gate passes immediately.
                    // SAFETY: tcb valid; marks Exited + drains every run queue
                    // under the all-CPU-locks discipline (mirrors sys_thread_exit).
                    unsafe {
                        // Committing Exited: a refusal means a teardown
                        // already did.
                        let _ = crate::sched::set_state_under_all_locks(
                            tcb,
                            crate::sched::thread::ThreadState::Exited,
                        );
                    }
                    // SAFETY: object exclusively owned (refcount 0), now Exited
                    // and drained; queue it for off-CPU reclaim on this CPU.
                    unsafe { push_deferred_reclaim(this_cpu, ptr) };
                    return;
                }
            }

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
                // client for wake outside the all-locks region. The wake's
                // target CPU is NOT snapshotted here: it is recomputed at the
                // deferred wake site below, under the client's up-to-date state
                // and excluding this (dealloc) CPU (#351).
                let server_reply_wake: Option<*mut crate::sched::thread::ThreadControlBlock>;
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

                    // Read priority inside the all-locks region. This dealloc and
                    // `set_state_under_all_locks` read it under their all-CPU-locks
                    // region; `sys_thread_set_priority` writes it under the per-TCB
                    // `sched_lock` this dealloc also holds (outer), so the read is
                    // serialised against that writer.
                    let prio = (*tcb).priority;

                    // Mark Exited under all locks — no schedule() on any CPU
                    // can see this thread as Ready/Running after this point.
                    (*tcb).state = ThreadState::Exited;

                    // Remove from whichever queue it's actually in.
                    for cpu in 0..cpu_count
                    {
                        crate::sched::scheduler_for(cpu).remove_from_queue(tcb, prio);
                    }

                    // A dying server orphans any reply-bound client. Claim the
                    // reply slot (CAS) and DEFER the wake past the all-locks
                    // release: deposit the resume disposition now, but leave the
                    // client Blocked and route it through the GATED
                    // enqueue_and_wake below. The client's Scheduling-group fields
                    // (state/ipc_state/blocked_on_object) are written ONLY by
                    // enqueue_and_wake under the CLIENT's own sched_lock — never
                    // here under the server's locks. Writing `state = Ready` here
                    // was the residual #284: a concurrent dealloc(client) marks the
                    // client Exited under the client's sched_lock, racing this
                    // unsynchronised Ready write, and the old enqueue_ready_thread
                    // then linked the Exited-and-being-freed client → freed-but-
                    // linked run-queue corruption / torn dispatch. The gated
                    // enqueue_and_wake instead observes Exited and aborts the link.
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
                            // Keep the client TCB alive against a concurrent
                            // dealloc(client) until the deferred enqueue_and_wake
                            // clears it (#160 wake-in-flight gate). A BlockedOnReply
                            // client already carries wake_in_flight = 1 from
                            // endpoint_call/recv; refresh it unconditionally so the
                            // gate also covers the BlockedOnFault entry path.
                            (*bound).wake_in_flight.store(1, Ordering::Release);
                            // Deposit the resume disposition (read on resume per the
                            // DEPOSIT model). A fault-blocked client cancels to Kill
                            // (the fault helper terminates it on resume); a syscall
                            // caller returns Interrupted. Reading ipc_state here is a
                            // read of a value stable until our own wake (we hold the
                            // sole claim via the reply_tcb CAS).
                            let was_fault = (*bound).ipc_state
                                == crate::sched::thread::IpcThreadState::BlockedOnFault;
                            if was_fault
                            {
                                (*bound).fault_outcome.store(
                                    crate::ipc::fault::FAULT_OUTCOME_KILL,
                                    Ordering::Release,
                                );
                                // CAS win = episode claim; fault disposition is
                                // the KILL above.
                                crate::sched::thread::stamp_deposit_episode(bound);
                            }
                            else
                            {
                                // The reply_tcb CAS win is the episode claim:
                                // the orphaned caller's resume returns
                                // Interrupted via the disposition. Only
                                // sys_ipc_call parks are reply-bound, so the
                                // disposition is the whole mechanism.
                                crate::sched::thread::stamp_park_deposit(
                                    bound,
                                    crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
                                );
                            }
                            Some(bound)
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
                    // the in-flight register save has published; see
                    // `wait_until_off_cpu`.
                    // SAFETY: tcb is Exited and unlinked from every run queue
                    // (all-locks region above); not the running thread here.
                    crate::sched::wait_until_off_cpu(tcb);

                    // After eager FPU save (#108), no fpu_owner sweep is
                    // needed: `nm_handler` only ever names the currently
                    // Running thread on its CPU, and `switch_out_save`
                    // clears the slot on switch-out — so by the time the
                    // not-`current`-anywhere and `context_saved` spins above
                    // have completed, no CPU's owner slot can name this TCB.
                }

                // Wake the captured reply-bound client outside the all-locks
                // region. The client is still Blocked (we deposited its
                // disposition above but did NOT pre-set Ready), so the gated
                // enqueue_and_wake links it under the client's own sched_lock —
                // and if a concurrent dealloc(client) already won the reap, the
                // gate observes Exited and aborts the link instead of resurrecting
                // a freed TCB. wake_in_flight (set above) kept the client alive
                // until here and is cleared on every enqueue_and_wake exit path.
                if let Some(bound) = server_reply_wake
                {
                    // #317 predecessor-of-free null: clear the claimed client's
                    // `blocked_on_object` (which still points at THIS dying server,
                    // `tcb`) under the CLIENT's sched_lock, BEFORE enqueue_and_wake.
                    // This is the strict predecessor of retype_free that the
                    // cancel_ipc_block / dealloc(client) CLOSURE LEMMA relies on: a
                    // withdrawer reading `blocked_on == server` under the client
                    // sched_lock thereby proves the server is not yet freed. It MUST
                    // run here, while `bound` is still pinned by wake_in_flight = 1
                    // (set at the claim above): for an Exited `bound` (a concurrent
                    // dealloc(client) won the reap) enqueue_and_wake takes its Exited
                    // arm and does NOT null blocked_on, and clearing wake_in_flight
                    // there would unblock that dealloc(client) to retype_free `bound`
                    // — so the null must precede the wake. Only the client's
                    // sched_lock is taken (the server's was released with the all-CPU
                    // locks above), so there is no two-TCB-sched_lock nesting.
                    // SAFETY: bound kept valid by wake_in_flight = 1 above.
                    unsafe {
                        let bs = (*bound).sched_lock.lock_raw();
                        if core::ptr::eq((*bound).blocked_on_object, tcb.cast::<u8>())
                        {
                            (*bound).blocked_on_object = core::ptr::null_mut();
                        }
                        (*bound).sched_lock.unlock_raw(bs);
                    }
                    // Recompute the wake target HERE (post-gates), under the
                    // client's current state, EXCLUDING this dealloc CPU. This
                    // CPU is wedged in the preempt-disabled UAF gates above, not
                    // in schedule(), so it cannot dispatch a client linked onto
                    // it — the save-window pin would strand a `context_saved==0`
                    // client here (#351). A peer dispatches it safely via the
                    // schedule() publication-barrier spin. Recomputing at wake
                    // time (rather than snapshotting under the all-CPU locks
                    // above) also closes the double-enqueue straddle: the target
                    // reflects the state at link time, not two unbounded spins
                    // earlier (#289).
                    let this_cpu = crate::arch::current::cpu::current_cpu() as usize;
                    // SAFETY: bound kept valid by wake_in_flight = 1 above;
                    // select_target_cpu_excluding is lock-free.
                    let bcpu =
                        unsafe { crate::sched::select_target_cpu_excluding(bound, Some(this_cpu)) };
                    // G1: the reply-wake is never self-pinned to the wedged
                    // dealloc CPU unless hard affinity names it or it is the only
                    // CPU.
                    debug_assert!(
                        bcpu != this_cpu
                            || crate::sched::CPU_COUNT
                                .load(core::sync::atomic::Ordering::Relaxed)
                                == 1
                            // SAFETY: bound valid (pinned by wake_in_flight).
                            || unsafe { (*bound).cpu_affinity } != crate::sched::AFFINITY_ANY,
                        "dealloc reply-wake self-pinned to dealloc cpu {this_cpu}",
                    );
                    // SAFETY: bound kept valid by wake_in_flight = 1 above.
                    unsafe { crate::sched::enqueue_and_wake(bound, bcpu) };
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
                                // blocked_obj is the server TCB. CAS-clear the
                                // server's reply slot iff this dying client is still
                                // bound. Same #317 hazard as cancel_ipc_block: a
                                // concurrent dealloc(server) could free the server
                                // under this deref. Guard it with THIS dying client's
                                // sched_lock + a `blocked_on == server` re-read — the
                                // CLOSURE LEMMA pins the server alive across the CAS
                                // (dealloc(server) nulls a claimed client's
                                // blocked_on under the same client sched_lock before
                                // retype_free). Only this client's sched_lock is held;
                                // the reply_tcb CAS on the server is wait-free.
                                use core::sync::atomic::Ordering;
                                let server =
                                    blocked_obj.cast::<crate::sched::thread::ThreadControlBlock>();
                                let saved = (*tcb).sched_lock.lock_raw();
                                if core::ptr::eq((*tcb).blocked_on_object, blocked_obj)
                                {
                                    // Win ⇒ we cancelled the reply wake; clear
                                    // wake_in_flight so the #160 gate below does not
                                    // wait for a wake that will never fire. Lose ⇒ a
                                    // reply is in flight and its enqueue_and_wake
                                    // clears the flag; the gate waits for it.
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
                                (*tcb).sched_lock.unlock_raw(saved);
                            }
                            IpcThreadState::BlockedOnFault =>
                            {
                                // A dying fault-blocked thread: `blocked_obj` is its
                                // handler (server) TCB. CAS-clear the handler's reply
                                // slot so a later reply does not target this freed
                                // faulter. Mirrors the BlockedOnReply arm including
                                // the #317 client-sched_lock guard; the faulter never
                                // resumes, so no disposition is recorded.
                                use core::sync::atomic::Ordering;
                                let server =
                                    blocked_obj.cast::<crate::sched::thread::ThreadControlBlock>();
                                let saved = (*tcb).sched_lock.lock_raw();
                                if core::ptr::eq((*tcb).blocked_on_object, blocked_obj)
                                {
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
                                (*tcb).sched_lock.unlock_raw(saved);
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

                // Remove this thread from the global sleep list before the
                // wake-in-flight gate below. A plain sleeper (sys_thread_sleep) or
                // a timed IPC waiter sits on the list as a raw TCB pointer; freeing
                // without removing it would let the next timer tick dereference the
                // freed pointer in sleep_check_wakeups. The remove races that pop
                // under SLEEP_LIST_LOCK: if we win, the entry is gone and no timer
                // wake fires; if the timer already popped it, the timer set
                // wake_in_flight = 1 at pop (under the same lock), so the gate
                // below waits for that wake to commit before the free. Placed
                // OUTSIDE the all-locks region — no sched.lock → SLEEP_LIST_LOCK
                // order edge (the timer takes SLEEP_LIST_LOCK first, then releases
                // it before any sched_lock).
                crate::sched::sleep_list_remove(tcb);

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
                crate::sched::spin_site_enter(crate::sched::SPIN_SITE_DEALLOC_WAKE_IN_FLIGHT);
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
                crate::sched::spin_site_exit();
                // SAFETY: wake_saved_int from save_and_disable_interrupts above.
                unsafe { crate::arch::current::cpu::restore_interrupts(wake_saved_int) };
                crate::percpu::preempt_enable();

                // Release the per-thread IOPB to SEED if one was bound via
                // `sys_ioport_bind` (x86-64 only). RISC-V threads never set this
                // field — there is no I/O port space — so `iopb` is always null
                // and this is a no-op there.
                // SAFETY: tcb validated non-null; iopb field always valid.
                let iopb_ptr = unsafe { (*tcb).iopb };
                if !iopb_ptr.is_null()
                {
                    crate::cap::retype::free_seed_scratch(
                        iopb_ptr.cast::<u8>(),
                        crate::arch::current::IOPB_SIZE as u64,
                    );
                    // SAFETY: tcb validated non-null.
                    unsafe {
                        (*tcb).iopb = core::ptr::null_mut();
                    }
                }

                // The per-thread XSAVE / FP-save area is page N+1 of the
                // Thread retype slot (see sys_cap_create_thread layout); it
                // is reclaimed wholesale by `retype_free` below as part of
                // the same slot release, so no separate free is needed.

                // Remove the TCB from the live-thread registry before
                // poisoning/freeing it. Both registry walks hold the registry
                // lock across every dereference, so unlinking strictly before
                // the free guarantees neither the watchdog nor an object
                // teardown observes a dangling node.
                // SAFETY: tcb valid (not yet freed); the registry lock is the
                // outermost lock and nothing is held here.
                unsafe { crate::sched::thread_registry::unregister(tcb) };

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
                // ── Stop bound threads ──
                // Same discipline as the CSpace arm: every thread bound to
                // this address space is marked Exited and waited off-CPU
                // before its root page table is freed, so no CPU can run in
                // it afterwards. Objects of the stopped threads are freed
                // when their own last caps go. If the running thread is
                // itself stopped — bound here, or by a concurrent teardown
                // — the free is deferred off-CPU (see push_deferred_reclaim).
                // SAFETY: as_ptr uniquely owned (refcount 0); no scheduler,
                // IPC, or registry lock is held here.
                let stopped = unsafe {
                    crate::sched::stop_threads_bound_to(|tcb| {
                        core::ptr::eq((*tcb).address_space, as_ptr)
                    })
                };
                // SAFETY: as_ptr valid; every bound thread is Exited and
                // off every run queue; no scheduler lock held.
                if stopped || !unsafe { crate::sched::wait_until_aspace_inactive(as_ptr) }
                {
                    // SAFETY: refcount 0, no slot references the object; the
                    // running thread is `Exited`, which rules out the idle
                    // drain (see defer_self_teardown), so this is the syscall
                    // path with interrupts disabled.
                    unsafe { defer_self_teardown(ptr, "AddressSpace") };
                    return;
                }

                // No CPU still has this address space loaded in satp/CR3
                // (waited for above), so the root page table can go.
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
        // are scrubbed by [`drain_dying_cspace_batch`]. Combined with the
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
                // ── Stop bound threads ──
                // Every thread bound to this CSpace is marked Exited and
                // waited off-CPU before anything below runs: no thread can
                // be mid-syscall against these slot pages when they are
                // freed, and none can wire derivation links during the drain.
                // Their objects are freed when their own last caps go — in
                // the dec_ref cascade below if those caps live here. If the
                // running thread is itself stopped — it is destroying its
                // own CSpace, or a concurrent teardown stopped it — nothing
                // is freed now: the object is queued for off-CPU reclaim
                // and the syscall epilogue schedules the thread away.
                // SAFETY: cs_ptr uniquely owned (refcount 0); no scheduler,
                // IPC, or registry lock is held here.
                let stopped = unsafe {
                    crate::sched::stop_threads_bound_to(|tcb| core::ptr::eq((*tcb).cspace, cs_ptr))
                };
                if stopped
                {
                    // SAFETY: refcount 0, no slot references the object; the
                    // running thread is `Exited`, which rules out the idle
                    // drain (see defer_self_teardown), so this is the syscall
                    // path with interrupts disabled.
                    unsafe { defer_self_teardown(ptr, "CSpace") };
                    return;
                }

                // SAFETY: cs_ptr non-null; allocated at creation.
                let id = unsafe { (*cs_ptr).id() };
                dying_id = id;
                let dying_epoch = crate::cap::registry_epoch(id);

                // ── Batched pre-unregister derivation drain ──
                // DERIVATION_LOCK is held per batch (bounded by
                // MAX_DRAIN_EDITS steps — slots visited plus link edits),
                // released between batches so
                // an arbitrarily large donor-funded CSpace never stalls
                // concurrent derivation traffic behind its teardown.
                // `unregister_cspace` runs inside the FINAL batch's
                // critical section so any concurrent foreign reader sees a
                // consistent "drained, then absent" transition.
                //
                // The lock MUST be released BEFORE the `for_each_object`
                // dec_ref cascade below: a slot in the dying CSpace may hold
                // a CSpace cap whose dec_ref drives a nested
                // `dealloc_object(CSpaceObj)` call, which would re-enter
                // this same non-recursive lock and deadlock. The drain
                // already removed every foreign link before this point, so
                // the dec_ref cascade has no derivation-tree work to do —
                // releasing is safe.
                let mut drain_cursor: u32 = 0;
                loop
                {
                    crate::cap::derivation::DERIVATION_LOCK.write_lock();
                    // SAFETY: DERIVATION_LOCK held; cs_ptr uniquely owned at
                    // refcount=0; registry entry still live (unregister
                    // below, in the final batch's hold).
                    let done = unsafe {
                        drain_dying_cspace_batch(cs_ptr, id, dying_epoch, &mut drain_cursor)
                    };
                    if done
                    {
                        crate::cap::unregister_cspace(id);
                        crate::cap::derivation::DERIVATION_LOCK.write_unlock();
                        break;
                    }
                    crate::cap::derivation::DERIVATION_LOCK.write_unlock();
                }

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
            // is reclaimed and DERIVATION_LOCK is released. Randomizing the
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
            // `header.ancestor` names the source Memory object (every Endpoint
            // is retype-backed): the blocked-queue and wait-set teardown runs,
            // then the slot is reclaimed to it.
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
                // SAFETY: state validated non-null. The drain runs under ep.lock:
                // a concurrent dealloc(waiter) BlockedOnSend/Recv unlink takes the
                // same lock, so it cannot mutate these queues or free a waiter
                // mid-walk, and the per-waiter wake_in_flight = 1 set here (the
                // #160 discipline) makes any dealloc(waiter) that already left the
                // queue wait at its wake-in-flight gate for our enqueue_and_wake
                // rather than free the TCB under it. Lock order ep.lock (source) →
                // sched_lock → run-queue lock is canonical, so holding ep.lock
                // across enqueue_and_wake is deadlock-free.
                unsafe {
                    let ep = &mut *state;
                    let saved = ep.lock.lock_raw();
                    // Wake senders. enqueue_and_wake commits the state
                    // transitions under sched_lock; we only detach the
                    // intrusive list pointers here.
                    let mut tcb = ep.send_head;
                    while !tcb.is_null()
                    {
                        let next = (*tcb).ipc_wait_next;
                        (*tcb).ipc_wait_next = None;
                        // The whole-queue detach under ep.lock is the episode
                        // claim. A queued fault sender (its handler never
                        // received) must kill, not resume, when woken: its
                        // resume runs the fault helper, which reads
                        // `fault_outcome`. A normal caller gets INTERRUPTED so
                        // its `sys_ipc_call` resume takes the error path
                        // instead of failing the no-deposit episode tripwire.
                        // Covers the unbind-drops-last-ref liveness case
                        // (fault-handling.md § Liveness rule 3).
                        crate::sched::thread::stamp_cancelled_deposit(
                            tcb,
                            (*tcb).in_fault_delivery,
                        );
                        // Claim for wake under ep.lock (#160). Cleared by
                        // enqueue_and_wake.
                        (*tcb)
                            .wake_in_flight
                            .store(1, core::sync::atomic::Ordering::Release);
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
                        // The queue detach under ep.lock is the episode claim:
                        // stamp INTERRUPTED so the woken server's recv resume
                        // returns the error instead of publishing a stale
                        // ipc_msg into its userspace buffer as a success.
                        crate::sched::thread::stamp_park_deposit(
                            tcb,
                            crate::sched::thread::PARK_DISPOSITION_INTERRUPTED,
                        );
                        // Claim for wake under ep.lock (#160). Cleared by
                        // enqueue_and_wake.
                        (*tcb)
                            .wake_in_flight
                            .store(1, core::sync::atomic::Ordering::Release);
                        let target_cpu = crate::sched::select_target_cpu(tcb);
                        crate::sched::enqueue_and_wake(tcb, target_cpu);
                        tcb = next.unwrap_or(core::ptr::null_mut());
                    }
                    ep.recv_head = core::ptr::null_mut();
                    ep.recv_tail = core::ptr::null_mut();
                    ep.lock.unlock_raw(saved);
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
                // arm above (which frees the buddy pages).
                push_ancestor(worklist, head, ancestor_nn);
            }
        }

        // ── Notification ────────────────────────────────────────────────────────
        ObjectType::Notification =>
        {
            // `header.ancestor` names the source Memory object the slot returns to.
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
                // SAFETY: state validated non-null. Claim the waiter under sig.lock
                // — the #160 discipline notification_send uses — so a concurrent
                // dealloc(waiter) BlockedOnNotification unlink (which takes sig.lock
                // and spins on wake_in_flight) cannot free the TCB before our
                // enqueue_and_wake commits.
                unsafe {
                    let sig = &mut *state;
                    let saved = sig.lock.lock_raw();
                    let waiter = sig.waiter;
                    if !waiter.is_null()
                    {
                        sig.waiter = core::ptr::null_mut();
                        // wakeup_value=0 = drop semantics; state transitions
                        // committed by enqueue_and_wake. Claim for wake under
                        // sig.lock (#160); cleared by enqueue_and_wake.
                        (*waiter).wakeup_value = 0;
                        (*waiter)
                            .wake_in_flight
                            .store(1, core::sync::atomic::Ordering::Release);
                        // A timed waiter is also on the sleep list; drop the
                        // entry under sig.lock (the #117 remove-before-clear
                        // order) so the timer can neither double-wake it nor
                        // hijack a later unrelated park via the stale entry.
                        // Mirrors notification_send's claim.
                        if (*waiter).sleep_deadline != 0
                        {
                            crate::sched::sleep_list_remove(waiter);
                            (*waiter).sleep_deadline = 0;
                        }
                    }
                    sig.lock.unlock_raw(saved);
                    if !waiter.is_null()
                    {
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

/// Maximum derivation-link edits per `DERIVATION_LOCK` hold while draining
/// a dying `CSpace` (mirrors `MAX_REVOKE_EDITS`): teardown of an
/// arbitrarily large donor-funded `CSpace` releases the global lock
/// between batches, so concurrent derivation traffic never stalls behind
/// more than a constant amount of drain work.
#[cfg(not(test))]
const MAX_DRAIN_EDITS: usize = 256;

/// Drain one batch of a dying `CSpace`'s derivation state.
///
/// Processes populated slots from `*cursor` upward. Per slot:
///
/// 1. **Unlink every child**, head-first (`unlink_node` on
///    `deriv_first_child` until the list is empty; one edit each, O(1)
///    per edit — no list walking). A foreign child becomes a derivation
///    root of its own subtree; a child in the dying `CSpace` becomes a
///    parentless dying node, unlinked from *its* children when the cursor
///    reaches its own index.
/// 2. **Unlink the slot** from its parent/sibling links (`unlink_node`) —
///    neighbours, live or dying, are re-linked directly. The head-pops in
///    step 1 already left `deriv_first_child` at `None`.
///
/// Because every unlink re-links the neighbours directly, the forest is
/// fully consistent after each edit — unlike a splice-then-clear two-pass
/// drain, no state depends on a later pass. The caller may therefore
/// release `DERIVATION_LOCK` between batches: a foreign traversal in the
/// window (a revoke hoist, a transfer repoint) sees ordinary consistent
/// nodes, and may even revoke a not-yet-drained dying slot — the drain
/// then skips it as Null and the object refcount is settled once (revoke
/// dec-refs it; the post-drain `for_each_object` pass skips Null slots).
///
/// The batch loop's progress: every edit removes one link, and the
/// head-pop's no-progress containment truncates any unresolvable or
/// cyclic chain instead of spinning. Work can still arrive between holds
/// — the `CSpace` stays registered until the final batch, so a foreign
/// `SYS_CAP_DELETE` of a slot whose parent is a dying slot reparents that
/// slot's children into the dying slot, and a surviving thread of the
/// owning process can derive out of the dying `CSpace` via its TCB
/// pointer or have an in-flight `ipc_recv` delivery land caps into it.
/// Each such event adds at most one reparent batch of work while the
/// drain removes a batch per hold, so the loop is bounded by lock
/// contention rather than by a constant, and it carries no batch backstop
/// (a teardown cannot fail): a holder of capabilities derived from the
/// dying `CSpace` can prolong the teardown for as long as it keeps
/// deleting, which stalls the deleting thread, not the system. Links
/// wired behind the cursor dangle once the `CSpace` unregisters and
/// surface downstream as dead-link truncation, in the drain's own
/// containment or `revoke_subtree_batch`'s — contained, and in the
/// owning-process case reachable only by the dying process harming
/// itself. The end state otherwise matches the previous whole-drain
/// design: no slot anywhere references the dying `CSpace`, which is the
/// invariant `free_cspace_id` recycling relies on.
///
/// Returns `true` once the whole `CSpace` is drained; `false` when the
/// step budget ran out (call again — the cursor resumes at the same
/// slot). Every slot visited and every link edit is one step, so a hold
/// is bounded by `MAX_DRAIN_EDITS` whatever the population.
///
/// ## Aliasing avoidance
///
/// No borrow into `cs_ptr` is held across foreign-slot accesses: reads of
/// the dying slot go through brief `(*cs_ptr).slot(..)` scopes, and all
/// link edits go through `unlink_node`, which resolves every slot it
/// touches via fresh registry lookups.
///
/// # Safety
///
/// Caller MUST hold `DERIVATION_LOCK` write lock. `cs_ptr` MUST be a
/// valid `CSpace` pointer whose refcount has reached zero (exclusive
/// ownership). The registry entry for `dying_id` MUST still be live —
/// `unregister_cspace` runs only after the final batch, in the same
/// critical section, so foreign readers see a consistent
/// "drained, then absent" transition.
#[cfg(not(test))]
unsafe fn drain_dying_cspace_batch(
    cs_ptr: *mut crate::cap::cspace::CSpace,
    dying_id: crate::cap::slot::CSpaceId,
    dying_epoch: u32,
    cursor: &mut u32,
) -> bool
{
    use crate::cap::cspace::L2_SIZE;
    use crate::cap::derivation::{truncate_dead_link, unlink_node};
    use crate::cap::slot::{CapTag, SlotId};
    use core::num::NonZeroU32;

    // Leaves are contiguous behind the grow cursor; leaf_count bounds the
    // slot range exactly.
    // SAFETY: cs_ptr is uniquely owned (refcount = 0).
    let slot_count = (unsafe { (*cs_ptr).leaf_count() } * L2_SIZE) as u32;
    let mut edits = 0usize;

    while *cursor < slot_count
    {
        let global_idx = *cursor;
        // Every slot visited counts against the budget like a link edit, so
        // a hold over a large but sparsely populated `CSpace` stays bounded.
        if edits >= MAX_DRAIN_EDITS
        {
            return false;
        }
        let Some(idx_nz) = NonZeroU32::new(global_idx)
        else
        {
            // Slot 0 is permanently null.
            *cursor += 1;
            edits += 1;
            continue;
        };
        // SAFETY: brief immutable borrow; dropped at the end of the call.
        let populated =
            unsafe { (*cs_ptr).slot(global_idx) }.is_some_and(|s| s.tag != CapTag::Null);
        if !populated
        {
            *cursor += 1;
            edits += 1;
            continue;
        }
        let self_id = SlotId::with_epoch(dying_id, dying_epoch, idx_nz);

        // 1. Unlink every child, head-first: each head pop is one O(1)
        //    edit (the head's unlink rewrites this slot's
        //    `deriv_first_child` to the next child — no list walking), so
        //    the edit budget bounds the hold's real work exactly.
        loop
        {
            if edits >= MAX_DRAIN_EDITS
            {
                // Budget exhausted mid-slot; the caller re-enters with the
                // cursor still naming this slot.
                return false;
            }
            // SAFETY: brief immutable borrow of the dying slot.
            let Some(head) =
                unsafe { (*cs_ptr).slot(global_idx) }.and_then(|s| s.deriv_first_child)
            else
            {
                break;
            };
            // SAFETY: DERIVATION_LOCK held; unlink_node resolves every slot
            // it touches via fresh registry lookups (occupancy-gated) and
            // clears the child's parent link.
            unsafe { unlink_node(head) };
            edits += 1;
            // No-progress containment: an unresolvable head (dead link, or
            // a stale/cyclic chain) makes unlink_node a no-op and would
            // otherwise pin the pop loop forever. Truncate the chain
            // hanging from it — the same containment revocation applies to
            // a dead link — and move on.
            // SAFETY: brief borrows of the dying slot.
            let still_head =
                unsafe { (*cs_ptr).slot(global_idx) }.and_then(|s| s.deriv_first_child);
            if still_head == Some(head)
            {
                // SAFETY: DERIVATION_LOCK held; self_id names an occupied
                // slot of a CSpace that stays registered until the final
                // batch.
                unsafe { truncate_dead_link(self_id, head, "teardown drain") };
                break;
            }
        }

        if edits >= MAX_DRAIN_EDITS
        {
            return false;
        }

        // 2. Unlink this slot from its parent/sibling dimension. Step 1
        //    left its child pointer at None.
        // SAFETY: DERIVATION_LOCK held (see above).
        unsafe { unlink_node(self_id) };
        edits += 1;

        *cursor += 1;
    }
    true
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use core::mem::offset_of;

    // Header MUST sit at offset 0 in every concrete object type: the kernel casts
    // *mut ConcreteObject to *mut KernelObjectHeader to read the refcount and type
    // generically, which is sound only if the header is the first field.
    #[test]
    fn concrete_object_headers_at_offset_zero()
    {
        assert_eq!(offset_of!(MemoryObject, header), 0);
        assert_eq!(offset_of!(MmioObject, header), 0);
        assert_eq!(offset_of!(InterruptObject, header), 0);
        assert_eq!(offset_of!(IoPortObject, header), 0);
        assert_eq!(offset_of!(SchedControlObject, header), 0);
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
