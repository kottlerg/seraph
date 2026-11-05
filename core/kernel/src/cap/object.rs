// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/cap/object.rs

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
//! (the root `CSpace`, which is init's `CSpace`, and init's `AddressSpace`
//! and `Thread`) and the Phase-7 boot-time identity wrappers are retyped from the SEED reserve
//! (`boot_retype_*`, `mint_phase7_body`) and carry the SEED ancestor. The
//! bodies a split or an `Mmio`, `IoPort`, or `Interrupt` copy creates at
//! runtime are chunks of
//! the receiving `CSpace`'s body arena ([`CSpaceKernelObject::alloc_body`]) and
//! carry the arena page that holds them ([`ArenaPage`]) as their ancestor.
//!
//! Deallocation: read `header.obj_type` from the raw pointer, drop the
//! object in place, and return its bytes to its ancestor: `retype_free`
//! against the ancestor `MemoryObject`, or, for an arena body, the chunk back
//! to the arena page ([`ArenaPage`]) its ancestor names.
//!
//! ## Layout
//!
//! Compile-time assertions cover each wrapper page — an `AddressSpaceObject`
//! followed by its in-place `AddressSpace`, a `CSpaceKernelObject` followed
//! by its inline `CSpace` — fitting one page, a `RecordPage` fitting one
//! page, and its records starting at `RECORD_PAGE_HEADER`. The header and
//! sub-page object sizes the retype bins depend on are asserted in
//! `core/kernel/src/cap/retype.rs`.

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
    /// The header of a `CSpace` body-arena page ([`ArenaPage`]); never in a
    /// capability slot.
    ArenaPage = 13,
}

// ── KernelObjectHeader ────────────────────────────────────────────────────────

/// Common header at offset 0 of every kernel object.
///
/// `ref_count` counts the capability slots and the kernel-internal owners
/// that hold this object (see core/kernel/docs/capability-internals.md
/// § Kernel Object Reference Counting). When `dec_ref` returns 0, no holder
/// remains and `dealloc_object` frees it, dispatching on `obj_type`.
///
/// `ancestor` is a direct pointer to the `MemoryObject`'s header from which
/// this object was retyped. Auto-reclaim consults this on `dec_ref → 0` to
/// credit bytes back to the source `MemoryObject` and return the object's
/// region to the per-Memory-cap allocator.
///
/// A direct pointer (rather than a `SlotId`) is necessary because the source
/// Memory cap's *slot* may be deleted before all retyped descendants are freed
/// — the `MemoryObject` itself stays alive via the refcount bump that retype
/// performs, but the slot index becomes `Null` as soon as `cap_delete` runs
/// on the source. Reclaim must reach the live object regardless of slot
/// state. No syscall exposes the ancestor.
///
/// `#[repr(C)]` with size 16 B, alignment 8. All concrete object structs
/// place this as their first field so pointer casts are safe.
#[repr(C)]
pub struct KernelObjectHeader
{
    /// Reference count; starts at 1 when created. Bounded by
    /// [`REF_COUNT_LIMIT`] for the references userspace can multiply. While
    /// the object waits on a dealloc cascade ([`CascadeStack`]) its count is
    /// 0 and this field holds the low 32 bits of the stack link instead.
    pub ref_count: AtomicU32,
    /// Concrete type, for use during deallocation.
    pub obj_type: ObjectType,
    /// The high 24 bits of the dealloc-cascade link ([`CascadeStack`]) while
    /// the object is queued on one, and zero at every other time. The bytes
    /// also pad the header to 8-byte alignment for `ancestor`. Public because
    /// mint sites outside this module build the header by struct literal.
    pub cascade_link_hi: [u8; 3],
    /// Pointer to the `MemoryObject`'s header this object was retyped from;
    /// every production object has one (null only in host tests). Set once at
    /// creation, read at deallocation. `AtomicPtr` for the unforgeable null
    /// sentinel without imposing const-init constraints on construction.
    pub ancestor: AtomicPtr<KernelObjectHeader>,
}

/// Ceiling on [`KernelObjectHeader::ref_count`] for the references userspace
/// can multiply without a bound of its own: a new capability slot (copy,
/// derive, badged derive, a move's destination) refuses at it, and so do a
/// retype from a Memory object whose count is at it and a death-observer bind
/// onto an `EventQueue` whose count is at it (its creator funds any number of
/// observer nodes).
///
/// The value is correct as is, not a limit a workload meets: every
/// userspace-amplifiable reference costs a 72-byte capability slot, a retype
/// child of at least 128 bytes, or a 24-byte death-observer node, so 2^31
/// references to one object hold at least 48 GiB against that single object,
/// which no workload does, and reaching the
/// ceiling refuses the request with `QuotaExceeded` instead of wrapping the
/// count and freeing a live object.
///
/// A move's destination slot takes its reference through the same check (a
/// move its liveness backstop abandons leaves that slot live beside the
/// source); an IPC transfer checks every cap of its message before its first
/// move and then takes the destinations' references unchecked.
///
/// The ceiling leaves 2^31 of headroom below `u32::MAX` for every other
/// reference, which the kernel takes unchecked. Each of those is bounded by an
/// object count, not by a caller's request. Per thread: its syscall pins (a
/// few), its fault-handler binding (one), the lease of a retype it has in flight
/// that passed `retype_allocate`'s check before another took the count to the
/// ceiling (one), and the destinations of an IPC transfer it has in flight that
/// passed the message check (at most `MSG_CAP_SLOTS_MAX`, four); fewer than 16
/// in all. Per other object: wait-set membership (one per source), Mmio mapping
/// records (each 16 bytes of a caller-funded body or spill chunk, so 2^31 of
/// them hold 32 GiB), SEED leases (the boot mints, bounded by the SEED reserve),
/// an arena page's chunk references (at most 31, its chunks), the leases of the
/// arena pages a dead `CSpace` keeps (at most one per page of the donation each
/// lies in), and the destinations IPC transfers' abandoned moves leave
/// live: a message check refuses once the count is at the ceiling, and
/// transfers run one at a time under `DERIVATION_LOCK`, so these keep an
/// object's slot references within `MSG_CAP_SLOTS_MAX - 1` of the ceiling.
/// Exhausting the headroom would take some 2^27 threads, each with its own
/// kernel stack and TCB (at least 2 TiB of kernel stacks), so the count cannot
/// wrap (core/kernel/docs/capability-internals.md § Kernel Object Reference
/// Counting).
pub const REF_COUNT_LIMIT: u32 = 1 << 31;

// SAFETY: ancestor is a back-pointer to a kernel object whose lifetime is
// guaranteed by retype's refcount semantics. Send+Sync via the surrounding
// object's existing locking discipline.
unsafe impl Send for KernelObjectHeader {}
// SAFETY: see Send impl above.
unsafe impl Sync for KernelObjectHeader {}

impl KernelObjectHeader
{
    /// Construct a new header with `ref_count = 1` and no ancestor yet.
    ///
    /// Used by host tests; for a body a `CSpace`'s arena funds, whose
    /// ancestor [`CSpaceKernelObject::alloc_body`] stamps; and for an
    /// [`ArenaPage`] header, whose ancestor its `CSpace`'s teardown sets if it
    /// keeps the page. Every other production object is retyped and uses
    /// [`Self::with_ancestor`] to record the source `MemoryObject` for
    /// auto-reclaim.
    pub fn new(obj_type: ObjectType) -> Self
    {
        Self {
            ref_count: AtomicU32::new(1),
            obj_type,
            cascade_link_hi: [0; 3],
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
            cascade_link_hi: [0; 3],
            ancestor: AtomicPtr::new(ancestor.as_ptr()),
        }
    }

    /// Increment the reference count for an owner whose number is bounded
    /// below the headroom above [`REF_COUNT_LIMIT`]: a syscall pin, a binding,
    /// a mapping record, a boot mint's SEED lease, a chunk's reference on its
    /// [`ArenaPage`] (at most 31 per page), a kept arena page's lease on its
    /// donation's Memory object (one per page of that donation), or the lease of a retype that
    /// [`crate::cap::retype::retype_allocate`] admitted (see
    /// core/kernel/docs/capability-internals.md § Kernel Object Reference
    /// Counting), or an IPC transfer's move destination, whose message
    /// [`crate::cap::transfer::check_transfer_ref_limits`] checked first. Every
    /// other new capability slot, a `SYS_CAP_MOVE` destination included, takes
    /// its reference through [`Self::try_inc_ref`] instead.
    pub fn inc_ref(&self)
    {
        let prev = self.ref_count.fetch_add(1, Ordering::Relaxed);
        debug_assert!(
            prev < u32::MAX,
            "inc_ref overflow: obj_type={:?} self={:p}",
            self.obj_type,
            self,
        );
    }

    /// Increment the reference count unless it has reached
    /// [`REF_COUNT_LIMIT`]. The path for references whose number userspace
    /// can grow without a bound of its own: new capability slots.
    ///
    /// # Errors
    ///
    /// `QuotaExceeded` when the count is at the limit; the count is left
    /// unchanged.
    pub fn try_inc_ref(&self) -> Result<(), syscall::SyscallError>
    {
        let mut cur = self.ref_count.load(Ordering::Relaxed);
        loop
        {
            if cur >= REF_COUNT_LIMIT
            {
                return Err(syscall::SyscallError::QuotaExceeded);
            }
            match self.ref_count.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            {
                Ok(_) => return Ok(()),
                Err(actual) => cur = actual,
            }
        }
    }

    /// Whether the count has reached [`REF_COUNT_LIMIT`], so a new
    /// userspace-amplifiable reference must be refused.
    pub fn at_ref_limit(&self) -> bool
    {
        self.ref_count.load(Ordering::Relaxed) >= REF_COUNT_LIMIT
    }

    /// Decrement the reference count and return the new value.
    ///
    /// Returns 0 when no capability slot or kernel-internal owner still holds
    /// the object (see core/kernel/docs/capability-internals.md § Kernel Object
    /// Reference Counting); the caller is responsible for freeing the object at
    /// that point. The decrement is a Release, and the one that reaches 0 is
    /// followed by an Acquire fence, so that freer observes every write the
    /// other owners made before releasing theirs.
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
        if prev == 1
        {
            // The last release: pair the Release decrements of every other
            // owner with an Acquire, so the caller that frees the object
            // observes every write those owners made before releasing.
            core::sync::atomic::fence(Ordering::Acquire);
        }
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
    /// Initialised to `size` for every Memory cap minted with `MemRights::RETYPE`:
    /// RAM, boot-module, init-segment, `InitInfo`/stack, and reclaimed boot-scratch
    /// caps. Set to `0` for firmware-table caps (ACPI regions, RSDP, DTB), which
    /// mint without `Retype` (docs/capability-model.md § Memory) and never take
    /// part in retype or auto-reclaim.
    /// `retype_allocate` debits this; `dealloc_object` auto-reclaim credits
    /// it back.
    pub available_bytes: AtomicU64,
    /// `true` if this Memory cap is responsible for returning `[base, base + size)`
    /// to the buddy allocator on final destruction. Buddy-backed RAM caps and the
    /// boot-module, init-segment, `InitInfo`/stack, and reclaim-range caps set it at
    /// creation. Firmware-table caps (ACPI regions, RSDP, DTB) leave it `false`.
    ///
    /// `sys_memory_split` leaves the parent's flag intact; the new
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
    /// mutated. Lock order: see core/kernel/docs/scheduling-internals.md
    /// § Lock Hierarchy, "Bare spin locks".
    pub lock: AtomicU32,
    /// Number of capability slots, in every `CSpace`, that name this object:
    /// raised when a slot is filled with it ([`MemoryObject::note_slot_filled`])
    /// and lowered when such a slot is freed or its dying `CSpace` releases it
    /// ([`MemoryObject::note_slot_released`]). Unlike `header.ref_count` it
    /// counts no retype lease, donation, or syscall pin. A slot that names an
    /// existing object is filled, and an occupied slot freed, only under
    /// `DERIVATION_LOCK` for writing (core/kernel/docs/capability-internals.md
    /// § Global Derivation Lock), so a reader holding that lock sees a count
    /// no other path can raise; a dying `CSpace`'s release, the one decrement
    /// outside it, can only lower it. `sys_memory_split` and
    /// `sys_memory_merge` refuse an object whose count is above one, since
    /// resizing it would change what another slot names.
    pub slot_count: AtomicU32,
}

/// Sentinel encoding a held write lock in [`MemoryObject::lock`]. Matches
/// `DerivationLock`'s convention. A reader count cannot reach it: a holder is
/// never descheduled (core/kernel/docs/scheduling-internals.md § Lock
/// Hierarchy), so readers are at most one per CPU.
const FRAME_WRITE_LOCKED: u32 = u32::MAX;

impl MemoryObject
{
    /// Count a capability slot just filled with the Memory object `object`
    /// ([`MemoryObject::slot_count`]).
    ///
    /// # Safety
    /// `object` must be the header of a live `MemoryObject` that the filled
    /// slot now names.
    pub unsafe fn note_slot_filled(object: NonNull<KernelObjectHeader>)
    {
        // SAFETY: caller contract; the header is at offset 0 of MemoryObject.
        // cast_ptr_alignment: a MemoryObject is 8-byte aligned wherever it is
        // placed, and holds the header at offset 0.
        #[allow(clippy::cast_ptr_alignment)]
        let memory = unsafe { &*object.as_ptr().cast::<MemoryObject>() };
        memory.slot_count.fetch_add(1, Ordering::AcqRel);
    }

    /// Uncount a capability slot that named the Memory object `object` and is
    /// being freed, or whose dying `CSpace` releases it
    /// ([`MemoryObject::slot_count`]).
    ///
    /// # Safety
    /// `object` must be the header of a live `MemoryObject` that the released
    /// slot names, counted by [`Self::note_slot_filled`] when it was filled.
    pub unsafe fn note_slot_released(object: NonNull<KernelObjectHeader>)
    {
        // SAFETY: caller contract; the header is at offset 0 of MemoryObject.
        // cast_ptr_alignment: as in `note_slot_filled`.
        #[allow(clippy::cast_ptr_alignment)]
        let memory = unsafe { &*object.as_ptr().cast::<MemoryObject>() };
        let before = memory.slot_count.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(before > 0, "MemoryObject slot_count underflow");
    }

    /// Whether no capability slot but the caller's names this object
    /// ([`MemoryObject::slot_count`]). Exact while the caller holds
    /// `DERIVATION_LOCK` for writing and its own slot is revalidated under it.
    pub fn named_by_one_slot(&self) -> bool
    {
        self.slot_count.load(Ordering::Acquire) == 1
    }

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

/// Most copies of one range-capability lineage that may be live at once: the
/// `SYS_CAP_COPY`, `SYS_CAP_DERIVE`, and `SYS_CAP_DERIVE_BADGE` copies of an
/// `Mmio`, `IoPort`, or `Interrupt` capability, each a fresh object funded by
/// the arena of the `CSpace` that receives it ([`object_for_new_slot`]). A copy
/// past it returns `QuotaExceeded` rather than carry the lineage count into
/// [`ROOT_SHARE`]. The bound is the count's encoding, not a capacity: each copy
/// costs its funder a 72-byte slot and a 128-byte chunk, so the limit's
/// 2^31 - 1 copies would hold more than 400 GiB of `CSpace` pools against one
/// range.
pub const RANGE_COPY_LIMIT: u32 = ROOT_SHARE - 1;

/// The lineage an `Mmio`, `IoPort`, or `Interrupt` object belongs to.
///
/// A boot mint or a range split produces a lineage *root*; copying a
/// capability of any of these types produces a fresh object whose lineage
/// names that root, so each capability slot owns its own object and the
/// mappings, port bindings, or interrupt binding made through it are withdrawn
/// when that object is freed (docs/capability-model.md § Interrupt, § Mmio,
/// § `IoPort`). The root's `live` holds
/// [`ROOT_SHARE`] while the root has references (dropped when its reference
/// count reaches zero) plus one per live copy; the root's body is freed when
/// `live` reaches zero, so a copy's lineage pointer never dangles, and the copy
/// limit counts copies alone, whether the root is still referenced or not.
#[repr(C)]
pub struct RangeLineage
{
    /// The lineage root; null when this object is the root.
    root: *mut KernelObjectHeader,
    /// Root only: live copies, plus [`ROOT_SHARE`] while the root has
    /// references.
    live: AtomicU32,
    _pad: u32,
}

/// The share of a lineage root's `live` count the root's own references hold.
/// The copy count below it is capped at `RANGE_COPY_LIMIT`, so the two never
/// collide.
const ROOT_SHARE: u32 = 1 << 31;

impl RangeLineage
{
    /// The lineage of a fresh root.
    pub const fn new_root() -> Self
    {
        Self {
            root: core::ptr::null_mut(),
            live: AtomicU32::new(ROOT_SHARE),
            _pad: 0,
        }
    }

    /// Reserve a copy against `root`'s limit and return the lineage of the
    /// copy.
    ///
    /// # Errors
    /// `QuotaExceeded` when `root` already has [`RANGE_COPY_LIMIT`] live copies.
    ///
    /// # Safety
    /// `root` is a live `Mmio`, `IoPort`, or `Interrupt` lineage root whose
    /// `live` count is held above zero by a pinned member of the lineage.
    unsafe fn reserve_copy(root: NonNull<KernelObjectHeader>)
    -> Result<Self, syscall::SyscallError>
    {
        // SAFETY: caller contract.
        let live = unsafe { &lineage_of(root).live };
        let mut cur = live.load(Ordering::Relaxed);
        loop
        {
            if cur & !ROOT_SHARE >= RANGE_COPY_LIMIT
            {
                return Err(syscall::SyscallError::QuotaExceeded);
            }
            match live.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
        Ok(Self {
            root: root.as_ptr(),
            live: AtomicU32::new(0),
            _pad: 0,
        })
    }

    /// The lineage root of the object this lineage belongs to.
    fn root_of(&self, own: NonNull<KernelObjectHeader>) -> NonNull<KernelObjectHeader>
    {
        NonNull::new(self.root).unwrap_or(own)
    }
}

/// The lineage of an `Mmio`, `IoPort`, or `Interrupt` object.
///
/// # Safety
/// `hdr` is a live `Mmio`, `IoPort`, or `Interrupt` object.
// cast_ptr_alignment: each object is constructed in place at a
// size-class-aligned retype offset; the header sits at offset 0.
#[allow(clippy::cast_ptr_alignment)]
unsafe fn lineage_of<'a>(hdr: NonNull<KernelObjectHeader>) -> &'a RangeLineage
{
    // SAFETY: caller contract; header at offset 0 of each concrete type.
    unsafe {
        match hdr.as_ref().obj_type
        {
            ObjectType::Mmio => &(*hdr.as_ptr().cast::<MmioObject>()).lineage,
            ObjectType::IoPort => &(*hdr.as_ptr().cast::<IoPortObject>()).lineage,
            ObjectType::Interrupt => &(*hdr.as_ptr().cast::<InterruptObject>()).lineage,
            _ => crate::fatal("lineage_of: not a range-capability object"),
        }
    }
}

/// `SYS_MMIO_MAP` mapping records an `Mmio` object holds inline. Mappings past
/// them go to spill chunks ([`MmioSpill`]) funded by the mapping caller's
/// `CSpace`; mapping the same region again at the same VA of the same address
/// space reuses its record.
pub const MMIO_INLINE_MAPPINGS: usize = 4;

/// Mapping records one spill chunk holds.
const MMIO_SPILL_RECORDS: usize = 7;

/// One `SYS_MMIO_MAP` mapping of an `Mmio` object's whole region.
///
/// Both fields are atomics: concurrent `SYS_MMIO_MAP` calls through one object
/// each hold only a shared reference to it. A record is claimed by moving
/// `aso` from null to [`MMIO_RECORD_CLAIMED`], then filled (`va` first, `aso`
/// published last with Release), so a reader that sees a real `aso` with
/// Acquire also sees its `va`.
#[repr(C)]
struct MmioMapping
{
    /// The address space mapped into, holding one reference on it; null for an
    /// empty record, [`MMIO_RECORD_CLAIMED`] while a map is filling it.
    aso: AtomicPtr<AddressSpaceObject>,
    /// User virtual address of the region's first page.
    va: AtomicU64,
}

/// The `MmioMapping::aso` value of a record a map has claimed and not yet
/// filled; never dereferenced.
const MMIO_RECORD_CLAIMED: *mut AddressSpaceObject = core::ptr::dangling_mut();

impl MmioMapping
{
    const fn vacant() -> Self
    {
        Self {
            aso: AtomicPtr::new(core::ptr::null_mut()),
            va: AtomicU64::new(0),
        }
    }

    /// Whether this record maps `va` in `aso`.
    fn names(&self, aso: *mut AddressSpaceObject, va: u64) -> bool
    {
        core::ptr::eq(self.aso.load(Ordering::Acquire), aso)
            && self.va.load(Ordering::Relaxed) == va
    }

    /// Claim this record if it is empty.
    fn claim(&self) -> bool
    {
        self.aso
            .compare_exchange(
                core::ptr::null_mut(),
                MMIO_RECORD_CLAIMED,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    /// Fill a claimed record with `va` in `aso`, taking a reference on `aso`.
    ///
    /// # Safety
    /// The caller claimed the record; `aso` is a live `AddressSpaceObject` the
    /// caller holds a reference on.
    unsafe fn fill(&self, aso: *mut AddressSpaceObject, va: u64)
    {
        // SAFETY: aso is live and referenced by the caller (contract).
        unsafe { (*aso).header.inc_ref() };
        self.va.store(va, Ordering::Relaxed);
        self.aso.store(aso, Ordering::Release);
    }
}

/// A chunk of further mapping records of one `Mmio` object, chained from
/// [`MmioObject`]'s spill head, newest first. Taken from the arena of the
/// `CSpace` the map that needed it resolved through, and returned there when
/// the object is freed.
#[repr(C)]
pub struct MmioSpill
{
    /// The next (older) chunk, or null.
    next: AtomicPtr<MmioSpill>,
    records: [MmioMapping; MMIO_SPILL_RECORDS],
}

const _: () = assert!(core::mem::size_of::<MmioSpill>() <= crate::cap::arena::CHUNK_BYTES);

impl MmioSpill
{
    /// An empty chunk.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            next: AtomicPtr::new(core::ptr::null_mut()),
            records: [const { MmioMapping::vacant() }; MMIO_SPILL_RECORDS],
        }
    }
}

/// Kernel object for a memory-mapped I/O region (`Mmio` capability).
///
/// Records every `SYS_MMIO_MAP` mapping made through it; freeing the object
/// unmaps each one ([`MmioObject::withdraw_mappings`]).
#[repr(C)]
pub struct MmioObject
{
    pub header: KernelObjectHeader,
    /// Physical base address of the MMIO region.
    pub base: u64,
    /// Size of the MMIO region in bytes.
    pub size: u64,
    /// Flags word; always `0` today (boot mints set `0`, `sys_mmio_split` and
    /// copies take the source's value, and no mapping path reads it).
    pub flags: u32,
    _pad: u32,
    /// The lineage this object belongs to (see [`RangeLineage`]).
    lineage: RangeLineage,
    /// Mappings made through this object.
    mappings: [MmioMapping; MMIO_INLINE_MAPPINGS],
    /// Newest spill chunk of further mappings, or null.
    spill: AtomicPtr<MmioSpill>,
}

// MmioObject fits the 128-byte size class of the SEED mints
// (`retype::round_to_class`) and of an arena chunk (`alloc_body` asserts it).
const _: () = assert!(core::mem::size_of::<MmioObject>() <= 128);

impl MmioObject
{
    /// A lineage-root `Mmio` object over `[base, base + size)`, with SEED as its
    /// ancestor; a split or copy restamps it with its funding `CSpace`
    /// ([`CSpaceKernelObject::alloc_body`]).
    pub fn new_root(base: u64, size: u64, flags: u32) -> Self
    {
        Self {
            header: KernelObjectHeader::with_ancestor(
                ObjectType::Mmio,
                crate::cap::seed_header_nn(),
            ),
            base,
            size,
            flags,
            _pad: 0,
            lineage: RangeLineage::new_root(),
            mappings: [const { MmioMapping::vacant() }; MMIO_INLINE_MAPPINGS],
            spill: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Record a mapping of this object's region at `va` in `aso`, taking a
    /// reference on `aso` for the record. A mapping already recorded at the same
    /// place is not recorded again; two maps racing to record the same place
    /// may each take a record, which costs a record and is otherwise harmless
    /// (the teardown withdraws both). When every record is taken, a spill chunk
    /// from `new_spill` is chained on with this mapping's record in it.
    ///
    /// # Errors
    /// The error of `new_spill` (`OutOfMemory` when the caller's arena cannot
    /// fund a chunk), with nothing recorded.
    ///
    /// # Safety
    /// `aso` is a live `AddressSpaceObject` the caller holds a reference on, and
    /// the caller pins this object. A chunk `new_spill` returns is a fresh
    /// [`MmioSpill`] the object then owns, freed by its teardown.
    pub unsafe fn record_mapping(
        &self,
        aso: *mut AddressSpaceObject,
        va: u64,
        new_spill: impl FnOnce() -> Result<NonNull<MmioSpill>, syscall::SyscallError>,
    ) -> Result<(), syscall::SyscallError>
    {
        if self.records().any(|m| m.names(aso, va))
        {
            return Ok(());
        }
        if let Some(m) = self.records().find(|m| m.claim())
        {
            // SAFETY: claimed above; aso is live and referenced (contract).
            unsafe { m.fill(aso, va) };
            return Ok(());
        }
        let chunk = new_spill()?;
        // SAFETY: a fresh chunk, ours alone until published below.
        let fresh = unsafe { chunk.as_ref() };
        let first = &fresh.records[0];
        let claimed = first.claim();
        debug_assert!(claimed, "a fresh spill chunk has a vacant first record");
        let mut head = self.spill.load(Ordering::Acquire);
        loop
        {
            fresh.next.store(head, Ordering::Relaxed);
            match self.spill.compare_exchange_weak(
                head,
                chunk.as_ptr(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            {
                Ok(_) => break,
                Err(now) => head = now,
            }
        }
        // SAFETY: claimed above; aso is live and referenced (contract).
        unsafe { first.fill(aso, va) };
        Ok(())
    }

    /// Every record: the inline ones, then each spill chunk's, newest chunk
    /// first.
    fn records(&self) -> impl Iterator<Item = &MmioMapping>
    {
        self.mappings
            .iter()
            .chain(self.spill_chunks().flat_map(|c| c.records.iter()))
    }

    /// The spill chunks, newest first.
    fn spill_chunks(&self) -> impl Iterator<Item = &MmioSpill>
    {
        let mut next = self.spill.load(Ordering::Acquire);
        core::iter::from_fn(move || {
            // SAFETY: a published chunk stays live, owned by this object, until
            // its teardown frees the chain.
            let chunk = unsafe { next.as_ref() }?;
            next = chunk.next.load(Ordering::Acquire);
            Some(chunk)
        })
    }

    /// Unmap every recorded mapping, with TLB shootdown, and release each
    /// record's address-space reference through [`release_ref`], which hands
    /// an address space whose last reference that was to this CPU's deferred
    /// reclaim rather than tearing it down here: an `Mmio` object can be freed
    /// in place inside IPC delivery (a moved capability's release), where an
    /// address-space teardown's bound-thread stop must not run. A page the user
    /// has since remapped to other memory is left in place
    /// (`AddressSpace::unmap_region_if_phys`).
    ///
    /// The spill chunks then go back to the arenas that funded them; a release
    /// that frees an arena page its `CSpace` outlived pushes it onto `stack`.
    ///
    /// # Safety
    /// No capability slot or syscall pin references the object (its reference
    /// count is zero), so no map can be recording into it; only its lineage
    /// count may still be touched by other CPUs. No lock is held, and the CPU
    /// is stable (`release_ref`'s preconditions).
    // cast_possible_truncation: a region's page count fits usize on the 64-bit
    // targets the kernel supports.
    #[allow(clippy::cast_possible_truncation)]
    #[cfg(not(test))]
    unsafe fn withdraw_mappings(&self, stack: &mut CascadeStack)
    {
        let pages = (self.size / crate::mm::PAGE_SIZE as u64) as usize;
        for m in self.records()
        {
            let Some(aso) = NonNull::new(m.aso.swap(core::ptr::null_mut(), Ordering::Acquire))
            else
            {
                continue;
            };
            debug_assert!(
                !core::ptr::eq(aso.as_ptr(), MMIO_RECORD_CLAIMED),
                "withdraw_mappings: a record was being filled at refcount zero"
            );
            let va = m.va.load(Ordering::Relaxed);
            // SAFETY: the record's reference keeps the address space live; the
            // span is the user range SYS_MMIO_MAP validated when it mapped it.
            unsafe {
                (*(*aso.as_ptr()).address_space).unmap_region_if_phys(va, pages, self.base);
            }
            // SAFETY: the record held this reference; no lock is held and the
            // CPU is stable (contract).
            unsafe { release_ref(aso.cast::<KernelObjectHeader>()) };
        }
        let mut next = self.spill.swap(core::ptr::null_mut(), Ordering::Acquire);
        while let Some(chunk) = NonNull::new(next)
        {
            // SAFETY: a chunk of this object's chain, which nothing else reads
            // at refcount zero.
            next = unsafe { chunk.as_ref().next.load(Ordering::Acquire) };
            // SAFETY: the chunk came from an arena and is unused now; no lock
            // is held (contract).
            unsafe { free_arena_chunk(chunk.as_ptr().cast::<u8>(), stack) };
        }
    }
}

/// Kernel object for a hardware interrupt range (Interrupt capability).
///
/// A cap with `count == 1` is a single-IRQ cap usable with
/// `sys_irq_register` / `sys_irq_ack`. Wider caps are delegatable
/// range authorities: narrow them with `sys_irq_split` before use.
///
/// Each capability references an object of its own (a copy is a fresh object
/// in its lineage, [`object_for_new_slot`]), so each carries its own binding of
/// its line; freeing the object removes that binding (`irq::unregister`).
#[repr(C)]
pub struct InterruptObject
{
    pub header: KernelObjectHeader,
    /// First IRQ line in the range (GSI on x86-64, PLIC source on RISC-V).
    pub start: u32,
    /// Number of consecutive IRQ lines covered by the cap.
    pub count: u32,
    /// The lineage this object belongs to (see [`RangeLineage`]).
    lineage: RangeLineage,
    /// This capability's binding of its line; unbound on a range cap.
    pub binding: crate::irq::IrqBinding,
}

// InterruptObject fits the 128-byte size class of the SEED mints
// (`retype::round_to_class`) and of an arena chunk (`alloc_body` asserts it).
const _: () = assert!(core::mem::size_of::<InterruptObject>() <= 128);

impl InterruptObject
{
    /// A lineage-root, unbound `Interrupt` object over `count` lines from
    /// `start`, with SEED as its ancestor; a split or copy restamps it with its
    /// funding `CSpace` ([`CSpaceKernelObject::alloc_body`]).
    pub fn new_root(start: u32, count: u32) -> Self
    {
        Self {
            header: KernelObjectHeader::with_ancestor(
                ObjectType::Interrupt,
                crate::cap::seed_header_nn(),
            ),
            start,
            count,
            lineage: RangeLineage::new_root(),
            binding: crate::irq::IrqBinding::unbound(),
        }
    }
}

/// Kernel object for an x86-64 I/O port range (`IoPort` capability).
///
/// The threads bound through it record it in their port-binding tables
/// (`cap::ioport_bindings`); freeing the object withdraws those bindings.
#[repr(C)]
pub struct IoPortObject
{
    pub header: KernelObjectHeader,
    /// First port number in the range.
    pub base: u16,
    /// Number of consecutive ports; `0` encodes the full 65536-port space
    /// (the root cap), which a `u16` cannot hold.
    pub size: u16,
    _pad: u32,
    /// The lineage this object belongs to (see [`RangeLineage`]).
    lineage: RangeLineage,
}

impl IoPortObject
{
    /// A lineage-root `IoPort` object over `size` ports from `base` (`size == 0`
    /// for all 65536), with SEED as its ancestor; a split or copy restamps it
    /// with its funding `CSpace` ([`CSpaceKernelObject::alloc_body`]).
    pub fn new_root(base: u16, size: u16) -> Self
    {
        Self {
            header: KernelObjectHeader::with_ancestor(
                ObjectType::IoPort,
                crate::cap::seed_header_nn(),
            ),
            base,
            size,
            _pad: 0,
            lineage: RangeLineage::new_root(),
        }
    }

    /// The number of ports the object covers (65536 for the root encoding).
    pub fn port_count(&self) -> u32
    {
        if self.size == 0
        {
            65536
        }
        else
        {
            u32::from(self.size)
        }
    }
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
    /// that stack — between the push (a self-teardown of the running thread's
    /// own `Thread` object, or `release_ref` dropping its last reference: a
    /// syscall pin, or a moved capability's freed source) and the off-CPU
    /// completion of that free. Null otherwise.
    /// Written only by the owning CPU.
    pub deferred_next: *mut KernelObjectHeader,
}

// SAFETY: ThreadObject is accessed only under the scheduler lock.
unsafe impl Send for ThreadObject {}
// SAFETY: ThreadObject is accessed only under the scheduler lock.
unsafe impl Sync for ThreadObject {}

/// Number of donation records held inline in a wrapper's [`PagePool`].
///
/// The create-time slab occupies record 0; the next fifteen augment-mode
/// donations fill the rest. Further donations spill into record pages
/// carved from the donations themselves (see `PagePool::add_donation`).
const INLINE_RECORDS: usize = 16;

/// Inline record of a retype-allocated multi-page region donated to an
/// `AddressSpaceObject`'s PT pool or a `CSpaceKernelObject`'s slot-page
/// pool.
///
/// At dealloc, every non-vacant record is fed back to its `ancestor`
/// `MemoryObject` (`retype::retype_free_runs`), then the ancestor is `dec_ref`'d.
/// The type builds in every configuration because the wrapper structs
/// embed it; only the non-test pool code reads it.
#[repr(C)]
struct InlineRecord
{
    /// `MemoryObject` ancestor this donation was carved from. Null = vacant.
    ancestor: AtomicPtr<KernelObjectHeader>,
    /// Byte offset within the ancestor's region.
    base_offset: AtomicU64,
    /// Total pages carved (initial + grown).
    page_count: AtomicU64,
    /// A dying `CSpace`'s arena pages in this donation that its teardown keeps
    /// past it, linked through [`ArenaPage::next`]; null otherwise. Written
    /// only by that teardown's pass (`CSpaceKernelObject::orphan_arena_pages`).
    holes: AtomicPtr<ArenaPage>,
}

impl InlineRecord
{
    /// Construct a vacant record (ancestor = null, offset = 0, count = 0).
    const fn vacant() -> Self
    {
        Self {
            ancestor: AtomicPtr::new(core::ptr::null_mut()),
            base_offset: AtomicU64::new(0),
            page_count: AtomicU64::new(0),
            holes: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// The record, or `None` while vacant. The Acquire load of `ancestor`
    /// pairs with the Release store that publishes a populated record.
    #[cfg(not(test))]
    fn load(&self) -> Option<DonationRecord>
    {
        let ancestor = self.ancestor.load(Ordering::Acquire);
        (!ancestor.is_null()).then(|| DonationRecord {
            ancestor,
            base_offset: self.base_offset.load(Ordering::Relaxed),
            page_count: self.page_count.load(Ordering::Relaxed),
            holes: self.holes.load(Ordering::Relaxed),
        })
    }
}

/// One donation record in a `RecordPage`: the content of an
/// `InlineRecord` as plain words. Record pages are read and written
/// only under the pool lock, or at teardown with no other reference alive.
#[cfg(not(test))]
#[repr(C)]
#[derive(Clone, Copy)]
struct DonationRecord
{
    ancestor: *mut KernelObjectHeader,
    base_offset: u64,
    page_count: u64,
    /// As [`InlineRecord`]'s `holes`.
    holes: *mut ArenaPage,
}

#[cfg(not(test))]
impl DonationRecord
{
    const VACANT: Self = Self {
        ancestor: core::ptr::null_mut(),
        base_offset: 0,
        page_count: 0,
        holes: core::ptr::null_mut(),
    };
}

/// Where a donation's record keeps its list of kept arena pages (the `holes`
/// field of an [`InlineRecord`] or of a `RecordPage` entry). Every free page
/// of a pool carries its donation's cell in its second word, so an arena page
/// carved from it knows its record without a search.
#[cfg(not(test))]
type HolesCell = *mut *mut ArenaPage;

/// Pages `PagePool::seed_pages` pushes per pool-lock hold, and per stretch
/// with interrupts masked. The pool lock is a bare spin lock
/// (scheduling-internals.md § Lock Hierarchy, "Bare spin locks"), and a hold
/// proportional to a caller-chosen donation size would be unbounded; batching
/// keeps every hold to this many pushes, and an [`interrupt_window`] between
/// batches keeps the syscall's interrupts-off stretches to one batch each,
/// whatever `init_pages` the caller chose.
#[cfg(not(test))]
const SEED_BATCH_PAGES: u64 = 64;

/// Let this CPU take the interrupts pending on it, then return to the
/// caller's interrupt state, with preemption disabled throughout so that an
/// interrupt taken here cannot switch the thread out. The page-pool seeding
/// and reclaim walks call it between their batches, whose number a caller
/// chooses, so that a syscall running one masks interrupts for one batch at a
/// time: shootdown and wakeup IPIs are acknowledged, and the timer and the
/// heartbeat tick, meanwhile (core/kernel/docs/capability-internals.md
/// § Donation Records and § Teardown).
///
/// No lock may be held across it. Every pool is created after the timer is
/// initialised, which enables interrupts with the trap vector in place, so
/// every caller runs where interrupts may be taken; the idle drain, which
/// runs with them enabled, keeps them enabled.
#[cfg(not(test))]
fn interrupt_window()
{
    crate::percpu::preempt_disable();
    // SAFETY: kernel mode; the state is restored below.
    let saved = unsafe { crate::arch::current::cpu::save_and_disable_interrupts() };
    // SAFETY: the trap vector is installed before any pool exists (above);
    // preemption is disabled and no lock is held, so an interrupt taken here
    // cannot switch this thread out or deadlock against it.
    unsafe { crate::arch::current::interrupts::enable() };
    // x86-64 defers interrupt recognition past the instruction after `sti`,
    // so one instruction separates the enable from the restore.
    core::hint::spin_loop();
    // SAFETY: `saved` came from save_and_disable_interrupts above.
    unsafe { crate::arch::current::cpu::restore_interrupts(saved) };
    crate::percpu::preempt_enable();
}

/// Bytes of `RecordPage` ahead of its records: `next_phys` and `used`.
#[cfg(not(test))]
const RECORD_PAGE_HEADER: usize = core::mem::size_of::<u64>() + core::mem::size_of::<usize>();

/// Donation records per `RecordPage`. Fixed by the page and record layout;
/// record pages chain through `next_phys`, so it bounds no record count.
#[cfg(not(test))]
const RECORDS_PER_PAGE: usize =
    (crate::mm::PAGE_SIZE - RECORD_PAGE_HEADER) / core::mem::size_of::<DonationRecord>();

/// A page of spilled donation records, carved from a donation once the
/// inline records are full. Record 0 always describes the donation this page
/// itself lives in, so freeing record 0 last releases the page.
#[cfg(not(test))]
#[repr(C)]
struct RecordPage
{
    /// Physical address of the next-older record page; `0` for the oldest.
    next_phys: u64,
    /// Records in use, `1..=RECORDS_PER_PAGE`. A `usize` (8 bytes on
    /// every Seraph target) so it indexes `records` without a cast; the
    /// page is kernel-private and lives only as long as its pool.
    used: usize,
    records: [DonationRecord; RECORDS_PER_PAGE],
}

#[cfg(not(test))]
const _: () = assert!(
    core::mem::size_of::<RecordPage>() <= crate::mm::PAGE_SIZE,
    "RecordPage exceeds one page"
);
#[cfg(not(test))]
const _: () = assert!(
    core::mem::offset_of!(RecordPage, records) == RECORD_PAGE_HEADER,
    "RECORD_PAGE_HEADER does not match the RecordPage layout"
);

/// A wrapper object's page pool: an intrusive free list of donated pages
/// plus a record of every donation, for reclaim at teardown: whole, or, for a
/// `CSpace`, around the arena pages its teardown keeps.
///
/// Shared by [`AddressSpaceObject`] (intermediate page tables) and
/// [`CSpaceKernelObject`] (slot and directory pages). The owner keeps the
/// byte budget the pool backs; the pool holds only pages and records.
///
/// Records live inline up to `INLINE_RECORDS`, then in
/// `RecordPage`s chained newest-first from `record_head_phys`. A
/// record page is the first pool page of the donation that overflowed
/// into it, so the number of donations is bounded only by the memory
/// donated: one page of bookkeeping per `RECORDS_PER_PAGE`
/// donations beyond the inline records.
#[repr(C)]
pub struct PagePool
{
    /// Spinlock guarding every other field and the record pages.
    /// `0` = unlocked, `1` = locked.
    lock: AtomicU64,
    /// Head of the intrusive free list of available pages, by physical
    /// address. `0` = empty. Each free page's first 8 bytes hold the
    /// physical address of the next free page (read/written via the
    /// kernel direct map).
    head_phys: AtomicU64,
    /// Newest record page, by physical address. `0` = none.
    record_head_phys: AtomicU64,
    /// Inline donation records; the create-time slab is record 0.
    inline: [InlineRecord; INLINE_RECORDS],
}

impl PagePool
{
    /// An empty pool: no pages, no records.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            lock: AtomicU64::new(0),
            head_phys: AtomicU64::new(0),
            record_head_phys: AtomicU64::new(0),
            inline: [const { InlineRecord::vacant() }; INLINE_RECORDS],
        }
    }

    /// Whether record 0, the create-time slab, is populated. Records are
    /// appended from index 0, and every wrapper the kernel constructs
    /// records its slab before the wrapper is published, so this is true
    /// for every live object. The map syscalls' check
    /// ([`AddressSpaceObject::require_create_donation`]) and the dealloc
    /// arms' debug assertions check that invariant rather than support an
    /// unrecorded object.
    #[cfg(not(test))]
    #[must_use]
    pub fn has_create_donation(&self) -> bool
    {
        !self.inline[0].ancestor.load(Ordering::Acquire).is_null()
    }

    /// Pop one free page, or `None` if the pool is empty.
    #[cfg(not(test))]
    #[track_caller]
    fn pop(&self) -> Option<u64>
    {
        pool_lock(&self.lock);
        // SAFETY: lock held; `head_phys` is this pool's free-list head.
        let phys = unsafe { pool_pop(&self.head_phys) };
        pool_unlock(&self.lock);
        (phys != 0).then_some(phys)
    }

    /// Return a page to the free list.
    ///
    /// # Safety
    /// `phys` must be a page of this pool that is no longer in use.
    #[cfg(not(test))]
    #[track_caller]
    unsafe fn push(&self, phys: u64)
    {
        pool_lock(&self.lock);
        // SAFETY: lock held; the caller's contract makes `phys` exclusively
        // owned and unaliased.
        unsafe { pool_push(&self.head_phys, phys) };
        pool_unlock(&self.lock);
    }

    /// Record a donation, seed its pool pages onto the free list, and credit
    /// `budget` with the bytes seeded: `pool_pages`, or one fewer when the
    /// donation had to supply a record page.
    ///
    /// `Err(())` only when there is no record space and `pool_pages == 0`,
    /// so the donation cannot supply a record page; nothing is recorded,
    /// seeded, or credited then. No current caller can provoke it — an
    /// augment always carries a pool page and a create finds record 0
    /// vacant — so the callers' rollbacks are the contract for a future
    /// caller, not a reachable path. The record is written under the first lock
    /// hold, before any page is published, so every seeded page belongs to
    /// a recorded, reclaimable donation; the pages then go onto the free list
    /// in batches of `SEED_BATCH_PAGES` under separate holds, each batch
    /// credited as it lands.
    ///
    /// Pool pages are the high `pool_pages` of the donation; the low
    /// `total_pages - pool_pages` stay reserved for the caller (wrapper
    /// page, root page table). The record always covers all `total_pages`
    /// so teardown reclaims the entire span.
    ///
    /// # Safety
    /// `ancestor` must be a live `MemoryObject`'s header on which the
    /// caller holds a reference for the pool's lifetime; `base_offset` and
    /// `total_pages` must come from a successful `retype_allocate` against
    /// it, with `ancestor_memory_base` that object's `base`. No lock may be
    /// held: the seeding takes interrupts between batches (`seed_pages`).
    #[cfg(not(test))]
    #[track_caller]
    unsafe fn add_donation(
        &self,
        ancestor: NonNull<KernelObjectHeader>,
        ancestor_memory_base: u64,
        base_offset: u64,
        total_pages: u64,
        pool_pages: u64,
        budget: &AtomicU64,
    ) -> Result<(), ()>
    {
        debug_assert!(pool_pages <= total_pages);
        let p = crate::mm::PAGE_SIZE as u64;
        let donation_phys = ancestor_memory_base + base_offset;
        let mut first_pool = total_pages - pool_pages;
        let record = DonationRecord {
            ancestor: ancestor.as_ptr(),
            base_offset,
            page_count: total_pages,
            holes: core::ptr::null_mut(),
        };

        pool_lock(&self.lock);
        let vacant = self
            .inline
            .iter()
            .find(|cell| cell.ancestor.load(Ordering::Relaxed).is_null());
        let recorded = if let Some(cell) = vacant
        {
            cell.base_offset.store(base_offset, Ordering::Relaxed);
            cell.page_count.store(total_pages, Ordering::Relaxed);
            cell.holes.store(core::ptr::null_mut(), Ordering::Relaxed);
            // A non-null ancestor marks the record populated, so it is
            // written last.
            cell.ancestor.store(ancestor.as_ptr(), Ordering::Release);
            Some(cell.holes.as_ptr())
        }
        else
        {
            // SAFETY: lock held.
            unsafe { self.record_spilled(record) }
        };
        let cell = if let Some(cell) = recorded
        {
            cell
        }
        else
        {
            if first_pool == total_pages
            {
                pool_unlock(&self.lock);
                return Err(());
            }
            // SAFETY: lock held; the page is the donation's first pool page,
            // freshly retyped from `ancestor` and not yet published.
            let cell = unsafe { self.open_record_page(donation_phys + first_pool * p, record) };
            first_pool += 1;
            cell
        };
        pool_unlock(&self.lock);

        // SAFETY: the record covering these pages is written above, at
        // `cell`; the pages were just retyped from `ancestor` and are
        // unaliased.
        unsafe { self.seed_pages(donation_phys, first_pool, total_pages, budget, cell) };
        Ok(())
    }

    /// Push pages `first..total` of the donation at `donation_phys` onto the free
    /// list, highest first so the lowest ends up at the head, in batches of
    /// `SEED_BATCH_PAGES` under separate lock holds with an
    /// [`interrupt_window`] between batches; credit `budget` with each batch
    /// as it lands, so a concurrent pop never debits a budget the pages have
    /// not yet been credited to.
    ///
    /// # Safety
    /// The pages must belong to a donation already recorded in this pool,
    /// be freshly retyped, and be unaliased. No lock may be held, the pool
    /// lock included.
    #[cfg(not(test))]
    #[track_caller]
    unsafe fn seed_pages(
        &self,
        donation_phys: u64,
        first: u64,
        total: u64,
        budget: &AtomicU64,
        cell: HolesCell,
    )
    {
        let p = crate::mm::PAGE_SIZE as u64;
        let mut end = total;
        while end > first
        {
            let start = end.saturating_sub(SEED_BATCH_PAGES).max(first);
            pool_lock(&self.lock);
            for i in (start..end).rev()
            {
                // SAFETY: lock held; the caller's contract makes the page
                // exclusively owned and recorded at `cell`.
                unsafe { pool_push_tagged(&self.head_phys, donation_phys + i * p, cell) };
            }
            budget.fetch_add((end - start) * p, Ordering::AcqRel);
            pool_unlock(&self.lock);
            end = start;
            if end > first
            {
                interrupt_window();
            }
        }
    }

    /// Append `record` to the newest record page. `false` if there is none
    /// or it is full.
    ///
    /// # Safety
    /// The pool lock must be held.
    #[cfg(not(test))]
    unsafe fn record_spilled(&self, record: DonationRecord) -> Option<HolesCell>
    {
        let page_phys = self.record_head_phys.load(Ordering::Acquire);
        if page_phys == 0
        {
            return None;
        }
        let page = crate::mm::paging::phys_to_virt(page_phys) as *mut RecordPage;
        // SAFETY: lock held; a published record page stays mapped in the
        // direct map and exclusively owned by this pool until teardown.
        let cell = unsafe {
            let used = (*page).used;
            if used >= RECORDS_PER_PAGE
            {
                return None;
            }
            (*page).records[used] = record;
            (*page).used = used + 1;
            core::ptr::addr_of_mut!((*page).records[used].holes)
        };
        // Re-publish the head with Release so the appended record and the
        // new `used` are visible to a reader that Acquire-loads the head
        // (`reclaim_donations`), as they are for an inline record's ancestor
        // store; teardown otherwise leans on the refcount edge alone.
        self.record_head_phys.store(page_phys, Ordering::Release);
        Some(cell)
    }

    /// Make `page_phys` the newest record page, holding `record` (the donation
    /// the page belongs to) as record 0.
    ///
    /// # Safety
    /// The pool lock must be held; `page_phys` must be a page-aligned page
    /// of `record`'s donation that is neither on the free list nor otherwise
    /// in use.
    #[cfg(not(test))]
    unsafe fn open_record_page(&self, page_phys: u64, record: DonationRecord) -> HolesCell
    {
        let page = crate::mm::paging::phys_to_virt(page_phys) as *mut RecordPage;
        // SAFETY: the page is exclusively owned and page-aligned (caller's
        // contract) and holds one RecordPage (fit asserted at compile
        // time).
        let cell = unsafe {
            core::ptr::write_bytes(page.cast::<u8>(), 0, crate::mm::PAGE_SIZE);
            (*page).next_phys = self.record_head_phys.load(Ordering::Acquire);
            (*page).used = 1;
            (*page).records[0] = record;
            core::ptr::addr_of_mut!((*page).records[0].holes)
        };
        self.record_head_phys.store(page_phys, Ordering::Release);
        cell
    }

    /// Hand every recorded donation to `free`, in groups of records that
    /// share a Memory object, each group sorted by offset, in an order that
    /// keeps each record readable until it is used: the spilled records
    /// newest page first, a page's other records before its record 0 (whose
    /// donation holds the page), then the inline records, snapshotted up
    /// front, with record 0 (the create-time slab that holds the owner and
    /// this pool) last. A record's `holes` is its list of kept arena pages
    /// (null for an `AddressSpace` pool, or a record with none); `free` may
    /// rewrite it.
    ///
    /// The other records of a page, or of the inline set, are sorted in
    /// place by Memory object and offset, so a group is one run of them; a
    /// record 0 is a group of its own. An [`interrupt_window`] follows every
    /// group but the create-time slab's, so the walk masks interrupts for at
    /// most one group, of at most `RECORDS_PER_PAGE` records, at a time,
    /// whatever the donation count; its context and cost are in
    /// core/kernel/docs/capability-internals.md § Teardown.
    ///
    /// # Safety
    /// The owner is being torn down at refcount 0: no other reference to
    /// it, the pool, or any recorded page exists, and `free` must not touch
    /// the pool. `self` is dangling once this returns. `free` receives raw
    /// records and may push onto the dealloc cascade stack; the caller
    /// holds no lock.
    #[cfg(not(test))]
    unsafe fn reclaim_donations<F>(&self, mut free: F)
    where
        F: FnMut(&mut [DonationRecord]),
    {
        let mut inline_snapshot = [DonationRecord::VACANT; INLINE_RECORDS];
        let mut count = 0;
        for record in self.inline.iter().filter_map(InlineRecord::load)
        {
            inline_snapshot[count] = record;
            count += 1;
        }

        let mut page_phys = self.record_head_phys.load(Ordering::Acquire);
        while page_phys != 0
        {
            let page = crate::mm::paging::phys_to_virt(page_phys) as *mut RecordPage;
            // SAFETY: caller's contract; the page stays intact until its
            // record 0 is freed below, after every read of it.
            let (next, used) = unsafe { ((*page).next_phys, (*page).used) };
            debug_assert!((1..=RECORDS_PER_PAGE).contains(&used));
            // The page is trusted kernel state and a corrupt record is not
            // survivable; the clamp only keeps the access inside the page.
            let used = used.min(RECORDS_PER_PAGE);
            // SAFETY: as above, and the dead pool's page is this walk's alone
            // to reorder; `used` is within it.
            let records = unsafe { &mut (&mut (*page).records)[..used] };
            if let Some((own, others)) = records.split_first_mut()
            {
                // Record 0 is copied out first: its return releases the page.
                let mut own = *own;
                free_in_groups(others, &mut free);
                free(core::slice::from_mut(&mut own));
                interrupt_window();
            }
            page_phys = next;
        }

        if let Some((slab, others)) = inline_snapshot[..count].split_first_mut()
        {
            free_in_groups(others, &mut free);
            free(core::slice::from_mut(slab));
        }
    }
}

/// Sort `records` in place by `key`, a record's `(ancestor, offset)`, and hand
/// `group` each maximal run of the records that share an ancestor, lowest
/// ancestor first, each run in ascending offset order.
fn for_each_ancestor_group<T>(
    records: &mut [T],
    key: impl Fn(&T) -> (usize, u64),
    mut group: impl FnMut(&mut [T]),
)
{
    records.sort_unstable_by_key(&key);
    for run in records.chunk_by_mut(|a, b| key(a).0 == key(b).0)
    {
        group(run);
    }
}

/// Hand `free` the donation records `records` in groups that share a Memory
/// object ([`for_each_ancestor_group`]), each followed by an
/// [`interrupt_window`].
#[cfg(not(test))]
fn free_in_groups(records: &mut [DonationRecord], free: &mut impl FnMut(&mut [DonationRecord]))
{
    for_each_ancestor_group(
        records,
        |record| (record.ancestor.addr(), record.base_offset),
        |group| {
            free(group);
            interrupt_window();
        },
    );
}

impl Default for PagePool
{
    fn default() -> Self
    {
        Self::new()
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
    /// Starts at `0`; credited with the pool pages each donation seeds — the
    /// create-time slab's pool pages, then each augment-mode donation (see
    /// `PagePool::add_donation`).
    /// Refilled via augment-mode on `SYS_CAP_CREATE_ASPACE`
    /// (`cap_create_aspace(memory_cap, target_aspace_cap, init_pages)`).
    /// `mem_map` returns `OutOfMemory` if a new PT page is needed but the
    /// budget is exhausted.
    pub pt_growth_budget_bytes: AtomicU64,
    /// Intermediate page-table pages donated to this AS, and the record of
    /// every donation; `dealloc` reclaims the donations wholesale.
    pub pt_pool: PagePool,
    /// Intrusive link for the per-CPU deferred reclaim stack
    /// ([`drain_deferred_reclaim`]). Non-null only while this object sits on
    /// that stack: the thread that dropped its last capability was itself
    /// bound to it (or was stopped by a concurrent teardown while freeing
    /// it), or `release_ref` dropped its last reference (a syscall pin, a
    /// batched capability move's freed source, or an Mmio object's mapping
    /// record), so the free completes off-CPU. Written only by the owning CPU.
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
    /// Starts at `0`; credited with the pool pages each donation seeds — the
    /// create-time slab's pool pages, then each augment-mode donation (see
    /// `PagePool::add_donation`).
    /// Refilled via augment-mode on `SYS_CAP_CREATE_CSPACE`
    /// (`cap_create_cspace(memory_cap, target_cspace_cap, init_pages)`).
    /// `CSpace::grow` returns `OutOfMemory` if a new slot page is needed but the
    /// budget is exhausted.
    pub cspace_growth_budget_bytes: AtomicU64,
    /// Slot and directory pages donated to this `CSpace`, and the record of
    /// every donation; `dealloc` returns every donation, but for the arena
    /// pages that still hold a live body, cut out of their donations' spans.
    pub cs_pool: PagePool,
    /// Head of the body arena's free-chunk list (a chunk's kernel virtual
    /// address, `0` for none): the 128-byte chunks of pool pages this `CSpace`
    /// funds runtime kernel object bodies from (`cap::arena`). Serialised by
    /// `cs_pool`'s lock.
    arena_free: AtomicU64,
    /// Every arena page this `CSpace` carved, newest first, linked through
    /// [`ArenaPage::next`]. Appended under `cs_pool`'s lock; walked by the
    /// teardown, when no allocation can run.
    arena_pages: AtomicPtr<ArenaPage>,
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
    "AddressSpaceObject + AddressSpace exceed the wrapper page"
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

/// Acquire a pool spinlock ([`PagePool::lock`]). A contended wait is
/// recorded in the calling CPU's lock-wait breadcrumb for the softlockup
/// watchdog; the uncontended path records nothing.
#[cfg(not(test))]
#[inline]
#[track_caller]
fn pool_lock(lock: &AtomicU64)
{
    crate::sched::check_lock_hold_preemptible(
        crate::sched::LockKind::Pool,
        core::panic::Location::caller(),
    );
    if lock
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        crate::sched::lock_wait_enter(
            crate::sched::LockKind::Pool,
            core::ptr::from_ref(lock).expose_provenance(),
        );
        while lock
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        crate::sched::lock_wait_exit();
    }
}

/// Release a pool spinlock.
#[cfg(not(test))]
#[inline]
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
unsafe fn pool_pop(head_phys: &AtomicU64) -> u64
{
    let head = head_phys.load(Ordering::Acquire);
    if head == 0
    {
        return 0;
    }
    let virt = crate::mm::paging::phys_to_virt(head);
    // SAFETY: `head` was placed on the list by a prior pool_push and points
    // inside a live retype donation; its first 8 bytes hold the next link.
    let next = unsafe { core::ptr::read_volatile(virt as *const u64) };
    head_phys.store(next, Ordering::Release);
    head
}

/// Push a page onto a `CSpace` pool's free list as [`pool_push`] does, and
/// write `cell`, its donation record's [`HolesCell`], in its second word.
///
/// # Safety
/// As [`pool_push`]; `cell` is the cell of the record of the donation `phys`
/// lies in.
#[cfg(not(test))]
unsafe fn pool_push_tagged(head_phys: &AtomicU64, phys: u64, cell: HolesCell)
{
    let virt = crate::mm::paging::phys_to_virt(phys);
    // SAFETY: caller guarantees `phys` is exclusively owned and unaliased.
    unsafe { core::ptr::write_volatile((virt as *mut u64).add(1), cell as u64) };
    // SAFETY: forwarded from the caller's contract.
    unsafe { pool_push(head_phys, phys) };
}

/// The [`HolesCell`] a free pool page carries in its second word
/// ([`pool_push_tagged`]).
///
/// # Safety
/// `phys` is a page just popped from a `CSpace` pool's free list, before
/// anything else writes it.
#[cfg(not(test))]
unsafe fn pool_page_cell(phys: u64) -> HolesCell
{
    let virt = crate::mm::paging::phys_to_virt(phys);
    // SAFETY: caller contract.
    unsafe { core::ptr::read_volatile((virt as *const u64).add(1)) as HolesCell }
}

/// Push a page onto the pool free-list. Caller must hold the pool lock and
/// must have ensured the page is no longer in use.
///
/// # Safety
/// `phys` must be page-aligned, within a donation owned by this pool, and not
/// concurrently aliased.
#[cfg(not(test))]
unsafe fn pool_push(head_phys: &AtomicU64, phys: u64)
{
    let prev = head_phys.load(Ordering::Acquire);
    let virt = crate::mm::paging::phys_to_virt(phys);
    // SAFETY: caller guarantees `phys` is exclusively owned and unaliased.
    unsafe { core::ptr::write_volatile(virt as *mut u64, prev) };
    head_phys.store(phys, Ordering::Release);
}

impl AddressSpaceObject
{
    /// Check, at a map syscall's entry, that this address space records its
    /// create-time donation, so its page-table pages come from its own pool.
    ///
    /// Both constructors record the donation before the object is published
    /// (`sys_cap_create_aspace` rolls the create back, and
    /// `boot_retype_aspace` halts the boot, if `add_donation` fails; record 0
    /// of a new pool is always vacant), and record 0 is cleared only at
    /// dealloc. So the check cannot fail on a live object, and no map
    /// syscall draws on the kernel page-table pool, whose only consumers are
    /// the Phase 9 bootstrap maps (core/kernel/docs/memory-internals.md
    /// § Page Table Node Ownership).
    ///
    /// # Errors
    ///
    /// `OutOfMemory`, the error of a map with no page-table page to draw, if
    /// the invariant is broken (debug builds assert it first).
    #[cfg(not(test))]
    pub fn require_create_donation(&self) -> Result<(), syscall::SyscallError>
    {
        let recorded = self.pt_pool.has_create_donation();
        debug_assert!(
            recorded,
            "address space published without its create-time donation"
        );
        if recorded
        {
            Ok(())
        }
        else
        {
            Err(syscall::SyscallError::OutOfMemory)
        }
    }

    /// Pop a free PT page from this AS's pool, charging the growth budget.
    /// Returns the page's physical address, or `None` if the pool is empty.
    /// Called under the address space's `pt_lock`, which serialises this
    /// debit against `free_pt_page`'s credit; a debit outside it could
    /// wrap the budget.
    #[cfg(not(test))]
    #[track_caller]
    pub fn alloc_pt_page(&self) -> Option<u64>
    {
        let phys = self.pt_pool.pop()?;
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
    /// The credit lands outside the pool lock: `alloc_pt_page` and this
    /// function are both called under the address space's `pt_lock`, which
    /// serialises the debit and the credit.
    ///
    /// # Safety
    /// `phys` must come from a prior [`alloc_pt_page`] call on this AS, and
    /// the page must no longer be in use as a page table.
    #[cfg(not(test))]
    #[track_caller]
    pub unsafe fn free_pt_page(&self, phys: u64)
    {
        // SAFETY: the caller's contract makes `phys` a pool page no longer
        // in use.
        unsafe { self.pt_pool.push(phys) };
        self.pt_growth_budget_bytes
            .fetch_add(crate::mm::PAGE_SIZE as u64, Ordering::AcqRel);
    }

    /// Record a freshly-retyped donation, seed its pool pages, and credit the
    /// growth budget with the pages actually seeded.
    ///
    /// # Safety
    /// See `PagePool::add_donation`. The caller has already `inc_ref`'d
    /// `ancestor`; the reference is released when the donation is reclaimed at
    /// dealloc.
    #[cfg(not(test))]
    #[track_caller]
    pub unsafe fn add_donation(
        &self,
        ancestor: NonNull<KernelObjectHeader>,
        ancestor_memory_base: u64,
        base_offset: u64,
        total_pages: u64,
        pool_pages: u64,
    ) -> Result<(), ()>
    {
        // SAFETY: forwarded from the caller's contract.
        unsafe {
            self.pt_pool.add_donation(
                ancestor,
                ancestor_memory_base,
                base_offset,
                total_pages,
                pool_pages,
                &self.pt_growth_budget_bytes,
            )
        }
    }
}

/// The header of a `CSpace` body-arena page, in the page's chunk 0
/// (`cap::arena`; core/kernel/docs/capability-internals.md § Body Arena).
///
/// Its reference count is the page's live chunks plus one hold: the funding
/// `CSpace`'s while it lives, then its teardown's while that cuts the
/// donations around the page. A page that still holds a live chunk when its
/// `CSpace` dies is kept past it: the teardown sets `header.ancestor` to the
/// Memory object the page's donation came from, with a lease, and the page
/// returns there when its last chunk goes (the `ArenaPage` arm of
/// [`dealloc_object`]).
#[repr(C)]
pub struct ArenaPage
{
    pub header: KernelObjectHeader,
    /// The funding wrapper while it lives; null once its teardown has passed
    /// this page. Serialised by `lock`.
    owner: AtomicPtr<CSpaceKernelObject>,
    /// The next page of the owner's list, then, once the teardown keeps the
    /// page, of its donation record's list of kept pages.
    next: AtomicPtr<ArenaPage>,
    /// The next page of the teardown's list of every page it keeps.
    kept_next: AtomicPtr<ArenaPage>,
    /// Serialises `owner` against a chunk free that pushes the chunk to the
    /// owner's list, so the teardown's pass over the page is a barrier.
    lock: AtomicU64,
    /// The cell of the donation record whose span holds this page, taken from
    /// the pool page when it was carved ([`HolesCell`]).
    record: AtomicU64,
}

const _: () = assert!(core::mem::size_of::<ArenaPage>() <= crate::cap::arena::CHUNK_BYTES);

/// Return the chunk at `chunk` to its arena page: to the funding `CSpace`'s
/// free list while it lives, and in any case releasing the page's reference.
/// The release that frees a page its `CSpace` outlived pushes it onto `stack`.
///
/// # Safety
/// `chunk` came from a `CSpace` arena ([`CSpaceKernelObject::alloc_body`],
/// [`CSpaceKernelObject::alloc_mmio_spill`]) and nothing references it any
/// more; no lock is held.
#[cfg(not(test))]
#[track_caller]
unsafe fn free_arena_chunk(chunk: *mut u8, stack: &mut CascadeStack)
{
    let page = crate::cap::arena::page_of(chunk as usize) as *mut ArenaPage;
    // SAFETY: the chunk's live reference keeps its page's header valid until
    // the release below (caller contract).
    let page = unsafe { &*page };
    pool_lock(&page.lock);
    let owner = page.owner.load(Ordering::Acquire);
    if !owner.is_null()
    {
        // SAFETY: a non-null owner under the page lock has not passed this
        // page in its teardown, which reclaims the wrapper only after every
        // page, so the wrapper is live. Only the two atomics a chunk free
        // uses are borrowed, never the whole wrapper: its teardown may be
        // writing `cspace` or its header's cascade link meanwhile.
        let (lock, free) = unsafe { (&(*owner).cs_pool.lock, &(*owner).arena_free) };
        pool_lock(lock);
        // SAFETY: pool lock held; the chunk is this arena's (contract).
        unsafe { crate::cap::arena::push_chunk(free, chunk) };
        pool_unlock(lock);
    }
    pool_unlock(&page.lock);
    if page.header.dec_ref() == 0
    {
        // SAFETY: the page's last reference: its owner has gone and no chunk
        // is live, so it is ours to return.
        unsafe { stack.push(NonNull::from(&page.header)) };
    }
}

impl CSpaceKernelObject
{
    /// A wrapper for the `CSpace` at `cspace`, with an empty pool and an empty
    /// body arena; `header` names the Memory object the slab was retyped from.
    #[must_use]
    pub const fn new(header: KernelObjectHeader, cspace: *mut crate::cap::cspace::CSpace) -> Self
    {
        Self {
            header,
            cspace,
            cspace_growth_budget_bytes: AtomicU64::new(0),
            cs_pool: PagePool::new(),
            arena_free: AtomicU64::new(0),
            arena_pages: AtomicPtr::new(core::ptr::null_mut()),
            deferred_next: core::ptr::null_mut(),
        }
    }

    /// Pop a free page from this `CSpace`'s pool, charging the growth budget,
    /// and zero it. Returns the page's physical address, or `None` if empty.
    /// Called from `CSpace::grow` for a slot or directory page, and for a
    /// thread's port-binding table ([`alloc_port_binding_table`]); the body
    /// arena pops its pages under the pool lock itself. Every credit lands
    /// under the pool lock together with the push of its page (`seed_pages`,
    /// [`free_pool_page`](Self::free_pool_page)), so a debit after a pop is
    /// always of a page already credited and the budget cannot wrap.
    #[cfg(not(test))]
    #[track_caller]
    pub fn alloc_slot_page(&self) -> Option<u64>
    {
        self.alloc_pool_page().map(|(phys, _)| phys)
    }

    /// [`alloc_slot_page`](Self::alloc_slot_page), also returning the page's
    /// donation record cell, for a page that goes back to the pool later
    /// ([`free_pool_page`](Self::free_pool_page)).
    #[cfg(not(test))]
    #[track_caller]
    fn alloc_pool_page(&self) -> Option<(u64, HolesCell)>
    {
        let phys = self.cs_pool.pop()?;
        // SAFETY: the page just left the free list; nothing wrote it.
        let cell = unsafe { pool_page_cell(phys) };
        self.cspace_growth_budget_bytes
            .fetch_sub(crate::mm::PAGE_SIZE as u64, Ordering::AcqRel);
        let virt = crate::mm::paging::phys_to_virt(phys);
        // SAFETY: page is now exclusively owned by the caller.
        unsafe { core::ptr::write_bytes(virt as *mut u8, 0, crate::mm::PAGE_SIZE) };
        Some((phys, cell))
    }

    /// Construct `body` in a chunk of this `CSpace`'s body arena, with its
    /// `header.ancestor` naming the chunk's [`ArenaPage`], so the dealloc
    /// cascade returns the chunk there ([`free_body`]). Returns the body's header, with the
    /// reference count `body` carries.
    ///
    /// The `CSpace` the calling syscall inserts the new capability into funds
    /// the body, as it funds the slot (core/kernel/docs/capability-internals.md
    /// § Body Arena).
    ///
    /// `T` must be `#[repr(C)]` with [`KernelObjectHeader`] at offset 0, as
    /// every kernel object type is; its size and alignment are checked at
    /// compile time against the chunk.
    ///
    /// # Errors
    /// `OutOfMemory` when no chunk is free and the pool has no page to carve.
    #[cfg(not(test))]
    #[track_caller]
    pub fn alloc_body<T>(
        &self,
        body: T,
    ) -> Result<NonNull<KernelObjectHeader>, syscall::SyscallError>
    {
        const {
            assert!(core::mem::size_of::<T>() <= crate::cap::arena::CHUNK_BYTES);
            assert!(crate::cap::arena::CHUNK_BYTES.is_multiple_of(core::mem::align_of::<T>()));
        };
        let chunk = self.alloc_chunk()?.cast::<T>();
        // SAFETY: the chunk is CHUNK_BYTES, aligned for T (asserted above),
        // and exclusively the caller's.
        unsafe { core::ptr::write(chunk, body) };
        let header = chunk.cast::<KernelObjectHeader>();
        let page = crate::cap::arena::page_of(chunk as usize) as *mut KernelObjectHeader;
        // SAFETY: every kernel object type holds its header at offset 0 (the
        // type requirement above), and the body was just written.
        unsafe {
            (*header).ancestor.store(page, Ordering::Release);
        }
        // SAFETY: chunk is non-null.
        Ok(unsafe { NonNull::new_unchecked(header) })
    }

    /// Take an empty [`MmioSpill`] chunk from the arena; the `Mmio` object that
    /// chains it frees it at its teardown.
    ///
    /// # Errors
    /// `OutOfMemory` when no chunk is free and the pool has no page to carve.
    #[cfg(not(test))]
    pub fn alloc_mmio_spill(&self) -> Result<NonNull<MmioSpill>, syscall::SyscallError>
    {
        // cast_ptr_alignment: a chunk is CHUNK_BYTES-aligned within its page,
        // which satisfies MmioSpill's alignment.
        #[allow(clippy::cast_ptr_alignment)]
        let chunk = self.alloc_chunk()?.cast::<MmioSpill>();
        // SAFETY: the chunk is CHUNK_BYTES (MmioSpill fits, asserted with its
        // definition), chunk-aligned, and exclusively ours.
        unsafe { core::ptr::write(chunk, MmioSpill::new()) };
        // SAFETY: chunk is non-null.
        Ok(unsafe { NonNull::new_unchecked(chunk) })
    }

    /// Take one chunk from the arena, carving a fresh pool page into a new
    /// [`ArenaPage`] when none is free, and take the chunk's reference on its
    /// page.
    #[cfg(not(test))]
    #[track_caller]
    fn alloc_chunk(&self) -> Result<*mut u8, syscall::SyscallError>
    {
        pool_lock(&self.cs_pool.lock);
        // SAFETY: pool lock held; every chunk on the list is the arena's.
        let mut chunk = unsafe { crate::cap::arena::pop_chunk(&self.arena_free) };
        if chunk.is_none()
        {
            // SAFETY: pool lock held.
            let phys = unsafe { pool_pop(&self.cs_pool.head_phys) };
            if phys != 0
            {
                // The credit of this page landed with its push, under the
                // lock held here.
                self.cspace_growth_budget_bytes
                    .fetch_sub(crate::mm::PAGE_SIZE as u64, Ordering::AcqRel);
                let page = crate::mm::paging::phys_to_virt(phys) as *mut ArenaPage;
                // SAFETY: the page just left the free list; nothing wrote it.
                let record = unsafe { pool_page_cell(phys) } as u64;
                // SAFETY: pool lock held; the page just left the free list,
                // so it is exclusively the arena's; its chunk 0 takes the
                // header, the rest go on the free list.
                unsafe {
                    core::ptr::write(
                        page,
                        ArenaPage {
                            header: KernelObjectHeader::new(ObjectType::ArenaPage),
                            owner: AtomicPtr::new(core::ptr::from_ref(self).cast_mut()),
                            next: AtomicPtr::new(self.arena_pages.load(Ordering::Relaxed)),
                            kept_next: AtomicPtr::new(core::ptr::null_mut()),
                            lock: AtomicU64::new(0),
                            record: AtomicU64::new(record),
                        },
                    );
                    self.arena_pages.store(page, Ordering::Release);
                    crate::cap::arena::carve_page(&self.arena_free, page.cast::<u8>());
                    chunk = crate::cap::arena::pop_chunk(&self.arena_free);
                }
            }
        }
        if let Some(c) = chunk
        {
            let page = crate::cap::arena::page_of(c as usize) as *const ArenaPage;
            // SAFETY: the chunk's page is live, held by this owner (pool lock
            // held, so its teardown cannot run).
            unsafe { (*page).header.inc_ref() };
        }
        pool_unlock(&self.cs_pool.lock);
        chunk.ok_or(syscall::SyscallError::OutOfMemory)
    }

    /// Return a page taken from this pool (a port-binding table's) to it,
    /// with its donation record cell, crediting the budget under the pool
    /// lock.
    ///
    /// # Safety
    /// `phys` and `cell` came from this wrapper's
    /// [`alloc_pool_page`](Self::alloc_pool_page) and nothing references the
    /// page any more.
    #[cfg(not(test))]
    #[track_caller]
    unsafe fn free_pool_page(&self, phys: u64, cell: HolesCell)
    {
        pool_lock(&self.cs_pool.lock);
        // SAFETY: pool lock held; caller contract.
        unsafe { pool_push_tagged(&self.cs_pool.head_phys, phys, cell) };
        self.cspace_growth_budget_bytes
            .fetch_add(crate::mm::PAGE_SIZE as u64, Ordering::AcqRel);
        pool_unlock(&self.cs_pool.lock);
    }

    /// Pass over every arena page at teardown, after the objects the
    /// `CSpace`'s slots held are torn down: clear its owner under its lock,
    /// so no later chunk free touches this wrapper, and keep the pages that
    /// still hold a live chunk, each with the teardown's hold (the owner's,
    /// carried over): each is linked onto its donation record's list of kept
    /// pages (through [`ArenaPage::next`]), and all of them onto the returned
    /// list (through [`ArenaPage::kept_next`]). A page with no live chunk is
    /// left to go back with its donation.
    ///
    /// # Safety
    /// The wrapper's reference count is zero and its `CSpace` is drained, so no
    /// chunk is allocated any more; no lock is held.
    #[cfg(not(test))]
    unsafe fn orphan_arena_pages(&self) -> *mut ArenaPage
    {
        let mut kept: *mut ArenaPage = core::ptr::null_mut();
        let mut cur = self
            .arena_pages
            .swap(core::ptr::null_mut(), Ordering::AcqRel);
        while !cur.is_null()
        {
            // SAFETY: a page of this arena, live: it is held by the owner hold
            // the teardown now carries.
            let page = unsafe { &*cur };
            let next = page.next.load(Ordering::Relaxed);
            pool_lock(&page.lock);
            page.owner.store(core::ptr::null_mut(), Ordering::Release);
            pool_unlock(&page.lock);
            // No chunk can be allocated, so a count of 1 (the hold alone)
            // stays 1; a higher count can only fall, never below the hold.
            if page.header.ref_count.load(Ordering::Acquire) > 1
            {
                let cell = page.record.load(Ordering::Relaxed) as HolesCell;
                if cell.is_null()
                {
                    crate::fatal("CSpace teardown: an arena page carries no donation record");
                }
                // SAFETY: the cell is a field of a record of this pool, which
                // stays intact until the donations are reclaimed after this
                // pass; only this pass writes it.
                unsafe {
                    page.next.store(*cell, Ordering::Relaxed);
                    *cell = cur;
                }
                page.kept_next.store(kept, Ordering::Relaxed);
                kept = cur;
            }
            cur = next;
        }
        kept
    }

    /// Record a freshly-retyped donation, seed its pool pages, and credit the
    /// growth budget with the pages actually seeded.
    ///
    /// # Safety
    /// See [`AddressSpaceObject::add_donation`].
    #[cfg(not(test))]
    #[track_caller]
    pub unsafe fn add_donation(
        &self,
        ancestor: NonNull<KernelObjectHeader>,
        ancestor_memory_base: u64,
        base_offset: u64,
        total_pages: u64,
        pool_pages: u64,
    ) -> Result<(), ()>
    {
        // SAFETY: forwarded from the caller's contract.
        unsafe {
            self.cs_pool.add_donation(
                ancestor,
                ancestor_memory_base,
                base_offset,
                total_pages,
                pool_pages,
                &self.cspace_growth_budget_bytes,
            )
        }
    }
}

/// Allocate a thread's port-binding table from `funder`'s pool, the pool of
/// the thread's own `CSpace`: the table's page and the pages of its bitmap's
/// parts, initialised with every port denied
/// (core/kernel/docs/capability-internals.md § `IoPort` Bindings).
///
/// # Errors
/// `OutOfMemory` when the pool cannot supply every page; the pages already
/// taken are returned.
#[cfg(not(test))]
pub fn alloc_port_binding_table(
    funder: &CSpaceKernelObject,
) -> Result<*mut crate::cap::ioport_bindings::IoPortBindings, syscall::SyscallError>
{
    use crate::arch::current::{IOPB_PART_BYTES, IOPB_PARTS};
    use crate::cap::ioport_bindings::{IoPortBindings, TABLE_PAGES};
    use crate::mm::paging::phys_to_virt;

    let mut pages = [0u64; TABLE_PAGES];
    let mut cells = [0usize; TABLE_PAGES];
    for i in 0..TABLE_PAGES
    {
        let Some((phys, cell)) = funder.alloc_pool_page()
        else
        {
            for (&phys, &cell) in pages[..i].iter().zip(&cells[..i])
            {
                // SAFETY: a page taken above and never used, with its cell.
                unsafe { funder.free_pool_page(phys, cell as HolesCell) };
            }
            return Err(syscall::SyscallError::OutOfMemory);
        };
        pages[i] = phys;
        cells[i] = cell as usize;
    }
    let mut parts = [core::ptr::null_mut::<[u8; IOPB_PART_BYTES]>(); IOPB_PARTS];
    for (part, &phys) in parts.iter_mut().zip(&pages[1..])
    {
        *part = phys_to_virt(phys) as *mut [u8; IOPB_PART_BYTES];
    }
    let table = phys_to_virt(pages[0]) as *mut IoPortBindings;
    // SAFETY: every page was taken above, page-aligned and exclusively ours;
    // each stays live until `free_port_binding_table` returns it.
    unsafe {
        IoPortBindings::init_in_place(table, parts, core::ptr::from_ref(funder) as usize, cells);
    }
    Ok(table)
}

/// Return a port-binding table's pages to the pool of the `CSpace` that funded
/// them, the bound thread's own.
///
/// # Safety
/// `table` came from [`alloc_port_binding_table`] and nothing references it
/// or its parts any more; its funder is live, which holds while the table's
/// thread is registered and its `sched_lock` is held, since a `CSpace`'s
/// teardown frees the tables of its threads under that lock first
/// (`ioport_bindings::free_tables_bound_to`).
#[cfg(not(test))]
pub unsafe fn free_port_binding_table(table: *mut crate::cap::ioport_bindings::IoPortBindings)
{
    use crate::mm::paging::virt_to_phys;
    // SAFETY: caller contract; the table names the funder its pages came from.
    let (funder, parts, cells) = unsafe {
        (
            &*((*table).funder() as *const CSpaceKernelObject),
            (*table).bitmap.parts,
            (*table).page_cells(),
        )
    };
    for (part, &cell) in parts.iter().zip(&cells[1..])
    {
        // SAFETY: a part page this table took, with its cell; unreferenced
        // (contract).
        unsafe { funder.free_pool_page(virt_to_phys(*part as u64), cell as HolesCell) };
    }
    // SAFETY: the table's own page, taken with the parts, with its cell;
    // nothing reads it after this.
    unsafe { funder.free_pool_page(virt_to_phys(table as u64), cells[0] as HolesCell) };
}

/// The wrapper of the `CSpace` at `cspace`: the arena that funds the bodies a
/// syscall inserting into that `CSpace` creates
/// ([`CSpaceKernelObject::alloc_body`]).
///
/// # Errors
/// `OutOfMemory` for a `CSpace` without a wrapper, which has no arena to fund
/// from (only the host-test stubs).
///
/// # Safety
/// `cspace` is a live `CSpace` the caller keeps live while it uses the
/// returned reference: its own, bound to the running thread; one named by a
/// capability it holds a pin on; or the bound `CSpace` of a thread whose
/// `sched_lock` the caller holds while that thread is not `Exited`, which
/// `sys_ioport_bind` uses. A `CSpace`'s teardown marks every thread bound to
/// it `Exited` under that lock before it frees anything, and frees their
/// port-binding tables under it before it reclaims the pool
/// (`ioport_bindings::free_tables_bound_to`).
#[cfg(not(test))]
pub unsafe fn arena_of<'a>(
    cspace: *mut crate::cap::cspace::CSpace,
) -> Result<&'a CSpaceKernelObject, syscall::SyscallError>
{
    // SAFETY: caller contract.
    let kobj = unsafe { (*cspace).kobj_ptr() }.ok_or(syscall::SyscallError::OutOfMemory)?;
    // SAFETY: a wired wrapper outlives its CSpace's pins (caller contract).
    Ok(unsafe { &*kobj })
}

/// Kernel object for an IPC endpoint (Endpoint capability).
#[repr(C)]
pub struct EndpointObject
{
    pub header: KernelObjectHeader,
    /// Pointer to the endpoint's mutable state, inline at
    /// `wrapper + size_of::<EndpointObject>()` (24) in
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
/// `WaitSetState` is the body, inline immediately after the 24-byte wrapper,
/// followed by the caller-sized member slots and ready ring, all in one retype
/// slot (`cap::retype::wait_set_dispatch`).
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
    let (tid, tf) = unsafe {
        (
            (*tcb).thread_id,
            (*tcb)
                .trap_frame
                .load(core::sync::atomic::Ordering::Relaxed),
        )
    };
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

/// Release one reference on `obj` that the caller owns, and free the object
/// if it was the last.
///
/// The release half of a syscall's pin ([`crate::syscall::PinnedCap`]), of
/// the reference a moved capability's freed source slot held
/// (`cap::transfer::release_moved_object`), of the slot references a range
/// split's consumed original and a memory merge's consumed tail held, of a
/// copy's or derive's unpublished new-slot reference, of the address-space
/// reference an Mmio mapping record held (`MmioObject::withdraw_mappings`),
/// of the fault-handler binding a rebind or unbind replaces
/// (`sys_thread_set_fault_handler`), and of the endpoint pin a fault delivery
/// holds until before its park (`ipc::fault::fault_dispatch`).
/// Pins, moves, and mapping records may name an object bound to the running
/// thread, so a `Thread`, `CSpace`, or `AddressSpace` whose last reference
/// goes here is queued for this CPU's deferred reclaim (drained at the next
/// syscall epilogue or idle loop) rather than torn down in place. Every other
/// type frees in place through [`dealloc_object`], which may take
/// `DERIVATION_LOCK` and the frame allocator and, for a Notification, an
/// `EventQueue`, or an Endpoint, wakes the waiters it drains (the running
/// thread among them, when it is parked on the object it released), for a
/// Notification first removes its IRQ bindings and waits out the device-IRQ
/// deliveries in flight on their lines (`irq::unregister_notification`), for a
/// Notification or
/// `EventQueue` waits for the timer's in-flight wakeup batch
/// (`sched::sleep_wakeups_quiesce`), and for an Mmio or `IoPort` object
/// waits for the TLB shootdown or takes the thread registry lock its
/// withdrawal needs — bounded waits that complete only when no IPC,
/// scheduler, or sleep-list lock is held; hence the lock preconditions below.
///
/// # Safety
///
/// - `obj` must carry an outstanding reference the caller owns, which this
///   call consumes.
/// - A stable CPU index, which the deferred-reclaim push needs: syscall
///   context with interrupts disabled; fault delivery on the faulting thread
///   with interrupts disabled, before its park (`ipc::fault::fault_dispatch`,
///   releasing an Endpoint, which frees in place and never reaches the push);
///   or the idle thread (pinned to its CPU) draining the deferred-reclaim
///   stack, which reaches here through an Mmio object's teardown
///   (`MmioObject::withdraw_mappings`).
/// - Must NOT be called with `DERIVATION_LOCK` held, nor with any IPC source,
///   per-TCB `sched_lock`, per-CPU scheduler, or sleep-list lock held (the
///   preconditions `dealloc_object` states).
#[cfg(not(test))]
pub unsafe fn release_ref(obj: NonNull<KernelObjectHeader>)
{
    // SAFETY: the caller owns an outstanding reference on obj, so it is live
    // until this decrement.
    if unsafe { obj.as_ref().dec_ref() } != 0
    {
        return;
    }
    // SAFETY: refcount reached 0; nothing else references the object, apart
    // from a `CSpace` wrapper's arena pages' `owner` back-pointer, used only
    // for `cs_pool.lock` and `arena_free` (`free_arena_chunk`).
    match unsafe { obj.as_ref().obj_type }
    {
        ObjectType::Thread | ObjectType::CSpaceObj | ObjectType::AddressSpace =>
        {
            let cpu = crate::arch::current::cpu::current_cpu() as usize;
            // SAFETY: refcount 0, exclusively owned (but for a `CSpace`
            // wrapper's arena-page `owner` back-pointer, which
            // `push_deferred_reclaim` allows), a linkable type; the CPU index
            // is stable (syscall context with interrupts disabled, or the
            // pinned idle thread's drain, per the contract).
            unsafe { push_deferred_reclaim(cpu, obj) };
        }
        _ =>
        {
            // SAFETY: refcount 0; no other references exist; no lock held
            // (contract).
            unsafe { dealloc_object(obj) };
        }
    }
}

/// Push an object whose free must not complete here onto this CPU's
/// deferred-reclaim stack.
///
/// Two producers. A thread deleting the last capability to its own `Thread`
/// object cannot run `dealloc_object`'s drain gate, which spins until the
/// target TCB is no longer `current` on any CPU (#341); a thread deleting
/// the last capability to its own `CSpace` or `AddressSpace` — directly, or
/// through the cascade of another object's teardown — cannot free storage
/// it is executing on (its slot pages, its root page table). In each case
/// the arm marks the thread `Exited`, pushes the object here, and returns;
/// the syscall epilogue then `schedule()`s away and
/// [`drain_deferred_reclaim`] completes the free from a context that is
/// provably not a bound thread. Second, [`release_ref`] pushes a `Thread`,
/// `CSpace`, or `AddressSpace` whose last reference it drops — a batched
/// capability move's freed source slot (`cap::transfer::release_moved_object`)
/// or a syscall's pin — from a live thread: possibly one bound to it, and
/// possibly from inside IPC delivery, where a teardown's bound-thread stop and
/// cross-CPU waits must not run; and the `AddressSpace` an Mmio object's
/// mapping record held, released by that object's teardown
/// (`MmioObject::withdraw_mappings`) from a syscall or from the idle thread's
/// own drain.
///
/// # Safety
/// `ptr` is an exclusively-owned `Thread`, `CSpaceObj`, or `AddressSpace`
/// object (refcount 0), apart from a `CSpace` wrapper's arena pages' `owner`
/// back-pointer, used only for the wrapper's `cs_pool.lock` and `arena_free`
/// (`free_arena_chunk`), never its `deferred_next`. A `Thread` pushed by a
/// self-teardown is already `Exited` and unlinked from every run queue; one
/// pushed by `release_ref` may be in any state, and the drain's Thread arm
/// then runs `dealloc_object`'s ordinary stop-and-drain — or its self net
/// when the draining thread is that thread. `cpu` is the local CPU index
/// (`< MAX_CPUS`) and its scheduler is initialised.
// cast_ptr_alignment: the `*mut u8` head only ever holds an object pointer
// stored by this function (header at offset 0, 8-byte aligned).
#[allow(clippy::cast_ptr_alignment)]
#[cfg(not(test))]
pub(crate) unsafe fn push_deferred_reclaim(cpu: usize, ptr: NonNull<KernelObjectHeader>)
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
        // SAFETY: node is exclusively owned (refcount 0) but for the `owner`
        // back-pointer the contract allows, which never reaches the link
        // field; the link field is ours.
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
/// the idle loop — neither is one of the queued dead threads, so re-entering
/// `dealloc_object` runs the normal arm: the Thread arm's `current`-anywhere
/// scan and `context_saved` gate pass on the first iteration, and the
/// `CSpace`/`AddressSpace` arms stop whatever threads are still bound (a
/// self-teardown producer left them `Exited` and off-CPU already; a move
/// producer may have left them live). If the draining thread is itself
/// bound to a queued object, that arm stops it, re-queues the object
/// through `defer_self_teardown`, and returns; the epilogue's post-drain
/// `Exited` check then schedules the thread away and the next drain on this
/// CPU completes the free.
///
/// # Safety
/// The running thread must be alive and on its own kernel stack. A thread
/// whose own `Thread` object was queued by a self-teardown is `Exited`,
/// reaches the Exited arm of the syscall epilogue, and `schedule()`s away,
/// never the drain arm; one whose own object reached the stack through
/// `release_ref` is caught by the Thread arm's self net, which
/// marks it `Exited`, re-queues the object, and returns, so the epilogue's
/// post-drain `Exited` check schedules it away.
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
        // SAFETY: node was pushed by push_deferred_reclaim (refcount 0;
        // exclusively owned but for the `owner` back-pointer its contract
        // allows, which never reaches the link field); the link field is
        // stable until freed.
        let nn = unsafe { NonNull::new_unchecked(node) };
        // SAFETY: nn is a linkable object pushed by push_deferred_reclaim.
        let next = unsafe { *deferred_link(nn) };
        // SAFETY: refcount 0 and no slot references it (dealloc_object's
        // contract); re-enters the object's arm from a context bound to
        // nothing queued here, running the full free.
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
    let cur = unsafe { crate::sched::scheduler_for(this_cpu).current() };
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
    // SAFETY: refcount 0, exclusively owned but for a `CSpace` wrapper's
    // arena-page `owner` back-pointer, which `push_deferred_reclaim` allows,
    // and of a linkable type; queued for off-CPU reclaim on this CPU.
    unsafe { push_deferred_reclaim(this_cpu, ptr) };
}

/// Unlink a dying thread from the source queue its park binding names, under
/// the source lock `ipc::lock_bound_source` took (step 11 of
/// core/kernel/docs/thread-lifecycle-and-sleep.md § `dealloc_object(Thread)`
/// Drain Protocol). A thread a waker already claimed is not on the queue, and
/// the unlink is a no-op.
///
/// # Safety
/// `tcb` is the dying, valid TCB; `blocked_on` is the source state its
/// binding names under `bound_state` (a source-blocking state), whose lock the
/// caller holds together with `tcb`'s `sched_lock`.
// cast_ptr_alignment: blocked_on_object stores a type-erased pointer to the
// source state bound_state names, whose allocation guarantees its alignment.
#[allow(clippy::cast_ptr_alignment)]
#[cfg(not(test))]
unsafe fn unlink_dying_waiter(
    tcb: *mut crate::sched::thread::ThreadControlBlock,
    bound_state: crate::sched::thread::IpcThreadState,
    blocked_on: *mut u8,
)
{
    use crate::sched::thread::IpcThreadState;

    // SAFETY: blocked_on is the live source of the named type, and its lock
    // is held (contract), which serialises every queue edit below.
    unsafe {
        match bound_state
        {
            IpcThreadState::BlockedOnNotification =>
            {
                let sig = blocked_on.cast::<crate::ipc::notification::NotificationState>();
                if (*sig).waiters.remove(tcb)
                {
                    (*sig).refresh_observer();
                }
            }
            IpcThreadState::BlockedOnSend =>
            {
                let ep = &mut *blocked_on.cast::<crate::ipc::endpoint::EndpointState>();
                crate::ipc::endpoint::unlink_from_wait_queue(
                    tcb,
                    &mut ep.send_head,
                    &mut ep.send_tail,
                );
                // Republish send-queue level (#285-adjacent): this unlink can
                // empty the queue, and the wait-set self-heal reads the shadow
                // locklessly.
                ep.refresh_send_ready();
            }
            IpcThreadState::BlockedOnRecv =>
            {
                let ep = &mut *blocked_on.cast::<crate::ipc::endpoint::EndpointState>();
                crate::ipc::endpoint::unlink_from_wait_queue(
                    tcb,
                    &mut ep.recv_head,
                    &mut ep.recv_tail,
                );
            }
            IpcThreadState::BlockedOnEventQueue =>
            {
                let eq = blocked_on.cast::<crate::ipc::event_queue::EventQueueState>();
                (*eq).waiters.remove(tcb);
            }
            IpcThreadState::BlockedOnWaitSet =>
            {
                let ws = blocked_on.cast::<crate::ipc::wait_set::WaitSetState>();
                (*ws).waiters.remove(tcb);
            }
            _ =>
            {}
        }
    }
}

// ── Dealloc cascade stack ─────────────────────────────────────────────────────

/// Width of the cascade link a queued header holds: the 32 bits of
/// `ref_count` and the 24 of `cascade_link_hi`.
const CASCADE_LINK_BITS: u32 = 56;

/// The objects a [`dealloc_object`] call has orphaned and not yet torn down:
/// a LIFO linked through the objects' own headers, so it holds any number of
/// them without allocating.
///
/// Only a refcount-0 object that nothing else references, and that is on no
/// stack, is pushed; the one reference allowed is a `CSpace` wrapper's arena
/// pages' `owner` back-pointer, through which a chunk free reaches only the
/// wrapper's `cs_pool.lock` and `arena_free` until the wrapper's second run
/// clears it. An object reaches 0 once, so only the stack of the call that
/// took it there holds it, and at most once at a time: the one object pushed
/// twice is that `CSpace` wrapper, whose first teardown run, having been
/// popped, re-queues it beneath the objects its slots held for its second
/// (core/kernel/docs/capability-internals.md § Teardown). While it is queued,
/// the header's `ref_count` and `cascade_link_hi` hold the link to the object
/// below it (its virtual address shifted right by 3, every header being
/// 8-byte aligned, kept to [`CASCADE_LINK_BITS`] and sign-extended back,
/// which every canonical address of up to 59 significant bits survives);
/// `obj_type` and `ancestor`, which the teardown reads, are never written.
/// [`Self::pop`] zeroes both link fields again, so the object it returns
/// reads `ref_count == 0`, as when it was pushed.
struct CascadeStack
{
    top: Option<NonNull<KernelObjectHeader>>,
}

impl CascadeStack
{
    /// An empty stack.
    const fn new() -> Self
    {
        Self { top: None }
    }

    /// The link word that names `next` (0 for none).
    fn encode(next: Option<NonNull<KernelObjectHeader>>) -> u64
    {
        let Some(next) = next
        else
        {
            return 0;
        };
        let va = next.as_ptr() as u64;
        debug_assert!(
            va.trailing_zeros() >= 3,
            "cascade: header {va:#x} not 8-byte aligned"
        );
        let word = (va >> 3) & ((1 << CASCADE_LINK_BITS) - 1);
        debug_assert!(
            Self::decode(word) == Some(next),
            "cascade: header {va:#x} outside the link's address range"
        );
        word
    }

    /// The header a link word names (`None` for 0).
    fn decode(word: u64) -> Option<NonNull<KernelObjectHeader>>
    {
        // Sign-extend the CASCADE_LINK_BITS-bit word, then restore the three
        // alignment bits: `(word << 8) >> 5`, arithmetic.
        // cast_possible_wrap, cast_sign_loss: the casts reinterpret the bits
        // for the arithmetic shift; no value is converted.
        #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
        let va = (((word << (64 - CASCADE_LINK_BITS)) as i64) >> (61 - CASCADE_LINK_BITS)) as u64;
        NonNull::new(va as *mut KernelObjectHeader)
    }

    /// Read the link word `obj`'s header holds.
    ///
    /// # Safety
    /// `obj` is a header on this stack.
    unsafe fn read_link(obj: NonNull<KernelObjectHeader>) -> u64
    {
        // SAFETY: caller contract; the queued object's link fields are this
        // stack's alone, so nothing writes them concurrently.
        let (lo, hi) = unsafe {
            (
                (*obj.as_ptr()).ref_count.load(Ordering::Relaxed),
                (*obj.as_ptr()).cascade_link_hi,
            )
        };
        u64::from(lo)
            | (u64::from(hi[0]) << 32)
            | (u64::from(hi[1]) << 40)
            | (u64::from(hi[2]) << 48)
    }

    /// Store `word` in `obj`'s link fields.
    ///
    /// # Safety
    /// `obj`'s link fields are the caller's alone and no reference to its
    /// header is used across this call.
    unsafe fn write_link(obj: NonNull<KernelObjectHeader>, word: u64)
    {
        // cast_possible_truncation: each cast keeps exactly the bits its
        // field holds.
        #[allow(clippy::cast_possible_truncation)]
        let (lo, hi) = (
            word as u32,
            [(word >> 32) as u8, (word >> 40) as u8, (word >> 48) as u8],
        );
        // SAFETY: caller contract.
        unsafe {
            (*obj.as_ptr()).ref_count.store(lo, Ordering::Relaxed);
            core::ptr::addr_of_mut!((*obj.as_ptr()).cascade_link_hi).write(hi);
        }
    }

    /// Queue `obj` for teardown.
    ///
    /// # Safety
    /// `obj` is a live object's header whose reference count is 0, that no
    /// capability slot, pin, or other kernel owner references, that is on no
    /// cascade stack, and that the caller owns exclusively; no reference to
    /// its header is used after this call. The one exception to "no other
    /// owner" is a `CSpace` wrapper's arena pages' `owner` back-pointer, used
    /// only for the wrapper's `cs_pool.lock` and `arena_free`
    /// (`free_arena_chunk`), never its header.
    unsafe fn push(&mut self, obj: NonNull<KernelObjectHeader>)
    {
        // SAFETY: caller contract (a live header).
        let refs = unsafe { obj.as_ref() }.ref_count.load(Ordering::Relaxed);
        debug_assert_eq!(refs, 0, "cascade: pushed object is still referenced");
        // SAFETY: caller contract: the link fields are ours alone; the one
        // other reference it allows, a `CSpace` wrapper's arena-page `owner`
        // back-pointer, never reaches the header.
        unsafe { Self::write_link(obj, Self::encode(self.top)) };
        self.top = Some(obj);
    }

    /// Take the most recently pushed object, its link fields zeroed.
    fn pop(&mut self) -> Option<NonNull<KernelObjectHeader>>
    {
        let top = self.top?;
        // SAFETY: `top` was queued by `push`, whose contract keeps it live,
        // its link fields this stack's alone, and unreferenced but for the
        // `owner` back-pointer it allows until it is popped here.
        unsafe {
            self.top = Self::decode(Self::read_link(top));
            Self::write_link(top, 0);
        }
        Some(top)
    }
}

/// Tear down `first` and everything its teardown orphans: `teardown` runs on
/// `first`, then on each object it or a later run pushed onto the stack, most
/// recent first, until the stack is empty.
///
/// The driver of [`dealloc_object`]; generic so the host tests drive the same
/// loop with a model teardown.
fn run_cascade<F>(first: NonNull<KernelObjectHeader>, mut teardown: F)
where
    F: FnMut(NonNull<KernelObjectHeader>, &mut CascadeStack),
{
    let mut stack = CascadeStack::new();
    teardown(first, &mut stack);
    while let Some(next) = stack.pop()
    {
        teardown(next, &mut stack);
    }
}

/// Return each death-observer node of the chain starting at `first` to its
/// queue's pool and release the `EventQueueObject` reference the node held,
/// queueing a queue whose last reference this was on the cascade stack (its
/// dealloc then runs from the caller's loop, not by recursion). Called by an
/// owner's teardown (the Thread and `AddressSpace` arms) with the chain it
/// took, once no death walk can read it.
///
/// # Safety
/// The caller owns every node of the chain and holds no lock.
#[cfg(not(test))]
unsafe fn release_death_observers(
    first: *mut crate::sched::thread::DeathObserver,
    stack: &mut CascadeStack,
)
{
    // SAFETY: the caller took the chain, so it owns every node; each lives in
    // its queue, which the node's reference keeps live until the dec_ref
    // below, issued after the node is back in the pool. A queue at zero has no
    // capability or binding left, so it is unreferenced for the push.
    unsafe {
        crate::sched::thread::for_each_observer(first, |node| {
            let eq = (*node).eq;
            crate::ipc::event_queue::event_queue_return_observer((*eq).state, node);
            if (*eq).header.dec_ref() == 0
            {
                stack.push(NonNull::new_unchecked(eq.cast::<KernelObjectHeader>()));
            }
        });
    }
}

/// Free the body of an object of concrete type `T`: drop it in place and
/// return its bytes to its ancestor. A body a `CSpace`'s arena funded goes back
/// to its arena page, releasing the page's reference
/// ([`CSpaceKernelObject::alloc_body`]); any other goes back to its ancestor
/// Memory object (SEED for a boot mint), releasing the retype lease. Either
/// release that leaves the ancestor unreferenced pushes it onto `stack`.
///
/// # Safety
/// `ptr` is an exclusively owned, retype- or arena-backed `T` (header at
/// offset 0) that nothing references; no lock is held.
#[cfg(not(test))]
unsafe fn free_body<T>(ptr: NonNull<KernelObjectHeader>, stack: &mut CascadeStack)
{
    // SAFETY: caller contract.
    let ancestor_ptr = unsafe { ptr.as_ref().ancestor.load(Ordering::Acquire) };
    let Some(ancestor) = NonNull::new(ancestor_ptr)
    else
    {
        crate::fatal("free_body: object carries no ancestor");
    };
    // SAFETY: the object's lease keeps its ancestor live until it is released
    // below.
    if unsafe { ancestor.as_ref().obj_type } == ObjectType::ArenaPage
    {
        // A body a CSpace's arena funded (CSpaceKernelObject::alloc_body).
        // SAFETY: exclusively owned body of type T (caller contract).
        unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<T>()) };
        // SAFETY: the chunk came from an arena and is no longer used; no lock
        // is held (contract).
        unsafe { free_arena_chunk(ptr.as_ptr().cast::<u8>(), stack) };
        return;
    }
    // cast_ptr_alignment: any other ancestor is a MemoryObject (header at
    // offset 0).
    #[allow(clippy::cast_ptr_alignment)]
    // SAFETY: as above.
    let ancestor_memory = unsafe { &*ancestor.as_ptr().cast::<MemoryObject>() };
    let body_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
    let offset = body_phys - ancestor_memory.base;
    // SAFETY: exclusively owned body of type T (caller contract).
    unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<T>()) };
    // SAFETY: the body was retyped from its ancestor at this offset with this
    // size, and was dropped above; nothing references it (caller contract).
    unsafe {
        crate::cap::retype::retype_free(ancestor_memory, offset, core::mem::size_of::<T>() as u64);
    }
    if ancestor_memory.header.dec_ref() == 0
    {
        // SAFETY: the body's lease was the ancestor's last reference.
        unsafe { stack.push(ancestor) };
    }
}

/// Release the lineage share of a refcount-0 `Mmio`, `IoPort`, or `Interrupt` object of
/// concrete type `T`, freeing whatever bodies that leaves unreferenced: a
/// copy's own body at once, and its root's when the copy was the root's last
/// live member; a root's body only once it has no live copy
/// ([`RangeLineage`]).
///
/// # Safety
/// `ptr` is a refcount-0 `T`, exclusively owned, whose mappings or bindings
/// have been withdrawn; no lock is held.
#[cfg(not(test))]
unsafe fn release_range_object<T>(ptr: NonNull<KernelObjectHeader>, stack: &mut CascadeStack)
{
    // SAFETY: a live Mmio, IoPort, or Interrupt object (caller contract).
    let root = unsafe { lineage_of(ptr) }.root_of(ptr);
    if root != ptr
    {
        // A copy: nothing names its body once its references are gone.
        // SAFETY: caller contract.
        unsafe { free_body::<T>(ptr, stack) };
    }
    // The root's `live` share of this object: the root's own on a root, the
    // copy's on a copy. The last share frees the root.
    let share = if root == ptr { ROOT_SHARE } else { 1 };
    // SAFETY: the root body is kept by this object's share until this decrement.
    if unsafe { lineage_of(root) }
        .live
        .fetch_sub(share, Ordering::AcqRel)
        == share
    {
        // SAFETY: no reference and no live copy names the root any more.
        unsafe { free_body::<T>(root, stack) };
    }
}

/// The object a new capability slot made by `SYS_CAP_COPY`, `SYS_CAP_DERIVE`,
/// or `SYS_CAP_DERIVE_BADGE` from a slot naming `src` references, with the
/// reference the new slot holds already taken.
///
/// For an `Mmio`, `IoPort`, or `Interrupt` capability this is a fresh object
/// over the same range, in `src`'s lineage, funded by the arena of `dest`, the
/// `CSpace` that receives the new slot, so mappings, port bindings, and the
/// interrupt binding made through the new capability are withdrawn when it is
/// deleted, consumed by a split, or revoked through an ancestor, whatever other
/// capabilities to the range survive
/// (docs/capability-model.md § Interrupt, § Mmio, § `IoPort`); an `Interrupt`
/// copy starts unbound. Every other type shares `src`, whose reference count is
/// incremented.
///
/// The caller releases the returned reference with [`release_ref`] if the
/// slot is never published.
///
/// `hidden_tag` is `tag` as the source's `PinnedCap::hidden_tag` holds it,
/// the value each tag arm masks `src` by.
///
/// # Errors
/// For `Mmio`, `IoPort`, and `Interrupt`: `QuotaExceeded` when the lineage
/// already has [`RANGE_COPY_LIMIT`] live copies, and `OutOfMemory` when
/// `dest`'s arena cannot back the copy. For every other type: `QuotaExceeded`
/// when `src`'s reference count is at [`REF_COUNT_LIMIT`].
///
/// # Safety
/// `src` is the live object of a slot tagged `tag`, pinned by the caller,
/// `hidden_tag` equals `tag as usize`, and `dest` is a live `CSpace` the
/// caller pins.
// cast_ptr_alignment: each object is constructed in place at a
// size-class-aligned retype offset; the header sits at offset 0.
#[allow(clippy::cast_ptr_alignment)]
#[cfg(not(test))]
pub unsafe fn object_for_new_slot(
    tag: crate::cap::slot::CapTag,
    hidden_tag: usize,
    src: NonNull<KernelObjectHeader>,
    dest: *mut crate::cap::cspace::CSpace,
) -> Result<NonNull<KernelObjectHeader>, syscall::SyscallError>
{
    use crate::cap::slot::CapTag;

    // Each typed arm reads `src` selected by its own tag as data, compared
    // against `hidden_tag`, which the match on `tag` tells the compiler
    // nothing about, so an arm a mispredicted tag match reaches reads through
    // null, never an object of another type
    // (core/kernel/docs/capability-internals.md § Speculative-Execution
    // Hardening).
    let typed = |arm: CapTag| {
        crate::arch::nospec::select_ptr(
            crate::arch::nospec::mask_if(hidden_tag == arm as usize),
            src.as_ptr(),
            core::ptr::null_mut(),
        )
    };

    match tag
    {
        CapTag::Mmio =>
        {
            // SAFETY: tag Mmio; src pinned (contract); `typed` returns src for it.
            let mo = unsafe { &*typed(CapTag::Mmio).cast::<MmioObject>() };
            let root = mo.lineage.root_of(src);
            // SAFETY: src is a pinned member of root's lineage, so root's live
            // count is above zero.
            let lineage = unsafe { RangeLineage::reserve_copy(root) }?;
            let mut body = MmioObject::new_root(mo.base, mo.size, mo.flags);
            body.lineage = lineage;
            // SAFETY: dest is pinned (contract).
            unsafe { arena_of(dest) }
                .and_then(|funder| funder.alloc_body(body))
                .inspect_err(|_| {
                    // SAFETY: undoes the reservation above; src's own share keeps
                    // root's count above zero.
                    unsafe { lineage_of(root) }
                        .live
                        .fetch_sub(1, Ordering::AcqRel);
                })
        }
        CapTag::IoPort =>
        {
            // SAFETY: tag IoPort; src pinned (contract); `typed` returns src for it.
            let po = unsafe { &*typed(CapTag::IoPort).cast::<IoPortObject>() };
            let root = po.lineage.root_of(src);
            // SAFETY: as the Mmio arm.
            let lineage = unsafe { RangeLineage::reserve_copy(root) }?;
            let mut body = IoPortObject::new_root(po.base, po.size);
            body.lineage = lineage;
            // SAFETY: as the Mmio arm.
            unsafe { arena_of(dest) }
                .and_then(|funder| funder.alloc_body(body))
                .inspect_err(|_| {
                    // SAFETY: as the Mmio arm.
                    unsafe { lineage_of(root) }
                        .live
                        .fetch_sub(1, Ordering::AcqRel);
                })
        }
        CapTag::Interrupt =>
        {
            // SAFETY: tag Interrupt; src pinned (contract); `typed` returns src for it.
            let io = unsafe { &*typed(CapTag::Interrupt).cast::<InterruptObject>() };
            let root = io.lineage.root_of(src);
            // SAFETY: as the Mmio arm.
            let lineage = unsafe { RangeLineage::reserve_copy(root) }?;
            let mut body = InterruptObject::new_root(io.start, io.count);
            body.lineage = lineage;
            // SAFETY: as the Mmio arm.
            unsafe { arena_of(dest) }
                .and_then(|funder| funder.alloc_body(body))
                .inspect_err(|_| {
                    // SAFETY: as the Mmio arm.
                    unsafe { lineage_of(root) }
                        .live
                        .fetch_sub(1, Ordering::AcqRel);
                })
        }
        _ =>
        {
            // A new slot is the reference userspace can multiply, so it is
            // refused at the ceiling (`REF_COUNT_LIMIT`).
            // SAFETY: src is pinned, so its count is above zero.
            unsafe { src.as_ref().try_inc_ref() }?;
            Ok(src)
        }
    }
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
/// - The CPU index must be stable — syscall context with interrupts disabled,
///   fault delivery with interrupts disabled before its park, or the idle
///   thread's deferred-reclaim drain — because the Mmio arm releases
///   address-space references through [`release_ref`].
/// - Must NOT be called with `DERIVATION_LOCK` held: the `CSpaceObj` arm
///   takes that (non-recursive) lock for its batched derivation drain, and
///   the Memory arm takes the frame-allocator lock.
/// - Must NOT be called with any IPC source, per-TCB `sched_lock`, per-CPU
///   scheduler, or sleep-list lock held: the Thread, Notification,
///   `EventQueue`, and Interrupt arms spin until work on other CPUs that takes
///   those locks finishes (with interrupts enabled: the Thread drain gates and
///   `sched::sleep_wakeups_quiesce`; with interrupts disabled under the IRQ
///   routing lock: the Notification and Interrupt arms' wait for in-flight
///   device-IRQ deliveries, `irq::unregister_notification` and
///   `irq::unregister`).
///
/// # Cascade handling
///
/// Tearing an object down releases references it held: its ancestor
/// `MemoryObject`'s retype lease, a pool donation's lease on its Memory
/// object, the references a dying `CSpace`'s slots hold, a wait set's
/// member references, a thread's fault-handler binding, death-observer
/// nodes' queue references. Each object one of those releases leaves
/// unreferenced is pushed onto a [`CascadeStack`] local to this call (and a
/// `CSpace` wrapper's first run re-pushes the wrapper beneath its slots'
/// objects, for the second run that returns its pool), linked through the
/// objects' own headers, and this function tears the stack down, most recent
/// first, until it is empty. No arm recurses into `dealloc_object`, so the
/// call's stack use is a constant whatever the fan-out (a caller-sized wait
/// set, a chain of observer nodes, a `CSpace`'s slots) or the depth of the
/// chain (a `CSpace` holding the last reference to another, a Memory object
/// whose last child frees it), and no arm runs inside another's lock scope.
/// The stack is unbounded and allocates nothing
/// (core/kernel/docs/capability-internals.md § Teardown).
#[cfg(not(test))]
pub unsafe fn dealloc_object(ptr: core::ptr::NonNull<KernelObjectHeader>)
{
    run_cascade(ptr, |next, stack| {
        // SAFETY: `next` is the caller's object (this function's contract)
        // or one an arm pushed, which `CascadeStack::push`'s contract leaves
        // unreferenced and exclusively owned but for a `CSpace` wrapper's
        // arena-page `owner` back-pointer; no lock is held between arms.
        unsafe { dealloc_object_one(next, stack) };
    });
}

/// Return a group of a dead pool's donations that share one Memory object,
/// sorted by offset, to that object through one walk of its page free list
/// (`retype::retype_free_runs`), but for the arena pages on each record's
/// `holes` list, which a `CSpace`'s teardown keeps (an `AddressSpace` pool's
/// records have none): each such page takes a lease of its own on the Memory
/// object and records it as its ancestor, and returns there with its last
/// chunk. Then drop the reference each donation held, pushing the Memory
/// object onto `stack` if that was its last.
///
/// Each record's kept pages are sorted once (the sorted list replaces its
/// `holes`) and its span walked with them in order, so a group of `g` records
/// with `k` kept pages costs one walk of the Memory object's page free list,
/// at most `g + k` insertions, and the sorts, `O(k log k)`.
///
/// # Safety
/// `group` is one group `PagePool::reclaim_donations` hands out, under that
/// function's contract; each record's `holes` is its list of kept pages
/// (linked through [`ArenaPage::next`] by
/// `CSpaceKernelObject::orphan_arena_pages`), every page on it held. No lock
/// is held.
#[cfg(not(test))]
unsafe fn free_donation_group(group: &mut [DonationRecord], stack: &mut CascadeStack)
{
    use crate::mm::paging::virt_to_phys;
    let Some(first) = group.first()
    else
    {
        return;
    };
    let anc_ptr = first.ancestor;
    debug_assert!(group.iter().all(|record| record.ancestor == anc_ptr));
    // cast_ptr_alignment: header at offset 0; MemoryObject is repr(C).
    #[allow(clippy::cast_ptr_alignment)]
    // SAFETY: the records' references keep their Memory object live until the
    // releases at the end.
    let anc_memory = unsafe { &*anc_ptr.cast::<MemoryObject>() };
    let offset_of = |page: *mut ArenaPage| virt_to_phys(page as u64) - anc_memory.base;
    for record in group.iter_mut()
    {
        // SAFETY: every page on the list is held (contract) and lies in this
        // donation's span (its record cell named this record).
        record.holes = unsafe {
            crate::cap::arena::sort_list(
                record.holes,
                &|page: *mut ArenaPage| (*page).next.load(Ordering::Relaxed),
                &|page: *mut ArenaPage, to| (*page).next.store(to, Ordering::Relaxed),
                &offset_of,
            )
        };
    }
    let kept = |sorted: *mut ArenaPage| {
        let mut cur = sorted;
        core::iter::from_fn(move || {
            // SAFETY: every page on the list is held (contract).
            let page = unsafe { cur.as_ref() }?;
            cur = page.next.load(Ordering::Relaxed);
            // The page's lease on the Memory object is taken while the
            // record's reference still holds it.
            anc_memory.header.inc_ref();
            page.header.ancestor.store(anc_ptr, Ordering::Release);
            Some(offset_of(core::ptr::from_ref(page).cast_mut()))
        })
    };
    let p = crate::mm::PAGE_SIZE as u64;
    // SAFETY: the runs are the parts of the records' page-class retypes that
    // no kept page covers, in ascending order (the records are sorted by
    // offset and their spans disjoint); the dead pool uses none of them.
    unsafe {
        crate::cap::retype::retype_free_runs(anc_memory, |free_run| {
            for record in &*group
            {
                let start = record.base_offset;
                let end = start + record.page_count * p;
                crate::cap::arena::for_each_run(start, end, kept(record.holes), |from, to| {
                    free_run(from, to - from);
                });
            }
        });
    }
    for _ in 0..group.len()
    {
        // SAFETY: one record's reference, released once, after every run.
        if unsafe { &*anc_ptr }.dec_ref() == 0
        {
            // SAFETY: refcount reached 0; no live cap holds it, and the
            // donations' bytes have been returned to it above.
            unsafe { stack.push(NonNull::new_unchecked(anc_ptr)) };
        }
    }
}

/// Return every donation of a dead `CSpace`'s pool, the create-time slab
/// (holding the wrapper and the pool) last, but for the arena pages the
/// teardown keeps, on its records' lists; `obj` is dangling afterwards. Then
/// release the teardown's hold on each kept page, through `kept`, pushing one
/// whose last chunk has gone meanwhile onto `stack`. No lock is held across
/// the walk (each return takes only its ancestor's cap lock), so nothing else
/// waits on it; it returns the donations in groups that share a Memory object
/// ([`free_donation_group`]), with interrupts taken between groups, and its
/// length is the number of donations the owner paid for plus the sort of the
/// kept pages.
///
/// # Safety
/// `obj`'s reference count is zero, its derivation drain has run and its
/// in-place `CSpace` is dropped, `kept` came from its
/// `CSpaceKernelObject::orphan_arena_pages`, and no lock is held.
#[cfg(not(test))]
unsafe fn reclaim_cspace_donations(
    obj: &CSpaceKernelObject,
    kept: *mut ArenaPage,
    stack: &mut CascadeStack,
)
{
    let free = |group: &mut [DonationRecord]| {
        // SAFETY: a group handed out by reclaim_donations under its
        // contract, with its kept pages; no lock held.
        unsafe { free_donation_group(group, stack) }
    };
    // SAFETY: caller contract.
    unsafe { obj.cs_pool.reclaim_donations(free) };
    let mut cur = kept;
    while !cur.is_null()
    {
        // SAFETY: a kept page, held by the teardown until the release below;
        // its ancestor and lease were set when its donation went back.
        let page = unsafe { &*cur };
        cur = page.kept_next.load(Ordering::Relaxed);
        debug_assert!(
            !page.header.ancestor.load(Ordering::Relaxed).is_null(),
            "a kept arena page lies in no donation of its CSpace"
        );
        if page.header.dec_ref() == 0
        {
            // SAFETY: its last chunk went while the teardown held it.
            unsafe { stack.push(NonNull::from(&page.header)) };
        }
    }
}

/// Reclaim one already-zero-refcount object. Every object the reclaim
/// leaves unreferenced (its ancestor `MemoryObject` when `dec_ref` returns
/// 0 against it, and the like) is pushed onto `stack` instead of recursing.
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
// items_after_statements: each arm imports the retype helpers it uses beside
// that use, after the arm's own statements.
#[allow(
    clippy::cast_ptr_alignment,
    clippy::too_many_lines,
    clippy::items_after_statements
)]
#[cfg(not(test))]
unsafe fn dealloc_object_one(ptr: core::ptr::NonNull<KernelObjectHeader>, stack: &mut CascadeStack)
{
    // SAFETY: ptr is NonNull<KernelObjectHeader>, validated at call site.
    let header = unsafe { ptr.as_ref() };
    match header.obj_type
    {
        // ── Simple objects (no sub-resources) ─────────────────────────────
        ObjectType::Memory =>
        {
            // Return buddy-backed physical memory before freeing the Rust
            // object. `owns_memory` is false only for firmware-table caps (ACPI
            // regions, RSDP, DTB), whose memory is not in the buddy, and for a
            // tail absorbed by `sys_memory_merge`. This is the buddy's only reverse
            // path; post-handoff the buddy is sealed (every `owns_memory` cap lives
            // permanently in memmgr's pool), so a live free here trips the seal —
            // see `buddy::free_range`.
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
            // The retype allocator lives inline in the MemoryObject and goes
            // with the object's own slot below; `RetypeAllocator` has no Drop
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

            // SAFETY: refcount 0, exclusively owned MemoryObject (dealloc_object's
            // contract); no lock is held.
            unsafe { free_body::<MemoryObject>(ptr, stack) };
        }
        ObjectType::Mmio =>
        {
            // Withdraw every mapping made through this capability's object
            // before its bytes go (docs/capability-model.md § Mmio).
            // SAFETY: refcount 0, so no slot or pin names the object and no map
            // records into it; no lock is held; the CPU is stable
            // (dealloc_object's contract).
            unsafe { (*ptr.as_ptr().cast::<MmioObject>()).withdraw_mappings(stack) };
            // SAFETY: a refcount-0 Mmio object; no lock held.
            unsafe { release_range_object::<MmioObject>(ptr, stack) };
        }
        ObjectType::Interrupt =>
        {
            // Remove this capability's binding of its line before its bytes go
            // (docs/capability-model.md § Interrupt): `irq::unregister` leaves an
            // unbound object (every range cap, and a line cap never registered)
            // untouched.
            // SAFETY: ptr points to a live InterruptObject; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<InterruptObject>()) };
            // SAFETY: not interrupt context, and no IPC source, scheduler, or
            // sleep-list lock is held (this function's contract), as
            // `irq::unregister` requires; the object stays live until the
            // release below.
            unsafe { crate::irq::unregister(obj.start, &obj.binding) };
            // SAFETY: a refcount-0 Interrupt object whose binding is removed; no
            // lock held.
            unsafe { release_range_object::<InterruptObject>(ptr, stack) };
        }
        ObjectType::IoPort =>
        {
            // Withdraw every port binding made through this capability's
            // object before its bytes go (docs/capability-model.md § IoPort).
            // SAFETY: no lock held; the pointer is only compared, never
            // dereferenced, by the withdrawal walk.
            unsafe { crate::cap::ioport_bindings::withdraw_everywhere(ptr.as_ptr() as usize) };
            // SAFETY: a refcount-0 IoPort object; no lock held.
            unsafe { release_range_object::<IoPortObject>(ptr, stack) };
        }
        ObjectType::SchedControl =>
        {
            // SAFETY: refcount 0, exclusively owned SchedControlObject (dealloc_object's
            // contract); no lock is held.
            unsafe { free_body::<SchedControlObject>(ptr, stack) };
        }
        ObjectType::SbiControl =>
        {
            // SAFETY: refcount 0, exclusively owned SbiControlObject (dealloc_object's
            // contract); no lock is held.
            unsafe { free_body::<SbiControlObject>(ptr, stack) };
        }

        // ── Arena page kept past its CSpace ───────────────────────────────
        ObjectType::ArenaPage =>
        {
            // Its last chunk has gone, and its CSpace with it: the page returns
            // to the Memory object its donation came from, releasing the lease
            // the CSpace's teardown gave it (free_donation_group).
            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);
            let Some(ancestor) = NonNull::new(ancestor_ptr)
            else
            {
                crate::fatal("dealloc ArenaPage: page kept without a donation");
            };
            // SAFETY: the page's lease keeps its Memory object live until the
            // release below.
            let ancestor_memory = unsafe { &*ancestor.as_ptr().cast::<MemoryObject>() };
            let offset =
                crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64) - ancestor_memory.base;
            // SAFETY: the page lies in a donation retyped from this Memory object
            // and was left out of its return; its last chunk and its CSpace have
            // gone, so nothing uses it.
            unsafe {
                crate::cap::retype::retype_free(
                    ancestor_memory,
                    offset,
                    crate::mm::PAGE_SIZE as u64,
                );
            }
            if ancestor_memory.header.dec_ref() == 0
            {
                // SAFETY: the page's lease was the ancestor's last reference.
                unsafe { stack.push(ancestor) };
            }
        }

        // ── Thread ────────────────────────────────────────────────────────
        ObjectType::Thread =>
        {
            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);

            // SAFETY: ptr points to a ThreadObject; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<ThreadObject>()) };
            let tcb = obj.tcb;

            // Self-teardown guard (#341): a dealloc of the running thread's own
            // Thread object (a self-targeting SYS_CAP_REVOKE, a teardown cascade, or
            // the deferred reclaim of an object a batched move dropped; SYS_CAP_DELETE
            // refuses a direct self thread-cap delete) cannot pass the drain gate
            // below; see core/kernel/docs/thread-lifecycle-and-sleep.md
            // § Self-teardown (the caller is the freed thread).
            // The drain gate below spins until `tcb` is no
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
                    crate::sched::scheduler_for(this_cpu).current()
                });
                if is_self
                {
                    log_self_teardown(tcb, "Thread");
                    // Self net. For SYS_CAP_DELETE this is unreachable —
                    // sys_cap_delete refuses a self thread-cap delete before the
                    // dec-ref. It guards every OTHER dealloc of the running
                    // thread: a self-targeting cap_revoke, and the deferred
                    // reclaim of a Thread object whose last reference a pin or
                    // a batched move dropped (`release_ref`) when the
                    // draining thread is that thread. Mark Exited + drain run
                    // queues (no free), queue the object for off-CPU reclaim,
                    // and return. The syscall epilogue observes Exited and
                    // schedule()s away; drain_deferred_reclaim completes the
                    // free off-CPU, where the existing gate passes immediately.
                    // SAFETY: tcb valid; marks Exited + drains every run queue
                    // under the all-CPU-locks discipline (mirrors `sys_exit`,
                    // `SYS_THREAD_EXIT`).
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
                // Remove the TCB from every run queue before freeing, so no scheduler
                // can dequeue a freed TCB after this dealloc completes. Drain protocol
                // per core/kernel/docs/thread-lifecycle-and-sleep.md
                // § `dealloc_object(Thread)` Drain Protocol: lock every CPU, commit
                // Exited, drain queues, and snapshot any reply-bound client for a wake
                // outside the all-locks region; the wake's target CPU is recomputed at
                // the deferred wake site below (#351).
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

                    // Acquire (*tcb).sched_lock first (outermost) so the Exited write
                    // serialises with schedule()'s dispatch flip and enqueue_and_wake on the
                    // same per-TCB lock; released right after the CPU locks below, before the
                    // UAF gate. Order per core/kernel/docs/scheduling-internals.md § Lock
                    // Hierarchy rule 4.
                    let tcb_sched_saved = (*tcb).sched_lock.lock_raw();

                    // Acquire all scheduler locks in ascending CPU order to
                    // prevent ABBA deadlock. Each CPU's saved interrupt-flag
                    // word is stashed in its own scheduler (under that lock).
                    for cpu in 0..cpu_count
                    {
                        crate::sched::scheduler_for(cpu).lock_saving_flags();
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

                    // A dying server orphans any reply-bound client: claim the reply slot
                    // (CAS), deposit only the resume disposition, and leave the client
                    // Blocked for the gated enqueue_and_wake below, per
                    // core/kernel/docs/thread-lifecycle-and-sleep.md § `dealloc_object(Thread)`
                    // Drain Protocol, step 5.
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
                        crate::sched::scheduler_for(cpu).unlock_saved_flags();
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
                    // Null the claimed client's `blocked_on_object` (still naming
                    // this dying server) under the client's sched_lock, before
                    // enqueue_and_wake and while wake_in_flight still pins `bound`:
                    // the CLOSURE LEMMA of core/kernel/docs/scheduling-internals.md
                    // § Cross-CPU TCB Ownership. Only the client's sched_lock is
                    // taken (the server's was released with the all-CPU locks
                    // above), so there is no two-TCB-sched_lock nesting.
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
                    // CPU stays inside this teardown through the wake-in-flight
                    // gate below, not in schedule(), so it cannot dispatch a
                    // client linked onto it — the save-window pin would strand a
                    // `context_saved==0` client here (#351; step 10 of
                    // core/kernel/docs/thread-lifecycle-and-sleep.md
                    // § `dealloc_object(Thread)` Drain Protocol). A peer
                    // dispatches it safely via the schedule()
                    // publication-barrier spin. Recomputing at wake time (rather
                    // than snapshotting under the all-CPU locks above) also
                    // closes the double-enqueue straddle: the target reflects
                    // the state at link time, not two unbounded spins earlier
                    // (#289).
                    let this_cpu = crate::arch::current::cpu::current_cpu() as usize;
                    // SAFETY: bound kept valid by wake_in_flight = 1 above;
                    // select_target_cpu_excluding is lock-free.
                    let bcpu =
                        unsafe { crate::sched::select_target_cpu_excluding(bound, Some(this_cpu)) };
                    // The reply-wake is never self-pinned to the wedged
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

                // Drop any sleep-list entry before the IPC unlink, so a timer pop
                // that wins the race still sees the full binding. Outside the
                // all-locks region (no sched.lock → SLEEP_LIST_LOCK edge). See
                // core/kernel/docs/thread-lifecycle-and-sleep.md
                // § `dealloc_object(Thread)` Drain Protocol, step 11.
                // SAFETY: tcb is valid (not yet freed).
                unsafe { crate::sched::sleep_list_remove(tcb) };

                // Unlink this thread from any IPC object it's blocked on.
                // Without this, a notification/endpoint/event_queue retains a
                // dangling waiter pointer to the freed TCB. A subsequent
                // notification_send would return that pointer, and the caller
                // would enqueue_and_wake a freed TCB — use-after-free.
                // The binding pair is read and cleared under tcb's sched_lock:
                // the abort arm of a wake that claimed tcb before its Exited
                // mark writes the same pair under that lock (see
                // core/kernel/docs/scheduling-internals.md § Cross-CPU TCB
                // Ownership). A source is reached only through
                // `ipc::lock_bound_source`, which re-reads the binding under
                // tcb's sched_lock and try-locks the source under it: a
                // binding still observed there names a source not yet freed,
                // so a concurrent last-capability delete of the source cannot
                // free it under this unlink.
                // SAFETY: tcb is valid (not yet freed); blocked_on_object
                // and ipc_state are always valid on an initialized TCB.
                unsafe {
                    use crate::sched::thread::IpcThreadState;
                    let sched_saved = (*tcb).sched_lock.lock_raw();
                    let blocked_obj = (*tcb).blocked_on_object;
                    let bound_state = (*tcb).ipc_state;
                    (*tcb).sched_lock.unlock_raw(sched_saved);
                    if !blocked_obj.is_null()
                    {
                        match bound_state
                        {
                            IpcThreadState::BlockedOnNotification
                            | IpcThreadState::BlockedOnSend
                            | IpcThreadState::BlockedOnRecv
                            | IpcThreadState::BlockedOnEventQueue
                            | IpcThreadState::BlockedOnWaitSet =>
                            {
                                if let Some(held) = crate::ipc::lock_bound_source(
                                    tcb,
                                    bound_state,
                                    blocked_obj,
                                    None,
                                )
                                {
                                    // SAFETY: `held` holds the live source's
                                    // lock and tcb's sched_lock.
                                    unlink_dying_waiter(tcb, bound_state, blocked_obj);
                                    // Retire the binding inside the hold, so
                                    // no later reader passes its re-read once
                                    // the source no longer queues tcb.
                                    (*tcb).blocked_on_object = core::ptr::null_mut();
                                    held.unlock();
                                }
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
                        let sched_saved = (*tcb).sched_lock.lock_raw();
                        (*tcb).blocked_on_object = core::ptr::null_mut();
                        (*tcb).sched_lock.unlock_raw(sched_saved);
                    }
                }

                // Release this thread's fault-handler bindings, one per class.
                // Each binding held an inc_ref on its endpoint object for its
                // lifetime (see ThreadControlBlock::fault_handlers); drop it, and
                // if this was its last reference enqueue the orphaned endpoint
                // on the cascade stack (rather than recursing into
                // `dealloc_object`, which the cascade exists to avoid). Done
                // after the unlink above (which removed this thread from the
                // endpoint's send queue if it was a queued faulter) so the
                // endpoint dealloc cannot observe this thread still on its queue.
                // SAFETY: tcb valid (not yet freed); the bindings are atomics;
                // no lock is held here; a binding's reference that was the
                // endpoint's last leaves it unreferenced for the push.
                unsafe {
                    for slot in &(*tcb).fault_handlers
                    {
                        let ep =
                            slot.swap(core::ptr::null_mut(), core::sync::atomic::Ordering::AcqRel);
                        if !ep.is_null() && (*ep).header.dec_ref() == 0
                        {
                            stack.push(core::ptr::NonNull::new_unchecked(
                                ep.cast::<KernelObjectHeader>(),
                            ));
                        }
                    }
                }

                // Release the death observers' EventQueue references. The
                // thread runs on no CPU (the gate above), so its death walk is
                // over or never runs, and no binder can pin it (refcount 0).
                // SAFETY: tcb valid (not yet freed) and unreachable by any
                // other path.
                let first = unsafe { (*tcb).death_observers.take() };
                // SAFETY: the chain was just taken; no lock is held here.
                unsafe { release_death_observers(first, stack) };

                // Wake-in-flight gate (#160): a waker that popped this thread
                // from a wait object (notification/endpoint/event_queue/wait_set)
                // under that object's lock sets `wake_in_flight = 1` before
                // releasing the lock and clears it in `enqueue_and_wake`. The
                // unlink above acquired the same wait-object lock after any
                // such waker released it, so this load cannot miss the set.
                // A server whose receive dequeued this thread and found its
                // rebind refused set the flag under `ep.lock` and retired the
                // binding under this thread's `sched_lock`, so the unlink found
                // no binding and skipped `ep.lock`; the binding re-read under
                // that `sched_lock` orders this load after the set instead.
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

                // A timer batch that popped this thread keeps its pointer, with no
                // reference, until it finishes: wait it out before the free (its
                // claim finds the waiter by address). See
                // core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List
                // Invariants, invariant 9.
                crate::sched::sleep_wakeups_quiesce();

                // Release the per-thread port-binding table to its thread's
                // CSpace's pool if one was
                // bound via `sys_ioport_bind` (x86-64 only). RISC-V threads never
                // set this field — there is no I/O port space — so `iopb` is
                // always null and this is a no-op there. The pointer is taken
                // under the thread's `sched_lock`: an `IoPort` teardown's
                // withdrawal walk (`ioport_bindings::withdraw_everywhere`) reads
                // the table under that lock while this TCB is still registered.
                // The table goes back under the same hold: the thread's
                // `CSpace`, whose pool funded it, frees the tables of its
                // threads under each one's lock before it reclaims its pool, so
                // a free inside the hold always finds that pool live.
                // SAFETY: tcb validated non-null; lock_raw/unlock_raw paired;
                // a non-null table was installed by sys_ioport_bind, and the
                // thread is off every CPU, so no TSS load reads it.
                unsafe {
                    let saved = (*tcb).sched_lock.lock_raw();
                    let table = (*tcb)
                        .iopb
                        .cast::<crate::cap::ioport_bindings::IoPortBindings>();
                    (*tcb).iopb = core::ptr::null_mut();
                    if !table.is_null()
                    {
                        free_port_binding_table(table);
                    }
                    (*tcb).sched_lock.unlock_raw(saved);
                }

                // The per-thread XSAVE / FP-save area is the pages after the
                // wrapper page of the Thread retype slot
                // (`sched::thread_slot::EXTENDED_OFFSET`); it
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
                // instead of plausible values. Both stores are volatile:
                // the lock-holder diagnostic may read the slot from another
                // CPU through a stale `current` pointer
                // (`sched::holder_info`) — a deliberate race the volatile
                // pair keeps well-defined — and `magic` also gates the
                // liveness debug assertions, so its store must not be
                // reordered or elided.
                // SAFETY: tcb is valid; we are about to free it.
                unsafe {
                    core::ptr::write_volatile(core::ptr::addr_of_mut!((*tcb).magic), 0);
                    core::ptr::write_volatile(core::ptr::addr_of_mut!((*tcb).priority), 0xFF);
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
            let raw_bytes = dispatch_for(ObjectType::Thread, 0)
                .map_or(crate::sched::thread_slot::thread_slot_bytes(), |e| {
                    e.raw_bytes
                });
            // SAFETY: ancestor_ptr is non-null: every production object is
            // retype-backed (`KernelObjectHeader::ancestor`).
            let ancestor_memory = unsafe { &*ancestor_ptr.cast::<MemoryObject>() };
            // The wrapper sits at the slot's `WRAPPER_OFFSET`, immediately
            // after the guard and the kstack pages (`sched::thread_slot`).
            let wrapper_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
            let block_phys = wrapper_phys - crate::sched::thread_slot::WRAPPER_OFFSET;
            let offset = block_phys - ancestor_memory.base;
            // Count this thread's stack depth before the slot is freed.
            // SAFETY: the kstack pages lie above the guard in the retype
            // slot, mapped through the direct map; the thread is dead, so
            // nothing runs on them.
            unsafe {
                crate::stack_depth::record_thread_stack(crate::mm::paging::phys_to_virt(
                    block_phys + crate::sched::thread_slot::STACK_OFFSET,
                ));
            }

            // SAFETY: ptr is in-place ThreadObject.
            unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<ThreadObject>()) };

            // Map the guard page back into the direct map before its memory
            // returns to the cap, then free the slot.
            // SAFETY: thread creation holed the slot's guard, and the thread
            // is dead; this arm holds no lock (`dealloc_object_one`'s
            // contract), after SMP bringup. The object was retyped from
            // `ancestor_memory` at `offset` with `raw_bytes`, and is dropped
            // above; nothing references it.
            unsafe {
                crate::mm::stack_guard::close(block_phys);
                retype_free(ancestor_memory, offset, raw_bytes);
            }

            let ancestor_nn =
                // SAFETY: ancestor_ptr non-null.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_memory.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: refcount reached 0.
                // SAFETY: the reference just released was its last.
                unsafe { stack.push(ancestor_nn) };
            }
        }

        // ── AddressSpace ──────────────────────────────────────────────────
        //
        // All `AddressSpace` objects are retype-backed: init's bootstrap AS
        // lands in a slab from `SEED_MEMORY` (Phase 9), and every userspace
        // AS lands in a slab from a Memory cap (`sys_cap_create_aspace`).
        // Both inline `AddressSpace` into the same wrapper page as
        // `AddressSpaceObject`; both record the create-time slab (wrapper,
        // root PT, and PT growth pool) as the pool's first donation.
        // Reclamation returns every donation to its Memory object wholesale
        // and drops the reference each held, the create-time slab last.
        ObjectType::AddressSpace =>
        {
            // SAFETY: ptr points at an in-place AddressSpaceObject; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<AddressSpaceObject>()) };
            let as_ptr = obj.address_space;

            debug_assert!(
                obj.pt_pool.has_create_donation(),
                "dealloc AddressSpace: donation-less AS reached typed-memory dealloc path"
            );

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
                    // SAFETY: as_ptr non-null; inactive_everywhere reads the set with Acquire.
                    unsafe { (*as_ptr).inactive_everywhere() },
                    "dealloc AddressSpace: freeing root while active_cpus != 0"
                );

                // Return this space's hardware tag (PCID/ASID) to the pool, if
                // any. No TLB flush is needed: active_cpus is empty (asserted
                // above), and any CPU that cached the tag while switched away is
                // flushed lazily by the generation check the next time it loads
                // the tag for whatever space claims it next.
                // free_tag reads the tag under the pool lock, since an eviction
                // can reissue this inactive space's tag to another space.
                // SAFETY: as_ptr is a valid AddressSpace being reclaimed.
                crate::mm::tag_allocator::free_tag(unsafe { &*as_ptr });

                // Lower the frame-map count of every frame the space still
                // maps (core/kernel/docs/memory-internals.md § Frame Map
                // Table): no CPU has it loaded and no bound thread can run
                // (both established above), so none of its leaves is used
                // again.
                // SAFETY: as_ptr is valid and being reclaimed; nothing maps
                // into it any more (refcount 0, no slot references it).
                unsafe { (*as_ptr).release_mapped_frames() };

                // Release the terminal-fault observers' EventQueue references.
                // Every bound thread is stopped and off-CPU (above), so no
                // terminal-fault post can still read them.
                // SAFETY: as_ptr valid and uniquely owned; death_lock not held.
                let first =
                    unsafe { crate::mm::address_space::AddressSpace::take_death_observers(as_ptr) };
                // SAFETY: the chain was just taken; no lock is held here.
                unsafe { release_death_observers(first, stack) };

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
            }

            // Return every donation, the create-time slab (holding the
            // wrapper and this pool) last; `obj` is dangling afterwards.
            // An address space's pool carves no arena page, so no record has
            // a kept page.
            let free = |group: &mut [DonationRecord]| {
                // SAFETY: a group handed out by reclaim_donations under its
                // contract, whose records list no kept page; no lock held.
                unsafe { free_donation_group(group, stack) }
            };
            // SAFETY: refcount 0, no slot references the object, the
            // in-place AddressSpace (if any) has been dropped, and no lock
            // is held.
            unsafe { obj.pt_pool.reclaim_donations(free) };

            // No separate free of the wrapper — it lives inside the slab reclaimed above.
        }

        // ── CSpaceObj ─────────────────────────────────────────────────────
        //
        // All `CSpaceKernelObject`s are retype-backed: the root CSpace lands
        // in a slab from `SEED_MEMORY` (Phase 7), and every userspace CSpace
        // lands in a slab from a Memory cap (`sys_cap_create_cspace`). Both
        // inline `CSpace` directly into the wrapper page; both record the
        // create-time slab (wrapper plus slot-page pool) as the pool's first
        // donation.
        //
        // The arm runs twice. The first run stops the bound threads, drains
        // and drops the `CSpace`, and queues itself on the cascade stack
        // beneath the objects its slots held, so those objects, and every
        // cascade they start, are torn down first, their arena chunks freed.
        // The second run, with `cspace` null, returns every donation to its
        // Memory object but for the arena pages still holding a live body,
        // cut out of their donations' spans, and drops the reference each
        // donation held, the create-time slab last.
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
                obj.cs_pool.has_create_donation(),
                "dealloc CSpaceObj: donation-less CSpace reached typed-memory dealloc path"
            );

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

                // The port-binding tables of the threads bound here came from
                // this pool; they go back before it is reclaimed.
                // SAFETY: no lock is held; every thread bound to cs_ptr is
                // stopped, so none binds again.
                unsafe { crate::cap::ioport_bindings::free_tables_bound_to(cs_ptr) };

                // SAFETY: cs_ptr non-null; allocated at creation.
                let id = unsafe { (*cs_ptr).id() };
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
                // The lock is released BEFORE the `for_each_object` dec_ref
                // pass below: the objects that pass orphans are torn down
                // later from the cascade stack, and a `CSpace` among them
                // takes this same non-recursive lock for its own drain. The
                // drain already removed every foreign link before this point,
                // so the dec_ref pass has no derivation-tree work to do —
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

                // The wrapper's second run, which returns the pool, comes
                // after the objects the slots queue below: `cspace` null marks
                // it, and pushing the wrapper first puts it beneath them.
                // SAFETY: refcount 0, so no capability or pin reaches the
                // wrapper, and it was popped, so it is on no stack. Between the
                // runs another CPU reaches it only through an arena page's
                // `owner`, which a chunk free borrows for `cs_pool`'s lock and
                // `arena_free` alone, never the whole wrapper, `cspace`, or the
                // header (`free_arena_chunk`), as `CascadeStack::push` allows;
                // this arm uses neither after the push.
                unsafe {
                    (*ptr.as_ptr().cast::<CSpaceKernelObject>()).cspace = core::ptr::null_mut();
                    stack.push(ptr);
                }

                // Dec-ref all objects referenced by non-null slots, queueing
                // each one this leaves unreferenced, a nested CSpace
                // included, on the cascade stack: a chain of CSpaces each
                // holding the last reference to the next is torn down
                // iteratively, not one recursion per level.
                // SAFETY: cs_ptr non-null; for_each_object handles iteration;
                // each slot's object is live until its reference is released,
                // so a Memory object is uncounted while live and once, as its
                // fill counted it; each slot's reference is released once, and
                // one that was its object's last leaves the object referenced
                // by no slot, pin, or kernel owner and on no stack; a nested
                // `CSpace` wrapper among them stays reachable only through its
                // arena pages' `owner`, which `CascadeStack::push` allows.
                unsafe {
                    (*cs_ptr).for_each_object(|obj_ptr| {
                        // The slot stops naming its object here, as a freed
                        // slot does in `CSpace::free_slot`.
                        if obj_ptr.as_ref().obj_type == ObjectType::Memory
                        {
                            MemoryObject::note_slot_released(obj_ptr);
                        }
                        if obj_ptr.as_ref().dec_ref() == 0
                        {
                            stack.push(obj_ptr);
                        }
                    });
                }

                // Drop the inline CSpace before reclaiming its storage; its
                // own `Drop` is a no-op for retype-backed (pool pages flow
                // back through the donation reclaim of the second run).
                // SAFETY: cs_ptr is about to be reclaimed; no outside
                // reference outlives the cap deletion that brought us here.
                unsafe {
                    core::ptr::drop_in_place(cs_ptr);
                }

                // Recycle the id once DERIVATION_LOCK is released and the
                // CSpace is unregistered and dropped. Randomizing the epoch
                // now invalidates any surviving SlotId stamped with the
                // pre-recycle value — subsequent `lookup_cspace` returns None.
                // The slot pages go back with the donations in the second
                // run; no live structure names them.
                crate::cap::free_cspace_id(id);
                return;
            }

            // Second run (or a wrapper that never had a CSpace): the objects
            // the slots held are torn down. Every donation goes back now but
            // for the arena pages that still hold a live body, one this
            // CSpace funded that lives on in another CSpace, its capability
            // moved there. Each kept page returns to its donation's Memory
            // object with its last chunk (core/kernel/docs/capability-internals.md
            // § Body Arena).
            // SAFETY: refcount 0, the CSpace is drained and dropped, so no
            // chunk is allocated; no lock is held.
            let kept = unsafe { obj.orphan_arena_pages() };
            // SAFETY: as above; `kept` lists the pages the pass kept, each held.
            unsafe { reclaim_cspace_donations(obj, kept, stack) };
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

                // Drain blocked senders and receivers, each woken with its park
                // stamped cancelled (INTERRUPTED; KILL for a queued faulter), so
                // sys_ipc_call / sys_ipc_recv return Interrupted.
                // SAFETY: state validated non-null. The drain runs under ep.lock:
                // a concurrent dealloc(waiter) BlockedOnSend/Recv unlink takes the
                // same lock, so it cannot mutate these queues or free a waiter
                // mid-walk, and the per-waiter wake_in_flight = 1 set here (the
                // #160 discipline) makes any dealloc(waiter) that already left the
                // queue wait at its wake-in-flight gate for our enqueue_and_wake
                // rather than free the TCB under it. Holding ep.lock across
                // enqueue_and_wake follows core/kernel/docs/scheduling-internals.md § Lock
                // Hierarchy rule 1.
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
                            crate::sched::thread::ParkKind::of_sender(tcb),
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
            // allocator, then dec_ref the ancestor — cascading through the
            // cascade stack if it hits zero.
            use crate::cap::retype::{dispatch_for, retype_free};
            // dispatch_for is total over the kernel's retypable types; the
            // Endpoint arm always returns Some. Unwrap-or-fall-through with
            // a fallback raw size keeps the lint quiet without panicking. The
            // fallback is the ABI constant the Endpoint arm returns, so it
            // cannot drift from the alloc-side size.
            let raw_bytes = dispatch_for(ObjectType::Endpoint, 0)
                .map_or(syscall::ENDPOINT_RETYPE_BYTES, |e| e.raw_bytes);

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
            // SAFETY: the object was retyped from `ancestor_memory` at `offset`
            // with `raw_bytes`, and is dropped above; nothing references it.
            unsafe { retype_free(ancestor_memory, offset, raw_bytes) };

            // Drop the retype-time refcount lease. If this was the Memory cap's last
            // reference, push it onto the cascade stack; dealloc_object frees it on
            // a later iteration (the Memory arm returns its buddy pages).
            let ancestor_nn =
                // SAFETY: ancestor_ptr is non-null per debug_assert.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_memory.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: the reference just released was its last; the
                // cascade runs the Memory arm above (which frees the buddy
                // pages).
                unsafe { stack.push(ancestor_nn) };
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
                // Remove the IRQ bindings that name this NotificationState and
                // wait out the device-IRQ deliveries in flight on their lines on
                // any CPU; a binding an earlier rebind or unbind took it from
                // was drained by that change, so none reaches the state after
                // the free below (irq::unregister_notification).
                // SAFETY: state is live; no IPC source, scheduler, or
                // sleep-list lock is held, and this is not interrupt context.
                unsafe { crate::irq::unregister_notification(state) };

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

                // Wake every blocked waiter with its park stamped Interrupted.
                // Each is claimed under sig.lock, as notification_send claims
                // (#160), and, as a multi-waiter drain, also woken under it
                // (core/kernel/docs/scheduling-internals.md § Lock Hierarchy
                // rule 5), so a concurrent dealloc(waiter) BlockedOnNotification
                // unlink (which takes sig.lock and spins on wake_in_flight)
                // cannot free a TCB before its enqueue_and_wake commits.
                // SAFETY: state validated non-null; sig.lock held across the
                // claims and wakes, with no scheduler or sleep-list lock held.
                unsafe {
                    let sig = &mut *state;
                    let saved = sig.lock.lock_raw();
                    crate::ipc::interrupt_all_waiters(&mut sig.waiters);
                    sig.refresh_observer();
                    sig.lock.unlock_raw(saved);
                }

                // A timer batch that popped a timed waiter of this notification
                // before the claim above may still hold `state` from its pop
                // snapshot (no reference); wait it out before the free.
                // core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List
                // Invariants.
                crate::sched::sleep_wakeups_quiesce();
            }

            debug_assert!(
                !ancestor_ptr.is_null(),
                "Notification: every production cap is retype-backed via cap_create_notification"
            );
            // Wrapper + state are in-place inside the ancestor Memory cap's
            // region.
            use crate::cap::retype::{dispatch_for, retype_free};
            // dispatch_for always returns Some for Notification; the fallback is
            // the same ABI constant its Notification arm returns.
            let raw_bytes = dispatch_for(ObjectType::Notification, 0)
                .map_or(syscall::NOTIFICATION_RETYPE_BYTES, |e| e.raw_bytes);

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

            // SAFETY: the object was retyped from `ancestor_memory` at `offset`
            // with `raw_bytes`, and is dropped above; nothing references it.
            unsafe { retype_free(ancestor_memory, offset, raw_bytes) };

            // Drop the retype-time refcount lease; on full release, queue the Memory
            // cap on the cascade stack.
            let ancestor_nn =
                // SAFETY: ancestor_ptr non-null.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_memory.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: the reference just released was its last.
                unsafe { stack.push(ancestor_nn) };
            }
        }

        // ── EventQueue ────────────────────────────────────────────────────
        ObjectType::EventQueue =>
        {
            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);

            // SAFETY: ptr points to an EventQueueObject; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<EventQueueObject>()) };
            let state = obj.state;

            // Read the sizes before any drop; they determine how many bytes
            // belong to the slot (wrapper + state + inline ring + node pool).
            // Every node is free by now: a bound node holds a reference on
            // this queue, which has none left.
            let (capacity, observers) = if state.is_null()
            {
                (0u32, 0u32)
            }
            else
            {
                // SAFETY: state non-null; EventQueueState live.
                unsafe { ((*state).capacity, (*state).observer_count) }
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

                // Wake every blocked waiter with its park stamped Interrupted.
                // The inline ring is part of this slot and gets reclaimed
                // below alongside the wrapper + state via `retype_free`.
                // SAFETY: state non-null and live.
                unsafe { crate::ipc::event_queue::event_queue_drop(state) };

                // A timer batch that popped a timed waiter of this queue
                // before the claim above may still hold `state` from its pop
                // snapshot (no reference); wait it out before the free.
                // core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List
                // Invariants.
                crate::sched::sleep_wakeups_quiesce();
            }

            debug_assert!(
                !ancestor_ptr.is_null(),
                "EventQueue: every production cap is retype-backed via cap_create_event_queue"
            );
            use crate::cap::retype::retype_free;
            // The same ABI formula `dispatch_for` debited at creation.
            let raw_bytes =
                syscall::event_queue_retype_bytes(u64::from(capacity), u64::from(observers));
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

            // SAFETY: the object was retyped from `ancestor_memory` at `offset`
            // with `raw_bytes`, and is dropped above; nothing references it.
            unsafe { retype_free(ancestor_memory, offset, raw_bytes) };

            let ancestor_nn =
                // SAFETY: ancestor_ptr non-null.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_memory.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: refcount reached 0.
                // SAFETY: the reference just released was its last.
                unsafe { stack.push(ancestor_nn) };
            }
        }

        // ── WaitSet ───────────────────────────────────────────────────────
        ObjectType::WaitSet =>
        {
            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);

            // SAFETY: ptr points to a WaitSetObject; header at offset 0.
            let obj = unsafe { &*(ptr.as_ptr().cast::<WaitSetObject>()) };
            let state = obj.state;
            // Read the capacity before any drop; it sizes the slot.
            let capacity = if state.is_null()
            {
                0
            }
            else
            {
                // SAFETY: state is the live in-place WaitSetState.
                unsafe { (*state).capacity() }
            };

            if !state.is_null()
            {
                // wait_set_drop wakes any blocked waiter, clears every source
                // back-pointer, and drops the +1 cap-level ref each member
                // held on its source. A source whose ref drops to zero is
                // queued on the cascade stack, and so torn down only after
                // `wait_set_drop` has returned and released every source/ws
                // IPC lock (see scheduling-internals.md § Lock Hierarchy),
                // however many members the caller-sized set held.
                // SAFETY: state non-null and live; each zeroed header has no
                // capability or membership left, so it is unreferenced for
                // the push.
                unsafe {
                    crate::ipc::wait_set::wait_set_drop(state, |source| stack.push(source));
                }
            }

            debug_assert!(
                !ancestor_ptr.is_null(),
                "WaitSet: every production cap is retype-backed via cap_create_wait_set"
            );
            use crate::cap::retype::retype_free;
            // The same ABI formula `wait_set_dispatch` debited at creation.
            let raw_bytes = syscall::wait_set_retype_bytes(u64::from(capacity));
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

            // SAFETY: the object was retyped from `ancestor_memory` at `offset`
            // with `raw_bytes`, and is dropped above; nothing references it.
            unsafe { retype_free(ancestor_memory, offset, raw_bytes) };

            let ancestor_nn =
                // SAFETY: ancestor_ptr non-null.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_memory.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: refcount reached 0.
                // SAFETY: the reference just released was its last.
                unsafe { stack.push(ancestor_nn) };
            }
        }
    }
}

// ── CSpace teardown helpers ──────────────────────────────────────────────────

/// Maximum drain steps (slots visited plus derivation-link edits) per
/// `DERIVATION_LOCK` hold while draining
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
/// slot's children into the dying slot, and a capability transfer that
/// committed to a receiver there before that receiver was stopped can land
/// caps into it (every bound thread is stopped before the drain, so none
/// derives out of it).
/// Each such event adds at most one reparent batch of work while the
/// drain removes a batch per hold, so the loop is bounded by lock
/// contention rather than by a constant, and it carries no batch backstop
/// (a teardown cannot fail): a holder of capabilities derived from the
/// dying `CSpace` can prolong the teardown for as long as it keeps
/// deleting, which stalls the deleting thread, not the system. Links
/// wired behind the cursor dangle once the `CSpace` unregisters and
/// surface downstream as dead-link truncation, in the drain's own
/// containment or `revoke_subtree_batch`'s — contained (see
/// core/kernel/docs/capability-internals.md § Revocation Algorithm).
/// Apart from those links, the end state is that no slot anywhere
/// references the dying `CSpace`, which is the invariant `free_cspace_id`
/// recycling relies on.
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

    // The defect caught: a teardown group that mixes Memory objects (its runs
    // returned to the wrong one), splits one Memory object's records across
    // groups out of order, or drops or repeats a record, so a donation goes
    // back twice, to the wrong object, or not at all, or the runs a group
    // hands `retype_free_runs` do not ascend.
    #[test]
    fn donation_records_group_by_memory_object_in_ascending_offset_order()
    {
        // (ancestor, offset) pairs, three ancestors interleaved out of order.
        let mut records = [
            (0x3000, 7),
            (0x1000, 5),
            (0x2000, 2),
            (0x1000, 1),
            (0x3000, 0),
            (0x1000, 9),
            (0x2000, 4),
        ];
        let mut groups: Vec<Vec<(usize, u64)>> = Vec::new();
        for_each_ancestor_group(&mut records, |&r| r, |group| groups.push(group.to_vec()));
        assert_eq!(
            groups,
            [
                vec![(0x1000, 1), (0x1000, 5), (0x1000, 9)],
                vec![(0x2000, 2), (0x2000, 4)],
                vec![(0x3000, 0), (0x3000, 7)],
            ]
        );

        let mut none: [(usize, u64); 0] = [];
        let mut calls = 0;
        for_each_ancestor_group(&mut none, |&r| r, |_| calls += 1);
        assert_eq!(calls, 0, "no records, no group");
    }

    // The defect caught: a copy count that runs into the root's share (the
    // root's body freed while copies live, or never freed), whether or not the
    // root itself is still referenced.
    #[test]
    fn a_range_lineage_admits_exactly_the_copy_limit()
    {
        for share in [ROOT_SHARE, 0]
        {
            let mut root = MmioObject::new_root(0x1000_0000, 0x1000, 0);
            let root_hdr = NonNull::from(&mut root).cast::<KernelObjectHeader>();
            // Copies up to one short of the limit, as if reserved one by one.
            root.lineage
                .live
                .store(share + RANGE_COPY_LIMIT - 1, Ordering::Relaxed);
            // SAFETY: root is a live lineage root whose count is held above zero.
            let copy = unsafe { RangeLineage::reserve_copy(root_hdr) }.unwrap();
            assert_eq!(copy.root_of(NonNull::dangling()), root_hdr);
            // SAFETY: as above.
            let refused = unsafe { RangeLineage::reserve_copy(root_hdr) };
            assert!(matches!(refused, Err(syscall::SyscallError::QuotaExceeded)));
            assert_eq!(
                root.lineage.live.load(Ordering::Relaxed),
                share + RANGE_COPY_LIMIT,
                "the limit is reached without touching the root's share"
            );
        }
    }

    // The defect caught: a mapping past the inline records that is refused or
    // dropped (so the teardown misses its pages), a repeat that takes a second
    // reference, or a spill chunk taken while a record is still free.
    #[test]
    fn mappings_past_the_inline_records_spill_into_chained_chunks()
    {
        const N: usize = MMIO_INLINE_MAPPINGS + 2 * MMIO_SPILL_RECORDS + 1;
        let mmio = MmioObject::new_root(0x1000_0000, 0x1000, 0);
        let mut spaces: [core::mem::MaybeUninit<AddressSpaceObject>; N] =
            [const { core::mem::MaybeUninit::uninit() }; N];
        let mut asos = [core::ptr::null_mut::<AddressSpaceObject>(); N];
        for (slot, aso) in spaces.iter_mut().zip(asos.iter_mut())
        {
            let p = slot.as_mut_ptr();
            // SAFETY: only the header is ever touched (record_mapping's inc_ref).
            unsafe {
                core::ptr::addr_of_mut!((*p).header)
                    .write(KernelObjectHeader::new(ObjectType::AddressSpace));
            }
            *aso = p;
        }
        let mut chunks = Vec::new();
        let mut spill = || {
            let c = Box::into_raw(Box::new(MmioSpill::new()));
            chunks.push(c);
            Ok(NonNull::new(c).unwrap())
        };
        for &aso in &asos
        {
            // SAFETY: each aso has a live header; mmio is exclusively ours.
            unsafe { mmio.record_mapping(aso, 0x4000_0000, &mut spill) }.unwrap();
        }
        // SAFETY: as above.
        unsafe { mmio.record_mapping(asos[N - 1], 0x4000_0000, &mut spill) }.unwrap();
        assert_eq!(
            chunks.len(),
            3,
            "a chunk is taken only once every record is full"
        );
        let recorded = mmio
            .records()
            .filter(|m| !m.aso.load(Ordering::Relaxed).is_null())
            .count();
        assert_eq!(recorded, N, "every distinct mapping holds one record");
        for &aso in &asos
        {
            // SAFETY: the header was initialised above.
            let refs = unsafe { (*aso).header.ref_count.load(Ordering::Relaxed) };
            assert_eq!(refs, 2, "one record reference per mapping, repeat or not");
        }
        // An unfunded spill leaves nothing recorded.
        let mut extra: core::mem::MaybeUninit<AddressSpaceObject> =
            core::mem::MaybeUninit::uninit();
        let extra = extra.as_mut_ptr();
        // SAFETY: as above.
        unsafe {
            core::ptr::addr_of_mut!((*extra).header)
                .write(KernelObjectHeader::new(ObjectType::AddressSpace));
        }
        // SAFETY: as above; every record is taken (N fills the third chunk but
        // one, so first take the last free record).
        let free_left = MMIO_INLINE_MAPPINGS + 3 * MMIO_SPILL_RECORDS - N;
        assert_eq!(free_left, MMIO_SPILL_RECORDS - 1);
        let refused = unsafe {
            mmio.record_mapping(extra, 0x5000_0000 + 0x1000 * free_left as u64, || {
                Err(syscall::SyscallError::OutOfMemory)
            })
        };
        assert!(
            refused.is_ok(),
            "a free record in the newest chunk is used first"
        );
        for chunk in chunks
        {
            // SAFETY: allocated above; mmio is no longer used.
            drop(unsafe { Box::from_raw(chunk) });
        }
    }

    // The protocol `CSpaceKernelObject::orphan_arena_pages` and
    // `free_arena_chunk` run on an arena page's count: the owner's hold plus
    // one per live chunk, the hold passed to the teardown, which keeps the page
    // when a chunk is live at its pass and releases the hold after the cut.
    // The defect caught: a page freed twice or never, or one kept with no live
    // chunk (left out of its donation for good), whatever the order of its
    // last frees around the pass.
    #[test]
    fn a_kept_arena_page_is_freed_once_whatever_the_order_of_its_last_frees()
    {
        for live in 0..5
        {
            for pass_at in 0..=live
            {
                let page = KernelObjectHeader::new(ObjectType::ArenaPage);
                for _ in 0..live
                {
                    page.inc_ref();
                }
                let mut freed = 0;
                let mut kept = false;
                for i in 0..=live
                {
                    if i == pass_at
                    {
                        kept = page.ref_count.load(Ordering::Acquire) > 1;
                    }
                    if i < live && page.dec_ref() == 0
                    {
                        freed += 1;
                    }
                }
                if kept && page.dec_ref() == 0
                {
                    freed += 1;
                }
                assert_eq!(
                    kept,
                    pass_at < live,
                    "{live} live, pass after {pass_at} frees"
                );
                assert_eq!(
                    freed,
                    u32::from(kept),
                    "{live} live, pass after {pass_at} frees"
                );
            }
        }
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

    // Defect guarded: a checked increment that admits the reference at the
    // ceiling, or one that moves the count when it refuses, lets userspace
    // walk the count toward the wrap that frees a live object.
    #[test]
    fn checked_increment_refuses_at_the_ceiling_and_leaves_the_count()
    {
        let h = KernelObjectHeader::new(ObjectType::Endpoint);
        h.ref_count.store(REF_COUNT_LIMIT - 1, Ordering::Relaxed);
        assert!(!h.at_ref_limit());
        assert!(h.try_inc_ref().is_ok());
        assert_eq!(h.ref_count.load(Ordering::Relaxed), REF_COUNT_LIMIT);
        assert!(h.at_ref_limit());
        assert!(matches!(
            h.try_inc_ref(),
            Err(syscall::SyscallError::QuotaExceeded)
        ));
        assert_eq!(h.ref_count.load(Ordering::Relaxed), REF_COUNT_LIMIT);
        // A release below the ceiling admits a new reference again.
        assert_eq!(h.dec_ref(), REF_COUNT_LIMIT - 1);
        assert!(h.try_inc_ref().is_ok());
    }

    /// A model kernel object for the cascade tests: a real header followed by
    /// the model's index for the object.
    #[repr(C)]
    struct ModelObject
    {
        header: KernelObjectHeader,
        index: usize,
    }

    /// Distinct non-null `ancestor` value for model object `i`, to check that
    /// queueing never touches the field.
    fn model_ancestor(i: usize) -> *mut KernelObjectHeader
    {
        ((i + 1) * 64) as *mut KernelObjectHeader
    }

    /// Heap model objects of `types`, object `i` with `refs[i]` references,
    /// as raw pointers: the cascade writes their headers, so every pointer it
    /// is handed must come from a raw (not a shared-reference) source, as the
    /// kernel's do. [`free_models`] reclaims them.
    fn alloc_models(types: &[ObjectType], refs: &[u32]) -> Vec<*mut ModelObject>
    {
        types
            .iter()
            .enumerate()
            .map(|(index, &obj_type)| {
                let header = KernelObjectHeader::new(obj_type);
                header.ref_count.store(refs[index], Ordering::Relaxed);
                header
                    .ancestor
                    .store(model_ancestor(index), Ordering::Relaxed);
                Box::into_raw(Box::new(ModelObject { header, index }))
            })
            .collect()
    }

    /// The header of model object `raw`, as the cascade's pointer to it.
    fn model_header(raw: *mut ModelObject) -> NonNull<KernelObjectHeader>
    {
        // SAFETY: `raw` is a live `alloc_models` object; the header is
        // addressed without creating a reference.
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*raw).header)) }
    }

    /// Reclaim the objects [`alloc_models`] returned.
    fn free_models(objects: Vec<*mut ModelObject>)
    {
        for raw in objects
        {
            // SAFETY: each pointer came from `Box::into_raw` and is freed once.
            drop(unsafe { Box::from_raw(raw) });
        }
    }

    /// Run `run_cascade` from object 0 over a model in which object `i` holds
    /// one reference on each object in `holds[i]` and its teardown releases
    /// them; every object starts with as many references as it has holders,
    /// object 0 with none. A `CSpaceObj` runs twice, as the kernel's arm does:
    /// its first run queues itself, then releases its holds, and its second
    /// run tears it down. Returns how many times each object was torn down,
    /// and the step at which each was (its last run).
    fn run_model_cascade(types: &[ObjectType], holds: &[Vec<usize>]) -> (Vec<u32>, Vec<usize>)
    {
        let mut refs = vec![0u32; types.len()];
        for held in holds
        {
            for &h in held
            {
                refs[h] += 1;
            }
        }
        assert_eq!(refs[0], 0, "the model's first object must be unreferenced");
        let objects = alloc_models(types, &refs);
        let ptrs: Vec<NonNull<KernelObjectHeader>> =
            objects.iter().map(|&raw| model_header(raw)).collect();
        let mut torn = vec![0u32; types.len()];
        let mut torn_at = vec![usize::MAX; types.len()];
        let mut requeued = vec![false; types.len()];
        let mut step = 0;
        run_cascade(ptrs[0], |obj, stack| {
            // SAFETY: every pointer the model queues is one of `objects`,
            // popped and so no longer written by the stack.
            let model = unsafe { &*obj.as_ptr().cast::<ModelObject>() };
            let i = model.index;
            assert_eq!(model.header.ref_count.load(Ordering::Relaxed), 0);
            assert_eq!(model.header.cascade_link_hi, [0; 3]);
            assert_eq!(model.header.obj_type, types[i]);
            assert_eq!(
                model.header.ancestor.load(Ordering::Relaxed),
                model_ancestor(i)
            );
            step += 1;
            let first_of_two = types[i] == ObjectType::CSpaceObj && !requeued[i];
            if first_of_two
            {
                requeued[i] = true;
                // SAFETY: popped and unreferenced, as the kernel's wrapper is
                // when its first run re-queues it.
                unsafe { stack.push(obj) };
            }
            else
            {
                torn[i] += 1;
                torn_at[i] = step;
            }
            if first_of_two || types[i] != ObjectType::CSpaceObj
            {
                for &h in &holds[i]
                {
                    // SAFETY: `ptrs[h]` is a live model header.
                    if unsafe { ptrs[h].as_ref() }.dec_ref() == 0
                    {
                        // SAFETY: that was the model object's last reference,
                        // and its pointer has a raw source.
                        unsafe { stack.push(ptrs[h]) };
                    }
                }
            }
        });
        free_models(objects);
        (torn, torn_at)
    }

    /// Add to the model a tree of CSpaces under `root`: `width` CSpaces per
    /// CSpace to `depth` levels, each non-leaf CSpace (the root included)
    /// also holding an endpoint and a thread, and below the first level the
    /// level's first CSpace also held by the previous level's last, in
    /// another subtree.
    fn add_nested_cspaces(
        types: &mut Vec<ObjectType>,
        holds: &mut Vec<Vec<usize>>,
        root: usize,
        width: usize,
        depth: usize,
    )
    {
        let mut level = vec![root];
        let mut extra_holder: Option<usize> = None;
        for _ in 0..depth
        {
            let mut next = Vec::new();
            for &parent in &level
            {
                for _ in 0..width
                {
                    let c = types.len();
                    types.push(ObjectType::CSpaceObj);
                    holds.push(Vec::new());
                    holds[parent].push(c);
                    next.push(c);
                }
                for t in [ObjectType::Endpoint, ObjectType::Thread]
                {
                    let o = types.len();
                    types.push(t);
                    holds.push(Vec::new());
                    holds[parent].push(o);
                }
            }
            if let Some(holder) = extra_holder
            {
                holds[holder].push(next[0]);
            }
            extra_holder = next.last().copied();
            level = next;
        }
    }

    // Defect guarded: a cascade that loses an entry (as any fixed-size
    // worklist does past its size), tears one object down twice, or corrupts
    // the type or ancestor a teardown reads while the object is queued.
    #[test]
    fn a_cascade_with_wide_fan_out_and_deep_chains_tears_every_object_down_once()
    {
        // Object 0, a CSpace, holds 40 objects (more than a 32-entry array
        // holds): 20 endpoints and 20 wait sets, each wait set holding 16
        // notifications. Every one of those holds a lease on one of the Memory
        // objects, which form a 64-deep ancestor chain, each holding the next.
        // Object 0 also holds a tree of CSpaces, 3 wide and 4 deep, whose
        // teardowns release further CSpaces and the objects they hold, with
        // one CSpace per level held from two subtrees.
        const CHAIN: usize = 64;
        let mut types = vec![ObjectType::CSpaceObj];
        let mut holds: Vec<Vec<usize>> = vec![Vec::new()];
        let memory_base = 1;
        for m in 0..CHAIN
        {
            types.push(ObjectType::Memory);
            holds.push(
                if m + 1 < CHAIN
                {
                    vec![memory_base + m + 1]
                }
                else
                {
                    Vec::new()
                },
            );
        }
        holds[0].push(memory_base);
        for e in 0..40
        {
            let obj = types.len();
            types.push(
                if e < 20
                {
                    ObjectType::Endpoint
                }
                else
                {
                    ObjectType::WaitSet
                },
            );
            holds.push(vec![memory_base + e % CHAIN]);
            holds[0].push(obj);
            if e >= 20
            {
                for _ in 0..16
                {
                    let n = types.len();
                    types.push(ObjectType::Notification);
                    holds.push(vec![memory_base]);
                    holds[obj].push(n);
                }
            }
        }
        add_nested_cspaces(&mut types, &mut holds, 0, 3, 4);
        let (torn, _) = run_model_cascade(&types, &holds);
        assert!(torn.iter().all(|&t| t == 1), "torn-down counts: {torn:?}");
    }

    // Defect guarded: a cascade stack that pops a re-pushed CSpace before
    // everything pushed above it, the order the kernel's CSpace arm relies on
    // to tear its slots' objects down before it returns its pool.
    #[test]
    fn a_cspace_is_torn_down_after_everything_its_slots_alone_held()
    {
        let mut types = vec![ObjectType::CSpaceObj];
        let mut holds: Vec<Vec<usize>> = vec![Vec::new()];
        add_nested_cspaces(&mut types, &mut holds, 0, 3, 3);
        let (torn, torn_at) = run_model_cascade(&types, &holds);
        assert!(torn.iter().all(|&t| t == 1), "torn-down counts: {torn:?}");
        let mut holders = vec![0usize; types.len()];
        for held in &holds
        {
            for &h in held
            {
                holders[h] += 1;
            }
        }
        for c in (0..types.len()).filter(|&c| types[c] == ObjectType::CSpaceObj)
        {
            // Everything reachable from `c` through objects held only once is
            // released by `c`'s first run or a cascade it starts.
            let mut owned: Vec<usize> = holds[c]
                .iter()
                .copied()
                .filter(|&h| holders[h] == 1)
                .collect();
            while let Some(o) = owned.pop()
            {
                assert!(
                    torn_at[o] < torn_at[c],
                    "object {o} torn down after CSpace {c}, which alone held it"
                );
                owned.extend(holds[o].iter().copied().filter(|&h| holders[h] == 1));
            }
        }
    }

    // Defect guarded: a link encoding that loses address bits (a header that
    // pops back as another), or a pop that leaves link bits in the reference
    // count or the type and ancestor fields disturbed.
    #[test]
    fn a_cascade_stack_pops_lifo_and_restores_each_header()
    {
        let types = [ObjectType::Endpoint; 100];
        let objects = alloc_models(&types, &[0; 100]);
        let mut stack = CascadeStack::new();
        for &raw in &objects
        {
            // SAFETY: an unreferenced model header with a raw source, queued
            // once.
            unsafe { stack.push(model_header(raw)) };
        }
        for &raw in objects.iter().rev()
        {
            assert_eq!(stack.pop(), Some(model_header(raw)));
            // SAFETY: popped, so the stack no longer writes it.
            let o = unsafe { &*raw };
            assert_eq!(o.header.ref_count.load(Ordering::Relaxed), 0);
            assert_eq!(o.header.cascade_link_hi, [0; 3]);
            assert_eq!(o.header.obj_type, ObjectType::Endpoint);
            assert_eq!(
                o.header.ancestor.load(Ordering::Relaxed),
                model_ancestor(o.index)
            );
        }
        assert_eq!(stack.pop(), None);
        free_models(objects);
    }

    // Defect guarded: a decode that fails to sign-extend, so a kernel
    // (upper-half) header address pops back as a lower-half one.
    #[test]
    fn the_cascade_link_round_trips_upper_and_lower_half_addresses()
    {
        for va in [
            0xFFFF_8000_0000_0040u64,
            0xFFFF_FFFF_FFFF_FFF8,
            0xFF00_0000_0000_0008,
            0x0000_7FFF_FFFF_FFF8,
            0x0000_0000_0000_1000,
        ]
        {
            let p = NonNull::new(va as *mut KernelObjectHeader);
            assert_eq!(CascadeStack::decode(CascadeStack::encode(p)), p, "{va:#x}");
        }
        assert_eq!(CascadeStack::encode(None), 0);
        assert_eq!(CascadeStack::decode(0), None);
    }
}
