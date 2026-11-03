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
//! (`boot_retype_*`, `mint_phase7_body`) and carry the SEED ancestor.
//!
//! Deallocation: read `header.obj_type` from the raw pointer, drop the
//! object in place, and call `retype_free` against the ancestor
//! `MemoryObject`; every object has one.
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
    /// [`REF_COUNT_LIMIT`] for the references userspace can multiply.
    pub ref_count: AtomicU32,
    /// Concrete type, for use during deallocation.
    pub obj_type: ObjectType,
    // Padding to reach 8-byte alignment for the ancestor pointer below. Public
    // because mint sites outside this module build the header by struct literal;
    // the underscore marks it as carrying no value.
    #[allow(clippy::pub_underscore_fields)]
    pub _pad: [u8; 3],
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
/// records (four per Mmio object, whose bodies are SEED-backed), SEED leases
/// (bounded by the SEED reserve), and the destinations IPC transfers' abandoned moves leave
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
            _pad: [0; 3],
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
            _pad: [0; 3],
            ancestor: AtomicPtr::new(ancestor.as_ptr()),
        }
    }

    /// Increment the reference count for an owner whose number is bounded
    /// below the headroom above [`REF_COUNT_LIMIT`]: a syscall pin, a binding,
    /// a mapping record, a SEED lease, or the lease of a retype that
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
}

/// Sentinel encoding a held write lock in [`MemoryObject::lock`]. Matches
/// `DerivationLock`'s convention. A reader count cannot reach it: a holder is
/// never descheduled (core/kernel/docs/scheduling-internals.md § Lock
/// Hierarchy), so readers are at most one per CPU.
const FRAME_WRITE_LOCKED: u32 = u32::MAX;

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

/// Most copies of one range-capability lineage that may be live at once: the
/// `SYS_CAP_COPY`, `SYS_CAP_DERIVE`, and `SYS_CAP_DERIVE_BADGE` copies of an
/// `Mmio` or `IoPort` capability, each a fresh SEED-backed object
/// ([`object_for_new_slot`]). A copy past it returns `QuotaExceeded`.
pub const RANGE_COPY_LIMIT: u32 = 64;

/// The lineage an `Mmio` or `IoPort` object belongs to.
///
/// A boot mint or a range split produces a lineage *root*; copying a
/// capability of either type produces a fresh object whose lineage names
/// that root, so each capability slot owns its own object and the mappings
/// or port bindings made through it are withdrawn when that object is freed
/// (docs/capability-model.md § Mmio, § `IoPort`). The root's `live` holds
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
/// The copy count below it is capped at `RANGE_COPY_LIMIT`, so the two never collide.
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
    /// `root` is a live `Mmio` or `IoPort` lineage root whose `live` count is
    /// held above zero by a pinned member of the lineage.
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

/// The lineage of an `Mmio` or `IoPort` object.
///
/// # Safety
/// `hdr` is a live `Mmio` or `IoPort` object.
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
            _ => crate::fatal("lineage_of: not a range-capability object"),
        }
    }
}

/// Most `SYS_MMIO_MAP` mappings one `Mmio` object records. A map past it
/// returns `QuotaExceeded`; mapping the same region again at the same VA of
/// the same address space reuses its record.
pub const MMIO_MAX_MAPPINGS: usize = 4;

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
    mappings: [MmioMapping; MMIO_MAX_MAPPINGS],
}

// MmioObject fits the 128-byte retype size class every SEED mint and copy
// carves it from (`retype::round_to_class`).
const _: () = assert!(core::mem::size_of::<MmioObject>() <= 128);

impl MmioObject
{
    /// A lineage-root `Mmio` object over `[base, base + size)`, retyped from SEED.
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
            mappings: [const {
                MmioMapping {
                    aso: AtomicPtr::new(core::ptr::null_mut()),
                    va: AtomicU64::new(0),
                }
            }; MMIO_MAX_MAPPINGS],
        }
    }

    /// Record a mapping of this object's region at `va` in `aso`, taking a
    /// reference on `aso` for the record. A mapping already recorded at the same
    /// place is not recorded again; two maps racing to record the same place
    /// may each take a record, which costs a record and is otherwise harmless
    /// (the teardown withdraws both).
    ///
    /// # Errors
    /// `QuotaExceeded` when [`MMIO_MAX_MAPPINGS`] mappings are already recorded.
    ///
    /// # Safety
    /// `aso` is a live `AddressSpaceObject` the caller holds a reference on, and
    /// the caller pins this object.
    pub unsafe fn record_mapping(
        &self,
        aso: *mut AddressSpaceObject,
        va: u64,
    ) -> Result<(), syscall::SyscallError>
    {
        if self.mappings.iter().any(|m| {
            core::ptr::eq(m.aso.load(Ordering::Acquire), aso) && m.va.load(Ordering::Relaxed) == va
        })
        {
            return Ok(());
        }
        for m in &self.mappings
        {
            if m.aso
                .compare_exchange(
                    core::ptr::null_mut(),
                    MMIO_RECORD_CLAIMED,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                // SAFETY: aso is live and referenced by the caller (contract).
                unsafe { (*aso).header.inc_ref() };
                m.va.store(va, Ordering::Relaxed);
                m.aso.store(aso, Ordering::Release);
                return Ok(());
            }
        }
        Err(syscall::SyscallError::QuotaExceeded)
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
    /// # Safety
    /// No capability slot or syscall pin references the object (its reference
    /// count is zero), so no map can be recording into it; only its lineage
    /// count may still be touched by other CPUs. No lock is held, and the CPU
    /// is stable (`release_ref`'s preconditions).
    // cast_possible_truncation: a region's page count fits usize on the 64-bit
    // targets the kernel supports.
    #[allow(clippy::cast_possible_truncation)]
    #[cfg(not(test))]
    unsafe fn withdraw_mappings(&self)
    {
        let pages = (self.size / crate::mm::PAGE_SIZE as u64) as usize;
        for m in &self.mappings
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
    }
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
    /// for all 65536), retyped from SEED.
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
/// `MemoryObject` via `retype_free`, then the ancestor is `dec_ref`'d.
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
}

#[cfg(not(test))]
impl DonationRecord
{
    const VACANT: Self = Self {
        ancestor: core::ptr::null_mut(),
        base_offset: 0,
        page_count: 0,
    };
}

/// Pages `PagePool::seed_pages` pushes per pool-lock hold. The pool lock is a
/// bare spin lock (scheduling-internals.md § Lock Hierarchy, "Bare spin
/// locks"), and a hold
/// proportional to a caller-chosen donation size would be unbounded; batching
/// keeps every hold to this many pushes. The interrupts-off window of the
/// syscall that seeds a donation is the sum of its batches, `init_pages`
/// pushes chosen by the caller, and is not bounded here (#434).
#[cfg(not(test))]
const SEED_BATCH_PAGES: u64 = 64;

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
/// plus a record of every donation, for wholesale reclaim at teardown.
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
    /// for every live object. The pooled map paths' fallback to the kernel
    /// page-table pool and the dealloc arms' debug assertions check that
    /// invariant rather than support an unrecorded object.
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
    /// it, with `ancestor_memory_base` that object's `base`.
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
            // A non-null ancestor marks the record populated, so it is
            // written last.
            cell.ancestor.store(ancestor.as_ptr(), Ordering::Release);
            true
        }
        else
        {
            // SAFETY: lock held.
            unsafe { self.record_spilled(record) }
        };
        if !recorded
        {
            if first_pool == total_pages
            {
                pool_unlock(&self.lock);
                return Err(());
            }
            // SAFETY: lock held; the page is the donation's first pool page,
            // freshly retyped from `ancestor` and not yet published.
            unsafe { self.open_record_page(donation_phys + first_pool * p, record) };
            first_pool += 1;
        }
        pool_unlock(&self.lock);

        // SAFETY: the record covering these pages is written above; the
        // pages were just retyped from `ancestor` and are unaliased.
        unsafe { self.seed_pages(donation_phys, first_pool, total_pages, budget) };
        Ok(())
    }

    /// Push pages `first..total` of the donation at `donation_phys` onto the free
    /// list, highest first so the lowest ends up at the head, in batches of
    /// `SEED_BATCH_PAGES` under separate lock holds; credit `budget` with
    /// each batch as it lands, so a concurrent pop never debits a budget
    /// the pages have not yet been credited to.
    ///
    /// # Safety
    /// The pages must belong to a donation already recorded in this pool,
    /// be freshly retyped, and be unaliased. The pool lock must not be held.
    #[cfg(not(test))]
    #[track_caller]
    unsafe fn seed_pages(&self, donation_phys: u64, first: u64, total: u64, budget: &AtomicU64)
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
                // exclusively owned and recorded.
                unsafe { pool_push(&self.head_phys, donation_phys + i * p) };
            }
            budget.fetch_add((end - start) * p, Ordering::AcqRel);
            pool_unlock(&self.lock);
            end = start;
        }
    }

    /// Append `record` to the newest record page. `false` if there is none
    /// or it is full.
    ///
    /// # Safety
    /// The pool lock must be held.
    #[cfg(not(test))]
    unsafe fn record_spilled(&self, record: DonationRecord) -> bool
    {
        let page_phys = self.record_head_phys.load(Ordering::Acquire);
        if page_phys == 0
        {
            return false;
        }
        let page = crate::mm::paging::phys_to_virt(page_phys) as *mut RecordPage;
        // SAFETY: lock held; a published record page stays mapped in the
        // direct map and exclusively owned by this pool until teardown.
        unsafe {
            let used = (*page).used;
            if used >= RECORDS_PER_PAGE
            {
                return false;
            }
            (*page).records[used] = record;
            (*page).used = used + 1;
        }
        // Re-publish the head with Release so the appended record and the
        // new `used` are visible to a reader that Acquire-loads the head
        // (`reclaim_donations`), as they are for an inline record's ancestor
        // store; teardown otherwise leans on the refcount edge alone.
        self.record_head_phys.store(page_phys, Ordering::Release);
        true
    }

    /// Make `page_phys` the newest record page, holding `record` (the donation
    /// the page belongs to) as record 0.
    ///
    /// # Safety
    /// The pool lock must be held; `page_phys` must be a page-aligned page
    /// of `record`'s donation that is neither on the free list nor otherwise
    /// in use.
    #[cfg(not(test))]
    unsafe fn open_record_page(&self, page_phys: u64, record: DonationRecord)
    {
        let page = crate::mm::paging::phys_to_virt(page_phys) as *mut RecordPage;
        // SAFETY: the page is exclusively owned and page-aligned (caller's
        // contract) and holds one RecordPage (fit asserted at compile
        // time).
        unsafe {
            core::ptr::write_bytes(page.cast::<u8>(), 0, crate::mm::PAGE_SIZE);
            (*page).next_phys = self.record_head_phys.load(Ordering::Acquire);
            (*page).used = 1;
            (*page).records[0] = record;
        }
        self.record_head_phys.store(page_phys, Ordering::Release);
    }

    /// Hand every recorded donation to `free` as `(ancestor, base_offset,
    /// page_count)`, in an order that keeps each record readable until it is
    /// used: spilled records newest page first and, within a page, last to
    /// first so record 0 (whose donation holds the page) goes last; then the
    /// inline records, snapshotted up front, with record 0 (the create-time
    /// slab that holds the owner and this pool) last. The walk is linear in the
    /// donation count; its context and cost are in
    /// core/kernel/docs/capability-internals.md § Teardown.
    ///
    /// # Safety
    /// The owner is being torn down at refcount 0: no other reference to
    /// it, the pool, or any recorded page exists, and `free` must not touch
    /// the pool. `self` is dangling once this returns. `free` receives raw
    /// records and may run a full nested object teardown, so the caller
    /// must hold no lock.
    #[cfg(not(test))]
    unsafe fn reclaim_donations<F>(&self, mut free: F)
    where
        F: FnMut(*mut KernelObjectHeader, u64, u64),
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
            let page = crate::mm::paging::phys_to_virt(page_phys) as *const RecordPage;
            // SAFETY: caller's contract; the page stays intact until its
            // record 0 is freed below, after every read of it.
            let (next, used) = unsafe { ((*page).next_phys, (*page).used) };
            debug_assert!((1..=RECORDS_PER_PAGE).contains(&used));
            // The page is trusted kernel state and a corrupt record is not
            // survivable; the clamp only keeps the read inside the page.
            let used = used.min(RECORDS_PER_PAGE);
            for i in (0..used).rev()
            {
                // SAFETY: as above; `i < used`, and record 0 — whose donation
                // holds the page — is read last, after which the page is
                // not read again.
                let record = unsafe { (*page).records[i] };
                free(record.ancestor, record.base_offset, record.page_count);
            }
            page_phys = next;
        }

        for record in inline_snapshot[..count].iter().rev()
        {
            free(record.ancestor, record.base_offset, record.page_count);
        }
    }
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
    /// every donation; `dealloc` reclaims the donations wholesale.
    pub cs_pool: PagePool,
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

impl CSpaceKernelObject
{
    /// Pop a free slot page from this `CSpace`'s pool, charging the growth
    /// budget. Returns the page's physical address, or `None` if empty.
    /// Called from `CSpace::grow` under the `CSpace` lock, the only debit;
    /// credits land under the pool lock in `seed_pages`.
    #[cfg(not(test))]
    #[track_caller]
    pub fn alloc_slot_page(&self) -> Option<u64>
    {
        let phys = self.cs_pool.pop()?;
        self.cspace_growth_budget_bytes
            .fetch_sub(crate::mm::PAGE_SIZE as u64, Ordering::AcqRel);
        let virt = crate::mm::paging::phys_to_virt(phys);
        // SAFETY: page is now exclusively owned by the caller.
        unsafe { core::ptr::write_bytes(virt as *mut u8, 0, crate::mm::PAGE_SIZE) };
        Some(phys)
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
/// Notification first clears its IRQ routes and waits out the device-IRQ
/// deliveries in flight through them (`irq::unregister_notification`), for a
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
    // SAFETY: refcount reached 0; nothing else references the object.
    match unsafe { obj.as_ref().obj_type }
    {
        ObjectType::Thread | ObjectType::CSpaceObj | ObjectType::AddressSpace =>
        {
            let cpu = crate::arch::current::cpu::current_cpu() as usize;
            // SAFETY: refcount 0, exclusively owned, a linkable type; the
            // CPU index is stable (syscall context with interrupts disabled,
            // or the pinned idle thread's drain, per the contract).
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
/// object (refcount 0). A `Thread` pushed by a self-teardown is already
/// `Exited` and unlinked from every run queue; one pushed by
/// `release_ref` may be in any state, and the drain's Thread arm
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
    // SAFETY: object exclusively owned (refcount 0) and of a linkable type;
    // queued for off-CPU reclaim on this CPU.
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

/// Push `obj`, a refcount-0 object, onto a dealloc cascade worklist. Drops the
/// entry on overflow — see `MAX_CASCADE` in [`dealloc_object`]. Overflow is
/// unreachable in practice for the derivation depths this kernel actually
/// produces; dropping is preferable to a panic in the dealloc path.
#[cfg(not(test))]
fn push_cascade(
    worklist: &mut [Option<NonNull<KernelObjectHeader>>],
    head: &mut usize,
    obj: NonNull<KernelObjectHeader>,
)
{
    if *head < worklist.len()
    {
        worklist[*head] = Some(obj);
        *head += 1;
    }
}

/// Return each death-observer node of the chain starting at `first` to its
/// queue's pool and release the `EventQueueObject` reference the node held.
/// A queue whose last reference this was is reclaimed through its own nested
/// cascade, not the caller's bounded worklist: a chain may hold any number of
/// nodes, each of a distinct queue (the re-entry `free_donation` makes).
/// Called by an owner's teardown (the Thread and `AddressSpace` arms) with the
/// chain it took, once no death walk can read it.
///
/// # Safety
/// The caller owns every node of the chain and holds no lock: the nested
/// cascade takes its own.
#[cfg(not(test))]
unsafe fn release_death_observers(first: *mut crate::sched::thread::DeathObserver)
{
    // SAFETY: the caller took the chain, so it owns every node; each lives in
    // its queue, which the node's reference keeps live until the dec_ref
    // below, issued after the node is back in the pool. A queue at zero has no
    // capability or binding left, as dealloc_object requires.
    unsafe {
        crate::sched::thread::for_each_observer(first, |node| {
            let eq = (*node).eq;
            crate::ipc::event_queue::event_queue_return_observer((*eq).state, node);
            if (*eq).header.dec_ref() == 0
            {
                dealloc_object(NonNull::new_unchecked(eq.cast::<KernelObjectHeader>()));
            }
        });
    }
}

/// Free the SEED-backed body of an object of concrete type `T`: drop it in
/// place, return its bytes to its ancestor Memory object, and release the
/// ancestor reference, pushing the ancestor onto `worklist` if that was the
/// last.
///
/// # Safety
/// `ptr` is an exclusively owned, retype-backed `T` (header at offset 0) that
/// nothing references; no lock is held.
#[cfg(not(test))]
unsafe fn free_body<T>(
    ptr: NonNull<KernelObjectHeader>,
    worklist: &mut [Option<NonNull<KernelObjectHeader>>],
    head: &mut usize,
)
{
    // SAFETY: caller contract.
    let ancestor_ptr = unsafe { ptr.as_ref().ancestor.load(Ordering::Acquire) };
    let Some(ancestor) = NonNull::new(ancestor_ptr)
    else
    {
        crate::fatal("free_body: object carries no ancestor");
    };
    // cast_ptr_alignment: the ancestor is a MemoryObject (header at offset 0).
    #[allow(clippy::cast_ptr_alignment)]
    // SAFETY: the object's reference keeps its ancestor live until the dec_ref.
    let ancestor_memory = unsafe { &*ancestor.as_ptr().cast::<MemoryObject>() };
    let body_phys = crate::mm::paging::virt_to_phys(ptr.as_ptr() as u64);
    let offset = body_phys - ancestor_memory.base;
    // SAFETY: exclusively owned body of type T (caller contract).
    unsafe { core::ptr::drop_in_place(ptr.as_ptr().cast::<T>()) };
    crate::cap::retype::retype_free(ancestor_memory, offset, core::mem::size_of::<T>() as u64);
    if ancestor_memory.header.dec_ref() == 0
    {
        push_cascade(worklist, head, ancestor);
    }
}

/// Release the lineage share of a refcount-0 `Mmio` or `IoPort` object of
/// concrete type `T`, freeing whatever bodies that leaves unreferenced: a
/// copy's own body at once, and its root's when the copy was the root's last
/// live member; a root's body only once it has no live copy
/// ([`RangeLineage`]).
///
/// # Safety
/// `ptr` is a refcount-0 `T`, exclusively owned, whose mappings or bindings
/// have been withdrawn; no lock is held.
#[cfg(not(test))]
unsafe fn release_range_object<T>(
    ptr: NonNull<KernelObjectHeader>,
    worklist: &mut [Option<NonNull<KernelObjectHeader>>],
    head: &mut usize,
)
{
    // SAFETY: a live Mmio or IoPort object (caller contract).
    let root = unsafe { lineage_of(ptr) }.root_of(ptr);
    if root != ptr
    {
        // A copy: nothing names its body once its references are gone.
        // SAFETY: caller contract.
        unsafe { free_body::<T>(ptr, worklist, head) };
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
        unsafe { free_body::<T>(root, worklist, head) };
    }
}

/// The object a new capability slot made by `SYS_CAP_COPY`, `SYS_CAP_DERIVE`,
/// or `SYS_CAP_DERIVE_BADGE` from a slot naming `src` references, with the
/// reference the new slot holds already taken.
///
/// For an `Mmio` or `IoPort` capability this is a fresh SEED-backed object
/// over the same range, in `src`'s lineage, so mappings and port bindings made
/// through the new capability are withdrawn when it is deleted, consumed by a
/// split, or revoked through an ancestor, whatever other capabilities to the
/// range survive
/// (docs/capability-model.md § Mmio, § `IoPort`). Every other type shares
/// `src`, whose reference count is incremented.
///
/// The caller releases the returned reference with [`release_ref`] if the
/// slot is never published.
///
/// # Errors
/// For `Mmio` and `IoPort`: `QuotaExceeded` when the lineage already has
/// [`RANGE_COPY_LIMIT`] live copies, and `OutOfMemory` when SEED cannot back
/// the copy. For every other type: `QuotaExceeded` when `src`'s reference
/// count is at [`REF_COUNT_LIMIT`].
///
/// # Safety
/// `src` is the live object of a slot tagged `tag`, pinned by the caller.
// cast_ptr_alignment: each object is constructed in place at a
// size-class-aligned retype offset; the header sits at offset 0.
#[allow(clippy::cast_ptr_alignment)]
#[cfg(not(test))]
pub unsafe fn object_for_new_slot(
    tag: crate::cap::slot::CapTag,
    src: NonNull<KernelObjectHeader>,
) -> Result<NonNull<KernelObjectHeader>, syscall::SyscallError>
{
    use crate::cap::retype::alloc_in_seed;
    use crate::cap::slot::CapTag;

    match tag
    {
        CapTag::Mmio =>
        {
            // SAFETY: tag Mmio; src pinned (contract).
            let mo = unsafe { &*src.as_ptr().cast::<MmioObject>() };
            let root = mo.lineage.root_of(src);
            // SAFETY: src is a pinned member of root's lineage, so root's live
            // count is above zero.
            let lineage = unsafe { RangeLineage::reserve_copy(root) }?;
            let mut body = MmioObject::new_root(mo.base, mo.size, mo.flags);
            body.lineage = lineage;
            alloc_in_seed(body).inspect_err(|_| {
                // SAFETY: undoes the reservation above; src's own share keeps
                // root's count above zero.
                unsafe { lineage_of(root) }
                    .live
                    .fetch_sub(1, Ordering::AcqRel);
            })
        }
        CapTag::IoPort =>
        {
            // SAFETY: tag IoPort; src pinned (contract).
            let po = unsafe { &*src.as_ptr().cast::<IoPortObject>() };
            let root = po.lineage.root_of(src);
            // SAFETY: as the Mmio arm.
            let lineage = unsafe { RangeLineage::reserve_copy(root) }?;
            let mut body = IoPortObject::new_root(po.base, po.size);
            body.lineage = lineage;
            alloc_in_seed(body).inspect_err(|_| {
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
/// Reclaiming a retype-backed object may credit bytes back to its ancestor
/// `MemoryObject` and decrement the ancestor's refcount. If the ancestor's
/// refcount reaches zero (transitively, when reclaiming a chain of caps
/// whose only ref was the descendant), the ancestor must also be freed.
/// This is handled via an explicit stack-local worklist driven by this
/// function rather than by recursion: each arm pushes the freshly-orphaned
/// ancestor into the worklist, and the outer loop processes it on the next
/// iteration. Recursion would risk deadlock if a future change introduced a
/// lock above this point. Four fan-outs nevertheless re-enter this function
/// with no lock held, because their width is unbounded or caller-chosen and
/// the worklist is not: the `CSpaceObj` arm for the objects a dying
/// `CSpace`'s slots reference; the `AddressSpace` and `CSpaceObj` arms'
/// `free_donation` (nested in `dealloc_object_one`) for a pool donation's
/// Memory object that reaches zero; the `WaitSet` arm for each member source
/// whose last reference the membership held; and `release_death_observers`,
/// from the Thread and `AddressSpace` arms, for each observer queue that
/// reaches zero. No re-entry can reach a `CSpace`: a nested `CSpace` whose
/// last reference a dying one held is linked, through its `deferred_next`
/// field, onto this call's pending list instead, and the outer loop below
/// tears it down once the worklist is empty. A `CSpace` slot's Thread,
/// `AddressSpace` or `WaitSet` may itself re-enter once more for its queues,
/// sources or donations, whose objects re-enter no further, so the re-entry
/// depth is at most two frames whatever the nesting depth of `CSpace`s
/// (core/kernel/docs/capability-internals.md § Teardown).
#[cfg(not(test))]
pub unsafe fn dealloc_object(ptr: core::ptr::NonNull<KernelObjectHeader>)
{
    /// Maximum nested-cascade depth handled. Real-world derivation chains
    /// (memmgr-memory → child-bootstrap split → kernel object) sit at depth
    /// `<= 4`, and each arm pushes at most a few entries per pop. Thirty-two
    /// entries fit comfortably on the kernel stack (256 B). The fan-outs whose
    /// width is unbounded or caller-chosen do not go through this worklist:
    /// `free_donation` runs each pool donation ancestor that reaches zero
    /// through its own nested cascade, and so do the `WaitSet` arm for each
    /// member source and `release_death_observers` for each observer's queue.
    const MAX_CASCADE: usize = 32;

    let mut worklist: [Option<core::ptr::NonNull<KernelObjectHeader>>; MAX_CASCADE] =
        [None; MAX_CASCADE];
    worklist[0] = Some(ptr);
    let mut head: usize = 1;
    // Nested `CSpace`s a dying `CSpace` released the last reference to,
    // linked through `CSpaceKernelObject::deferred_next` (see `# Cascade
    // handling`). Each is exclusively owned (refcount 0) and on no other list.
    let mut pending: *mut KernelObjectHeader = core::ptr::null_mut();

    loop
    {
        while head > 0
        {
            head -= 1;
            let Some(next) = worklist[head]
            else
            {
                continue;
            };
            worklist[head] = None;
            // SAFETY: `next` is a NonNull<KernelObjectHeader> that was the
            // original caller-supplied pointer, pushed onto the worklist by an
            // ancestor-reclaim arm, or taken from `pending` below — every
            // contract requires that no slot references the object (refcount
            // 0, or a never-published body) and exclusive ownership.
            unsafe { dealloc_object_one(next, &mut worklist, &mut head, &mut pending) };
        }
        let Some(nested) = NonNull::new(pending)
        else
        {
            break;
        };
        // SAFETY: `nested` is a refcount-0 CSpaceObj the CSpaceObj arm linked
        // here; its link field is read before its teardown can reuse it (a
        // self-teardown re-queues it on the per-CPU stack through the same
        // field).
        pending = unsafe { *deferred_link(nested) };
        worklist[0] = Some(nested);
        head = 1;
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
// items_after_statements: each arm imports the retype helpers it uses beside
// that use, after the arm's own statements.
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
    pending: &mut *mut KernelObjectHeader,
)
{
    /// Return one donation to its ancestor Memory object and drop the
    /// reference the donation held on it. An ancestor that reaches zero is
    /// reclaimed through its own nested cascade rather than the caller's
    /// worklist: a pool may hold any number of donations, each from a
    /// distinct Memory object, and the worklist is bounded. The nested call
    /// is the same re-entry the `CSpaceObj` arm already makes for the
    /// objects its slots reference.
    ///
    /// # Safety
    /// `(anc_ptr, off, pages)` must be a donation record handed out by
    /// `PagePool::reclaim_donations` under that function's contract, and the
    /// caller must hold no lock: the nested cascade takes its own.
    unsafe fn free_donation(anc_ptr: *mut KernelObjectHeader, off: u64, pages: u64)
    {
        // SAFETY: anc_ptr was set at donation recording from a live
        // MemoryObject's header; the inc_ref then is matched by the
        // dec_ref here.
        let anc_hdr = unsafe { &*anc_ptr };
        // cast_ptr_alignment: header at offset 0; MemoryObject is repr(C).
        #[allow(clippy::cast_ptr_alignment)]
        // SAFETY: as above; the ancestor stays live until the dec_ref below.
        let anc_memory = unsafe { &*anc_ptr.cast::<MemoryObject>() };
        crate::cap::retype::retype_free(anc_memory, off, pages * crate::mm::PAGE_SIZE as u64);
        if anc_hdr.dec_ref() == 0
        {
            // SAFETY: refcount reached 0; no live cap holds it, and the
            // donation's bytes have been returned to it above.
            unsafe { dealloc_object(NonNull::new_unchecked(anc_ptr)) };
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

            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);
            debug_assert!(
                !ancestor_ptr.is_null(),
                "Memory: every production cap is retype-backed (Phase-7 SEED, sys_memory_split SEED)"
            );
            // Retype-backed body lives inside the ancestor (the seed
            // Memory cap). Drop in place, return the body bytes to the
            // seed's per-Memory allocator, drop the retype-time lease.
            use crate::cap::retype::retype_free;
            // SAFETY: ancestor_ptr is non-null: every production object is
            // retype-backed (`KernelObjectHeader::ancestor`).
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
                push_cascade(worklist, head, ancestor_nn);
            }
        }
        ObjectType::Mmio =>
        {
            // Withdraw every mapping made through this capability's object
            // before its bytes go (docs/capability-model.md § Mmio).
            // SAFETY: refcount 0, so no slot or pin names the object and no map
            // records into it; no lock is held; the CPU is stable
            // (dealloc_object's contract).
            unsafe { (*ptr.as_ptr().cast::<MmioObject>()).withdraw_mappings() };
            // SAFETY: a refcount-0 Mmio object; no lock held.
            unsafe { release_range_object::<MmioObject>(ptr, worklist, head) };
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
            // have no routing-table footprint to clean up. Nor does a
            // single-id cap outside the routable range, which
            // sys_irq_register refuses; `irq::unregister` ignores an id
            // inside it that lies past the discovered routing table.
            if count == 1
                && (crate::arch::current::MIN_IRQ_ID..=crate::arch::current::MAX_IRQ_ID)
                    .contains(&start)
            {
                // SAFETY: not interrupt context, and no IPC source, scheduler,
                // or sleep-list lock is held (this function's contract), as
                // `irq::unregister` requires; it masks and releases the line.
                unsafe { crate::irq::unregister(start) };
            }

            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);
            debug_assert!(
                !ancestor_ptr.is_null(),
                "Interrupt: every production cap is retype-backed (Phase-7 SEED, sys_irq_split SEED)"
            );
            use crate::cap::retype::retype_free;
            // SAFETY: ancestor_ptr is non-null: every production object is
            // retype-backed (`KernelObjectHeader::ancestor`).
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
                push_cascade(worklist, head, ancestor_nn);
            }
        }
        ObjectType::IoPort =>
        {
            // Withdraw every port binding made through this capability's
            // object before its bytes go (docs/capability-model.md § IoPort).
            // SAFETY: no lock held; the pointer is only compared, never
            // dereferenced, by the withdrawal walk.
            unsafe { crate::cap::ioport_bindings::withdraw_everywhere(ptr.as_ptr() as usize) };
            // SAFETY: a refcount-0 IoPort object; no lock held.
            unsafe { release_range_object::<IoPortObject>(ptr, worklist, head) };
        }
        ObjectType::SchedControl =>
        {
            let ancestor_ptr = header.ancestor.load(Ordering::Acquire);
            debug_assert!(
                !ancestor_ptr.is_null(),
                "SchedControl: every production cap is retype-backed (Phase-7 SEED)"
            );
            use crate::cap::retype::retype_free;
            // SAFETY: ancestor_ptr is non-null: every production object is
            // retype-backed (`KernelObjectHeader::ancestor`).
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
                push_cascade(worklist, head, ancestor_nn);
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
            // SAFETY: ancestor_ptr is non-null: every production object is
            // retype-backed (`KernelObjectHeader::ancestor`).
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
                push_cascade(worklist, head, ancestor_nn);
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
                        push_cascade(
                            worklist,
                            head,
                            core::ptr::NonNull::new_unchecked(ep.cast::<KernelObjectHeader>()),
                        );
                    }
                }

                // Release the death observers' EventQueue references. The
                // thread runs on no CPU (the gate above), so its death walk is
                // over or never runs, and no binder can pin it (refcount 0).
                // SAFETY: tcb valid (not yet freed) and unreachable by any
                // other path.
                let first = unsafe { (*tcb).death_observers.take() };
                // SAFETY: the chain was just taken; no lock is held here.
                unsafe { release_death_observers(first) };

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

                // Release the per-thread port-binding table to SEED if one was
                // bound via `sys_ioport_bind` (x86-64 only). RISC-V threads never
                // set this field — there is no I/O port space — so `iopb` is
                // always null and this is a no-op there. The pointer is taken
                // under the thread's `sched_lock`: an `IoPort` teardown's
                // withdrawal walk (`ioport_bindings::withdraw_everywhere`) reads
                // the table under that lock while this TCB is still registered.
                // SAFETY: tcb validated non-null; lock_raw/unlock_raw paired.
                let iopb_ptr = unsafe {
                    let saved = (*tcb).sched_lock.lock_raw();
                    let p = (*tcb).iopb;
                    (*tcb).iopb = core::ptr::null_mut();
                    (*tcb).sched_lock.unlock_raw(saved);
                    p
                };
                if !iopb_ptr.is_null()
                {
                    crate::cap::retype::free_seed_scratch(
                        iopb_ptr.cast::<u8>(),
                        crate::cap::ioport_bindings::TABLE_BYTES,
                    );
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
            let raw_bytes = dispatch_for(ObjectType::Thread, 0).map_or(
                (crate::sched::KERNEL_STACK_PAGES as u64 + 2) * crate::mm::PAGE_SIZE as u64,
                |e| e.raw_bytes,
            );
            // SAFETY: ancestor_ptr is non-null: every production object is
            // retype-backed (`KernelObjectHeader::ancestor`).
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
                push_cascade(worklist, head, ancestor_nn);
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
                    // SAFETY: as_ptr non-null; active_cpu_mask is an Acquire snapshot.
                    unsafe { (*as_ptr).active_cpu_mask() }.is_empty(),
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
                unsafe { release_death_observers(first) };

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
            let free = |anc: *mut KernelObjectHeader, off: u64, pages: u64| {
                // SAFETY: a record handed out by reclaim_donations under
                // its contract; no lock held.
                unsafe { free_donation(anc, off, pages) }
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
        // donation. Reclamation returns every donation to its Memory object
        // wholesale and drops the reference each held, the create-time slab
        // last.
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

            // Captured for the final `free_cspace_id` after the lock release;
            // `needs_free_id` stays false when cs_ptr is null (no id to
            // recycle), which short-circuits the free-list push below.
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
                // without DERIVATION_LOCK so the nested deallocs can take it.
                // A nested CSpace reaching zero is not torn down here: it is
                // linked onto the outer `dealloc_object`'s pending list, so a
                // chain of CSpaces each holding the last reference to the
                // next is torn down iteratively, not one recursion per level.
                // No other type's teardown can release a CSpace, so the
                // re-entry below adds one frame, and a slot's Thread,
                // AddressSpace or WaitSet at most one more (see
                // `dealloc_object`).
                // SAFETY: cs_ptr non-null; for_each_object handles iteration.
                unsafe {
                    (*cs_ptr).for_each_object(|obj_ptr| {
                        let hdr = obj_ptr.as_ref();
                        let rc = hdr.dec_ref();
                        if rc != 0
                        {
                            return;
                        }
                        if hdr.obj_type == ObjectType::CSpaceObj
                        {
                            // Refcount 0: the object is ours and on no list.
                            *deferred_link(obj_ptr) = *pending;
                            *pending = obj_ptr.as_ptr();
                        }
                        else
                        {
                            dealloc_object(obj_ptr);
                        }
                    });
                }

                // Drop the inline CSpace before reclaiming its storage; its
                // own `Drop` is a no-op for retype-backed (pool pages flow
                // back through the donation reclaim below).
                // SAFETY: cs_ptr is about to be reclaimed; no outside
                // reference outlives the cap deletion that brought us here.
                unsafe {
                    core::ptr::drop_in_place(cs_ptr);
                }

                needs_free_id = true;
            }

            // Return every donation, the create-time slab (holding the
            // wrapper and this pool) last; `obj` is dangling afterwards.
            // Unlike the derivation drain above, this walk is not batched:
            // no lock is held across it (each return takes only its
            // ancestor's cap lock), so nothing else waits on it, and its
            // length is the number of donations the owner paid for.
            let free = |anc: *mut KernelObjectHeader, off: u64, pages: u64| {
                // SAFETY: a record handed out by reclaim_donations under its
                // contract; no lock held.
                unsafe { free_donation(anc, off, pages) }
            };
            // SAFETY: refcount 0, no slot references the object, the
            // in-place CSpace has been dropped, and no lock is held.
            unsafe { obj.cs_pool.reclaim_donations(free) };

            // Recycle the id last, after all of the dying CSpace's storage
            // is reclaimed and DERIVATION_LOCK is released. Randomizing the
            // epoch now invalidates any surviving SlotId stamped with the
            // pre-recycle value — subsequent `lookup_cspace` returns None.
            if needs_free_id
            {
                crate::cap::free_cspace_id(dying_id);
            }

            // No separate free of the wrapper — it lives inside the slab reclaimed above.
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
            // worklist if it hits zero.
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
            retype_free(ancestor_memory, offset, raw_bytes);

            // Drop the retype-time refcount lease. If this was the Memory cap's last
            // reference, push it onto the cascade worklist; dealloc_object frees it on
            // a later iteration (the Memory arm returns its buddy pages).
            let ancestor_nn =
                // SAFETY: ancestor_ptr is non-null per debug_assert.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_memory.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: refcount reached 0; the worklist runs the Memory
                // arm above (which frees the buddy pages).
                push_cascade(worklist, head, ancestor_nn);
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
                // Clear the IRQ routes that point to this NotificationState and
                // wait out the device-IRQ deliveries in flight through them on
                // any CPU; a route an earlier replace or clear removed was
                // drained by that change, so none reaches the state after the
                // free below (irq::unregister_notification).
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

            retype_free(ancestor_memory, offset, raw_bytes);

            // Drop the retype-time refcount lease; on full release, queue the Memory
            // cap on the cascade worklist.
            let ancestor_nn =
                // SAFETY: ancestor_ptr non-null.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_memory.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: refcount reached 0; queue the Memory cap on the cascade worklist.
                push_cascade(worklist, head, ancestor_nn);
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

            retype_free(ancestor_memory, offset, raw_bytes);

            let ancestor_nn =
                // SAFETY: ancestor_ptr non-null.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_memory.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: refcount reached 0.
                push_cascade(worklist, head, ancestor_nn);
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
                // reclaimed only after its back-pointer clear released every
                // source/ws IPC lock (see scheduling-internals.md § Lock
                // Hierarchy). A set may hold up to WAIT_SET_MAX_MEMBERS last
                // references, more than the bounded worklist, so each zeroed
                // source is reclaimed through its own nested cascade (the
                // re-entry `free_donation` makes); `wait_set_drop` calls back
                // with no lock held.
                // SAFETY: state non-null and live; each zeroed header has no
                // capability or membership left, as dealloc_object requires.
                unsafe {
                    crate::ipc::wait_set::wait_set_drop(state, |source| dealloc_object(source));
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

            retype_free(ancestor_memory, offset, raw_bytes);

            let ancestor_nn =
                // SAFETY: ancestor_ptr non-null.
                unsafe { core::ptr::NonNull::new_unchecked(ancestor_ptr) };
            let new_rc = ancestor_memory.header.dec_ref();
            if new_rc == 0
            {
                // SAFETY: refcount reached 0.
                push_cascade(worklist, head, ancestor_nn);
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

    #[test]
    fn a_range_lineage_admits_exactly_the_copy_limit()
    {
        let mut root = MmioObject::new_root(0x1000_0000, 0x1000, 0);
        let root_hdr = NonNull::from(&mut root).cast::<KernelObjectHeader>();
        for _ in 0..RANGE_COPY_LIMIT
        {
            // SAFETY: root is a live lineage root with its own share held.
            let copy = unsafe { RangeLineage::reserve_copy(root_hdr) }.unwrap();
            assert_eq!(copy.root_of(NonNull::dangling()), root_hdr);
        }
        // SAFETY: as above.
        let refused = unsafe { RangeLineage::reserve_copy(root_hdr) };
        assert!(matches!(refused, Err(syscall::SyscallError::QuotaExceeded)));
        assert_eq!(
            root.lineage.live.load(Ordering::Relaxed),
            ROOT_SHARE + RANGE_COPY_LIMIT
        );
    }

    #[test]
    fn a_full_mapping_table_refuses_a_new_mapping_but_not_a_repeat()
    {
        let mmio = MmioObject::new_root(0x1000_0000, 0x1000, 0);
        let mut spaces: [core::mem::MaybeUninit<AddressSpaceObject>; MMIO_MAX_MAPPINGS + 1] =
            [const { core::mem::MaybeUninit::uninit() }; MMIO_MAX_MAPPINGS + 1];
        let mut asos = [core::ptr::null_mut::<AddressSpaceObject>(); MMIO_MAX_MAPPINGS + 1];
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
        for &aso in &asos[..MMIO_MAX_MAPPINGS]
        {
            // SAFETY: each aso has a live header; mmio is exclusively ours.
            unsafe { mmio.record_mapping(aso, 0x4000_0000) }.unwrap();
        }
        // SAFETY: as above.
        let full = unsafe { mmio.record_mapping(asos[MMIO_MAX_MAPPINGS], 0x4000_0000) };
        assert!(matches!(full, Err(syscall::SyscallError::QuotaExceeded)));
        // SAFETY: as above.
        unsafe { mmio.record_mapping(asos[0], 0x4000_0000) }.unwrap();
        // SAFETY: the header was initialised above.
        let refs = unsafe { (*asos[0]).header.ref_count.load(Ordering::Relaxed) };
        assert_eq!(refs, 2, "a repeat mapping takes no second reference");
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
}
