// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/cap/mod.rs

//! Capability subsystem (Phase 7).
//!
//! Initialised by [`init_capability_system`], which creates the root `CSpace`
//! (id 0) populated with initial capabilities for all boot-provided hardware
//! resources:
//!
//! - Usable physical memory → [`CapTag::Frame`] caps (MAP | WRITE | EXECUTE)
//! - MMIO apertures (coarse non-RAM ranges from the boot protocol)
//!   → [`CapTag::MmioRegion`] caps (MAP | WRITE)
//! - One root [`CapTag::Interrupt`] range cap covering every valid IRQ id
//!   (userspace narrows via `sys_irq_split`)
//! - Per `AcpiReclaimable` region, the ACPI RSDP page, and the DTB blob →
//!   read-only [`CapTag::Frame`] caps so userspace can parse firmware tables
//! - One root [`CapTag::IoPortRange`] cap covering the full 64K I/O port
//!   space (x86-64, USE)
//! - One [`CapTag::SchedControl`] cap (ELEVATE)
//! - One [`CapTag::SbiControl`] cap on RISC-V (CALL)
//!
//! The populated `CSpace` is stored in [`ROOT_CSPACE`] until Phase 9 hands it
//! to the init process. Boot module ELF images get their own RO Frame caps
//! in [`mint_module_frame_caps`].

// cast_possible_truncation: u64→usize/u32/u16 capability field extractions bounded by capability space.
#![allow(clippy::cast_possible_truncation)]

// `alloc` is only required by the test build (heap-backed CSpace stub +
// `nonnull_from_box` test helper). Production has no `GlobalAlloc`.
#[cfg(test)]
extern crate alloc;

#[cfg(test)]
use alloc::boxed::Box;

pub mod cspace;
pub mod derivation;
pub mod object;
pub mod retype;
pub mod slot;

// Re-exports for convenience. Many are consumed by future phases; suppress the
// unused lint rather than removing symbols that future code will reference.
#[allow(unused_imports)]
pub use cspace::{CSpace, CapError, L1_SIZE, L2_SIZE};
#[allow(unused_imports)]
pub use derivation::DERIVATION_LOCK;
#[allow(unused_imports)]
pub use object::{
    AddressSpaceObject, CSpaceKernelObject, EndpointObject, FrameObject, InterruptObject,
    IoPortRangeObject, KernelObjectHeader, MmioRegionObject, ObjectType, SbiControlObject,
    SchedControlObject, SignalObject, ThreadObject,
};
#[allow(unused_imports)]
pub use slot::{CSpaceId, CapTag, CapabilitySlot, Rights, SlotId};

use boot_protocol::{BootInfo, MemoryMapEntry, MemoryType, MmioAperture};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use init_protocol::CapDescriptor;

use crate::mm::paging::phys_to_virt;

// ── Globals ───────────────────────────────────────────────────────────────────

/// Root capability space, populated during Phase 7.
///
/// The pointer indexes into a SEED-derived retype slab whose storage is
/// pinned for the lifetime of the kernel (the seed's pin keeps the chunk
/// alive — see [`install_seed_frame`]). Set in [`init_capability_system`]
/// via [`boot_retype_cspace`]; consumed (read out into init's TCB) during
/// Phase 9. Access is single-threaded during boot; `static mut` is safe
/// here under that invariant.
#[cfg(not(test))]
pub static mut ROOT_CSPACE: *mut CSpace = core::ptr::null_mut();

/// Take the root `CSpace` pointer, clearing the slot to null.
///
/// Returns the raw pointer (storage lives inside a SEED slab; ownership is
/// "use by-pointer until init dies"). The slot is cleared so no other code
/// can observe a live root cspace pointer afterwards.
///
/// Uses raw pointer operations to avoid creating a mutable reference to a
/// mutable static. Safe because access is single-threaded during boot.
///
/// # Safety
/// Must be called only in single-threaded boot context before init runs.
#[cfg(not(test))]
pub unsafe fn take_root_cspace() -> *mut CSpace
{
    let ptr_loc = core::ptr::addr_of_mut!(ROOT_CSPACE);
    // SAFETY: single-threaded boot; no concurrent access.
    unsafe {
        let prev = *ptr_loc;
        *ptr_loc = core::ptr::null_mut();
        prev
    }
}

/// Borrow the root `CSpace` mutably.
///
/// Uses raw pointer operations to avoid creating a mutable reference to a
/// mutable static. Safe here because access is single-threaded during boot.
///
/// # Safety
/// Must be called only in single-threaded boot context before init runs.
#[cfg(not(test))]
pub unsafe fn root_cspace_mut() -> Option<&'static mut CSpace>
{
    let ptr_loc = core::ptr::addr_of_mut!(ROOT_CSPACE);
    // SAFETY: single-threaded boot; no concurrent access.
    let raw = unsafe { *ptr_loc };
    if raw.is_null()
    {
        None
    }
    else
    {
        // SAFETY: raw was set by `boot_retype_cspace` and points at a live
        // `CSpace` inside a SEED-pinned slab; single-threaded boot.
        unsafe { Some(&mut *raw) }
    }
}

/// Maximum number of `CSpace`s that can be live in the registry at one time.
///
/// IDs are recycled via the [`CSPACE_FREE_LIST`] free list once
/// [`free_cspace_id`] runs at the end of a `CSpace`'s `dealloc_object` pass,
/// so this is a live-count bound — not the cumulative-ever bound it used to
/// be under the pre-#137 monotonic allocator. Per-id generation counters in
/// [`CSPACE_REGISTRY`] make any pre-existing stale `SlotId` resolution fail
/// fast on epoch mismatch, so recycling cannot mis-target a recycled
/// tenant. The pre-unregister derivation drain (`dealloc_object` for
/// `CSpaceObj`) additionally scrubs the back-links in steady state.
///
/// Live-count peaks in ktest stress today sit in the low hundreds; 4096
/// gives 10–40× headroom while reclaiming ~432 KiB of BSS the
/// pre-#137 65536-entry registry burned (65536 × 8 B = 512 KiB old
/// registry vs 4096 × 16 B = 64 KiB new registry + 4096 × 4 B = 16 KiB
/// free list = 80 KiB total; 512 − 80 = 432 KiB net). A future workload
/// that genuinely needs more live `CSpace`s only has to bump this
/// constant — no layout, ABI, or algorithmic change is required.
const MAX_CSPACES: usize = 4096;

/// High-water mark for the bump-allocator side of `alloc_cspace_id` — only
/// consulted when the free list is empty. Once `HIGH_WATER_CSPACE_ID` reaches
/// `MAX_CSPACES`, no new id can be minted until a prior id is recycled.
static HIGH_WATER_CSPACE_ID: AtomicU32 = AtomicU32::new(0);

/// One slot of the global `CSpace` registry.
///
/// `ptr` is the live `CSpace` pointer or null when the slot is vacant.
/// `epoch` is a generation counter incremented each time an id is freed
/// (see [`free_cspace_id`]); a `SlotId` stamped with a stale epoch fails
/// resolution at [`lookup_cspace`] so a recycled id cannot alias a foreign
/// derivation link into the new tenant.
///
/// `align(16)` colocates `ptr` and `epoch` on the same cache line and leaves
/// room for a future 16-byte CAS if contention warrants it.
#[repr(C, align(16))]
struct CSpaceRegistryEntry
{
    ptr: AtomicPtr<CSpace>,
    epoch: AtomicU32,
    _pad: [u8; 4],
}

impl CSpaceRegistryEntry
{
    const fn empty() -> Self
    {
        Self {
            ptr: AtomicPtr::new(core::ptr::null_mut()),
            // Epoch starts at 1 so the sentinel value `0` (used by the
            // free-list intrusive encoding in `CapabilitySlot::set_next_free`)
            // never matches any live entry — a stale lookup of a free-listed
            // slot resolves to `None` rather than the root `CSpace`.
            epoch: AtomicU32::new(1),
            _pad: [0; 4],
        }
    }
}

/// Global registry mapping `CSpaceId` → (`*mut CSpace`, epoch).
///
/// Populated by [`register_cspace`] when a `CSpace` is created. Cleared by
/// [`unregister_cspace`] when the backing object is freed. The epoch is
/// bumped by [`free_cspace_id`] at the end of `dealloc_object` so any
/// stale `SlotId` carrying the old epoch fails fast on subsequent
/// resolution.
///
/// # Safety invariant
/// A non-null `ptr` is valid as long as the corresponding `CSpaceKernelObject`
/// refcount is > 0. After `dec_ref` reaches 0 and `dealloc_object` runs,
/// `unregister_cspace` clears `ptr` before the memory is freed, and
/// `free_cspace_id` bumps `epoch` before the id returns to the free list.
static CSPACE_REGISTRY: [CSpaceRegistryEntry; MAX_CSPACES] =
    [const { CSpaceRegistryEntry::empty() }; MAX_CSPACES];

/// Free list of returned `CSpaceId`s, popped LIFO before
/// [`HIGH_WATER_CSPACE_ID`] is bumped.
///
/// Protected by [`CSPACE_FREE_LIST_LOCK`]. The stack stores released ids;
/// `len` is the number of valid entries. Single global spinlock is fine —
/// cap-create/destroy is rare relative to IPC/map fast paths, and the
/// critical sections are O(1) push/pop.
#[cfg(not(test))]
static CSPACE_FREE_LIST_LOCK: crate::sync::Spinlock = crate::sync::Spinlock::new();
#[cfg(not(test))]
static mut CSPACE_FREE_LIST: [CSpaceId; MAX_CSPACES] = [0; MAX_CSPACES];
#[cfg(not(test))]
static mut CSPACE_FREE_LIST_LEN: usize = 0;

/// Push a recycled id onto the free list.
///
/// Called from [`free_cspace_id`] after the epoch bump. Saturating: if the
/// free list is already at capacity (impossible by construction since we
/// only push ids in `[0, MAX_CSPACES)` and `MAX_CSPACES` slots fit), the
/// id leaks rather than panicking.
#[cfg(not(test))]
fn push_free(id: CSpaceId)
{
    // SAFETY: lock serialises all free-list mutations.
    let saved = unsafe { CSPACE_FREE_LIST_LOCK.lock_raw() };
    // SAFETY: single-writer access under lock.
    unsafe {
        if CSPACE_FREE_LIST_LEN < MAX_CSPACES
        {
            CSPACE_FREE_LIST[CSPACE_FREE_LIST_LEN] = id;
            CSPACE_FREE_LIST_LEN += 1;
        }
    }
    // SAFETY: paired with lock_raw above.
    unsafe { CSPACE_FREE_LIST_LOCK.unlock_raw(saved) };
}

/// Pop a recycled id from the free list, or `None` if empty.
#[cfg(not(test))]
fn pop_free() -> Option<CSpaceId>
{
    // SAFETY: lock serialises all free-list mutations.
    let saved = unsafe { CSPACE_FREE_LIST_LOCK.lock_raw() };
    // SAFETY: single-writer access under lock.
    let id = unsafe {
        if CSPACE_FREE_LIST_LEN > 0
        {
            CSPACE_FREE_LIST_LEN -= 1;
            Some(CSPACE_FREE_LIST[CSPACE_FREE_LIST_LEN])
        }
        else
        {
            None
        }
    };
    // SAFETY: paired with lock_raw above.
    unsafe { CSPACE_FREE_LIST_LOCK.unlock_raw(saved) };
    id
}

/// Allocate a unique `CSpace` ID.
///
/// Pops a recycled id off the free list first; otherwise bumps the
/// high-water counter. Returns `None` once `MAX_CSPACES` are simultaneously
/// live (callers must surface `SyscallError::OutOfMemory`).
///
/// The root `CSpace` receives id `0` at init time via the high-water path
/// — Phase 7 runs before any `free_cspace_id` could populate the free list,
/// so the root deterministically gets id 0 (and is hard-rejected from
/// returning to the free list by [`free_cspace_id`]).
#[cfg(not(test))]
pub fn alloc_cspace_id() -> Option<CSpaceId>
{
    if let Some(id) = pop_free()
    {
        return Some(id);
    }
    let next = HIGH_WATER_CSPACE_ID.fetch_add(1, Ordering::Relaxed);
    if (next as usize) >= MAX_CSPACES
    {
        // Clamp so the counter doesn't wrap u32 under sustained pressure.
        HIGH_WATER_CSPACE_ID.store(MAX_CSPACES as u32, Ordering::Relaxed);
        return None;
    }
    Some(next)
}

/// Test-only stub: monotonic allocation, no recycling.
///
/// The host-side test path doesn't exercise the lock primitive or the BSS
/// free list (no SMP, no interrupts), and tests only ever create the single
/// root CSpace before tearing down. The simple monotonic allocator matches
/// the pre-#137 behavior exactly.
#[cfg(test)]
pub fn alloc_cspace_id() -> Option<CSpaceId>
{
    let next = HIGH_WATER_CSPACE_ID.fetch_add(1, Ordering::Relaxed);
    if (next as usize) >= MAX_CSPACES
    {
        return None;
    }
    Some(next)
}

/// Register a `CSpace` pointer under its ID.
///
/// Called immediately after a [`CSpace`] is allocated. Returns the registry
/// entry's current epoch so the caller can stamp `SlotId`s minted in this
/// `CSpace`'s lifetime. Returns `Err(())` if `id >= MAX_CSPACES`.
pub fn register_cspace(id: CSpaceId, ptr: *mut CSpace) -> Result<u32, ()>
{
    if (id as usize) >= MAX_CSPACES
    {
        return Err(());
    }
    let entry = &CSPACE_REGISTRY[id as usize];
    debug_assert!(
        entry.ptr.load(Ordering::Acquire).is_null(),
        "register_cspace: id {id} already registered"
    );
    entry.ptr.store(ptr, Ordering::Release);
    Ok(entry.epoch.load(Ordering::Acquire))
}

/// Clear a `CSpace` registration.
///
/// Called from `dealloc_object` for `ObjectType::CSpaceObj` *before* freeing
/// the backing allocation, so no dangling pointer is observable. The
/// generation bump that retires this id is deferred to [`free_cspace_id`]
/// so the pre-unregister derivation drain can still resolve foreign
/// back-links into this `CSpace`'s live (now-quiescent) registry entry.
pub fn unregister_cspace(id: CSpaceId)
{
    if (id as usize) < MAX_CSPACES
    {
        CSPACE_REGISTRY[id as usize]
            .ptr
            .store(core::ptr::null_mut(), Ordering::Release);
    }
}

/// Bump the registry epoch for `id` and return it to the free list.
///
/// Pre-condition: `unregister_cspace(id)` has run (registry `ptr` is null).
/// Bumping the epoch invalidates any surviving `SlotId` stamped with the
/// old value — subsequent `lookup_cspace(id, old_epoch)` returns `None`.
///
/// If the epoch would overflow `u32`, the id is permanently retired: not
/// pushed back to the free list. The eventually-leaked-id rate is bounded
/// by `u32::MAX` recycles per id, which is unreachable in any realistic
/// system lifetime (≥13 years at 10k recycles/sec/id).
///
/// Asserts `id != 0`: the root `CSpace`'s id is reserved for kernel
/// lifetime; the `HDR_FLAG_IS_ROOT` clamp in `dec_ref` should already make
/// it unreachable, but defense-in-depth catches misroutes here.
#[cfg(not(test))]
pub fn free_cspace_id(id: CSpaceId)
{
    assert!(id != 0, "free_cspace_id: root CSpace cannot be recycled");
    debug_assert!((id as usize) < MAX_CSPACES);
    let entry = &CSPACE_REGISTRY[id as usize];
    debug_assert!(
        entry.ptr.load(Ordering::Acquire).is_null(),
        "free_cspace_id called before unregister_cspace for id {id}"
    );
    let prev = entry.epoch.fetch_add(1, Ordering::AcqRel);
    if prev == u32::MAX
    {
        // Retired: the next fetch_add would wrap to 0, which the registry
        // initialiser treats as "no entry"/free-list sentinel. Leak the id
        // rather than risk aliasing.
        crate::kprintln!("cspace: id {id} retired (epoch wraparound)");
        return;
    }
    push_free(id);
}

/// Read the current epoch for a registry entry. Returns 0 if `id` is out
/// of range (a stale `SlotId` carrying an out-of-range `cspace_id` is
/// always rejected by `lookup_cspace` regardless).
pub fn registry_epoch(id: CSpaceId) -> u32
{
    if (id as usize) >= MAX_CSPACES
    {
        return 0;
    }
    CSPACE_REGISTRY[id as usize].epoch.load(Ordering::Acquire)
}

/// Resolve a `CSpaceId` and expected epoch to a raw pointer.
///
/// Returns `None` if `id` is out of range, the slot is vacant, or the
/// stamped epoch doesn't match the registry's current value. The double
/// epoch load brackets the ptr load so a concurrent `unregister →
/// free_cspace_id → reuse → register` sequence cannot present a
/// newly-registered ptr alongside an old expected epoch.
///
/// The returned pointer is valid only while the corresponding
/// `CSpaceKernelObject` has a positive refcount and (for derivation-tree
/// reads) `DERIVATION_LOCK` is held.
pub fn lookup_cspace(id: CSpaceId, expected_epoch: u32) -> Option<*mut CSpace>
{
    if (id as usize) >= MAX_CSPACES
    {
        return None;
    }
    let entry = &CSPACE_REGISTRY[id as usize];
    let e1 = entry.epoch.load(Ordering::Acquire);
    if e1 != expected_epoch
    {
        return None;
    }
    let ptr = entry.ptr.load(Ordering::Acquire);
    if ptr.is_null()
    {
        return None;
    }
    let e2 = entry.epoch.load(Ordering::Acquire);
    if e2 != expected_epoch
    {
        return None;
    }
    Some(ptr)
}

/// Sum [`FrameObject::available_bytes`] across every [`CapTag::Frame`] cap
/// in `cspace`. Used by Phase 9 to print the boot-handover ledger so that
/// "RAM granted to userspace as retypable bytes" can be reconciled against
/// the buddy/SEED bookkeeping over time.
///
/// Must be called single-threaded with no concurrent retype/dealloc.
#[cfg(not(test))]
#[must_use]
pub fn sum_frame_available_bytes(cspace: &cspace::CSpace) -> u64
{
    use core::sync::atomic::Ordering;
    let mut sum: u64 = 0;
    cspace.for_each_object(|obj_nn| {
        // SAFETY: for_each_object yields live KernelObjectHeader pointers.
        let obj_type = unsafe { obj_nn.as_ref().obj_type };
        if obj_type == object::ObjectType::Frame
        {
            // cast_ptr_alignment: header at offset 0; FrameObject is repr(C).
            #[allow(clippy::cast_ptr_alignment)]
            // SAFETY: obj_type confirms FrameObject layout; pointer live.
            let frame = unsafe { &*obj_nn.as_ptr().cast::<object::FrameObject>() };
            sum += frame.available_bytes.load(Ordering::Acquire);
        }
    });
    sum
}

/// Maximum slots in the root `CSpace` (full two-level directory).
const ROOT_CSPACE_MAX_SLOTS: usize = 14336;

/// Target slot capacity for the root `CSpace`'s initial slot-page pool.
///
/// `populate_cspace` plus [`mint_module_frame_caps`] mint ~150 caps into
/// the root; userspace init then mints, copies, and derives ~700 more
/// caps during memmgr / procmgr bootstrap (kernel-object inserts +
/// per-RAM-Frame derive/copy chains in `finalize_memmgr`). Sized at
/// 1536 slots: roughly 1.8× the observed ~850-cap pre-memmgr-handover
/// peak. The headroom absorbs realistic per-RAM-block-count growth
/// (more drained blocks ⇒ more init-time Frame-cap derivations) and
/// per-service growth (more boot modules ⇒ more module-frame caps)
/// without revisiting this knob.
///
/// MUST be kept in sync with the boot footprint: a target below the
/// peak boot slot count means `pre_allocate`'s grow loop hits an
/// exhausted pool, the syscall errors out, and the userspace caller
/// either retries indefinitely (e.g. `request_round` in a child) or
/// surfaces an unexpected `OutOfMemory`. After memmgr is alive, further
/// growth is bounded only by `ROOT_CSPACE_MAX_SLOTS`.
#[cfg(not(test))]
const ROOT_CSPACE_INIT_SLOT_CAPACITY: u64 = 1536;

/// Pages carved from `SEED_FRAME` for the root `CSpace` slab: page 0 is the
/// wrapper page (`CSpaceKernelObject` + inlined `CSpace`); the remaining
/// pages seed the slot-page pool. Sized so the pool holds at least
/// [`ROOT_CSPACE_INIT_SLOT_CAPACITY`] slots regardless of `L2_SIZE`
/// (slots-per-page). The slot-0 reservation on page 0 costs one slot
/// and is absorbed by rounding up.
#[cfg(not(test))]
const ROOT_CSPACE_INIT_PAGES: u64 =
    1 + ROOT_CSPACE_INIT_SLOT_CAPACITY.div_ceil(cspace::L2_SIZE as u64);

// ── Phase-7 seed Frame cap ───────────────────────────────────────────────────

/// Bytes carved off the front of the largest drained RAM block to host
/// every initial cap-identity body.
///
/// Today's footprint on `x86_64` is ~150 KB:
/// ~15 KB for sub-page cap-identity bodies (≈ 110 bin-128 slots: 91 other
/// RAM `FrameObject`s + 10 `MmioRegion` wrappers + 1 `Interrupt` + 1
/// `IoPortRange` + 1 `SchedControl` + 2 ACPI Frames + 6 module Frames +
/// 3 init-segment Frames + 1 seed-tail Frame, plus the seed's own
/// `RetypeAllocator` metadata), plus ~130 KB for init's bootstrap state
/// (one [`AddressSpaceObject`] slab — wrapper page + root PT + PT growth
/// pool, one [`CSpaceKernelObject`] slab — wrapper page + slot-page pool,
/// one [`ThreadObject`] slab — kernel stack + wrapper/TCB).
/// `SEED_RESERVE_BYTES` is sized at 512 KB — generous headroom so future
/// cap types and longer module lists land without revisiting the constant.
///
/// The remainder of the largest block is exposed to userspace as a
/// regular retype-backed RAM Frame cap (the "seed-tail"), so init and
/// memmgr operate on virgin caps with zero behavioural change in their
/// front-split allocators.
#[cfg(not(test))]
const SEED_RESERVE_BYTES: u64 = 512 * 1024;

/// BSS-static `FrameObject` covering the seed RAM region.
///
/// Phase 7 mints every initial cap identity (`FrameObject` for every
/// drained RAM block, `MmioRegion` / `Interrupt` / `IoPortRange` /
/// `SchedControl` / `SbiControl` wrappers, plus firmware-table and
/// boot-module `FrameObject`s, plus init's ELF-segment `FrameObject`s,
/// plus the seed-tail `FrameObject` exposing the rest of the largest
/// drained block) from this seed via [`crate::cap::retype::boot_retype_body`].
/// The bodies land inside the seed's `SEED_RESERVE_BYTES` reservation,
/// debited from `available_bytes` like every other byte.
///
/// The seed itself is **not** inserted into init's `CSpace`: it is pure
/// kernel-internal storage. Userspace sees the largest drained block's
/// RAM via the seed-tail cap, which is virgin (`bump_offset = 0`) and
/// behaves like every other RAM Frame cap.
///
/// Pinned with a `+1` refcount in [`install_seed_frame`] so dealloc never
/// fires against this static. The static's initial `ref_count = 1`
/// represents that pin; every retyped descendant body adds another
/// reference; reclaim of every descendant drops back to `1`, which is
/// non-zero — `dec_ref` returns `1`, `dealloc_object` is never invoked,
/// and the BSS storage stays valid for the lifetime of the kernel.
///
/// Single-threaded boot context permits `static mut`; `addr_of(_mut)!`
/// access patterns sidestep the `static_mut_refs` lint.
#[cfg(not(test))]
static mut SEED_FRAME: object::FrameObject = object::FrameObject {
    header: object::KernelObjectHeader {
        ref_count: AtomicU32::new(1),
        obj_type: object::ObjectType::Frame,
        flags: 0,
        _pad: [0; 2],
        ancestor: AtomicPtr::new(core::ptr::null_mut()),
    },
    base: 0,
    size: 0,
    available_bytes: core::sync::atomic::AtomicU64::new(0),
    owns_memory: core::sync::atomic::AtomicBool::new(true),
    allocator: crate::cap::retype::RetypeAllocator::new_inline(),
    lock: AtomicU32::new(0),
};

/// Borrow the seed `FrameObject` shared.
///
/// `base`/`size` are mutated only during [`install_seed_frame`] (single-
/// threaded Phase 7); after that, retype/dealloc paths see them as stable.
#[cfg(not(test))]
pub(crate) fn seed_frame_ref() -> &'static object::FrameObject
{
    let p = core::ptr::addr_of!(SEED_FRAME);
    // SAFETY: `SEED_FRAME` is a non-null BSS static; `addr_of!` produces a
    // valid pointer for shared access.
    unsafe { &*p }
}

/// `NonNull` over the seed `FrameObject`'s header for use as a
/// `KernelObjectHeader::with_ancestor` argument and as the seed slot's
/// `object` pointer.
#[cfg(not(test))]
pub(crate) fn seed_header_nn() -> NonNull<object::KernelObjectHeader>
{
    // SAFETY: `SEED_FRAME` is a non-null BSS static; `addr_of_mut!` produces
    // a valid pointer.
    let p = unsafe { core::ptr::addr_of_mut!(SEED_FRAME.header) };
    // SAFETY: `p` is non-null; the lifetime of the underlying storage is
    // the kernel image lifetime (the seed is pinned).
    unsafe { NonNull::new_unchecked(p) }
}

/// Test-build placeholder. The test path leaks every kernel object via
/// `Box::leak` and never invokes `dealloc_object` (which is
/// `cfg(not(test))`), so the ancestor pointer is written into bodies but
/// never dereferenced; a dangling `NonNull` satisfies the type without
/// allocating.
#[cfg(test)]
pub(crate) fn seed_header_nn() -> NonNull<object::KernelObjectHeader>
{
    NonNull::dangling()
}

/// One-shot Phase-7 seed initializer. Sets the seed `FrameObject`'s runtime
/// fields (covering the front [`SEED_RESERVE_BYTES`] of the largest
/// drained block) and bumps the refcount once for the kernel pin. Caller
/// must invoke before any [`crate::cap::retype::boot_retype_body`] against
/// the seed.
///
/// # Safety
///
/// Call exactly once during Phase 7, single-threaded.
#[cfg(not(test))]
unsafe fn install_seed_frame(base: u64)
{
    let p = core::ptr::addr_of_mut!(SEED_FRAME);
    // SAFETY: single-threaded boot; the seed is not published anywhere
    // until after this call, so no other reader exists.
    unsafe {
        (*p).base = base;
        (*p).size = SEED_RESERVE_BYTES;
        (*p).available_bytes
            .store(SEED_RESERVE_BYTES, Ordering::Release);
        (*p).header.inc_ref();
    }
}

/// Drain results: per-RAM-block (physical base, size in bytes). The seed
/// block contributes only its post-reserve tail; every other block its
/// full size. `populate_cspace` mints one Frame cap per entry.
///
/// Production path populates this from the buddy drain via
/// [`drain_and_install_seed`]; the test path passes an empty slice and
/// `populate_cspace`'s test-only branch mints from `mmap` directly.
pub(crate) type RamBlock = (u64, u64);

/// Maximum number of buddy blocks `drain_and_install_seed` collects. Each
/// order can have at most `POOL_SIZE` entries; in practice far fewer.
#[cfg(not(test))]
pub(crate) const MAX_DRAIN_BLOCKS: usize = 4096;

/// Backing storage for the buddy drain in [`drain_and_install_seed`] and
/// the per-block (base, size) results consumed by [`populate_cspace`].
/// Lives in BSS so the kernel never grows the heap during Phase 7. Cost:
/// 4096 × 16 B (`RamBlock`) + 4096 × 16 B (`(u64, usize)` order tuple) ≈ 128 KiB.
#[cfg(not(test))]
static mut DRAIN_ORDER_BUF: [(u64, usize); MAX_DRAIN_BLOCKS] = [(0u64, 0usize); MAX_DRAIN_BLOCKS];

#[cfg(not(test))]
static mut DRAIN_RAM_BLOCKS: [RamBlock; MAX_DRAIN_BLOCKS] = [(0u64, 0u64); MAX_DRAIN_BLOCKS];

/// Pages of the kernel reserve seeded into [`crate::mm::kernel_pt_pool`] at
/// Phase 7. The pool backs only the kernel-side Phase-9 bootstrap maps that
/// build init's (or ktest's) boot address space — ELF segments, stack, and
/// `InitInfo` — via [`crate::mm::address_space::AddressSpace::map_page`].
/// Userspace-driven PT growth (drivers' MMIO, services' scratch) funds its
/// own retype-backed growth pool and never draws here; see
/// [`crate::mm::kernel_pt_pool`].
///
/// Measured Phase-9 consumption is 6 pages (init) / 7 pages (ktest) on both
/// arches; 64 leaves ~9× slack for init-binary growth and VA-layout
/// fragmentation. Undersizing is not silent — the pool returning `None`
/// fatals at the first failed bootstrap map.
#[cfg(not(test))]
pub(crate) const POOL_SEED_PAGES: usize = 64;
/// Pages kept in the buddy for kernel-internal use after Phase 7:
///
/// 1. **Phase 8 idle-thread kernel stacks**: `sched::init` allocates
///    `MAX_CPUS × KERNEL_STACK_PAGES = 64 × 4 = 256` pages worst case (one
///    per CPU at order 2).
/// 2. **Phase 9 `InitInfo` / stack pages**: bounded; ~30 pages.
/// 3. **`dealloc_object` → `free_range` reverse-ledger path** that returns
///    reclaimable Frame caps to the buddy on teardown.
///
/// 384 covers (1) + (2) with ~100 pages of slack; PT growth does not touch
/// the buddy on this path. The post-handoff buddy free count never exceeds
/// this (Phases 8–9 only draw pages out of it), which the Phase-9 boot guard
/// asserts.
#[cfg(not(test))]
pub(crate) const BUDDY_RESIDUE_PAGES: usize = 384;
/// Total fixed reserve carved from the buddy at Phase 7. `64 + 384 = 448`
/// pages ≈ 1.75 MiB. Pages not carved here are minted as userspace RAM Frame
/// caps and route to memmgr's pool, so shrinking this only moves pages from
/// reserve into pool; the all-RAM-accounted identity is unaffected
/// (`kernel_reserved` is computed as the complement at Phase 9).
#[cfg(not(test))]
pub(crate) const KERNEL_RESERVE_PAGES: usize = POOL_SEED_PAGES + BUDDY_RESIDUE_PAGES;

/// Drain user-cap RAM from the buddy and install [`SEED_FRAME`] over the
/// largest drained block, reserving its first [`SEED_RESERVE_BYTES`] for
/// kernel-internal cap-identity storage. Returns the per-block
/// (base, size) records ready for `populate_cspace` to mint Frame caps.
///
/// After the drain completes, seeds [`crate::mm::kernel_pt_pool`] with
/// most of the kernel reserve so the steady-state PT-growth path is
/// cap-backed (sourced from a pool minted out of [`KERNEL_RESERVE_PAGES`])
/// rather than drawing directly from the buddy. A small residue stays in
/// the buddy for the `dealloc_object` → `free_range` reverse path's
/// ledger arithmetic.
///
/// MUST run before any [`mint_phase7_body`] / [`boot_retype_aspace`] /
/// [`boot_retype_cspace`] / `boot_retype_thread_slab` call against the
/// seed, and before any `map_user_page` consumer (the kernel PT pool
/// must be live before Phase 9's init bootstrap maps run).
///
/// # Safety
/// Single-threaded Phase 7. Buddy active.
#[cfg(not(test))]
pub(crate) unsafe fn drain_and_install_seed(out: &mut [RamBlock]) -> usize
{
    use crate::mm::buddy::PAGE_SIZE as BUDDY_PAGE_SIZE;

    debug_assert!(out.len() >= MAX_DRAIN_BLOCKS);

    // SAFETY: single-threaded Phase 7; DRAIN_ORDER_BUF is exclusively
    // used by this call.
    let order_buf: &mut [(u64, usize); MAX_DRAIN_BLOCKS] =
        unsafe { &mut *core::ptr::addr_of_mut!(DRAIN_ORDER_BUF) };
    let block_count = crate::mm::with_frame_allocator(|alloc| {
        alloc.drain_for_usercaps(KERNEL_RESERVE_PAGES, order_buf)
    });

    if block_count == 0
    {
        crate::fatal("Phase 7: no drained RAM blocks to seed Frame caps");
    }

    // Largest block hosts the seed; anything else is exposed verbatim.
    let (seed_idx, _) = order_buf[..block_count]
        .iter()
        .enumerate()
        .max_by_key(|&(_, &(_, order))| order)
        .unwrap_or_else(|| crate::fatal("Phase 7: drain returned only zero-order blocks"));
    let (seed_block_base, seed_block_order) = order_buf[seed_idx];
    let seed_block_size = (BUDDY_PAGE_SIZE << seed_block_order) as u64;
    if seed_block_size <= SEED_RESERVE_BYTES
    {
        crate::fatal("Phase 7: largest drained RAM block too small to host SEED_RESERVE_BYTES");
    }

    // SAFETY: first and only call; single-threaded Phase 7.
    unsafe { install_seed_frame(seed_block_base) };

    let mut drained_pages: usize = 0;
    for (i, &(addr, order)) in order_buf[..block_count].iter().enumerate()
    {
        let block_size = (BUDDY_PAGE_SIZE << order) as u64;
        drained_pages += 1usize << order;
        out[i] = if i == seed_idx
        {
            // Seed-tail: front SEED_RESERVE_BYTES go to the SEED's pool
            // (kernel-internal); the remainder is exposed as a virgin RAM
            // Frame cap.
            (
                seed_block_base + SEED_RESERVE_BYTES,
                seed_block_size - SEED_RESERVE_BYTES,
            )
        }
        else
        {
            (addr, block_size)
        };
    }

    crate::kprintln!(
        "Phase 7: drained {} pages across {} blocks; seed reserve {} KiB",
        drained_pages,
        block_count,
        SEED_RESERVE_BYTES / 1024,
    );

    // Seed the kernel PT-frame pool from the residual buddy carve. This
    // must run before any `map_user_page` consumer (the first is Phase
    // 9's init bootstrap). The pool is the cap-backed source for
    // intermediate page-table frames; the buddy keeps only
    // `BUDDY_RESIDUE_PAGES` for `dealloc_object` → `free_range`
    // ledger arithmetic.
    // SAFETY: single-threaded Phase 7; drain has populated the buddy
    // free list with up to KERNEL_RESERVE_PAGES; kernel_pt_pool::init
    // takes its own LOCK internally.
    unsafe {
        crate::mm::kernel_pt_pool::init(POOL_SEED_PAGES);
    }
    let pool_remaining = crate::mm::kernel_pt_pool::remaining_pages();
    crate::kprintln!(
        "kernel_pt_pool: {} pages installed (buddy residue {})",
        pool_remaining,
        BUDDY_RESIDUE_PAGES,
    );

    block_count
}

/// Boot-time helper: retype an `init_pages`-page slab from `seed` and
/// in-place construct a new `AddressSpace` and `AddressSpaceObject` in
/// page 0, with the root PT in page 1 and the remainder seeding the PT
/// growth pool. Returns `(wrapper_header, address_space)` — the wrapper
/// header is suitable for [`insert_or_fatal`] / direct cap insertion;
/// the AS pointer is what TCBs store as `tcb.address_space`.
///
/// Mirrors `sys_cap_create_aspace` create-mode but skips the syscall
/// boilerplate (no caller validation, no augment-mode); used by Phase 9
/// for init's bootstrap AS.
///
/// `init_pages` MUST be `>= 2`. Calls [`crate::fatal`] on retype-allocator
/// or chunk-slot exhaustion (boot cannot recover).
#[cfg(not(test))]
#[allow(clippy::missing_safety_doc)]
pub(crate) unsafe fn boot_retype_aspace(
    seed: &object::FrameObject,
    init_pages: u64,
) -> (
    NonNull<object::KernelObjectHeader>,
    *mut crate::mm::address_space::AddressSpace,
)
{
    use crate::cap::object::{
        AddressSpaceObject, KernelObjectHeader, ObjectType, vacant_chunk_slots,
    };
    use crate::mm::PAGE_SIZE;
    use crate::mm::address_space::AddressSpace;
    use crate::mm::paging::phys_to_virt;
    use core::sync::atomic::AtomicU64;

    debug_assert!(init_pages >= 2);

    let bytes = init_pages * PAGE_SIZE as u64;
    let Ok(offset) = retype::retype_allocate(seed, bytes)
    else
    {
        crate::fatal("boot_retype_aspace: seed Frame too small");
    };
    let frame_base = seed.base;
    let wrapper_phys = frame_base + offset;
    let root_pt_phys = wrapper_phys + PAGE_SIZE as u64;
    let wrapper_virt = phys_to_virt(wrapper_phys) as *mut u8;

    // cast_ptr_alignment: wrapper_virt is page-aligned (4096), the wrapper
    // struct's alignment is at most 8.
    #[allow(clippy::cast_ptr_alignment)]
    let aso_ptr = wrapper_virt.cast::<AddressSpaceObject>();
    let as_offset = core::mem::size_of::<AddressSpaceObject>();
    debug_assert_eq!(as_offset % core::mem::align_of::<AddressSpace>(), 0);
    debug_assert!(as_offset + core::mem::size_of::<AddressSpace>() <= PAGE_SIZE);
    // cast_ptr_alignment: as_offset is a multiple of align_of::<AddressSpace>()
    // (asserted above) and wrapper_virt is page-aligned.
    // similar_names: aso_ptr / aspace_ptr both name pointers in the same
    // wrapper page; the disambiguating prefixes (`aso` vs `aspace`) are
    // intentional to mirror the wrapper-vs-body roles.
    #[allow(clippy::cast_ptr_alignment, clippy::similar_names)]
    // SAFETY: wrapper_virt page-aligned; as_offset stays inside page 0.
    let aspace_ptr = unsafe { wrapper_virt.add(as_offset) }.cast::<AddressSpace>();

    // SAFETY: root_pt_phys is freshly retyped, exclusively owned, page-aligned.
    let aspace = unsafe { AddressSpace::new_user_with_root(root_pt_phys) };
    // SAFETY: aspace_ptr lives in the wrapper page, exclusively owned.
    unsafe { core::ptr::write(aspace_ptr, aspace) };

    // SAFETY: aso_ptr is page-aligned and exclusively owned.
    unsafe {
        core::ptr::write(
            aso_ptr,
            AddressSpaceObject {
                header: KernelObjectHeader::with_ancestor(
                    ObjectType::AddressSpace,
                    seed_header_nn(),
                ),
                address_space: aspace_ptr,
                pt_growth_budget_bytes: AtomicU64::new(0),
                pt_pool_lock: AtomicU64::new(0),
                pt_pool_head_phys: AtomicU64::new(0),
                pt_chunks: vacant_chunk_slots(),
            },
        );
    }

    seed.header.inc_ref();

    let pool_pages = init_pages - 2;
    // SAFETY: aso_ptr just constructed; offset/init_pages from a successful retype.
    let res = unsafe {
        (*aso_ptr).add_chunk(seed_header_nn(), frame_base, offset, init_pages, pool_pages)
    };
    if res.is_err()
    {
        crate::fatal("boot_retype_aspace: chunk slot exhausted");
    }

    // SAFETY: aso_ptr is in-place; header at offset 0.
    let nonnull = unsafe { NonNull::new_unchecked(aso_ptr.cast::<KernelObjectHeader>()) };
    (nonnull, aspace_ptr)
}

/// Boot-time helper: retype an `init_pages`-page slab from `seed` and
/// in-place construct a new `CSpace` and `CSpaceKernelObject` in page 0,
/// with pages `1..init_pages` seeding the slot-page pool. Returns
/// `(wrapper_header, cspace)`.
///
/// Mirrors `sys_cap_create_cspace` create-mode; used by
/// [`init_capability_system`] for the root `CSpace`.
///
/// `init_pages` MUST be `>= 1`. Calls [`crate::fatal`] on retype-allocator
/// or chunk-slot exhaustion.
#[cfg(not(test))]
#[allow(clippy::missing_safety_doc)]
pub(crate) unsafe fn boot_retype_cspace(
    seed: &object::FrameObject,
    init_pages: u64,
    max_slots: usize,
    id: CSpaceId,
) -> (NonNull<object::KernelObjectHeader>, *mut cspace::CSpace)
{
    use crate::cap::cspace::CSpace;
    use crate::cap::object::{
        CSpaceKernelObject, KernelObjectHeader, ObjectType, vacant_chunk_slots,
    };
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::phys_to_virt;
    use core::sync::atomic::AtomicU64;

    debug_assert!(init_pages >= 1);

    let bytes = init_pages * PAGE_SIZE as u64;
    let Ok(offset) = retype::retype_allocate(seed, bytes)
    else
    {
        crate::fatal("boot_retype_cspace: seed Frame too small");
    };
    let frame_base = seed.base;
    let wrapper_phys = frame_base + offset;
    let wrapper_virt = phys_to_virt(wrapper_phys) as *mut u8;

    // cast_ptr_alignment: wrapper_virt is page-aligned (4096), the wrapper
    // struct's alignment is at most 8.
    #[allow(clippy::cast_ptr_alignment)]
    let cs_kobj_ptr = wrapper_virt.cast::<CSpaceKernelObject>();
    let cs_offset = core::mem::size_of::<CSpaceKernelObject>();
    debug_assert_eq!(cs_offset % core::mem::align_of::<CSpace>(), 0);
    debug_assert!(cs_offset + core::mem::size_of::<CSpace>() <= PAGE_SIZE);
    // cast_ptr_alignment: cs_offset is a multiple of align_of::<CSpace>()
    // (asserted above) and wrapper_virt is page-aligned.
    #[allow(clippy::cast_ptr_alignment)]
    // SAFETY: wrapper_virt page-aligned; cs_offset stays inside page 0.
    let cs_ptr = unsafe { wrapper_virt.add(cs_offset) }.cast::<CSpace>();

    // SAFETY: cs_ptr lives in the wrapper page, exclusively owned.
    unsafe { core::ptr::write(cs_ptr, CSpace::new(id, max_slots)) };

    // SAFETY: cs_kobj_ptr is page-aligned and exclusively owned.
    unsafe {
        core::ptr::write(
            cs_kobj_ptr,
            CSpaceKernelObject {
                header: KernelObjectHeader::with_ancestor(ObjectType::CSpaceObj, seed_header_nn()),
                cspace: cs_ptr,
                cspace_growth_budget_bytes: AtomicU64::new(0),
                cs_pool_lock: AtomicU64::new(0),
                cs_pool_head_phys: AtomicU64::new(0),
                cs_chunks: vacant_chunk_slots(),
            },
        );
    }
    // The root CSpace is pinned for kernel lifetime: marking it here makes
    // `dec_ref` clamp at 1, so any upstream refcount mismanagement of the
    // wrapper / self-cap pair cannot route it through `dealloc_object`.
    // SAFETY: header just written, exclusively owned, single-threaded boot.
    unsafe { (*cs_kobj_ptr).header.flags |= crate::cap::object::HDR_FLAG_IS_ROOT };

    // SAFETY: cs_ptr just constructed.
    unsafe { (*cs_ptr).set_kobj(cs_kobj_ptr) };
    seed.header.inc_ref();

    let pool_pages = init_pages - 1;
    // SAFETY: wrapper just constructed; offset/init_pages from a successful retype.
    let res = unsafe {
        (*cs_kobj_ptr).add_chunk(seed_header_nn(), frame_base, offset, init_pages, pool_pages)
    };
    if res.is_err()
    {
        crate::fatal("boot_retype_cspace: chunk slot exhausted");
    }

    // SAFETY: cs_kobj_ptr is in-place; header at offset 0.
    let nonnull = unsafe { NonNull::new_unchecked(cs_kobj_ptr.cast::<KernelObjectHeader>()) };
    (nonnull, cs_ptr)
}

/// Phase-7 mint helper: in production, retype `body` in place inside the
/// seed Frame cap and bump the seed's refcount; in tests, leak `body` via
/// `Box`. Returns a `NonNull<KernelObjectHeader>` suitable for
/// [`insert_or_fatal`].
///
/// `T` MUST be `#[repr(C)]` with [`object::KernelObjectHeader`] as its
/// first field; callers stamp `header.ancestor` via
/// [`object::KernelObjectHeader::with_ancestor`] using [`seed_header_nn`]
/// so the dealloc cascade can reclaim the body's storage to the seed.
pub(crate) fn mint_phase7_body<T>(body: T) -> NonNull<object::KernelObjectHeader>
{
    #[cfg(not(test))]
    {
        crate::cap::retype::boot_retype_body(seed_frame_ref(), body)
    }
    #[cfg(test)]
    {
        nonnull_from_box(Box::new(body))
    }
}

// ── Phase 7 entry point ───────────────────────────────────────────────────────

// ── CSpace layout ────────────────────────────────────────────────────────────

/// Describes the `CSpace` slot layout after Phase 7 population.
///
/// Returned by [`init_capability_system`] so Phase 9 can populate the
/// [`InitInfo`](init_protocol::InitInfo) page without re-scanning the `CSpace`.
pub struct CSpaceLayout
{
    /// First slot index of usable memory `Frame` capabilities.
    pub memory_frame_base: u32,
    /// Number of usable memory `Frame` capabilities.
    pub memory_frame_count: u32,
    /// First slot index of hardware resource capabilities (MMIO, IRQ, I/O port, firmware tables).
    pub hw_cap_base: u32,
    /// Number of hardware resource capabilities.
    pub hw_cap_count: u32,
    /// Slot index of the `SchedControl` capability.
    pub sched_control_slot: u32,
    /// Slot index of the `SbiControl` capability (RISC-V only; 0 on x86-64).
    pub sbi_control_slot: u32,
    /// Slot index of the root `Interrupt` range capability. Zero if no
    /// valid range could be determined at boot.
    pub irq_range_slot: u32,
    /// Slot index of the RO `Frame` cap covering the ACPI RSDP page.
    /// Zero if `BootInfo.acpi_rsdp` is zero.
    pub acpi_rsdp_frame_slot: u32,
    /// First slot index of the RO `Frame` caps covering the
    /// `AcpiReclaimable` regions from the boot memory map.
    pub acpi_region_frame_base: u32,
    /// Number of ACPI reclaimable-region `Frame` caps.
    pub acpi_region_frame_count: u32,
    /// Slot index of the RO `Frame` cap covering the DTB blob.
    /// Zero if `BootInfo.device_tree` is zero.
    pub dtb_frame_slot: u32,
    /// Total number of populated slots.
    pub total_populated: usize,
    /// Number of valid entries in the global [`CSPACE_LAYOUT_DESCRIPTORS`]
    /// buffer for this layout. Use [`descriptors`] to obtain the slice.
    pub descriptor_count: usize,
    /// Number of populated [`InitModuleName`] entries in
    /// [`Self::module_names`]. Capped at
    /// [`init_protocol::INIT_MAX_NAMED_MODULES`].
    pub module_name_count: u32,
    /// Module-name → cap-slot table mirroring
    /// [`init_protocol::InitInfo::module_names`]. Populated by
    /// `mint_module_frame_caps` and written verbatim into the
    /// `InitInfo` header by Phase 9.
    pub module_names: [init_protocol::InitModuleName; init_protocol::INIT_MAX_NAMED_MODULES],
}

/// Capacity of the [`CSPACE_LAYOUT_DESCRIPTORS`] backing buffer. Bounded
/// by every cap kind minted at boot:
/// - [`MAX_DRAIN_BLOCKS`] RAM Frame caps (worst case from the buddy drain).
/// - ~32 hardware caps (MMIO + IRQ + `IoPortRange`/`SbiControl` + `SchedControl`).
/// - 8 ACPI region caps (`MAX_ACPI_REGIONS`), 1 ACPI RSDP, 1 DTB.
/// - ~8 init segment caps + ~16 boot module caps.
/// - [`boot_protocol::MAX_RECLAIM_RANGES`] reclaim Frame caps (worst case
///   from `mint_reclaim_frame_caps`).
///
/// `4096 + 256 + 128 = 4480` covers the worst case with headroom; BSS
/// cost is 4480 × 24 B ≈ 105 KiB, comfortably small relative to total
/// system RAM. The `4096` term matches `MAX_DRAIN_BLOCKS` in the
/// production-only branch; `256` is `boot_protocol::MAX_RECLAIM_RANGES`;
/// the trailing `128` covers every other Phase-7 cap kind.
pub const CSPACE_LAYOUT_MAX_DESCRIPTORS: usize = 4096 + boot_protocol::MAX_RECLAIM_RANGES + 128;

/// Backing storage for [`CSpaceLayout::descriptor_count`]. `static mut`
/// because [`populate_cspace`] writes entries during single-threaded
/// Phase 7, and Phase 9 reads them as `&[CapDescriptor]` to build the
/// `InitInfo` page. After hand-off init owns its `InitInfo` copy and
/// the kernel never re-reads this buffer.
#[cfg(not(test))]
pub static mut CSPACE_LAYOUT_DESCRIPTORS: [CapDescriptor; CSPACE_LAYOUT_MAX_DESCRIPTORS] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const VACANT: CapDescriptor = CapDescriptor {
        slot: 0,
        cap_type: init_protocol::CapType::Frame,
        pad: [0; 3],
        aux0: 0,
        aux1: 0,
    };
    [VACANT; CSPACE_LAYOUT_MAX_DESCRIPTORS]
};

/// Test-build duplicate so test code can reference the symbol unconditionally.
#[cfg(test)]
pub static mut CSPACE_LAYOUT_DESCRIPTORS: [CapDescriptor; CSPACE_LAYOUT_MAX_DESCRIPTORS] =
    [CapDescriptor {
        slot: 0,
        cap_type: init_protocol::CapType::Frame,
        pad: [0; 3],
        aux0: 0,
        aux1: 0,
    }; CSPACE_LAYOUT_MAX_DESCRIPTORS];

/// Borrow the descriptor slice for the supplied [`CSpaceLayout`].
///
/// Returns the first `layout.descriptor_count` entries of the global
/// [`CSPACE_LAYOUT_DESCRIPTORS`] buffer.
///
/// # Safety
/// `layout.descriptor_count` must reflect the entries written by the
/// `populate_cspace`, `mint_module_frame_caps`, and
/// `mint_reclaim_frame_caps` writers that produced `layout`.
/// Single-threaded boot guarantees no concurrent writer.
#[allow(clippy::missing_safety_doc)]
pub unsafe fn descriptors(layout: &CSpaceLayout) -> &'static [CapDescriptor]
{
    debug_assert!(layout.descriptor_count <= CSPACE_LAYOUT_MAX_DESCRIPTORS);
    // SAFETY: see function-level doc; single-threaded boot read of
    // CSPACE_LAYOUT_DESCRIPTORS, no writer can race. The intermediate
    // shared reference to the static array is taken explicitly to satisfy
    // the `dangerous_implicit_autorefs` lint.
    let p = core::ptr::addr_of!(CSPACE_LAYOUT_DESCRIPTORS);
    // SAFETY: `p` is the address of a valid 'static array; single-threaded
    // boot read with no concurrent writer.
    let arr_ref: &[CapDescriptor; CSPACE_LAYOUT_MAX_DESCRIPTORS] = unsafe { &*p };
    &arr_ref[..layout.descriptor_count]
}

/// Running total of `owns_memory = true` `Frame` cap bytes minted into
/// init's root `CSpace`. These pages are the reclaimable complement of the
/// fixed kernel reserve; `kernel_reserved_bytes = system_ram - this`.
/// Single-threaded boot, so a relaxed atomic suffices.
static OWNS_MEMORY_MINTED_BYTES: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Record `bytes` of a newly-minted `owns_memory` `Frame` cap toward the
/// minted-to-init ledger. Called at every Phase-7/Phase-9 mint site.
pub(crate) fn note_owns_memory_minted(bytes: u64)
{
    OWNS_MEMORY_MINTED_BYTES.fetch_add(bytes, core::sync::atomic::Ordering::Relaxed);
}

/// Total `owns_memory` `Frame` cap bytes minted to init.
#[must_use]
pub(crate) fn owns_memory_minted_bytes() -> u64
{
    OWNS_MEMORY_MINTED_BYTES.load(core::sync::atomic::Ordering::Relaxed)
}

/// Append a `CapDescriptor` to the global buffer and bump `descriptor_count`.
/// Calls [`crate::fatal`] if the buffer is full.
fn push_descriptor(count: &mut usize, desc: CapDescriptor)
{
    if *count >= CSPACE_LAYOUT_MAX_DESCRIPTORS
    {
        crate::fatal("cap: CSPACE_LAYOUT_DESCRIPTORS buffer exhausted");
    }
    // SAFETY: single-threaded boot; `count` is the only writer index.
    unsafe {
        let p = core::ptr::addr_of_mut!(CSPACE_LAYOUT_DESCRIPTORS);
        (*p)[*count] = desc;
    }
    *count += 1;
}

/// Initialise the capability system and populate the root `CSpace.`
///
/// `mmio_apertures` is the validated aperture list from Phase 6.
/// `boot_info_phys` is the physical address of the [`BootInfo`] structure;
/// re-derived here via the direct physical map (active since Phase 3) to
/// access the memory map.
///
/// Returns a [`CSpaceLayout`] describing the slot ranges populated. Calls
/// [`crate::fatal`] on any allocation failure.
///
/// # Safety
///
/// Must be called exactly once, single-threaded, after Phase 4 (heap active)
/// and Phase 3 (direct map active).
pub fn init_capability_system(mmio_apertures: &[MmioAperture], boot_info_phys: u64)
-> CSpaceLayout
{
    // Re-derive BootInfo via the direct physical map to access the memory map.
    // SAFETY: boot_info_phys was validated in Phase 0; direct map active since Phase 3.
    let info: &BootInfo = unsafe { &*(phys_to_virt(boot_info_phys) as *const BootInfo) };

    // Build memory map slice.
    let mmap: &[MemoryMapEntry] = if info.memory_map.count == 0 || info.memory_map.entries.is_null()
    {
        &[]
    }
    else
    {
        // SAFETY: Phase 0 confirmed memory_map is valid; direct map active.
        unsafe {
            core::slice::from_raw_parts(
                phys_to_virt(info.memory_map.entries as u64) as *const MemoryMapEntry,
                info.memory_map.count as usize,
            )
        }
    };

    // ── Production path ───────────────────────────────────────────────────
    // 1. Drain the buddy + install SEED_FRAME (largest block hosts the seed
    //    reserve; remainder exposed as the seed-tail cap).
    // 2. Boot-retype the root CSpace from SEED into a typed-memory slab.
    // 3. populate_cspace fills the root with Frame caps (from the drained
    //    blocks) plus all hardware-resource caps.
    // 4. mint_module_frame_caps appends boot-module Frame caps.
    // 5. mint_reclaim_frame_caps appends reclaimable bootloader-scratch
    //    Frame caps (BootInfo, descriptor arrays, transient PT frames).
    // 6. Stash the root CSpace pointer; Phase 9 hands it to init.
    #[cfg(not(test))]
    {
        // SAFETY: single-threaded Phase 7; DRAIN_RAM_BLOCKS is exclusively
        // used by this call.
        let ram_buf: &mut [RamBlock; MAX_DRAIN_BLOCKS] =
            unsafe { &mut *core::ptr::addr_of_mut!(DRAIN_RAM_BLOCKS) };
        // SAFETY: first call; single-threaded Phase 7.
        let block_count = unsafe { drain_and_install_seed(ram_buf) };
        let ram_blocks: &[RamBlock] = &ram_buf[..block_count];

        let id = alloc_cspace_id()
            .unwrap_or_else(|| crate::fatal("root CSpace: alloc_cspace_id exhausted at boot"));
        debug_assert_eq!(
            id, 0,
            "root CSpace must receive id 0 (free list empty at boot)"
        );
        // SAFETY: SEED installed above.
        let (_cs_kobj_nn, cs_ptr) = unsafe {
            boot_retype_cspace(
                seed_frame_ref(),
                ROOT_CSPACE_INIT_PAGES,
                ROOT_CSPACE_MAX_SLOTS,
                id,
            )
        };
        // The root CSpace's epoch is fixed at 1 (initial registry value) and
        // never bumps — it's never recycled (asserted in `free_cspace_id`),
        // so we discard the returned value.
        let _root_epoch = register_cspace(id, cs_ptr)
            .unwrap_or_else(|()| crate::fatal("root CSpace register: id exceeds MAX_CSPACES"));

        // SAFETY: cs_ptr is freshly constructed and exclusively owned
        // (single-threaded Phase 7).
        let cspace = unsafe { &mut *cs_ptr };
        let mut layout = populate_cspace(cspace, ram_blocks, mmap, mmio_apertures, info);
        mint_module_frame_caps(cspace, info, &mut layout);
        mint_reclaim_frame_caps(cspace, info, &mut layout);

        // SAFETY: single-threaded boot; ROOT_CSPACE not yet observed.
        unsafe { ROOT_CSPACE = cs_ptr };

        layout
    }

    // ── Test path ─────────────────────────────────────────────────────────
    // Tests don't exercise the SEED / boot-retype machinery (no buddy, no
    // direct map, no FrameObject lifecycle in the test stub). They allocate
    // a heap-backed CSpace and let `populate_cspace`'s test-only RAM-mint
    // branch iterate `mmap` directly — `ram_blocks` is empty.
    #[cfg(test)]
    {
        let id = alloc_cspace_id().expect("root CSpace: alloc_cspace_id exhausted at boot");
        let mut cspace = Box::new(CSpace::new(id, ROOT_CSPACE_MAX_SLOTS));
        let empty: [RamBlock; 0] = [];
        let mut layout = populate_cspace(&mut cspace, &empty, mmap, mmio_apertures, info);
        mint_module_frame_caps(&mut cspace, info, &mut layout);
        mint_reclaim_frame_caps(&mut cspace, info, &mut layout);
        // Tests intentionally leak the box; isolated unit-test invariants
        // (every kernel object Boxed via `nonnull_from_box`) make explicit
        // teardown unnecessary.
        let _ = cspace;
        layout
    }
}

/// Core `CSpace` population logic, separated for testability.
///
/// Creates one capability per usable memory region, one `MmioRegion`
/// capability per MMIO aperture, and one `SchedControl` capability (plus
/// the arch-specific root `IoPortRange` on x86-64 and `SbiControl` on
/// RISC-V). Returns a [`CSpaceLayout`] describing the slot ranges and
/// per-cap descriptors.
// too_many_lines: one logical pass over all boot-time resource types; splitting
// would require threading shared state (cspace) through multiple helper functions.
#[allow(clippy::too_many_lines)]
fn populate_cspace(
    cspace: &mut CSpace,
    ram_blocks: &[RamBlock],
    mmap: &[MemoryMapEntry],
    mmio_apertures: &[MmioAperture],
    info: &BootInfo,
) -> CSpaceLayout
{
    use init_protocol::CapType;

    /// Width of the root `Interrupt` range cap minted at Phase 7.
    /// x86-64 IOAPICs cover GSI 0..256; RISC-V PLIC spec max is 1024
    /// sources. Sized at the per-arch spec max — arch helpers reject
    /// out-of-range ids, so oversizing is safe.
    #[cfg(target_arch = "x86_64")]
    const ROOT_IRQ_COUNT: u32 = 256;
    #[cfg(target_arch = "riscv64")]
    const ROOT_IRQ_COUNT: u32 = 1024;

    /// Maximum number of `AcpiReclaimable` regions to mint caps for.
    /// Real firmware reports 1–2; the cap guards against pathological
    /// memory maps exhausting the `CSpace`.
    const MAX_ACPI_REGIONS: usize = 8;

    // Descriptor entries land in the global CSPACE_LAYOUT_DESCRIPTORS
    // buffer; this counter tracks how many have been written.
    let mut desc_count: usize = 0;

    // Usable physical memory → Frame caps with MAP | WRITE | EXECUTE.
    // Init is root authority; it holds the full right set for each frame.
    // W^X is enforced at mapping time — no page can be simultaneously
    // writable and executable — but the cap carries both rights so init
    // can derive attenuated sub-caps (MAP|WRITE for data, MAP|EXECUTE
    // for code) when loading processes.
    //
    // Frame caps are allocated FROM the buddy allocator so the same
    // physical pages are not double-booked between the kernel's internal
    // frame pool and userspace capabilities.
    // Initialised to 0 so the test build (which uses an `if count == 0`
    // guard inside its mmap loop to capture the first slot) compiles; the
    // production build overwrites both before any read.
    #[allow(unused_assignments)]
    let mut memory_frame_base: u32 = 0;
    #[allow(unused_assignments)]
    let mut memory_frame_count: u32 = 0;

    #[cfg(not(test))]
    {
        let seed_anc = seed_header_nn();

        // Mint one Frame cap per drained RAM block. `ram_blocks` is the
        // already-resolved (base, size) list from `drain_and_install_seed`:
        // the seed block contributes only its post-reserve tail; every
        // other block contributes its full size. SEED itself is never
        // inserted into the CSpace — it's pure kernel-internal storage.
        for &(cap_base, cap_size) in ram_blocks
        {
            let ptr = mint_phase7_body(FrameObject {
                header: KernelObjectHeader::with_ancestor(ObjectType::Frame, seed_anc),
                base: cap_base,
                size: cap_size,
                // Full retypable budget: this cap covers virgin RAM. The
                // seed's ledger only debits for the FrameObject body bytes.
                available_bytes: core::sync::atomic::AtomicU64::new(cap_size),
                // Buddy-backed: responsible for freeing its (disjoint) range
                // on final destruction. The seed's own SEED_RESERVE_BYTES
                // prefix is owned by the pinned SEED_FRAME and never returns
                // to the buddy.
                owns_memory: core::sync::atomic::AtomicBool::new(true),
                allocator: crate::cap::retype::RetypeAllocator::new_inline(),
                lock: core::sync::atomic::AtomicU32::new(0),
            });
            let slot = insert_or_fatal(
                cspace,
                CapTag::Frame,
                Rights::MAP | Rights::WRITE | Rights::EXECUTE | Rights::RETYPE,
                ptr,
                "Phase 7: cannot allocate Frame capability for usable memory",
            );
            if memory_frame_count == 0
            {
                memory_frame_base = slot;
            }
            push_descriptor(
                &mut desc_count,
                CapDescriptor {
                    slot,
                    cap_type: CapType::Frame,
                    pad: [0; 3],
                    aux0: cap_base,
                    aux1: cap_size,
                },
            );
            note_owns_memory_minted(cap_size);
            memory_frame_count += 1;
        }

        crate::kprintln!(
            "Phase 7: {} Frame caps minted from {} drained RAM blocks",
            memory_frame_count,
            ram_blocks.len(),
        );
    }
    #[cfg(test)]
    let _ = ram_blocks;

    // Test builds: create Frame caps directly from mmap entries (no buddy).
    #[cfg(test)]
    for entry in mmap
    {
        if entry.memory_type != MemoryType::Usable
        {
            continue;
        }
        // FrameObject invariant: page-aligned base, whole-page size.
        let aligned_base = entry.physical_base & !0xFFF_u64;
        let aligned_size = (entry.physical_base - aligned_base + entry.size + 0xFFF) & !0xFFF_u64;
        let obj = Box::new(FrameObject {
            header: KernelObjectHeader::new(ObjectType::Frame),
            base: aligned_base,
            size: aligned_size,
            // RAM cap: full retypable budget mirrors the production path.
            available_bytes: core::sync::atomic::AtomicU64::new(aligned_size),
            // Test stub: buddy not active; leaking on destruction is the
            // expected unit-test behaviour.
            owns_memory: core::sync::atomic::AtomicBool::new(false),
            allocator: crate::cap::retype::RetypeAllocator::new_inline(),
            lock: core::sync::atomic::AtomicU32::new(0),
        });
        let ptr = nonnull_from_box(obj);
        let slot = insert_or_fatal(
            cspace,
            CapTag::Frame,
            Rights::MAP | Rights::WRITE | Rights::EXECUTE | Rights::RETYPE,
            ptr,
            "Phase 7: cannot allocate Frame capability for usable memory",
        );
        if memory_frame_count == 0
        {
            memory_frame_base = slot;
        }
        push_descriptor(
            &mut desc_count,
            CapDescriptor {
                slot,
                cap_type: CapType::Frame,
                pad: [0; 3],
                aux0: aligned_base,
                aux1: aligned_size,
            },
        );
        memory_frame_count += 1;
    }

    // MMIO apertures → one MmioRegion cap each, MAP | WRITE. Init is root
    // authority and holds these coarse caps until userspace narrows them
    // (via `mmio_split`) and delegates device-sized sub-caps to drivers.
    //
    // On RISC-V the kernel's UART MMIO range is advertised via
    // `BootInfo.kernel_mmio.uart_base` rather than the coarse aperture
    // list (the ns16550 UART sits outside both the PLIC aperture and the
    // PCIe apertures on every supported platform). Synthesise an extra
    // MmioRegion cap here so userspace init has a cap for it — init's
    // serial scan looks for any aperture containing the resolved UART base.
    let mut hw_cap_base: u32 = 0;
    let mut hw_cap_count: u32 = 0;

    #[cfg(target_arch = "riscv64")]
    {
        let uart_base = crate::arch::current::platform::uart_base();
        let uart_size = crate::arch::current::platform::uart_size();
        let ptr = mint_phase7_body(MmioRegionObject {
            header: KernelObjectHeader::with_ancestor(ObjectType::MmioRegion, seed_header_nn()),
            base: uart_base,
            size: uart_size,
            flags: 0,
            _pad: 0,
        });
        let slot = insert_or_fatal(
            cspace,
            CapTag::MmioRegion,
            Rights::MAP | Rights::WRITE,
            ptr,
            "Phase 7: cannot allocate MmioRegion capability for console UART",
        );
        if hw_cap_count == 0
        {
            hw_cap_base = slot;
        }
        hw_cap_count += 1;
        push_descriptor(
            &mut desc_count,
            CapDescriptor {
                slot,
                cap_type: CapType::MmioRegion,
                pad: [0; 3],
                aux0: uart_base,
                aux1: uart_size,
            },
        );
    }

    for ap in mmio_apertures
    {
        let ptr = mint_phase7_body(MmioRegionObject {
            header: KernelObjectHeader::with_ancestor(ObjectType::MmioRegion, seed_header_nn()),
            base: ap.phys_base,
            size: ap.size,
            flags: 0,
            _pad: 0,
        });
        let slot = insert_or_fatal(
            cspace,
            CapTag::MmioRegion,
            Rights::MAP | Rights::WRITE,
            ptr,
            "Phase 7: cannot allocate MmioRegion capability for aperture",
        );
        if hw_cap_count == 0
        {
            hw_cap_base = slot;
        }
        push_descriptor(
            &mut desc_count,
            CapDescriptor {
                slot,
                cap_type: CapType::MmioRegion,
                pad: [0; 3],
                aux0: ap.phys_base,
                aux1: ap.size,
            },
        );
        hw_cap_count += 1;
    }

    // One SchedControl capability — grants elevated scheduling authority.
    let ptr = mint_phase7_body(SchedControlObject {
        header: KernelObjectHeader::with_ancestor(ObjectType::SchedControl, seed_header_nn()),
    });
    let sched_control_slot = insert_or_fatal(
        cspace,
        CapTag::SchedControl,
        Rights::ELEVATE,
        ptr,
        "Phase 7: cannot allocate SchedControl capability",
    );
    push_descriptor(
        &mut desc_count,
        CapDescriptor {
            slot: sched_control_slot,
            cap_type: CapType::SchedControl,
            pad: [0; 3],
            aux0: 0,
            aux1: 0,
        },
    );

    // Root Interrupt range capability — covers every valid IRQ source on
    // this arch. Userspace narrows it to single-IRQ children via
    // `SYS_IRQ_SPLIT` and delegates one per device.
    //
    // x86-64: 256 GSI lines covers every IOAPIC pin in the currently
    // targeted systems. RISC-V: 1024 PLIC sources is the spec maximum;
    // most platforms expose far fewer (e.g. 128). Sizing the root at the
    // spec max is safe because `plic_enable` rejects out-of-range ids.
    let irq_ptr = mint_phase7_body(InterruptObject {
        header: KernelObjectHeader::with_ancestor(ObjectType::Interrupt, seed_header_nn()),
        start: 0,
        count: ROOT_IRQ_COUNT,
    });
    let irq_range_slot = insert_or_fatal(
        cspace,
        CapTag::Interrupt,
        Rights::SIGNAL,
        irq_ptr,
        "Phase 7: cannot allocate root Interrupt range capability",
    );
    push_descriptor(
        &mut desc_count,
        CapDescriptor {
            slot: irq_range_slot,
            cap_type: CapType::Interrupt,
            pad: [0; 3],
            aux0: 0,
            aux1: u64::from(ROOT_IRQ_COUNT),
        },
    );

    // Read-only Frame caps covering each AcpiReclaimable region. userspace
    // parses XSDT / MADT / MCFG through these. Capped by `MAX_ACPI_REGIONS`
    // so a pathological firmware cannot exhaust the CSpace here.
    let mut acpi_region_frame_base: u32 = 0;
    let mut acpi_region_frame_count: u32 = 0;
    for entry in mmap
    {
        if entry.memory_type != MemoryType::AcpiReclaimable
        {
            continue;
        }
        if (acpi_region_frame_count as usize) >= MAX_ACPI_REGIONS
        {
            #[cfg(not(test))]
            crate::kprintln!(
                "Phase 7: AcpiReclaimable region count exceeds {}; truncating",
                MAX_ACPI_REGIONS
            );
            break;
        }
        // UEFI memory map entries are page-aligned per UEFI spec §7.2,
        // but mask defensively to uphold FrameObject's alignment invariant.
        let aligned_base = entry.physical_base & !0xFFF;
        let size = (entry.physical_base - aligned_base + entry.size + 0xFFF) & !0xFFF;
        if size == 0
        {
            continue;
        }
        let ptr = mint_phase7_body(FrameObject {
            header: KernelObjectHeader::with_ancestor(ObjectType::Frame, seed_header_nn()),
            base: aligned_base,
            size,
            // Firmware table: not retypable; cap minted without RETYPE.
            available_bytes: core::sync::atomic::AtomicU64::new(0),
            // Firmware-reserved memory; not buddy-backed.
            owns_memory: core::sync::atomic::AtomicBool::new(false),
            allocator: crate::cap::retype::RetypeAllocator::new_inline(),
            lock: core::sync::atomic::AtomicU32::new(0),
        });
        let slot = insert_or_fatal(
            cspace,
            CapTag::Frame,
            Rights::MAP | Rights::READ,
            ptr,
            "Phase 7: cannot allocate Frame capability for ACPI region",
        );
        if acpi_region_frame_count == 0
        {
            acpi_region_frame_base = slot;
        }
        push_descriptor(
            &mut desc_count,
            CapDescriptor {
                slot,
                cap_type: CapType::Frame,
                pad: [0; 3],
                aux0: aligned_base,
                aux1: size,
            },
        );
        acpi_region_frame_count += 1;
    }

    // RO Frame cap over the single 4 KiB page containing the ACPI RSDP.
    // RSDP commonly sits in firmware-reserved memory outside
    // `AcpiReclaimable`, so it gets its own cap regardless of the region scan.
    //
    // The cap's backing Frame covers the page (aligned base, 4 KiB size),
    // but the descriptor's `aux0` carries the exact RSDP physical address
    // so userspace knows where inside the page to start reading.
    let acpi_rsdp_frame_slot: u32 = if info.acpi_rsdp != 0
    {
        let page_base = info.acpi_rsdp & !0xFFF;
        let ptr = mint_phase7_body(FrameObject {
            header: KernelObjectHeader::with_ancestor(ObjectType::Frame, seed_header_nn()),
            base: page_base,
            size: 0x1000,
            // Firmware table: not retypable; cap minted without RETYPE.
            available_bytes: core::sync::atomic::AtomicU64::new(0),
            owns_memory: core::sync::atomic::AtomicBool::new(false),
            allocator: crate::cap::retype::RetypeAllocator::new_inline(),
            lock: core::sync::atomic::AtomicU32::new(0),
        });
        let slot = insert_or_fatal(
            cspace,
            CapTag::Frame,
            Rights::MAP | Rights::READ,
            ptr,
            "Phase 7: cannot allocate Frame capability for ACPI RSDP page",
        );
        push_descriptor(
            &mut desc_count,
            CapDescriptor {
                slot,
                cap_type: CapType::Frame,
                pad: [0; 3],
                aux0: info.acpi_rsdp,
                aux1: 0x1000,
            },
        );
        slot
    }
    else
    {
        0
    };

    // RO Frame cap covering the DTB blob. The kernel read the totalsize
    // header in `mm::init::collect_exclusions` to keep these pages out of
    // the buddy pool; repeat the read here to size the cap.
    let dtb_frame_slot: u32 = if info.device_tree != 0
    {
        let dtb_size = read_dtb_totalsize(info.device_tree).unwrap_or(0);
        if dtb_size != 0
        {
            let rounded = (dtb_size + 0xFFF) & !0xFFF;
            let ptr = mint_phase7_body(FrameObject {
                header: KernelObjectHeader::with_ancestor(ObjectType::Frame, seed_header_nn()),
                base: info.device_tree & !0xFFF,
                size: rounded,
                // Firmware table: not retypable; cap minted without RETYPE.
                available_bytes: core::sync::atomic::AtomicU64::new(0),
                owns_memory: core::sync::atomic::AtomicBool::new(false),
                allocator: crate::cap::retype::RetypeAllocator::new_inline(),
                lock: core::sync::atomic::AtomicU32::new(0),
            });
            let slot = insert_or_fatal(
                cspace,
                CapTag::Frame,
                Rights::MAP | Rights::READ,
                ptr,
                "Phase 7: cannot allocate Frame capability for DTB blob",
            );
            push_descriptor(
                &mut desc_count,
                CapDescriptor {
                    slot,
                    cap_type: CapType::Frame,
                    pad: [0; 3],
                    aux0: info.device_tree & !0xFFF,
                    aux1: rounded,
                },
            );
            slot
        }
        else
        {
            0
        }
    }
    else
    {
        0
    };

    // x86-64: root IoPortRange covering the full 64K I/O port space.
    // This is a static architectural fact, not derived from any bootloader
    // field. Init subdivides and delegates sub-ranges to services as needed.
    #[cfg(target_arch = "x86_64")]
    {
        let ptr = mint_phase7_body(IoPortRangeObject {
            header: KernelObjectHeader::with_ancestor(ObjectType::IoPortRange, seed_header_nn()),
            base: 0,
            size: 0, // 0 means 0x10000 (full range; u16 cannot hold 65536)
            _pad: 0,
        });
        let ioport_root_slot = insert_or_fatal(
            cspace,
            CapTag::IoPortRange,
            Rights::USE,
            ptr,
            "Phase 7: cannot allocate root IoPortRange capability",
        );
        push_descriptor(
            &mut desc_count,
            CapDescriptor {
                slot: ioport_root_slot,
                cap_type: CapType::IoPortRange,
                pad: [0; 3],
                aux0: 0,
                aux1: 0x10000, // full 64K range
            },
        );
    }

    // RISC-V: one SbiControl capability — grants authority to forward SBI calls.
    #[cfg(target_arch = "riscv64")]
    let sbi_control_slot = {
        let ptr = mint_phase7_body(SbiControlObject {
            header: KernelObjectHeader::with_ancestor(ObjectType::SbiControl, seed_header_nn()),
        });
        let slot = insert_or_fatal(
            cspace,
            CapTag::SbiControl,
            Rights::CALL,
            ptr,
            "Phase 7: cannot allocate SbiControl capability",
        );
        push_descriptor(
            &mut desc_count,
            CapDescriptor {
                slot,
                cap_type: CapType::SbiControl,
                pad: [0; 3],
                aux0: 0,
                aux1: 0,
            },
        );
        slot
    };
    #[cfg(not(target_arch = "riscv64"))]
    let sbi_control_slot = 0u32;

    CSpaceLayout {
        memory_frame_base,
        memory_frame_count,
        hw_cap_base,
        hw_cap_count,
        sched_control_slot,
        sbi_control_slot,
        irq_range_slot,
        acpi_rsdp_frame_slot,
        acpi_region_frame_base,
        acpi_region_frame_count,
        dtb_frame_slot,
        total_populated: cspace.populated_count(),
        descriptor_count: desc_count,
        module_name_count: 0,
        module_names: [init_protocol::INIT_MODULE_NAME_EMPTY;
            init_protocol::INIT_MAX_NAMED_MODULES],
    }
}

/// Read the `totalsize` field of a flattened device tree blob.
///
/// Mirror of `crate::mm::init::read_dtb_totalsize`, duplicated here because
/// the buddy-init and cap-mint phases both need to bound DTB page accesses
/// without creating a public dep between the two modules.
fn read_dtb_totalsize(phys: u64) -> Option<u64>
{
    const FDT_MAGIC: u32 = 0xd00d_feed;
    const DTB_MAX_SIZE: u64 = 64 * 1024;

    // `phys` is in the direct physical map (active since Phase 3). The
    // FDT spec places magic + totalsize in the first 8 bytes of the blob.
    let base = phys_to_virt(phys) as *const u8;
    // SAFETY: direct physical map; first 4 bytes are the FDT magic field.
    let magic_bytes = unsafe { core::ptr::read_volatile(base.cast::<[u8; 4]>()) };
    let magic = u32::from_be_bytes(magic_bytes);
    if magic != FDT_MAGIC
    {
        return None;
    }
    // SAFETY: direct physical map; bytes 4..8 are the totalsize field.
    let size_bytes = unsafe { core::ptr::read_volatile(base.add(4).cast::<[u8; 4]>()) };
    let size = u64::from(u32::from_be_bytes(size_bytes));
    if size == 0 || size > DTB_MAX_SIZE
    {
        return None;
    }
    Some(size)
}

/// Mint `Frame` capabilities for boot modules into the root `CSpace`.
///
/// Each boot module (raw ELF image for an early service) gets a read-only
/// Frame cap. The kernel additionally publishes a name → slot mapping in
/// [`CSpaceLayout::module_names`] so init can match modules by their
/// bundle entry identifier instead of relying on ordinal position.
///
/// Updates `layout.module_names` / `layout.module_name_count` and
/// appends [`CapDescriptor`] entries for each module. Init looks
/// modules up by name via the published `module_names` table; the
/// older `module_frame_base` / `module_frame_count` ordinal surface
/// was retired with the init-protocol v6→v7 bump.
fn mint_module_frame_caps(cspace: &mut CSpace, boot_info: &BootInfo, layout: &mut CSpaceLayout)
{
    use boot_protocol::BootModule;
    use init_protocol::CapType;

    let module_count = boot_info.modules.count as usize;
    if module_count == 0 || boot_info.modules.entries.is_null()
    {
        return;
    }

    // SAFETY: boot_info.modules was validated by the bootloader; entries pointer
    // is in the direct physical map (active since Phase 3).
    let modules: &[BootModule] = unsafe {
        core::slice::from_raw_parts(
            phys_to_virt(boot_info.modules.entries as u64) as *const BootModule,
            module_count,
        )
    };

    for module in modules
    {
        // UEFI `AllocatePages` returns page-aligned bases, but mask
        // defensively to uphold FrameObject's alignment invariant.
        let aligned_base = module.physical_base & !0xFFF;
        // Round size up so the cap covers every page that holds module bytes.
        let rounded_size = (module.physical_base - aligned_base + module.size + 0xFFF) & !0xFFF;

        // Register the module's pages as managed-but-not-free so that if
        // the cap is ever destroyed, `dealloc_object`'s `buddy.free_range`
        // path keeps `free / total` well-defined. Idempotent at boot
        // since module page ranges are disjoint. Production-only:
        // `with_frame_allocator` is `cfg(not(test))`.
        #[cfg(not(test))]
        // SAFETY: module pages were not added via `add_region`
        // (`mm/init.rs` excludes loaded regions); single-threaded boot.
        unsafe {
            crate::mm::with_frame_allocator(|alloc| {
                alloc.register_owned_range(aligned_base, rounded_size);
            });
        }

        let ptr = mint_phase7_body(FrameObject {
            header: KernelObjectHeader::with_ancestor(ObjectType::Frame, seed_header_nn()),
            base: aligned_base,
            size: rounded_size,
            // Boot module pages are reclaimable: full byte ledger so the
            // pages can flow through `memmgr_labels::DONATE_FRAMES` into
            // memmgr's pool once the loader (init or procmgr) has copied
            // the ELF contents into the target process's AddressSpace.
            available_bytes: core::sync::atomic::AtomicU64::new(rounded_size),
            // Reclaimable: when this cap's last refcount drops, the pages
            // are returned to the buddy via `dealloc_object`. In normal
            // operation memmgr never destroys the cap (it ingests it into
            // its pool); this is a safety net.
            owns_memory: core::sync::atomic::AtomicBool::new(true),
            allocator: crate::cap::retype::RetypeAllocator::new_inline(),
            lock: core::sync::atomic::AtomicU32::new(0),
        });
        // Full rights so the cap can flow through the donation chain into
        // memmgr's pool (memmgr-issued reply caps must carry RETYPE for
        // userspace to retype into kernel objects). Loaders (init,
        // procmgr) map with `MAP_READONLY` for defence-in-depth on the
        // ELF source — read-only at the page-table level despite the
        // cap allowing WRITE.
        let slot = insert_or_fatal(
            cspace,
            CapTag::Frame,
            Rights::MAP | Rights::READ | Rights::WRITE | Rights::EXECUTE | Rights::RETYPE,
            ptr,
            "Phase 7: cannot allocate Frame capability for boot module",
        );
        note_owns_memory_minted(rounded_size);
        push_descriptor(
            &mut layout.descriptor_count,
            CapDescriptor {
                slot,
                cap_type: CapType::Frame,
                pad: [0; 3],
                aux0: module.physical_base,
                aux1: module.size,
            },
        );
        // Publish a name → slot entry in the InitInfo header table so
        // init can resolve modules by name without scanning descriptors.
        let name_slot = layout.module_name_count as usize;
        if name_slot < init_protocol::INIT_MAX_NAMED_MODULES
        {
            layout.module_names[name_slot] = init_protocol::InitModuleName {
                slot,
                _pad: 0,
                name: module.name,
            };
            layout.module_name_count += 1;
        }
    }

    layout.total_populated = cspace.populated_count();
}

/// Mint reclaimable `Frame` capabilities over bootloader scratch ranges.
///
/// Walks `boot_info.reclaim_ranges` — the `BootInfo` page, module
/// descriptor array, memory-map entry array, MMIO aperture array, the
/// reclaim-array page itself, the bootloader's transient page-table
/// frames, and the bundle's non-module pages (header + entry table +
/// pad, init ELF source body, inter-module and trailing slack —
/// module bodies are excluded because [`mint_module_frame_caps`]
/// covers them) — and mints one reclaimable `FrameObject`
/// cap per range with `owns_memory = true` and the full byte ledger.
/// Each cap is inserted into the root `CSpace` and a matching
/// `CapDescriptor` entry pushed into `layout.descriptors`, so the cap
/// reaches init through the standard descriptor-table walk in the same
/// shape boot-module caps take. Pages return to the buddy on cap teardown
/// via the existing `dealloc_object` → `free_range` path.
///
/// Entries marked [`boot_protocol::RECLAIM_FLAG_LATE`] are skipped here
/// and minted later by [`mint_late_reclaim_frame_caps`] after SMP
/// bringup completes (the AP SIPI trampoline is the only such entry
/// today).
///
/// Symmetric to [`mint_module_frame_caps`]; runs immediately after it.
/// The kernel MUST NOT dereference any address inside a recorded
/// non-late range after this function returns.
///
/// Appends one [`CapDescriptor`] entry per reclaimed range; init walks
/// the descriptor table to discover the caps. There is no dedicated
/// `reclaim_frame_base` / `reclaim_frame_count` pair on [`CSpaceLayout`]
/// because reclaim caps carry no per-index meaning — unlike boot
/// modules where slot N == module N, reclaim caps are a homogeneous
/// pool and userspace inspects each `CapDescriptor.aux0`/`aux1` to
/// learn the underlying physical range.
fn mint_reclaim_frame_caps(cspace: &mut CSpace, boot_info: &BootInfo, layout: &mut CSpaceLayout)
{
    mint_reclaim_pass(cspace, boot_info, layout, false, "reclaim");
}

/// Mint reclaimable `Frame` capabilities for entries flagged
/// [`boot_protocol::RECLAIM_FLAG_LATE`] in `boot_info.reclaim_ranges`.
///
/// Caller MUST have already (a) completed SMP bringup so no AP is
/// executing inside any late-flagged page, and (b) torn down any kernel
/// identity mapping that aliases the page (see
/// [`crate::mm::paging::unmap_identity_page`]). The mint itself is
/// identical to [`mint_reclaim_frame_caps`] — same `FrameObject`
/// shape, same `register_owned_range` ledger entry, same descriptor
/// push — so init discovers the cap through the standard descriptor
/// walk.
///
/// Must run before Phase 9 consumes [`descriptors`] so the new entry
/// reaches init via the same `CSpace` handoff.
#[cfg(not(test))]
pub(crate) fn mint_late_reclaim_frame_caps(
    cspace: &mut CSpace,
    boot_info: &BootInfo,
    layout: &mut CSpaceLayout,
)
{
    mint_reclaim_pass(cspace, boot_info, layout, true, "late reclaim");
}

/// Shared implementation backing both reclaim passes. `late` selects
/// which subset to process: `false` mints all entries with the LATE flag
/// clear, `true` mints only entries with the LATE flag set. `label`
/// prefixes the diagnostic line so the two passes are distinguishable
/// in the boot log.
// Linear Phase-7 sequence: per-range overlap check, owned-range
// registration, FrameObject mint, descriptor push. The debug-only
// overlap assertion adds ~25 lines without a natural extraction point.
#[allow(clippy::too_many_lines)]
fn mint_reclaim_pass(
    cspace: &mut CSpace,
    boot_info: &BootInfo,
    layout: &mut CSpaceLayout,
    late: bool,
    label: &str,
)
{
    use init_protocol::CapType;

    let range_count = boot_info.reclaim_ranges.count as usize;
    if range_count == 0 || boot_info.reclaim_ranges.entries.is_null()
    {
        return;
    }
    // The reclaim-array page is identity-mapped at boot and accessible via
    // the direct physical map after Phase 3; reach it through the direct map.
    // SAFETY: bootloader contract — `entries` points to a `count`-element
    // ReclaimRange array; direct map active since Phase 3.
    let ranges: &[boot_protocol::ReclaimRange] = unsafe {
        core::slice::from_raw_parts(
            phys_to_virt(boot_info.reclaim_ranges.entries as u64)
                as *const boot_protocol::ReclaimRange,
            range_count,
        )
    };

    #[cfg(not(test))]
    let total_before = crate::mm::with_frame_allocator(|alloc| alloc.total_page_count());
    #[cfg(test)]
    let total_before: usize = 0;

    let mut count: u32 = 0;
    let mut pages_total: u64 = 0;

    // Module-range slice for the debug-only overlap check below. Hoisted
    // out of the per-range loop because `boot_info.modules` is invariant
    // across iterations.
    #[cfg(debug_assertions)]
    let modules: &[boot_protocol::BootModule] = if !boot_info.modules.entries.is_null()
        && boot_info.modules.count > 0
    {
        // SAFETY: boot_info.modules was validated by the bootloader; the
        // entries pointer is in the direct physical map (active since
        // Phase 3) — same provenance as the slice in
        // `mint_module_frame_caps`.
        unsafe {
            core::slice::from_raw_parts(
                phys_to_virt(boot_info.modules.entries as u64) as *const boot_protocol::BootModule,
                boot_info.modules.count as usize,
            )
        }
    }
    else
    {
        &[]
    };

    for range in ranges
    {
        if range.page_count == 0
        {
            continue;
        }
        let is_late = range.flags & boot_protocol::RECLAIM_FLAG_LATE != 0;
        if is_late != late
        {
            continue;
        }
        let phys_base = range.phys_base & !0xFFF;
        let size_bytes = u64::from(range.page_count) * (crate::mm::PAGE_SIZE as u64);
        pages_total += u64::from(range.page_count);

        // Catch double-coverage with module Frame caps: any overlap here
        // would have `register_owned_range` double-bump `total_pages` and
        // (on cap destroy) cause `free_range` to double-free into the
        // buddy. The bootloader (`step9` bundle carve-out, scratch-page
        // allocations) is responsible for disjointness; this asserts the
        // contract at the consumer.
        #[cfg(debug_assertions)]
        {
            let range_end = phys_base + size_bytes;
            for m in modules
            {
                let m_base = m.physical_base & !0xFFF;
                let m_end = (m.physical_base + m.size + 0xFFF) & !0xFFF;
                debug_assert!(
                    range_end <= m_base || phys_base >= m_end,
                    "reclaim range overlaps module Frame cap",
                );
            }
        }

        // Register the range as managed-but-not-free so that if the cap is
        // ever destroyed, `dealloc_object`'s `free_range` keeps the buddy
        // `free / total` ratio well-defined. These pages were never in
        // `total_pages` — `mm::init::collect_usable_ranges` filters
        // `Loaded`-typed regions out of the buddy at Phase 2 — so
        // `register_owned_range` is the correct ledger entry (not
        // `add_region`, which would also push them onto the free list).
        #[cfg(not(test))]
        // SAFETY: range pages were not added via `add_region`
        // (bootloader-typed `Loaded`, filtered by
        // `mm::init::collect_usable_ranges`); single-threaded Phase 7.
        unsafe {
            crate::mm::with_frame_allocator(|alloc| {
                alloc.register_owned_range(phys_base, size_bytes);
            });
        }

        let ptr = mint_phase7_body(FrameObject {
            header: KernelObjectHeader::with_ancestor(ObjectType::Frame, seed_header_nn()),
            base: phys_base,
            size: size_bytes,
            // Reclaim pages carry the full byte ledger and `owns_memory = true`
            // so the buddy ledger is balanced when the cap is eventually
            // destroyed — matching the boot-module precedent above. Routing
            // beyond init's CSpace (donate-to-memmgr vs cascade-to-buddy) is
            // a userspace policy decision; the kernel only delivers the cap.
            available_bytes: core::sync::atomic::AtomicU64::new(size_bytes),
            owns_memory: core::sync::atomic::AtomicBool::new(true),
            allocator: crate::cap::retype::RetypeAllocator::new_inline(),
            lock: core::sync::atomic::AtomicU32::new(0),
        });
        let slot = insert_or_fatal(
            cspace,
            CapTag::Frame,
            Rights::MAP | Rights::READ | Rights::WRITE | Rights::EXECUTE | Rights::RETYPE,
            ptr,
            "Phase 7: cannot allocate Frame capability for reclaimed boot scratch",
        );
        push_descriptor(
            &mut layout.descriptor_count,
            CapDescriptor {
                slot,
                cap_type: CapType::Frame,
                pad: [0; 3],
                aux0: phys_base,
                aux1: size_bytes,
            },
        );
        count += 1;
    }

    note_owns_memory_minted(pages_total * crate::mm::PAGE_SIZE as u64);

    layout.total_populated = cspace.populated_count();

    #[cfg(not(test))]
    {
        let total_after = crate::mm::with_frame_allocator(|alloc| alloc.total_page_count());
        crate::kprintln!(
            "{}: minted {} Frame caps over {} scratch pages (total accounted {} → {})",
            label,
            count,
            pages_total,
            total_before,
            total_after,
        );
    }
    #[cfg(test)]
    let _ = (total_before, pages_total, label);
}

/// Cast `Box<T>` to `NonNull<KernelObjectHeader>` by leaking the box.
///
/// Used only by the test build's `mint_phase7_body` arm and by the test
/// build's RAM-Frame mint loop; the production path mints exclusively
/// through `cap::retype::boot_retype_body`.
///
/// # Safety contract
///
/// `T` must be `#[repr(C)]` with `KernelObjectHeader` as its first field
/// (offset 0). Dropping the returned pointer requires reconstructing the
/// original `Box<T>` based on `header.obj_type` (future phases).
#[cfg(test)]
fn nonnull_from_box<T>(b: Box<T>) -> NonNull<KernelObjectHeader>
{
    let raw = Box::into_raw(b).cast::<KernelObjectHeader>();
    // SAFETY: Box::into_raw never returns null.
    unsafe { NonNull::new_unchecked(raw) }
}

/// Move a capability between `CSpaces`, rewriting derivation tree pointers in place.
///
/// The moved slot takes the **same position** in the derivation tree as the source:
/// parent, children, and siblings all have their pointers updated to the new
/// `(dst_cspace_id, new_idx)` location. No ref-count change occurs — this is a
/// move, not a copy.
///
/// # Contract
/// - **Caller must hold [`DERIVATION_LOCK`]`.write_lock()`** for the duration.
/// - **Caller must hold both `src_cspace.lock` and `dst_cspace.lock`** (or
///   the single lock when both pointers are equal). Acquire in pointer
///   address order to prevent ABBA deadlock; the same order
///   `transfer_caps` uses.
/// - Source slot must be non-null.
/// - `dst_cspace` must have at least one free slot (call `pre_allocate` first).
///
/// Returns the new slot index in `dst_cspace`, or an error if the source slot
/// is null/invalid or the destination `CSpace` is full.
///
/// # Safety
/// `src_cspace` and `dst_cspace` must be valid, live `CSpace` pointers.
///
/// # To add support for explicit destination index
/// Add a `dst_idx: Option<u32>` parameter and call `insert_cap_at` when `Some`.
#[cfg(not(test))]
#[allow(clippy::too_many_lines)]
pub unsafe fn move_cap_between_cspaces(
    src_cspace: *mut CSpace,
    src_idx: u32,
    dst_cspace: *mut CSpace,
) -> Result<u32, syscall::SyscallError>
{
    use syscall::SyscallError;

    // Read source slot (tag, rights, object pointer, token).
    let (src_tag, src_rights, src_object, src_token) = {
        // SAFETY: src_cspace is a valid CSpace pointer; guaranteed by caller contract.
        let cs = unsafe { &*src_cspace };
        let slot = cs.slot(src_idx).ok_or(SyscallError::InvalidCapability)?;
        if slot.tag == CapTag::Null
        {
            return Err(SyscallError::InvalidCapability);
        }
        (
            slot.tag,
            slot.rights,
            slot.object.ok_or(SyscallError::InvalidCapability)?,
            slot.token,
        )
    };

    // SAFETY: src_cspace is a valid CSpace pointer; guaranteed by caller contract.
    let src_cspace_id = unsafe { (*src_cspace).id() };
    // SAFETY: dst_cspace is a valid CSpace pointer; guaranteed by caller contract.
    let dst_cspace_id = unsafe { (*dst_cspace).id() };

    // Insert into destination (auto-allocate free slot).
    // SAFETY: dst_cspace is a valid CSpace pointer; guaranteed by caller contract.
    let new_idx_nz = unsafe { (*dst_cspace).insert_cap(src_tag, src_rights, src_object) }
        .map_err(|_| SyscallError::OutOfMemory)?;
    let new_idx = new_idx_nz.get();

    let src_idx_nz = core::num::NonZeroU32::new(src_idx).ok_or(SyscallError::InvalidCapability)?;
    let src_slot_id = SlotId::current(src_cspace_id, src_idx_nz);
    let dst_slot_id = SlotId::current(dst_cspace_id, new_idx_nz);

    // Read derivation links from the source slot.
    let (src_parent, src_first_child, src_prev, src_next) = {
        // SAFETY: src_cspace is a valid CSpace pointer; guaranteed by caller contract.
        let cs = unsafe { &*src_cspace };
        // SAFETY: We validated src_idx exists at line 434
        #[allow(clippy::unwrap_used)]
        let slot = cs.slot(src_idx).unwrap();
        (
            slot.deriv_parent,
            slot.deriv_first_child,
            slot.deriv_prev_sibling,
            slot.deriv_next_sibling,
        )
    };

    // Copy token and derivation links to the destination slot.
    // SAFETY: dst_cspace is a valid CSpace pointer; new_idx was just allocated by insert_cap.
    if let Some(dst_slot) = unsafe { (*dst_cspace).slot_mut(new_idx) }
    {
        dst_slot.token = src_token;
        dst_slot.deriv_parent = src_parent;
        dst_slot.deriv_first_child = src_first_child;
        dst_slot.deriv_prev_sibling = src_prev;
        dst_slot.deriv_next_sibling = src_next;
    }

    // Update parent's first_child if it pointed to source.
    if let Some(parent_id) = src_parent
        && let Some(parent_cs) = lookup_cspace(parent_id.cspace_id, parent_id.epoch)
    {
        // SAFETY: parent_cs returned by lookup_cspace is valid; parent_id.index from derivation link is within bounds.
        if let Some(parent_slot) = unsafe { (*parent_cs).slot_mut(parent_id.index.get()) }
            && parent_slot.deriv_first_child == Some(src_slot_id)
        {
            parent_slot.deriv_first_child = Some(dst_slot_id);
        }
    }

    // Update prev sibling's next pointer.
    if let Some(prev_id) = src_prev
        && let Some(prev_cs) = lookup_cspace(prev_id.cspace_id, prev_id.epoch)
    {
        // SAFETY: prev_cs returned by lookup_cspace is valid; prev_id.index from derivation link is within bounds.
        if let Some(prev_slot) = unsafe { (*prev_cs).slot_mut(prev_id.index.get()) }
            && prev_slot.deriv_next_sibling == Some(src_slot_id)
        {
            prev_slot.deriv_next_sibling = Some(dst_slot_id);
        }
    }

    // Update next sibling's prev pointer.
    if let Some(next_id) = src_next
        && let Some(next_cs) = lookup_cspace(next_id.cspace_id, next_id.epoch)
    {
        // SAFETY: next_cs returned by lookup_cspace is valid; next_id.index from derivation link is within bounds.
        if let Some(next_slot) = unsafe { (*next_cs).slot_mut(next_id.index.get()) }
            && next_slot.deriv_prev_sibling == Some(src_slot_id)
        {
            next_slot.deriv_prev_sibling = Some(dst_slot_id);
        }
    }

    // Update all children's parent pointer.
    // Walk via next_sibling; children's order is preserved.
    let mut child_cur = src_first_child;
    while let Some(child_id) = child_cur
    {
        child_cur = if let Some(child_cs) = lookup_cspace(child_id.cspace_id, child_id.epoch)
        {
            // SAFETY: child_cs returned by lookup_cspace is valid; child_id.index from derivation link is within bounds.
            if let Some(child_slot) = unsafe { (*child_cs).slot_mut(child_id.index.get()) }
            {
                child_slot.deriv_parent = Some(dst_slot_id);
                child_slot.deriv_next_sibling
            }
            else
            {
                None
            }
        }
        else
        {
            None
        };
    }

    // Clear the source slot. No inc_ref/dec_ref — it's a move.
    // SAFETY: src_cspace is a valid CSpace pointer; src_idx was validated at entry.
    unsafe {
        (*src_cspace).free_slot(src_idx);
    }

    Ok(new_idx)
}

/// Insert a capability, calling [`crate::fatal`] on error.
fn insert_or_fatal(
    cspace: &mut CSpace,
    tag: CapTag,
    rights: Rights,
    object: NonNull<KernelObjectHeader>,
    msg: &'static str,
) -> u32
{
    match cspace.insert_cap(tag, rights, object)
    {
        Ok(idx) => idx.get(),
        #[cfg(not(test))]
        Err(_) => crate::fatal(msg),
        // In test mode, panic with the message instead of halting the CPU.
        #[cfg(test)]
        Err(e) => panic!("{}: {:?}", msg, e),
    }
}
