// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/cap/mod.rs

//! Capability subsystem (Phase 7).
//!
//! Initialised by [`init_capability_system`], which creates the root `CSpace`
//! (id 0) populated with initial capabilities for all boot-provided hardware
//! resources:
//!
//! - Usable physical memory → [`CapTag::Memory`] caps (MAP | WRITE | EXECUTE | RETYPE)
//! - MMIO apertures (coarse non-RAM ranges from the boot protocol)
//!   → [`CapTag::Mmio`] caps (MAP | WRITE)
//! - One root [`CapTag::Interrupt`] range cap covering every valid IRQ id
//!   (userspace narrows via `sys_irq_split`)
//! - Per `AcpiReclaimable` region, the ACPI RSDP page, and the DTB blob →
//!   read-only [`CapTag::Memory`] caps so userspace can parse firmware tables
//! - One root [`CapTag::IoPort`] cap covering the full 64K I/O port
//!   space (x86-64, USE)
//! - One [`CapTag::SchedControl`] cap spanning the full userspace priority range
//! - One [`CapTag::SbiControl`] cap on RISC-V (all sanctioned SBI rights)
//!
//! The populated `CSpace` is stored in [`ROOT_CSPACE`] until Phase 9 hands it
//! to the init process. Boot module ELF images get their own full-rights, reclaimable
//! Memory caps in [`mint_module_memory_caps`] (see `docs/capability-model.md` § Memory).

// cast_possible_truncation: u64→usize/u32/u16 capability field extractions bounded by capability space.
#![allow(clippy::cast_possible_truncation)]

// `alloc` is only required by the test build (heap-backed CSpace stub +
// `nonnull_from_box` test helper). Production has no `GlobalAlloc`.
#[cfg(test)]
extern crate alloc;

#[cfg(test)]
use alloc::boxed::Box;

pub mod arena;
pub mod cspace;
pub mod derivation;
pub mod ioport_bindings;
pub mod object;
pub mod registry;
pub mod retype;
pub mod slot;
// Split-helper body uses production-only object/derivation internals
// (`dealloc_object`, `link_child`, …) that are `#[cfg(not(test))]`. Its only
// callers are the `#[cfg(not(test))]` split syscalls, so gate the whole module.
#[cfg(not(test))]
pub mod split;
pub mod transfer;

// unused_imports: convenience re-exports of the cap subsystem's public types;
// not every symbol has an in-crate consumer.
#[allow(unused_imports)]
pub use cspace::{CSpace, CapError, L2_SIZE};
// unused_imports: same rationale as the `cspace` re-export above.
#[allow(unused_imports)]
pub use derivation::DERIVATION_LOCK;
// unused_imports: same rationale as the `cspace` re-export above.
#[allow(unused_imports)]
pub use object::{
    AddressSpaceObject, CSpaceKernelObject, EndpointObject, InterruptObject, IoPortObject,
    KernelObjectHeader, MemoryObject, MmioObject, NotificationObject, ObjectType, SbiControlObject,
    SchedControlObject, ThreadObject,
};
// unused_imports: same rationale as the `cspace` re-export above.
#[allow(unused_imports)]
pub use slot::{
    AsRights, CSpaceId, CapKind, CapTag, CapabilitySlot, CsRights, EpRights, EqRights,
    IoPortRights, IrqRights, MemRights, MmioRights, NtfRights, Rights, SbiRights, SchedRights,
    SlotId, ThreadRights, TypedRights, WsRights,
};

use boot_protocol::{BootInfo, MemoryMapEntry, MemoryType};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use init_protocol::CapDescriptor;

use crate::mm::paging::phys_to_virt;

// ── Globals ───────────────────────────────────────────────────────────────────

/// Root capability space, populated during Phase 7.
///
/// The pointer indexes into a SEED-derived retype slab. Set in
/// [`init_capability_system`] via [`boot_retype_cspace`], whose creation
/// reference is the kernel's hold on the `CSpace` through boot; consumed
/// (read out into init's TCB) during Phase 9, where that reference passes
/// to init's self-cap, so from then on the `CSpace` is an ordinary one that
/// its last capability's deletion frees. Access is single-threaded during
/// boot; `static mut` is safe here under that invariant.
#[cfg(not(test))]
pub static mut ROOT_CSPACE: *mut CSpace = core::ptr::null_mut();

/// Take the root `CSpace` pointer, clearing the slot to null.
///
/// Returns the raw pointer (storage lives inside a SEED slab). The slot is
/// cleared so no other code can observe the pointer afterwards: once init
/// runs, the `CSpace`'s lifetime is that of its capabilities.
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
        // `CSpace` inside a SEED slab, held by its creation reference;
        // single-threaded boot.
        unsafe { Some(&mut *raw) }
    }
}

use registry::CSPACE_REGISTRY;

/// Carve the `CSpace` registry arena from the buddy: a chunk table sized from
/// DRAM, then one entry per page of DRAM
/// ([`crate::mm::init::system_ram_bytes`]), in
/// [`registry::REGISTRY_CHUNK_ORDER`] blocks. Fatal when the buddy cannot
/// supply the table or a chunk.
///
/// # Safety
/// The single boot thread, once, after Phase 3 (the chunks are written
/// through the direct map) and before the Phase-7 drain and any
/// `alloc_cspace_id`.
#[cfg(not(test))]
pub unsafe fn init_cspace_registry(alloc: &mut crate::mm::BuddyAllocator)
{
    let chunks = registry::chunks_for_ram(crate::mm::init::system_ram_bytes());
    let table = crate::sched::alloc_zeroed_slab::<AtomicPtr<registry::RegistryEntry>>(
        chunks * core::mem::size_of::<AtomicPtr<registry::RegistryEntry>>(),
        alloc,
        "CSPACE_REGISTRY_TABLE",
    );
    // SAFETY: `chunks` zeroed (null) slots owned by the registry for the
    // kernel's life; the boot thread is alone.
    unsafe { CSPACE_REGISTRY.install_table(table, chunks) };
    for _ in 0..chunks
    {
        let Some(phys) = alloc.alloc(registry::REGISTRY_CHUNK_ORDER)
        else
        {
            crate::fatal("Phase 4: buddy exhausted allocating the CSpace registry");
        };
        let entries = phys_to_virt(phys) as *mut registry::RegistryEntry;
        // SAFETY: the block is freshly allocated, owned by the registry for
        // the kernel's life, reached through the direct map active since
        // Phase 3, page-aligned, and exactly ENTRIES_PER_CHUNK entries long;
        // the boot thread is alone.
        if unsafe { CSPACE_REGISTRY.install_chunk(entries) }.is_err()
        {
            crate::fatal("Phase 4: CSpace registry chunk table full");
        }
    }
}

/// Allocate a unique `CSpace` ID.
///
/// Pops the most recently retired id first; otherwise hands out the next
/// fresh one. Returns `None` once every id the registry arena backs is live
/// (callers surface `SyscallError::OutOfMemory`); the arena holds one id per
/// page of DRAM and every `CSpace` costs at least one page, so that point
/// lies past the memory that pays for the `CSpace`s.
///
/// The root `CSpace` receives id `0` at init time as the first fresh id —
/// Phase 7 runs before any `free_cspace_id` could list an id, so the root
/// deterministically gets id 0. The id carries no special meaning after
/// boot: freeing init's `CSpace` at its reap recycles it like any other.
pub fn alloc_cspace_id() -> Option<CSpaceId>
{
    CSPACE_REGISTRY.alloc()
}

/// Number of `CSpace` ids in use: allocated by [`alloc_cspace_id`] and not
/// yet returned by [`free_cspace_id`], the root `CSpace`'s included.
/// `SYS_SYSTEM_INFO(LiveCSpaceCount)` reports it.
#[must_use]
pub fn live_cspace_count() -> u32
{
    CSPACE_REGISTRY.live()
}

/// Register a `CSpace` pointer under its ID.
///
/// Called immediately after a [`CSpace`] is allocated. Returns the registry
/// entry's current epoch so the caller can stamp `SlotId`s minted in this
/// `CSpace`'s lifetime. Returns `Err(())` if no registry chunk backs `id`.
pub fn register_cspace(id: CSpaceId, ptr: *mut CSpace) -> Result<u32, ()>
{
    CSPACE_REGISTRY.register(id, ptr)
}

/// Clear a `CSpace` registration.
///
/// Called from `dealloc_object` for `ObjectType::CSpaceObj` *before* freeing
/// the backing allocation, so no dangling pointer is observable. The
/// epoch redraw that retires this id is deferred to [`free_cspace_id`]
/// so the pre-unregister derivation drain can still resolve foreign
/// back-links into this `CSpace`'s live (now-quiescent) registry entry.
pub fn unregister_cspace(id: CSpaceId)
{
    CSPACE_REGISTRY.unregister(id);
}

/// Redraw the registry epoch for `id` and return it to the free list.
///
/// Pre-condition: `unregister_cspace(id)` has run (registry `ptr` is null).
/// The new epoch is drawn from the kernel CSPRNG, excluding the sentinel `0`
/// and the current value, so any surviving `SlotId` stamped with the old
/// value fails resolution at [`lookup_cspace`], and the epoch carries no
/// monotonic information that would leak recycle counts or rates. The
/// vacant entry keeps the new epoch until the id's next registration.
///
/// The epoch-recycle design (random non-zero redraw excluding the prior
/// value) is specified in `core/kernel/docs/capability-internals.md`
/// § Representation.
#[cfg(not(test))]
pub fn free_cspace_id(id: CSpaceId)
{
    debug_assert!(id < CSPACE_REGISTRY.capacity());
    let cur = CSPACE_REGISTRY.epoch(id);
    let mut next = crate::entropy::next_u32();
    while next == 0 || next == cur
    {
        next = crate::entropy::next_u32();
    }
    CSPACE_REGISTRY.retire(id, next);
}

/// Read the current epoch for a registry entry. Returns 0 if no registry
/// chunk backs `id` (a stale `SlotId` carrying such a `cspace_id` is
/// always rejected by `lookup_cspace` regardless).
pub fn registry_epoch(id: CSpaceId) -> u32
{
    CSPACE_REGISTRY.epoch(id)
}

/// Resolve a `CSpaceId` and expected epoch to a raw pointer.
///
/// Returns `None` if no registry chunk backs `id`, the entry is vacant, or
/// the stamped epoch doesn't match the registry's current value (see
/// [`registry::CSpaceRegistry::lookup`]).
///
/// The returned pointer is valid only while the corresponding
/// `CSpaceKernelObject` has a positive refcount and (for derivation-tree
/// reads) `DERIVATION_LOCK` is held.
pub fn lookup_cspace(id: CSpaceId, expected_epoch: u32) -> Option<*mut CSpace>
{
    CSPACE_REGISTRY.lookup(id, expected_epoch)
}

/// Sum [`MemoryObject::available_bytes`] across every [`CapTag::Memory`] cap
/// in `cspace`. Used by Phase 9 to print the boot-handover ledger so that
/// "RAM granted to userspace as retypable bytes" can be reconciled against
/// the buddy/SEED bookkeeping over time.
///
/// Must be called single-threaded with no concurrent retype/dealloc.
#[cfg(not(test))]
#[must_use]
pub fn sum_memory_available_bytes(cspace: &cspace::CSpace) -> u64
{
    use core::sync::atomic::Ordering;
    let mut sum: u64 = 0;
    cspace.for_each_object(|obj_nn| {
        // SAFETY: for_each_object yields live KernelObjectHeader pointers.
        let obj_type = unsafe { obj_nn.as_ref().obj_type };
        if obj_type == object::ObjectType::Memory
        {
            // cast_ptr_alignment: header at offset 0; MemoryObject is repr(C).
            #[allow(clippy::cast_ptr_alignment)]
            // SAFETY: obj_type confirms MemoryObject layout; pointer live.
            let memory = unsafe { &*obj_nn.as_ptr().cast::<object::MemoryObject>() };
            sum += memory.available_bytes.load(Ordering::Acquire);
        }
    });
    sum
}

/// Slots of the root `CSpace`'s initial slot-page pool beyond the boot mint:
/// what userspace init mints, copies, and derives into it during memmgr /
/// procmgr bootstrap (kernel-object inserts and the per-RAM-Memory
/// derive/copy chains in `finalize_memmgr`), about 700 caps observed. Set
/// at about 1.8× that, per the seeding policy in docs/capability-model.md
/// (growth budgets), so realistic growth of init's own use (more services,
/// more derivations per RAM extent) does not revisit it.
#[cfg(not(test))]
const ROOT_CSPACE_INIT_HEADROOM_SLOTS: u64 = 1280;

/// Slots of the root `CSpace` the boot takes besides one per capability body:
/// the permanently null slot 0 and the caps Phase 9 inserts over objects it
/// does not count as bodies, init's `AddressSpace`, `Thread` and `CSpace`.
#[cfg(not(test))]
const ROOT_CSPACE_BOOT_EXTRA_SLOTS: u64 = 4;

/// Slot capacity of the root `CSpace`'s initial slot-page pool: the boot's
/// capability bodies ([`boot_body_bound`], from the `InitInfo` descriptor
/// capacity Phase 7 sized from this boot's counts), the
/// [`ROOT_CSPACE_BOOT_EXTRA_SLOTS`], and [`ROOT_CSPACE_INIT_HEADROOM_SLOTS`]
/// for init.
///
/// A pool below the peak slot count means `pre_allocate`'s grow loop hits
/// an exhausted pool, the syscall errors out, and the userspace caller
/// either retries indefinitely (e.g. `request_round` in a child) or
/// surfaces an unexpected `OutOfMemory`.
///
/// Backing the directory's full structural ceiling would cost about 65,800
/// SEED pages (~257 MiB: 65,664 leaves plus 128 directory pages) for a
/// `CSpace` whose occupancy peaks at boot and is bounded in steady state.
/// Growth past the seeded pool returns the refillable `OutOfMemory`. init
/// never augments this `CSpace`; it budgets its own use inside the pool: it
/// stops its forward of RAM caps to memmgr at `INIT_FORWARD_HEADROOM` general
/// slots, a reserve sized for what it mints after the forward
/// (services/init/src/bootstrap.rs), and hands the rest over at its reap.
#[cfg(not(test))]
fn root_cspace_init_slot_capacity() -> u64
{
    boot_body_bound() as u64 + ROOT_CSPACE_BOOT_EXTRA_SLOTS + ROOT_CSPACE_INIT_HEADROOM_SLOTS
}

/// Pool pages of the root `CSpace` beyond its slots, for the bodies its arena
/// funds: init's bootstrap allocator splits a Memory cap once per page it hands
/// out, and each split's tail body takes a 128-byte chunk of init's own
/// `CSpace` (core/kernel/docs/capability-internals.md § Body Arena), which init
/// never augments. 16 pages hold 496 bodies (31 per page after its header),
/// about twice the splits init makes before it hands memory to memmgr; a
/// shortfall is the refillable `OutOfMemory` of the split that meets it.
#[cfg(not(test))]
const ROOT_CSPACE_BODY_PAGES: u64 = 16;

/// Pages carved from `SEED_MEMORY` for the root `CSpace` slab: page 0 is the
/// wrapper page (`CSpaceKernelObject` + inlined `CSpace`); the remaining
/// pages seed the slot-page pool. Sized so the pool holds at least
/// [`root_cspace_init_slot_capacity`] slots regardless of `L2_SIZE`
/// (slots-per-page), plus [`ROOT_CSPACE_BODY_PAGES`] for the bodies of init's
/// splits. The slot-0 reservation, on the pool's first slot page, is one of the
/// [`ROOT_CSPACE_BOOT_EXTRA_SLOTS`].
#[cfg(not(test))]
fn root_cspace_init_pages() -> u64
{
    1 + root_cspace_init_slot_capacity().div_ceil(cspace::L2_SIZE as u64) + ROOT_CSPACE_BODY_PAGES
}

/// Pages of init's bootstrap `AddressSpace` slab, retyped from SEED at Phase 9:
/// 1 wrapper + 1 root PT + 16 PT pool pages. Phase 9 mappings (ELF segments,
/// `InitInfo`, stack) go through `map_page`, a kernel-direct call whose
/// intermediate PT pages come from `kernel_pt_pool`, not this wrapper's pool.
/// The wrapper's pool serves init's userspace pooled paths: `sys_mem_map`
/// (`TEMP_MAP_BASE` + `ELF_PAGE_TEMP_VA` scratch) and `sys_mmio_map` for init's
/// own MMIO (the riscv64 serial UART, one page). 16 pool pages cover that
/// footprint with margin. The footprint is fixed by init's own code, so no
/// hardware count grows it; the pool also takes augment-mode
/// `SYS_CAP_CREATE_ASPACE` donations, which ktest uses.
#[cfg(not(test))]
pub(crate) const INIT_ASPACE_PAGES: u64 = 18;

/// Most descriptors an `InitInfo` block can hold: the
/// [`init_protocol::INIT_INFO_MAX_PAGES`] (64) pages of the protocol's ceiling
/// past the header, one [`CapDescriptor`] slot each, 10,775. Phase 7 sizes
/// each boot's block from its own counts ([`init_info_descriptor_bound`]), so
/// this binds only a boot whose counts pass it, which halts by name at the
/// reservation; no platform comes near it (see the ceiling's rustdoc).
pub const INIT_INFO_DESCRIPTOR_CAPACITY: usize =
    descriptors_in_pages(init_protocol::INIT_INFO_MAX_PAGES);

/// Descriptors an `InitInfo` region of `pages` pages holds past its header.
const fn descriptors_in_pages(pages: usize) -> usize
{
    (pages * crate::mm::PAGE_SIZE - core::mem::size_of::<init_protocol::InitInfo>())
        / core::mem::size_of::<CapDescriptor>()
}

/// Pages of the `InitInfo` region that holds the header and `descriptors`
/// descriptors.
const fn init_info_pages(descriptors: usize) -> usize
{
    (core::mem::size_of::<init_protocol::InitInfo>()
        + descriptors * core::mem::size_of::<CapDescriptor>())
    .div_ceil(crate::mm::PAGE_SIZE)
}

/// Descriptors Phases 7 and 8 write besides one per RAM extent, ACPI
/// region, MMIO aperture, boot module and reclaim range: the console UART
/// `Mmio` cap, the `SchedControl` and root `Interrupt` caps, the RSDP and DTB
/// `Memory` caps, the root `IoPort` or `SbiControl` cap, and two to spare.
const FIXED_BOOT_DESCRIPTORS: usize = 8;

/// The most descriptors this boot's Phases 7 and 8 can write into the
/// `InitInfo` block: one per drained RAM extent (at most `ram_extents`), per
/// `AcpiReclaimable` memory-map entry, per MMIO aperture, per boot module and
/// per reclaim range, plus [`FIXED_BOOT_DESCRIPTORS`]. Every count is the
/// platform's own, read before the drain, so the block Phase 7 reserves is
/// sized for this boot.
const fn init_info_descriptor_bound(
    ram_extents: usize,
    acpi_regions: usize,
    apertures: usize,
    modules: usize,
    reclaim_ranges: usize,
) -> usize
{
    ram_extents + acpi_regions + apertures + modules + reclaim_ranges + FIXED_BOOT_DESCRIPTORS
}

/// Descriptors the `InitInfo` block Phase 7 reserved holds, set once by
/// `reserve_init_backing`; Phases 7 and 8 write the boot capability
/// descriptors straight into the block (the buddy drain its RAM extents
/// first, [`drain_and_install_seed`]), so this is the one bound on the
/// capabilities that carry a descriptor: [`push_descriptor`] halts the boot
/// by name past it. Phase 9's Memory caps reach init through header fields
/// instead ([`boot_body_bound`] counts them).
#[cfg(not(test))]
static DESCRIPTOR_CAPACITY: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Host-test stand-in for the reserved block's capacity: a four-page
/// region's, enough for the test maps.
#[cfg(test)]
const TEST_DESCRIPTOR_CAPACITY: usize = descriptors_in_pages(4);

/// Descriptors the reserved `InitInfo` block holds ([`DESCRIPTOR_CAPACITY`]).
fn descriptor_capacity() -> usize
{
    #[cfg(not(test))]
    {
        DESCRIPTOR_CAPACITY.load(core::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(test)]
    {
        TEST_DESCRIPTOR_CAPACITY
    }
}

/// Pages of the `InitInfo` block Phase 7 reserved, set with
/// [`DESCRIPTOR_CAPACITY`].
#[cfg(not(test))]
static INIT_INFO_BLOCK_PAGES: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

// `mint_module_memory_caps` copies each boot module's `BootModule.name`
// straight into its `InitModuleName.name`, so the two widths are one ABI fact,
// and publishes one name per module, so the name table holds as many entries
// as a `BootInfo` can list modules.
const _: () = assert!(init_protocol::INIT_MODULE_NAME_LEN == boot_protocol::BOOT_MODULE_NAME_LEN);
const _: () = assert!(init_protocol::INIT_MAX_NAMED_MODULES == boot_protocol::MAX_BOOT_MODULES);

// The descriptor array starts right after the header, at an offset its
// element alignment divides.
const _: () = assert!(
    core::mem::size_of::<init_protocol::InitInfo>()
        .is_multiple_of(core::mem::align_of::<CapDescriptor>())
);

/// Most boot-minted capability bodies: one per descriptor the reserved
/// `InitInfo` block can carry ([`descriptor_capacity`]), since every capability
/// Phases 7 and 8 mint into the root `CSpace` is described to init there, plus
/// the `Memory` bodies Phase 9 mints that init learns of through header fields
/// instead: one per init segment, `InitInfo` page and init stack page. Valid
/// once Phase 7 has reserved the block.
#[cfg(not(test))]
fn boot_body_bound() -> usize
{
    descriptor_capacity()
        + boot_protocol::INIT_MAX_SEGMENTS
        + INIT_INFO_BLOCK_PAGES.load(core::sync::atomic::Ordering::Relaxed)
        + INIT_STACK_PAGES
}

/// Bytes of one boot-minted body: the 128-byte retype size class, which
/// every body type fits (asserted below).
#[cfg(not(test))]
const BOOT_BODY_BYTES: usize = 128;

#[cfg(not(test))]
const _: () = assert!(
    core::mem::size_of::<MemoryObject>() <= BOOT_BODY_BYTES
        && core::mem::size_of::<object::MmioObject>() <= BOOT_BODY_BYTES
        && core::mem::size_of::<object::InterruptObject>() <= BOOT_BODY_BYTES
        && core::mem::size_of::<object::IoPortObject>() <= BOOT_BODY_BYTES
        && core::mem::size_of::<object::SchedControlObject>() <= BOOT_BODY_BYTES
        && core::mem::size_of::<object::SbiControlObject>() <= BOOT_BODY_BYTES,
    "a boot-minted body exceeds the size class the seed reserve budgets"
);

/// Pages the seed's bump cursor can lose to page alignment: one at each switch
/// from sub-page bodies to a page-aligned slab, and the boot makes three
/// (Phase 7's bodies, then Phase 9's address-space slab, bodies, and thread
/// slab), with one to spare.
#[cfg(not(test))]
const SEED_ALIGNMENT_SLACK_PAGES: u64 = 4;

// ── Phase-7 seed Memory cap ───────────────────────────────────────────────────

/// The seed reserve less init's Thread slot ([`seed_reserve_bytes`] adds it):
/// the part of the boot footprint carved off the front of the largest
/// drained RAM extent that the `InitInfo` descriptor capacity sizes, every
/// kernel object the boot mints before init runs:
///
/// - the root `CSpace` slab ([`root_cspace_init_pages`]: one wrapper page,
///   the slot pages for [`root_cspace_init_slot_capacity`], and
///   [`ROOT_CSPACE_BODY_PAGES`]);
/// - init's bootstrap `AddressSpace` slab ([`INIT_ASPACE_PAGES`] 18);
/// - the boot-minted capability bodies, at most [`boot_body_bound`] of
///   [`BOOT_BODY_BYTES`] each: one RAM `MemoryObject`
///   per coalesced drained extent, the `Mmio`, `Interrupt`, `IoPort`,
///   `SchedControl` and `SbiControl` roots, the firmware-table, boot-module,
///   init-segment, `InitInfo`/stack and reclaim Memory caps;
/// - [`SEED_ALIGNMENT_SLACK_PAGES`] (4).
///
/// Valid once Phase 7 has reserved the `InitInfo` block, which sets the
/// capacity. init's Thread slot adds seven or more pages
/// (`sched::thread_slot::thread_slot_bytes`). Nothing draws on SEED at runtime: the
/// bodies a syscall creates are funded by the caller's `CSpace`
/// (core/kernel/docs/capability-internals.md § Body Arena). A boot whose
/// capabilities pass the descriptor capacity halts the boot by name in
/// Phase 7 or 8 (`push_descriptor`) before it could exhaust SEED.
///
/// The remainder of the largest extent is exposed to userspace as a
/// regular retype-backed RAM Memory cap (the "seed-tail"), so init and
/// memmgr operate on virgin caps with zero behavioural change in their
/// front-split allocators.
#[cfg(not(test))]
fn seed_fixed_reserve_bytes() -> u64
{
    (root_cspace_init_pages()
        + INIT_ASPACE_PAGES
        + (boot_body_bound() * BOOT_BODY_BYTES).div_ceil(crate::mm::PAGE_SIZE) as u64
        + SEED_ALIGNMENT_SLACK_PAGES)
        * crate::mm::PAGE_SIZE as u64
}

/// Bytes carved off the front of the largest drained RAM extent for the boot
/// footprint: [`seed_fixed_reserve_bytes`] plus init's Thread slot, whose
/// save area the boot CPU sized at Phase 5 (`sched::thread_slot`).
#[cfg(not(test))]
fn seed_reserve_bytes() -> u64
{
    seed_fixed_reserve_bytes() + crate::sched::thread_slot::thread_slot_bytes()
}

/// BSS-static `MemoryObject` covering the seed RAM region.
///
/// Phase 7 mints every initial cap identity (`MemoryObject` for every
/// drained RAM extent, `Mmio` / `Interrupt` / `IoPort` /
/// `SchedControl` / `SbiControl` wrappers, plus firmware-table and
/// boot-module `MemoryObject`s, plus init's ELF-segment `MemoryObject`s,
/// plus the seed-tail `MemoryObject` exposing the rest of the largest
/// drained extent) from this seed via [`crate::cap::retype::boot_retype_body`].
/// The bodies land inside the seed's `seed_reserve_bytes()` reservation,
/// debited from `available_bytes` like every other byte.
///
/// The seed itself is **not** inserted into init's `CSpace`: it is pure
/// kernel-internal storage. Userspace sees the largest drained extent's
/// RAM via the seed-tail cap, which is virgin (`bump_offset = 0`) and
/// behaves like every other RAM Memory cap.
///
/// Pinned by two references that are never released: the static's initial
/// `ref_count = 1` and the `+1` added in [`install_seed_memory`]. Every retyped
/// descendant body adds another reference; reclaim of every descendant drops
/// back to `2`, which is non-zero — `dealloc_object` is never invoked, and the
/// BSS storage stays valid for the lifetime of the kernel.
///
/// Single-threaded boot context permits `static mut`; `addr_of(_mut)!`
/// access patterns sidestep the `static_mut_refs` lint.
#[cfg(not(test))]
static mut SEED_MEMORY: object::MemoryObject = object::MemoryObject {
    header: object::KernelObjectHeader {
        ref_count: AtomicU32::new(1),
        obj_type: object::ObjectType::Memory,
        cascade_link_hi: [0; 3],
        ancestor: AtomicPtr::new(core::ptr::null_mut()),
    },
    base: 0,
    size: 0,
    available_bytes: core::sync::atomic::AtomicU64::new(0),
    owns_memory: core::sync::atomic::AtomicBool::new(true),
    allocator: crate::cap::retype::RetypeAllocator::new_inline(),
    lock: AtomicU32::new(0),
};

/// Borrow the seed `MemoryObject` shared.
///
/// `base`/`size` are mutated only during [`install_seed_memory`] (single-
/// threaded Phase 7); after that, retype/dealloc paths see them as stable.
#[cfg(not(test))]
pub(crate) fn seed_memory_ref() -> &'static object::MemoryObject
{
    let p = core::ptr::addr_of!(SEED_MEMORY);
    // SAFETY: `SEED_MEMORY` is a non-null BSS static; `addr_of!` produces a
    // valid pointer for shared access.
    unsafe { &*p }
}

/// `NonNull` over the seed `MemoryObject`'s header for use as a
/// `KernelObjectHeader::with_ancestor` argument and as the seed slot's
/// `object` pointer.
#[cfg(not(test))]
pub(crate) fn seed_header_nn() -> NonNull<object::KernelObjectHeader>
{
    // SAFETY: `SEED_MEMORY` is a non-null BSS static; `addr_of_mut!` produces
    // a valid pointer.
    let p = unsafe { core::ptr::addr_of_mut!(SEED_MEMORY.header) };
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

/// One-shot Phase-7 seed initializer. Sets the seed `MemoryObject`'s runtime
/// fields (covering the front [`seed_reserve_bytes`] of the largest
/// drained extent) and bumps the refcount once for the kernel pin. Caller
/// must invoke before any [`crate::cap::retype::boot_retype_body`] against
/// the seed.
///
/// # Safety
///
/// Call exactly once during Phase 7, single-threaded.
#[cfg(not(test))]
unsafe fn install_seed_memory(base: u64)
{
    let p = core::ptr::addr_of_mut!(SEED_MEMORY);
    // SAFETY: single-threaded boot; the seed is not published anywhere
    // until after this call, so no other reader exists.
    unsafe {
        (*p).base = base;
        (*p).size = seed_reserve_bytes();
        (*p).available_bytes
            .store(seed_reserve_bytes(), Ordering::Release);
        (*p).header.inc_ref();
    }
}

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

/// Pages the kernel permanently reserves from RAM at Phase 7, as the sum of its
/// named contributors:
///
/// 1. `POOL_SEED_PAGES` — the kernel PT-frame pool seed.
/// 2. Idle-thread kernel stacks — `cpu_count × (KERNEL_STACK_PAGES + 1)`, one
///    stack and the guard page below it per online CPU (pre-allocated in
///    Phase 4 from the pristine buddy).
/// 3. The guard-table reserve — `mm::stack_guard::seeded_frames()`, one leaf
///    table per 2 MiB chunk of RAM (`mm::stack_guard::reserve_frames`),
///    seeded in Phase 4, for the direct-map splits the kernel-stack guard
///    pages make.
/// 4. The `InitInfo` block — sized at Phase 7 from this boot's counts.
/// 5. Init's user stack — `INIT_STACK_PAGES`.
/// 6. The SEED arena — `seed_reserve_bytes()`.
///
/// Every other page of RAM is drained for userspace and routes to memmgr's
/// pool, leaving the post-handoff buddy fully empty. This value is a Phase-7
/// diagnostic; the authoritative `kernel_reserved` is the complement of the
/// `owns_memory` ledger computed at Phase 9 (`core/kernel/src/main.rs`, from
/// [`owns_memory_minted_bytes`]). Valid once Phase 7 has reserved the
/// `InitInfo` block, which sizes terms 4 and 6.
#[cfg(not(test))]
pub(crate) fn kernel_reserve_pages() -> usize
{
    let cpu_count = crate::sched::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    let idle_stacks = cpu_count * (crate::sched::KERNEL_STACK_PAGES + 1);
    let guard_tables = crate::mm::stack_guard::seeded_frames();
    let init_info = INIT_INFO_BLOCK_PAGES.load(core::sync::atomic::Ordering::Relaxed);
    let seed = (seed_reserve_bytes() / crate::mm::PAGE_SIZE as u64) as usize;
    POOL_SEED_PAGES + idle_stacks + guard_tables + init_info + INIT_STACK_PAGES + seed
}

/// Number of init user-stack pages reserved ahead of the drain.
#[cfg(not(test))]
const INIT_STACK_PAGES: usize = crate::mm::address_space::INIT_STACK_PAGES;

/// Physical base of the `InitInfo` block reserved from the pristine buddy in
/// [`drain_and_install_seed`], consumed once at Phase 9 via
/// [`take_init_info_block`].
#[cfg(not(test))]
static INIT_INFO_BLOCK_PHYS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Physical bases of init's user-stack pages ([`INIT_STACK_PAGES`] order-0
/// frames) reserved from the pristine buddy in [`drain_and_install_seed`],
/// consumed once each at Phase 9 via [`init_stack_phys`].
#[cfg(not(test))]
static INIT_STACK_PHYS: [core::sync::atomic::AtomicU64; INIT_STACK_PAGES] =
    [const { core::sync::atomic::AtomicU64::new(0) }; INIT_STACK_PAGES];

/// The counts, read from `BootInfo` before the drain, that bound this boot's
/// non-RAM descriptors ([`init_info_descriptor_bound`]).
pub(crate) struct DescriptorCounts
{
    /// `AcpiReclaimable` memory-map entries, at most one ACPI region cap each
    /// (none for an entry whose page-rounded span is empty).
    pub acpi_regions: usize,
    /// MMIO apertures, one `Mmio` cap each.
    pub apertures: usize,
    /// Boot modules, one `Memory` cap each.
    pub modules: usize,
    /// Reclaim ranges, at most one reclaimable `Memory` cap each (none for a
    /// zero-length range).
    pub reclaim_ranges: usize,
}

impl DescriptorCounts
{
    /// The counts of `mmap`'s `AcpiReclaimable` entries, `apertures` and
    /// `info`'s module and reclaim arrays: Phases 7 and 8 mint at most one
    /// descriptor per entry of each (an ACPI entry whose page-rounded span is
    /// empty, or a zero-length reclaim range, gets none).
    fn of(
        mmap: &[MemoryMapEntry],
        apertures: &crate::platform::ValidatedApertures,
        info: &BootInfo,
    ) -> Self
    {
        Self {
            acpi_regions: mmap
                .iter()
                .filter(|e| e.memory_type == MemoryType::AcpiReclaimable)
                .count(),
            apertures: apertures.iter().count(),
            modules: info.modules.count as usize,
            reclaim_ranges: info.reclaim_ranges.count as usize,
        }
    }

    /// [`init_info_descriptor_bound`] over these counts and `ram_extents`.
    const fn bound(&self, ram_extents: usize) -> usize
    {
        init_info_descriptor_bound(
            ram_extents,
            self.acpi_regions,
            self.apertures,
            self.modules,
            self.reclaim_ranges,
        )
    }
}

/// Reserve, from the pristine buddy, every page Phase 9 consumes after the
/// Phase-7 drain: init's user-stack pages and the `InitInfo` block. Done
/// before the drain so the drain can take 100% of the remainder, driving the
/// post-handoff buddy free count to 0.
///
/// The block is sized for this boot: once the stack pages are out, the
/// buddy's coalesced extents are counted without draining
/// ([`crate::mm::buddy::BuddyAllocator::coalesced_extent_count`]), and the
/// block taken holds that count plus two (taking it and returning its tail
/// can each split one extent) together with the descriptors `counts` bounds.
/// The block is one contiguous extent, so the descriptor array that spans its
/// pages lives in a single backing allocation; the pages of its power-of-two
/// buddy block past the region go back to the buddy, which the drain then
/// takes. A boot whose region would pass the protocol's ceiling
/// ([`init_protocol::INIT_INFO_MAX_PAGES`]) halts by name.
#[cfg(not(test))]
fn reserve_init_backing(counts: &DescriptorCounts)
{
    crate::mm::with_frame_allocator(|alloc| {
        for slot in &INIT_STACK_PHYS
        {
            let page = alloc
                .alloc(0)
                .unwrap_or_else(|| crate::fatal("Phase 7: out of memory reserving init stack"));
            slot.store(page, core::sync::atomic::Ordering::Relaxed);
        }

        let bound = counts.bound(alloc.coalesced_extent_count() + 2);
        if bound > INIT_INFO_DESCRIPTOR_CAPACITY
        {
            crate::kprintln!(
                "Phase 7: {} boot descriptors; {} InitInfo pages, the protocol's ceiling, hold {}",
                bound,
                init_protocol::INIT_INFO_MAX_PAGES,
                INIT_INFO_DESCRIPTOR_CAPACITY
            );
            crate::fatal("Phase 7: boot descriptors exceed the InitInfo region ceiling");
        }
        let pages = init_info_pages(bound);
        let order = pages.next_power_of_two().trailing_zeros() as usize;
        let info = alloc
            .alloc(order)
            .unwrap_or_else(|| crate::fatal("Phase 7: out of memory reserving InitInfo block"));
        let page = crate::mm::PAGE_SIZE as u64;
        let tail = ((1usize << order) - pages) as u64 * page;
        if tail != 0
        {
            // SAFETY: the tail pages are the end of the block just taken, so
            // they were allocated from this buddy and nothing references them.
            unsafe { alloc.free_range(info + pages as u64 * page, tail) };
        }
        INIT_INFO_BLOCK_PHYS.store(info, core::sync::atomic::Ordering::Relaxed);
        INIT_INFO_BLOCK_PAGES.store(pages, core::sync::atomic::Ordering::Relaxed);
        DESCRIPTOR_CAPACITY.store(
            descriptors_in_pages(pages),
            core::sync::atomic::Ordering::Relaxed,
        );
        let block = phys_to_virt(info) as *mut u8;
        // SAFETY: the region's pages were just taken from the buddy, so
        // nothing else references them, and the direct map covers all RAM
        // since Phase 3 but the kernel-stack guard pages (`mm::stack_guard`), none of them
        // a free buddy page. Zeroed here, before the drain and the descriptors are
        // written into it, so the header and every unused slot reach init as
        // zeroes.
        unsafe {
            core::ptr::write_bytes(block, 0, pages * crate::mm::PAGE_SIZE);
        }
        // SAFETY: the header fits the region's first page, so the array start
        // lies inside the region.
        let array = unsafe { block.add(core::mem::size_of::<init_protocol::InitInfo>()) };
        // cast_ptr_alignment: the region is page-aligned and the header's size
        // is a multiple of the descriptor alignment (asserted at
        // INIT_INFO_DESCRIPTOR_CAPACITY), so the array start is aligned.
        #[allow(clippy::cast_ptr_alignment)]
        DESCRIPTOR_ARRAY.store(
            array.cast::<CapDescriptor>(),
            core::sync::atomic::Ordering::Relaxed,
        );
    });
}

/// Physical base and page count of the pre-reserved `InitInfo` region.
/// Single consumption: returns them and clears the base.
#[cfg(not(test))]
pub(crate) fn take_init_info_block() -> (u64, usize)
{
    // The block goes to init now, so the descriptor array is retired with it:
    // a later `descriptor_array()` halts, naming the array's lifetime (its
    // Phase 7 reservation to this Phase 9 hand-off), instead of writing into
    // it.
    DESCRIPTOR_ARRAY.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Relaxed);
    let phys = INIT_INFO_BLOCK_PHYS.swap(0, core::sync::atomic::Ordering::Relaxed);
    debug_assert!(phys != 0, "InitInfo block consumed before it was reserved");
    (
        phys,
        INIT_INFO_BLOCK_PAGES.load(core::sync::atomic::Ordering::Relaxed),
    )
}

/// Physical base of init's pre-reserved user-stack page `i` (`i <
/// INIT_STACK_PAGES`). Single consumption per page.
#[cfg(not(test))]
pub(crate) fn init_stack_phys(i: usize) -> u64
{
    let phys = INIT_STACK_PHYS[i].swap(0, core::sync::atomic::Ordering::Relaxed);
    debug_assert!(phys != 0, "init stack page consumed before it was reserved");
    phys
}

/// Drain user-cap RAM from the buddy as coalesced extents and install
/// [`SEED_MEMORY`] at the base of the largest, reserving its first
/// [`seed_reserve_bytes`] for kernel-internal cap-identity storage. Zeroes
/// every user-exposed extent (each drained extent, and the seed extent's tail
/// past the reserve) through the direct map, which also clears the buddy's
/// free-block links, and leaves the extents in the first slots of the
/// `InitInfo` descriptor array, one per slot as a `Memory` descriptor with
/// its base and size and no cap slot yet, returning their count;
/// `populate_cspace` mints a Memory cap per extent and completes each slot's
/// descriptor in place.
///
/// Before draining, seeds [`crate::mm::kernel_pt_pool`] and reserves init's
/// Phase-9 backing (the user stack, then the `InitInfo` block sized from the
/// buddy's extent count and `counts`) from the pristine buddy, so the drain
/// takes 100% of the remaining RAM and the post-handoff buddy is empty. The
/// pool is the cap-backed source for intermediate page-table frames on the
/// kernel-side Phase-9 bootstrap maps.
///
/// MUST run before any [`mint_phase7_body`] / [`boot_retype_aspace`] /
/// [`boot_retype_cspace`] call against the seed, before Phase 9's
/// `retype_allocate` of init's Thread slab, and before any `map_user_page`
/// consumer (the kernel PT pool must be live before Phase 9's init bootstrap
/// maps run).
///
/// # Safety
/// Single-threaded Phase 7. Buddy active.
#[cfg(not(test))]
pub(crate) unsafe fn drain_and_install_seed(counts: &DescriptorCounts) -> usize
{
    use crate::mm::buddy::PAGE_SIZE as BUDDY_PAGE_SIZE;

    let cpu_count = crate::sched::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;

    // Reserve every page Phase 9 consumes after the drain — the kernel
    // PT-frame pool, init's user stack and InitInfo block — from the pristine
    // buddy first, the InitInfo block last so the extent count it is sized
    // from already reflects the others. With those out of the way the drain
    // takes 100% of the remainder, so the post-handoff buddy free count
    // reaches 0. The PT pool must also be live before Phase 9's first
    // bootstrap map, which holds.
    // SAFETY: single-threaded Phase 7 with no other pool consumer live yet,
    // so the unlocked init has exclusive access.
    unsafe {
        crate::mm::kernel_pt_pool::init(POOL_SEED_PAGES);
    }
    reserve_init_backing(counts);
    let reserve_pages = kernel_reserve_pages();

    crate::kprintln!(
        "Phase 7: kernel reserve {} pages = pool {} + idle {}×{} + guard tables {} + \
         initinfo {} + initstack {} + seed {} KiB; draining all remaining RAM to userspace",
        reserve_pages,
        POOL_SEED_PAGES,
        cpu_count,
        crate::sched::KERNEL_STACK_PAGES + 1,
        crate::mm::stack_guard::seeded_frames(),
        INIT_INFO_BLOCK_PAGES.load(core::sync::atomic::Ordering::Relaxed),
        INIT_STACK_PAGES,
        seed_reserve_bytes() / 1024,
    );
    // SAFETY: single-threaded Phase 7; the array was pointed at the block
    // `reserve_init_backing` just reserved, and nothing else borrows it.
    let out = unsafe { descriptor_slots_mut() };
    let drained = crate::mm::with_frame_allocator(|alloc| {
        // Each extent fills one descriptor slot, as the Memory descriptor
        // `populate_cspace` completes in place.
        let drained = alloc.drain_coalesced(out.len(), |i, base, size| {
            out[i] = CapDescriptor {
                slot: 0,
                cap_type: init_protocol::CapType::Memory,
                pad: [0; 3],
                aux0: base,
                aux1: size,
            };
        });
        // The drain emptied the buddy; seal it. memmgr owns all dynamic RAM
        // from here. A later free into the buddy (a destroyed `owns_memory`
        // cap) is an accounting violation that the seal trips.
        alloc.seal();
        drained
    });
    // The one capacity check the in-place mint relies on: every extent has
    // its own slot, so `populate_cspace` can complete descriptor i over
    // extent i (see there). Later descriptors fail in `push_descriptor`.
    let extent_count = drained.unwrap_or_else(|overflow| {
        crate::kprintln!(
            "Phase 7: drain yielded {} RAM extents; the InitInfo block holds {} descriptors",
            overflow.extents,
            descriptor_capacity()
        );
        crate::fatal("Phase 7: drained RAM extents exceed the InitInfo descriptor capacity")
    });

    if extent_count == 0
    {
        crate::fatal("Phase 7: no drained RAM extents to seed Memory caps");
    }

    // The largest extent hosts the seed; every other extent is exposed
    // verbatim.
    let (seed_idx, seed_base, seed_extent_size) = out[..extent_count]
        .iter()
        .enumerate()
        .map(|(i, d)| (i, d.aux0, d.aux1))
        .max_by_key(|&(_, _, size)| size)
        .unwrap_or_else(|| crate::fatal("Phase 7: no drained RAM extents to seed Memory caps"));
    if seed_extent_size <= seed_reserve_bytes()
    {
        crate::fatal("Phase 7: largest drained RAM extent too small to host the seed reserve");
    }

    // SAFETY: first and only call; single-threaded Phase 7.
    unsafe { install_seed_memory(seed_base) };
    // Seed-tail: the front `seed_reserve_bytes()` bytes go to the SEED's pool
    // (kernel-internal); the remainder is exposed as a virgin RAM Memory cap.
    out[seed_idx].aux0 = seed_base + seed_reserve_bytes();
    out[seed_idx].aux1 = seed_extent_size - seed_reserve_bytes();

    let mut drained_pages: u64 = seed_reserve_bytes() / BUDDY_PAGE_SIZE as u64;
    let zero_start_us = crate::arch::current::timer::elapsed_us().unwrap_or(0);
    // The seed reserve is zeroed too, so no free-block link or firmware
    // leftover survives anywhere in the drained RAM.
    // SAFETY: the reserve is the front of an extent just drained from the
    // buddy, and nothing has been retyped from the seed yet; the direct map
    // covers all RAM since Phase 3 but the kernel-stack guard pages (`mm::stack_guard`), none of
    // them a drained page; single-threaded Phase 7.
    unsafe {
        core::ptr::write_bytes(
            phys_to_virt(seed_base) as *mut u8,
            0,
            seed_reserve_bytes() as usize,
        );
    }
    for &CapDescriptor {
        aux0: base,
        aux1: size,
        ..
    } in &out[..extent_count]
    {
        drained_pages += size / BUDDY_PAGE_SIZE as u64;
        // Zero the user-exposed extent before it is minted: free RAM still
        // holds whatever firmware and the bootloader left in it, the UEFI
        // stack with the slid kernel layout among it, and the buddy's
        // free-block links (core/kernel/docs/cross-boundary-disclosure.md
        // § Kernel state in donated memory).
        // SAFETY: the extent is free RAM just drained from the buddy (or the
        // seed extent's tail), so nothing references it; the direct map
        // covers all RAM since Phase 3 but the kernel-stack guard pages (`mm::stack_guard`), none of
        // them a drained page; single-threaded Phase 7.
        unsafe { core::ptr::write_bytes(phys_to_virt(base) as *mut u8, 0, size as usize) };
    }
    let zero_us = crate::arch::current::timer::elapsed_us()
        .unwrap_or(0)
        .saturating_sub(zero_start_us);

    let coalesced = promote_largest_extent(&mut out[..extent_count], |d| d.aux1);

    crate::kprintln!(
        "Phase 7: drained {} pages as {} contiguous regions (zeroed in {} us); \
         seed reserve {} KiB",
        drained_pages,
        coalesced,
        zero_us,
        seed_reserve_bytes() / 1024,
    );

    let pool_remaining = crate::mm::kernel_pt_pool::remaining_pages();
    crate::kprintln!("kernel_pt_pool: {pool_remaining} pages installed");

    coalesced
}

/// Move the largest drained RAM extent to index 0 so `populate_cspace`
/// assigns it to `memory_base`; returns `extents.len()`.
///
/// The buddy drain (`BuddyAllocator::drain_coalesced`) returns maximal
/// contiguous extents in address order, so the lowest-address (possibly
/// small) fragment would otherwise become `memory_base`. ktest (`frame_pool`,
/// `fund_boot_aspace_pt`, and the retype-heavy stress tests) bump-allocates
/// every kernel object it creates from `memory_base`, so it must be the large
/// cap. Strict `>` keeps the earliest extent on ties. Consumers that take the
/// whole range (init, memmgr) read each cap's size/base individually and do
/// not depend on the order.
fn promote_largest_extent<T>(extents: &mut [T], size: impl Fn(&T) -> u64) -> usize
{
    let mut largest = 0usize;
    for i in 1..extents.len()
    {
        if size(&extents[i]) > size(&extents[largest])
        {
            largest = i;
        }
    }
    if !extents.is_empty()
    {
        extents.swap(0, largest);
    }
    extents.len()
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
/// exhaustion (boot cannot recover).
///
/// # Safety
///
/// Single-threaded boot (Phase 9). `seed` must be the SEED installed by
/// [`drain_and_install_seed`]; `init_pages >= 2`.
#[cfg(not(test))]
pub(crate) unsafe fn boot_retype_aspace(
    seed: &object::MemoryObject,
    init_pages: u64,
) -> (
    NonNull<object::KernelObjectHeader>,
    *mut crate::mm::address_space::AddressSpace,
)
{
    use crate::cap::object::{AddressSpaceObject, KernelObjectHeader, ObjectType, PagePool};
    use crate::mm::PAGE_SIZE;
    use crate::mm::address_space::AddressSpace;
    use crate::mm::paging::phys_to_virt;
    use core::sync::atomic::AtomicU64;

    debug_assert!(init_pages >= 2);

    let bytes = init_pages * PAGE_SIZE as u64;
    let Ok(offset) = retype::retype_allocate(seed, bytes)
    else
    {
        crate::fatal("boot_retype_aspace: seed Memory cap too small");
    };
    let memory_base = seed.base;
    let wrapper_phys = memory_base + offset;
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
    // SAFETY: aspace_ptr is derived from the wrapper page's pointer and the
    // AddressSpace just written is the last thing in that page, which holds
    // its active-CPU words (ACTIVE_CPU_WORDS_FIT); nothing else references it
    // and no CPU has it active.
    unsafe { AddressSpace::attach_active_cpus(aspace_ptr) };

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
                pt_pool: PagePool::new(),
                deferred_next: core::ptr::null_mut(),
            },
        );
    }

    seed.header.inc_ref();

    let pool_pages = init_pages - 2;
    // SAFETY: aso_ptr just constructed; offset/init_pages from a successful retype.
    let res = unsafe {
        (*aso_ptr).add_donation(
            seed_header_nn(),
            memory_base,
            offset,
            init_pages,
            pool_pages,
        )
    };
    if res.is_err()
    {
        crate::fatal("boot_retype_aspace: donation not recorded");
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
/// exhaustion.
///
/// # Safety
///
/// Single-threaded Phase 7. `seed` must be the SEED installed by
/// [`drain_and_install_seed`]; `init_pages >= 1`; `id` freshly allocated by
/// [`alloc_cspace_id`] and not yet registered.
#[cfg(not(test))]
pub(crate) unsafe fn boot_retype_cspace(
    seed: &object::MemoryObject,
    init_pages: u64,
    id: CSpaceId,
) -> (NonNull<object::KernelObjectHeader>, *mut cspace::CSpace)
{
    use crate::cap::cspace::CSpace;
    use crate::cap::object::{CSpaceKernelObject, KernelObjectHeader, ObjectType};
    use crate::mm::PAGE_SIZE;
    use crate::mm::paging::phys_to_virt;

    debug_assert!(init_pages >= 1);

    let bytes = init_pages * PAGE_SIZE as u64;
    let Ok(offset) = retype::retype_allocate(seed, bytes)
    else
    {
        crate::fatal("boot_retype_cspace: seed Memory cap too small");
    };
    let memory_base = seed.base;
    let wrapper_phys = memory_base + offset;
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
    unsafe { core::ptr::write(cs_ptr, CSpace::new(id)) };

    // SAFETY: cs_kobj_ptr is page-aligned and exclusively owned.
    unsafe {
        core::ptr::write(
            cs_kobj_ptr,
            CSpaceKernelObject::new(
                KernelObjectHeader::with_ancestor(ObjectType::CSpaceObj, seed_header_nn()),
                cs_ptr,
            ),
        );
    }
    // SAFETY: cs_ptr just constructed.
    unsafe { (*cs_ptr).set_kobj(cs_kobj_ptr) };
    seed.header.inc_ref();

    let pool_pages = init_pages - 1;
    // SAFETY: wrapper just constructed; offset/init_pages from a successful retype.
    let res = unsafe {
        (*cs_kobj_ptr).add_donation(
            seed_header_nn(),
            memory_base,
            offset,
            init_pages,
            pool_pages,
        )
    };
    if res.is_err()
    {
        crate::fatal("boot_retype_cspace: donation not recorded");
    }

    // SAFETY: cs_kobj_ptr is in-place; header at offset 0.
    let nonnull = unsafe { NonNull::new_unchecked(cs_kobj_ptr.cast::<KernelObjectHeader>()) };
    (nonnull, cs_ptr)
}

/// Phase-7 mint helper: in production, retype `body` in place inside the
/// seed Memory cap and bump the seed's refcount; in tests, leak `body` via
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
        crate::cap::retype::boot_retype_body(seed_memory_ref(), body)
    }
    #[cfg(test)]
    {
        nonnull_from_box(Box::new(body))
    }
}

// ── CSpace layout ────────────────────────────────────────────────────────────

/// Describes the `CSpace` slot layout after Phase 7 population.
///
/// Returned by [`init_capability_system`] so Phase 9 can populate the
/// [`InitInfo`](init_protocol::InitInfo) page without re-scanning the `CSpace`.
pub struct CSpaceLayout
{
    /// First slot index of usable memory `Memory` capabilities.
    pub memory_base: u32,
    /// Number of usable memory `Memory` capabilities.
    pub memory_count: u32,
    /// First slot index of the `Mmio` capabilities (RISC-V console UART, then
    /// one per validated aperture).
    pub hw_cap_base: u32,
    /// Number of `Mmio` capabilities.
    pub hw_cap_count: u32,
    /// Slot index of the `SchedControl` capability.
    pub sched_control_slot: u32,
    /// Slot index of the `SbiControl` capability (RISC-V only; 0 on x86-64).
    pub sbi_control_slot: u32,
    /// Slot index of the root `Interrupt` range capability (always minted,
    /// covering `ROOT_IRQ_COUNT` ids).
    pub irq_range_slot: u32,
    /// Slot index of the RO `Memory` cap covering the ACPI RSDP page.
    /// Zero if `BootInfo.acpi_rsdp` is zero.
    pub acpi_rsdp_memory_slot: u32,
    /// First slot index of the RO `Memory` caps covering the
    /// `AcpiReclaimable` regions from the boot memory map.
    pub acpi_region_memory_base: u32,
    /// Number of ACPI reclaimable-region `Memory` caps.
    pub acpi_region_memory_count: u32,
    /// Slot index of the RO `Memory` cap covering the DTB blob.
    /// Zero if `BootInfo.device_tree` is zero.
    pub dtb_memory_slot: u32,
    /// Total number of populated slots.
    pub total_populated: usize,
    /// Number of valid entries in the `InitInfo` descriptor array for this
    /// layout. Use [`descriptors`] to obtain the slice.
    pub descriptor_count: usize,
    /// Number of populated [`InitModuleName`] entries in
    /// [`Self::module_names`]. Capped at
    /// [`init_protocol::INIT_MAX_NAMED_MODULES`].
    pub module_name_count: u32,
    /// Module-name → cap-slot table mirroring
    /// [`init_protocol::InitInfo::module_names`]. Populated by
    /// `mint_module_memory_caps` and written verbatim into the
    /// `InitInfo` header by Phase 9.
    pub module_names: [init_protocol::InitModuleName; init_protocol::INIT_MAX_NAMED_MODULES],
}

/// Start of the `InitInfo` descriptor array: the reserved `InitInfo` block's
/// bytes past the header, [`descriptor_capacity`] slots, set by
/// `reserve_init_backing` at Phase 7. Phases 7 and 8 write every boot
/// capability's descriptor there, the buddy drain's RAM extents first (in the
/// slots their descriptors take), and Phase 9 writes the header in front of
/// them, so no copy of the array exists; after hand-off it is init's, and
/// `take_init_info_block` nulls this pointer.
#[cfg(not(test))]
static DESCRIPTOR_ARRAY: core::sync::atomic::AtomicPtr<CapDescriptor> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Host-test stand-in for the `InitInfo` descriptor array.
#[cfg(test)]
static mut TEST_DESCRIPTOR_ARRAY: [CapDescriptor; TEST_DESCRIPTOR_CAPACITY] = [CapDescriptor {
    slot: 0,
    cap_type: init_protocol::CapType::Memory,
    pad: [0; 3],
    aux0: 0,
    aux1: 0,
};
    TEST_DESCRIPTOR_CAPACITY];

/// The descriptor array's first slot.
fn descriptor_array() -> *mut CapDescriptor
{
    #[cfg(not(test))]
    {
        let p = DESCRIPTOR_ARRAY.load(core::sync::atomic::Ordering::Relaxed);
        if p.is_null()
        {
            crate::fatal(
                "cap: InitInfo descriptor array used before Phase 7 reserves it or after Phase 9 \
                 hands it to init",
            );
        }
        p
    }
    #[cfg(test)]
    {
        core::ptr::addr_of_mut!(TEST_DESCRIPTOR_ARRAY).cast::<CapDescriptor>()
    }
}

/// The whole descriptor array, mutably.
///
/// # Safety
/// Single-threaded boot; no other reference to the array is live while the
/// returned one is.
#[cfg(not(test))]
unsafe fn descriptor_slots_mut() -> &'static mut [CapDescriptor]
{
    // SAFETY: the array spans descriptor_capacity() slots of the reserved
    // block; caller contract for exclusivity.
    unsafe { core::slice::from_raw_parts_mut(descriptor_array(), descriptor_capacity()) }
}

/// Borrow the descriptor slice for the supplied [`CSpaceLayout`]: the first
/// `layout.descriptor_count` slots of the `InitInfo` descriptor array.
///
/// # Safety
/// `layout.descriptor_count` must reflect the entries written by the
/// `populate_cspace`, `mint_module_memory_caps`, and
/// `mint_reclaim_memory_caps` writers that produced `layout`.
/// Single-threaded boot guarantees no concurrent writer.
pub unsafe fn descriptors(layout: &CSpaceLayout) -> &'static [CapDescriptor]
{
    debug_assert!(layout.descriptor_count <= descriptor_capacity());
    // SAFETY: see function-level doc; the first descriptor_count slots are
    // written and nothing writes them while the slice lives.
    unsafe { core::slice::from_raw_parts(descriptor_array(), layout.descriptor_count) }
}

/// Running total of `owns_memory = true` `Memory` cap bytes minted into
/// init's root `CSpace`. These pages are the reclaimable complement of the
/// fixed kernel reserve; `kernel_reserved_bytes = system_ram - this`.
/// Single-threaded boot, so a relaxed atomic suffices.
static OWNS_MEMORY_MINTED_BYTES: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Record `bytes` of a newly-minted `owns_memory` `Memory` cap toward the
/// minted-to-init ledger. Called at every Phase 7, 8 and 9 mint site.
pub(crate) fn note_owns_memory_minted(bytes: u64)
{
    OWNS_MEMORY_MINTED_BYTES.fetch_add(bytes, core::sync::atomic::Ordering::Relaxed);
}

/// Total `owns_memory` `Memory` cap bytes minted to init.
#[must_use]
pub(crate) fn owns_memory_minted_bytes() -> u64
{
    OWNS_MEMORY_MINTED_BYTES.load(core::sync::atomic::Ordering::Relaxed)
}

/// Write `desc` to slot `*count` of the `InitInfo` descriptor array and bump
/// the count. Halts the boot, naming the capacity, when the array is full: the
/// boot describes at most [`descriptor_capacity`] capabilities, in
/// Phases 7 and 8.
fn push_descriptor(count: &mut usize, desc: CapDescriptor)
{
    if *count >= descriptor_capacity()
    {
        crate::kprintln!(
            "cap: the boot capabilities exceed the {} descriptors the InitInfo block holds",
            descriptor_capacity()
        );
        crate::fatal("cap: boot capabilities exceed the InitInfo descriptor capacity");
    }
    // SAFETY: single-threaded boot; `*count` is in bounds (checked above) and
    // the only writer index; no reference to the slot is live.
    unsafe { descriptor_array().add(*count).write(desc) };
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
/// Preconditions: called exactly once, single-threaded, after Phase 4
/// (per-CPU storage allocated) and Phase 3 (direct map active).
pub fn init_capability_system(
    mmio_apertures: crate::platform::ValidatedApertures,
    boot_info_phys: u64,
) -> CSpaceLayout
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
    // 1. Drain the buddy + install SEED_MEMORY (largest extent hosts the seed
    //    reserve; remainder exposed as the seed-tail cap).
    // 2. Boot-retype the root CSpace from SEED into a typed-memory slab.
    // 3. populate_cspace fills the root with Memory caps (from the drained
    //    blocks) plus all hardware-resource caps.
    // 4. mint_module_memory_caps appends boot-module Memory caps.
    // 5. mint_reclaim_memory_caps appends reclaimable bootloader-scratch
    //    Memory caps (BootInfo, descriptor arrays, transient PT frames).
    // 6. Stash the root CSpace pointer; Phase 9 hands it to init.
    #[cfg(not(test))]
    {
        let counts = DescriptorCounts::of(mmap, &mmio_apertures, info);
        // SAFETY: first call; single-threaded Phase 7.
        let ram_extents = unsafe { drain_and_install_seed(&counts) };

        let id = alloc_cspace_id()
            .unwrap_or_else(|| crate::fatal("root CSpace: alloc_cspace_id exhausted at boot"));
        debug_assert_eq!(
            id, 0,
            "root CSpace must receive id 0 (free list empty at boot)"
        );
        // SAFETY: SEED installed above.
        let (_cs_kobj_nn, cs_ptr) =
            unsafe { boot_retype_cspace(seed_memory_ref(), root_cspace_init_pages(), id) };
        // Nothing mints a `SlotId` from the epoch here: Phase 9 reads it
        // back with `registry_epoch` for init's TCB, so the returned value
        // is discarded.
        let _root_epoch = register_cspace(id, cs_ptr).unwrap_or_else(|()| {
            crate::fatal("root CSpace register: no registry chunk backs id 0")
        });

        // SAFETY: cs_ptr is freshly constructed and exclusively owned
        // (single-threaded Phase 7).
        let cspace = unsafe { &mut *cs_ptr };
        let mut layout = populate_cspace(cspace, ram_extents, mmap, mmio_apertures, info);
        mint_module_memory_caps(cspace, info, &mut layout);
        mint_reclaim_memory_caps(cspace, info, &mut layout);

        // SAFETY: single-threaded boot; ROOT_CSPACE not yet observed.
        unsafe { ROOT_CSPACE = cs_ptr };

        layout
    }

    // ── Test path ─────────────────────────────────────────────────────────
    // Tests don't exercise the SEED / boot-retype machinery (no buddy, no
    // direct map, no MemoryObject lifecycle in the test stub). They allocate
    // a heap-backed CSpace and let `populate_cspace`'s test-only RAM-mint
    // branch iterate `mmap` directly, with no drained extents.
    #[cfg(test)]
    {
        let id = alloc_cspace_id().expect("root CSpace: alloc_cspace_id exhausted at boot");
        let mut cspace = Box::new(CSpace::new(id));
        let mut layout = populate_cspace(&mut cspace, 0, mmap, mmio_apertures, info);
        mint_module_memory_caps(&mut cspace, info, &mut layout);
        mint_reclaim_memory_caps(&mut cspace, info, &mut layout);
        // Tests intentionally leak the box; isolated unit-test invariants
        // (every kernel object Boxed via `nonnull_from_box`) make explicit
        // teardown unnecessary.
        let _ = cspace;
        layout
    }
}

/// Mint a read-only Memory cap over each `AcpiReclaimable` region of `mmap`
/// (userspace parses XSDT / MADT / MCFG through them), in consecutive slots,
/// with a descriptor each, handed to `record`. Returns the run's first slot
/// and its length, the `CSpaceLayout`'s `acpi_region_memory_base` and
/// `acpi_region_memory_count`.
///
/// There is one cap per region, however many the map reports, and a root
/// `CSpace` or descriptor array they overflowed
/// ([`descriptor_capacity`]) would halt the boot with a message
/// rather than drop tables.
fn mint_acpi_region_caps(
    cspace: &mut CSpace,
    mmap: &[MemoryMapEntry],
    mut record: impl FnMut(CapDescriptor),
) -> (u32, u32)
{
    let mut base: u32 = 0;
    let mut count: u32 = 0;
    for entry in mmap
    {
        if entry.memory_type != MemoryType::AcpiReclaimable
        {
            continue;
        }
        // UEFI memory map entries are page-aligned per UEFI spec §7.2,
        // but mask defensively to uphold MemoryObject's alignment invariant.
        let aligned_base = entry.physical_base & !0xFFF;
        let size = (entry.physical_base - aligned_base + entry.size + 0xFFF) & !0xFFF;
        if size == 0
        {
            continue;
        }
        let ptr = mint_phase7_body(firmware_table_memory(aligned_base, size));
        let slot = insert_or_fatal(
            cspace,
            MemRights::MAP,
            ptr,
            "Phase 7: cannot allocate Memory capability for ACPI region",
        );
        extend_slot_run_or_fatal(
            &mut base,
            count,
            slot,
            "Phase 7: ACPI region Memory caps are not in consecutive slots",
        );
        record(CapDescriptor {
            slot,
            cap_type: init_protocol::CapType::Memory,
            pad: [0; 3],
            aux0: aligned_base,
            aux1: size,
        });
        count += 1;
    }
    (base, count)
}

/// The body of a read-only Memory cap over the firmware table at
/// `[base, base + size)`: not retypable, and not buddy-backed.
fn firmware_table_memory(base: u64, size: u64) -> MemoryObject
{
    MemoryObject {
        header: KernelObjectHeader::with_ancestor(ObjectType::Memory, seed_header_nn()),
        base,
        size,
        // Firmware table: not retypable; cap minted without RETYPE.
        available_bytes: core::sync::atomic::AtomicU64::new(0),
        // Firmware-reserved memory; not buddy-backed.
        owns_memory: core::sync::atomic::AtomicBool::new(false),
        allocator: crate::cap::retype::RetypeAllocator::new_inline(),
        lock: AtomicU32::new(0),
    }
}

/// Complete the RAM Memory descriptors in place. `extents` are the first
/// descriptor slots, each holding a drained RAM extent as the buddy drain
/// left it (`drain_and_install_seed`); `mint(base, size)` mints that
/// extent's cap and returns its descriptor, which is written over the
/// extent. Each extent is read whole into locals before its own slot is
/// written, and slot i holds both extent i and descriptor i, so every
/// extent not yet read lies in a slot above the one being written.
fn complete_extent_descriptors(
    extents: &mut [CapDescriptor],
    mut mint: impl FnMut(u64, u64) -> CapDescriptor,
)
{
    for slot in extents
    {
        let CapDescriptor {
            aux0: base,
            aux1: size,
            ..
        } = *slot;
        *slot = mint(base, size);
    }
}

/// Core `CSpace` population logic, separated for testability.
///
/// Creates one capability per usable memory region, one `Mmio`
/// capability per MMIO aperture, and one `SchedControl` capability (plus
/// the arch-specific root `IoPort` on x86-64 and `SbiControl` on
/// RISC-V). Returns a [`CSpaceLayout`] describing the slot ranges and
/// per-cap descriptors.
// too_many_lines: one logical pass over all boot-time resource types; splitting
// would require threading shared state (cspace) through multiple helper functions.
#[allow(clippy::too_many_lines)]
fn populate_cspace(
    cspace: &mut CSpace,
    ram_extents: usize,
    mmap: &[MemoryMapEntry],
    mmio_apertures: crate::platform::ValidatedApertures,
    info: &BootInfo,
) -> CSpaceLayout
{
    use init_protocol::CapType;

    /// Width of the root `Interrupt` range cap minted at Phase 7 — the per-arch
    /// interrupt id space (`arch::current::ROOT_IRQ_COUNT`: 32768 GSIs on x86-64,
    /// `MAX_IOAPICS` (128) I/O APICs of 256 pins; on RISC-V the PLIC's 1024-entry id space,
    /// sources 1-1023). `SYS_IRQ_REGISTER` refuses an id no discovered controller
    /// implements, and the routing table ignores one past its discovered size,
    /// so oversizing is safe.
    const ROOT_IRQ_COUNT: u32 = crate::arch::current::ROOT_IRQ_COUNT;

    // Descriptor entries land in the InitInfo descriptor array; this counter
    // tracks how many have been written.
    //
    // ORDER: the RAM Memory caps are minted first, one per drained extent and
    // in slot order (the drain's, with the largest extent promoted to slot 0),
    // with nothing minted between them, because the drain left extent i in
    // descriptor slot i (`drain_and_install_seed`) and descriptor i is written
    // over it. Minting anything before them, or between them, would
    // overwrite extents not yet read.
    let mut desc_count: usize = 0;

    // Usable physical memory → Memory caps with MAP | WRITE | EXECUTE | RETYPE
    // (rights policy and the mapping-time W^X rule: docs/capability-model.md § Memory).
    //
    // Memory caps are allocated FROM the buddy allocator so the same
    // physical pages are not double-booked between the kernel's internal
    // frame pool and userspace capabilities.
    // Initialised to 0, the value reported when no RAM Memory cap is minted;
    // both builds overwrite `memory_base` at their first mint
    // (`if memory_count == 0`) and increment `memory_count` per mint.
    let mut memory_base: u32 = 0;
    let mut memory_count: u32 = 0;

    #[cfg(not(test))]
    {
        let seed_anc = seed_header_nn();

        // Mint one Memory cap per drained RAM extent. The drain left the
        // extents, already resolved, in the first `ram_extents` descriptor
        // slots (`drain_and_install_seed`): the seed extent contributes only
        // its post-reserve tail; every other extent contributes its full
        // size. SEED itself is never inserted into the CSpace — it's pure
        // kernel-internal storage.
        //
        // In place (`complete_extent_descriptors`): these are the first
        // descriptors (ORDER above), so descriptor slot i is extent slot i.
        debug_assert_eq!(desc_count, 0, "RAM descriptors are not the first");
        // SAFETY: single-threaded Phase 7; the drain filled the first
        // ram_extents <= descriptor_capacity() slots, and no other
        // reference to the array is live while this one is.
        let extents = unsafe { &mut descriptor_slots_mut()[..ram_extents] };
        complete_extent_descriptors(extents, |cap_base, cap_size| {
            let ptr = mint_phase7_body(MemoryObject {
                header: KernelObjectHeader::with_ancestor(ObjectType::Memory, seed_anc),
                base: cap_base,
                size: cap_size,
                // Full retypable budget: this cap covers virgin RAM. The
                // seed's ledger only debits for the MemoryObject body bytes.
                available_bytes: core::sync::atomic::AtomicU64::new(cap_size),
                // Drained RAM: `owns_memory` marks this cap as the range's owner.
                // It routes to memmgr, which never destroys it; a free into the
                // sealed buddy is an accounting violation
                // (docs/userspace-memory-model.md § Ownership Boundaries). The
                // seed's own `seed_reserve_bytes()` prefix is owned by the pinned
                // SEED_MEMORY.
                owns_memory: core::sync::atomic::AtomicBool::new(true),
                allocator: crate::cap::retype::RetypeAllocator::new_inline(),
                lock: core::sync::atomic::AtomicU32::new(0),
            });
            let slot = insert_or_fatal(
                cspace,
                MemRights::MAP | MemRights::WRITE | MemRights::EXECUTE | MemRights::RETYPE,
                ptr,
                "Phase 7: cannot allocate Memory capability for usable memory",
            );
            extend_slot_run_or_fatal(
                &mut memory_base,
                memory_count,
                slot,
                "Phase 7: RAM Memory caps are not in consecutive slots",
            );
            note_owns_memory_minted(cap_size);
            memory_count += 1;
            CapDescriptor {
                slot,
                cap_type: CapType::Memory,
                pad: [0; 3],
                aux0: cap_base,
                aux1: cap_size,
            }
        });
        desc_count = ram_extents;

        crate::kprintln!(
            "Phase 7: {} Memory caps minted from {} drained RAM blocks",
            memory_count,
            ram_extents,
        );
    }
    #[cfg(test)]
    let _ = ram_extents;

    // Test builds: create Memory caps directly from mmap entries (no buddy).
    #[cfg(test)]
    for entry in mmap
    {
        if entry.memory_type != MemoryType::Usable
        {
            continue;
        }
        // MemoryObject invariant: page-aligned base, whole-page size.
        let aligned_base = entry.physical_base & !0xFFF_u64;
        let aligned_size = (entry.physical_base - aligned_base + entry.size + 0xFFF) & !0xFFF_u64;
        let obj = Box::new(MemoryObject {
            header: KernelObjectHeader::new(ObjectType::Memory),
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
            MemRights::MAP | MemRights::WRITE | MemRights::EXECUTE | MemRights::RETYPE,
            ptr,
            "Phase 7: cannot allocate Memory capability for usable memory",
        );
        extend_slot_run_or_fatal(
            &mut memory_base,
            memory_count,
            slot,
            "Phase 7: RAM Memory caps are not in consecutive slots",
        );
        push_descriptor(
            &mut desc_count,
            CapDescriptor {
                slot,
                cap_type: CapType::Memory,
                pad: [0; 3],
                aux0: aligned_base,
                aux1: aligned_size,
            },
        );
        memory_count += 1;
    }

    // MMIO apertures → one Mmio cap each, MAP | WRITE. Init is root
    // authority and holds these coarse caps until userspace narrows them
    // (via `mmio_split`) and delegates device-sized sub-caps to drivers.
    //
    // On RISC-V the kernel's UART MMIO range is advertised via
    // `BootInfo.kernel_mmio.uart_base` rather than the coarse aperture
    // list. The UART range can also lie inside an aperture (the boot
    // loader's riscv64 platform defaults and DTB `ns16550a` seeds cover it),
    // so this cap may overlap an aperture cap. Synthesise an extra
    // Mmio cap here so userspace init has a cap for it — init's
    // serial scan looks for the Mmio descriptor containing its fixed
    // `UART_PHYS` (services/init/src/arch/riscv64/mod.rs).
    let mut hw_cap_base: u32 = 0;
    let mut hw_cap_count: u32 = 0;

    if let Some((uart_base, uart_size)) = crate::arch::current::platform::console_mmio()
    {
        let ptr = mint_phase7_body(MmioObject::new_root(uart_base, uart_size, 0));
        let slot = insert_or_fatal(
            cspace,
            MmioRights::MAP | MmioRights::WRITE,
            ptr,
            "Phase 7: cannot allocate Mmio capability for console UART",
        );
        extend_slot_run_or_fatal(
            &mut hw_cap_base,
            hw_cap_count,
            slot,
            "Phase 7: hardware caps are not in consecutive slots",
        );
        hw_cap_count += 1;
        push_descriptor(
            &mut desc_count,
            CapDescriptor {
                slot,
                cap_type: CapType::Mmio,
                pad: [0; 3],
                aux0: uart_base,
                aux1: uart_size,
            },
        );
    }

    for ap in mmio_apertures.iter()
    {
        let ptr = mint_phase7_body(MmioObject::new_root(ap.phys_base, ap.size, 0));
        let slot = insert_or_fatal(
            cspace,
            MmioRights::MAP | MmioRights::WRITE,
            ptr,
            "Phase 7: cannot allocate Mmio capability for aperture",
        );
        extend_slot_run_or_fatal(
            &mut hw_cap_base,
            hw_cap_count,
            slot,
            "Phase 7: hardware caps are not in consecutive slots",
        );
        push_descriptor(
            &mut desc_count,
            CapDescriptor {
                slot,
                cap_type: CapType::Mmio,
                pad: [0; 3],
                aux0: ap.phys_base,
                aux1: ap.size,
            },
        );
        hw_cap_count += 1;
    }

    // One root SchedControl capability spanning the full userspace priority
    // range. Holding it (plus its band) is the authority to assign priorities
    // in that band; init narrows it with `SYS_SCHED_SPLIT` and delegates
    // baseline bands to services. Presence-only — no rights bit.
    let ptr = mint_phase7_body(SchedControlObject {
        header: KernelObjectHeader::with_ancestor(ObjectType::SchedControl, seed_header_nn()),
        min: syscall::PRIORITY_MIN,
        max: syscall::PRIORITY_MAX,
    });
    let sched_control_slot = insert_or_fatal(
        cspace,
        SchedRights::NONE,
        ptr,
        "Phase 7: cannot allocate SchedControl capability",
    );
    push_descriptor(
        &mut desc_count,
        CapDescriptor {
            slot: sched_control_slot,
            cap_type: CapType::SchedControl,
            pad: [0; 3],
            aux0: u64::from(syscall::PRIORITY_MIN),
            aux1: u64::from(syscall::PRIORITY_MAX),
        },
    );

    // Root Interrupt range capability — covers every valid IRQ source on
    // this arch. Userspace narrows it to single-IRQ children via
    // `SYS_IRQ_SPLIT` and delegates one per device.
    //
    // x86-64: 32768 GSI lines, every pin of the `MAX_IOAPICS` (128) I/O
    // APICs the boot protocol carries. RISC-V: the PLIC's 1024-entry id space (sources
    // 1-1023) is the spec maximum; most platforms expose far fewer (e.g.
    // 95). Sizing the root at the id space is safe because
    // `SYS_IRQ_REGISTER` refuses an id no discovered controller implements and
    // the routing table ignores one past its discovered size (see
    // `ROOT_IRQ_COUNT` above).
    let irq_ptr = mint_phase7_body(InterruptObject::new_root(0, ROOT_IRQ_COUNT));
    let irq_range_slot = insert_or_fatal(
        cspace,
        IrqRights::NOTIFY,
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

    let (acpi_region_memory_base, acpi_region_memory_count) =
        mint_acpi_region_caps(cspace, mmap, |d| push_descriptor(&mut desc_count, d));

    // RO Memory cap over the single 4 KiB page containing the ACPI RSDP.
    // RSDP commonly sits in firmware-reserved memory outside
    // `AcpiReclaimable`, so it gets its own cap regardless of the region scan.
    //
    // The cap's backing region covers the page (aligned base, 4 KiB size),
    // but the descriptor's `aux0` carries the exact RSDP physical address
    // so userspace knows where inside the page to start reading.
    let acpi_rsdp_memory_slot: u32 = if info.acpi_rsdp != 0
    {
        let page_base = info.acpi_rsdp & !0xFFF;
        let ptr = mint_phase7_body(firmware_table_memory(page_base, 0x1000));
        let slot = insert_or_fatal(
            cspace,
            MemRights::MAP,
            ptr,
            "Phase 7: cannot allocate Memory capability for ACPI RSDP page",
        );
        push_descriptor(
            &mut desc_count,
            CapDescriptor {
                slot,
                cap_type: CapType::Memory,
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

    // RO Memory cap covering the DTB blob, over the page-aligned extent that
    // `mm::init::populate_buddy` sized from the FDT header and kept out of
    // the buddy.
    let dtb_memory_slot: u32 = if let Some((dtb_base, dtb_size)) = crate::mm::init::dtb_extent()
    {
        let ptr = mint_phase7_body(firmware_table_memory(dtb_base, dtb_size));
        let slot = insert_or_fatal(
            cspace,
            MemRights::MAP,
            ptr,
            "Phase 7: cannot allocate Memory capability for DTB blob",
        );
        push_descriptor(
            &mut desc_count,
            CapDescriptor {
                slot,
                cap_type: CapType::Memory,
                pad: [0; 3],
                aux0: dtb_base,
                aux1: dtb_size,
            },
        );
        slot
    }
    else
    {
        0
    };

    // Root IoPort covering the full 64K I/O port space (x86-64 only). This is
    // a static architectural fact, not derived from any bootloader field. Init
    // subdivides and delegates sub-ranges to services as needed.
    if crate::arch::current::HAS_IO_PORTS
    {
        // Size 0 means 0x10000 (the full range; u16 cannot hold 65536).
        let ptr = mint_phase7_body(IoPortObject::new_root(0, 0));
        let ioport_root_slot = insert_or_fatal(
            cspace,
            IoPortRights::USE,
            ptr,
            "Phase 7: cannot allocate root IoPort capability",
        );
        push_descriptor(
            &mut desc_count,
            CapDescriptor {
                slot: ioport_root_slot,
                cap_type: CapType::IoPort,
                pad: [0; 3],
                aux0: 0,
                aux1: 0x10000, // full 64K range
            },
        );
    }

    // RISC-V: one SbiControl capability — the root forwarding authority. It
    // carries every sanctioned SBI right; init attenuates per-consumer copies
    // (devmgr serves pwrmgr a `SBI_RESET`-only derivative).
    let sbi_control_slot = if crate::arch::current::HAS_SBI
    {
        let ptr = mint_phase7_body(SbiControlObject {
            header: KernelObjectHeader::with_ancestor(ObjectType::SbiControl, seed_header_nn()),
        });
        let slot = insert_or_fatal(
            cspace,
            SbiRights::RESET
                | SbiRights::SUSPEND
                | SbiRights::CPPC
                | SbiRights::BASE
                | SbiRights::DBCN
                | SbiRights::PMU,
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
    }
    else
    {
        0u32
    };

    CSpaceLayout {
        memory_base,
        memory_count,
        hw_cap_base,
        hw_cap_count,
        sched_control_slot,
        sbi_control_slot,
        irq_range_slot,
        acpi_rsdp_memory_slot,
        acpi_region_memory_base,
        acpi_region_memory_count,
        dtb_memory_slot,
        total_populated: cspace.populated_count(),
        descriptor_count: desc_count,
        module_name_count: 0,
        module_names: [init_protocol::INIT_MODULE_NAME_EMPTY;
            init_protocol::INIT_MAX_NAMED_MODULES],
    }
}

/// Mint `Memory` capabilities for boot modules into the root `CSpace`.
///
/// Each boot module (raw ELF image for an early service) gets a full-rights,
/// reclaimable Memory cap (`owns_memory = true`, full byte ledger), per
/// `docs/capability-model.md` § Memory; loaders map the ELF source read-only.
/// The kernel additionally publishes a name → slot mapping in
/// [`CSpaceLayout::module_names`] so init can match modules by their
/// bundle entry identifier instead of relying on ordinal position.
///
/// Updates `layout.module_names` / `layout.module_name_count` and
/// appends [`CapDescriptor`] entries for each module. Init looks
/// modules up by name via the published `module_names` table.
fn mint_module_memory_caps(cspace: &mut CSpace, boot_info: &BootInfo, layout: &mut CSpaceLayout)
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
        // defensively to uphold MemoryObject's alignment invariant.
        let aligned_base = module.physical_base & !0xFFF;
        // Round size up so the cap covers every page that holds module bytes.
        let rounded_size = (module.physical_base - aligned_base + module.size + 0xFFF) & !0xFFF;

        // Register the module's pages as managed-but-not-free so the buddy's
        // `total_pages` ledger accounts for them (they are excluded from the
        // free list — `mm::init::collect_usable_ranges` in core/kernel/src/mm/init.rs
        // filters loaded regions). These caps route to memmgr via reap and are
        // not destroyed in the kernel; the post-handoff buddy is sealed, so the
        // dealloc `free_range` path is a tripwire, not a routine reclaim.
        // Idempotent at boot since module page ranges are disjoint.
        // Production-only: `with_frame_allocator` is `cfg(not(test))`.
        #[cfg(not(test))]
        // SAFETY: module pages were not added via `add_region`
        // (core/kernel/src/mm/init.rs `collect_usable_ranges` excludes loaded
        // regions); single-threaded boot.
        unsafe {
            crate::mm::with_frame_allocator(|alloc| {
                alloc.register_owned_range(aligned_base, rounded_size);
            });
        }

        let ptr = mint_phase7_body(MemoryObject {
            header: KernelObjectHeader::with_ancestor(ObjectType::Memory, seed_header_nn()),
            base: aligned_base,
            size: rounded_size,
            // Boot module pages are reclaimable: full byte ledger so the
            // pages can flow through `memmgr_labels::DONATE_MEMORY_CAPS` into
            // memmgr's pool at init's reap (docs/process-lifecycle.md § Init reap)
            // once the loader (init or procmgr) has copied the ELF contents into
            // the target process's AddressSpace.
            available_bytes: core::sync::atomic::AtomicU64::new(rounded_size),
            // Reclaimable: `owns_memory` marks this cap as the pages' owner. It
            // routes to memmgr via init's reap and is never destroyed; a
            // `dealloc_object` free into the sealed buddy is an accounting
            // violation (docs/userspace-memory-model.md § Ownership Boundaries).
            owns_memory: core::sync::atomic::AtomicBool::new(true),
            allocator: crate::cap::retype::RetypeAllocator::new_inline(),
            lock: core::sync::atomic::AtomicU32::new(0),
        });
        // Full rights so the cap can flow through the donation chain into
        // memmgr's pool (memmgr-issued reply caps must carry RETYPE for
        // userspace to retype into kernel objects). The loaders (init,
        // procmgr) never map this cap: each derives a MAP-only child
        // (`RIGHTS_MEM_MAP`) and maps that with prot 0 (`MAP_FROM_CAP`),
        // which takes the permissions from the mapped cap's rights, so the
        // ELF source is read-only at the page-table level because the child
        // lacks WRITE and EXECUTE.
        let slot = insert_or_fatal(
            cspace,
            MemRights::MAP | MemRights::WRITE | MemRights::EXECUTE | MemRights::RETYPE,
            ptr,
            "Phase 7: cannot allocate Memory capability for boot module",
        );
        note_owns_memory_minted(rounded_size);
        push_descriptor(
            &mut layout.descriptor_count,
            CapDescriptor {
                slot,
                cap_type: CapType::Memory,
                pad: [0; 3],
                aux0: module.physical_base,
                aux1: module.size,
            },
        );
        // Publish a name → slot entry in the InitInfo header table so
        // init can resolve modules by name without scanning descriptors.
        let name_slot = layout.module_name_count as usize;
        if name_slot >= init_protocol::INIT_MAX_NAMED_MODULES
        {
            crate::fatal("Phase 7: more boot modules than INIT_MAX_NAMED_MODULES");
        }
        layout.module_names[name_slot] = init_protocol::InitModuleName {
            slot,
            _pad: 0,
            name: module.name,
        };
        layout.module_name_count += 1;
    }

    layout.total_populated = cspace.populated_count();
}

/// Mint reclaimable `Memory` capabilities over bootloader scratch ranges.
///
/// Walks `boot_info.reclaim_ranges` — the `BootInfo` page, module
/// descriptor array, memory-map entry array, the raw UEFI memory-map buffer
/// (zeroed by the bootloader after its last read), MMIO aperture array, the
/// reclaim-array page itself, the CPU-id pages, the bootloader's
/// transient page-table frames, and the bundle's non-module pages (header +
/// entry table + pad, init ELF source body, inter-module and trailing slack —
/// module bodies are excluded because [`mint_module_memory_caps`]
/// covers them) — and mints one reclaimable `MemoryObject`
/// cap per range with `owns_memory = true` and the full byte ledger.
/// Each cap is inserted into the root `CSpace` and a matching `CapDescriptor`
/// entry pushed into the `InitInfo` descriptor array (counted by
/// `layout.descriptor_count`), so the cap reaches init through the standard
/// descriptor-table walk in the same shape boot-module caps take. init routes
/// each cap to memmgr via reap; the post-handoff buddy is sealed, so the
/// `dealloc_object` → `free_range` path is a tripwire for a leaked cap, not a
/// routine reclaim.
///
/// Entries marked [`boot_protocol::RECLAIM_FLAG_LATE`] are skipped here
/// and minted later by [`mint_late_reclaim_memory_caps`] after SMP
/// bringup completes (the AP SIPI trampoline is the only such entry
/// today).
///
/// Symmetric to [`mint_module_memory_caps`]; runs immediately after it.
/// The minted pages keep their contents until [`scrub_reclaim_ranges`]
/// zeroes every recorded range in Phase 9, before init can run; the kernel
/// MUST NOT dereference an address inside a recorded range after that scrub.
///
/// Appends one [`CapDescriptor`] entry per reclaimed range; init walks
/// the descriptor table to discover the caps. There is no dedicated
/// `reclaim_memory_base` / `reclaim_memory_count` pair on [`CSpaceLayout`]
/// because reclaim caps carry no per-index meaning — unlike boot
/// modules, which init resolves by name through [`CSpaceLayout::module_names`],
/// reclaim caps are a homogeneous pool and userspace inspects each
/// `CapDescriptor.aux0`/`aux1` to learn the underlying physical range.
fn mint_reclaim_memory_caps(cspace: &mut CSpace, boot_info: &BootInfo, layout: &mut CSpaceLayout)
{
    mint_reclaim_pass(cspace, boot_info, layout, false, "reclaim");
}

/// Mint reclaimable `Memory` capabilities for entries flagged
/// [`boot_protocol::RECLAIM_FLAG_LATE`] in `boot_info.reclaim_ranges`.
///
/// Caller MUST have already (a) completed SMP bringup so no AP is
/// executing inside any late-flagged page, and (b) torn down any kernel
/// identity mapping that aliases the page (see
/// [`crate::mm::paging::unmap_identity_page`]). The mint itself is
/// identical to [`mint_reclaim_memory_caps`] — same `MemoryObject`
/// shape, same `register_owned_range` ledger entry, same descriptor
/// push — so init discovers the cap through the standard descriptor
/// walk.
///
/// Must run before Phase 9 consumes [`descriptors`] so the new entry
/// reaches init via the same `CSpace` handoff.
#[cfg(not(test))]
pub(crate) fn mint_late_reclaim_memory_caps(
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
///
/// The pass mints over the ranges as the bootloader left them; the kernel
/// still reads the `BootInfo` page and the reclaim array through Phase 9, so
/// the contents are cleared later, by [`scrub_reclaim_ranges`] right before
/// init is enqueued, not here.
// Linear sequence, run once in Phase 7 and once (the late pass) in Phase 8:
// per-range overlap check, owned-range registration, MemoryObject mint,
// descriptor push. The debug-only overlap assertion adds ~25 lines without a
// natural extraction point.
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
        // `mint_module_memory_caps`.
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

        // Catch double-coverage with module Memory caps: any overlap here
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
                    "reclaim range overlaps module Memory cap",
                );
            }
        }

        // Register the range as managed-but-not-free so the buddy's
        // `total_pages` ledger accounts for it. These pages were never in
        // `total_pages` — `mm::init::collect_usable_ranges` filters
        // `Loaded`-typed regions out of the free ranges at Phase 2 — so
        // `register_owned_range` is the correct ledger entry (not
        // `add_region`, which would also push them onto the free list). The
        // cap routes to memmgr via reap and is not destroyed in the kernel;
        // post-handoff the buddy is sealed, so a `free_range` here is a
        // tripwire, not a routine reclaim.
        #[cfg(not(test))]
        // SAFETY: range pages were not added via `add_region`
        // (bootloader-typed `Loaded`, filtered by
        // `mm::init::collect_usable_ranges`); single-threaded Phase 7, or for
        // the late pass the BSP's Phase 8 boot path, before `sched::enter`,
        // with the APs idle.
        unsafe {
            crate::mm::with_frame_allocator(|alloc| {
                alloc.register_owned_range(phys_base, size_bytes);
            });
        }

        let ptr = mint_phase7_body(MemoryObject {
            header: KernelObjectHeader::with_ancestor(ObjectType::Memory, seed_header_nn()),
            base: phys_base,
            size: size_bytes,
            // Reclaim pages carry the full byte ledger and `owns_memory = true`,
            // matching the boot-module caps above; init donates every reclaim
            // cap to memmgr at reap and the sealed buddy receives none
            // (core/kernel/docs/initialization.md § Phase 7).
            available_bytes: core::sync::atomic::AtomicU64::new(size_bytes),
            owns_memory: core::sync::atomic::AtomicBool::new(true),
            allocator: crate::cap::retype::RetypeAllocator::new_inline(),
            lock: core::sync::atomic::AtomicU32::new(0),
        });
        let slot = insert_or_fatal(
            cspace,
            MemRights::MAP | MemRights::WRITE | MemRights::EXECUTE | MemRights::RETYPE,
            ptr,
            if late
            {
                "Phase 8: cannot allocate Memory capability for late-reclaimed boot scratch"
            }
            else
            {
                "Phase 7: cannot allocate Memory capability for reclaimed boot scratch"
            },
        );
        push_descriptor(
            &mut layout.descriptor_count,
            CapDescriptor {
                slot,
                cap_type: CapType::Memory,
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
            "{}: minted {} Memory caps over {} scratch pages (total accounted {} → {})",
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

/// Pages the reclaim array can span: at most [`boot_protocol::MAX_RECLAIM_RANGES`]
/// entries fill one page, and an array whose base is not page-aligned reaches
/// into one more.
#[cfg(not(test))]
const RECLAIM_ARRAY_MAX_SPAN_PAGES: usize = (boot_protocol::MAX_RECLAIM_RANGES
    * core::mem::size_of::<boot_protocol::ReclaimRange>())
.div_ceil(crate::mm::PAGE_SIZE)
    + 1;

/// Zero every range `BootInfo.reclaim_ranges` records, late-flagged entries
/// included, through the direct map, so no page the bootloader wrote (its
/// transient page tables, which encode the slid kernel layout, the `BootInfo`
/// page, the descriptor arrays, the CPU-id pages, the bundle's non-module
/// pages, and the AP trampoline page) reaches userspace with its contents intact
/// (`core/kernel/docs/cross-boundary-disclosure.md` § Kernel state in donated
/// memory).
///
/// The slice header is read by value from the `BootInfo` page and each entry
/// by value from the reclaim array, so no reference into a page outlives the
/// read that precedes its zeroing; the pages holding the reclaim array are
/// zeroed last, after every entry has been read. Calls [`crate::fatal`] when
/// the entry count exceeds [`boot_protocol::MAX_RECLAIM_RANGES`], the bound
/// the one-page reclaim array sets.
///
/// # Safety
/// Single-threaded Phase 9, after the last kernel read of the `BootInfo`
/// page and of every recorded range, and before init is enqueued: nothing
/// reads a recorded range after this call, and no userspace thread can yet
/// reach the caps minted over them. `boot_info_phys` was validated in
/// Phase 0; the direct map covers all RAM since Phase 3 but the kernel-stack
/// guard pages (`mm::stack_guard`), none of them in a reclaim range.
#[cfg(not(test))]
pub(crate) unsafe fn scrub_reclaim_ranges(boot_info_phys: u64)
{
    use boot_protocol::{MAX_RECLAIM_RANGES, ReclaimRange};

    let page = crate::mm::PAGE_SIZE as u64;
    let info = phys_to_virt(boot_info_phys) as *const BootInfo;
    // SAFETY: the BootInfo page is mapped through the direct map (caller
    // contract); the slice header is copied out and no reference is formed.
    let slice = unsafe { core::ptr::addr_of!((*info).reclaim_ranges).read() };
    let count = slice.count as usize;
    if count == 0 || slice.entries.is_null()
    {
        return;
    }
    if count > MAX_RECLAIM_RANGES
    {
        crate::fatal("Phase 9: reclaim_ranges count exceeds MAX_RECLAIM_RANGES");
    }

    let array_phys = slice.entries as u64;
    let span_lo = array_phys & !(page - 1);
    let span_hi =
        (array_phys + (count * core::mem::size_of::<ReclaimRange>()) as u64).next_multiple_of(page);
    let mut span_covered = [false; RECLAIM_ARRAY_MAX_SPAN_PAGES];
    let entries = phys_to_virt(array_phys) as *const ReclaimRange;
    let mut pages: u64 = 0;

    for i in 0..count
    {
        // SAFETY: i < count, within the bootloader-recorded array, which the
        // loop never zeroes (pages of [span_lo, span_hi) are deferred below).
        let range = unsafe { entries.add(i).read_unaligned() };
        // SAFETY: a recorded range, which nothing reads after this call
        // (caller contract).
        pages += unsafe { scrub_outside_span(range, span_lo, span_hi, &mut span_covered) };
    }

    // SAFETY: every entry was read in the loop above, so nothing reads the
    // reclaim array's pages again.
    unsafe { zero_covered_span_pages(span_lo, span_covered) };

    crate::kprintln!("reclaim scrub: zeroed {pages} pages over {count} ranges");
}

/// Zero the pages of one reclaim `range` that lie outside the reclaim-array
/// span `[span_lo, span_hi)`, mark the span pages it covers in
/// `span_covered` (indexed from `span_lo`) for [`zero_covered_span_pages`],
/// and return its page count.
///
/// # Safety
/// `range` is a recorded reclaim range that nothing reads afterwards, and the
/// span is at most `span_covered.len()` pages.
#[cfg(not(test))]
unsafe fn scrub_outside_span(
    range: boot_protocol::ReclaimRange,
    span_lo: u64,
    span_hi: u64,
    span_covered: &mut [bool; RECLAIM_ARRAY_MAX_SPAN_PAGES],
) -> u64
{
    let page = crate::mm::PAGE_SIZE as u64;
    if range.page_count == 0
    {
        return 0;
    }
    let lo = range.phys_base & !(page - 1);
    let hi = lo + u64::from(range.page_count) * page;
    let (outside, inside) = split_around_span(lo, hi, span_lo, span_hi);
    for (start, end) in outside
    {
        // SAFETY: part of `range` (caller contract), disjoint from the span.
        unsafe { zero_phys(start, end - start) };
    }
    let mut p = inside.0;
    while p < inside.1
    {
        span_covered[((p - span_lo) / page) as usize] = true;
        p += page;
    }
    u64::from(range.page_count)
}

/// Zero each reclaim-array span page, from `span_lo`, that `span_covered`
/// marks as recorded.
///
/// # Safety
/// No reclaim entry is read after this call.
#[cfg(not(test))]
unsafe fn zero_covered_span_pages(span_lo: u64, span_covered: [bool; RECLAIM_ARRAY_MAX_SPAN_PAGES])
{
    let page = crate::mm::PAGE_SIZE as u64;
    for (k, covered) in span_covered.into_iter().enumerate()
    {
        if covered
        {
            // SAFETY: a recorded page of the reclaim array (caller contract).
            unsafe { zero_phys(span_lo + k as u64 * page, page) };
        }
    }
}

/// Split the page range `[lo, hi)` around the span `[span_lo, span_hi)`:
/// returns the parts below and above the span (each possibly empty) and the
/// part inside it (possibly empty, as `start >= end`).
fn split_around_span(lo: u64, hi: u64, span_lo: u64, span_hi: u64)
-> ([(u64, u64); 2], (u64, u64))
{
    let below = (lo, hi.min(span_lo).max(lo));
    let above = (lo.max(span_hi).min(hi), hi);
    let inside = (lo.max(span_lo), hi.min(span_hi));
    let inside = if inside.0 < inside.1 { inside } else { (0, 0) };
    ([below, above], inside)
}

/// Zero `len` bytes of physical memory at `base` through the direct map.
///
/// # Safety
/// `[base, base + len)` is RAM the direct map covers, and nothing holds a
/// reference into it.
#[cfg(not(test))]
unsafe fn zero_phys(base: u64, len: u64)
{
    if len == 0
    {
        return;
    }
    // SAFETY: per the function's contract.
    unsafe { core::ptr::write_bytes(phys_to_virt(base) as *mut u8, 0, len as usize) };
}

/// Cast `Box<T>` to `NonNull<KernelObjectHeader>` by leaking the box.
///
/// Used only by the test build's `mint_phase7_body` arm and by the test
/// build's RAM-Memory mint loop; the production path mints exclusively
/// through `cap::retype::boot_retype_body`.
///
/// # Safety contract
///
/// `T` must be `#[repr(C)]` with `KernelObjectHeader` as its first field
/// (offset 0). The test build never drops the returned pointer: every
/// test-path kernel object is leaked.
#[cfg(test)]
fn nonnull_from_box<T>(b: Box<T>) -> NonNull<KernelObjectHeader>
{
    let raw = Box::into_raw(b).cast::<KernelObjectHeader>();
    // SAFETY: Box::into_raw never returns null.
    unsafe { NonNull::new_unchecked(raw) }
}

/// Acquire a pair of `CSpace` locks in pointer-address order (lower address
/// first, preventing ABBA deadlock between concurrent pairs; a same-pointer
/// pair is locked once). Returns the saved interrupt states to hand back to
/// [`unlock_cspace_pair`] with the same `(a, b)` argument order.
///
/// # Safety
///
/// `a` and `b` must be valid `CSpace` pointers; the acquisition must be
/// released exactly once via [`unlock_cspace_pair`].
#[cfg(not(test))]
pub(crate) unsafe fn lock_cspace_pair(a: *mut CSpace, b: *mut CSpace) -> (u64, u64)
{
    // SAFETY: caller contract.
    unsafe {
        use core::cmp::Ordering;
        match a.cmp(&b)
        {
            Ordering::Less =>
            {
                let sa = (*a).lock.lock_raw();
                let sb = (*b).lock.lock_raw();
                (sa, sb)
            }
            Ordering::Greater =>
            {
                let sb = (*b).lock.lock_raw();
                let sa = (*a).lock.lock_raw();
                (sa, sb)
            }
            Ordering::Equal =>
            {
                let sa = (*a).lock.lock_raw();
                (sa, 0)
            }
        }
    }
}

/// Release a pair of `CSpace` locks taken in pointer-address order, in
/// reverse order of acquisition (same-pointer pairs were locked once).
///
/// # Safety
///
/// `saved_a`/`saved_b` must come from the matching `lock_raw` acquisition
/// over the same `(a, b)` pointer pair (lower address locked first, or a
/// single acquisition when `a == b`); each pair must be released exactly
/// once.
#[cfg(not(test))]
pub(crate) unsafe fn unlock_cspace_pair(a: *mut CSpace, b: *mut CSpace, saved_a: u64, saved_b: u64)
{
    // SAFETY: caller contract.
    unsafe {
        use core::cmp::Ordering;
        match a.cmp(&b)
        {
            Ordering::Equal =>
            {
                (*a).lock.unlock_raw(saved_a);
            }
            Ordering::Less =>
            {
                (*b).lock.unlock_raw(saved_b);
                (*a).lock.unlock_raw(saved_a);
            }
            Ordering::Greater =>
            {
                (*a).lock.unlock_raw(saved_a);
                (*b).lock.unlock_raw(saved_b);
            }
        }
    }
}

/// Whether `slot` may join the published slot run `[base, base + count)`: any
/// slot starts an empty run, and a later one must be `base + count`.
fn extends_slot_run(base: u32, count: u32, slot: u32) -> bool
{
    count == 0 || base.checked_add(count) == Some(slot)
}

/// Record `slot` as the next member of the slot run `base`/`count` (setting
/// `base` for the first), calling [`crate::fatal`] (a panic in host tests)
/// when it breaks the run. `InitInfo` hands these runs to init as
/// `[base, base + count)` ranges, so a gap would name a slot outside the run;
/// the free list's ascending order keeps boot inserts consecutive
/// (core/kernel/docs/capability-internals.md § Free Slot Tracking).
pub(crate) fn extend_slot_run_or_fatal(base: &mut u32, count: u32, slot: u32, msg: &'static str)
{
    if !extends_slot_run(*base, count, slot)
    {
        #[cfg(not(test))]
        {
            crate::kprintln!(
                "{}: slot {} where the run expected {}",
                msg,
                slot,
                base.saturating_add(count)
            );
            crate::fatal(msg);
        }
        #[cfg(test)]
        panic!(
            "{msg}: slot {slot} where the run expected {}",
            *base + count
        );
    }
    if count == 0
    {
        *base = slot;
    }
}

/// Insert a capability, calling [`crate::fatal`] on error.
///
/// The tag is derived from the typed rights argument, so a mint site cannot
/// pair a tag with another type's rights.
fn insert_or_fatal<K: slot::CapKind>(
    cspace: &mut CSpace,
    rights: slot::TypedRights<K>,
    object: NonNull<KernelObjectHeader>,
    msg: &'static str,
) -> u32
{
    match cspace.insert_cap_typed(rights, object)
    {
        Ok(idx) => idx.get(),
        #[cfg(not(test))]
        Err(_) => crate::fatal(msg),
        // In test mode, panic with the message instead of halting the CPU.
        #[cfg(test)]
        Err(e) => panic!("{}: {:?}", msg, e),
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    // ── published slot runs ───────────────────────────────────────────────────

    #[test]
    fn slot_run_accepts_any_first_slot_then_only_the_next()
    {
        assert!(extends_slot_run(0, 0, 77));
        assert!(extends_slot_run(77, 1, 78));
        assert!(extends_slot_run(77, 5, 82));
    }

    #[test]
    fn slot_run_rejects_a_gap_a_repeat_and_an_overflow()
    {
        assert!(
            !extends_slot_run(77, 5, 83),
            "a skipped slot breaks the run"
        );
        assert!(
            !extends_slot_run(77, 5, 81),
            "a repeated slot breaks the run"
        );
        assert!(
            !extends_slot_run(u32::MAX, 1, 0),
            "a wrapped base + count breaks the run"
        );
    }

    #[test]
    #[should_panic(expected = "not in consecutive slots")]
    fn extending_a_run_past_a_gap_is_fatal()
    {
        let mut base = 10;
        extend_slot_run_or_fatal(&mut base, 3, 14, "runs: not in consecutive slots");
    }

    #[test]
    fn extending_an_empty_run_sets_its_base()
    {
        let mut base = 0;
        extend_slot_run_or_fatal(&mut base, 0, 42, "runs: not in consecutive slots");
        assert_eq!(base, 42);
    }

    // Defect guarded: ACPI regions past a fixed count silently
    // dropped, so the tables in them never reach devmgr; and a region other
    // than an AcpiReclaimable one, or a zero-length one, minted as ACPI.
    #[test]
    fn every_acpi_reclaimable_region_gets_one_consecutive_cap()
    {
        let mut mmap = Vec::new();
        for i in 0..20u64
        {
            mmap.push(MemoryMapEntry {
                physical_base: 0x1000_0000 + i * 0x10_0000,
                size: 0x2000,
                memory_type: MemoryType::AcpiReclaimable,
            });
            mmap.push(MemoryMapEntry {
                physical_base: 0x1000_8000 + i * 0x10_0000,
                size: 0x1000,
                memory_type: MemoryType::Usable,
            });
        }
        mmap.push(MemoryMapEntry {
            physical_base: 0x2000_0000,
            size: 0,
            memory_type: MemoryType::AcpiReclaimable,
        });
        let mut cspace = CSpace::new(0);
        let mut descs = Vec::new();
        let (base, count) = mint_acpi_region_caps(&mut cspace, &mmap, |d| descs.push(d));
        assert_eq!(count, 20);
        assert_eq!(descs.len(), 20);
        for (i, d) in descs.iter().enumerate()
        {
            assert_eq!(d.slot, base + i as u32);
            assert_eq!(d.aux0, 0x1000_0000 + i as u64 * 0x10_0000);
            assert_eq!(d.aux1, 0x2000);
            assert!(cspace.slot(d.slot).is_some_and(|s| s.tag == CapTag::Memory));
        }
    }

    // Defect caught: a `populate_cspace` capability with a descriptor that
    // the `InitInfo` bound does not count (a new fixed cap, or ACPI regions
    // counted short by the counts Phase 7 sizes from), so a boot sized from the
    // bound overruns the region it reserved. The aperture and module
    // descriptors are one per entry of the array each count reads, the reclaim
    // descriptors at most one.
    #[test]
    fn the_descriptor_bound_counts_every_fixed_and_acpi_descriptor_phase_7_mints()
    {
        let mut mmap = Vec::new();
        for i in 0..5u64
        {
            mmap.push(MemoryMapEntry {
                physical_base: 0x1000_0000 + i * 0x10_0000,
                size: 0x2000,
                memory_type: MemoryType::AcpiReclaimable,
            });
            mmap.push(MemoryMapEntry {
                physical_base: 0x1000_8000 + i * 0x10_0000,
                size: 0x1000,
                memory_type: MemoryType::Usable,
            });
        }
        // SAFETY: every `BootInfo` field is an integer, a raw pointer, an
        // array of those, or a `repr(u32)` enum with a 0 variant, so the
        // all-zero bit pattern is a valid value.
        let mut info: BootInfo = unsafe { core::mem::zeroed() };
        info.acpi_rsdp = 0xE_0010;
        let mut cspace = CSpace::new(0);
        let layout = populate_cspace(
            &mut cspace,
            0,
            &mmap,
            crate::platform::ValidatedApertures::empty(),
            &info,
        );
        let counts =
            DescriptorCounts::of(&mmap, &crate::platform::ValidatedApertures::empty(), &info);
        let non_ram = layout.descriptor_count - layout.memory_count as usize;
        assert_eq!(
            counts.acpi_regions,
            layout.acpi_region_memory_count as usize
        );
        assert!(
            non_ram <= counts.bound(0),
            "{non_ram} non-RAM descriptors past the bound"
        );
        // The fixed caps this build mints, exactly: one more fails here until
        // the list below and FIXED_BOOT_DESCRIPTORS count it.
        let fixed = [
            true, // SchedControl
            true, // root Interrupt
            info.acpi_rsdp != 0,
            crate::mm::init::dtb_extent().is_some(),
            crate::arch::current::platform::console_mmio().is_some(),
            crate::arch::current::HAS_IO_PORTS,
            crate::arch::current::HAS_SBI,
        ];
        let fixed_here = fixed.iter().filter(|&&f| f).count();
        assert_eq!(non_ram - counts.acpi_regions, fixed_here);
        // The most any build mints (IoPort and SbiControl are exclusive, no
        // architecture has both), with the two spare slots, is what the
        // constant holds.
        assert!(!(crate::arch::current::HAS_IO_PORTS && crate::arch::current::HAS_SBI));
        assert_eq!(fixed.len() - 1 + 2, FIXED_BOOT_DESCRIPTORS);
    }

    // ── split_around_span (reclaim scrub) ─────────────────────────────────────

    #[test]
    fn range_disjoint_from_span_stays_wholly_outside()
    {
        let (outside, inside) = split_around_span(0x1000, 0x3000, 0x8000, 0x9000);
        assert_eq!(outside, [(0x1000, 0x3000), (0x3000, 0x3000)]);
        assert_eq!(inside, (0, 0));
        let (outside, inside) = split_around_span(0xA000, 0xC000, 0x8000, 0x9000);
        assert_eq!(outside, [(0xA000, 0xA000), (0xA000, 0xC000)]);
        assert_eq!(inside, (0, 0));
    }

    #[test]
    fn range_containing_span_splits_into_three()
    {
        let (outside, inside) = split_around_span(0x7000, 0xB000, 0x8000, 0x9000);
        assert_eq!(outside, [(0x7000, 0x8000), (0x9000, 0xB000)]);
        assert_eq!(inside, (0x8000, 0x9000));
    }

    #[test]
    fn range_equal_to_span_is_wholly_deferred()
    {
        let (outside, inside) = split_around_span(0x8000, 0x9000, 0x8000, 0x9000);
        assert!(outside.iter().all(|&(a, b)| a >= b));
        assert_eq!(inside, (0x8000, 0x9000));
    }

    // Defect caught: an InitInfo region sized for fewer descriptors than the
    // bound counts, so Phase 7's drain or a later push overruns it, or one a
    // page larger than the bound needs, or a ceiling capacity that the
    // protocol's page limit does not hold.
    #[test]
    fn the_init_info_region_is_the_fewest_pages_that_hold_the_bound()
    {
        for bound in [
            1,
            50,
            168,
            169,
            170,
            500,
            4096,
            INIT_INFO_DESCRIPTOR_CAPACITY,
        ]
        {
            let pages = init_info_pages(bound);
            assert!(
                descriptors_in_pages(pages) >= bound,
                "{bound} in {pages} pages"
            );
            assert!(pages == 1 || descriptors_in_pages(pages - 1) < bound);
        }
        assert_eq!(
            init_info_pages(INIT_INFO_DESCRIPTOR_CAPACITY),
            init_protocol::INIT_INFO_MAX_PAGES
        );
        assert!(
            init_info_pages(INIT_INFO_DESCRIPTOR_CAPACITY + 1) > init_protocol::INIT_INFO_MAX_PAGES
        );
        // Every count the bound takes adds one descriptor each.
        let base = init_info_descriptor_bound(0, 0, 0, 0, 0);
        assert_eq!(init_info_descriptor_bound(3, 0, 0, 0, 0), base + 3);
        assert_eq!(init_info_descriptor_bound(0, 1, 2, 3, 4), base + 10);
    }

    // Defect guarded: an in-place completion that writes a descriptor over
    // an extent not yet read, or reads a slot it has already rewritten, mints
    // RAM caps with another extent's base or size.
    #[test]
    fn ram_descriptors_complete_in_place_over_a_full_array()
    {
        let extent = |i: usize| CapDescriptor {
            slot: 0,
            cap_type: init_protocol::CapType::Memory,
            pad: [0; 3],
            aux0: 0x1_0000_0000 + (i as u64) * 0x20_0000,
            aux1: 0x1000 * (i as u64 + 1),
        };
        let mut slots: Vec<CapDescriptor> =
            (0..INIT_INFO_DESCRIPTOR_CAPACITY).map(extent).collect();
        let mut seen = Vec::new();
        complete_extent_descriptors(&mut slots, |base, size| {
            seen.push((base, size));
            CapDescriptor {
                slot: seen.len() as u32,
                cap_type: init_protocol::CapType::Memory,
                pad: [0; 3],
                aux0: base,
                aux1: size,
            }
        });
        for (i, d) in slots.iter().enumerate()
        {
            let want = extent(i);
            assert_eq!(seen[i], (want.aux0, want.aux1), "extent {i} read intact");
            assert_eq!(
                (d.slot, d.aux0, d.aux1),
                (i as u32 + 1, want.aux0, want.aux1)
            );
        }
    }

    #[test]
    fn largest_extent_promoted_to_front()
    {
        // A strictly larger extent must land at index 0 so it becomes
        // `memory_base`, even though a smaller lower-address extent sorts
        // ahead of it; the earliest of equal extents stays put.
        let mut extents = [(0x1000, 0x1000), (0x8000, 0x3000), (0x20000, 0x3000)];
        assert_eq!(promote_largest_extent(&mut extents, |e| e.1), 3);
        assert_eq!(
            extents,
            [(0x8000, 0x3000), (0x1000, 0x1000), (0x20000, 0x3000)]
        );
        assert_eq!(promote_largest_extent(&mut [(0u64, 0u64); 0], |e| e.1), 0);
    }

    /// `CSpaceId` reserved for the recycle test below. The host-test
    /// `CSPACE_REGISTRY` is a process-wide static and `cargo test` runs tests
    /// concurrently, so every host `#[test]` that registers a `CSpace`
    /// directly — this one and the derivation-tree tests in
    /// `core/kernel/src/cap/derivation.rs`, which use the `31xx` block — picks
    /// an id unique to that test; nothing enforces it. A high id keeps this
    /// one clear of that block.
    const RECYCLE_TEST_ID: CSpaceId = (registry::ENTRIES_PER_CHUNK as u32) - 1;

    /// A `SlotId` stamped before a `CSpace` id is recycled must fail
    /// `lookup_cspace` (epoch mismatch) even after the id is reused by a new
    /// tenant, while a freshly stamped `SlotId` resolves. Couples the real
    /// stamp (`SlotId::current` → `registry_epoch`) and validation
    /// (`lookup_cspace`) paths; only the epoch redraw is simulated, because
    /// `free_cspace_id` is `#[cfg(not(test))]` (it draws from the kernel
    /// CSPRNG).
    #[test]
    fn cspace_recycle_invalidates_stale_slotid()
    {
        use core::num::NonZeroU32;

        let id = RECYCLE_TEST_ID;
        let idx = NonZeroU32::new(1).unwrap();
        // Sentinel backing pointers; `lookup_cspace` only null-checks them
        // and never dereferences. Two distinct addresses model two tenants.
        let tenant_a = NonNull::<CSpace>::dangling().as_ptr();
        let tenant_b = tenant_a.wrapping_byte_add(0x1000);

        // Tenant A live; stamp a SlotId the way derivation write sites do.
        let epoch_a = register_cspace(id, tenant_a).expect("register tenant A");
        let stale = SlotId::current(id, idx);
        assert_eq!(
            stale.epoch, epoch_a,
            "SlotId::current must stamp the live epoch"
        );
        assert!(
            lookup_cspace(stale.cspace_id, stale.epoch).is_some(),
            "fresh SlotId must resolve against the live tenant"
        );

        // Destroy A and recycle the id. `free_cspace_id` is
        // `#[cfg(not(test))]` (draws from the kernel CSPRNG); replicate its
        // epoch change directly, without listing the id, so no concurrent
        // test's `alloc_cspace_id` can take it. `unregister_cspace` clears the ptr. #248
        // randomized this in production; the test stores a fixed distinct
        // non-zero epoch to stay deterministic (coding-standards: no
        // randomness in tests). The assertions check the property (epoch
        // changed ⇒ stale fails), not the arithmetic.
        unregister_cspace(id);
        CSPACE_REGISTRY.force_epoch(id, epoch_a ^ 0x5EED_0001);

        // Tenant B reuses the id at the new epoch.
        let epoch_b = register_cspace(id, tenant_b).expect("register tenant B");
        assert_ne!(epoch_b, epoch_a, "recycle must change the epoch");
        let fresh = SlotId::current(id, idx);
        assert_eq!(fresh.epoch, epoch_b);

        // The property #174 asks for: the stale SlotId fails fast even though
        // the id is live again, while the fresh SlotId resolves (proving the
        // None is epoch mismatch, not entry absence).
        assert!(
            lookup_cspace(stale.cspace_id, stale.epoch).is_none(),
            "stale epoch must not resolve against the recycled tenant"
        );
        assert!(
            lookup_cspace(fresh.cspace_id, fresh.epoch).is_some(),
            "current epoch must resolve"
        );

        unregister_cspace(id); // leave the shared registry slot clean
    }
}
