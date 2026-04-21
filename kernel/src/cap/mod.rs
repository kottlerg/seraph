// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/cap/mod.rs

//! Capability subsystem (Phase 7).
//!
//! Initialised by [`init_capability_system`], which creates the root `CSpace`
//! (id 0) populated with initial capabilities for all boot-provided hardware
//! resources:
//!
//! - Usable physical memory → [`CapTag::Frame`] caps (MAP | WRITE)
//! - MMIO ranges (`MmioRange`, `PciEcam`, `IommuUnit`) → [`CapTag::MmioRegion`] caps (MAP | WRITE)
//! - Interrupt lines → [`CapTag::Interrupt`] caps
//! - Firmware tables → [`CapTag::Frame`] caps (MAP only, no WRITE)
//! - One root [`CapTag::IoPortRange`] cap covering the full 64K I/O port space (x86-64, USE)
//! - One [`CapTag::SchedControl`] cap (ELEVATE)
//!
//! The populated `CSpace` is stored in [`ROOT_CSPACE`] until Phase 9 hands it
//! to the init process.

// cast_possible_truncation: u64→usize/u32/u16 capability field extractions bounded by capability space.
#![allow(clippy::cast_possible_truncation)]

extern crate alloc;

use alloc::boxed::Box;

pub mod cspace;
pub mod derivation;
pub mod object;
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

#[cfg(test)]
use boot_protocol::MemoryType;
use boot_protocol::{BootInfo, MemoryMapEntry, PlatformResource, ResourceType};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use init_protocol::CapDescriptor;

use crate::mm::paging::phys_to_virt;

// ── Globals ───────────────────────────────────────────────────────────────────

/// Root capability space, populated during Phase 7.
///
/// Consumed (transferred to init) during Phase 9. Access is single-threaded
/// during boot; `static mut` is safe here under that invariant.
#[cfg(not(test))]
pub static mut ROOT_CSPACE: Option<Box<CSpace>> = None;

/// Take the root `CSpace` out of `ROOT_CSPACE`, leaving `None`.
///
/// Uses raw pointer operations to avoid creating a mutable reference to a
/// mutable static (which is undefined behaviour in concurrent contexts and
/// warned by `static_mut_refs`). Safe here because access is single-threaded
/// during boot.
///
/// # Safety
/// Must be called only in single-threaded boot context before init runs.
#[cfg(not(test))]
pub unsafe fn take_root_cspace() -> Option<Box<CSpace>>
{
    // SAFETY: single-threaded boot; no concurrent access.
    let ptr = core::ptr::addr_of_mut!(ROOT_CSPACE);
    // SAFETY: ptr is a valid writable pointer to ROOT_CSPACE; single-threaded boot.
    unsafe { core::ptr::replace(ptr, None) }
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
    let ptr = core::ptr::addr_of_mut!(ROOT_CSPACE);
    // SAFETY: single-threaded boot; no concurrent access.
    unsafe { (*ptr).as_mut().map(Box::as_mut) }
}

/// Monotonically increasing `CSpace` ID allocator. Root gets ID 0.
static NEXT_CSPACE_ID: AtomicU32 = AtomicU32::new(0);

/// Maximum number of live `CSpaces.` Sized for practical OS use.
const MAX_CSPACES: usize = 4096;

/// Global registry mapping `CSpaceId` → raw *mut `CSpace.`
///
/// Populated by [`register_cspace`] when a `CSpace` is created, cleared by
/// [`unregister_cspace`] when the backing object is freed. Required for
/// derivation tree traversal: `SlotId` stores a `CSpaceId`, and we need
/// O(1) resolution to the actual `CSpace` to read/write derivation pointers.
///
/// # Safety invariant
/// A non-null entry is valid as long as the corresponding `CSpaceKernelObject`
/// refcount is > 0. After `dec_ref` reaches 0 and `dealloc_object` runs,
/// `unregister_cspace` clears the entry before the memory is freed.
// SAFETY: AtomicPtr<CSpace> is Send+Sync; array-of-atomics is always valid
// for static initialisation.
static CSPACE_REGISTRY: [AtomicPtr<CSpace>; MAX_CSPACES] = {
    // SAFETY: AtomicPtr<T> is repr(transparent) over *mut T; zero-initialized usize array
    // is valid array of null AtomicPtr values.
    unsafe {
        core::mem::transmute::<[usize; MAX_CSPACES], [AtomicPtr<CSpace>; MAX_CSPACES]>(
            [0usize; MAX_CSPACES],
        )
    }
};

/// Register a `CSpace` pointer under its ID.
///
/// Called immediately after a [`CSpace`] is heap-allocated. Panics (in debug)
/// or silently drops (in release) if `id >= MAX_CSPACES`.
pub fn register_cspace(id: CSpaceId, ptr: *mut CSpace)
{
    if (id as usize) < MAX_CSPACES
    {
        CSPACE_REGISTRY[id as usize].store(ptr, Ordering::Release);
    }
}

/// Clear a `CSpace` registration.
///
/// Called from `dealloc_object` for `ObjectType::CSpaceObj` *before* freeing
/// the backing allocation, so no dangling pointer is observable.
pub fn unregister_cspace(id: CSpaceId)
{
    if (id as usize) < MAX_CSPACES
    {
        CSPACE_REGISTRY[id as usize].store(core::ptr::null_mut(), Ordering::Release);
    }
}

/// Resolve a `CSpaceId` to a raw pointer.
///
/// Returns `None` if `id` is out of range or not yet registered. The returned
/// pointer is valid only while the corresponding `CSpaceKernelObject` has a
/// positive refcount and `DERIVATION_LOCK` is held by the caller.
pub fn lookup_cspace(id: CSpaceId) -> Option<*mut CSpace>
{
    if (id as usize) >= MAX_CSPACES
    {
        return None;
    }
    let ptr = CSPACE_REGISTRY[id as usize].load(Ordering::Acquire);
    if ptr.is_null() { None } else { Some(ptr) }
}

/// Allocate a unique `CSpace` ID.
///
/// Called by `SYS_CAP_CREATE_CSPACE` when creating new `CSpace` objects at
/// runtime. The root `CSpace` is assigned ID 0 at init time via this same
/// counter.
pub fn alloc_cspace_id() -> CSpaceId
{
    NEXT_CSPACE_ID.fetch_add(1, Ordering::Relaxed)
}

/// Maximum slots in the root `CSpace` (full two-level directory).
const ROOT_CSPACE_MAX_SLOTS: usize = 16384;

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
    /// First slot index of boot module `Frame` capabilities.
    pub module_frame_base: u32,
    /// Number of boot module `Frame` capabilities.
    pub module_frame_count: u32,
    /// Slot index of the `SchedControl` capability.
    pub sched_control_slot: u32,
    /// Slot index of the `SbiControl` capability (RISC-V only; 0 on x86-64).
    pub sbi_control_slot: u32,
    /// Total number of populated slots.
    pub total_populated: usize,
    /// Per-capability descriptors for all populated slots.
    pub descriptors: alloc::vec::Vec<CapDescriptor>,
}

/// Initialise the capability system and populate the root `CSpace.`
///
/// `platform_resources` is the validated list from Phase 6. `boot_info_phys`
/// is the physical address of the [`BootInfo`] structure; re-derived here via
/// the direct physical map (active since Phase 3) to access the memory map.
///
/// Returns a [`CSpaceLayout`] describing the slot ranges populated. Calls
/// [`crate::fatal`] on any allocation failure.
///
/// # Safety
///
/// Must be called exactly once, single-threaded, after Phase 4 (heap active)
/// and Phase 3 (direct map active).
pub fn init_capability_system(
    platform_resources: &[PlatformResource],
    boot_info_phys: u64,
) -> CSpaceLayout
{
    let id = NEXT_CSPACE_ID.fetch_add(1, Ordering::Relaxed);
    let mut cspace = Box::new(CSpace::new(id, ROOT_CSPACE_MAX_SLOTS));

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

    let mut layout = populate_cspace(&mut cspace, mmap, platform_resources);

    // Mint Frame caps for boot modules (raw ELF images for early services).
    // Each module gets a read-only Frame cap so init can map and parse the ELF.
    mint_module_frame_caps(&mut cspace, info, &mut layout);

    // Store in ROOT_CSPACE (kernel runtime only; test builds skip this).
    #[cfg(not(test))]
    // SAFETY: single-threaded boot; ROOT_CSPACE not yet accessed; no concurrent access.
    unsafe {
        // SAFETY: addr_of_mut valid on boxed heap allocation.
        let raw = core::ptr::addr_of_mut!(*cspace);
        register_cspace(id, raw);
        ROOT_CSPACE = Some(cspace);
    }
    // In test mode the box is dropped here — kernel objects are leaked
    // intentionally via Box::into_raw in nonnull_from_box, which is
    // acceptable for isolated unit tests.
    #[cfg(test)]
    let _ = cspace;

    layout
}

/// Core `CSpace` population logic, separated for testability.
///
/// Creates one capability per usable memory region, per platform resource,
/// and one `SchedControl` capability. Returns a [`CSpaceLayout`] describing
/// the slot ranges and per-cap descriptors.
// too_many_lines: one logical pass over all boot-time resource types; splitting
// would require threading shared state (cspace) through multiple helper functions.
#[allow(clippy::too_many_lines)]
fn populate_cspace(
    cspace: &mut CSpace,
    #[cfg_attr(not(test), allow(unused))] mmap: &[MemoryMapEntry],
    platform_resources: &[PlatformResource],
) -> CSpaceLayout
{
    use init_protocol::CapType;

    let mut descriptors = alloc::vec::Vec::new();

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
    let mut memory_frame_base: u32 = 0;
    let mut memory_frame_count: u32 = 0;

    #[cfg(not(test))]
    {
        use crate::mm::buddy::PAGE_SIZE as BUDDY_PAGE_SIZE;

        // Pages kept in the buddy for kernel-internal use (page tables,
        // heap slabs, kernel stacks). 16 MiB = 4096 pages.
        const KERNEL_RESERVE_PAGES: usize = 4096;

        // Maximum number of buddy blocks that drain_for_usercaps can return.
        // Each order can have at most POOL_SIZE entries; in practice far fewer.
        const MAX_DRAIN_BLOCKS: usize = 4096;

        let mut drain_buf = alloc::vec![(0u64, 0usize); MAX_DRAIN_BLOCKS];

        let block_count = crate::mm::with_frame_allocator(|alloc| {
            alloc.drain_for_usercaps(KERNEL_RESERVE_PAGES, &mut drain_buf)
        });

        let mut drained_pages: usize = 0;
        for &(addr, order) in &drain_buf[..block_count]
        {
            let size = (BUDDY_PAGE_SIZE << order) as u64;
            drained_pages += 1 << order;

            let obj = Box::new(FrameObject {
                header: KernelObjectHeader::new(ObjectType::Frame),
                base: addr,
                size,
                // Buddy-backed: responsible for freeing on final destruction.
                owns_memory: core::sync::atomic::AtomicBool::new(true),
            });
            let ptr = nonnull_from_box(obj);
            let slot = insert_or_fatal(
                cspace,
                CapTag::Frame,
                Rights::MAP | Rights::WRITE | Rights::EXECUTE,
                ptr,
                "Phase 7: cannot allocate Frame capability for usable memory",
            );
            if memory_frame_count == 0
            {
                memory_frame_base = slot;
            }
            descriptors.push(CapDescriptor {
                slot,
                cap_type: CapType::Frame,
                pad: [0; 3],
                aux0: addr,
                aux1: size,
            });
            memory_frame_count += 1;
        }

        crate::kprintln!(
            "Phase 7: {} Frame caps ({} pages drained, {} blocks), kernel reserve {} pages",
            memory_frame_count,
            drained_pages,
            block_count,
            KERNEL_RESERVE_PAGES,
        );
    }

    // Test builds: create Frame caps directly from mmap entries (no buddy).
    #[cfg(test)]
    for entry in mmap
    {
        if entry.memory_type != MemoryType::Usable
        {
            continue;
        }
        let obj = Box::new(FrameObject {
            header: KernelObjectHeader::new(ObjectType::Frame),
            base: entry.physical_base,
            size: entry.size,
            // Test stub: buddy not active; leaking on destruction is the
            // expected unit-test behaviour.
            owns_memory: core::sync::atomic::AtomicBool::new(false),
        });
        let ptr = nonnull_from_box(obj);
        let slot = insert_or_fatal(
            cspace,
            CapTag::Frame,
            Rights::MAP | Rights::WRITE | Rights::EXECUTE,
            ptr,
            "Phase 7: cannot allocate Frame capability for usable memory",
        );
        if memory_frame_count == 0
        {
            memory_frame_base = slot;
        }
        descriptors.push(CapDescriptor {
            slot,
            cap_type: CapType::Frame,
            pad: [0; 3],
            aux0: entry.physical_base,
            aux1: entry.size,
        });
        memory_frame_count += 1;
    }

    // Platform resources → type-specific capabilities.
    let mut hw_cap_base: u32 = 0;
    let mut hw_cap_count: u32 = 0;
    for res in platform_resources
    {
        match res.resource_type
        {
            // MMIO regions: MAP | WRITE (init is root authority; it delegates
            // narrower rights to child services).
            ResourceType::MmioRange | ResourceType::PciEcam | ResourceType::IommuUnit =>
            {
                let obj = Box::new(MmioRegionObject {
                    header: KernelObjectHeader::new(ObjectType::MmioRegion),
                    base: res.base,
                    size: res.size,
                    flags: res.flags,
                    _pad: 0,
                });
                let ptr = nonnull_from_box(obj);
                let slot = insert_or_fatal(
                    cspace,
                    CapTag::MmioRegion,
                    Rights::MAP | Rights::WRITE,
                    ptr,
                    "Phase 7: cannot allocate MmioRegion capability",
                );
                if hw_cap_count == 0
                {
                    hw_cap_base = slot;
                }
                let desc_cap_type = if res.resource_type == ResourceType::PciEcam
                {
                    CapType::PciEcam
                }
                else
                {
                    CapType::MmioRegion
                };
                descriptors.push(CapDescriptor {
                    slot,
                    cap_type: desc_cap_type,
                    pad: [0; 3],
                    aux0: res.base,
                    aux1: res.size,
                });
                hw_cap_count += 1;
            }

            // Firmware tables: Frame cap with MAP only (read-only, no WRITE/EXECUTE).
            // Size is rounded up to cover whole pages so mem_map can map them.
            // The intra-page offset of base is preserved; userspace accounts for it.
            ResourceType::PlatformTable =>
            {
                let page_offset = res.base & 0xFFF;
                let rounded_size = (page_offset + res.size + 0xFFF) & !0xFFF;
                let obj = Box::new(FrameObject {
                    header: KernelObjectHeader::new(ObjectType::Frame),
                    base: res.base,
                    size: rounded_size,
                    // Firmware table: physical memory is not part of the
                    // buddy pool; never return it.
                    owns_memory: core::sync::atomic::AtomicBool::new(false),
                });
                let ptr = nonnull_from_box(obj);
                let slot = insert_or_fatal(
                    cspace,
                    CapTag::Frame,
                    Rights::MAP,
                    ptr,
                    "Phase 7: cannot allocate Frame capability for firmware table",
                );
                if hw_cap_count == 0
                {
                    hw_cap_base = slot;
                }
                descriptors.push(CapDescriptor {
                    slot,
                    cap_type: CapType::Frame,
                    pad: [0; 3],
                    aux0: res.base,
                    aux1: res.size,
                });
                hw_cap_count += 1;
            }

            // Interrupt lines: Interrupt cap with SIGNAL right so drivers can
            // call SYS_IRQ_REGISTER and SYS_IRQ_ACK.
            ResourceType::IrqLine =>
            {
                let obj = Box::new(InterruptObject {
                    header: KernelObjectHeader::new(ObjectType::Interrupt),
                    irq_id: res.id as u32,
                    flags: res.flags,
                });
                let ptr = nonnull_from_box(obj);
                let slot = insert_or_fatal(
                    cspace,
                    CapTag::Interrupt,
                    Rights::SIGNAL,
                    ptr,
                    "Phase 7: cannot allocate Interrupt capability",
                );
                if hw_cap_count == 0
                {
                    hw_cap_base = slot;
                }
                descriptors.push(CapDescriptor {
                    slot,
                    cap_type: CapType::Interrupt,
                    pad: [0; 3],
                    aux0: u64::from(res.id as u32),
                    aux1: u64::from(res.flags),
                });
                hw_cap_count += 1;
            }

            // I/O port ranges (x86-64 only — validated/filtered in Phase 6).
            ResourceType::IoPortRange =>
            {
                let obj = Box::new(IoPortRangeObject {
                    header: KernelObjectHeader::new(ObjectType::IoPortRange),
                    base: res.base as u16,
                    size: res.size as u16,
                    _pad: 0,
                });
                let ptr = nonnull_from_box(obj);
                let slot = insert_or_fatal(
                    cspace,
                    CapTag::IoPortRange,
                    Rights::USE,
                    ptr,
                    "Phase 7: cannot allocate IoPortRange capability",
                );
                if hw_cap_count == 0
                {
                    hw_cap_base = slot;
                }
                descriptors.push(CapDescriptor {
                    slot,
                    cap_type: CapType::IoPortRange,
                    pad: [0; 3],
                    aux0: res.base,
                    aux1: res.size,
                });
                hw_cap_count += 1;
            }
        }
    }

    // One SchedControl capability — grants elevated scheduling authority.
    let obj = Box::new(SchedControlObject {
        header: KernelObjectHeader::new(ObjectType::SchedControl),
    });
    let ptr = nonnull_from_box(obj);
    let sched_control_slot = insert_or_fatal(
        cspace,
        CapTag::SchedControl,
        Rights::ELEVATE,
        ptr,
        "Phase 7: cannot allocate SchedControl capability",
    );
    descriptors.push(CapDescriptor {
        slot: sched_control_slot,
        cap_type: CapType::SchedControl,
        pad: [0; 3],
        aux0: 0,
        aux1: 0,
    });

    // x86-64: root IoPortRange covering the full 64K I/O port space.
    // This is a static architectural fact — not from bootloader PlatformResources.
    // Init subdivides and delegates sub-ranges to services as needed.
    #[cfg(target_arch = "x86_64")]
    {
        let obj = Box::new(IoPortRangeObject {
            header: KernelObjectHeader::new(ObjectType::IoPortRange),
            base: 0,
            size: 0, // 0 means 0x10000 (full range; u16 cannot hold 65536)
            _pad: 0,
        });
        let ptr = nonnull_from_box(obj);
        let ioport_root_slot = insert_or_fatal(
            cspace,
            CapTag::IoPortRange,
            Rights::USE,
            ptr,
            "Phase 7: cannot allocate root IoPortRange capability",
        );
        descriptors.push(CapDescriptor {
            slot: ioport_root_slot,
            cap_type: CapType::IoPortRange,
            pad: [0; 3],
            aux0: 0,
            aux1: 0x10000, // full 64K range
        });
    }

    // RISC-V: one SbiControl capability — grants authority to forward SBI calls.
    #[cfg(target_arch = "riscv64")]
    let sbi_control_slot = {
        let obj = Box::new(SbiControlObject {
            header: KernelObjectHeader::new(ObjectType::SbiControl),
        });
        let ptr = nonnull_from_box(obj);
        let slot = insert_or_fatal(
            cspace,
            CapTag::SbiControl,
            Rights::CALL,
            ptr,
            "Phase 7: cannot allocate SbiControl capability",
        );
        descriptors.push(CapDescriptor {
            slot,
            cap_type: CapType::SbiControl,
            pad: [0; 3],
            aux0: 0,
            aux1: 0,
        });
        slot
    };
    #[cfg(not(target_arch = "riscv64"))]
    let sbi_control_slot = 0u32;

    CSpaceLayout {
        memory_frame_base,
        memory_frame_count,
        hw_cap_base,
        hw_cap_count,
        module_frame_base: 0,
        module_frame_count: 0,
        sched_control_slot,
        sbi_control_slot,
        total_populated: cspace.populated_count(),
        descriptors,
    }
}

/// Mint `Frame` capabilities for boot modules into the root `CSpace`.
///
/// Each boot module (raw ELF image for an early service) gets a read-only
/// Frame cap. Module order matches `boot.conf`'s `modules=` line, so init
/// can identify modules by index (index 0 = procmgr, etc.).
///
/// Updates `layout.module_frame_base`, `layout.module_frame_count`, and
/// appends [`CapDescriptor`] entries for each module.
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

    let mut base_slot: u32 = 0;
    let mut count: u32 = 0;

    for module in modules
    {
        // Round size up to page boundary so mem_map can map whole pages.
        let rounded_size = (module.size + 0xFFF) & !0xFFF;

        let obj = Box::new(FrameObject {
            header: KernelObjectHeader::new(ObjectType::Frame),
            base: module.physical_base,
            size: rounded_size,
            // Boot module pages are pre-loaded by the bootloader outside
            // the buddy pool; never return them.
            owns_memory: core::sync::atomic::AtomicBool::new(false),
        });
        let ptr = nonnull_from_box(obj);
        let slot = insert_or_fatal(
            cspace,
            CapTag::Frame,
            Rights::MAP | Rights::READ,
            ptr,
            "Phase 7: cannot allocate Frame capability for boot module",
        );
        if count == 0
        {
            base_slot = slot;
        }
        layout.descriptors.push(CapDescriptor {
            slot,
            cap_type: CapType::Frame,
            pad: [0; 3],
            aux0: module.physical_base,
            aux1: module.size,
        });
        count += 1;
    }

    layout.module_frame_base = base_slot;
    layout.module_frame_count = count;
    layout.total_populated = cspace.populated_count();
}

/// Cast `Box<T>` to `NonNull<KernelObjectHeader>` by leaking the box.
///
/// # Safety contract
///
/// `T` must be `#[repr(C)]` with `KernelObjectHeader` as its first field
/// (offset 0). Dropping the returned pointer requires reconstructing the
/// original `Box<T>` based on `header.obj_type` (future phases).
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
    let src_slot_id = SlotId::new(src_cspace_id, src_idx_nz);
    let dst_slot_id = SlotId::new(dst_cspace_id, new_idx_nz);

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
        && let Some(parent_cs) = lookup_cspace(parent_id.cspace_id)
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
        && let Some(prev_cs) = lookup_cspace(prev_id.cspace_id)
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
        && let Some(next_cs) = lookup_cspace(next_id.cspace_id)
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
        child_cur = if let Some(child_cs) = lookup_cspace(child_id.cspace_id)
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
