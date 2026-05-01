// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/main.rs

//! Seraph microkernel — kernel entry point.
//!
//! Receives control from the bootloader after page tables are installed and
//! UEFI boot services have exited. See `boot/docs/kernel-handoff.md` for the
//! CPU-state contract and the `abi/boot-protocol` crate for the `BootInfo`
//! layout.
//!
//! Initialization phases implemented here:
//! - Phase 0: validate `BootInfo` (pre-console; halts silently on failure).
//! - Phase 1: initialize early console (serial + framebuffer); emit startup banner.
//! - Phase 2: parse memory map, populate buddy frame allocator.
//! - Phase 3: install kernel page tables (direct physical map + W^X image).
//! - Phase 4: activate kernel heap (`GlobalAlloc` via slab/size-class allocator).
//! - Phase 5: architecture hardware init (GDT/IDT/APIC or stvec/PLIC, timer, syscall).
//! - Phase 6: cache `kernel_mmio` and validate `mmio_apertures` slice before capability minting.
//! - Phase 7: initialise capability subsystem; mint root `CSpace` with initial hardware caps.
//! - Phase 8: initialise per-CPU scheduler state and per-CPU idle threads for all online CPUs.
//! - Phase 9: create init process address space + TCB; hand off root `CSpace`; enter user mode.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(not(test))]
use core::panic::PanicInfo;
#[cfg(not(test))]
use core::sync::atomic::{AtomicU32, Ordering};

// Pull in the `alloc` crate (Box, Vec, …) for no_std kernel builds.
// In test mode the standard library provides alloc implicitly.
#[cfg(not(test))]
extern crate alloc;

// ── AP ready counter ──────────────────────────────────────────────────────────

/// Number of APs that have completed SMP startup and are online.
///
/// Incremented by each AP in `kernel_entry_ap` just before entering the idle
/// loop. The BSP spins on this counter after sending SIPIs to wait for all APs
/// to come online before entering the scheduler.
#[cfg(not(test))]
static APS_READY: AtomicU32 = AtomicU32::new(0);

use boot_protocol::BootInfo;

mod arch;
mod cap;
mod console;
mod framebuffer;
mod ipc;
pub mod irq;
mod mm;
mod percpu;
mod platform;
mod sched;
mod sync;
mod syscall;
mod validate;

/// Kernel entry point.
///
/// Called by the bootloader with CPU state per `boot/docs/kernel-handoff.md`.
/// `boot_info` is the physical address of a populated [`BootInfo`] structure,
/// accessible before the kernel's own page tables are established because the
/// bootloader identity-maps the `BootInfo` region.
// too_many_lines: kernel_entry is the single-entry boot sequence; splitting it would
// obscure the sequential phase structure without reducing actual complexity.
// not_unsafe_ptr_arg_deref: boot_info is validated (null + alignment) before deref;
// the function is `extern "C"` and cannot be marked unsafe per the ABI contract.
// needless_range_loop/cast_possible_truncation: cpu_idx loop uses the index directly
// as both slice index and CPU ID; Seraph never has > 2^32 CPUs.
#[unsafe(no_mangle)]
#[allow(
    clippy::too_many_lines,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::needless_range_loop,
    clippy::cast_possible_truncation,
    clippy::similar_names
)]
pub extern "C" fn kernel_entry(boot_info: *const BootInfo) -> !
{
    // ── Phase 0: validate BootInfo ──────────────────────────────────────────
    // Pre-console. On failure the kernel halts silently; no output is possible
    // yet. GDB can distinguish this halt from a successful boot by checking
    // whether execution reaches the Phase 1 console init below.
    //
    // SAFETY: validate_boot_info checks null and alignment before dereferencing.
    if !unsafe { validate::validate_boot_info(boot_info) }
    {
        arch::current::cpu::halt_loop();
    }

    // SAFETY: validate_boot_info confirmed non-null, aligned, and readable.
    let info = unsafe { &*boot_info };

    // Copy all fields needed beyond Phase 3 out of BootInfo now, while the
    // identity mapping is still live. After Phase 3 activates the kernel page
    // tables, the physical address in `info` is no longer mapped.
    let boot_cpu_count = info.cpu_count.max(1);
    let boot_cpu_ids = info.cpu_ids;
    let trampoline_pa = info.ap_trampoline_page;
    let init_image = info.init_image; // InitImage is Copy
    let cmdline_phys = info.command_line as u64;
    let cmdline_len = info.command_line_len as usize;

    // ── Phase 1: early console ──────────────────────────────────────────────
    // SAFETY: called exactly once, from the single kernel boot thread, after
    // Phase 0 confirmed boot_info is valid; boot_info pointer from bootloader
    // validated at kernel entry.
    unsafe {
        console::init(info);
    }

    // Decode KERNEL_VERSION — the same constant the SYS_SYSTEM_INFO syscall returns —
    // so the banner and the queryable version are guaranteed to stay in sync.
    let kver = ::syscall::KERNEL_VERSION;
    let (kmaj, kmin, kpat) = (kver >> 32, (kver >> 16) & 0xFFFF, kver & 0xFFFF);
    kprintln!(
        "Seraph kernel v{}.{}.{} ({})",
        kmaj,
        kmin,
        kpat,
        arch::current::ARCH_NAME
    );
    kprintln!("Phase 1: Early Console");
    kprintln!("boot protocol v{}", info.version);

    // ── Phase 2: physical memory ────────────────────────────────────────────
    // Parse the memory map, subtract reserved regions, populate the buddy
    // allocator. Halts with a FATAL message if no usable memory is found.
    //
    // SAFETY: single-threaded boot phase; FRAME_ALLOCATOR static mut not
    // accessed elsewhere; mutable borrow is exclusive.
    let allocator = unsafe { &mut *core::ptr::addr_of_mut!(mm::FRAME_ALLOCATOR) };
    kprintln!("Phase 2: Memory Map Parsing and Buddy Allocator");
    mm::init::init_physical_memory(info, allocator);
    mm::init::print_memory_map(info);

    // ── Phase 3: kernel page tables ─────────────────────────────────────────
    // Replace the bootloader's minimal page tables with the kernel's own,
    // establishing the direct physical map and W^X kernel image mappings.
    //
    // Save the framebuffer physical base before the switch; `info` is a
    // physical-address reference that is no longer identity-mapped in the
    // new tables (it is accessible via the direct map as a future Phase 4
    // concern). All further uses of `info` must be resolved before activate.
    let fb_phys = info.framebuffer.physical_base;
    if let Err(_e) = mm::paging::init_kernel_page_tables(info, allocator)
    {
        fatal("Phase 3: boot page table pool exhausted (RAM > 248 GiB?)");
    }

    // Rebase the boot stack pointer from identity-mapped (VA == PA) to the
    // direct physical map (VA == DIRECT_MAP_BASE + PA). The identity mapping
    // covers only 64 KiB around SP and can be exhausted by later phases;
    // the direct map covers all physical RAM with no size limit.
    // SAFETY: new page tables active with direct map covering all RAM.
    // Adding DIRECT_MAP_BASE to RSP/RBP switches to the same physical
    // frames through the direct map virtual range.
    unsafe {
        arch::current::paging::rebase_boot_stack(mm::paging::DIRECT_MAP_BASE);
    }

    // Rebase MMIO-based console devices to the direct physical map.
    // On RISC-V the UART is MMIO and must be accessed via the direct map after
    // the page table switch; on x86-64 the UART is I/O-mapped (no-op).
    // SAFETY: kernel page tables active with direct physical map covering all
    // RAM and UART MMIO region; framebuffer physical base from validated BootInfo.
    unsafe {
        let uart_phys = arch::current::console::uart_phys_base();
        if uart_phys != 0
        {
            arch::current::console::rebase_serial(mm::paging::phys_to_virt(uart_phys));
        }
        console::rebase_framebuffer(fb_phys);
    }
    kprintln!("Phase 3: Kernel Page Tables");
    kprintln!(
        "page tables active (direct map {:#x})",
        mm::paging::DIRECT_MAP_BASE
    );

    // ── Phase 4: kernel heap ─────────────────────────────────────────────────
    // Flip the GlobalAlloc ready flag. The SizeClassAllocator and KernelCaches
    // are const-initialised in their statics; no heap memory is consumed here.
    //
    // Note on bootloader page table frame reclamation:
    // Two categories of frames are NOT reclaimed:
    //   1. BOOT_TABLE_POOL (BSS array): part of the kernel image; cannot be
    //      freed to buddy. The unused portion (~750 KiB) is acceptable waste.
    //   2. Bootloader's original page tables: BootInfo does not record their
    //      physical addresses, so they cannot be identified. Future enhancement:
    //      have the bootloader pass old CR3/satp in BootInfo.
    mm::heap::init();
    kprintln!("Phase 4: Slab Allocator and Kernel Heap");
    kprintln!("kernel heap active");

    // Cache `BootInfo.kernel_mmio` so Phase 5 arch hardware init can read
    // bootloader-discovered MMIO bases instead of compile-time defaults. This
    // is heap-free and depends only on the direct physical map (Phase 3).
    // SAFETY: single-threaded boot; called exactly once, after Phase 3.
    unsafe { platform::capture_kernel_mmio(boot_info as u64) };

    // ── Phase 5: architecture hardware initialization ─────────────────────────
    kprintln!("Phase 5: Architecture Hardware Initialisation");
    // SAFETY: single-threaded boot phase; heap and direct map active; called
    // once during initialization; dependencies (Phases 2-4) completed.
    unsafe {
        arch::current::interrupts::init();
    }
    kprintln!("interrupts ok");
    // Install per-CPU GS-base (x86-64) / tp (RISC-V) for the BSP.
    // Must be before timer::init() — the timer ISR calls current_cpu() which
    // reads GS-base. Without this, a timer interrupt before init_bsp reads
    // garbage from gs:[0].
    #[cfg(not(test))]
    // SAFETY: GDT/TSS loaded by interrupt init above; current_cpu() not yet
    // called; BSP per-CPU initialization happens once during boot.
    unsafe {
        percpu::init_bsp();
    }
    kprintln!("percpu ok");
    // SAFETY: IDT installed and interrupts initialized above; syscall entry
    // point registered during arch init; single-threaded boot phase.
    unsafe {
        arch::current::syscall::init();
    }
    kprintln!("syscall ok");
    // Enable preemption timer at 1 ms period (both architectures).
    // With TIME_SLICE_TICKS=10, this gives a 10 ms scheduling quantum.
    // timer::init() enables interrupts as its final step.
    // SAFETY: IDT/GDT/interrupts initialized above; percpu initialized;
    // called once during boot with all prerequisites met.
    unsafe {
        arch::current::timer::init(1_000);
    }
    kprintln!("timer ok");

    // Initialize the CPU-to-APIC-ID mapping for wakeup IPIs.
    #[cfg(not(test))]
    // SAFETY: single-threaded boot; boot_cpu_ids copied from BootInfo above;
    // init_apic_ids writes CPU_APIC_IDS once before SMP is active.
    unsafe {
        percpu::init_apic_ids(&boot_cpu_ids);
    }

    // ── Phase 6: platform resource validation ─────────────────────────────────
    // Validate mmio_apertures from BootInfo before Phase 7 mints caps from
    // them. (kernel_mmio was cached earlier, after Phase 4, so Phase 5 arch
    // init can read it.)
    kprintln!("Phase 6: Platform Resource Validation");
    let mmio_apertures = platform::validate_mmio_apertures(boot_info as u64);

    // ── Phase 7: capability system ─────────────────────────────────────────────
    // Initialises the root CSpace and mints initial capabilities for all
    // boot-provided hardware resources.
    kprintln!("Phase 7: Capability System");
    let cspace_layout = cap::init_capability_system(&mmio_apertures, boot_info as u64);
    kprintln!(
        "capability system initialised, {} slots populated",
        cspace_layout.total_populated
    );

    // ── Phase 8: scheduler ────────────────────────────────────────────────────
    // Initialise per-CPU scheduler state and create idle threads.
    // cpu_count from BootInfo (populated by bootloader from ACPI MADT / DTB).
    // APs are not yet started; sched::init allocates idle threads for all CPUs
    // so AP startup can call sched::ap_enter without re-allocating.
    kprintln!("Phase 8: Scheduler");
    let cpu_count = sched::init(boot_cpu_count, allocator);
    kprintln!(
        "scheduler initialised, {} CPU{}",
        cpu_count,
        if cpu_count == 1 { "" } else { "s" }
    );

    // ── Phase 9: create and launch init ───────────────────────────────────────
    // Gated #[cfg(not(test))]: Phase 9 uses heap allocation and arch-specific
    // functions unavailable in the host test environment. Tests exercise Phases
    // 0-8 via their individual stub functions; kernel_entry is never invoked.
    #[cfg(not(test))]
    {
        kprintln!("Phase 9: Init Creation and Scheduler Entry");

        if init_image.segment_count == 0 || init_image.entry_point == 0
        {
            fatal("Phase 9: init image missing or has no entry point");
        }

        kprintln!(
            "init: {} segments entry={:#x}",
            init_image.segment_count,
            init_image.entry_point
        );

        // Create init's user address space via the typed-memory boot path:
        // a slab is retyped from `SEED_FRAME` (page 0 = wrapper page holding
        // `AddressSpaceObject` + inlined `AddressSpace`; page 1 = root PT;
        // pages 2..init_pages = PT growth pool). The wrapper header is the
        // cap object inserted into init's CSpace below.
        // 18 pages = 1 wrapper + 1 root PT + 16 PT pool. Phase 9 mappings
        // (ELF segments, InitInfo, stack) go through the legacy buddy path
        // via `map_page` (kernel-direct call); the wrapper's pool serves
        // only init's userspace `sys_mem_map` calls (TEMP_MAP_BASE +
        // ELF_PAGE_TEMP_VA scratch regions). 16 pool pages comfortably
        // covers the bootstrap loop's PT footprint.
        #[allow(clippy::items_after_statements)]
        const INIT_ASPACE_PAGES: u64 = 18;
        // SAFETY: SEED installed in Phase 7; single-threaded Phase 9.
        let (init_as_obj_nn, init_as_ptr) =
            unsafe { cap::boot_retype_aspace(cap::seed_frame_ref(), INIT_ASPACE_PAGES) };
        let _ = allocator; // legacy buddy path no longer used for init's AS

        // Map each ELF LOAD segment into the init address space. `map_page`
        // self-dispatches via the wrapper back-pointer wired by
        // `boot_retype_aspace`, so every intermediate PT page comes from
        // the wrapper's growth pool.
        for i in 0..init_image.segment_count as usize
        {
            let seg = &init_image.segments[i];
            // SAFETY: init_as_ptr is freshly retyped above; segment data
            // lives in bootloader-loaded memory accessible via the direct
            // physical map (Phase 3).
            unsafe { (*init_as_ptr).map_segment(seg) }
                .unwrap_or_else(|()| fatal("Phase 9: failed to map init segment"));
        }

        // Insert an AddressSpace cap for init's own address space into the root
        // CSpace, followed by Frame caps for each init segment. These are needed
        // so init can create child threads bound to its own address space and map
        // its code pages into child processes once a process manager is available.
        let (init_aspace_cap_slot, segment_frame_base, segment_frame_count) = {
            use boot_protocol::SegmentFlags;
            use cap::object::{FrameObject, KernelObjectHeader, ObjectType};
            use cap::slot::{CapTag, Rights};

            // SAFETY: ROOT_CSPACE initialized in Phase 7, still owned by kernel
            // (not yet transferred to init); single-threaded boot phase.
            let cs = unsafe { cap::root_cspace_mut() }
                .unwrap_or_else(|| fatal("Phase 9: ROOT_CSPACE missing"));

            let aspace_slot = cs
                .insert_cap(
                    CapTag::AddressSpace,
                    Rights::MAP | Rights::READ,
                    init_as_obj_nn,
                )
                .unwrap_or_else(|_| fatal("Phase 9: cannot insert init AddressSpace cap"));

            // Frame caps for each init segment (phys base + size + permissions).
            let seg_count = init_image.segment_count as usize;
            let mut seg_base: u32 = 0;
            for i in 0..seg_count
            {
                let seg = &init_image.segments[i];
                let rights = match seg.flags
                {
                    SegmentFlags::Read => Rights::MAP,
                    SegmentFlags::ReadWrite => Rights::MAP | Rights::WRITE,
                    SegmentFlags::ReadExecute => Rights::MAP | Rights::EXECUTE,
                };
                let fo_nn = cap::mint_phase7_body(FrameObject {
                    header: KernelObjectHeader::with_ancestor(
                        ObjectType::Frame,
                        cap::seed_header_nn(),
                    ),
                    base: seg.phys_addr,
                    size: seg.size,
                    // Init ELF segment: not retypable; cap minted without RETYPE.
                    available_bytes: core::sync::atomic::AtomicU64::new(0),
                    // Init ELF segments are bootloader-loaded pages outside
                    // the buddy pool; never return them.
                    owns_memory: core::sync::atomic::AtomicBool::new(false),
                    allocator: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
                    lock: core::sync::atomic::AtomicU32::new(0),
                });
                let slot = cs
                    .insert_cap(CapTag::Frame, rights, fo_nn)
                    .unwrap_or_else(|_| fatal("Phase 9: cannot insert init segment Frame cap"));
                if i == 0
                {
                    seg_base = slot.get();
                }
            }
            kprintln!(
                "init: aspace cap={} + {} frame caps",
                aspace_slot.get(),
                seg_count,
            );
            (aspace_slot.get(), seg_base, seg_count as u32)
        };

        // ── Populate InitInfo region ─────────────────────────────────────────
        // Allocate enough physical pages for InitInfo + CapDescriptor array +
        // command line, fill them via the direct map, then map read-only into
        // init's address space starting at INIT_INFO_VADDR.
        let info_page_virt = {
            use init_protocol::{INIT_INFO_VADDR, INIT_PROTOCOL_VERSION, InitInfo};

            let descriptors_offset = core::mem::size_of::<InitInfo>() as u32;
            let desc_count = cspace_layout.descriptors.len();
            let desc_byte_len = desc_count * core::mem::size_of::<init_protocol::CapDescriptor>();
            let cmdline_start = descriptors_offset as usize + desc_byte_len;
            let total_bytes = cmdline_start + cmdline_len;
            let info_pages = total_bytes.div_ceil(mm::PAGE_SIZE).max(1);

            // Allocate and map each page.
            let flags = mm::paging::PageFlags {
                readable: true,
                writable: false,
                executable: false,
                uncacheable: false,
            };
            /// Resolve a byte offset within the `InitInfo` region to a writable
            /// direct-map pointer, handling page boundaries.
            #[allow(clippy::items_after_statements)]
            fn info_ptr(page_ptrs: &[*mut u8], offset: usize) -> *mut u8
            {
                let page_idx = offset / mm::PAGE_SIZE;
                let page_off = offset % mm::PAGE_SIZE;
                // SAFETY: page_ptrs[page_idx] is a valid direct-map pointer.
                unsafe { page_ptrs[page_idx].add(page_off) }
            }

            // Track per-page direct-map pointers so we can write across
            // page boundaries without requiring physically contiguous memory.
            if info_pages > init_protocol::INIT_INFO_MAX_PAGES
            {
                fatal("Phase 9: InitInfo region too large");
            }
            let mut page_ptrs: [*mut u8; init_protocol::INIT_INFO_MAX_PAGES] =
                [core::ptr::null_mut(); init_protocol::INIT_INFO_MAX_PAGES];

            for pg in 0..info_pages
            {
                let phys = allocator
                    .alloc(0)
                    .unwrap_or_else(|| fatal("Phase 9: out of memory for InitInfo"));
                let virt = mm::paging::phys_to_virt(phys) as *mut u8;
                // SAFETY: just allocated; valid for PAGE_SIZE bytes.
                unsafe { core::ptr::write_bytes(virt, 0, mm::PAGE_SIZE) };
                let map_va = INIT_INFO_VADDR + (pg as u64) * mm::PAGE_SIZE as u64;
                // SAFETY: init_as_ptr valid; phys just allocated; map_va page-aligned.
                unsafe { (*init_as_ptr).map_page(map_va, phys, flags) }
                    .unwrap_or_else(|()| fatal("Phase 9: failed to map InitInfo page"));
                page_ptrs[pg] = virt;
            }
            let info_base = page_ptrs[0];

            let cmdline_copy_len = cmdline_len;
            let cmdline_off = if cmdline_copy_len > 0
            {
                cmdline_start as u32
            }
            else
            {
                0
            };

            let info = InitInfo {
                version: INIT_PROTOCOL_VERSION,
                cap_descriptor_count: desc_count as u32,
                aspace_cap: init_aspace_cap_slot,
                sched_control_cap: cspace_layout.sched_control_slot,
                memory_frame_base: cspace_layout.memory_frame_base,
                memory_frame_count: cspace_layout.memory_frame_count,
                segment_frame_base,
                segment_frame_count,
                module_frame_base: cspace_layout.module_frame_base,
                module_frame_count: cspace_layout.module_frame_count,
                hw_cap_base: cspace_layout.hw_cap_base,
                hw_cap_count: cspace_layout.hw_cap_count,
                cap_descriptors_offset: descriptors_offset,
                thread_cap: 0, // patched below after Thread cap is minted
                cmdline_offset: cmdline_off,
                cmdline_len: cmdline_copy_len as u32,
                sbi_control_cap: cspace_layout.sbi_control_slot,
                cspace_cap: 0, // patched below after CSpace cap is minted
                irq_range_cap: cspace_layout.irq_range_slot,
                acpi_rsdp_frame_cap: cspace_layout.acpi_rsdp_frame_slot,
                acpi_region_frame_base: cspace_layout.acpi_region_frame_base,
                acpi_region_frame_count: cspace_layout.acpi_region_frame_count,
                dtb_frame_cap: cspace_layout.dtb_frame_slot,
                _pad_tail: 0,
            };

            // Write InitInfo header (always fits in first page).
            // SAFETY: info_base is page-aligned; InitInfo fits in one page.
            #[allow(clippy::cast_ptr_alignment)]
            unsafe {
                core::ptr::write(info_base.cast::<InitInfo>(), info);
            }

            // Write CapDescriptor array — may span page boundaries.
            let desc_src = cspace_layout.descriptors.as_ptr().cast::<u8>();
            let mut written = 0usize;
            while written < desc_byte_len
            {
                let offset = descriptors_offset as usize + written;
                let chunk = (mm::PAGE_SIZE - offset % mm::PAGE_SIZE).min(desc_byte_len - written);
                // SAFETY: offset is within the mapped region; desc_src is valid.
                unsafe {
                    let dst = info_ptr(&page_ptrs, offset);
                    core::ptr::copy_nonoverlapping(desc_src.add(written), dst, chunk);
                }
                written += chunk;
            }

            // Copy kernel command line after the CapDescriptor array.
            if cmdline_copy_len > 0 && cmdline_phys != 0
            {
                let cmdline_src = mm::paging::phys_to_virt(cmdline_phys) as *const u8;
                let mut written = 0usize;
                while written < cmdline_copy_len
                {
                    let offset = cmdline_start + written;
                    let chunk =
                        (mm::PAGE_SIZE - offset % mm::PAGE_SIZE).min(cmdline_copy_len - written);
                    // SAFETY: offset within mapped region; cmdline_src is valid.
                    unsafe {
                        let dst = info_ptr(&page_ptrs, offset);
                        core::ptr::copy_nonoverlapping(cmdline_src.add(written), dst, chunk);
                    }
                    written += chunk;
                }
            }

            kprintln!(
                "init: info at {:#x} ({} cap descriptors, {} pages)",
                INIT_INFO_VADDR,
                desc_count,
                info_pages,
            );

            info_base
        };

        // Map init's user stack (INIT_STACK_PAGES pages below INIT_STACK_TOP).
        // SAFETY: init_as_ptr valid (allocated above); stack_top is page-aligned
        // constant within user address range; frame allocator validated in Phase 2.
        unsafe {
            (*init_as_ptr).map_stack(
                mm::address_space::INIT_STACK_TOP,
                mm::address_space::INIT_STACK_PAGES,
            )
        }
        .unwrap_or_else(|()| fatal("Phase 9: failed to map init stack"));

        // Retype a 5-page slab from SEED_FRAME for init's Thread:
        //   pages 0..3 — kernel stack (KERNEL_STACK_PAGES = 4 = 16 KiB)
        //   page 4   — ThreadObject (24 B) followed by ThreadControlBlock
        // Mirrors the layout established in `sys_cap_create_thread`.
        #[allow(clippy::items_after_statements)]
        const INIT_THREAD_PAGES: u64 = (sched::KERNEL_STACK_PAGES + 1) as u64;
        let (init_thread_obj_nn, init_kstack_top, init_tcb) = {
            use cap::object::{KernelObjectHeader, ObjectType, ThreadObject};

            let bytes = INIT_THREAD_PAGES * mm::PAGE_SIZE as u64;
            let seed = cap::seed_frame_ref();
            let offset = cap::retype::retype_allocate(seed, bytes)
                .unwrap_or_else(|_| fatal("Phase 9: SEED too small for init Thread slab"));
            let block_phys = seed.base + offset;
            let block_virt = mm::paging::phys_to_virt(block_phys);
            let kstack_top = block_virt + (sched::KERNEL_STACK_PAGES * mm::PAGE_SIZE) as u64;
            let thread_obj_ptr = kstack_top as *mut ThreadObject;
            let tcb_offset = core::mem::size_of::<ThreadObject>() as u64;
            let tcb_ptr = (kstack_top + tcb_offset) as *mut sched::thread::ThreadControlBlock;

            // Prepare saved CPU state for init: user entry point + kernel stack.
            let init_saved = arch::current::context::new_state(
                init_image.entry_point,
                kstack_top,
                init_protocol::INIT_INFO_VADDR, // forwarded to init's a0/rdi on first entry
                true,
            );

            // SAFETY: tcb_ptr lies on page 4 of the freshly-retyped slab,
            // exclusively owned. CSpace is wired below (after take_root_cspace).
            unsafe {
                core::ptr::write(
                    tcb_ptr,
                    sched::thread::ThreadControlBlock {
                        state: sched::thread::ThreadState::Ready,
                        priority: sched::INIT_PRIORITY,
                        slice_remaining: sched::TIME_SLICE_TICKS,
                        cpu_affinity: sched::AFFINITY_ANY,
                        preferred_cpu: 0,
                        run_queue_next: None,
                        ipc_state: sched::thread::IpcThreadState::None,
                        ipc_msg: ipc::message::Message::default(),
                        reply_tcb: core::ptr::null_mut(),
                        ipc_wait_next: None,
                        is_user: true,
                        saved_state: init_saved,
                        kernel_stack_top: kstack_top,
                        trap_frame: core::ptr::null_mut(),
                        address_space: init_as_ptr,
                        ipc_buffer: 0,
                        wakeup_value: 0,
                        timed_out: false,
                        iopb: core::ptr::null_mut(),
                        blocked_on_object: core::ptr::null_mut(),
                        cspace: core::ptr::null_mut(),
                        thread_id: 1, // 0 = idle BSP, 1 = init
                        context_saved: core::sync::atomic::AtomicU32::new(1),
                        death_observers: [sched::thread::DeathObserver::empty();
                            sched::thread::MAX_DEATH_OBSERVERS],
                        death_observer_count: 0,
                        sleep_deadline: 0,
                        magic: sched::thread::TCB_MAGIC,
                    },
                );
                core::ptr::write(
                    thread_obj_ptr,
                    ThreadObject {
                        header: KernelObjectHeader::with_ancestor(
                            ObjectType::Thread,
                            cap::seed_header_nn(),
                        ),
                        tcb: tcb_ptr,
                    },
                );
            }
            seed.header.inc_ref();

            // SAFETY: thread_obj_ptr in-place; header at offset 0.
            let nn = unsafe {
                core::ptr::NonNull::new_unchecked(thread_obj_ptr.cast::<KernelObjectHeader>())
            };
            (nn, kstack_top, tcb_ptr)
        };

        // Mint a Thread cap for init's own thread (CONTROL right) into the root
        // CSpace. This must happen before take_root_cspace transfers ownership.
        let init_thread_cap_slot = {
            use cap::slot::{CapTag, Rights};

            // SAFETY: ROOT_CSPACE initialized in Phase 7; single-threaded boot.
            let cs = unsafe { cap::root_cspace_mut() }
                .unwrap_or_else(|| fatal("Phase 9: ROOT_CSPACE missing for Thread cap"));
            cs.insert_cap(CapTag::Thread, Rights::CONTROL, init_thread_obj_nn)
                .unwrap_or_else(|_| fatal("Phase 9: cannot insert init Thread cap"))
                .get()
        };

        kprintln!("init: thread cap={}", init_thread_cap_slot);

        // Mint a CSpace cap so init can create threads bound to its own CSpace
        // (e.g. a log-serving thread that shares init's capability namespace).
        // The wrapper `CSpaceKernelObject` was constructed alongside the
        // CSpace itself in Phase 7's `boot_retype_cspace` and is reachable
        // via `CSpace::kobj`.
        let init_cspace_cap_slot = {
            use cap::object::{CSpaceKernelObject, KernelObjectHeader};
            use cap::slot::{CapTag, Rights};
            use core::ptr::NonNull;

            // SAFETY: ROOT_CSPACE initialized in Phase 7; single-threaded boot.
            let cs = unsafe { cap::root_cspace_mut() }
                .unwrap_or_else(|| fatal("Phase 9: ROOT_CSPACE missing for CSpace cap"));
            let cs_kobj_ptr: *mut CSpaceKernelObject = cs
                .kobj_ptr()
                .unwrap_or_else(|| fatal("Phase 9: ROOT_CSPACE wrapper not wired"));
            // SAFETY: cs_kobj_ptr is in-place inside the SEED slab; header at offset 0.
            let cs_nn = unsafe { NonNull::new_unchecked(cs_kobj_ptr.cast::<KernelObjectHeader>()) };
            cs.insert_cap(
                CapTag::CSpace,
                Rights::INSERT | Rights::DELETE | Rights::DERIVE,
                cs_nn,
            )
            .unwrap_or_else(|_| fatal("Phase 9: cannot insert init CSpace cap"))
            .get()
        };

        // Patch thread_cap and cspace_cap in the InitInfo page.
        // SAFETY: info_page_virt points to a kernel-writable page (mapped
        // read-only in userspace but writable via the direct physical map);
        // single-threaded boot; the write is within the InitInfo struct bounds.
        // cast_ptr_alignment: page alignment (4096) exceeds InitInfo alignment (4).
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            let info_ptr = info_page_virt.cast::<init_protocol::InitInfo>();
            (*info_ptr).thread_cap = init_thread_cap_slot;
            (*info_ptr).cspace_cap = init_cspace_cap_slot;
        }

        // Transfer the root CSpace pointer into init's TCB. The CSpace lives
        // inside a SEED-pinned slab; ownership is conveyed by-pointer (no
        // Box involved). `take_root_cspace` clears `ROOT_CSPACE` so no
        // other code observes a live root pointer afterwards.
        // SAFETY: ROOT_CSPACE wired in Phase 7; single-threaded boot.
        let init_cspace_ptr = unsafe { cap::take_root_cspace() };
        if init_cspace_ptr.is_null()
        {
            fatal("Phase 9: ROOT_CSPACE missing");
        }
        // SAFETY: init_tcb was just retyped above and is valid; single-threaded boot.
        unsafe { (*init_tcb).cspace = init_cspace_ptr };

        // Enqueue init on the BSP scheduler at INIT_PRIORITY.
        // SAFETY: scheduler initialized in Phase 8; single-threaded boot phase;
        // BSP scheduler (index 0) exclusively accessed by boot thread.
        unsafe {
            let sched = sched::scheduler_for(0);
            sched.enqueue(init_tcb, sched::INIT_PRIORITY);
        }

        kprintln!(
            "init: TCB tid=1 priority={} stack={:#x}",
            sched::INIT_PRIORITY,
            init_kstack_top
        );

        // ── SMP: start Application Processors ────────────────────────────────
        // Arch-neutral: each architecture implements `ap_trampoline::setup_trampoline`
        // and `ap_trampoline::start_ap` behind the `arch::current` facade.
        // APs enter their idle loops and increment APS_READY. The BSP waits
        // for all APs before entering the scheduler.
        {
            let ap_count = (boot_cpu_count - 1) as usize;
            if ap_count > 0
            {
                if trampoline_pa == 0
                {
                    kprintln!("smp: no AP trampoline page — SMP disabled");
                }
                else
                {
                    kprintln!("smp: starting {} AP(s)", ap_count);

                    // Copy/patch the trampoline code into the physical page.
                    // SAFETY: direct physical map active (Phase 3); trampoline_pa
                    // from BootInfo points to bootloader-allocated RWX page <1 MiB.
                    unsafe {
                        arch::current::ap_trampoline::setup_trampoline(trampoline_pa);
                    }

                    let entry_fn = kernel_entry_ap as *const () as u64;

                    for cpu_idx in 1..=ap_count
                    {
                        let hw_id = boot_cpu_ids[cpu_idx];
                        // SAFETY: idle threads allocated in Phase 8 for all CPUs;
                        // cpu_idx < boot_cpu_count validated by loop bound.
                        let stack_top = unsafe { sched::idle_stack_top_for(cpu_idx) };

                        // Arch-specific: write params + send SIPI / SBI hart_start.
                        // SAFETY: trampoline setup complete above; all boot phases
                        // (2-8) initialized; AP will use shared kernel state.
                        let ok = unsafe {
                            arch::current::ap_trampoline::start_ap(
                                trampoline_pa,
                                cpu_idx as u32,
                                hw_id,
                                entry_fn,
                                stack_top,
                            )
                        };
                        if !ok
                        {
                            kprintln!("smp: start_ap(cpu={}) failed", cpu_idx);
                            continue;
                        }

                        while APS_READY.load(Ordering::Acquire) < cpu_idx as u32
                        {
                            core::hint::spin_loop();
                        }
                    }

                    kprintln!("smp: all {} AP(s) online", ap_count);
                }
            }
        }

        // Hand off to the scheduler. Never returns.
        sched::enter();
    }

    // Test-mode divergence: kernel_entry is never called in host tests, but
    // the function must type-check as returning `!`.
    #[cfg(test)]
    arch::current::cpu::halt_loop()
}

// ── AP entry point ────────────────────────────────────────────────────────────

/// Entry point for Application Processor startup.
///
/// Called from the AP trampoline after the PM32 → LM64 transition. The AP
/// arrives here with:
/// - RSP set to its idle thread kernel stack top (loaded by the relay stub).
/// - RDI = `cpu_id`, RSI = `ist1_top`, RDX = `ist2_top` (trampoline params).
///
/// Initialises per-CPU hardware state, announces the AP as ready, then enters
/// the idle loop via [`sched::ap_enter`].
///
/// # Safety
/// Runs on a fresh kernel stack. All Phase 3–8 globals (direct map, heap,
/// scheduler, IDT) must have been set up by the BSP before this is called.
#[cfg(not(test))]
#[unsafe(no_mangle)]
pub extern "C" fn kernel_entry_ap(cpu_id: u32, ist1_top: u64, ist2_top: u64) -> !
{
    // 1. Load per-CPU GDT + TSS with the idle thread's kernel stack as RSP0.
    //    Must come before percpu::init_ap because lgdt reloads all segment
    //    registers (including GS ← null selector), which resets the GS
    //    shadow-register base to 0. percpu::init_ap reinstalls it afterward.
    // SAFETY: idle threads allocated in Phase 8 (BSP); cpu_id in valid range.
    let idle_stack_top = unsafe { sched::idle_stack_top_for(cpu_id as usize) };
    // SAFETY: heap active (Phase 4, BSP); init_ap box-allocates per-CPU GDT+TSS;
    // called once per AP during startup; idle_stack_top from allocated idle thread.
    unsafe {
        arch::current::gdt::init_ap(cpu_id, idle_stack_top, ist1_top, ist2_top);
    }

    // 2. Install per-CPU GS-base (IA32_GS_BASE → &PER_CPU[cpu_id]).
    //    After gdt::init_ap reloaded GS with selector 0, the GS shadow-register
    //    base is 0. Write the MSR here to restore GS-relative addressing.
    // SAFETY: PER_CPU[cpu_id] allocated during Phase 8 (BSP); not yet accessed
    // by this AP or any other CPU; called once per AP during startup.
    unsafe {
        percpu::init_ap(cpu_id);
    }

    // 3. Load the BSP's shared IDT on this AP.
    // SAFETY: IDT initialized and populated in Phase 5 (BSP); all interrupt
    // handlers registered; IDT is shared across all CPUs (x86-64 arch).
    unsafe {
        arch::current::idt::load();
    }

    // 4. Software-enable local APIC and mask all LVT entries.
    // SAFETY: direct physical map active (Phase 3, BSP); APIC MMIO region
    // accessible; local APIC per-CPU configuration; called once per AP.
    unsafe {
        arch::current::interrupts::init_ap();
    }

    // 5. Configure SYSCALL/SYSRET MSRs (IA32_EFER.SCE, STAR, LSTAR, SFMASK).
    //    MSR writes are per-CPU; each AP must execute this.
    // SAFETY: running at ring 0; GDT loaded above; MSR configuration is
    // per-CPU; syscall entry handler already registered (Phase 5, BSP).
    unsafe {
        arch::current::syscall::init();
    }

    // 6. Start the per-CPU preemption timer (1 ms, matching BSP).
    //    x86-64: programs the local APIC timer using the BSP's calibrated rate.
    //    RISC-V: arms the SBI timer using the BSP's stored tick period.
    // SAFETY: local APIC/interrupt delivery initialized above; timer IRQ
    // handler registered (Phase 5, BSP); per-CPU timer configuration.
    unsafe {
        arch::current::timer::init_ap(1_000);
    }

    kprintln!("smp: AP {} online", cpu_id);

    // 6. Signal BSP that this AP is ready.
    APS_READY.fetch_add(1, Ordering::Release);

    // 7. Enter idle loop (never returns).
    sched::ap_enter(cpu_id)
}

/// Emit a fatal error message and halt.
///
/// Used for unrecoverable post-console errors. Prints the message then halts
/// permanently. Never returns.
pub(crate) fn fatal(msg: &str) -> !
{
    kprintln!("FATAL: {}", msg);
    arch::current::cpu::halt_loop();
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> !
{
    // Use panic_write_fmt (serial-only, lock-bypassing) instead of kprintln!.
    // kprintln! goes through CONSOLE_LOCK; if the panic occurred inside
    // console_write_fmt (or anywhere else that holds the lock), using kprintln!
    // here would deadlock. panic_write_fmt force-stores the lock and writes
    // directly to serial, which is always safe.
    if let Some(loc) = info.location()
    {
        // SAFETY: panic handler runs once per panic; panic_write_fmt bypasses
        // CONSOLE_LOCK to avoid deadlock; writes directly to serial port.
        unsafe {
            console::panic_write_fmt(format_args!(
                "\nPANIC at {}:{}: {}\n",
                loc.file(),
                loc.line(),
                info.message()
            ));
        }
    }
    else
    {
        // SAFETY: panic handler runs once per panic; panic_write_fmt bypasses
        // CONSOLE_LOCK to avoid deadlock; writes directly to serial port.
        unsafe {
            console::panic_write_fmt(format_args!("\nPANIC: {}\n", info.message()));
        }
    }
    arch::current::cpu::halt_loop();
}
