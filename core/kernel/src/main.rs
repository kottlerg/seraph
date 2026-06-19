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
//! - Phase 4: typed-memory cap surface (no `GlobalAlloc`; bodies sourced from caps).
//! - Phase 5: architecture hardware init (GDT/IDT/APIC or stvec/PLIC, timer, syscall).
//! - Phase 6: cache `kernel_mmio` and validate `mmio_apertures` slice before capability minting.
//! - Phase 7: initialise capability subsystem; mint root `CSpace` with initial hardware caps;
//!   mint reclaimable Memory caps over bootloader scratch pages (`BootInfo`,
//!   descriptor arrays, transient PT frames) so they flow to userspace via the
//!   standard `CapDescriptor` path.
//! - Phase 8: initialise per-CPU scheduler state and idle threads, start APs,
//!   and retire the AP trampoline identity mapping into a reclaimable Memory cap.
//! - Phase 9: create init process address space + TCB; hand off root `CSpace`; enter user mode.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(not(test))]
use core::panic::PanicInfo;
#[cfg(not(test))]
use core::sync::atomic::{AtomicU32, Ordering};

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
mod cpu_mask;
mod entropy;
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
    let boot_entropy_seed = info.boot_entropy_seed;
    let boot_entropy_len = info.boot_entropy_len;

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
    //
    // Call into the bulk of `kernel_entry` through an `#[inline(never)]`
    // boundary so LLVM cannot hoist sp-derived local-address
    // materialisations from phases 4-9 to before the rebase. Rust
    // inline asm cannot list sp as an output, so a per-call rebase would
    // continue to mislead LLVM about sp's value across the call (the
    // standard ABI promises sp is callee-saved; the rebase asm silently
    // violates that, but only the optimisation barrier of an opaque
    // function call boundary blocks the hoist that hosed PR #138's
    // riscv64 release ktest cell in CI — sepc=0xffffffff8000d972,
    // stval=0x9ddc0f58 from a stale `add s7, sp, 0x19E0`).
    //
    // SAFETY: new page tables active with direct map covering all RAM.
    // Adding DIRECT_MAP_BASE to RSP/RBP switches to the same physical
    // frames through the direct map virtual range.
    unsafe {
        arch::current::paging::rebase_boot_stack(mm::paging::DIRECT_MAP_BASE);
    }

    #[cfg(not(test))]
    // SAFETY: post-rebase phases consume validated boot state copied above.
    unsafe {
        kernel_entry_post_rebase(
            boot_info as u64,
            boot_cpu_count,
            boot_cpu_ids,
            trampoline_pa,
            init_image,
            boot_entropy_seed,
            boot_entropy_len,
            fb_phys,
            allocator,
        )
    }

    // Test-mode divergence: kernel_entry is never called in host tests, but
    // the function must type-check as returning `!`.
    #[cfg(test)]
    arch::current::cpu::halt_loop()
}

/// Continuation of [`kernel_entry`] after the boot-stack rebase.
///
/// `#[inline(never)]` is load-bearing: see the comment in `kernel_entry`
/// at the rebase site. The body runs phase-3 console rebasing through
/// phase-9 `init` launch and the scheduler hand-off.
#[cfg(not(test))]
#[inline(never)]
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::needless_range_loop,
    clippy::similar_names,
    // boot_cpu_ids ([u32; 512] = 2 KiB) and init_image (272 B) cross
    // the by-value/by-reference threshold. The `#[inline(never)]`
    // boundary is what defeats the cross-rebase hoist; the by-value
    // signature is incidental — the ABI passes both via hidden-pointer
    // and emits an explicit memcpy into the callee's stack frame either
    // way. Single boot-path copy; nothing on the hot path.
    clippy::large_types_passed_by_value
)]
unsafe fn kernel_entry_post_rebase(
    boot_info_phys: u64,
    boot_cpu_count: u32,
    boot_cpu_ids: [u32; boot_protocol::MAX_CPUS],
    trampoline_pa: u64,
    init_image: boot_protocol::InitImage,
    mut boot_entropy_seed: [u8; 32],
    boot_entropy_len: u32,
    fb_phys: u64,
    allocator: &'static mut mm::buddy::BuddyAllocator,
) -> !
{
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

    // ── Phase 4: typed-memory cap surface ────────────────────────────────────
    // The kernel does not run a `GlobalAlloc`; every kernel-object body is
    // sourced from a Memory cap via `crate::cap::retype` (caller-supplied at
    // userspace `cap_create_*` boundaries; SEED-backed at boot time and for
    // split-derived wrappers). Phase 4 carries no setup cost — the typed-
    // memory machinery is ready as soon as `SEED_FRAME` is installed in
    // Phase 7.
    //
    // Note on bootloader page table frame reclamation:
    // Bootloader transient page-table frames are now recorded in
    // `BootInfo.reclaim_ranges` (boot protocol v7) and minted into init's
    // CSpace by `cap::mint_reclaim_memory_caps`. The remaining un-reclaimed
    // category is `BOOT_TABLE_POOL` (BSS array): part of the kernel image,
    // cannot be freed to buddy; the unused portion (~750 KiB) is acceptable
    // waste.
    kprintln!("Phase 4: Typed-Memory Cap Surface (no kernel heap)");

    // Cache `BootInfo.kernel_mmio` so Phase 5 arch hardware init can read
    // bootloader-discovered MMIO bases instead of compile-time defaults. This
    // is heap-free and depends only on the direct physical map (Phase 3).
    // SAFETY: single-threaded boot; called exactly once, after Phase 3.
    unsafe { platform::capture_kernel_mmio(boot_info_phys) };

    // Allocate per-CPU storage slabs (SCHEDULERS, IDLE_TCBS, AP TSS/GDT/IST
    // on x86) sized to boot_cpu_count. Must precede Phase 5: timer::init
    // arms the BSP timer, and timer_tick reads the scheduler slab via
    // CPU_COUNT + SCHEDULERS_PTR. Replaces the prior MAX_CPUS-sized BSS
    // tables with dynamically sized allocations.
    sched::init_storage(boot_cpu_count, allocator);

    // Allocate entropy subsystem per-CPU storage (CSPRNGs, jitter accumulators)
    // and the central pool from the buddy allocator, alongside the scheduler
    // slabs and for the same reason: before the Phase-7 user-cap drain, while
    // the buddy still holds large contiguous blocks.
    #[cfg(not(test))]
    entropy::init_storage(boot_cpu_count, allocator);

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
    // `current_cpu()` (and thus the panic-context dump) is safe from here.
    #[cfg(not(test))]
    PANIC_DUMP_READY.store(true, core::sync::atomic::Ordering::Release);
    kprintln!("percpu ok");
    // Enable hardware address-space tags (x86-64 PCID / RISC-V ASID) where
    // available, seeding the tag pool sized to boot_cpu_count. Where the feature
    // is absent this is a no-op and the kernel keeps the full-flush
    // context-switch path. Must precede any tagged activate (Phase 9 / scheduler).
    #[cfg(not(test))]
    // SAFETY: BSP, ring 0 / S-mode; kernel root active; `allocator` is the live
    // frame allocator; called once before any tagged activate.
    unsafe {
        let hw_tags = arch::current::paging::enable_tagged_tlb();
        mm::tag_allocator::enable(hw_tags, boot_cpu_count as usize, allocator);
    }
    kprintln!("tagged-tlb ok");
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

    // Seed the entropy pool from the firmware boot seed (where the bootloader
    // supplied one), hardware RNG (where present, health-gated), and boot-time
    // jitter, then open the kernel draw API. After timer::init so the cycle
    // counter is live for jitter samples.
    #[cfg(not(test))]
    {
        // Clamp defensively: the Phase-0 validator checks only the protocol
        // version, not this length field.
        let n = (boot_entropy_len as usize).min(boot_entropy_seed.len());
        entropy::init(&boot_entropy_seed[..n]);

        // Scrub the conditioned seed once it is absorbed. The BootInfo page is
        // a reclaim range donated to userspace at Phase 7 (memmgr re-hands its
        // frames without zeroing), so the seed must not survive there; the
        // local copy is wiped too. The pool retains the entropy — the seed
        // itself is secret (it feeds KASLR and key/nonce generation).
        boot_entropy_seed.fill(0);
        // SAFETY: the direct map covers all RAM since Phase 3; boot_info_phys
        // was validated in Phase 0. Single-threaded boot, and no live BootInfo
        // reference aliases the page at this point.
        unsafe {
            let bi = mm::paging::phys_to_virt(boot_info_phys) as *mut BootInfo;
            core::ptr::write_bytes(
                core::ptr::addr_of_mut!((*bi).boot_entropy_seed).cast::<u8>(),
                0,
                32,
            );
            (*bi).boot_entropy_len = 0;
        }
    }

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
    // SAFETY: single-threaded boot Phase 6; first and only call.
    let mmio_apertures = unsafe { platform::validate_mmio_apertures(boot_info_phys) };

    // ── Phase 7: capability system ─────────────────────────────────────────────
    // Initialises the root CSpace and mints initial capabilities for all
    // boot-provided hardware resources. `cspace_layout` is held `mut` so
    // the post-SMP late-reclaim pass (after Phase 8) can append the AP
    // trampoline cap to its descriptor table before Phase 9 consumes it.
    kprintln!("Phase 7: Capability System");
    let mut cspace_layout = cap::init_capability_system(mmio_apertures, boot_info_phys);
    kprintln!(
        "capability system initialised, {} slots populated",
        cspace_layout.total_populated
    );

    // ── Phase 8: scheduler ────────────────────────────────────────────────────
    // Initialise per-CPU scheduler state and create idle threads.
    // cpu_count from BootInfo (populated by bootloader from ACPI MADT / DTB).
    // APs are not yet started; sched::init allocates idle threads for all CPUs
    // so AP startup can call sched::ap_enter without re-allocating.
    kprintln!("Phase 8: Scheduler and SMP Bringup");
    let cpu_count = sched::init(boot_cpu_count);
    kprintln!(
        "scheduler initialised, {} CPU{}",
        cpu_count,
        if cpu_count == 1 { "" } else { "s" }
    );

    // SMP startup brings every AP online using the per-CPU idle threads
    // `sched::init` just allocated. APs depend only on Phase 5/8 state
    // (interrupts, percpu, scheduler idle threads); they never touch
    // init's AS or any Phase-9 state. Each architecture implements
    // `ap_trampoline::setup_trampoline` and `ap_trampoline::start_ap`
    // behind the `arch::current` facade. APs enter their idle loops
    // and increment `APS_READY`; the BSP's Acquire load on `APS_READY`
    // doubles as the barrier guaranteeing every AP has jumped from the
    // trampoline page to its kernel-VA entry, making the physical page
    // safe to retire from the identity map immediately below.
    #[cfg(not(test))]
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

    // Validate the entropy subsystem now that every CPU's generator is live:
    // per-CPU independence + sanity (a power-on self-test). The PASS/FAIL marker
    // is scraped by the run-parallel fail-regex.
    #[cfg(not(test))]
    entropy::selftest::run(cpu_count as usize);

    // With every AP executing at kernel virtual addresses, the low-VA
    // identity-RWX mapping at `trampoline_pa` (installed in Phase 3 on
    // both arches; required for the post-`csrw satp` / post-CR3-write
    // instructions inside the trampoline to fetch correctly) is no
    // longer reachable by any code path. Tear it down with a TLB
    // shootdown across all online CPUs, then mint a reclaimable Memory
    // cap over the page so it reaches init via the standard
    // `CapDescriptor` walk.
    #[cfg(not(test))]
    if trampoline_pa != 0
    {
        // SAFETY: APS_READY-observed Acquire above guarantees no AP is
        // still inside the trampoline page; preempt discipline is handled
        // by `unmap_identity_page` internally.
        unsafe {
            mm::paging::unmap_identity_page(trampoline_pa);
        }
        // Re-resolve `BootInfo` through the direct physical map. The
        // original `info` reference points to the bootloader's
        // identity-mapped VA, which Phase 3 unmapped; reading through it
        // here would page-fault. (Phase 7's `cap::init_capability_system`
        // does the same translation when called with `boot_info_phys`.)
        // SAFETY: direct map covers all RAM since Phase 3; boot_info
        // physical address validated in Phase 0.
        let info_dm = unsafe { &*(mm::paging::phys_to_virt(boot_info_phys) as *const BootInfo) };
        // SAFETY: ROOT_CSPACE installed in Phase 7; trampoline page no
        // longer mapped at its PA; single-threaded boot.
        unsafe {
            let cs = cap::root_cspace_mut()
                .unwrap_or_else(|| fatal("late reclaim: ROOT_CSPACE missing"));
            cap::mint_late_reclaim_memory_caps(cs, info_dm, &mut cspace_layout);
        }
    }

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
        // (ELF segments, InitInfo, stack) go through `map_page`, a
        // kernel-direct call whose intermediate PT pages come from
        // `kernel_pt_pool`, not this wrapper's pool. The wrapper's pool
        // serves init's userspace pooled paths: `sys_mem_map`
        // (TEMP_MAP_BASE + ELF_PAGE_TEMP_VA scratch) and, post-Gap-B,
        // `sys_mmio_map` for init's own MMIO (the riscv64 serial UART, one
        // page). 16 pool pages cover that footprint with margin.
        #[allow(clippy::items_after_statements)]
        const INIT_ASPACE_PAGES: u64 = 18;
        // SAFETY: SEED installed in Phase 7; single-threaded Phase 9.
        let (init_as_obj_nn, init_as_ptr) =
            unsafe { cap::boot_retype_aspace(cap::seed_memory_ref(), INIT_ASPACE_PAGES) };
        // init's AS is built from typed memory (boot_retype_aspace), so the
        // buddy allocator is unused here.
        let _ = allocator;

        // Map each ELF LOAD segment into the init address space via
        // `map_page`, whose intermediate PT pages come from `kernel_pt_pool`
        // (the kernel-direct path). The wrapper's growth pool is
        // reserved for init's later userspace pooled maps.
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
        // CSpace, followed by Memory caps for each init segment. These are needed
        // so init can create child threads bound to its own address space and map
        // its code pages into child processes once a process manager is available.
        let (init_aspace_cap_slot, segment_memory_base, segment_memory_count) = {
            use cap::object::{KernelObjectHeader, MemoryObject, ObjectType};
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

            // Memory caps for each init segment (phys base + size + permissions).
            // Minted reclaimable: full byte ledger + `owns_memory = true` +
            // `register_owned_range` so init's reap-handoff donation
            // (`procmgr.REGISTER_INIT_TEARDOWN` → `memmgr.DONATE_FRAMES`)
            // routes these pages into memmgr's pool. The segments live in EFI
            // LoaderData (not in the buddy free list at boot — see `mm/init.rs`
            // exclusion list), so `register_owned_range` accounts for them in
            // the buddy's `total_pages` ledger. memmgr holds the cap from then
            // on; the post-handoff buddy is sealed, so the `dealloc_object` →
            // `free_range` path is a tripwire, not an expected reclaim.
            let seg_count = init_image.segment_count as usize;
            let mut seg_base: u32 = 0;
            for i in 0..seg_count
            {
                let seg = &init_image.segments[i];
                // Full rights regardless of the segment's protection. This cap
                // is held only to donate the frame into memmgr's pool at init's
                // reap, where it becomes general anonymous RAM any consumer may
                // map writable (demand paging, REQUEST_MEMORY_CAPS). Cap rights
                // gate derivation, not the live mapping: init's segments are
                // already mapped at their true protection (R/RW/RX) by
                // `map_segment` above, so a writable cap cannot widen a running
                // segment. A narrower cap donates a non-writable frame that
                // fails downstream writable maps. Mirrors the boot-module and
                // reclaim-scratch mints (`cap/mod.rs`).
                let rights =
                    Rights::MAP | Rights::READ | Rights::WRITE | Rights::EXECUTE | Rights::RETYPE;
                // The bootloader encodes the ELF in-page offset into
                // `phys_addr` so `map_segment` can preserve
                // `phys & 0xFFF == virt & 0xFFF`. The Memory cap exposed
                // to userspace describes whole pages, so mask the base
                // down and ceil-round the size to PAGE_SIZE — upholds
                // MemoryObject's alignment invariant for downstream
                // sys_mem_map / sys_memory_split.
                let page_mask = mm::PAGE_SIZE as u64 - 1;
                let phys_aligned = seg.phys_addr & !page_mask;
                let in_page_off = seg.phys_addr & page_mask;
                let size_aligned = (in_page_off + seg.size + page_mask) & !page_mask;
                // SAFETY: segment phys range is disjoint from buddy
                // free list (excluded in `mm/init.rs::collect_exclusions`)
                // and from boot module ranges; single-threaded boot.
                unsafe {
                    crate::mm::with_frame_allocator(|alloc| {
                        alloc.register_owned_range(phys_aligned, size_aligned);
                    });
                }
                let fo_nn = cap::mint_phase7_body(MemoryObject {
                    header: KernelObjectHeader::with_ancestor(
                        ObjectType::Memory,
                        cap::seed_header_nn(),
                    ),
                    base: phys_aligned,
                    size: size_aligned,
                    available_bytes: core::sync::atomic::AtomicU64::new(size_aligned),
                    owns_memory: core::sync::atomic::AtomicBool::new(true),
                    allocator: crate::cap::retype::RetypeAllocator::new_inline(),
                    lock: core::sync::atomic::AtomicU32::new(0),
                });
                let slot = cs
                    .insert_cap(CapTag::Memory, rights, fo_nn)
                    .unwrap_or_else(|_| fatal("Phase 9: cannot insert init segment Memory cap"));
                cap::note_owns_memory_minted(size_aligned);
                if i == 0
                {
                    seg_base = slot.get();
                }
            }
            kprintln!(
                "init: aspace cap={} + {} memory caps",
                aspace_slot.get(),
                seg_count,
            );
            (aspace_slot.get(), seg_base, seg_count as u32)
        };

        // ── Populate InitInfo region ─────────────────────────────────────────
        // Allocate enough physical pages for InitInfo + CapDescriptor array +
        // command line, fill them via the direct map, then map read-only into
        // init's address space starting at INIT_INFO_VADDR. Each backing page
        // also gets a reclaimable Memory cap minted into init's CSpace so the
        // pages flow into memmgr's pool through init's reap-handoff donate
        // path (see `services/init/src/service.rs` end-of-phase-3).
        let info_page_virt = {
            use cap::object::{KernelObjectHeader, MemoryObject, ObjectType};
            use cap::slot::{CapTag, Rights};
            use init_protocol::{
                INIT_INFO_VADDR, INIT_PROTOCOL_VERSION, InitFramebufferInfo, InitInfo,
                InitPixelFormat,
            };

            // Re-read `BootInfo.framebuffer` via the direct physical map so
            // init can forward the geometry to devmgr. The bootloader's
            // captured GOP framebuffer identity dies at `ExitBootServices`;
            // this is the only path from there to userspace.
            // SAFETY: direct map covers all RAM since Phase 3; boot_info_phys
            // validated in Phase 0; same pattern as `info_dm` above.
            let boot_info_for_fb =
                unsafe { &*(mm::paging::phys_to_virt(boot_info_phys) as *const BootInfo) };
            let fb_in = boot_info_for_fb.framebuffer;
            let init_framebuffer = InitFramebufferInfo {
                physical_base: fb_in.physical_base,
                width: fb_in.width,
                height: fb_in.height,
                stride: fb_in.stride,
                pixel_format: match fb_in.pixel_format
                {
                    boot_protocol::PixelFormat::Rgbx8 => InitPixelFormat::Rgbx8,
                    boot_protocol::PixelFormat::Bgrx8 => InitPixelFormat::Bgrx8,
                },
            };

            let descriptors_offset = core::mem::size_of::<InitInfo>() as u32;
            // SAFETY: single-threaded boot; cspace_layout produced by Phase 7.
            let desc_slice = unsafe { cap::descriptors(&cspace_layout) };
            let desc_count = desc_slice.len();
            let desc_byte_len = core::mem::size_of_val(desc_slice);
            let total_bytes = descriptors_offset as usize + desc_byte_len;
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

            // Allocate the InitInfo region as one physically contiguous
            // buddy extent so the descriptor array (which can span pages
            // once CapDescriptor.name is included) lives in a single
            // backing allocation. Per-page allocation works for the
            // kernel-side `copy_nonoverlapping` writes, but init reads
            // the descriptor slice as one cross-page Rust slice; on
            // release builds LLVM exploits provenance assumptions about
            // single-allocation slices to mis-load fields of descriptors
            // that straddle page boundaries. A contiguous physical
            // extent eliminates the discrepancy between virtual and
            // physical contiguity, so the optimiser sees one allocation
            // backing the slice.
            if info_pages > init_protocol::INIT_INFO_MAX_PAGES
            {
                kprintln!(
                    "Phase 9: InitInfo region needs {} pages ({} descriptors, {} bytes) \
                     but INIT_INFO_MAX_PAGES = {}",
                    info_pages,
                    desc_count,
                    total_bytes,
                    init_protocol::INIT_INFO_MAX_PAGES,
                );
                fatal("Phase 9: InitInfo region too large");
            }
            // Round to next power of two for buddy allocation; for
            // INIT_INFO_MAX_PAGES = 4 the upper bound is order 2 (4 pages).
            let info_order = info_pages.next_power_of_two().trailing_zeros() as usize;
            let block_pages = 1usize << info_order;
            // The block was reserved from the pristine buddy at Phase 7
            // (worst-case INIT_INFO_MAX_PAGES, one contiguous extent); the
            // post-drain buddy is empty. info_pages <= INIT_INFO_MAX_PAGES is
            // enforced above, so it fits within the reserved extent.
            let block_phys = cap::take_init_info_block_phys();
            let block_virt = mm::paging::phys_to_virt(block_phys) as *mut u8;
            // SAFETY: just allocated; valid for block_pages * PAGE_SIZE bytes.
            unsafe {
                core::ptr::write_bytes(block_virt, 0, block_pages * mm::PAGE_SIZE);
            }

            let mut page_ptrs: [*mut u8; init_protocol::INIT_INFO_MAX_PAGES] =
                [core::ptr::null_mut(); init_protocol::INIT_INFO_MAX_PAGES];
            let mut page_phys: [u64; init_protocol::INIT_INFO_MAX_PAGES] =
                [0u64; init_protocol::INIT_INFO_MAX_PAGES];

            for pg in 0..info_pages
            {
                let phys = block_phys + (pg as u64) * mm::PAGE_SIZE as u64;
                // SAFETY: pg < block_pages by construction (info_pages <= block_pages).
                let virt = unsafe { block_virt.add(pg * mm::PAGE_SIZE) };
                let map_va = INIT_INFO_VADDR + (pg as u64) * mm::PAGE_SIZE as u64;
                // SAFETY: init_as_ptr valid; phys is part of the contiguous extent.
                unsafe { (*init_as_ptr).map_page(map_va, phys, flags) }
                    .unwrap_or_else(|()| fatal("Phase 9: failed to map InitInfo page"));
                page_ptrs[pg] = virt;
                page_phys[pg] = phys;
            }
            // The block was reserved at the worst-case INIT_INFO_MAX_PAGES;
            // the unused tail (INIT_INFO_MAX_PAGES - info_pages pages, ≤ 3)
            // stays kernel-held — neither mapped nor minted below. Small but
            // constant waste, bounded and accounted as kernel_reserved.
            let _ = block_pages;
            let info_base = page_ptrs[0];

            let info = InitInfo {
                version: INIT_PROTOCOL_VERSION,
                cap_descriptor_count: desc_count as u32,
                aspace_cap: init_aspace_cap_slot,
                sched_control_cap: cspace_layout.sched_control_slot,
                memory_base: cspace_layout.memory_base,
                memory_count: cspace_layout.memory_count,
                segment_memory_base,
                segment_memory_count,
                hw_cap_base: cspace_layout.hw_cap_base,
                hw_cap_count: cspace_layout.hw_cap_count,
                cap_descriptors_offset: descriptors_offset,
                thread_cap: 0, // patched below after Thread cap is minted
                sbi_control_cap: cspace_layout.sbi_control_slot,
                cspace_cap: 0, // patched below after CSpace cap is minted
                irq_range_cap: cspace_layout.irq_range_slot,
                acpi_rsdp_memory_cap: cspace_layout.acpi_rsdp_memory_slot,
                acpi_region_memory_base: cspace_layout.acpi_region_memory_base,
                acpi_region_memory_count: cspace_layout.acpi_region_memory_count,
                dtb_memory_cap: cspace_layout.dtb_memory_slot,
                init_stack_memory_base: 0,  // patched after stack mint
                init_stack_memory_count: 0, // patched after stack mint
                init_info_memory_base: 0,   // patched after self-mint below
                init_info_memory_count: 0,  // patched after self-mint below
                module_name_count: cspace_layout.module_name_count,
                module_names: cspace_layout.module_names,
                system_ram_bytes: 0, // patched below after all owns_memory mints
                kernel_reserved_bytes: 0, // patched below after all owns_memory mints
                framebuffer: init_framebuffer,
            };

            // Write InitInfo header (always fits in first page).
            // SAFETY: info_base is page-aligned; InitInfo fits in one page.
            #[allow(clippy::cast_ptr_alignment)]
            unsafe {
                core::ptr::write(info_base.cast::<InitInfo>(), info);
            }

            // Write CapDescriptor array — may span page boundaries.
            let desc_src = desc_slice.as_ptr().cast::<u8>();
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

            // Mint a reclaimable Memory cap per InitInfo page so init's
            // reap-handoff donates the pages back to memmgr after AS
            // teardown. Caps carry full pool-frame rights (see the per-mint
            // comment below) and the standard reclaim flags
            // (RETYPE + owns_memory=true + full ledger).
            // SAFETY: ROOT_CSPACE initialised in Phase 7; single-threaded boot.
            let cs = unsafe { cap::root_cspace_mut() }
                .unwrap_or_else(|| fatal("Phase 9: ROOT_CSPACE missing for InitInfo mint"));
            let mut info_memory_base_slot: u32 = 0;
            for pg in 0..info_pages
            {
                let phys = page_phys[pg];
                // No register_owned_range: these pages came from the buddy
                // (reserved at Phase 7), so they are already in `total_pages`.
                // `register_owned_range` would double-count.
                let fo_nn = cap::mint_phase7_body(MemoryObject {
                    header: KernelObjectHeader::with_ancestor(
                        ObjectType::Memory,
                        cap::seed_header_nn(),
                    ),
                    base: phys,
                    size: mm::PAGE_SIZE as u64,
                    available_bytes: core::sync::atomic::AtomicU64::new(mm::PAGE_SIZE as u64),
                    owns_memory: core::sync::atomic::AtomicBool::new(true),
                    allocator: crate::cap::retype::RetypeAllocator::new_inline(),
                    lock: core::sync::atomic::AtomicU32::new(0),
                });
                // Full rights, matching the segment caps above. This cap is
                // held only to donate the page into memmgr's pool at init's
                // reap, where it becomes general anonymous RAM any consumer may
                // map writable or executable (demand paging, REQUEST_MEMORY_CAPS).
                // Cap rights gate derivation, not the live mapping: the InitInfo
                // region is already mapped read-only into init by `map_page`
                // above, so a writable cap cannot widen it. A narrower cap
                // donates a frame that cannot satisfy a downstream RW/RX map and
                // fails the consumer's fault.
                let slot = cs
                    .insert_cap(
                        CapTag::Memory,
                        Rights::MAP
                            | Rights::READ
                            | Rights::WRITE
                            | Rights::EXECUTE
                            | Rights::RETYPE,
                        fo_nn,
                    )
                    .unwrap_or_else(|_| fatal("Phase 9: cannot insert InitInfo Memory cap"));
                cap::note_owns_memory_minted(mm::PAGE_SIZE as u64);
                if pg == 0
                {
                    info_memory_base_slot = slot.get();
                }
            }

            // Patch the just-written InitInfo header with the self-
            // referential cap slot range.
            // SAFETY: info_base mapped writable through the direct map;
            // header lives at offset 0; single-threaded boot.
            #[allow(clippy::cast_ptr_alignment)]
            unsafe {
                let info_ptr = info_base.cast::<InitInfo>();
                (*info_ptr).init_info_memory_base = info_memory_base_slot;
                (*info_ptr).init_info_memory_count = info_pages as u32;
            }

            kprintln!(
                "init: info at {:#x} ({} cap descriptors, {} pages)",
                INIT_INFO_VADDR,
                desc_count,
                info_pages,
            );

            info_base
        };

        // Map init's user stack (INIT_STACK_PAGES pages below INIT_STACK_TOP)
        // and mint a reclaimable Memory cap for each backing page. Inlined
        // (rather than calling `map_stack`) so we capture each phys address
        // for cap minting; `register_owned_range` accounts for the pages in
        // the buddy's `total_pages` ledger. The caps route to memmgr via reap;
        // post-handoff the buddy is sealed, so the dealloc `free_range` path
        // is a tripwire, not an expected reclaim.
        let (init_stack_memory_base, init_stack_memory_count) = {
            use cap::object::{KernelObjectHeader, MemoryObject, ObjectType};
            use cap::slot::{CapTag, Rights};

            const STACK_PAGES: usize = mm::address_space::INIT_STACK_PAGES;
            let stack_top = mm::address_space::INIT_STACK_TOP;
            let rw_flags = mm::paging::PageFlags {
                readable: true,
                writable: true,
                executable: false,
                uncacheable: false,
            };

            // SAFETY: ROOT_CSPACE initialised in Phase 7; single-threaded boot.
            let cs = unsafe { cap::root_cspace_mut() }
                .unwrap_or_else(|| fatal("Phase 9: ROOT_CSPACE missing for stack mint"));

            let mut base_slot: u32 = 0;
            for i in 0..STACK_PAGES
            {
                // Page reserved from the pristine buddy at Phase 7; the
                // post-drain buddy is empty.
                let phys = cap::init_stack_phys(i);

                // Zero the page through the kernel direct map.
                // SAFETY: phys_to_virt yields a valid kernel virtual address.
                unsafe {
                    let virt = mm::paging::phys_to_virt(phys);
                    core::ptr::write_bytes(virt as *mut u8, 0, mm::PAGE_SIZE);
                }

                let virt = stack_top - ((i + 1) * mm::PAGE_SIZE) as u64;
                // SAFETY: virt in user range; phys freshly allocated.
                unsafe {
                    (*init_as_ptr)
                        .map_page(virt, phys, rw_flags)
                        .unwrap_or_else(|()| fatal("Phase 9: failed to map init stack page"));
                }

                // Mint a reclaimable Memory cap covering this page.
                // No register_owned_range: the page came from the buddy
                // (reserved at Phase 7), so it is already in `total_pages`.
                // `register_owned_range` would double-count.
                let fo_nn = cap::mint_phase7_body(MemoryObject {
                    header: KernelObjectHeader::with_ancestor(
                        ObjectType::Memory,
                        cap::seed_header_nn(),
                    ),
                    base: phys,
                    size: mm::PAGE_SIZE as u64,
                    available_bytes: core::sync::atomic::AtomicU64::new(mm::PAGE_SIZE as u64),
                    owns_memory: core::sync::atomic::AtomicBool::new(true),
                    allocator: crate::cap::retype::RetypeAllocator::new_inline(),
                    lock: core::sync::atomic::AtomicU32::new(0),
                });
                // Full rights, matching the segment and InitInfo caps. This cap
                // is held only to donate the page into memmgr's pool at init's
                // reap, where it becomes general anonymous RAM any consumer may
                // map writable or executable. Cap rights gate derivation, not
                // the live mapping: init's stack is already mapped RW by
                // `map_page` above, so the EXECUTE right cannot make the running
                // stack executable. A narrower cap donates a frame that cannot
                // satisfy a downstream RX map and fails the consumer's fault.
                let slot = cs
                    .insert_cap(
                        CapTag::Memory,
                        Rights::MAP
                            | Rights::READ
                            | Rights::WRITE
                            | Rights::EXECUTE
                            | Rights::RETYPE,
                        fo_nn,
                    )
                    .unwrap_or_else(|_| fatal("Phase 9: cannot insert init stack Memory cap"));
                cap::note_owns_memory_minted(mm::PAGE_SIZE as u64);
                if i == 0
                {
                    base_slot = slot.get();
                }
            }
            // The guard page (one page below the stack) is intentionally left
            // unmapped: accessing it will fault, catching stack overflows.
            (base_slot, STACK_PAGES as u32)
        };

        // Patch InitInfo with the just-minted stack cap slot range.
        // SAFETY: info_page_virt mapped writable through the direct map;
        // header at offset 0; single-threaded boot.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            let info_ptr = info_page_virt.cast::<init_protocol::InitInfo>();
            (*info_ptr).init_stack_memory_base = init_stack_memory_base;
            (*info_ptr).init_stack_memory_count = init_stack_memory_count;
        }

        // Patch the immutable memory-accounting facts. All `owns_memory` Memory
        // caps minted to init (Phase-7 drain/module/reclaim + the segment,
        // InitInfo, and stack caps above) are now in the ledger, so the
        // reserved total is the complement against installed RAM.
        let system_ram = mm::init::system_ram_bytes();
        let kernel_reserved = system_ram.saturating_sub(cap::owns_memory_minted_bytes());
        // SAFETY: info_page_virt mapped writable through the direct map;
        // header at offset 0; single-threaded boot.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            let info_ptr = info_page_virt.cast::<init_protocol::InitInfo>();
            (*info_ptr).system_ram_bytes = system_ram;
            (*info_ptr).kernel_reserved_bytes = kernel_reserved;
        }
        kprintln!(
            "init: system_ram={} KiB, kernel_reserved={} KiB, pool={} KiB",
            system_ram / 1024,
            kernel_reserved / 1024,
            cap::owns_memory_minted_bytes() / 1024,
        );

        // Every page Phase 8/9 consumes was pre-reserved before the Phase-7
        // drain, which then took 100% of the remainder, so the post-handoff
        // buddy is empty: every page of RAM is either a named kernel
        // reservation or minted to userspace. The reap-time reverse path has
        // not run yet, so any nonzero free count here is a Phase-7 reservation
        // or drain bug. debug_assert, not assert: a stray free page wastes RAM
        // but keeps the all-RAM-accounted identity sound (kernel_reserved is
        // its complement), so it must not brick a release boot; CI's debug
        // matrix enforces it.
        let buddy_free = crate::mm::with_frame_allocator(|alloc| alloc.free_page_count());
        kprintln!("init: post-handoff buddy free={buddy_free} pages");
        debug_assert!(
            buddy_free == 0,
            "post-handoff buddy is not empty — a Phase-7 reservation or drain leak",
        );

        // Retype a 6-page slab from SEED_FRAME for init's Thread:
        //   pages 0..3 — kernel stack (KERNEL_STACK_PAGES = 4 = 16 KiB)
        //   page 4   — ThreadObject (24 B) followed by ThreadControlBlock
        //   page 5   — per-thread FPU/SIMD/V save area
        // Mirrors the layout established in `sys_cap_create_thread`.
        #[allow(clippy::items_after_statements)]
        const INIT_THREAD_PAGES: u64 = (sched::KERNEL_STACK_PAGES + 2) as u64;
        let (init_thread_obj_nn, init_kstack_top, init_tcb) = {
            use cap::object::{KernelObjectHeader, ObjectType, ThreadObject};

            let bytes = INIT_THREAD_PAGES * mm::PAGE_SIZE as u64;
            let seed = cap::seed_memory_ref();
            let offset = cap::retype::retype_allocate(seed, bytes)
                .unwrap_or_else(|_| fatal("Phase 9: SEED too small for init Thread slab"));
            let block_phys = seed.base + offset;
            let block_virt = mm::paging::phys_to_virt(block_phys);
            let kstack_top = block_virt + (sched::KERNEL_STACK_PAGES * mm::PAGE_SIZE) as u64;
            let thread_obj_ptr = kstack_top as *mut ThreadObject;
            let tcb_offset = core::mem::size_of::<ThreadObject>() as u64;
            let tcb_ptr = (kstack_top + tcb_offset) as *mut sched::thread::ThreadControlBlock;
            // Per-thread FPU/SIMD/V save area: one page directly after the
            // wrapper page in the retyped slab.
            let init_extended_area = (kstack_top + mm::PAGE_SIZE as u64) as *mut u8;
            // SAFETY: init_extended_area lies on page 5 of the freshly-retyped
            // slab, exclusively owned by this init bootstrap.
            unsafe {
                core::ptr::write_bytes(init_extended_area, 0u8, mm::PAGE_SIZE);
            }

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
                        queued_on: core::sync::atomic::AtomicI16::new(-1),
                        #[cfg(debug_assertions)]
                        last_enqueue: None,
                        sched_lock: crate::sync::Spinlock::new(),
                        wake_pending: false,
                        park_started_tick: 0,
                        ipc_state: sched::thread::IpcThreadState::None,
                        ipc_msg: ipc::message::Message::default(),
                        reply_tcb: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
                        park_disposition: core::sync::atomic::AtomicU8::new(
                            sched::thread::PARK_DISPOSITION_NONE,
                        ),
                        #[cfg(debug_assertions)]
                        park_episode: core::sync::atomic::AtomicU32::new(0),
                        #[cfg(debug_assertions)]
                        deposit_episode: core::sync::atomic::AtomicU32::new(0),
                        ipc_wait_next: None,
                        fault_handler: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
                        fault_badge: core::sync::atomic::AtomicU64::new(0),
                        fault_outcome: core::sync::atomic::AtomicU8::new(0),
                        in_fault_delivery: false,
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
                        wake_in_flight: core::sync::atomic::AtomicU32::new(0),
                        death_observers: [sched::thread::DeathObserver::empty();
                            sched::thread::MAX_DEATH_OBSERVERS],
                        death_observer_count: 0,
                        exit_reason: 0,
                        sleep_deadline: 0,
                        extended: sched::thread::ExtendedState::from_raw(init_extended_area),
                        registry_next: core::ptr::null_mut(),
                        registry_prev: core::ptr::null_mut(),
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
                        deferred_next: core::ptr::null_mut(),
                    },
                );
                // Diagnostic registry: thread the init TCB onto the live-thread
                // list so the softlockup watchdog can enumerate it as a Blocked
                // waiter (#351). Removed by `dealloc_object(Thread)` if init's
                // Thread cap is ever deleted/revoked.
                sched::thread_registry::register(tcb_ptr);
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
            // The root CSpace wrapper now has two logical holders: init's TCB
            // (`init_tcb.cspace`, set below) and the self-cap slot inserted
            // here. `insert_cap` does not bump the refcount of the inserted
            // object — it's the caller's responsibility — so we inc here.
            // `HDR_FLAG_IS_ROOT` (stamped in `boot_retype_cspace`) is the
            // belt-and-suspenders defense if this accounting ever drifts.
            // SAFETY: header at offset 0 of cs_kobj_ptr; single-threaded boot.
            unsafe { cs_nn.as_ref().inc_ref() };
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
            let linked = sched.enqueue(init_tcb, sched::INIT_PRIORITY);
            debug_assert!(linked, "boot: init enqueue skipped");
        }

        kprintln!(
            "init: TCB tid=1 priority={} stack={:#x}",
            sched::INIT_PRIORITY,
            init_kstack_top
        );

        // ── Boot-handover ledger ────────────────────────────────────────────
        // Sum MemoryObject.available_bytes across every Memory cap in init's
        // CSpace plus SEED's residual reserve. After 4b, SEED is the kernel's
        // ongoing body source for split-derived wrappers and per-thread IOPB
        // pages; printing both makes the invariant
        //
        //   total_RAM == kernel_static_image_size + Σ per-CPU kstack pages
        //                + SEED_available + Σ caps_available
        //                + bootloader-loaded modules
        //
        // observable byte-for-byte. The kernel heap is deleted; no `Box::new`
        // path remains in production.
        // SAFETY: init_cspace_ptr is the root CSpace, single-threaded boot.
        let cap_available_bytes = unsafe { cap::sum_memory_available_bytes(&*init_cspace_ptr) };
        let seed_available_bytes = cap::seed_memory_ref()
            .available_bytes
            .load(core::sync::atomic::Ordering::Acquire);
        let kstack_bytes =
            u64::from(boot_cpu_count) * (sched::KERNEL_STACK_PAGES as u64) * (mm::PAGE_SIZE as u64);
        kprintln!(
            "ledger: caps_available={} KiB, seed_available={} KiB, kstack_total={} KiB ({} CPUs × {} KiB)",
            cap_available_bytes / 1024,
            seed_available_bytes / 1024,
            kstack_bytes / 1024,
            boot_cpu_count,
            (sched::KERNEL_STACK_PAGES * mm::PAGE_SIZE / 1024) as u64,
        );

        // Hand off to the scheduler. Never returns. APs are already
        // idle (Phase 8 brought them online).
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
    // SAFETY: the PerCpuData slab was allocated in Phase 4 (sched::init_storage);
    // this AP's entry is not yet accessed by any other CPU; called once per AP
    // during startup.
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

    // Enable hardware address-space tags on this AP (x86-64 sets CR4.PCIDE;
    // RISC-V probes its ASID width). Must precede this AP's first tagged
    // activate in the scheduler. If this CPU provides fewer tags than the pool
    // the BSP configured, the tagged path could load a tag past this hart's
    // tag-field width (RISC-V: a too-narrow ASID), aliasing address spaces —
    // a fatal heterogeneity. (`< num_tags` also covers a CPU with no tags at
    // all; on x86 enable_tagged_tlb returns 4096 or 0, so only 0 trips it.)
    // SAFETY: ring 0 / S-mode; kernel root active; once per AP, before any
    // tagged activate.
    let ap_hw_tags = unsafe { arch::current::paging::enable_tagged_tlb() };
    if mm::tag_allocator::tagging_enabled() && ap_hw_tags < mm::tag_allocator::num_tags()
    {
        fatal("AP provides fewer hardware TLB tags than the BSP configured");
    }

    kprintln!("smp: AP {} online", cpu_id);

    // Capture this AP's entropy self-test sample. The AP's generator seeds
    // lazily from the pool (already seeded in Phase 5) on this first draw.
    entropy::init_ap();

    // 6. Notification BSP that this AP is ready.
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

// Kernel `.text` bounds (linker-provided) for the panic backtrace scan.
// SAFETY: provided by the linker script; only their addresses are taken.
#[cfg(not(test))]
unsafe extern "C" {
    static __text_start: u8;
    static __text_end: u8;
}

/// Set once the BSP per-CPU subsystem is initialized (after `percpu::init_bsp`),
/// gating [`panic_context_dump`]'s per-CPU reads. A panic before this point keeps
/// the banner-only behaviour and cannot fault inside the handler.
#[cfg(not(test))]
static PANIC_DUMP_READY: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Best-effort panic context: CPU, current thread, the in-flight syscall, and a
/// kernel-text stack scan. The in-flight syscall is the load-bearing line for
/// issue #316: a torn-context (#314) makes a syscall execute with garbage
/// register args, which reach a stdlib precondition (`slice::get_unchecked`) and
/// panic — this dump shows the syscall + args, pinning kernel-side corruption vs
/// a deterministic kernel bug. Serial-only / lock-bypassing, mirroring the panic
/// banner. Skips entirely until the per-CPU subsystem is initialized
/// (`PANIC_DUMP_READY`); after that every read is null-checked or stack-bounded,
/// so the dump cannot fault.
///
/// # Safety
/// Called only from the panic handler.
#[cfg(not(test))]
unsafe fn panic_context_dump()
{
    // Bail before per-CPU GS-base/tp and the scheduler slabs exist: a pre-init
    // panic would otherwise fault in `current_cpu()` / `current_tcb()` /
    // `scheduler_for()` (the last re-entering this handler → unbounded recursion).
    // The banner is already printed by the caller, so it is not lost.
    if !PANIC_DUMP_READY.load(core::sync::atomic::Ordering::Acquire)
    {
        return;
    }
    let cpu = arch::current::cpu::current_cpu();
    // SAFETY: current_tcb may be null very early in boot; checked before deref.
    let cur = unsafe { crate::syscall::current_tcb() };
    if cur.is_null()
    {
        // SAFETY: panic path; lock-bypassing serial write.
        unsafe {
            console::panic_write_fmt(format_args!(
                "  context: cpu={cpu} (no current thread; backtrace skipped)\n"
            ));
        }
        return;
    }
    // SAFETY: cur non-null; thread_id / trap_frame / kernel_stack_top are
    // always valid to read on a live TCB.
    let (tid, tf, stack_top) =
        unsafe { ((*cur).thread_id, (*cur).trap_frame, (*cur).kernel_stack_top) };
    // SAFETY: panic path; lock-bypassing serial write.
    unsafe {
        console::panic_write_fmt(format_args!("  context: cpu={cpu} tid={tid}\n"));
    }
    if !tf.is_null()
    {
        // SAFETY: a non-null trap_frame is the in-flight userspace register
        // snapshot; syscall_nr/arg are plain field reads.
        let (nr, a0, a1, a2) =
            unsafe { ((*tf).syscall_nr(), (*tf).arg(0), (*tf).arg(1), (*tf).arg(2)) };
        // SAFETY: panic path; lock-bypassing serial write.
        unsafe {
            console::panic_write_fmt(format_args!(
                "  in-flight syscall: nr={nr} args=[{a0:#x}, {a1:#x}, {a2:#x}]\n"
            ));
        }
    }
    // SAFETY: cur non-null; kernel_stack_top bounds the scan to mapped stack.
    unsafe { backtrace_scan(stack_top) };
}

/// Scan the current kernel stack for words in the kernel `.text` range and print
/// them as probable return addresses (resolve offline with addr2line against the
/// kernel ELF). Frame pointers are not forced (dev `opt-level=1` / release
/// `opt-level="s"`), so this is a heuristic scan, not an exact unwind. Bounded by
/// `stack_top` (the thread's kernel-stack base) and a hard cap, and read-only, so
/// it cannot fault during the panic.
///
/// # Safety
/// `stack_top` must be the current thread's `kernel_stack_top`.
#[cfg(not(test))]
unsafe fn backtrace_scan(stack_top: u64)
{
    const MAX_BYTES: usize = 8 * 1024;
    const MAX_HITS: usize = 24;

    // cast_possible_truncation: usize is 64-bit on every Seraph target, so the
    // stack-pointer value always fits.
    #[allow(clippy::cast_possible_truncation)]
    let sp = crate::arch::current::cpu::current_stack_pointer() as usize;

    let text_start = core::ptr::addr_of!(__text_start) as usize;
    let text_end = core::ptr::addr_of!(__text_end) as usize;
    let top = usize::try_from(stack_top)
        .unwrap_or(usize::MAX)
        .min(sp.saturating_add(MAX_BYTES));
    // SAFETY: panic path; lock-bypassing serial write.
    unsafe {
        console::panic_write_fmt(format_args!(
            "  backtrace (kernel-text words on stack; addr2line offline):\n"
        ));
    }
    let mut addr = (sp + 7) & !7usize;
    let mut hits = 0usize;
    while addr < top && hits < MAX_HITS
    {
        // SAFETY: addr in [sp, stack_top) is mapped kernel stack; 8-byte aligned.
        let val = unsafe { *(addr as *const usize) };
        if val >= text_start && val < text_end
        {
            // SAFETY: panic path; lock-bypassing serial write.
            unsafe {
                console::panic_write_fmt(format_args!("    {val:#018x}\n"));
            }
            hits += 1;
        }
        addr += 8;
    }
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
    // Best-effort context: CPU, current thread, the in-flight syscall, and a
    // kernel-text stack scan. A torn-context (#314) makes a syscall execute with
    // garbage register args that reach a stdlib precondition (e.g.
    // slice::get_unchecked) — this dump pins the kernel call site #316 needs.
    // SAFETY: panic path; every read inside is bounded / null-checked.
    unsafe {
        panic_context_dump();
    }
    arch::current::cpu::halt_loop();
}
