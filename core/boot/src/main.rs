// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/main.rs

//! Seraph UEFI bootloader — ten-step boot sequence orchestrator.
//!
//! Loads the kernel ELF and init module from the ESP, establishes initial
//! page tables with W^X enforcement, discovers firmware table addresses,
//! exits UEFI boot services, populates `BootInfo`, and jumps to the kernel
//! entry point. See `boot/docs/boot-flow.md` for the step-by-step design.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![feature(never_type)]

mod acpi;
mod arch;
mod config;
mod console;
mod dtb;
mod elf;
mod error;
mod firmware;
mod framebuffer;
mod memory_map;
mod paging;
mod uefi;

use crate::config::{BootConfig, MAX_MODULES, load_boot_config};
use crate::elf::{KernelInfo, load_init, load_kernel, load_module};
use crate::error::BootError;
use crate::firmware::{FirmwareInfo, discover_firmware};
use crate::paging::{PageTableBuilder, build_initial_tables};
use crate::uefi::{
    EfiBootServices, EfiFileProtocol, EfiHandle, EfiSystemTable, allocate_pages,
    connect_all_controllers, exit_boot_services, file_read, file_size, get_loaded_image,
    get_memory_map, open_esp_volume, open_file, query_gop,
};
use boot_protocol::{
    BOOT_PROTOCOL_VERSION, BootInfo, BootModule, FramebufferInfo, InitImage, KernelMmio,
    MAX_APERTURES, MAX_CPUS, MemoryMapEntry, MemoryMapSlice, MmioAperture, MmioApertureSlice,
    ModuleSlice,
};

// ── Size constants ────────────────────────────────────────────────────────────

/// Number of 4 KiB pages allocated for the kernel stack (64 KiB).
const KERNEL_STACK_PAGES: usize = 16;

/// Number of 4 KiB pages allocated for the translated `MemoryMapEntry` output
/// array. At 24 bytes per entry this accommodates roughly 680 entries, which
/// comfortably exceeds any real UEFI memory map.
const MEM_MAP_ENTRY_PAGES: usize = 4;

/// Maximum number of physical regions tracked for identity mapping.
/// Covers kernel segments, all fixed allocations, and the framebuffer.
const MAX_IDENTITY_REGIONS: usize = 64;

/// Size of the aperture-seed scratch buffer (firmware-advertised MMIO extents
/// before merging with the UEFI memory map).
const MAX_APERTURE_SEEDS: usize = 64;

// ── Forward-state groupings ───────────────────────────────────────────────────

/// UEFI handles and early-discovery results held across the boot sequence.
///
/// Populated by [`step1_locate_uefi_protocols`]. All pointers remain valid
/// until [`step8_exit_boot_services`] completes; after that only `image` and
/// `st` remain addressable, and neither is used post-exit.
struct UefiContext
{
    image: EfiHandle,
    st: *mut EfiSystemTable,
    bs: *mut EfiBootServices,
    esp_root: *mut EfiFileProtocol,
    framebuffer: FramebufferInfo,
}

/// Kernel ELF load result: the parsed info and the read-buffer allocation.
///
/// The read buffer is kept identity-mapped until `ExitBootServices` because
/// UEFI retains the allocation; the kernel itself does not need it after that
/// (segments are already copied).
struct KernelLoad
{
    info: KernelInfo,
    buf_phys: u64,
    buf_pages: usize,
}

/// Init ELF load result with its read-buffer allocation, same shape as
/// [`KernelLoad`].
struct InitLoad
{
    image: InitImage,
    buf_phys: u64,
    buf_pages: usize,
}

/// Boot-module load results: a fixed-capacity array of [`BootModule`]
/// descriptors plus the per-module read-buffer allocations.
struct ModulesLoad
{
    modules: [BootModule; MAX_MODULES],
    count: usize,
    buf_phys: [u64; MAX_MODULES],
    buf_pages: [usize; MAX_MODULES],
}

/// CPU topology derived from firmware tables (MADT / DTB /cpus).
struct CpuTopology
{
    /// RISC-V boot hart ID (from `EFI_RISCV_BOOT_PROTOCOL`); 0 on x86-64.
    boot_hart_id: u64,
    /// Hardware identifier of the bootstrap processor.
    bsp_id: u32,
    /// Number of enabled CPUs (always ≥ 1).
    count: u32,
    /// Per-CPU hardware identifiers; `[0] == bsp_id`.
    cpu_ids: [u32; MAX_CPUS],
}

/// All pre-`ExitBootServices` physical allocations the boot sequence
/// produces, gathered by [`step6_allocate_boot_structures`].
struct BootAllocations
{
    boot_info_phys: u64,
    modules_phys: u64,
    mem_entries_phys: u64,
    apertures_phys: u64,
    stack_phys: u64,
    stack_top: u64,
    cmdline_phys: u64,
    ap_trampoline_phys: u64,
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// UEFI application entry point.
///
/// UEFI firmware calls this function after loading and relocating the
/// bootloader image. Delegates immediately to [`boot_sequence`] and prints
/// a fatal error message before halting if the sequence fails.
///
/// Returns a `usize` (UEFI `EFI_STATUS`) to satisfy the UEFI ABI, but in
/// practice never returns — the boot sequence either jumps to the kernel or
/// halts on error.
// UEFI entry point — must be a public non-unsafe `extern "efiapi"` function per the UEFI spec;
// the raw-pointer parameters are validated before first deref inside the unsafe blocks below.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: EfiHandle, st: *mut EfiSystemTable) -> usize
{
    // Discover the UART MMIO base from ACPI SPCR or DTB before initializing
    // the serial console. Falls back to the arch default if neither is present.
    // SAFETY: st is valid; called exactly once before init_serial.
    unsafe { arch::current::pre_serial_init(st) };

    // SAFETY: serial_init called exactly once, before boot_sequence.
    unsafe {
        crate::console::init_serial();
    }

    // SAFETY: image and st are valid UEFI handles passed from firmware; boot_sequence called once.
    match unsafe { boot_sequence(image, st) }
    {
        Ok(never) => match never {},
        Err(err) => error::fatal_error(&err),
    }
}

// ── Boot sequence orchestrator ───────────────────────────────────────────────

/// Execute the ten-step boot sequence and transfer control to the kernel.
///
/// Returns `Result<!, BootError>`: the `Ok` variant is uninhabited (`!`) because
/// a successful sequence ends with a non-returning kernel jump. Any `Err` is
/// propagated to `efi_main` for error reporting.
///
/// # Safety
/// `image` must be the UEFI image handle passed to `efi_main`. `st` must be
/// a valid pointer to the UEFI system table.
unsafe fn boot_sequence(image: EfiHandle, st: *mut EfiSystemTable) -> Result<!, BootError>
{
    // SAFETY: caller guarantees image and st are the UEFI-provided handles.
    let ctx = unsafe { step1_locate_uefi_protocols(image, st)? };
    // SAFETY: ctx.esp_root is a valid FAT directory handle.
    let cfg = unsafe { step2_load_boot_config(&ctx)? };
    // SAFETY: ctx.bs / esp_root are valid until ExitBootServices.
    let kernel = unsafe { step3_load_kernel(&ctx, &cfg)? };
    // SAFETY: same validity window as step 3.
    let init = unsafe { step4a_load_init(&ctx, &cfg)? };
    // SAFETY: same validity window.
    let mods = unsafe { step4b_load_modules(&ctx, &cfg)? };
    // SAFETY: ctx.st is a valid UEFI system table.
    let firm = unsafe { step5_discover_firmware(&ctx) };
    // SAFETY: ctx.st is valid; firmware addresses are identity-mapped by UEFI.
    let cpus = unsafe { step5_discover_cpu_topology(&ctx, &firm) };
    // SAFETY: ctx.bs valid pre-exit.
    let ap_trampoline_phys = unsafe { step5b_alloc_ap_trampoline(&ctx) };
    // SAFETY: all prior unsafe outputs remain valid; step 6 allocates via bs.
    let (allocs, mut page_table) = unsafe {
        step6_allocate_and_build_page_tables(&ctx, &cfg, &kernel, &init, &mods, ap_trampoline_phys)?
    };
    // SAFETY: ctx.bs valid; step 7 is the last pre-exit allocation.
    let mut uefi_map = unsafe { step7_query_memory_map(&ctx)? };
    // SAFETY: uefi_map produced by the immediately preceding get_memory_map;
    // no intervening allocations.
    unsafe { step8_exit_boot_services(&ctx, &mut uefi_map)? };
    // After this point: no UEFI calls. All subsequent work uses pre-allocated
    // physical memory already identity-mapped in page_table.
    // SAFETY: all referenced allocations are pre-ExitBS, identity-mapped,
    // and retained in `Loaded`-classified regions per step 7.
    unsafe {
        step9_populate_boot_info(
            &cfg,
            &kernel,
            &init,
            &mods,
            &firm,
            &cpus,
            &ctx.framebuffer,
            &allocs,
            &uefi_map,
        );
    }
    // SAFETY: page_table root frames are valid; kernel_info.entry_virtual is
    // within the loaded kernel image; BootInfo at allocs.boot_info_phys is
    // populated; allocs.stack_top is the top of a 64 KiB identity-mapped stack.
    unsafe {
        step10_handoff(
            &mut page_table,
            kernel.info.entry_virtual,
            allocs.boot_info_phys,
            allocs.stack_top,
            cpus.boot_hart_id,
        )
    }
}

// ── Step 1: UEFI protocol discovery ──────────────────────────────────────────

/// Resolve the UEFI protocols and handles the subsequent steps need: the
/// `EFI_LOADED_IMAGE_PROTOCOL`, the ESP root directory, and the (optional)
/// GOP framebuffer. Initializes the framebuffer backend of the early console.
///
/// # Safety
/// `image` and `st` must be the UEFI firmware-supplied handle and system
/// table pointer.
unsafe fn step1_locate_uefi_protocols(
    image: EfiHandle,
    st: *mut EfiSystemTable,
) -> Result<UefiContext, BootError>
{
    bprintln!("[--------] boot: step 1/10: UEFI protocol discovery");

    // SAFETY: st is validated by the caller.
    let bs = unsafe { (*st).boot_services };
    // SAFETY: bs is valid boot services; image is the EFI application handle.
    let loaded_image = unsafe { get_loaded_image(bs, image)? };
    // SAFETY: loaded_image is a valid EFI_LOADED_IMAGE_PROTOCOL pointer.
    let device_handle = unsafe { (*loaded_image).device_handle };
    // SAFETY: bs is valid; device_handle is the boot volume device handle.
    let esp_root = unsafe { open_esp_volume(bs, device_handle)? };
    // Force EDK2 to bind device drivers (e.g. virtio-gpu → GOP) on platforms
    // that don't auto-connect during BDS (notably RISC-V).
    // SAFETY: bs is valid boot services.
    unsafe {
        connect_all_controllers(bs);
    }

    // GOP is optional; absence is handled gracefully with a zeroed FramebufferInfo.
    // SAFETY: bs is valid.
    let framebuffer = unsafe { query_gop(bs) }.unwrap_or_else(FramebufferInfo::empty);
    // SAFETY: framebuffer describes a valid GOP framebuffer (or is zeroed if absent).
    unsafe {
        crate::console::init_framebuffer(&framebuffer);
    }
    if framebuffer.physical_base != 0
    {
        bprintln!("[--------] boot: GOP: present");
    }
    else
    {
        bprintln!("[--------] boot: GOP: absent (headless)");
    }

    Ok(UefiContext {
        image,
        st,
        bs,
        esp_root,
        framebuffer,
    })
}

// ── Step 2: Load boot configuration ──────────────────────────────────────────

/// Read and parse `\EFI\seraph\boot.conf` from the ESP.
///
/// # Safety
/// `ctx.esp_root` must be a valid open `EFI_FILE_PROTOCOL` directory handle.
unsafe fn step2_load_boot_config(ctx: &UefiContext) -> Result<BootConfig, BootError>
{
    bprintln!("[--------] boot: step 2/10: load boot configuration");
    // SAFETY: esp_root is a valid EFI_FILE_PROTOCOL directory handle.
    unsafe { load_boot_config(ctx.esp_root) }
}

// ── Step 3: Load kernel ELF ──────────────────────────────────────────────────

/// Load and parse the kernel ELF into UEFI-allocated physical memory.
///
/// # Safety
/// `ctx.bs` and `ctx.esp_root` must be valid UEFI services and directory
/// handle respectively. `cfg.kernel_path` must be a null-terminated UTF-16
/// file name.
unsafe fn step3_load_kernel(ctx: &UefiContext, cfg: &BootConfig) -> Result<KernelLoad, BootError>
{
    bprintln!("[--------] boot: step 3/10: load kernel ELF");
    // SAFETY: esp_root is a valid directory handle; path is null-terminated UTF-16.
    let kernel_file =
        unsafe { open_file(ctx.esp_root, cfg.kernel_path.as_ptr(), "kernel (boot.conf)")? };
    // SAFETY: kernel_file is a valid open file handle.
    // File size is a u64 from UEFI; usize is 64-bit on all supported targets so cast is exact.
    #[allow(clippy::cast_possible_truncation)]
    let kernel_file_sz = unsafe { file_size(kernel_file)? } as usize;
    let buf_pages = kernel_file_sz.div_ceil(4096);
    // SAFETY: bs is valid.
    let buf_phys = unsafe { allocate_pages(ctx.bs, buf_pages)? };
    // SAFETY: buf_phys is a freshly allocated region of buf_pages*4096 bytes,
    // identity-mapped by UEFI. Slicing to kernel_file_sz is within the allocation.
    let kernel_buf =
        unsafe { core::slice::from_raw_parts_mut(buf_phys as *mut u8, kernel_file_sz) };
    // SAFETY: kernel_file is open and at position 0; kernel_buf is the correct size.
    unsafe { file_read(kernel_file, kernel_buf)? };
    // SAFETY: bs is valid; kernel_buf is the complete ELF file.
    let info = unsafe { load_kernel(ctx.bs, kernel_buf, arch::current::EXPECTED_ELF_MACHINE)? };

    // Direct-write helpers avoid format-arg vtable dispatch — on RISC-V the
    // PE .reloc section is currently empty, so the firmware does not patch
    // vtable entries when relocating the image and core::fmt's fat-pointer
    // write_str faults.
    bprint!("[--------] boot: kernel entry=");
    // SAFETY: console initialized.
    unsafe {
        crate::console::console_write_hex64(info.entry_virtual);
    }
    bprint!("  size=");
    // SAFETY: console initialized.
    unsafe {
        crate::console::console_write_hex64(info.size);
    }
    bprintln!(" bytes");

    Ok(KernelLoad {
        info,
        buf_phys,
        buf_pages,
    })
}

// ── Step 4a: Load and pre-parse init ELF ─────────────────────────────────────

/// Load init's ELF image, parse its segments, and produce an `InitImage`.
///
/// # Safety
/// Same validity requirements as [`step3_load_kernel`].
unsafe fn step4a_load_init(ctx: &UefiContext, cfg: &BootConfig) -> Result<InitLoad, BootError>
{
    bprintln!("[--------] boot: step 4/10: load init ELF and boot modules");
    // SAFETY: esp_root is a valid directory handle; path is null-terminated UTF-16.
    let init_file = unsafe { open_file(ctx.esp_root, cfg.init_path.as_ptr(), "init (boot.conf)")? };
    // SAFETY: init_file is a valid open file handle.
    #[allow(clippy::cast_possible_truncation)]
    let init_file_sz = unsafe { file_size(init_file)? } as usize;
    let buf_pages = init_file_sz.div_ceil(4096);
    // SAFETY: bs is valid.
    let buf_phys = unsafe { allocate_pages(ctx.bs, buf_pages)? };
    // SAFETY: buf_phys is a freshly allocated region; slice is within the allocation.
    let init_buf = unsafe { core::slice::from_raw_parts_mut(buf_phys as *mut u8, init_file_sz) };
    // SAFETY: init_file is open at position 0; init_buf is the correct size.
    unsafe { file_read(init_file, init_buf)? };
    // load_init allocates at any available physical address (not p_paddr) because
    // init is a userspace ELF whose p_paddr values conflict with UEFI low-memory
    // use. The kernel receives phys_addr+virt_addr pairs to map init without an
    // ELF parser.
    // SAFETY: bs is valid; init_buf contains the complete ELF file.
    let image = unsafe { load_init(ctx.bs, init_buf, arch::current::EXPECTED_ELF_MACHINE)? };

    bprint!("[--------] boot: init entry=");
    // SAFETY: console initialized.
    unsafe {
        crate::console::console_write_hex64(image.entry_point);
    }
    bprint!("  size=");
    // SAFETY: console initialized.
    unsafe {
        crate::console::console_write_hex64(init_file_sz as u64);
    }
    bprintln!(" bytes");

    Ok(InitLoad {
        image,
        buf_phys,
        buf_pages,
    })
}

// ── Step 4b: Load additional boot modules ────────────────────────────────────

/// Load each boot module listed in `cfg.modules` as a flat binary image.
///
/// # Safety
/// Same validity requirements as [`step3_load_kernel`].
unsafe fn step4b_load_modules(ctx: &UefiContext, cfg: &BootConfig)
-> Result<ModulesLoad, BootError>
{
    let mut modules = [BootModule {
        physical_base: 0,
        size: 0,
    }; MAX_MODULES];
    let mut buf_phys = [0u64; MAX_MODULES];
    let mut buf_pages = [0usize; MAX_MODULES];
    let mut count: usize = 0;

    for i in 0..cfg.module_count
    {
        // SAFETY: esp_root is valid; module_paths[i] is a null-terminated UTF-16 path.
        let mod_file = unsafe {
            open_file(
                ctx.esp_root,
                cfg.module_paths[i].as_ptr(),
                "module (boot.conf)",
            )?
        };
        // SAFETY: mod_file is a valid open file handle.
        #[allow(clippy::cast_possible_truncation)]
        let file_sz = unsafe { file_size(mod_file)? } as usize;
        let pages = file_sz.div_ceil(4096);
        // SAFETY: bs is valid.
        let phys = unsafe { allocate_pages(ctx.bs, pages)? };
        // SAFETY: phys is a freshly allocated region of pages*4096 bytes.
        let mod_buf = unsafe { core::slice::from_raw_parts_mut(phys as *mut u8, file_sz) };
        // SAFETY: mod_file is open at position 0; mod_buf is the correct size.
        unsafe { file_read(mod_file, mod_buf)? };
        // SAFETY: bs is valid; mod_buf contains the complete module file.
        let module = unsafe { load_module(ctx.bs, mod_buf)? };

        buf_phys[i] = phys;
        buf_pages[i] = pages;
        modules[count] = module;
        count += 1;
    }

    Ok(ModulesLoad {
        modules,
        count,
        buf_phys,
        buf_pages,
    })
}

// ── Step 5: Firmware discovery ───────────────────────────────────────────────

/// Scan the UEFI configuration table for the ACPI RSDP and Device Tree GUIDs.
///
/// # Safety
/// `ctx.st` must be a valid UEFI system table pointer.
unsafe fn step5_discover_firmware(ctx: &UefiContext) -> FirmwareInfo
{
    bprintln!("[--------] boot: step 5/10: firmware discovery and platform resources");
    // SAFETY: st is a valid UEFI system table pointer.
    let firm = unsafe { discover_firmware(ctx.st) };
    if firm.acpi_rsdp != 0
    {
        bprintln!("[--------] boot: ACPI RSDP: found");
    }
    else
    {
        bprintln!("[--------] boot: ACPI RSDP: not found");
    }
    if firm.device_tree != 0
    {
        bprintln!("[--------] boot: DTB: found");
    }
    else
    {
        bprintln!("[--------] boot: DTB: not found");
    }
    firm
}

/// Derive the CPU topology from ACPI MADT (primary on both arches) or DTB
/// `/cpus` (fallback on RISC-V when ACPI is absent).
///
/// # Safety
/// `ctx.st` must be valid. `firm.acpi_rsdp` / `firm.device_tree` must be
/// zero or the physical address of an identity-mapped table.
unsafe fn step5_discover_cpu_topology(ctx: &UefiContext, firm: &FirmwareInfo) -> CpuTopology
{
    // SAFETY: ctx.st is valid.
    let boot_hart_id = unsafe { arch::current::discover_boot_hart_id(ctx.st) };
    // BSP hardware ID: APIC ID on x86-64 (CPUID), boot hart ID on RISC-V.
    let bsp_id: u32 = arch::current::bsp_hardware_id(boot_hart_id);

    // Primary: ACPI MADT (works on both x86-64 and RISC-V UEFI).
    // Fallback on RISC-V: DTB /cpus if ACPI is absent.
    if firm.acpi_rsdp != 0
    {
        // SAFETY: acpi_rsdp is identity-mapped; parse_cpu_topology validates the table.
        let (count, _, cpu_ids) = unsafe { acpi::parse_cpu_topology(firm.acpi_rsdp, bsp_id) };
        bprint!("[--------] boot: ACPI: ");
        // SAFETY: console initialized.
        unsafe { crate::console::console_write_dec32(count) };
        bprintln!(" CPU(s) found via MADT");
        CpuTopology {
            boot_hart_id,
            bsp_id,
            count,
            cpu_ids,
        }
    }
    else if firm.device_tree != 0
    {
        // SAFETY: device_tree is identity-mapped; parse_cpu_count validates the FDT.
        let (count, hart_ids) = unsafe { dtb::parse_cpu_count(firm.device_tree) };
        if count > 0
        {
            bprint!("[--------] boot: DTB: ");
            // SAFETY: console initialized.
            unsafe { crate::console::console_write_dec32(count) };
            bprintln!(" hart(s) found");
            let mut cpu_ids = [0u32; MAX_CPUS];
            cpu_ids[0] = bsp_id;
            let mut ap_idx = 1usize;
            for &hart_id in hart_ids.iter().take(count as usize)
            {
                if hart_id != bsp_id && ap_idx < MAX_CPUS
                {
                    cpu_ids[ap_idx] = hart_id;
                    ap_idx += 1;
                }
            }
            CpuTopology {
                boot_hart_id,
                bsp_id,
                count,
                cpu_ids,
            }
        }
        else
        {
            bprintln!("[--------] boot: DTB: no CPU nodes found, defaulting to 1");
            single_cpu_topology(boot_hart_id, bsp_id)
        }
    }
    else
    {
        bprintln!("[--------] boot: CPU topology: no firmware tables, defaulting to 1");
        single_cpu_topology(boot_hart_id, bsp_id)
    }
}

fn single_cpu_topology(boot_hart_id: u64, bsp_id: u32) -> CpuTopology
{
    let mut cpu_ids = [0u32; MAX_CPUS];
    cpu_ids[0] = bsp_id;
    CpuTopology {
        boot_hart_id,
        bsp_id,
        count: 1,
        cpu_ids,
    }
}

// ── Step 5b: AP trampoline allocation ────────────────────────────────────────

/// Reserve a 4 KiB page for the AP startup trampoline. Returns 0 if the
/// allocation fails (SMP is then disabled); arch-specific placement
/// constraints are enforced inside `arch::current::allocate_ap_trampoline`.
///
/// # Safety
/// `ctx.bs` must be valid UEFI boot services.
unsafe fn step5b_alloc_ap_trampoline(ctx: &UefiContext) -> u64
{
    // SAFETY: ctx.bs is valid.
    if let Some(phys) = unsafe { arch::current::allocate_ap_trampoline(ctx.bs) }
    {
        bprint!("[--------] boot: AP trampoline page: ");
        // SAFETY: console initialized.
        unsafe { crate::console::console_write_hex64(phys) };
        bprintln!("");
        phys
    }
    else
    {
        bprintln!("[--------] boot: WARNING: cannot allocate AP trampoline page — SMP disabled");
        0
    }
}

// ── Step 6: Allocate boot structures and build page tables ──────────────────

/// Allocate the fixed pre-exit scratch pages (`BootInfo` page, modules
/// descriptor page, memory-map page, aperture page, stack, command-line page),
/// accumulate the identity-map region list, build initial page tables, and
/// install the x86-64 handoff-trampoline mapping.
///
/// # Safety
/// `ctx.bs` must be valid pre-exit; all addresses in `kernel`, `init`, and
/// `mods` must come from their respective `step3`/`step4*` outputs.
unsafe fn step6_allocate_and_build_page_tables(
    ctx: &UefiContext,
    cfg: &BootConfig,
    kernel: &KernelLoad,
    init: &InitLoad,
    mods: &ModulesLoad,
    ap_trampoline_phys: u64,
) -> Result<(BootAllocations, arch::current::BootPageTable), BootError>
{
    // BootInfo: one page — holds the BootInfo struct populated in step 9.
    // SAFETY: bs is valid.
    let boot_info_phys = unsafe { allocate_pages(ctx.bs, 1)? };
    // Module array: one page — BootInfo.modules descriptor array.
    // SAFETY: bs is valid.
    let modules_phys = unsafe { allocate_pages(ctx.bs, 1)? };
    // MemoryMapEntry output array.
    // SAFETY: bs is valid.
    let mem_entries_phys = unsafe { allocate_pages(ctx.bs, MEM_MAP_ENTRY_PAGES)? };
    // MMIO aperture array: one page easily covers MAX_APERTURES × 16 bytes.
    // SAFETY: bs is valid.
    let apertures_phys = unsafe { allocate_pages(ctx.bs, 1)? };
    // Kernel stack.
    // SAFETY: bs is valid.
    let stack_phys = unsafe { allocate_pages(ctx.bs, KERNEL_STACK_PAGES)? };
    let stack_top = stack_phys + (KERNEL_STACK_PAGES as u64) * 4096;
    // Command line.
    // SAFETY: bs is valid.
    let cmdline_phys = unsafe { allocate_pages(ctx.bs, 1)? };
    if cfg.cmdline_len > 0
    {
        // SAFETY: cmdline_phys is a valid allocation; config.cmdline[..cmdline_len]
        // is valid ASCII. Regions are disjoint (config is stack data).
        unsafe {
            core::ptr::copy_nonoverlapping(
                cfg.cmdline.as_ptr(),
                cmdline_phys as *mut u8,
                cfg.cmdline_len,
            );
        }
    }
    // SAFETY: cmdline_phys + cmdline_len is within the 4096-byte allocation
    // because MAX_CMDLINE_LEN (512) < 4096.
    unsafe { core::ptr::write((cmdline_phys + cfg.cmdline_len as u64) as *mut u8, 0u8) };

    let allocs = BootAllocations {
        boot_info_phys,
        modules_phys,
        mem_entries_phys,
        apertures_phys,
        stack_phys,
        stack_top,
        cmdline_phys,
        ap_trampoline_phys,
    };

    let mut identity_regions: [(u64, u64); MAX_IDENTITY_REGIONS] =
        [(0u64, 0u64); MAX_IDENTITY_REGIONS];
    let region_count = collect_identity_regions(
        &allocs,
        kernel,
        init,
        mods,
        cfg,
        &ctx.framebuffer,
        arch::current::uart_mmio_region(),
        &mut identity_regions,
    );

    bprintln!("[--------] boot: step 6/10: allocate and build page tables");
    let mut page_table =
        build_initial_tables(ctx.bs, &kernel.info, &identity_regions[0..region_count])?;
    install_handoff_trampoline_mapping(&mut page_table)?;

    Ok((allocs, page_table))
}

/// Fill `out` with all physical regions that must be identity-mapped so the
/// kernel can access them before establishing its own page tables. Returns
/// the number of filled entries; silently caps at [`MAX_IDENTITY_REGIONS`].
// Each parameter names a distinct origin of an identity-mapped region
// (kernel, init, modules, config, framebuffer, UART, fixed allocations);
// bundling them further hides where a region came from.
#[allow(clippy::too_many_arguments)]
fn collect_identity_regions(
    allocs: &BootAllocations,
    kernel: &KernelLoad,
    init: &InitLoad,
    mods: &ModulesLoad,
    cfg: &BootConfig,
    framebuffer: &FramebufferInfo,
    uart_base: u64,
    out: &mut [(u64, u64); MAX_IDENTITY_REGIONS],
) -> usize
{
    let mut n: usize = 0;
    let mut push = |phys: u64, size: u64| {
        if n < MAX_IDENTITY_REGIONS
        {
            out[n] = (phys, size);
            n += 1;
        }
    };

    // Kernel ELF segments.
    for i in 0..kernel.info.segment_count
    {
        let seg = &kernel.info.segments[i];
        push(seg.phys_base, (seg.size + 4095) & !4095);
    }
    // Fixed boot allocations.
    push(allocs.boot_info_phys, 4096);
    push(allocs.modules_phys, 4096);
    push(allocs.mem_entries_phys, (MEM_MAP_ENTRY_PAGES as u64) * 4096);
    push(allocs.stack_phys, (KERNEL_STACK_PAGES as u64) * 4096);
    push(allocs.cmdline_phys, 4096);
    // Init segments.
    for i in 0..(init.image.segment_count as usize)
    {
        let seg = &init.image.segments[i];
        push(seg.phys_addr, (seg.size + 4095) & !4095);
    }
    // File read buffers (UEFI retains these allocations until ExitBootServices).
    push(init.buf_phys, (init.buf_pages as u64) * 4096);
    push(kernel.buf_phys, (kernel.buf_pages as u64) * 4096);
    // Boot modules: both the read buffer (UEFI-retained) and the loaded region.
    for i in 0..cfg.module_count
    {
        push(mods.buf_phys[i], (mods.buf_pages[i] as u64) * 4096);
        push(
            mods.modules[i].physical_base,
            (mods.modules[i].size + 4095) & !4095,
        );
    }
    // Framebuffer (if present).
    if framebuffer.physical_base != 0
    {
        let fb_size = u64::from(framebuffer.stride) * u64::from(framebuffer.height);
        push(framebuffer.physical_base, (fb_size + 4095) & !4095);
    }
    // RISC-V MMIO UART (no-op on x86-64 where uart_base == 0).
    if uart_base != 0
    {
        push(uart_base, 4096);
    }
    // MMIO aperture array page.
    push(allocs.apertures_phys, 4096);
    n
}

/// Identity-map the handoff trampoline page(s) as RX in the new tables.
///
/// On x86-64, after `mov cr3` the CPU fetches the next instruction at the same
/// virtual address; under UEFI x86-64 VA == PA, so the symbol address doubles
/// as the physical address. On RISC-V the stub returns (0, 0) and this is a
/// no-op.
fn install_handoff_trampoline_mapping(
    page_table: &mut arch::current::BootPageTable,
) -> Result<(), BootError>
{
    let (tramp_first, tramp_last) = arch::current::trampoline_page_range();
    if tramp_first == 0
    {
        return Ok(());
    }
    let flags = || paging::PageFlags {
        writable: false,
        executable: true,
    };
    map_trampoline_page(page_table, tramp_first, flags())?;
    if tramp_last != tramp_first
    {
        map_trampoline_page(page_table, tramp_last, flags())?;
    }
    Ok(())
}

fn map_trampoline_page(
    page_table: &mut arch::current::BootPageTable,
    phys: u64,
    flags: paging::PageFlags,
) -> Result<(), BootError>
{
    page_table.map(phys, phys, 4096, flags).map_err(|e| match e
    {
        paging::MapError::OutOfMemory => BootError::OutOfMemory,
        paging::MapError::WxViolation => BootError::WxViolation,
    })
}

// ── Step 7: Query final memory map ───────────────────────────────────────────

/// Query UEFI for the final memory map. Must be the last allocation-generating
/// call before `ExitBootServices`.
///
/// # Safety
/// `ctx.bs` must be valid; no allocations must occur between this call and
/// [`step8_exit_boot_services`].
unsafe fn step7_query_memory_map(ctx: &UefiContext) -> Result<uefi::MemoryMapResult, BootError>
{
    bprintln!("[--------] boot: step 7/10: query final memory map");
    // SAFETY: bs is valid.
    unsafe { get_memory_map(ctx.bs) }
}

// ── Step 8: ExitBootServices ─────────────────────────────────────────────────

/// Exit UEFI boot services. After this returns, no further UEFI calls may be
/// made.
///
/// # Safety
/// `uefi_map` must have been produced by the immediately preceding
/// `get_memory_map` with no intervening allocations.
unsafe fn step8_exit_boot_services(
    ctx: &UefiContext,
    uefi_map: &mut uefi::MemoryMapResult,
) -> Result<(), BootError>
{
    bprintln!("[--------] boot: step 8/10: ExitBootServices");
    // SAFETY: bs and image are valid; uefi_map is the freshest memory map.
    unsafe { exit_boot_services(ctx.bs, ctx.image, uefi_map) }
}

// ── Step 9: Populate BootInfo ────────────────────────────────────────────────

/// Write the final `BootInfo` into `allocs.boot_info_phys` together with the
/// auxiliary module descriptor array, translated memory map, and MMIO
/// aperture list.
///
/// # Safety
/// All physical allocations named in `allocs` must remain identity-mapped and
/// writable. `uefi_map` must be the exited-boot memory map from step 7.
// BootInfo population is the fan-in point for every earlier step: config,
// kernel, init, modules, firmware, cpu topology, framebuffer, boot
// allocations, and the memory map all contribute distinct fields. Bundling
// them would only rename the argument list into an ad-hoc struct.
#[allow(clippy::too_many_arguments)]
unsafe fn step9_populate_boot_info(
    cfg: &BootConfig,
    kernel: &KernelLoad,
    init: &InitLoad,
    mods: &ModulesLoad,
    firm: &FirmwareInfo,
    cpus: &CpuTopology,
    framebuffer: &FramebufferInfo,
    allocs: &BootAllocations,
    uefi_map: &uefi::MemoryMapResult,
)
{
    bprintln!("[--------] boot: step 9/10: populate BootInfo");

    // Module descriptor array.
    let modules_ptr = allocs.modules_phys as *mut BootModule;
    for (i, &module) in mods.modules.iter().enumerate().take(mods.count)
    {
        // SAFETY: modules_phys is a 4096-byte allocation; count ≤ MAX_MODULES (16)
        // so 16 × 16-byte BootModule entries fit.
        unsafe { core::ptr::write(modules_ptr.add(i), module) };
    }

    // Translate + sort the UEFI memory map.
    let entry_out = allocs.mem_entries_phys as *mut MemoryMapEntry;
    let max_entries = (MEM_MAP_ENTRY_PAGES * 4096) / core::mem::size_of::<MemoryMapEntry>();
    // SAFETY: entry_out is a valid allocated buffer of max_entries entries;
    // uefi_map is a valid map buffer populated by UEFI GetMemoryMap.
    let entry_count = unsafe { memory_map::translate_memory_map(uefi_map, entry_out, max_entries) };
    // SAFETY: elements [0..entry_count] were written by the call above.
    unsafe { memory_map::insertion_sort_memory_map(entry_out, entry_count) };

    // kernel_mmio: arch-dispatched extractor. Fields left zero cause the kernel
    // to fall back to its compiled-in constants.
    let mut kernel_mmio = KernelMmio::zero();
    // SAFETY: firmware addresses are identity-mapped; each arch validates.
    unsafe { arch::current::populate_kernel_mmio(firm, &mut kernel_mmio) };

    // mmio_apertures: merge firmware-table seeds with the raw UEFI MMIO
    // descriptors. Both ACPI and DTB parsers are tried on every architecture;
    // derive_mmio_apertures merges duplicates.
    let mut aperture_seed = [MmioAperture {
        phys_base: 0,
        size: 0,
    }; MAX_APERTURE_SEEDS];
    let mut seed_count: usize = 0;
    // SAFETY: acpi_rsdp is zero or identity-mapped; parse_aperture_seed validates.
    seed_count +=
        unsafe { acpi::parse_aperture_seed(firm.acpi_rsdp, &mut aperture_seed[seed_count..]) };
    // SAFETY: device_tree is zero or identity-mapped; parse_aperture_seed validates.
    seed_count +=
        unsafe { dtb::parse_aperture_seed(firm.device_tree, &mut aperture_seed[seed_count..]) };

    let apertures_out = allocs.apertures_phys as *mut MmioAperture;
    // SAFETY: apertures_phys is a valid 4 KiB allocation with room for
    // MAX_APERTURES × sizeof(MmioAperture) = 256 bytes.
    let apertures_buf: &mut [MmioAperture; MAX_APERTURES] =
        unsafe { &mut *(apertures_out.cast::<[MmioAperture; MAX_APERTURES]>()) };
    *apertures_buf = [MmioAperture {
        phys_base: 0,
        size: 0,
    }; MAX_APERTURES];
    // SAFETY: uefi_map.buffer_phys is the raw UEFI map from step 7, still mapped.
    let aperture_count = unsafe {
        memory_map::derive_mmio_apertures(uefi_map, &aperture_seed[..seed_count], apertures_buf)
    };
    bprint!("[--------] boot: MMIO apertures: ");
    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: console initialized.
    unsafe {
        crate::console::console_write_dec32(aperture_count as u32);
    }
    bprintln!(" derived");

    // Write the populated BootInfo.
    // SAFETY: boot_info_phys is a valid 4 KiB allocation; BootInfo fits in one page.
    unsafe {
        core::ptr::write(
            allocs.boot_info_phys as *mut BootInfo,
            BootInfo {
                version: BOOT_PROTOCOL_VERSION,
                memory_map: MemoryMapSlice {
                    entries: entry_out,
                    count: entry_count as u64,
                },
                kernel_physical_base: kernel.info.physical_base,
                kernel_virtual_base: kernel.info.virtual_base,
                kernel_size: kernel.info.size,
                init_image: init.image,
                modules: ModuleSlice {
                    entries: if mods.count > 0
                    {
                        allocs.modules_phys as *const BootModule
                    }
                    else
                    {
                        core::ptr::null()
                    },
                    count: mods.count as u64,
                },
                framebuffer: *framebuffer,
                acpi_rsdp: firm.acpi_rsdp,
                device_tree: firm.device_tree,
                kernel_mmio,
                mmio_apertures: MmioApertureSlice {
                    entries: if aperture_count > 0
                    {
                        allocs.apertures_phys as *const MmioAperture
                    }
                    else
                    {
                        core::ptr::null()
                    },
                    count: aperture_count as u64,
                },
                command_line: allocs.cmdline_phys as *const u8,
                command_line_len: cfg.cmdline_len as u64,
                cpu_count: cpus.count.max(1),
                bsp_id: cpus.bsp_id,
                cpu_ids: cpus.cpu_ids,
                ap_trampoline_page: allocs.ap_trampoline_phys,
            },
        );
    }
}

// ── Step 10: Kernel handoff ──────────────────────────────────────────────────

/// Transfer control to the kernel. Installs new page tables, sets the stack,
/// and jumps to the kernel entry point. Never returns.
///
/// # Safety
/// `page_table` must be fully populated; `entry_virtual` must be within the
/// loaded kernel image; `boot_info_phys` must point at a populated `BootInfo`;
/// `stack_top` must be the top of the pre-allocated kernel stack;
/// `ExitBootServices` must have completed.
unsafe fn step10_handoff(
    page_table: &mut arch::current::BootPageTable,
    entry_virtual: u64,
    boot_info_phys: u64,
    stack_top: u64,
    boot_hart_id: u64,
) -> Result<!, BootError>
{
    bprintln!("[--------] boot: step 10/10: kernel handoff");
    // SAFETY: contract enforced by caller.
    unsafe {
        arch::current::perform_handoff(
            page_table.root_physical(),
            entry_virtual,
            boot_info_phys,
            stack_top,
            boot_hart_id,
        )
    }
}
