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

// Include the hand-crafted PE/COFF header for RISC-V UEFI builds. LLVM has no
// PE/COFF backend for RISC-V, so we prepend this header and convert with
// llvm-objcopy. See boot/src/arch/riscv64/header.S and
// boot/linker/riscv64-uefi.ld.
#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(include_str!("arch/riscv64/header.S"));

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
mod platform;
mod uefi;

use crate::config::load_boot_config;
use crate::elf::{load_init, load_kernel, load_module};
use crate::error::BootError;
use crate::firmware::discover_firmware;
use crate::paging::{PageTableBuilder, build_initial_tables};
#[cfg(target_arch = "x86_64")]
use crate::uefi::allocate_pages_max_addr;
use crate::uefi::{
    EfiHandle, EfiSystemTable, allocate_pages, connect_all_controllers, exit_boot_services,
    file_read, file_size, get_loaded_image, get_memory_map, open_esp_volume, open_file, query_gop,
};
use boot_protocol::{
    BOOT_PROTOCOL_VERSION, BootInfo, BootModule, MemoryMapEntry, MemoryMapSlice, ModuleSlice,
    PlatformResource, PlatformResourceSlice,
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

// ── Boot sequence ─────────────────────────────────────────────────────────────

/// Execute the ten-step boot sequence and transfer control to the kernel.
///
/// Returns `Result<!, BootError>`: the `Ok` variant is uninhabited (`!`) because
/// a successful sequence ends with a non-returning kernel jump. Any `Err` is
/// propagated to `efi_main` for error reporting.
///
/// # Safety
/// `image` must be the UEFI image handle passed to `efi_main`. `st` must be
/// a valid pointer to the UEFI system table.
// boot_sequence orchestrates the ten sequential boot steps; each step is already
// decomposed into focused helpers — splitting further would only scatter context.
#[allow(clippy::too_many_lines)]
unsafe fn boot_sequence(image: EfiHandle, st: *mut EfiSystemTable) -> Result<!, BootError>
{
    // SAFETY: st is validated by the caller (efi_main receives it from UEFI).
    let bs = unsafe { (*st).boot_services };

    // ── Step 1: UEFI protocol discovery ──────────────────────────────────────

    bprintln!("[--------] boot: step 1/10: UEFI protocol discovery");

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
    let framebuffer =
        unsafe { query_gop(bs) }.unwrap_or_else(boot_protocol::FramebufferInfo::empty);

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

    // ── Step 2: Load boot configuration ──────────────────────────────────────

    bprintln!("[--------] boot: step 2/10: load boot configuration");

    // SAFETY: esp_root is a valid EFI_FILE_PROTOCOL directory handle.
    let config = unsafe { load_boot_config(esp_root)? };

    // ── Step 3: Load kernel ELF ───────────────────────────────────────────────

    bprintln!("[--------] boot: step 3/10: load kernel ELF");

    // SAFETY: esp_root is a valid directory handle; path is a null-terminated UTF-16.
    let kernel_file =
        unsafe { open_file(esp_root, config.kernel_path.as_ptr(), "kernel (boot.conf)")? };
    // SAFETY: kernel_file is a valid open file handle.
    // File size is a u64 from UEFI; usize is 64-bit on all supported targets so cast is exact.
    #[allow(clippy::cast_possible_truncation)]
    let kernel_file_sz = unsafe { file_size(kernel_file)? } as usize;
    let kernel_buf_pages = kernel_file_sz.div_ceil(4096);
    // SAFETY: bs is valid.
    let kernel_buf_phys = unsafe { allocate_pages(bs, kernel_buf_pages)? };
    // SAFETY: kernel_buf_phys is a freshly allocated region of kernel_buf_pages*4096 bytes,
    // identity-mapped by UEFI. Slicing to kernel_file_sz is within the allocation.
    let kernel_buf =
        unsafe { core::slice::from_raw_parts_mut(kernel_buf_phys as *mut u8, kernel_file_sz) };
    // SAFETY: kernel_file is open and at position 0; kernel_buf is the correct size.
    unsafe { file_read(kernel_file, kernel_buf)? };
    // SAFETY: bs is valid; kernel_buf is the complete ELF file.
    let kernel_info = unsafe { load_kernel(bs, kernel_buf, arch::current::EXPECTED_ELF_MACHINE)? };

    // Use direct-write helpers instead of format-arg bprintln! to avoid vtable
    // dispatch. On RISC-V, the PE .reloc section is currently empty, so the
    // firmware does not patch vtable entries when relocating the image;
    // core::fmt::write's write_str call through a fat pointer faults.
    bprint!("[--------] boot: kernel entry=");
    // SAFETY: console initialized; function writes to UART MMIO or framebuffer.
    unsafe {
        crate::console::console_write_hex64(kernel_info.entry_virtual);
    }
    bprint!("  size=");
    // SAFETY: console initialized.
    unsafe {
        crate::console::console_write_hex64(kernel_info.size as u64);
    }
    bprintln!(" bytes");

    // ── Step 4: Load and pre-parse init ELF ──────────────────────────────────

    bprintln!("[--------] boot: step 4/10: load init ELF and boot modules");

    // SAFETY: esp_root is a valid directory handle; path is null-terminated UTF-16.
    let init_file = unsafe { open_file(esp_root, config.init_path.as_ptr(), "init (boot.conf)")? };
    // SAFETY: init_file is a valid open file handle.
    // File size is a u64 from UEFI; usize is 64-bit on all supported targets so cast is exact.
    #[allow(clippy::cast_possible_truncation)]
    let init_file_sz = unsafe { file_size(init_file)? } as usize;
    let init_buf_pages = init_file_sz.div_ceil(4096);
    // SAFETY: bs is valid.
    let init_buf_phys = unsafe { allocate_pages(bs, init_buf_pages)? };
    // SAFETY: init_buf_phys is a freshly allocated region; slice is within the allocation.
    let init_buf =
        unsafe { core::slice::from_raw_parts_mut(init_buf_phys as *mut u8, init_file_sz) };
    // SAFETY: init_file is open at position 0; init_buf is the correct size.
    unsafe { file_read(init_file, init_buf)? };
    // Parse the init ELF and load its segments into physical memory.
    // load_init allocates at any available physical address (not p_paddr) because
    // init is a userspace ELF whose p_paddr values conflict with UEFI low-memory use.
    // The kernel receives phys_addr+virt_addr pairs to map init without an ELF parser.
    // SAFETY: bs is valid; init_buf contains the complete ELF file.
    let init_image = unsafe { load_init(bs, init_buf, arch::current::EXPECTED_ELF_MACHINE)? };

    // Print init entry point and file size, matching the kernel ELF info in step 3.
    // Direct-write helpers are used here (instead of format-arg bprintln!) to avoid
    // vtable dispatch. On RISC-V the PE .reloc section is empty so the firmware does
    // not patch vtable entries; core::fmt::write's fat-pointer write_str call faults.
    bprint!("[--------] boot: init entry=");
    // SAFETY: console initialized.
    unsafe {
        crate::console::console_write_hex64(init_image.entry_point);
    }
    bprint!("  size=");
    // SAFETY: console initialized.
    unsafe {
        crate::console::console_write_hex64(init_file_sz as u64);
    }
    bprintln!(" bytes");

    // ── Step 4b: Load additional boot modules ─────────────────────────────────
    //
    // Modules listed in boot.conf under `modules=` are flat binary images
    // (raw ELF files for early userspace services). Each is loaded into a
    // UEFI-allocated physical region via load_module(); the resulting BootModule
    // descriptors are held in a local array and written into modules_phys during
    // step 9. The file read buffers are tracked for identity mapping below.

    // Local arrays: sized to MAX_MODULES (16). Filled entries are [0..boot_module_count].
    // BootModule is Copy so the zeroed initializer compiles without a Default impl.
    let mut boot_modules = [BootModule {
        physical_base: 0,
        size: 0,
    }; crate::config::MAX_MODULES];
    let mut boot_module_count: usize = 0;

    // Per-module file read buffer: (physical_base, page_count) for identity mapping.
    let mut mod_buf_phys_arr = [0u64; crate::config::MAX_MODULES];
    let mut mod_buf_pages_arr = [0usize; crate::config::MAX_MODULES];

    for i in 0..config.module_count
    {
        // SAFETY: esp_root is valid; module_paths[i] is a null-terminated UTF-16 path.
        let mod_file = unsafe {
            open_file(
                esp_root,
                config.module_paths[i].as_ptr(),
                "module (boot.conf)",
            )?
        };
        // SAFETY: mod_file is a valid open file handle.
        // File size is a u64 from UEFI; usize is 64-bit on all supported targets so cast is exact.
        #[allow(clippy::cast_possible_truncation)]
        let mod_file_sz = unsafe { file_size(mod_file)? } as usize;
        let mod_buf_pages = mod_file_sz.div_ceil(4096);
        // SAFETY: bs is valid.
        let mod_buf_phys = unsafe { allocate_pages(bs, mod_buf_pages)? };
        // SAFETY: mod_buf_phys is a freshly allocated region of mod_buf_pages*4096 bytes.
        let mod_buf =
            unsafe { core::slice::from_raw_parts_mut(mod_buf_phys as *mut u8, mod_file_sz) };
        // SAFETY: mod_file is open at position 0; mod_buf is the correct size.
        unsafe { file_read(mod_file, mod_buf)? };
        // SAFETY: bs is valid; mod_buf contains the complete module file.
        let module = unsafe { load_module(bs, mod_buf)? };

        mod_buf_phys_arr[i] = mod_buf_phys;
        mod_buf_pages_arr[i] = mod_buf_pages;
        boot_modules[boot_module_count] = module;
        boot_module_count += 1;
    }

    // ── Step 5: Firmware discovery ────────────────────────────────────────────

    bprintln!("[--------] boot: step 5/10: firmware discovery and platform resources");

    // Scan the UEFI configuration table for the ACPI RSDP and Device Tree GUIDs.
    // SAFETY: st is a valid UEFI system table pointer.
    let firmware = unsafe { discover_firmware(st) };

    if firmware.acpi_rsdp != 0
    {
        bprintln!("[--------] boot: ACPI RSDP: found");
    }
    else
    {
        bprintln!("[--------] boot: ACPI RSDP: not found");
    }
    if firmware.device_tree != 0
    {
        bprintln!("[--------] boot: DTB: found");
    }
    else
    {
        bprintln!("[--------] boot: DTB: not found");
    }

    // Query the boot hart ID via EFI_RISCV_BOOT_PROTOCOL (RISC-V only).
    // Returns 0 on x86-64 (no-op) or when the protocol is unavailable.
    // SAFETY: st is a valid UEFI system table pointer.
    let boot_hart_id = unsafe { arch::current::discover_boot_hart_id(st) };

    // ── CPU topology discovery ────────────────────────────────────────────────
    // BSP hardware ID: APIC ID on x86-64 (from CPUID), boot hart ID on RISC-V.
    #[cfg(target_arch = "x86_64")]
    let bsp_hw_id: u32 = arch::current::bsp_hardware_id();
    #[cfg(not(target_arch = "x86_64"))]
    // SAFETY: hart IDs are small integers; lower 32 bits are sufficient.
    #[allow(clippy::cast_possible_truncation)]
    let bsp_hw_id: u32 = boot_hart_id as u32;

    // Primary: ACPI MADT (works on both x86-64 and RISC-V UEFI).
    // Fallback on RISC-V: DTB /cpus if ACPI is absent.
    // SAFETY: firmware.acpi_rsdp / firmware.device_tree are identity-mapped.
    let (cpu_count, boot_cpu_id, boot_cpu_ids) = if firmware.acpi_rsdp != 0
    {
        // SAFETY: firmware.acpi_rsdp is identity-mapped by UEFI; parse_cpu_topology validates table.
        let (n, b, ids) = unsafe { acpi::parse_cpu_topology(firmware.acpi_rsdp, bsp_hw_id) };
        bprint!("[--------] boot: ACPI: ");
        // SAFETY: console initialized.
        unsafe { crate::console::console_write_dec32(n) };
        bprintln!(" CPU(s) found via MADT");
        (n, b, ids)
    }
    else if firmware.device_tree != 0
    {
        // SAFETY: firmware.device_tree is identity-mapped by UEFI; parse_cpu_count validates FDT.
        let (n, hart_ids) = unsafe { dtb::parse_cpu_count(firmware.device_tree) };
        if n > 0
        {
            bprint!("[--------] boot: DTB: ");
            // SAFETY: console initialized.
            unsafe { crate::console::console_write_dec32(n) };
            bprintln!(" hart(s) found");
            // BSP is first; re-order so bsp_hw_id is at index 0.
            let mut ids = [0u32; 64];
            ids[0] = bsp_hw_id;
            let mut ap_idx = 1usize;
            for &hart_id in hart_ids.iter().take(n as usize)
            {
                if hart_id != bsp_hw_id && ap_idx < 64
                {
                    ids[ap_idx] = hart_id;
                    ap_idx += 1;
                }
            }
            (n, bsp_hw_id, ids)
        }
        else
        {
            bprintln!("[--------] boot: DTB: no CPU nodes found, defaulting to 1");
            let mut ids = [0u32; 64];
            ids[0] = bsp_hw_id;
            (1, bsp_hw_id, ids)
        }
    }
    else
    {
        bprintln!("[--------] boot: CPU topology: no firmware tables, defaulting to 1");
        let mut ids = [0u32; 64];
        ids[0] = bsp_hw_id;
        (1, bsp_hw_id, ids)
    };

    // Parse ACPI and/or DTB tables into a sorted PlatformResource array.
    // If a framebuffer is present, a descriptor page is allocated and two
    // additional resources (MmioRange + PlatformTable) are emitted.
    // SAFETY: bs is valid boot services; firmware addresses are from UEFI config table.
    let (resources_phys, resource_count, fb_desc_phys) =
        unsafe { platform::parse_platform_resources(bs, &firmware, &framebuffer)? };
    bprint!("[--------] boot: platform resources: ");
    // resource_count is bounded by the platform_resources array size (≤ 256), fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    // SAFETY: console initialized.
    unsafe {
        crate::console::console_write_dec32(resource_count as u32);
    }
    bprintln!(" parsed");

    // ── Step 6: Pre-allocate boot structures and build page tables ────────────

    // BootInfo: one page — holds the BootInfo struct populated in step 8.
    // SAFETY: bs is valid.
    let boot_info_phys = unsafe { allocate_pages(bs, 1)? };

    // Module array: one page — reserved for BootInfo.modules (future boot modules).
    // Currently unused (init is passed via init_image, not modules). Keep the
    // allocation so the page is identity-mapped and available if populated later.
    // SAFETY: bs is valid.
    let modules_phys = unsafe { allocate_pages(bs, 1)? };

    // MemoryMapEntry output array: MEM_MAP_ENTRY_PAGES pages — the translated
    // physical memory map. Passed to BootInfo; must remain accessible to the kernel.
    // SAFETY: bs is valid.
    let mem_entries_phys = unsafe { allocate_pages(bs, MEM_MAP_ENTRY_PAGES)? };

    // Kernel stack: KERNEL_STACK_PAGES pages (64 KiB). Stack grows downward;
    // stack_top is the address of the byte past the last allocated page.
    // SAFETY: bs is valid.
    let stack_phys = unsafe { allocate_pages(bs, KERNEL_STACK_PAGES)? };
    let stack_top = stack_phys + (KERNEL_STACK_PAGES as u64) * 4096;

    // Command line: one page. Copy cmdline from config and null-terminate.
    // MAX_CMDLINE_LEN (512) is well within the 4096-byte allocation.
    // SAFETY: bs is valid.
    let cmdline_phys = unsafe { allocate_pages(bs, 1)? };
    if config.cmdline_len > 0
    {
        // SAFETY: cmdline_phys is a valid allocation; config.cmdline[..cmdline_len]
        // is valid ASCII. Regions are disjoint (config is stack data).
        unsafe {
            core::ptr::copy_nonoverlapping(
                config.cmdline.as_ptr(),
                cmdline_phys as *mut u8,
                config.cmdline_len,
            );
        }
    }
    // SAFETY: cmdline_phys + cmdline_len is within the 4096-byte allocation
    // because MAX_CMDLINE_LEN (512) < 4096.
    unsafe { core::ptr::write((cmdline_phys + config.cmdline_len as u64) as *mut u8, 0u8) };

    // Accumulate all physical regions that must be identity-mapped so the kernel
    // can access them before its own page tables are established. The array is
    // fixed-size; region_count tracks valid entries.
    let mut identity_regions: [(u64, u64); MAX_IDENTITY_REGIONS] =
        [(0u64, 0u64); MAX_IDENTITY_REGIONS];
    let mut region_count: usize = 0;

    /// Add a (`physical_base`, `size`) pair to the identity-map tracking array.
    /// Silently drops entries beyond `MAX_IDENTITY_REGIONS` (design budget is 64).
    macro_rules! track_region {
        ($phys:expr, $size:expr) => {
            if region_count < MAX_IDENTITY_REGIONS
            {
                identity_regions[region_count] = ($phys as u64, $size as u64);
                region_count += 1;
            }
        };
    }

    // Kernel ELF segments: each mapped at its ELF virtual address by the page
    // table builder, but the physical range must also be identity-mapped so the
    // kernel can verify the mapping before establishing its own tables.
    for i in 0..kernel_info.segment_count
    {
        let seg = &kernel_info.segments[i];
        // Align size up to page boundary for identity-map coverage.
        let aligned_size = (seg.size + 4095) & !4095;
        track_region!(seg.phys_base, aligned_size);
    }

    // Fixed boot allocations — all must be identity-mapped.
    track_region!(boot_info_phys, 4096u64);
    track_region!(modules_phys, 4096u64);
    track_region!(mem_entries_phys, (MEM_MAP_ENTRY_PAGES as u64) * 4096);
    track_region!(stack_phys, (KERNEL_STACK_PAGES as u64) * 4096);
    track_region!(cmdline_phys, 4096u64);
    // Init segments: each allocated at an arbitrary physical address by load_init.
    // The kernel identity-maps these to copy them into init's address space.
    for i in 0..(init_image.segment_count as usize)
    {
        let seg = &init_image.segments[i];
        track_region!(seg.phys_addr, (seg.size + 4095) & !4095);
    }
    // Keep the init ELF read buffer mapped until ExitBootServices; the kernel
    // does not need it (segments are already copied), but UEFI holds the
    // allocation until ExitBootServices so we account for it.
    track_region!(init_buf_phys, (init_buf_pages as u64) * 4096);
    track_region!(kernel_buf_phys, (kernel_buf_pages as u64) * 4096);

    // Boot modules: identity-map both the file read buffer (UEFI retains it until
    // ExitBootServices) and the loaded module region (kernel reads the ELF content).
    for i in 0..config.module_count
    {
        track_region!(mod_buf_phys_arr[i], (mod_buf_pages_arr[i] as u64) * 4096);
        let aligned_size = (boot_modules[i].size + 4095) & !4095;
        track_region!(boot_modules[i].physical_base, aligned_size);
    }

    // Framebuffer: identity-map if present so the kernel can write early output.
    if framebuffer.physical_base != 0
    {
        let fb_size = u64::from(framebuffer.stride) * u64::from(framebuffer.height);
        track_region!(framebuffer.physical_base, (fb_size + 4095) & !4095);
    }

    // RISC-V MMIO UART: identity-map so the kernel can use it for early console.
    // Use the runtime-discovered address from arch::current::uart_mmio_region().
    {
        let uart_base = arch::current::uart_mmio_region();
        if uart_base != 0
        {
            track_region!(uart_base, 4096u64);
        }
    }

    // Platform resource array: identity-map if allocated.
    if resource_count > 0
    {
        let resource_array_size = resource_count * core::mem::size_of::<PlatformResource>();
        track_region!(resources_phys, (resource_array_size + 4095) & !4095);
    }

    // Framebuffer descriptor page: identity-map if allocated.
    if fb_desc_phys != 0
    {
        track_region!(fb_desc_phys, 4096u64);
    }

    // ── Step 5b: Allocate AP trampoline page (x86-64 only) ───────────────────
    // Must happen before ExitBootServices. Allocate exactly one 4 KiB page below
    // 1 MiB (physical < 0x100000) so the SIPI vector (bits[19:12]) fits in 8 bits.
    // The kernel writes AP startup code here at Phase C; the page appears as
    // `Loaded` in the memory map and is protected from the buddy allocator.
    #[cfg(target_arch = "x86_64")]
    let ap_trampoline_phys: u64 = {
        // Reserve just below 1 MiB. AllocateMaxAddress places the page anywhere
        // below the supplied upper bound (= 0xFFFFF = last byte of first MiB).
        // SAFETY: bs is valid; requesting low-memory page for x86-64 real-mode trampoline.
        if let Ok(phys) = unsafe { allocate_pages_max_addr(bs, 0xFFFFF, 1) }
        {
            bprint!("[--------] boot: AP trampoline page: ");
            // SAFETY: console initialized.
            unsafe { crate::console::console_write_hex64(phys) };
            bprintln!("");
            phys
        }
        else
        {
            bprintln!(
                "[--------] boot: WARNING: cannot allocate AP trampoline page below 1 MiB — SMP disabled"
            );
            0
        }
    };
    // RISC-V: allocate any 4 KiB page for the AP trampoline. No below-1 MiB
    // constraint — SBI HSM accepts any physical start address. The kernel
    // identity-maps this page (Phase 3) before copying trampoline code there.
    #[cfg(target_arch = "riscv64")]
    // SAFETY: bs is valid boot services.
    let ap_trampoline_phys: u64 = if let Ok(phys) = unsafe { allocate_pages(bs, 1) }
    {
        bprint!("[--------] boot: AP trampoline page: 0x");
        // SAFETY: console initialized.
        unsafe { crate::console::console_write_hex64(phys) };
        bprintln!("");
        phys
    }
    else
    {
        bprintln!("[--------] boot: WARNING: cannot allocate AP trampoline page — SMP disabled");
        0
    };
    #[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
    let ap_trampoline_phys: u64 = 0;

    bprintln!("[--------] boot: step 6/10: allocate and build page tables");

    // Build the initial page tables. All AllocatePages calls for page table
    // frames happen here, before ExitBootServices.
    let mut page_table =
        build_initial_tables(bs, &kernel_info, &identity_regions[0..region_count])?;

    // Identity-map the handoff trampoline page(s) as RX in the new page tables.
    // After `mov cr3` the CPU fetches the next instruction at the same VA; that
    // VA must be mapped RX in the new tables or the CPU faults immediately.
    // Under UEFI x86-64, VA == PA, so we use the symbol address as the physical
    // address directly. On RISC-V the stub returns (0,0); we skip mapping.
    let (tramp_first, tramp_last) = arch::current::trampoline_page_range();
    if tramp_first != 0
    {
        let tramp_flags = paging::PageFlags {
            writable: false,
            executable: true,
        };
        page_table
            .map(tramp_first, tramp_first, 4096, tramp_flags)
            .map_err(|e| match e
            {
                paging::MapError::OutOfMemory => BootError::OutOfMemory,
                paging::MapError::WxViolation => BootError::WxViolation,
            })?;
        if tramp_last != tramp_first
        {
            let tramp_flags = paging::PageFlags {
                writable: false,
                executable: true,
            };
            page_table
                .map(tramp_last, tramp_last, 4096, tramp_flags)
                .map_err(|e| match e
                {
                    paging::MapError::OutOfMemory => BootError::OutOfMemory,
                    paging::MapError::WxViolation => BootError::WxViolation,
                })?;
        }
    }

    // ── Step 7: Query final memory map ────────────────────────────────────────

    bprintln!("[--------] boot: step 7/10: query final memory map");

    // This must be the last allocation-generating operation before ExitBootServices.
    // AllocatePages inside get_memory_map invalidates any prior map key; this call
    // produces the map key used in step 7.
    // SAFETY: bs is valid.
    let mut uefi_map = unsafe { get_memory_map(bs)? };

    // ── Step 8: ExitBootServices ──────────────────────────────────────────────

    bprintln!("[--------] boot: step 8/10: ExitBootServices");

    // SAFETY: bs and image are valid; uefi_map was produced by the preceding
    // get_memory_map call with no intervening allocations.
    unsafe { exit_boot_services(bs, image, &mut uefi_map)? };

    // ══════════════════════════════════════════════════════════════════════════
    // NO UEFI CALLS AFTER THIS POINT. Boot services are permanently unavailable.
    // All subsequent operations use only pre-allocated physical memory.
    // ══════════════════════════════════════════════════════════════════════════

    // ── Step 9: Populate BootInfo ─────────────────────────────────────────────

    bprintln!("[--------] boot: step 9/10: populate BootInfo");

    // Write loaded BootModule descriptors into the pre-allocated modules page.
    // Each BootModule is 16 bytes; MAX_MODULES (16) entries fit in one 4096-byte page.
    // SAFETY: modules_phys is a valid 4096-byte allocation. boot_module_count <=
    // MAX_MODULES (16) so the writes stay within the allocation.
    let modules_ptr = modules_phys as *mut BootModule;
    for (i, &module) in boot_modules.iter().enumerate().take(boot_module_count)
    {
        // SAFETY: modules_phys is a 4096-byte allocation; i < boot_module_count ≤ 16;
        // BootModule is 48 bytes so 16 entries fit comfortably within 4096 bytes.
        unsafe { core::ptr::write(modules_ptr.add(i), module) };
    }

    // Translate the UEFI memory descriptors into the boot protocol's MemoryMapEntry
    // format and sort by physical_base ascending.
    let entry_out = mem_entries_phys as *mut MemoryMapEntry;
    let max_entries = (MEM_MAP_ENTRY_PAGES * 4096) / core::mem::size_of::<MemoryMapEntry>();
    // SAFETY: entry_out is a valid allocated buffer of max_entries entries; uefi_map
    // is a valid map buffer populated by UEFI GetMemoryMap above.
    let entry_count =
        unsafe { memory_map::translate_memory_map(&uefi_map, entry_out, max_entries) };

    // Sort the output array by physical_base ascending (insertion sort).
    // SAFETY: entry_out is a valid allocated array of max_entries entries;
    // elements [0..entry_count] were written by translate_memory_map above.
    unsafe { memory_map::insertion_sort_memory_map(entry_out, entry_count) };

    // Write a populated BootInfo into the pre-allocated page.
    // SAFETY: boot_info_phys is a valid 4096-byte physical allocation, identity-mapped
    // by UEFI. BootInfo fits comfortably within one page.
    unsafe {
        core::ptr::write(
            boot_info_phys as *mut BootInfo,
            BootInfo {
                version: BOOT_PROTOCOL_VERSION,
                memory_map: MemoryMapSlice {
                    entries: entry_out,
                    count: entry_count as u64,
                },
                kernel_physical_base: kernel_info.physical_base,
                kernel_virtual_base: kernel_info.virtual_base,
                kernel_size: kernel_info.size,
                init_image,
                modules: ModuleSlice {
                    entries: if boot_module_count > 0
                    {
                        modules_phys as *const BootModule
                    }
                    else
                    {
                        core::ptr::null()
                    },
                    count: boot_module_count as u64,
                },
                framebuffer,
                acpi_rsdp: firmware.acpi_rsdp,
                device_tree: firmware.device_tree,
                platform_resources: PlatformResourceSlice {
                    entries: if resource_count > 0
                    {
                        resources_phys as *const PlatformResource
                    }
                    else
                    {
                        core::ptr::null()
                    },
                    count: resource_count as u64,
                },
                command_line: cmdline_phys as *const u8,
                command_line_len: config.cmdline_len as u64,
                cpu_count: cpu_count.max(1),
                bsp_id: boot_cpu_id,
                cpu_ids: boot_cpu_ids,
                ap_trampoline_page: ap_trampoline_phys,
            },
        );
    }

    // ── Step 10: Kernel handoff ───────────────────────────────────────────────

    bprintln!("[--------] boot: step 10/10: kernel handoff");

    // Transfer control to the kernel. Installs new page tables, sets the
    // stack, and jumps to the kernel entry point. Does not return.
    // SAFETY: page_table was built from valid physical frames covering all
    // required virtual ranges. entry_virtual is within the loaded kernel image.
    // boot_info_phys is a populated BootInfo in a pre-allocated, identity-mapped
    // page. stack_top is the top of a 64 KiB pre-allocated, identity-mapped
    // stack region. ExitBootServices has completed.
    unsafe {
        arch::current::perform_handoff(
            page_table.root_physical(),
            kernel_info.entry_virtual,
            boot_info_phys,
            stack_top,
            boot_hart_id,
        )
    }
}
