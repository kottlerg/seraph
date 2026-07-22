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
mod console;
mod dtb;
mod elf;
mod error;
mod firmware;
mod framebuffer;
mod memory_map;
mod paging;
mod uefi;

use crate::elf::{KernelInfo, load_init, load_kernel};
use crate::error::BootError;
use crate::firmware::{FirmwareInfo, discover_firmware};
use crate::paging::{PageTableBuilder, build_initial_tables};
use crate::uefi::{
    EFI_RNG_PROTOCOL_GUID, EFI_SUCCESS, EfiBootServices, EfiFileProtocol, EfiGuid, EfiHandle,
    EfiRngProtocol, EfiSystemTable, allocate_pages, connect_all_controllers, exit_boot_services,
    file_read, file_size, get_loaded_image, get_memory_map, open_esp_volume, open_file, query_gop,
};
use boot_protocol::{
    BOOT_MODULE_NAME_LEN, BOOT_PROTOCOL_VERSION, BootInfo, BootModule, FramebufferInfo, InitImage,
    KernelMmio, MAX_APERTURES, MAX_CPUS, MAX_RECLAIM_RANGES, MemoryMapEntry, MemoryMapSlice,
    MmioAperture, MmioApertureSlice, ModuleSlice, RECLAIM_FLAG_LATE, ReclaimRange, ReclaimSlice,
    bundle,
};

/// Maximum boot modules carried in [`BootInfo::modules`]. Sized to comfortably
/// cover the current `procmgr, memmgr, devmgr, vfsd, virtio-blk, fatfs` set
/// plus future additions before the bundle entry count exceeds the array.
const MAX_MODULES: usize = 16;

/// `\EFI\seraph\kernel` as a NUL-terminated UTF-16 path for
/// `EFI_FILE_PROTOCOL.Open()`.
#[rustfmt::skip]
static KERNEL_PATH: [u16; 19] = [
    b'\\' as u16, b'E' as u16, b'F' as u16, b'I' as u16, b'\\' as u16,
    b's' as u16, b'e' as u16, b'r' as u16, b'a' as u16, b'p' as u16,
    b'h' as u16, b'\\' as u16, b'k' as u16, b'e' as u16, b'r' as u16,
    b'n' as u16, b'e' as u16, b'l' as u16, 0u16,
];

/// `\EFI\seraph\bootstrap.bundle` as a NUL-terminated UTF-16 path.
#[rustfmt::skip]
static BUNDLE_PATH: [u16; 29] = [
    b'\\' as u16, b'E' as u16, b'F' as u16, b'I' as u16, b'\\' as u16,
    b's' as u16, b'e' as u16, b'r' as u16, b'a' as u16, b'p' as u16,
    b'h' as u16, b'\\' as u16, b'b' as u16, b'o' as u16, b'o' as u16,
    b't' as u16, b's' as u16, b't' as u16, b'r' as u16, b'a' as u16,
    b'p' as u16, b'.' as u16, b'b' as u16, b'u' as u16, b'n' as u16,
    b'd' as u16, b'l' as u16, b'e' as u16, 0u16,
];

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

/// Init ELF load result. Pre-parsed via [`load_init`]; segment bodies live
/// in their own UEFI allocations (referenced by `image.segments[].phys_addr`).
/// The source ELF bytes are part of the single bundle allocation tracked in
/// [`BundleLoad`], so no per-init read buffer is recorded here.
struct InitLoad
{
    image: InitImage,
}

/// Boot-module load results: a fixed-capacity array of [`BootModule`]
/// descriptors. Module bodies are slices of the bundle allocation (see
/// [`BundleLoad`]); there is no per-module read buffer.
struct ModulesLoad
{
    modules: [BootModule; MAX_MODULES],
    count: usize,
}

/// Bundle load result: a single UEFI allocation holding the whole
/// `\EFI\seraph\bootstrap.bundle` file. The parsed entry headers (kept as
/// raw bytes) drive [`step4_parse_bundle`].
struct BundleLoad
{
    /// Physical base of the UEFI allocation holding the bundle.
    phys: u64,
    /// Page count of the UEFI allocation (covers `len` bytes rounded up).
    pages: usize,
    /// Exact bundle file size in bytes.
    len: u64,
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

/// Conditioned early-boot entropy seed drawn from UEFI `EFI_RNG_PROTOCOL`.
///
/// `len` is `0` when the firmware exposes no RNG; the kernel then degrades to
/// timing jitter alone. Produced by [`step5c_fetch_boot_entropy`] while boot
/// services are live and written into [`BootInfo`] by step 9.
struct BootEntropy
{
    /// Random bytes; only the first `len` are valid, the remainder zero.
    seed: [u8; 32],
    /// Number of valid leading bytes in `seed` (`0` or `32`).
    len: u32,
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
    ap_trampoline_phys: u64,
    /// Physical address of the dedicated 4 KiB page that backs
    /// `BootInfo.reclaim_ranges`. The bootloader allocates this page in
    /// step 6, populates the `ReclaimRange` array in step 9, and records
    /// the page itself as a reclaim entry so the kernel reclaims it last.
    reclaim_array_phys: u64,
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
    let bundle_load = unsafe { step2_load_bundle(&ctx)? };
    // SAFETY: ctx.bs / esp_root are valid until ExitBootServices.
    let mut kernel = unsafe { step3_load_kernel(&ctx)? };
    // SAFETY: bundle_load.phys/len name a valid identity-mapped UEFI allocation.
    let (init, mods) = unsafe { step4_parse_bundle(&ctx, &bundle_load)? };
    // SAFETY: ctx.st is a valid UEFI system table.
    let firm = unsafe { step5_discover_firmware(&ctx) };
    // SAFETY: ctx.st is valid; firmware addresses are identity-mapped by UEFI.
    let cpus = unsafe { step5_discover_cpu_topology(&ctx, &firm) };
    // Negotiate the paging mode before step 6 fixes the table hierarchy depth
    // and step 10 installs it. No-op on x86-64.
    // SAFETY: ctx.bs valid pre-exit; firm.device_tree is zero or an
    // identity-mapped FDT; the probe masks SIE and restores the live satp.
    unsafe { arch::current::negotiate_paging(ctx.bs, firm.device_tree, cpus.boot_hart_id)? };
    // SAFETY: ctx.bs valid pre-exit.
    let ap_trampoline_phys = unsafe { step5b_alloc_ap_trampoline(&ctx) };
    // SAFETY: ctx.bs valid pre-exit; draws the boot entropy seed while boot
    // services (and thus EFI_RNG_PROTOCOL) are still available.
    let boot_entropy = unsafe { step5c_fetch_boot_entropy(&ctx) };
    // Apply the KASLR slide before step 6 maps the segments at their
    // (biased) virtual addresses.
    // SAFETY: kernel.info comes from load_kernel with its span allocation
    // live and identity-mapped; virtual addresses are still unbiased link VAs.
    unsafe { step5d_apply_kaslr_slide(&mut kernel.info)? };
    // SAFETY: all prior unsafe outputs remain valid; step 6 allocates via bs.
    let (allocs, mut page_table) = unsafe {
        step6_allocate_and_build_page_tables(
            &ctx,
            &bundle_load,
            &kernel,
            &init,
            &mods,
            ap_trampoline_phys,
        )?
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
            &bundle_load,
            &kernel,
            &init,
            &mods,
            &firm,
            &cpus,
            &boot_entropy,
            &ctx.framebuffer,
            &allocs,
            &uefi_map,
            &page_table,
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
        bprintln!(
            "[--------] boot: GOP: present {}x{}",
            framebuffer.width,
            framebuffer.height
        );
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

// ── Step 2: Load bundle ──────────────────────────────────────────────────────

/// Open `\EFI\seraph\bootstrap.bundle`, allocate one contiguous UEFI
/// region big enough to hold the whole file, and read it in. The header
/// is validated at the start of [`step4_parse_bundle`].
///
/// # Safety
/// `ctx.bs` and `ctx.esp_root` must be valid UEFI services / directory
/// handles, pre-`ExitBootServices`.
unsafe fn step2_load_bundle(ctx: &UefiContext) -> Result<BundleLoad, BootError>
{
    bprintln!("[--------] boot: step 2/10: load bootstrap.bundle");
    // SAFETY: esp_root is a valid directory handle; path is null-terminated UTF-16.
    let file = unsafe {
        open_file(
            ctx.esp_root,
            BUNDLE_PATH.as_ptr(),
            "\\EFI\\seraph\\bootstrap.bundle",
        )?
    };
    // SAFETY: file is a valid open file handle.
    // cast_possible_truncation: usize is 64-bit on every UEFI target Seraph supports.
    #[allow(clippy::cast_possible_truncation)]
    let len = unsafe { file_size(file)? } as usize;
    if len == 0
    {
        return Err(BootError::InvalidBundle("bootstrap.bundle is empty"));
    }
    let pages = len.div_ceil(4096);
    // SAFETY: bs is valid.
    let phys = unsafe { allocate_pages(ctx.bs, pages)? };
    // SAFETY: phys is a freshly allocated region of `pages * 4096 >= len` bytes,
    // identity-mapped by UEFI. The slice covers exactly the file extent.
    let buf = unsafe { core::slice::from_raw_parts_mut(phys as *mut u8, len) };
    // SAFETY: file is open at position 0; buf is the correct size.
    unsafe { file_read(file, buf)? };

    bprintln!("[--------] boot: bundle size={:#018x} bytes", len as u64);

    Ok(BundleLoad {
        phys,
        pages,
        len: len as u64,
    })
}

// ── Step 3: Load kernel ELF ──────────────────────────────────────────────────

/// Load and parse the kernel ELF into UEFI-allocated physical memory.
///
/// # Safety
/// `ctx.bs` and `ctx.esp_root` must be valid UEFI services and directory
/// handle respectively.
unsafe fn step3_load_kernel(ctx: &UefiContext) -> Result<KernelLoad, BootError>
{
    bprintln!("[--------] boot: step 3/10: load kernel ELF");
    // SAFETY: esp_root is a valid directory handle; path is null-terminated UTF-16.
    let kernel_file =
        unsafe { open_file(ctx.esp_root, KERNEL_PATH.as_ptr(), "\\EFI\\seraph\\kernel")? };
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

    bprintln!(
        "[--------] boot: kernel base={:#018x}  entry={:#018x}  size={:#018x} bytes",
        info.physical_base,
        info.entry_virtual,
        info.size
    );

    Ok(KernelLoad {
        info,
        buf_phys,
        buf_pages,
    })
}

// ── Step 4: Parse bundle, pre-parse init ELF, collect modules ────────────────

/// Walk the bundle header, ELF-load the entry named [`bundle::INIT_ENTRY_NAME`]
/// into a fresh set of segment pages, and expose every other entry as a
/// [`BootModule`] referencing the bundle allocation in place.
///
/// # Safety
/// `bundle_load.phys`/`len` must name the UEFI allocation produced by
/// [`step2_load_bundle`]; the bytes must remain valid until `step9` runs.
/// `ctx.bs` must be valid pre-`ExitBootServices`.
unsafe fn step4_parse_bundle(
    ctx: &UefiContext,
    bundle_load: &BundleLoad,
) -> Result<(InitLoad, ModulesLoad), BootError>
{
    bprintln!("[--------] boot: step 4/10: parse bundle (init + modules)");

    // SAFETY: bundle_load.phys names a valid identity-mapped UEFI allocation
    // of `pages * 4096 >= len` bytes; we read exactly `len` bytes. usize is
    // 64-bit on every UEFI target Seraph supports, so the len cast is exact.
    #[allow(clippy::cast_possible_truncation)]
    let bytes = unsafe {
        core::slice::from_raw_parts(bundle_load.phys as *const u8, bundle_load.len as usize)
    };

    let header = match bundle::parse_header(bytes)
    {
        Ok(h) => h,
        Err(bundle::BundleError::TooSmall) =>
        {
            return Err(BootError::InvalidBundle("bundle truncated"));
        }
        Err(bundle::BundleError::BadMagic) =>
        {
            return Err(BootError::InvalidBundle("bundle magic mismatch"));
        }
        Err(bundle::BundleError::BadVersion) =>
        {
            return Err(BootError::InvalidBundle("bundle version mismatch"));
        }
        Err(bundle::BundleError::EntryOutOfBounds) =>
        {
            return Err(BootError::InvalidBundle("bundle entry out of bounds"));
        }
        Err(bundle::BundleError::EntryMisaligned) =>
        {
            return Err(BootError::InvalidBundle("bundle entry misaligned"));
        }
    };

    let mut init_image: Option<InitImage> = None;
    let mut modules = [BootModule {
        name: [0u8; BOOT_MODULE_NAME_LEN],
        physical_base: 0,
        size: 0,
    }; MAX_MODULES];
    let mut count: usize = 0;

    for i in 0..header.entry_count
    {
        let entry = bundle::entry_at(bytes, i);
        let name = bundle::name_str(&entry.name);
        // usize is 64-bit on every UEFI target Seraph supports; parse_header
        // already bounds-checked offset+size against `bytes.len()`.
        #[allow(clippy::cast_possible_truncation)]
        let body_start = entry.offset as usize;
        #[allow(clippy::cast_possible_truncation)]
        let body_end = body_start + entry.size as usize;
        if body_end > bytes.len()
        {
            return Err(BootError::InvalidBundle("bundle body past file end"));
        }
        let body = &bytes[body_start..body_end];

        if name == bundle::INIT_ENTRY_NAME
        {
            if init_image.is_some()
            {
                return Err(BootError::InvalidBundle(
                    "bundle has multiple `init` entries",
                ));
            }
            // SAFETY: bs is valid; body is the complete ELF file slice.
            let image = unsafe { load_init(ctx.bs, body, arch::current::EXPECTED_ELF_MACHINE)? };
            init_image = Some(image);
            bprintln!(
                "[--------] boot: init entry={:#018x}  size={:#018x} bytes",
                image.entry_point,
                entry.size
            );
        }
        else
        {
            if count >= MAX_MODULES
            {
                return Err(BootError::InvalidBundle(
                    "bundle exceeds MAX_MODULES entries",
                ));
            }
            modules[count] = BootModule {
                name: entry.name,
                // Bundle bodies are page-aligned (per `bundle::BODY_ALIGNMENT`),
                // so this physical base is a valid 4 KiB-aligned address inside
                // the bundle UEFI allocation.
                physical_base: bundle_load.phys + entry.offset,
                size: entry.size,
            };
            count += 1;
        }
    }

    let image = init_image.ok_or(BootError::InvalidBundle("bundle missing `init` entry"))?;
    Ok((InitLoad { image }, ModulesLoad { modules, count }))
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
        bprintln!("[--------] boot: ACPI: {count} CPU(s) found via MADT");
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
            bprintln!("[--------] boot: DTB: {count} hart(s) found");
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
        bprintln!("[--------] boot: AP trampoline page: {phys:#018x}");
        phys
    }
    else
    {
        bprintln!("[--------] boot: WARNING: cannot allocate AP trampoline page — SMP disabled");
        0
    }
}

// ── Step 5c: boot entropy seed ───────────────────────────────────────────────

/// Draw a conditioned early-boot entropy seed from UEFI `EFI_RNG_PROTOCOL`.
///
/// The seed narrows the kernel's boot-time entropy hole before any early
/// consumer (KASLR/ASLR) draws randomness. Returns `len == 0` when the firmware
/// exposes no RNG — the protocol is absent or `GetRNG` fails — in which case the
/// kernel degrades to timing jitter alone (no regression).
///
/// Silent by design: the kernel reports the resolved entropy source
/// (`entropy: seeded from firmware RNG …` / `… using jitter`) after handoff, so
/// the bootloader adds no console output here.
///
/// # Safety
/// `ctx.bs` must be valid UEFI boot services (before `ExitBootServices`).
unsafe fn step5c_fetch_boot_entropy(ctx: &UefiContext) -> BootEntropy
{
    let mut seed = [0u8; 32];
    let mut iface: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: ctx.bs is valid; locate_protocol fills iface on success.
    let status = unsafe {
        ((*ctx.bs).locate_protocol)(
            core::ptr::addr_of!(EFI_RNG_PROTOCOL_GUID),
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(iface),
        )
    };
    if status != EFI_SUCCESS || iface.is_null()
    {
        return BootEntropy { seed, len: 0 };
    }

    let proto = iface.cast::<EfiRngProtocol>();
    // SAFETY: proto is a valid protocol pointer from LocateProtocol; a null
    // algorithm selects the implementation default; seed has room for 32 bytes.
    // GetRNG returns EFI_SUCCESS only after writing all requested bytes.
    let s = unsafe {
        ((*proto).get_rng)(
            proto,
            core::ptr::null::<EfiGuid>(),
            seed.len(),
            seed.as_mut_ptr(),
        )
    };
    if s == EFI_SUCCESS
    {
        BootEntropy { seed, len: 32 }
    }
    else
    {
        // Discard any partial output rather than hand the kernel a short draw.
        seed = [0u8; 32];
        BootEntropy { seed, len: 0 }
    }
}

// ── Step 5d: KASLR slide ─────────────────────────────────────────────────────

/// Apply the kernel's KASLR slide: relocate the loaded image and bias its
/// virtual addresses before step 6 maps the segments.
///
/// The slide is currently always 0 — the image is relocated in place at its
/// link base. The randomized draw lands with the KASLR window selection
/// (issue #252).
///
/// # Safety
/// `info` must come from `load_kernel` with its span allocation live and
/// identity-mapped, and must not have been relocated already.
unsafe fn step5d_apply_kaslr_slide(info: &mut KernelInfo) -> Result<(), BootError>
{
    // SAFETY: forwarded from the caller's contract.
    unsafe { elf::relocate_kernel(info, 0, arch::current::EXPECTED_ELF_MACHINE) }
}

// ── Step 6: Allocate boot structures and build page tables ──────────────────

/// Allocate the fixed pre-exit scratch pages (`BootInfo` page, modules
/// descriptor page, memory-map page, aperture page, stack, reclaim-ranges
/// page), accumulate the identity-map region list, build initial page
/// tables, and install the x86-64 handoff-trampoline mapping.
///
/// # Safety
/// `ctx.bs` must be valid pre-exit; all addresses in `kernel`, `init`, and
/// `mods` must come from their respective `step3`/`step4*` outputs.
unsafe fn step6_allocate_and_build_page_tables(
    ctx: &UefiContext,
    bundle: &BundleLoad,
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
    // Reclaim-array page: dedicated 4 KiB backing for BootInfo.reclaim_ranges.
    // SAFETY: bs is valid.
    let reclaim_array_phys = unsafe { allocate_pages(ctx.bs, 1)? };

    let allocs = BootAllocations {
        boot_info_phys,
        modules_phys,
        mem_entries_phys,
        apertures_phys,
        stack_phys,
        stack_top,
        ap_trampoline_phys,
        reclaim_array_phys,
    };

    let mut identity_regions: [(u64, u64); MAX_IDENTITY_REGIONS] =
        [(0u64, 0u64); MAX_IDENTITY_REGIONS];
    let region_count = collect_identity_regions(
        &allocs,
        bundle,
        kernel,
        init,
        mods,
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
// (kernel, init, modules, bundle, framebuffer, UART, fixed allocations);
// bundling them further hides where a region came from.
#[allow(clippy::too_many_arguments)]
fn collect_identity_regions(
    allocs: &BootAllocations,
    bundle: &BundleLoad,
    kernel: &KernelLoad,
    init: &InitLoad,
    _mods: &ModulesLoad,
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
    // Init segments — segment bodies live in their own UEFI allocations,
    // produced by `load_init` against the bundle slice for the `init` entry.
    for i in 0..(init.image.segment_count as usize)
    {
        let seg = &init.image.segments[i];
        push(seg.phys_addr, (seg.size + 4095) & !4095);
    }
    // Kernel file read buffer (UEFI retains the allocation until ExitBootServices).
    push(kernel.buf_phys, (kernel.buf_pages as u64) * 4096);
    // Bundle blob: one allocation covers every module body and the init
    // ELF source bytes. Map once.
    push(bundle.phys, (bundle.pages as u64) * 4096);
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
    // Reclaim-array page: backs BootInfo.reclaim_ranges.
    push(allocs.reclaim_array_phys, 4096);
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
// them would only rename the argument list into an ad-hoc struct. The
// too_many_lines allowance covers the inline reclaim-array build below,
// which sits between aperture derivation and the BootInfo write.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
unsafe fn step9_populate_boot_info(
    bundle: &BundleLoad,
    kernel: &KernelLoad,
    init: &InitLoad,
    mods: &ModulesLoad,
    firm: &FirmwareInfo,
    cpus: &CpuTopology,
    boot_entropy: &BootEntropy,
    framebuffer: &FramebufferInfo,
    allocs: &BootAllocations,
    uefi_map: &uefi::MemoryMapResult,
    page_table: &arch::current::BootPageTable,
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

    // kernel_mmio: arch-dispatched extractor. Per-field docs on `KernelMmio`
    // state whether a zero field falls back to a kernel compiled-in constant
    // or is fatal at the consuming subsystem's initialization.
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
    // GOP linear framebuffer: UEFI typically reports it as
    // `EfiReservedMemoryType` rather than `EfiMemoryMappedIO`, so
    // `derive_mmio_apertures` cannot recover it from the UEFI map alone.
    // Seed it explicitly when present. The framebuffer's identity dies
    // at `ExitBootServices` (only GOP knows it pre-exit), so the
    // bootloader is the only entity that can carry this aperture
    // through to userspace.
    if framebuffer.physical_base != 0 && seed_count < MAX_APERTURE_SEEDS
    {
        let base_aligned = framebuffer.physical_base & !0xFFF;
        let span = framebuffer.physical_base
            + u64::from(framebuffer.stride) * u64::from(framebuffer.height);
        let end_aligned = (span + 0xFFF) & !0xFFF;
        aperture_seed[seed_count] = MmioAperture {
            phys_base: base_aligned,
            size: end_aligned - base_aligned,
        };
        seed_count += 1;
    }

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
    bprintln!("[--------] boot: MMIO apertures: {aperture_count} derived");

    // Build the reclaim-after-Phase-7 array in the dedicated 4 KiB page at
    // `allocs.reclaim_array_phys`. AP trampoline is handled by kernel-side
    // late reclaim after SMP bringup (see `mint_late_reclaim_memory_caps`);
    // every other bootloader scratch page lands here. The reclaim-array page
    // is itself recorded as the final entry so the kernel reclaims it last.
    // SAFETY: reclaim_array_phys is a valid 4 KiB allocation; we treat it as
    // a fixed-size array of MAX_RECLAIM_RANGES entries (256 × 16 B = 4 KiB).
    let reclaim_ranges: &mut [ReclaimRange; MAX_RECLAIM_RANGES] =
        unsafe { &mut *(allocs.reclaim_array_phys as *mut [ReclaimRange; MAX_RECLAIM_RANGES]) };
    *reclaim_ranges = [ReclaimRange {
        phys_base: 0,
        page_count: 0,
        flags: 0,
    }; MAX_RECLAIM_RANGES];
    let mut reclaim_len: usize = 0;
    let mut push_reclaim = |phys_base: u64, page_count: u32, flags: u32| {
        if page_count == 0
        {
            return;
        }
        if reclaim_len >= MAX_RECLAIM_RANGES
        {
            bprintln!("[--------] boot: FATAL: reclaim_ranges overflow (bump MAX_RECLAIM_RANGES)");
            // Post-exit, pre-handoff: BootInfo will be malformed; halt
            // explicitly so the failure is obvious rather than silent.
            loop
            {
                core::hint::spin_loop();
            }
        }
        reclaim_ranges[reclaim_len] = ReclaimRange {
            phys_base,
            page_count,
            flags,
        };
        reclaim_len += 1;
    };
    push_reclaim(allocs.boot_info_phys, 1, 0);
    push_reclaim(allocs.modules_phys, 1, 0);
    // MEM_MAP_ENTRY_PAGES and reclaim_len (bounded by MAX_RECLAIM_RANGES) are
    // both small compile-time constants well within u32 range.
    #[allow(clippy::cast_possible_truncation)]
    {
        push_reclaim(allocs.mem_entries_phys, MEM_MAP_ENTRY_PAGES as u32, 0);
    }
    push_reclaim(allocs.apertures_phys, 1, 0);
    for &frame in page_table.allocated_frames()
    {
        push_reclaim(frame, 1, 0);
    }
    // Bundle blob: emit reclaim ranges over every bundle page NOT
    // covered by a module Memory cap. Module bodies are 4 KiB-aligned
    // per `bundle::BODY_ALIGNMENT` (enforced by `bundle::parse_header`),
    // and `mods.modules[..mods.count]` arrives in ascending
    // `physical_base` because `xtask/src/bundle.rs::write_bundle` lays
    // bodies out at a monotonically-increasing aligned cursor and
    // `step4_parse_bundle` preserves header-entry order while filtering
    // `init` out. The gaps walked here cover the bundle header + entry
    // table + leading pad, the init ELF source body (no longer needed —
    // `load_init` copied segments out into separate allocations during
    // step 4), and any inter-module or trailing slack pages.
    //
    // Module-covered pages are accounted exclusively by
    // `cap::mint_module_memory_caps`; carving around them keeps the
    // `register_owned_range` ledger entries disjoint and avoids the
    // double-count / double-free trap that motivated PR #138 commit 6.
    let bundle_end = bundle.phys + (bundle.pages as u64) * 4096;
    let mut bundle_cursor = bundle.phys;
    for module in &mods.modules[..mods.count]
    {
        // Bundle bodies are 4 KiB-aligned per `bundle::BODY_ALIGNMENT`,
        // already enforced (release-mode) by `bundle::parse_header`'s
        // `EntryMisaligned` check. Only the cursor-ordering invariant
        // needs an explicit debug guard.
        let module_base = module.physical_base;
        let module_end = (module.physical_base + module.size + 0xFFF) & !0xFFF;
        debug_assert!(
            bundle_cursor <= module_base,
            "bundle modules not in ascending offset order",
        );
        if bundle_cursor < module_base
        {
            #[allow(clippy::cast_possible_truncation)]
            let gap_pages = ((module_base - bundle_cursor) / 4096) as u32;
            push_reclaim(bundle_cursor, gap_pages, 0);
        }
        bundle_cursor = module_end;
    }
    if bundle_cursor < bundle_end
    {
        #[allow(clippy::cast_possible_truncation)]
        let tail_pages = ((bundle_end - bundle_cursor) / 4096) as u32;
        push_reclaim(bundle_cursor, tail_pages, 0);
    }
    // AP SIPI trampoline page: kernel mints this through the late-reclaim
    // pass once SMP bringup completes and `mm::paging::unmap_identity_page`
    // has retired the low-VA identity mapping (installed on both arches by
    // the arch-neutral kernel page-table builder).
    if allocs.ap_trampoline_phys != 0
    {
        push_reclaim(allocs.ap_trampoline_phys, 1, RECLAIM_FLAG_LATE);
    }
    // The reclaim-array page itself is reclaim-safe once the kernel has
    // walked it — record it last so the kernel processes it in order.
    push_reclaim(allocs.reclaim_array_phys, 1, 0);
    bprintln!("[--------] boot: reclaim_ranges: {reclaim_len} entries recorded");

    // VMGENID GUID address: QEMU-specific SSDT scan (no AML evaluation).
    // Zero when absent; the kernel then has no snapshot-detection channel.
    // SAFETY: acpi_rsdp is zero or identity-mapped; the parser validates.
    let vmgenid_paddr = unsafe { acpi::parse_vmgenid_paddr(firm.acpi_rsdp) };
    if vmgenid_paddr != 0
    {
        bprintln!("[--------] boot: vmgenid guid at {vmgenid_paddr:#x}");
    }

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
                cpu_count: cpus.count.max(1),
                bsp_id: cpus.bsp_id,
                cpu_ids: cpus.cpu_ids,
                ap_trampoline_page: allocs.ap_trampoline_phys,
                reclaim_ranges: ReclaimSlice {
                    entries: allocs.reclaim_array_phys as *const ReclaimRange,
                    count: reclaim_len as u64,
                },
                boot_entropy_seed: boot_entropy.seed,
                boot_entropy_len: boot_entropy.len,
                vmgenid_paddr,
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
