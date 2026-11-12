// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/main.rs

//! Seraph UEFI bootloader — ten-step boot sequence orchestrator.
//!
//! Loads the kernel ELF and the bootstrap bundle (init plus boot modules) from
//! the ESP, establishes initial page tables with W^X enforcement, discovers
//! firmware table addresses, exits UEFI boot services, populates `BootInfo`,
//! and jumps to the kernel entry point. See `core/boot/docs/boot-flow.md` for the step-by-step design.

// Staged roll-out of these two lints: docs/coding-standards.md § Clippy.
#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

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

use crate::elf::{ElfKind, KernelInfo, load_init, load_kernel};
use crate::error::BootError;
use crate::firmware::{FirmwareInfo, discover_firmware};
use crate::paging::{PageTableBuilder, build_initial_tables};
use crate::uefi::{
    EFI_RNG_PROTOCOL_GUID, EFI_SUCCESS, EfiBootServices, EfiFileProtocol, EfiGuid, EfiHandle,
    EfiRngProtocol, EfiSystemTable, allocate_pages, connect_all_controllers, exit_boot_services,
    file_read, file_size, free_pages, get_loaded_image, get_memory_map, open_esp_volume, open_file,
    query_gop,
};
use boot_protocol::{
    BOOT_MODULE_NAME_LEN, BOOT_PROTOCOL_VERSION, BootInfo, BootModule, FramebufferInfo, InitImage,
    KernelMmio, MAX_RECLAIM_RANGES, MemoryMapEntry, MemoryMapSlice, MmioAperture,
    MmioApertureSlice, ModuleSlice, RECLAIM_FLAG_LATE, ReclaimRange, ReclaimSlice, bundle,
};

/// Maximum boot modules carried in [`BootInfo::modules`]: the ABI bound, the
/// `BootModule` entries the one-page module array holds. A bundle with more is
/// refused by name ([`BootError::InvalidBundle`]).
const MAX_MODULES: usize = boot_protocol::MAX_BOOT_MODULES;

/// `\EFI\seraph\kernel` as a NUL-terminated UTF-16 path for
/// `EFI_FILE_PROTOCOL.Open()`.
#[rustfmt::skip]
static KERNEL_PATH: [u16; 19] = [
    b'\\' as u16, b'E' as u16, b'F' as u16, b'I' as u16, b'\\' as u16,
    b's' as u16, b'e' as u16, b'r' as u16, b'a' as u16, b'p' as u16,
    b'h' as u16, b'\\' as u16, b'k' as u16, b'e' as u16, b'r' as u16,
    b'n' as u16, b'e' as u16, b'l' as u16, 0u16,
];

/// `\EFI\seraph\nokaslr` as a NUL-terminated UTF-16 path — the presence of
/// this file disables KASLR for deterministic debugging (staged by
/// `cargo xtask mkdisk --no-kaslr`).
#[rustfmt::skip]
static NOKASLR_PATH: [u16; 20] = [
    b'\\' as u16, b'E' as u16, b'F' as u16, b'I' as u16, b'\\' as u16,
    b's' as u16, b'e' as u16, b'r' as u16, b'a' as u16, b'p' as u16,
    b'h' as u16, b'\\' as u16, b'n' as u16, b'o' as u16, b'k' as u16,
    b'a' as u16, b's' as u16, b'l' as u16, b'r' as u16, 0u16,
];

/// `\EFI\seraph\mapredo` as a NUL-terminated UTF-16 path — the presence of
/// this file makes the first attempt of steps 6 and 7 redo whatever its
/// map's size, so a boot runs the redo path ([`MapRedo`]; staged by
/// `cargo xtask test-map-redo`).
#[rustfmt::skip]
static MAPREDO_PATH: [u16; 20] = [
    b'\\' as u16, b'E' as u16, b'F' as u16, b'I' as u16, b'\\' as u16,
    b's' as u16, b'e' as u16, b'r' as u16, b'a' as u16, b'p' as u16,
    b'h' as u16, b'\\' as u16, b'm' as u16, b'a' as u16, b'p' as u16,
    b'r' as u16, b'e' as u16, b'd' as u16, b'o' as u16, 0u16,
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

/// Number of 4 KiB pages allocated for the kernel's handoff stack: the shared
/// `HANDOFF_STACK_BYTES`, which the kernel's Phase 3 identity window over the
/// stack is derived from too.
const KERNEL_STACK_PAGES: usize = boot_protocol::layout::HANDOFF_STACK_BYTES / 4096;

/// Number of 4 KiB pages allocated for the handoff stack and its guard: the
/// [`KERNEL_STACK_PAGES`] of stack above one guard page, which the boot page
/// tables leave unmapped so an overflow of the stack faults instead of
/// overwriting another allocation ([`handoff_stack_span`]).
const HANDOFF_STACK_ALLOC_PAGES: usize = KERNEL_STACK_PAGES + 1;

/// 64-bit words in the handoff stack ([`KERNEL_STACK_PAGES`] pages).
const KERNEL_STACK_WORDS: usize = (KERNEL_STACK_PAGES * 4096) / core::mem::size_of::<u64>();

/// Descriptors of growth the translated `MemoryMapEntry` array allows for
/// above the firmware's descriptor count, which step 6 reads before its first
/// allocation; the array then holds every descriptor the buffer step 7
/// allocates for a map that large could ever hold
/// ([`uefi::map_buffer_descriptor_reach`]). Each allocation after the count
/// (the ten of steps 6 and 7: the `BootInfo`, module, entry, aperture, two
/// seed and reclaim pages, the stack, the page-table pool, and the raw map
/// buffer) adds at most two descriptors, 20 in all; the other 12 absorb the
/// firmware's own housekeeping allocations in that window, which no count
/// bounds. Its overflow costs only another round: a final map (step 7) whose
/// buffer reaches past the array makes the bootloader free steps 6 and 7 and
/// redo them with twice the slack, up to [`MEM_MAP_ATTEMPTS`] times.
const MEM_MAP_SLACK_ENTRIES: usize = 32;

/// Times steps 6 and 7 run before the bootloader gives up on a memory map
/// that keeps outgrowing the entry array sized for it, the slack doubling each
/// time ([`BootError::MemoryMapKeptGrowing`]). It bounds no capacity: it is a
/// retry guard against firmware that never stops allocating, as
/// `uefi::EXIT_BOOT_SERVICES_MAX_ATTEMPTS` is. A redo frees the first
/// attempt's allocations before it counts again, so its count includes what
/// the firmware itself allocated during the first window; a third attempt is
/// reached only by firmware that outgrows twice that slack in the second.
const MEM_MAP_ATTEMPTS: usize = 3;

/// Maximum number of physical regions tracked for identity mapping.
/// Covers kernel segments, all fixed allocations, and the framebuffer.
///
/// Provably sufficient: `collect_identity_regions` pushes a fixed set of at
/// most `MAX_LOAD_SEGMENTS + INIT_MAX_SEGMENTS + 10` = 26 regions.
const MAX_IDENTITY_REGIONS: usize = 64;

/// Most entries step 9 records in `BootInfo.reclaim_ranges`: the `BootInfo`,
/// module, memory-map entry, aperture, named-seed, heuristic-seed, CPU-id and
/// reclaim-array pages, the raw map buffer, the page-table pool, the x86-64
/// LA57 toggle page and the AP trampoline page (twelve), and one bundle gap
/// before, between and after the at most [`MAX_MODULES`] module bodies.
const MAX_RECLAIM_ENTRIES: usize = 12 + MAX_MODULES + 1;

// The reclaim array's page holds every entry step 9 can record, so the
// overflow halt in step 9 is unreachable.
const _: () = assert!(MAX_RECLAIM_ENTRIES <= MAX_RECLAIM_RANGES);

// The bundle entry name is copied straight into `BootModule.name` (step 4), so
// the two widths are one ABI fact.
const _: () = assert!(bundle::ENTRY_NAME_LEN == BOOT_MODULE_NAME_LEN);

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

/// Kernel ELF load result. The file read buffer is released inside
/// [`step3_load_kernel`] once `load_kernel` has copied the segments out, so
/// only the parsed info outlives step 3.
struct KernelLoad
{
    info: KernelInfo,
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
    /// Physical address of the per-CPU hardware identifiers, `count` `u32`s
    /// with `[0] == bsp_id`, in pages of their own (`BootInfo.cpu_ids`).
    ids_phys: u64,
    /// Pages of the allocation at `ids_phys`, recorded as a reclaim range.
    ids_pages: usize,
}

/// Conditioned early-boot entropy drawn from UEFI `EFI_RNG_PROTOCOL` or, as a
/// fallback, from the DTB `/chosen/rng-seed` property.
///
/// `len` is `0` when no source produced a seed; the kernel then seeds from its
/// remaining sources (see `core/kernel/docs/entropy.md`). Produced by
/// [`step5c_fetch_boot_entropy`] while boot services are live and written into
/// [`BootInfo`] by step 9. The `kaslr` words are a separate draw feeding the
/// KASLR slide / direct-map base (#252); `kaslr_available` is false when no RNG
/// source produced them.
struct BootEntropy
{
    /// Random bytes for the entropy pool; only the first `len` are valid.
    seed: [u8; 32],
    /// Number of valid leading bytes in `seed` (`0..=32`: 32 from the firmware
    /// RNG, fewer from the DTB fallback).
    len: u32,
    /// Two 64-bit KASLR entropy words: `[0]` picks the image slide, `[1]`
    /// the direct-map base. Valid only when `kaslr_available`.
    kaslr: [u64; 2],
    /// Whether `kaslr` carries a real random draw.
    kaslr_available: bool,
    /// KASLR flag identifying the entropy source (0, or a `KASLR_ENTROPY_*`
    /// bit); merged into `BootInfo::kaslr_flags`.
    kaslr_source_flag: u32,
}

impl BootEntropy
{
    /// No seed and no KASLR draw.
    const NONE: Self = Self {
        seed: [0u8; 32],
        len: 0,
        kaslr: [0u64; 2],
        kaslr_available: false,
        kaslr_source_flag: 0,
    };
}

/// Whether the `\EFI\seraph\nokaslr` override knob is present on the ESP.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KaslrOverride
{
    /// No knob: the layout follows the entropy draw.
    Absent,
    /// The knob is present: both layout dimensions stay deterministic.
    DisabledByKnob,
}

/// Whether the `\EFI\seraph\mapredo` test knob is present on the ESP.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MapRedo
{
    /// No knob: an attempt of steps 6 and 7 stands when its map fits.
    Absent,
    /// The knob is present: the first attempt is redone even when its map
    /// fits, so the boot runs the redo path.
    ForcedByKnob,
}

/// The KASLR layout the bootloader chose, threaded from
/// [`step5d_apply_kaslr_slide`] (which biases the kernel image) to
/// [`step9_populate_boot_info`] (which selects the direct-map base and
/// writes both into [`BootInfo`]).
struct KaslrDecision
{
    /// Entropy word reserved for the direct-map base selection in step 9.
    dm_rand: u64,
    /// Whether step 9 should attempt to randomize the direct-map base.
    randomize_dm: bool,
    /// Flags accumulated so far (image + source + knob bits); step 9 ORs in
    /// the direct-map bits.
    flags: u32,
}

/// All pre-`ExitBootServices` physical allocations the boot sequence
/// produces, gathered by [`step6_allocate_and_build_page_tables`].
struct BootAllocations
{
    boot_info_phys: u64,
    modules_phys: u64,
    mem_entries_phys: u64,
    /// Pages of the `MemoryMapEntry` array at `mem_entries_phys`, sized at
    /// step 6 to the reach of the map buffer for the firmware's descriptor
    /// count plus the attempt's slack ([`MEM_MAP_SLACK_ENTRIES`], doubled on
    /// each redo).
    mem_entries_pages: usize,
    apertures_phys: u64,
    /// Apertures the array at `apertures_phys` holds
    /// (`memory_map::aperture_capacity`).
    aperture_capacity: usize,
    /// Pages of the array at `apertures_phys`.
    apertures_pages: usize,
    stack_phys: u64,
    stack_top: u64,
    ap_trampoline_phys: u64,
    /// Physical address of the dedicated 4 KiB page that backs
    /// `BootInfo.reclaim_ranges`. The bootloader allocates this page in
    /// step 6, populates the `ReclaimRange` array in step 9, and records
    /// the page itself as a reclaim entry so the kernel reclaims it last.
    reclaim_array_phys: u64,
    /// The CPU-id pages step 5 allocated (`BootInfo.cpu_ids`), carried here
    /// so step 6 identity-maps them.
    cpu_ids_phys: u64,
    /// Pages of the array at `cpu_ids_phys`.
    cpu_ids_pages: usize,
    /// The named aperture-seed buffer (`MmioAperture`s), sized at step 6 from
    /// the ACPI and DTB seeders' count pass and the framebuffer; filled at
    /// step 9.
    seeds_phys: u64,
    /// Seeds the buffer at `seeds_phys` holds.
    seeds_capacity: usize,
    /// Pages of the buffer at `seeds_phys`.
    seeds_pages: usize,
    /// The heuristic-window seed buffer, sized as the named one is.
    heuristic_phys: u64,
    /// Seeds the buffer at `heuristic_phys` holds.
    heuristic_capacity: usize,
    /// Pages of the buffer at `heuristic_phys`.
    heuristic_pages: usize,
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// UEFI application entry point.
///
/// On x86-64 UEFI firmware calls this function after loading and relocating
/// the bootloader image; on RISC-V the `_start` trampoline in
/// `core/boot/src/arch/riscv64/header.S` applies the image's relocations and
/// tail-calls it (see `core/boot/docs/riscv-uefi-boot.md`). Delegates
/// immediately to [`boot_sequence`] and prints a fatal error message before
/// halting if the sequence fails.
///
/// Returns a `usize` (UEFI `EFI_STATUS`) to satisfy the UEFI ABI, but in
/// practice never returns — the boot sequence either jumps to the kernel or
/// halts on error.
// UEFI entry point — must be a public non-unsafe `extern "efiapi"` function per the UEFI spec;
// the raw-pointer parameters are the firmware-supplied image handle and system table, trusted
// per the UEFI calling contract and passed only to the unsafe callees below.
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
    let cpus = unsafe { step5_discover_cpu_topology(&ctx, &firm)? };
    // Negotiate the paging mode before step 6 fixes the table hierarchy depth
    // and step 10 installs it: Sv39/Sv48/Sv57 on riscv64, 4- or 5-level on
    // x86-64, where a depth other than the firmware's also reserves the LA57
    // toggle page.
    // SAFETY: ctx.bs valid pre-exit; firm.device_tree is zero or an
    // identity-mapped FDT; the probe masks SIE and restores the live satp.
    unsafe { arch::current::negotiate_paging(ctx.bs, firm.device_tree, cpus.boot_hart_id)? };
    // SAFETY: ctx.bs valid pre-exit.
    let ap_trampoline_phys = unsafe { step5b_alloc_ap_trampoline(&ctx) };
    let mut boot_entropy = BootEntropy::NONE;
    // SAFETY: ctx.bs valid pre-exit; draws the boot entropy seed while boot
    // services (and thus EFI_RNG_PROTOCOL) are still available; firm.device_tree
    // is zero or an identity-mapped, writable (pre-ExitBootServices) FDT for the
    // DTB rng-seed fallback's in-place scrub.
    unsafe { step5c_fetch_boot_entropy(&ctx, &firm, &mut boot_entropy) };
    // Apply the KASLR slide before step 6 maps the segments at their
    // (biased) virtual addresses.
    // SAFETY: kernel.info comes from load_kernel with its span allocation
    // live and identity-mapped; virtual addresses are still unbiased link VAs;
    // ctx.esp_root is valid until ExitBootServices.
    let mut kaslr = unsafe { step5d_apply_kaslr_slide(&ctx, &mut kernel.info, &boot_entropy)? };
    // SAFETY: all prior unsafe outputs remain valid; ctx.esp_root is valid
    // until ExitBootServices; steps 6 and 7 allocate via bs, and step 7 is the
    // last pre-exit allocation.
    let (allocs, mut page_table, mut uefi_map) = unsafe {
        steps6_and_7_sized_to_the_map(
            &ctx,
            &bundle_load,
            &kernel,
            &init,
            &cpus,
            &firm,
            ap_trampoline_phys,
        )?
    };
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
            &kaslr,
            &ctx.framebuffer,
            &allocs,
            &uefi_map,
            &page_table,
        )?;
    }
    // Scrub the bootloader's own copies of the KASLR entropy words
    // (`boot_entropy.kaslr`, and the `kaslr.dm_rand` copy step 9 consumed) and
    // of the pool seed; the BootInfo copy is the kernel's to scrub, and step 5c
    // scrubs its own byte buffers. The kernel zeroes the whole UEFI stack (free
    // RAM it drains at Phase 7) and every reclaim range before init runs
    // (core/kernel/docs/cross-boundary-disclosure.md § Kernel state in donated
    // memory); these local scrubs keep the secrets from outliving their last
    // bootloader consumer.
    scrub(&mut boot_entropy.seed);
    // SAFETY: all are live locals; volatile so the stores are not elided as
    // dead ahead of the values going out of scope.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(boot_entropy.kaslr), [0u64; 2]);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(boot_entropy.len), 0u32);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(kaslr.dm_rand), 0u64);
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
    // The read buffer is dead: load_kernel copied every segment and the
    // relocation table into the image span. Zero it, so the kernel file
    // bytes do not reach the memory the kernel hands out, then return it to
    // the firmware; a refused free only leaves it allocated.
    kernel_buf.fill(0);
    // SAFETY: bs is valid pre-exit; buf_phys/buf_pages is the allocation made
    // above, and kernel_buf, its only view, is not used again.
    if unsafe { free_pages(ctx.bs, buf_phys, buf_pages) }.is_err()
    {
        bprintln!("[--------] boot: kernel ELF read buffer not freed; it stays allocated");
    }

    bprintln!(
        "[--------] boot: kernel base={:#018x}  entry={:#018x}  size={:#018x} bytes",
        info.physical_base,
        info.entry_virtual,
        info.size
    );

    Ok(KernelLoad { info })
}

// ── Step 4: Parse bundle, pre-parse init ELF, collect modules ────────────────

/// The `len` bytes of `bytes` from `start`, or `None` when the body ends past
/// the end of `bytes` or its end overflows `usize`.
fn bundle_body(bytes: &[u8], start: usize, len: usize) -> Option<&[u8]>
{
    bytes.get(start..start.checked_add(len)?)
}

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
        let Some(entry) = bundle::entry_at(bytes, i)
        else
        {
            return Err(BootError::InvalidBundle("bundle truncated"));
        };
        let name = bundle::name_str(&entry.name);
        // usize is 64-bit on every UEFI target Seraph supports; parse_header
        // already bounds-checked offset+size against `bytes.len()`.
        #[allow(clippy::cast_possible_truncation)]
        let body_start = entry.offset as usize;
        // usize is 64-bit on every UEFI target Seraph supports, so the size cast is exact.
        #[allow(clippy::cast_possible_truncation)]
        let body_len = entry.size as usize;
        let Some(body) = bundle_body(bytes, body_start, body_len)
        else
        {
            return Err(BootError::InvalidBundle("bundle body past file end"));
        };

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
            let Some(slot) = modules.get_mut(count)
            else
            {
                return Err(BootError::InvalidBundle(
                    "bundle exceeds MAX_MODULES entries",
                ));
            };
            let Some(physical_base) = bundle_load.phys.checked_add(entry.offset)
            else
            {
                return Err(BootError::InvalidBundle("bundle body past file end"));
            };
            *slot = BootModule {
                name: entry.name,
                // Bundle bodies are page-aligned (per `bundle::BODY_ALIGNMENT`),
                // so this physical base is a valid 4 KiB-aligned address inside
                // the bundle UEFI allocation.
                physical_base,
                size: entry.size,
            };
            // `count` indexed a slot of `modules`, so it is far below `usize::MAX`.
            count = count.saturating_add(1);
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
/// Each source is walked twice: once to count its enabled CPU entries, which
/// sizes the `cpu_ids` allocation (`firmware::cpu_id_capacity`), and once to
/// fill it.
///
/// # Errors
/// [`BootError::OutOfMemory`] when the `cpu_ids` pages cannot be allocated.
///
/// # Safety
/// `ctx.st` and `ctx.bs` must be valid. `firm.acpi_rsdp` / `firm.device_tree`
/// must be zero or the physical address of an identity-mapped table.
unsafe fn step5_discover_cpu_topology(
    ctx: &UefiContext,
    firm: &FirmwareInfo,
) -> Result<CpuTopology, BootError>
{
    // SAFETY: ctx.st is valid.
    let boot_hart_id = unsafe { arch::current::discover_boot_hart_id(ctx.st) };
    // BSP hardware ID: APIC ID on x86-64 (CPUID), boot hart ID on RISC-V.
    let bsp_id: u32 = arch::current::bsp_hardware_id(boot_hart_id);

    // Primary: ACPI MADT (works on both x86-64 and RISC-V UEFI).
    // Fallback on RISC-V: DTB /cpus if ACPI is absent.
    if firm.acpi_rsdp != 0
    {
        // SAFETY: acpi_rsdp is identity-mapped; the walk validates the tables.
        let capacity = unsafe { acpi::cpu_topology_capacity(firm.acpi_rsdp) };
        // SAFETY: bs is valid.
        let (ids, ids_phys, ids_pages) = unsafe { allocate_cpu_ids(ctx.bs, capacity)? };
        // SAFETY: as above.
        let count = unsafe { acpi::parse_cpu_topology(firm.acpi_rsdp, bsp_id, ids) };
        bprintln!("[--------] boot: ACPI: {count} CPU(s) found via MADT");
        return Ok(CpuTopology {
            boot_hart_id,
            bsp_id,
            count,
            ids_phys,
            ids_pages,
        });
    }
    let entries = if firm.device_tree != 0
    {
        // SAFETY: device_tree is identity-mapped; parse_cpu_count validates the FDT.
        unsafe { dtb::parse_cpu_count(firm.device_tree) }
    }
    else
    {
        0
    };
    // SAFETY: bs is valid.
    let (ids, ids_phys, ids_pages) =
        unsafe { allocate_cpu_ids(ctx.bs, firmware::cpu_id_capacity(entries))? };
    let count = if entries > 0
    {
        // SAFETY: device_tree is identity-mapped; the walk validates the FDT.
        let count = unsafe { dtb::place_hart_ids(firm.device_tree, bsp_id, ids) };
        bprintln!("[--------] boot: DTB: {count} hart(s) found");
        count
    }
    else
    {
        if firm.device_tree != 0
        {
            bprintln!("[--------] boot: DTB: no CPU nodes found, defaulting to 1");
        }
        else
        {
            bprintln!("[--------] boot: CPU topology: no firmware tables, defaulting to 1");
        }
        // `allocate_cpu_ids` returns at least one slot.
        if let Some(slot) = ids.first_mut()
        {
            *slot = bsp_id;
        }
        1
    };
    Ok(CpuTopology {
        boot_hart_id,
        bsp_id,
        count,
        ids_phys,
        ids_pages,
    })
}

/// Allocate the zeroed pages for `capacity` CPU hardware IDs
/// (`BootInfo.cpu_ids`). Returns the array, its physical address, and its
/// page count.
///
/// # Errors
/// [`BootError::OutOfMemory`] when `AllocatePages` fails.
///
/// # Safety
/// `bs` must be valid boot services (before `ExitBootServices`).
unsafe fn allocate_cpu_ids(
    bs: *mut uefi::EfiBootServices,
    capacity: usize,
) -> Result<(&'static mut [u32], u64, usize), BootError>
{
    let bytes = capacity
        .max(1)
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or(BootError::OutOfMemory)?;
    let pages = bytes.div_ceil(4096);
    // SAFETY: bs is valid.
    let phys = unsafe { allocate_pages(bs, pages)? };
    // SAFETY: allocate_pages returned `pages` identity-mapped pages this
    // allocation owns and nothing else references; they hold `capacity` u32s,
    // zeroed before the slice is formed.
    let ids = unsafe {
        // `pages` came from `bytes`, which fit in `usize`, so the page span below
        // stays within the allocation.
        core::ptr::write_bytes(phys as *mut u8, 0, pages.saturating_mul(4096));
        core::slice::from_raw_parts_mut(phys as *mut u32, capacity.max(1))
    };
    Ok((ids, phys, pages))
}

// ── Step 5b: AP trampoline allocation ────────────────────────────────────────

/// Reserve a 4 KiB page for the AP startup trampoline. Returns 0 if the
/// allocation fails (the consequence is in `core/boot/docs/boot-flow.md`
/// § Step 5b); arch-specific placement constraints are enforced inside
/// `arch::current::allocate_ap_trampoline`.
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
        bprintln!(
            "[--------] boot: WARNING: cannot allocate AP trampoline page; the kernel halts \
             at Phase 8 if more than one CPU is listed"
        );
        0
    }
}

// ── Step 5c: boot entropy seed ───────────────────────────────────────────────

/// Draw conditioned early-boot entropy for the pool seed and the KASLR
/// slide / direct-map base into `out`, which the caller owns zeroed and
/// scrubs; the seed and the KASLR words are written straight into it, so this
/// frame holds only the byte buffers it scrubs itself.
///
/// Draws the pool seed from UEFI `EFI_RNG_PROTOCOL` when the firmware exposes
/// it and the draw succeeds; a failed KASLR draw after a successful pool draw
/// leaves `len == 32` with `kaslr_available == false`. Otherwise draws from
/// the DTB `/chosen/rng-seed` reader ([`dtb::parse_rng_seed`]); otherwise
/// leaves `len == 0` and `kaslr_available == false`, and the kernel seeds the
/// pool from its remaining sources and the layout is deterministic (no
/// regression). Which firmware exposes which source is documented in
/// `core/boot/docs/boot-flow.md`.
///
/// # Safety
/// `ctx.bs` must be valid UEFI boot services (before `ExitBootServices`);
/// `firm.device_tree` must be 0 or an identity-mapped writable FDT.
unsafe fn step5c_fetch_boot_entropy(ctx: &UefiContext, firm: &FirmwareInfo, out: &mut BootEntropy)
{
    let mut iface: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: ctx.bs is valid; locate_protocol fills iface on success.
    let status = unsafe {
        ((*ctx.bs).locate_protocol)(
            core::ptr::addr_of!(EFI_RNG_PROTOCOL_GUID),
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(iface),
        )
    };
    if status == EFI_SUCCESS && !iface.is_null()
    {
        let proto = iface.cast::<EfiRngProtocol>();
        // SAFETY: proto is a valid protocol pointer from LocateProtocol; a
        // null algorithm selects the default; out.seed has room for 32 bytes.
        // GetRNG returns EFI_SUCCESS only after writing all requested bytes.
        let s = unsafe {
            ((*proto).get_rng)(
                proto,
                core::ptr::null::<EfiGuid>(),
                out.seed.len(),
                out.seed.as_mut_ptr(),
            )
        };
        if s == EFI_SUCCESS
        {
            out.len = 32;
            // Independent 16-byte KASLR draw, kept separate from the pool
            // seed so neither reveals the other.
            let mut kaslr_bytes = [0u8; 16];
            // SAFETY: proto valid; null algorithm; 16-byte buffer.
            let ks = unsafe {
                ((*proto).get_rng)(
                    proto,
                    core::ptr::null::<EfiGuid>(),
                    kaslr_bytes.len(),
                    kaslr_bytes.as_mut_ptr(),
                )
            };
            if ks == EFI_SUCCESS
            {
                out.kaslr = kaslr_words(&kaslr_bytes);
                out.kaslr_available = true;
                out.kaslr_source_flag = boot_protocol::KASLR_ENTROPY_FW_RNG;
            }
            scrub(&mut kaslr_bytes);
            return;
        }
        // Partial/failed draw: discard and fall through to the DTB source.
        scrub(&mut out.seed);
    }

    // DTB fallback: the firmware-delivered /chosen/rng-seed. One draw
    // serves both consumers: the first 16 bytes seed KASLR, the remainder
    // seeds the entropy pool (non-overlapping so the pool seed never
    // reveals the KASLR words).
    let mut dtb_seed = [0u8; 32];
    // SAFETY: firm.device_tree is 0 or an identity-mapped writable FDT.
    let n = unsafe { dtb::parse_rng_seed(firm.device_tree, &mut dtb_seed) };
    // n ≤ 32 (dtb_seed length), so `drawn` is the first n bytes and every cast
    // below is exact.
    let drawn = dtb_seed.get(..n).unwrap_or_default();
    let split = drawn.split_at_checked(16).filter(|_| drawn.len() >= 24);
    #[allow(clippy::cast_possible_truncation)]
    if let Some((key, pool)) = split
    {
        let mut kb = [0u8; 16];
        kb.copy_from_slice(key);
        out.kaslr = kaslr_words(&kb);
        scrub(&mut kb);
        out.kaslr_available = true;
        out.kaslr_source_flag = boot_protocol::KASLR_ENTROPY_DTB_SEED;
        // The pool part is at most 16 bytes, which `out.seed` holds.
        if let Some(dst) = out.seed.get_mut(..pool.len())
        {
            dst.copy_from_slice(pool);
            out.len = pool.len() as u32;
        }
    }
    else if !drawn.is_empty()
    {
        // Too short to split: feed the whole draw to the pool; KASLR uses
        // its deterministic fallback.
        if let Some(dst) = out.seed.get_mut(..drawn.len())
        {
            dst.copy_from_slice(drawn);
            out.len = drawn.len() as u32;
        }
    }
    // No source at all leaves `out` as the caller zeroed it.
    scrub(&mut dtb_seed);
}

/// Pack 16 little-endian bytes into two KASLR entropy words; no named
/// intermediate buffer.
fn kaslr_words(bytes: &[u8; 16]) -> [u64; 2]
{
    let (chunks, _) = bytes.as_chunks::<8>();
    // 16 bytes are exactly two chunks of 8.
    let [lo, hi] = chunks
    else
    {
        return [0u64; 2];
    };
    [u64::from_le_bytes(*lo), u64::from_le_bytes(*hi)]
}

/// Zero a secret that is never read again. Volatile so the stores survive
/// dead-store elimination; a plain `fill(0)` on a dying local may be dropped.
fn scrub(bytes: &mut [u8])
{
    for b in bytes
    {
        // SAFETY: `b` is a valid exclusive reference into the caller's array.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

// ── Step 5d: KASLR slide ─────────────────────────────────────────────────────

/// Choose and apply the kernel's KASLR image slide, biasing the loaded image
/// before step 6 maps its segments; return the [`KaslrDecision`] step 9 needs
/// to pick the matching direct-map base.
///
/// The decision is [`choose_kaslr_layout`]'s: the slide comes from the
/// bootloader's KASLR entropy draw and is forced to 0 — the deterministic
/// layout — when no entropy was available or when the `\EFI\seraph\nokaslr`
/// override knob is present, and an `ET_EXEC` kernel is pinned to slide 0
/// while the direct-map base is still randomized. For a PIE, relocations are
/// applied even at slide 0, so the mapped image never depends on lld having
/// pre-filled the RELATIVE targets.
///
/// # Safety
/// `ctx.esp_root` must be valid; `info` must come from `load_kernel` with its
/// span allocation live and identity-mapped, and must not have been relocated
/// already.
unsafe fn step5d_apply_kaslr_slide(
    ctx: &UefiContext,
    info: &mut KernelInfo,
    entropy: &BootEntropy,
) -> Result<KaslrDecision, BootError>
{
    // SAFETY: ctx.esp_root is a valid ESP root directory handle per the
    // caller's contract.
    let knob = unsafe { nokaslr_override(ctx) };
    let (slide, decision) = choose_kaslr_layout(knob, entropy, info.kind, info.size);

    // SAFETY: forwarded from the caller's contract; slide is a valid 2 MiB
    // multiple within the image window.
    unsafe { elf::relocate_kernel(info, slide, arch::current::EXPECTED_ELF_MACHINE)? };

    Ok(decision)
}

/// Choose the image slide and the direct-map decision from the override knob,
/// the entropy draw, and the image kind. Pure, so the outcomes are host-tested.
fn choose_kaslr_layout(
    knob: KaslrOverride,
    entropy: &BootEntropy,
    kind: ElfKind,
    image_size: u64,
) -> (u64, KaslrDecision)
{
    let (slide, dm_rand, randomize_dm, flags) = if knob == KaslrOverride::DisabledByKnob
    {
        (0u64, 0u64, false, boot_protocol::KASLR_DISABLED_BY_KNOB)
    }
    else if entropy.kaslr_available
    {
        // A PIE takes the drawn slide (KASLR_IMAGE_RANDOMIZED marks the draw,
        // whichever slot it selected); an ET_EXEC kernel cannot slide
        // (core/boot/docs/elf-loading.md § ELF Validation) and stays at the link base with
        // only the source bits set.
        let (slide, image_flag) = match kind
        {
            ElfKind::Dyn => (
                boot_protocol::layout::image_slide(entropy.kaslr[0], image_size),
                boot_protocol::KASLR_IMAGE_RANDOMIZED,
            ),
            ElfKind::Exec => (0, 0),
        };
        (
            slide,
            entropy.kaslr[1],
            true,
            entropy.kaslr_source_flag | image_flag,
        )
    }
    else
    {
        // No boot entropy: the defined fallback — deterministic layout.
        (0u64, 0u64, false, 0)
    };
    (
        slide,
        KaslrDecision {
            dm_rand,
            randomize_dm,
            flags,
        },
    )
}

/// Whether the `\EFI\seraph\nokaslr` override knob file exists on the ESP.
///
/// # Safety
/// `ctx.esp_root` must be a valid ESP root directory handle.
unsafe fn nokaslr_override(ctx: &UefiContext) -> KaslrOverride
{
    // SAFETY: caller contract; the path is NUL-terminated UTF-16.
    if unsafe { knob_present(ctx, &NOKASLR_PATH, "\\EFI\\seraph\\nokaslr") }
    {
        KaslrOverride::DisabledByKnob
    }
    else
    {
        KaslrOverride::Absent
    }
}

/// Whether the presence-only knob file at `path` (NUL-terminated UTF-16,
/// named `name` in logs) exists on the ESP. A failed open reads as an absent
/// knob; the handle of a successful one is closed at once.
///
/// # Safety
/// `ctx.esp_root` must be a valid ESP root directory handle and `path` must
/// end in a NUL.
unsafe fn knob_present(ctx: &UefiContext, path: &[u16], name: &'static str) -> bool
{
    // SAFETY: esp_root is a valid directory handle; path is NUL-terminated UTF-16.
    match unsafe { open_file(ctx.esp_root, path.as_ptr(), name) }
    {
        Ok(file) =>
        {
            // SAFETY: file is a valid open handle from open_file.
            unsafe {
                ((*file).close)(file);
            }
            true
        }
        Err(_) => false,
    }
}

// ── Step 6: Allocate boot structures and build page tables ──────────────────

/// Allocate the fixed pre-exit scratch pages (`BootInfo` page, modules
/// descriptor page, memory-map entry pages, the named and heuristic
/// aperture-seed buffers, aperture pages, stack, reclaim-ranges page),
/// accumulate the identity-map region list (those pages
/// and step 5's CPU-id pages, `cpus`, among others), build initial page
/// tables, and install the handoff-trampoline mapping.
///
/// # Safety
/// `ctx.bs` must be valid pre-exit; all addresses in `kernel` and `init` must
/// come from their respective `step3`/`step4*` outputs.
// too_many_arguments: step 6 sizes its allocations from every earlier step's
// output (the bundle, kernel and init loads, the CPU topology, the firmware
// tables for the seed counts), plus the retry's slack.
#[allow(clippy::too_many_arguments)]
unsafe fn step6_allocate_and_build_page_tables(
    ctx: &UefiContext,
    bundle: &BundleLoad,
    kernel: &KernelLoad,
    init: &InitLoad,
    cpus: &CpuTopology,
    firm: &FirmwareInfo,
    ap_trampoline_phys: u64,
    slack: usize,
) -> Result<(BootAllocations, arch::current::BootPageTable), BootError>
{
    // The memory map's descriptor count and stride, read before this step's
    // first allocation. The entry array holds every descriptor the buffer
    // step 7 allocates could hold, for a map `slack` descriptors larger
    // (MEM_MAP_SLACK_ENTRIES on the first attempt; its doc gives the budget).
    // SAFETY: bs is valid; the size query allocates nothing.
    let (firmware_descriptors, stride) = unsafe { uefi::memory_map_shape(ctx.bs)? };
    let mem_entries_pages = entry_array_pages(firmware_descriptors, slack, stride);
    // BootInfo: one page — holds the BootInfo struct populated in step 9.
    // SAFETY: bs is valid.
    let boot_info_phys = unsafe { allocate_pages(ctx.bs, 1)? };
    // Module array: one page — BootInfo.modules descriptor array.
    // SAFETY: bs is valid.
    let modules_phys = unsafe { allocate_pages(ctx.bs, 1)? };
    // MemoryMapEntry output array.
    // SAFETY: bs is valid.
    let mem_entries_phys = unsafe { allocate_pages(ctx.bs, mem_entries_pages)? };
    // Aperture seed buffers, sized by the seeders' count pass over the same
    // firmware tables step 9 reads (one more named seed for the framebuffer).
    // SAFETY: acpi_rsdp and device_tree are zero or identity-mapped firmware
    // tables; the seeders validate them.
    let (acpi_named, heuristic_capacity) = unsafe { acpi::count_aperture_seed(firm.acpi_rsdp) };
    // SAFETY: as above.
    let dtb_named = unsafe { dtb::count_aperture_seed(firm.device_tree) };
    // A count too large to size saturates, and the allocation below then fails.
    let seeds_capacity = acpi_named
        .saturating_add(dtb_named)
        .saturating_add(usize::from(ctx.framebuffer.physical_base != 0));
    let seed_bytes = core::mem::size_of::<MmioAperture>();
    let seeds_pages = seeds_capacity
        .saturating_mul(seed_bytes)
        .div_ceil(4096)
        .max(1);
    // SAFETY: bs is valid.
    let seeds_phys = unsafe { allocate_pages(ctx.bs, seeds_pages)? };
    let heuristic_pages = heuristic_capacity
        .saturating_mul(seed_bytes)
        .div_ceil(4096)
        .max(1);
    // SAFETY: bs is valid.
    let heuristic_phys = unsafe { allocate_pages(ctx.bs, heuristic_pages)? };
    // MMIO aperture array, sized from the entry array's capacity (the bound
    // step 7 checks the map buffer against) and the seed counts
    // (memory_map::aperture_capacity).
    let aperture_capacity = aperture_array_capacity(
        mem_entries_pages,
        seeds_capacity.saturating_add(heuristic_capacity),
    );
    let apertures_pages = aperture_capacity
        .saturating_mul(core::mem::size_of::<MmioAperture>())
        .div_ceil(4096);
    // SAFETY: bs is valid.
    let apertures_phys = unsafe { allocate_pages(ctx.bs, apertures_pages)? };
    // Kernel handoff stack, above its guard page.
    // SAFETY: bs is valid.
    let stack_alloc_phys = unsafe { allocate_pages(ctx.bs, HANDOFF_STACK_ALLOC_PAGES)? };
    let (stack_phys, stack_top) = handoff_stack_span(stack_alloc_phys);
    // Paint the stack and mark its lowest word for the kernel's depth report
    // (core/boot/docs/boot-flow.md § Step 6; the kernel derives the span from
    // this page-aligned top).
    // SAFETY: allocate_pages returned HANDOFF_STACK_ALLOC_PAGES identity-mapped,
    // page-aligned pages owned by this allocation, and [stack_phys, stack_top)
    // is the KERNEL_STACK_PAGES of them above the guard; nothing uses them yet.
    unsafe {
        let p = stack_phys as *mut u64;
        for i in 1..KERNEL_STACK_WORDS
        {
            p.add(i).write(boot_protocol::layout::STACK_PAINT);
        }
        p.write(boot_protocol::layout::HANDOFF_STACK_BASE_MARK);
    }
    // Reclaim-array page: dedicated 4 KiB backing for BootInfo.reclaim_ranges.
    // SAFETY: bs is valid.
    let reclaim_array_phys = unsafe { allocate_pages(ctx.bs, 1)? };

    let allocs = BootAllocations {
        boot_info_phys,
        modules_phys,
        mem_entries_phys,
        mem_entries_pages,
        apertures_phys,
        aperture_capacity,
        apertures_pages,
        stack_phys,
        stack_top,
        ap_trampoline_phys,
        reclaim_array_phys,
        cpu_ids_phys: cpus.ids_phys,
        cpu_ids_pages: cpus.ids_pages,
        seeds_phys,
        seeds_capacity,
        seeds_pages,
        heuristic_phys,
        heuristic_capacity,
        heuristic_pages,
    };

    let mut identity_regions: [(u64, u64); MAX_IDENTITY_REGIONS] =
        [(0u64, 0u64); MAX_IDENTITY_REGIONS];
    let region_count = collect_identity_regions(
        &allocs,
        bundle,
        kernel,
        init,
        &ctx.framebuffer,
        arch::current::uart_mmio_region(),
        &mut identity_regions,
    );

    // `collect_identity_regions` returns at most `MAX_IDENTITY_REGIONS`.
    let identity_regions_filled = identity_regions
        .get(..region_count)
        .ok_or(BootError::OutOfMemory)?;

    bprintln!("[--------] boot: step 6/10: allocate and build page tables");
    let mut page_table = build_initial_tables(ctx.bs, &kernel.info, identity_regions_filled)?;
    install_handoff_trampoline_mapping(&mut page_table)?;

    Ok((allocs, page_table))
}

/// The handoff stack's `[base, top)` in its allocation at `alloc_phys`
/// ([`HANDOFF_STACK_ALLOC_PAGES`] pages): the allocation's lowest page is the
/// guard, and the stack is the [`KERNEL_STACK_PAGES`] above it, so its top is
/// the allocation's end and page-aligned.
fn handoff_stack_span(alloc_phys: u64) -> (u64, u64)
{
    // The allocation is `HANDOFF_STACK_ALLOC_PAGES` pages of real memory, so
    // its end is far below `u64::MAX`.
    let base = alloc_phys.saturating_add(4096);
    (
        base,
        base.saturating_add((KERNEL_STACK_PAGES as u64).saturating_mul(4096)),
    )
}

/// Fill `out` with all physical regions that must be identity-mapped so the
/// kernel can access them before establishing its own page tables. Returns
/// the number of filled entries; silently caps at [`MAX_IDENTITY_REGIONS`].
/// Module bodies lie inside the bundle mapping, so modules need no region of
/// their own. The handoff stack's region starts at `allocs.stack_phys`, above
/// its guard page, which no region covers.
fn collect_identity_regions(
    allocs: &BootAllocations,
    bundle: &BundleLoad,
    kernel: &KernelLoad,
    init: &InitLoad,
    framebuffer: &FramebufferInfo,
    uart_base: u64,
    out: &mut [(u64, u64); MAX_IDENTITY_REGIONS],
) -> usize
{
    let mut n: usize = 0;
    let mut push = |phys: u64, size: u64| {
        if let Some(slot) = out.get_mut(n)
        {
            *slot = (phys, size);
            // `n` indexed a slot of `out`, so it is far below `usize::MAX`.
            n = n.saturating_add(1);
        }
    };

    // Kernel ELF segments.
    for seg in kernel.info.segments.iter().take(kernel.info.segment_count)
    {
        // A size too large to round up saturates, which the page builder refuses.
        push(seg.phys_base, seg.size.saturating_add(4095) & !4095);
    }
    // Fixed boot allocations.
    for (phys, size) in allocation_regions(allocs)
    {
        push(phys, size);
    }
    // Init segments — segment bodies live in their own UEFI allocations,
    // produced by `load_init` against the bundle slice for the `init` entry.
    // `phys_addr` carries the `p_vaddr` in-page offset; `build_initial_tables`
    // maps every page the byte range touches.
    for seg in init
        .image
        .segments
        .iter()
        .take(init.image.segment_count as usize)
    {
        push(seg.phys_addr, seg.size);
    }
    // Bundle blob: one allocation covers every module body and the init
    // ELF source bytes. Map once.
    push(bundle.phys, (bundle.pages as u64).saturating_mul(4096));
    // Framebuffer (if present).
    if framebuffer.physical_base != 0
    {
        // Two `u32` factors widened to `u64`, so the product fits.
        let fb_size = u64::from(framebuffer.stride).saturating_mul(u64::from(framebuffer.height));
        push(
            framebuffer.physical_base,
            fb_size.saturating_add(4095) & !4095,
        );
    }
    // RISC-V MMIO UART (no-op on x86-64 where uart_base == 0).
    if uart_base != 0
    {
        push(uart_base, 4096);
    }
    n
}

/// Bytes in `pages` 4 KiB pages; a count too large to size saturates, which the
/// page builder refuses.
fn pages_to_bytes(pages: usize) -> u64
{
    (pages as u64).saturating_mul(4096)
}

/// The identity-map regions of the fixed boot allocations: the `BootInfo`
/// page, the boot-module array page, the memory-map entry pages, the handoff
/// stack above its guard page, the MMIO aperture array pages, the
/// reclaim-array page (`BootInfo.reclaim_ranges`), and the CPU-id pages
/// (`BootInfo.cpu_ids`). The AP trampoline page is mapped by the kernel, not
/// here.
fn allocation_regions(allocs: &BootAllocations) -> [(u64, u64); 7]
{
    [
        (allocs.boot_info_phys, 4096),
        (allocs.modules_phys, 4096),
        (
            allocs.mem_entries_phys,
            pages_to_bytes(allocs.mem_entries_pages),
        ),
        (allocs.stack_phys, pages_to_bytes(KERNEL_STACK_PAGES)),
        (
            allocs.apertures_phys,
            pages_to_bytes(allocs.apertures_pages),
        ),
        (allocs.reclaim_array_phys, 4096),
        (allocs.cpu_ids_phys, pages_to_bytes(allocs.cpu_ids_pages)),
    ]
}

/// Identity-map the handoff trampoline page(s) as RX in the new tables.
///
/// On x86-64, after `mov cr3` the CPU fetches the next instruction at the same
/// virtual address; under UEFI x86-64 VA == PA, so the symbol address doubles
/// as the physical address. When the handoff changes the paging depth, the
/// page mapped is the LA57 toggle page instead, whose copy of the trampoline
/// re-enables paging on the new tables. On RISC-V the trampoline page(s) are
/// likewise identity-mapped RX so execution continues across the satp write.
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

/// Entries the `MemoryMapEntry` array of `pages` pages holds: the one capacity
/// step 6 sizes the aperture array from, step 7 checks the map buffer against
/// ([`map_buffer_fits`]), and step 9 translates into.
const fn entry_array_capacity(pages: usize) -> usize
{
    match pages
        .saturating_mul(4096)
        .checked_div(core::mem::size_of::<MemoryMapEntry>())
    {
        Some(capacity) => capacity,
        // `MemoryMapEntry` is not zero-sized.
        None => 0,
    }
}

/// Pages of the `MemoryMapEntry` array for a map of `descriptors` descriptors
/// at `stride` bytes, with `slack` descriptors of growth: enough for the reach
/// of the buffer step 7 would allocate for a map that large
/// ([`uefi::map_buffer_descriptor_reach`] of [`uefi::map_buffer_bytes`]).
fn entry_array_pages(descriptors: usize, slack: usize, stride: usize) -> usize
{
    // A map too large to size saturates, and the allocation of its array fails.
    let reach = uefi::map_buffer_descriptor_reach(uefi::map_buffer_bytes(
        descriptors.saturating_add(slack).saturating_mul(stride),
        stride,
    ));
    reach
        .saturating_mul(core::mem::size_of::<MemoryMapEntry>())
        .div_ceil(4096)
}

/// Apertures the `MmioAperture` array step 6 allocates holds, for an entry
/// array of `mem_entries_pages` pages and `seeds` seeds of both classes: the
/// [`memory_map::aperture_capacity`] of the entry array's capacity, so a map
/// any buffer [`map_buffer_fits`] accepts derives no more apertures than it
/// holds.
fn aperture_array_capacity(mem_entries_pages: usize, seeds: usize) -> usize
{
    memory_map::aperture_capacity(entry_array_capacity(mem_entries_pages), seeds)
}

/// Whether step 7's map buffer of `buffer_bytes` fits the entry array of
/// `pages` pages: every map read into that buffer, step 8's re-query
/// included, then has an entry for each descriptor, and its apertures a slot.
fn map_buffer_fits(buffer_bytes: usize, pages: usize) -> bool
{
    uefi::map_buffer_descriptor_reach(buffer_bytes) <= entry_array_capacity(pages)
}

/// Run steps 6 and 7 until the final memory map's buffer holds no more
/// descriptors than the entry array step 6 sized
/// ([`uefi::map_buffer_descriptor_reach`], which bounds step 8's re-query
/// into the same buffer too): a buffer past the array frees both steps' allocations
/// ([`release_step6_and_7`]) and redoes them with twice the slack, from
/// [`MEM_MAP_SLACK_ENTRIES`], up to [`MEM_MAP_ATTEMPTS`] times
/// (`core/boot/docs/memory-map.md` § Sizing the Entry Array). The
/// `\EFI\seraph\mapredo` test knob, read before step 6's first allocation,
/// redoes the first attempt as if its buffer were past the array
/// ([`attempt_stands`]).
///
/// # Errors
/// [`BootError::MemoryMapKeptGrowing`] when the last attempt's buffer still
/// reaches past its array, and any error of steps 6 and 7 or of the frees.
///
/// # Safety
/// As [`step6_allocate_and_build_page_tables`], and `ctx.esp_root` must be a
/// valid ESP root directory handle; nothing between the returned map and
/// `ExitBootServices` may allocate.
unsafe fn steps6_and_7_sized_to_the_map(
    ctx: &UefiContext,
    bundle: &BundleLoad,
    kernel: &KernelLoad,
    init: &InitLoad,
    cpus: &CpuTopology,
    firm: &FirmwareInfo,
    ap_trampoline_phys: u64,
) -> Result<
    (
        BootAllocations,
        arch::current::BootPageTable,
        uefi::MemoryMapResult,
    ),
    BootError,
>
{
    // Read before step 6's size query, so the knob's open is not one of the
    // firmware allocations the first attempt's slack absorbs.
    // SAFETY: ctx.esp_root is valid until ExitBootServices; the path is
    // NUL-terminated UTF-16.
    let knob = if unsafe { knob_present(ctx, &MAPREDO_PATH, "\\EFI\\seraph\\mapredo") }
    {
        MapRedo::ForcedByKnob
    }
    else
    {
        MapRedo::Absent
    };
    let mut slack = MEM_MAP_SLACK_ENTRIES;
    let mut attempt = 1;
    loop
    {
        // SAFETY: caller contract; step 6 allocates via bs.
        let (allocs, page_table) = unsafe {
            step6_allocate_and_build_page_tables(
                ctx,
                bundle,
                kernel,
                init,
                cpus,
                firm,
                ap_trampoline_phys,
                slack,
            )?
        };
        // SAFETY: ctx.bs valid; step 7 is the last pre-exit allocation.
        let uefi_map = unsafe { step7_query_memory_map(ctx)? };
        let fits = map_buffer_fits(uefi_map.buffer_size, allocs.mem_entries_pages);
        if attempt_stands(fits, attempt, knob)
        {
            return Ok((allocs, page_table, uefi_map));
        }
        let reach = uefi::map_buffer_descriptor_reach(uefi_map.buffer_size);
        let capacity = entry_array_capacity(allocs.mem_entries_pages);
        if attempt == MEM_MAP_ATTEMPTS
        {
            return Err(BootError::MemoryMapKeptGrowing(reach));
        }
        if knob_redoes(attempt, knob)
        {
            bprintln!("[--------] boot: memory map: mapredo knob present; redoing steps 6 and 7");
        }
        else
        {
            bprintln!(
                "[--------] boot: memory map: a buffer of {reach} descriptors past the \
                 {capacity}-entry array; redoing steps 6 and 7"
            );
        }
        // SAFETY: bs is valid pre-exit; the spans are the allocations steps 6
        // and 7 just made, which nothing else references.
        unsafe { release_step6_and_7(ctx, &allocs, &page_table, &uefi_map)? };
        // `attempt` is below `MEM_MAP_ATTEMPTS` here, so neither overflows in a
        // few doublings of `MEM_MAP_SLACK_ENTRIES`.
        slack = slack.saturating_mul(2);
        attempt = attempt.saturating_add(1);
    }
}

/// Whether attempt `attempt` (from 1) of steps 6 and 7 stands, its map
/// buffer fitting the entry array or not (`fits`): one that fits stands,
/// except the first while the `mapredo` knob is present ([`MapRedo`]), which
/// is redone so the boot runs the redo path.
fn attempt_stands(fits: bool, attempt: usize, knob: MapRedo) -> bool
{
    fits && !knob_redoes(attempt, knob)
}

/// Whether the `mapredo` knob ([`MapRedo`]) redoes attempt `attempt` (from 1)
/// of steps 6 and 7 whatever its map's size: the first attempt alone, while
/// the knob is present.
fn knob_redoes(attempt: usize, knob: MapRedo) -> bool
{
    knob == MapRedo::ForcedByKnob && attempt == 1
}

/// The `(physical base, page count)` spans of every allocation steps 6 and 7
/// make: the `BootInfo`, module, entry and aperture pages, the two seed
/// buffers, the handoff stack with its guard page, the reclaim-array page,
/// the page-table frame pool (`pool`, [`paging::PageTableBuilder::pool_span`]),
/// and the raw map buffer (`map_buffer`, its base and size in bytes). The
/// CPU-id pages and the AP trampoline page (step 5 and 5b) and the x86-64
/// LA57 toggle page (paging negotiation) are earlier steps' allocations, which
/// the handoff still uses, and are not among them.
fn step6_and_7_spans(
    allocs: &BootAllocations,
    pool: (u64, u64),
    map_buffer: (u64, usize),
) -> [(u64, usize); 10]
{
    // cast_possible_truncation: the pool is sized by table_frame_bound, a few
    // hundred frames, far below usize::MAX on every target.
    #[allow(clippy::cast_possible_truncation)]
    let pool_pages = pool.1 as usize;
    [
        (allocs.boot_info_phys, 1),
        (allocs.modules_phys, 1),
        (allocs.mem_entries_phys, allocs.mem_entries_pages),
        (allocs.apertures_phys, allocs.apertures_pages),
        (allocs.seeds_phys, allocs.seeds_pages),
        (allocs.heuristic_phys, allocs.heuristic_pages),
        (
            allocs.stack_phys.saturating_sub(4096),
            HANDOFF_STACK_ALLOC_PAGES,
        ),
        (allocs.reclaim_array_phys, 1),
        (pool.0, pool_pages),
        (map_buffer.0, map_buffer.1.div_ceil(4096)),
    ]
}

/// Free every allocation steps 6 and 7 made ([`step6_and_7_spans`]), for a
/// redo of both with more slack.
///
/// # Errors
/// [`BootError`] from `FreePages`.
///
/// # Safety
/// `ctx.bs` is valid pre-exit; `allocs`, `page_table` and `uefi_map` are the
/// outputs of the steps 6 and 7 just run, and none of their memory is used
/// after this call.
unsafe fn release_step6_and_7(
    ctx: &UefiContext,
    allocs: &BootAllocations,
    page_table: &arch::current::BootPageTable,
    uefi_map: &uefi::MemoryMapResult,
) -> Result<(), BootError>
{
    let map_buffer = (uefi_map.buffer_phys, uefi_map.buffer_size);
    for (phys, pages) in step6_and_7_spans(allocs, page_table.pool_span(), map_buffer)
    {
        // SAFETY: caller contract.
        unsafe { free_pages(ctx.bs, phys, pages)? };
    }
    Ok(())
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
/// # Errors
/// [`BootError::ReclaimRangesOverflow`] when step 9 has more reclaim entries
/// than `MAX_RECLAIM_ENTRIES` allows for.
///
/// # Safety
/// All physical allocations named in `allocs` must remain identity-mapped and
/// writable. `uefi_map` must be the exited-boot memory map from step 7.
// BootInfo population is the fan-in point for every earlier step: bundle,
// kernel, init, modules, firmware, cpu topology, boot entropy, KASLR
// decision, framebuffer, boot allocations, the memory map, and the page-table
// frame pool all contribute distinct fields. Bundling them would only rename
// the argument list into an ad-hoc struct. The too_many_lines allowance
// covers the inline reclaim-array build below, which sits between aperture
// derivation and the BootInfo write.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
unsafe fn step9_populate_boot_info(
    bundle: &BundleLoad,
    kernel: &KernelLoad,
    init: &InitLoad,
    mods: &ModulesLoad,
    firm: &FirmwareInfo,
    cpus: &CpuTopology,
    boot_entropy: &BootEntropy,
    kaslr: &KaslrDecision,
    framebuffer: &FramebufferInfo,
    allocs: &BootAllocations,
    uefi_map: &uefi::MemoryMapResult,
    page_table: &arch::current::BootPageTable,
) -> Result<(), BootError>
{
    bprintln!("[--------] boot: step 9/10: populate BootInfo");

    // Module descriptor array.
    let modules_ptr = allocs.modules_phys as *mut BootModule;
    for (i, &module) in mods.modules.iter().enumerate().take(mods.count)
    {
        // SAFETY: modules_phys is a 4096-byte allocation; count ≤ MAX_MODULES (85)
        // so 85 × 48-byte BootModule entries (4080 bytes) fit.
        unsafe { core::ptr::write(modules_ptr.add(i), module) };
    }

    // Translate + sort the UEFI memory map.
    let entry_out = allocs.mem_entries_phys as *mut MemoryMapEntry;
    let max_entries = entry_array_capacity(allocs.mem_entries_pages);
    // Step 6 sized the array and step 7 checked the map buffer's reach, which
    // bounds the step 8 re-query too, against it, so every descriptor has an
    // entry.
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
    // The buffers step 6 sized from the seeders' count pass. The ACPI
    // seeder's layout-heuristic PCI windows go to their own buffer:
    // derive_mmio_apertures clips them harder than the named seeds
    // (core/boot/docs/firmware-parsing.md § Firmware exclusion).
    // SAFETY: seeds_phys and heuristic_phys are step 6 allocations of
    // seeds_pages and heuristic_pages pages, identity-mapped under the
    // firmware's tables and owned by the bootloader, with room for their
    // capacities; they are zeroed before the slices are formed.
    let (aperture_seed, heuristic_seed): (&mut [MmioAperture], &mut [MmioAperture]) = unsafe {
        core::ptr::write_bytes(
            allocs.seeds_phys as *mut u8,
            0,
            allocs.seeds_pages.saturating_mul(4096),
        );
        core::ptr::write_bytes(
            allocs.heuristic_phys as *mut u8,
            0,
            allocs.heuristic_pages.saturating_mul(4096),
        );
        (
            core::slice::from_raw_parts_mut(
                allocs.seeds_phys as *mut MmioAperture,
                allocs.seeds_capacity,
            ),
            core::slice::from_raw_parts_mut(
                allocs.heuristic_phys as *mut MmioAperture,
                allocs.heuristic_capacity,
            ),
        )
    };
    // SAFETY: acpi_rsdp is zero or identity-mapped; parse_aperture_seed validates.
    let (mut seed_count, heuristic_count) =
        unsafe { acpi::parse_aperture_seed(firm.acpi_rsdp, aperture_seed, heuristic_seed) };
    // `seed_count` is at most the seed buffer's length; past it the DTB seeder gets none.
    let dtb_room = aperture_seed.get_mut(seed_count..).unwrap_or_default();
    // SAFETY: device_tree is zero or identity-mapped; parse_aperture_seed validates.
    let dtb_seeds = unsafe { dtb::parse_aperture_seed(firm.device_tree, dtb_room) };
    seed_count = seed_count.saturating_add(dtb_seeds);
    // GOP linear framebuffer: UEFI typically reports it as
    // `EfiReservedMemoryType` rather than `EfiMemoryMappedIO`, so
    // `derive_mmio_apertures` cannot recover it from the UEFI map alone.
    // Seed it explicitly when present. The framebuffer's identity dies
    // at `ExitBootServices` (only GOP knows it pre-exit), so the
    // bootloader is the only entity that can carry this aperture
    // through to userspace.
    if framebuffer.physical_base != 0
    {
        if let Some(slot) = aperture_seed.get_mut(seed_count)
        {
            if let Some(aperture) = framebuffer_aperture(framebuffer)
            {
                *slot = aperture;
                // `seed_count` indexed a slot of `aperture_seed`, so it is far
                // below `usize::MAX`.
                seed_count = seed_count.saturating_add(1);
            }
            else
            {
                bprintln!(
                    "[--------] boot: MMIO apertures: framebuffer span out of range; \
                     framebuffer seed dropped"
                );
            }
        }
        else
        {
            bprintln!(
                "[--------] boot: MMIO apertures: seed buffer full; framebuffer seed dropped"
            );
        }
    }

    // SAFETY: apertures_phys is the step 6 allocation of apertures_pages pages,
    // identity-mapped and owned by the bootloader, with room for
    // aperture_capacity entries; it is zeroed before the slice is formed.
    let apertures_buf: &mut [MmioAperture] = unsafe {
        core::ptr::write_bytes(
            allocs.apertures_phys as *mut u8,
            0,
            allocs.apertures_pages.saturating_mul(4096),
        );
        core::slice::from_raw_parts_mut(
            allocs.apertures_phys as *mut MmioAperture,
            allocs.aperture_capacity,
        )
    };
    // SAFETY: uefi_map.buffer_phys is the raw UEFI map from step 7, still mapped.
    let aperture_count = unsafe {
        memory_map::derive_mmio_apertures(
            uefi_map,
            aperture_seed.get(..seed_count).unwrap_or_default(),
            heuristic_seed.get(..heuristic_count).unwrap_or_default(),
            apertures_buf,
        )
    };
    bprintln!("[--------] boot: MMIO apertures: {aperture_count} derived");

    // The raw UEFI memory-map buffer is dead: the translation and the
    // aperture derivation above were its last readers. Zero it before it is
    // recorded below, so the firmware's map does not reach the memory the
    // kernel hands out.
    // SAFETY: buffer_phys is the step 7 allocation of buffer_size bytes, still
    // identity-mapped under the firmware's tables; nothing reads it again.
    unsafe { core::ptr::write_bytes(uefi_map.buffer_phys as *mut u8, 0, uefi_map.buffer_size) };

    // Build `BootInfo.reclaim_ranges` in the dedicated 4 KiB page at
    // `allocs.reclaim_array_phys`: the scratch pages core/boot/docs/boot-flow.md
    // § Step 9 lists for `reclaim_ranges` (the AP trampoline entry flagged
    // `RECLAIM_FLAG_LATE`), with the reclaim-array page itself recorded last.
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
        push_reclaim_range(
            reclaim_ranges,
            &mut reclaim_len,
            ReclaimRange {
                phys_base,
                page_count,
                flags,
            },
        )
    };
    push_reclaim(allocs.boot_info_phys, 1, 0)?;
    push_reclaim(allocs.modules_phys, 1, 0)?;
    // The entry array is a few pages per thousand descriptors, far below
    // u32::MAX pages.
    #[allow(clippy::cast_possible_truncation)]
    {
        push_reclaim(allocs.mem_entries_phys, allocs.mem_entries_pages as u32, 0)?;
    }
    // The aperture array and the seed buffers are a few pages at most, far
    // below u32::MAX pages.
    #[allow(clippy::cast_possible_truncation)]
    {
        push_reclaim(allocs.apertures_phys, allocs.apertures_pages as u32, 0)?;
        push_reclaim(allocs.seeds_phys, allocs.seeds_pages as u32, 0)?;
        push_reclaim(allocs.heuristic_phys, allocs.heuristic_pages as u32, 0)?;
    }
    // The map buffer is a whole-page allocation far below u32::MAX pages.
    #[allow(clippy::cast_possible_truncation)]
    {
        push_reclaim(
            uefi_map.buffer_phys,
            (uefi_map.buffer_size / 4096) as u32,
            0,
        )?;
    }
    for &(base, pages) in page_table.reclaim_spans()
    {
        // The page-table pool is a few hundred pages at most, far below
        // u32::MAX pages, and the LA57 toggle span is one page.
        #[allow(clippy::cast_possible_truncation)]
        {
            push_reclaim(base, pages as u32, 0)?;
        }
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
    // Module bodies are minted separately and are skipped here
    // (core/boot/docs/boot-flow.md § Step 9: Populate BootInfo, `reclaim_ranges`).
    let bundle_end = bundle
        .phys
        .saturating_add((bundle.pages as u64).saturating_mul(4096));
    let mut bundle_cursor = bundle.phys;
    for module in mods.modules.iter().take(mods.count)
    {
        // Bundle bodies are 4 KiB-aligned per `bundle::BODY_ALIGNMENT`,
        // already enforced (release-mode) by `bundle::parse_header`'s
        // `EntryMisaligned` check. Only the cursor-ordering invariant
        // needs an explicit debug guard.
        let module_base = module.physical_base;
        let module_end = module
            .physical_base
            .saturating_add(module.size)
            .saturating_add(0xFFF)
            & !0xFFF;
        debug_assert!(
            bundle_cursor <= module_base,
            "bundle modules not in ascending offset order",
        );
        if bundle_cursor < module_base
        {
            // The gap lies inside the bundle allocation, and no UEFI allocation
            // reaches u32::MAX pages (16 TiB), so the cast is exact.
            #[allow(clippy::cast_possible_truncation)]
            let gap_pages = (module_base.saturating_sub(bundle_cursor) / 4096) as u32;
            push_reclaim(bundle_cursor, gap_pages, 0)?;
        }
        bundle_cursor = module_end;
    }
    if bundle_cursor < bundle_end
    {
        // The tail lies inside the bundle allocation (see the gap cast above).
        #[allow(clippy::cast_possible_truncation)]
        let tail_pages = (bundle_end.saturating_sub(bundle_cursor) / 4096) as u32;
        push_reclaim(bundle_cursor, tail_pages, 0)?;
    }
    // CPU-id pages: the kernel reads them through Phase 8 (SMP bringup), before
    // init, the first user of a reclaimed page, runs.
    // The array is a few pages at most (`MAX_CPUS` u32s), far below u32::MAX.
    #[allow(clippy::cast_possible_truncation)]
    {
        push_reclaim(cpus.ids_phys, cpus.ids_pages as u32, 0)?;
    }
    // AP trampoline page: flagged `RECLAIM_FLAG_LATE`; the kernel mints it after
    // SMP bringup (core/kernel/docs/initialization.md § Phase 8: Scheduler and
    // SMP Bringup).
    if allocs.ap_trampoline_phys != 0
    {
        push_reclaim(allocs.ap_trampoline_phys, 1, RECLAIM_FLAG_LATE)?;
    }
    // The reclaim-array page itself is reclaim-safe once the kernel has
    // walked it — record it last so the kernel processes it in order.
    push_reclaim(allocs.reclaim_array_phys, 1, 0)?;
    bprintln!("[--------] boot: reclaim_ranges: {reclaim_len} entries recorded");

    // VMGENID GUID address: QEMU-specific SSDT scan (no AML evaluation).
    // Zero when absent; the kernel then has no snapshot-detection channel.
    // SAFETY: acpi_rsdp is zero or identity-mapped; the parser validates.
    let vmgenid_paddr = unsafe { acpi::parse_vmgenid_paddr(firm.acpi_rsdp) };
    if vmgenid_paddr != 0
    {
        bprintln!("[--------] boot: vmgenid guid at {vmgenid_paddr:#x}");
    }

    // Direct-map base (KASLR): the paging mode's kernel-half floor, or a
    // 1 GiB-aligned random base below the (already-biased) kernel image when
    // step 5d set `randomize_dm` (entropy present, no nokaslr knob). Uses the
    // same shared ceiling the kernel's Phase-3 guard and Phase-0 validator use,
    // over the translated map produced above.
    let floor = arch::current::default_direct_map_base();
    let image_base = kernel.info.virtual_base;
    let (direct_map_base, kaslr_flags) = if kaslr.randomize_dm
    {
        // SAFETY: entry_out[..entry_count] were written and sorted above.
        let entries = unsafe { core::slice::from_raw_parts(entry_out, entry_count) };
        let ceiling = boot_protocol::direct_map_ceiling(entries, framebuffer, &kernel_mmio);
        let (base, limited) =
            boot_protocol::layout::direct_map_base(kaslr.dm_rand, floor, image_base, ceiling);
        let f = if limited
        {
            kaslr.flags | boot_protocol::KASLR_DM_WINDOW_LIMITED
        }
        else
        {
            kaslr.flags | boot_protocol::KASLR_DM_RANDOMIZED
        };
        (base, f)
    }
    else
    {
        (floor, kaslr.flags)
    };
    // Only the opaque flags are printed: the bootloader console mirrors to the
    // framebuffer (core/kernel/docs/cross-boundary-disclosure.md § Kernel
    // console diagnostics, "KASLR values are serial-only").
    bprintln!("[--------] boot: kaslr flags={kaslr_flags:#x}");

    // Write the populated BootInfo.
    // SAFETY: boot_info_phys is a valid 4 KiB allocation; BootInfo fits in one
    // page. `boot_entropy.seed` is a live local distinct from that page, so
    // the in-place copy cannot overlap, and both field pointers are derived
    // from the just-written BootInfo.
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
                cpu_ids: cpus.ids_phys as *const u32,
                ap_trampoline_page: allocs.ap_trampoline_phys,
                reclaim_ranges: ReclaimSlice {
                    entries: allocs.reclaim_array_phys as *const ReclaimRange,
                    count: reclaim_len as u64,
                },
                boot_entropy_seed: [0u8; 32],
                boot_entropy_len: 0,
                vmgenid_paddr,
                direct_map_base,
                kaslr_flags,
            },
        );
        // The seed goes into the page in place rather than through the struct
        // literal above, so no copy of it is materialised in this frame.
        let bi = allocs.boot_info_phys as *mut BootInfo;
        core::ptr::copy_nonoverlapping(
            boot_entropy.seed.as_ptr(),
            core::ptr::addr_of_mut!((*bi).boot_entropy_seed).cast::<u8>(),
            boot_entropy.seed.len(),
        );
        core::ptr::addr_of_mut!((*bi).boot_entropy_len).write(boot_entropy.len);
    }
    Ok(())
}

/// The page-aligned MMIO aperture covering the framebuffer, or `None` when its
/// span runs past the end of the address space.
fn framebuffer_aperture(framebuffer: &FramebufferInfo) -> Option<MmioAperture>
{
    let base_aligned = framebuffer.physical_base & !0xFFF;
    // Two `u32` factors widened to `u64`, so the product fits.
    let len = u64::from(framebuffer.stride).saturating_mul(u64::from(framebuffer.height));
    let span = framebuffer.physical_base.checked_add(len)?;
    let end_aligned = span.checked_add(0xFFF)? & !0xFFF;
    Some(MmioAperture {
        phys_base: base_aligned,
        size: end_aligned.checked_sub(base_aligned)?,
    })
}

/// Append `range` to `ranges[..*len]`, skipping an empty range.
///
/// # Errors
/// [`BootError::ReclaimRangesOverflow`] when `ranges` is full. Unreachable from
/// step 9 while `MAX_RECLAIM_ENTRIES` bounds its pushes at compile time; it is
/// reported rather than written past the page if that count is ever wrong.
fn push_reclaim_range(
    ranges: &mut [ReclaimRange],
    len: &mut usize,
    range: ReclaimRange,
) -> Result<(), BootError>
{
    if range.page_count == 0
    {
        return Ok(());
    }
    let Some(slot) = ranges.get_mut(*len)
    else
    {
        return Err(BootError::ReclaimRangesOverflow);
    };
    *slot = range;
    // `*len` indexed a slot of `ranges`, so it is far below `usize::MAX`.
    *len = len.saturating_add(1);
    Ok(())
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

#[cfg(test)]
mod tests
{
    use super::{
        BootAllocations, BootEntropy, BootError, ElfKind, HANDOFF_STACK_ALLOC_PAGES,
        KERNEL_STACK_PAGES, KaslrOverride, MEM_MAP_ATTEMPTS, MapRedo, ReclaimRange,
        allocation_regions, aperture_array_capacity, attempt_stands, bundle_body,
        choose_kaslr_layout, entry_array_pages, framebuffer_aperture, handoff_stack_span,
        knob_redoes, map_buffer_fits, memory_map, push_reclaim_range, scrub, step6_and_7_spans,
        uefi,
    };
    use boot_protocol::{KASLR_DISABLED_BY_KNOB, KASLR_ENTROPY_FW_RNG, KASLR_IMAGE_RANDOMIZED};

    const IMAGE: u64 = 8 << 20;

    fn draw(word: u64) -> BootEntropy
    {
        BootEntropy {
            kaslr: [word, 0x0fed_cba9_8765_4321],
            kaslr_available: true,
            kaslr_source_flag: KASLR_ENTROPY_FW_RNG,
            ..BootEntropy::NONE
        }
    }

    #[test]
    fn knob_disables_both_dimensions()
    {
        let e = draw(0x1234_5678_9abc_def1);
        let (slide, d) =
            choose_kaslr_layout(KaslrOverride::DisabledByKnob, &e, ElfKind::Dyn, IMAGE);
        assert_eq!(slide, 0);
        assert!(!d.randomize_dm);
        assert_eq!(d.dm_rand, 0);
        assert_eq!(d.flags, KASLR_DISABLED_BY_KNOB);
    }

    #[test]
    fn no_entropy_is_the_deterministic_layout()
    {
        let (slide, d) = choose_kaslr_layout(
            KaslrOverride::Absent,
            &BootEntropy::NONE,
            ElfKind::Dyn,
            IMAGE,
        );
        assert_eq!(slide, 0);
        assert!(!d.randomize_dm);
        assert_eq!(d.flags, 0);
    }

    #[test]
    fn pie_with_entropy_slides_and_flags_agree()
    {
        let e = draw(0x1234_5678_9abc_def1);
        let (slide, d) = choose_kaslr_layout(KaslrOverride::Absent, &e, ElfKind::Dyn, IMAGE);
        assert_eq!(slide, boot_protocol::layout::image_slide(e.kaslr[0], IMAGE));
        assert_ne!(slide, 0);
        assert!(d.randomize_dm);
        assert_eq!(d.dm_rand, e.kaslr[1]);
        assert_eq!(d.flags, KASLR_ENTROPY_FW_RNG | KASLR_IMAGE_RANDOMIZED);
    }

    #[test]
    fn pie_whose_draw_lands_on_slot_zero_still_reads_as_randomized()
    {
        let e = draw(0);
        let (slide, d) = choose_kaslr_layout(KaslrOverride::Absent, &e, ElfKind::Dyn, IMAGE);
        assert_eq!(slide, 0);
        assert!(d.randomize_dm);
        assert_eq!(d.dm_rand, e.kaslr[1]);
        assert_eq!(d.flags, KASLR_ENTROPY_FW_RNG | KASLR_IMAGE_RANDOMIZED);
    }

    #[test]
    fn et_exec_with_entropy_is_pinned_but_randomizes_the_direct_map()
    {
        let e = draw(0x1234_5678_9abc_def1);
        let (slide, d) = choose_kaslr_layout(KaslrOverride::Absent, &e, ElfKind::Exec, IMAGE);
        assert_eq!(slide, 0);
        assert!(d.randomize_dm);
        assert_eq!(d.dm_rand, e.kaslr[1]);
        assert_eq!(d.flags, KASLR_ENTROPY_FW_RNG);
    }

    // Defect caught: a span that starts at the allocation's base, leaving no
    // guard page below the stack, or one that is shorter than the shared
    // HANDOFF_STACK_BYTES or runs past the allocation's end.
    #[test]
    fn the_handoff_stack_sits_above_one_guard_page_and_ends_at_its_allocation_end()
    {
        let alloc = 0x7_e000u64;
        let (base, top) = handoff_stack_span(alloc);
        assert_eq!(base, alloc + 4096);
        assert_eq!(
            top - base,
            boot_protocol::layout::HANDOFF_STACK_BYTES as u64
        );
        assert_eq!(top, alloc + (HANDOFF_STACK_ALLOC_PAGES as u64) * 4096);
    }

    /// Boot allocations at distinct, non-overlapping addresses.
    fn sample_allocations() -> BootAllocations
    {
        BootAllocations {
            boot_info_phys: 0x1_0000,
            modules_phys: 0x2_0000,
            mem_entries_phys: 0x3_0000,
            mem_entries_pages: 3,
            apertures_phys: 0x4_0000,
            aperture_capacity: 600,
            apertures_pages: 3,
            stack_phys: 0x5_1000,
            stack_top: 0x6_1000,
            ap_trampoline_phys: 0x8000,
            reclaim_array_phys: 0x7_0000,
            cpu_ids_phys: 0x8_0000,
            cpu_ids_pages: 2,
            seeds_phys: 0x9_0000,
            seeds_capacity: 4,
            seeds_pages: 1,
            heuristic_phys: 0xA_0000,
            heuristic_capacity: 2,
            heuristic_pages: 1,
        }
    }

    // Defect caught: a redo of steps 6 and 7 that frees an allocation of an
    // earlier step the handoff still uses (the AP trampoline or the CPU-id
    // pages), or that leaks one of its own.
    #[test]
    fn a_redo_of_steps_6_and_7_frees_exactly_their_allocations()
    {
        let allocs = sample_allocations();
        let pool = (0xB_0000, 7);
        let map_buffer = (0xC_0000, 3 * 4096 + 1);
        let spans = step6_and_7_spans(&allocs, pool, map_buffer);
        let expected = [
            (0x1_0000, 1),
            (0x2_0000, 1),
            (0x3_0000, 3),
            (0x4_0000, 3),
            (0x9_0000, 1),
            (0xA_0000, 1),
            (0x5_0000, HANDOFF_STACK_ALLOC_PAGES),
            (0x7_0000, 1),
            (0xB_0000, 7),
            (0xC_0000, 4),
        ];
        assert_eq!(spans, expected);
        for kept in [allocs.ap_trampoline_phys, allocs.cpu_ids_phys]
        {
            assert!(
                spans
                    .iter()
                    .all(|&(base, pages)| kept < base || kept >= base + pages as u64 * 4096),
                "{kept:#x} is an earlier step's allocation"
            );
        }
    }

    // Defect caught: a mapredo knob that is ignored (the first attempt stands
    // although the knob is present), that redoes a later attempt too (the boot
    // would end in MemoryMapKeptGrowing), or that makes an attempt whose map
    // does not fit stand; or a knob line logged for an attempt the knob does
    // not redo, or missing from the one it does.
    #[test]
    fn the_mapredo_knob_redoes_the_first_attempt_alone()
    {
        assert!(!attempt_stands(true, 1, MapRedo::ForcedByKnob));
        assert!(knob_redoes(1, MapRedo::ForcedByKnob));
        for attempt in 2..=MEM_MAP_ATTEMPTS
        {
            assert!(attempt_stands(true, attempt, MapRedo::ForcedByKnob));
            assert!(!knob_redoes(attempt, MapRedo::ForcedByKnob));
        }
        for attempt in 1..=MEM_MAP_ATTEMPTS
        {
            assert!(!knob_redoes(attempt, MapRedo::Absent));
            assert!(attempt_stands(true, attempt, MapRedo::Absent));
            assert!(!attempt_stands(false, attempt, MapRedo::Absent));
            assert!(!attempt_stands(false, attempt, MapRedo::ForcedByKnob));
        }
    }

    // Defect caught: step 6 sizing the aperture array from a smaller capacity
    // than the one step 7 accepts a map buffer against (the entry array's
    // reach before page rounding, for one), so a map that passes the check
    // derives more apertures than the array holds; or a buffer for a map no
    // larger than step 6 allowed for that fails the check.
    #[test]
    fn every_map_buffer_step_7_accepts_fits_the_arrays_step_6_sized()
    {
        let seeds = 7;
        for stride in [40usize, 48, 56, 80]
        {
            for descriptors in [0usize, 1, 50, 100, 160, 400]
            {
                for slack in [32usize, 64, 128]
                {
                    let pages = entry_array_pages(descriptors, slack, stride);
                    let apertures = aperture_array_capacity(pages, seeds);
                    for grown in 0..=descriptors + slack
                    {
                        let buffer = uefi::map_buffer_bytes(grown * stride, stride);
                        assert!(
                            map_buffer_fits(buffer, pages),
                            "{stride} {descriptors} {grown}"
                        );
                    }
                    // Every buffer step 7 accepts, up to the largest: a map read
                    // into one derives at most `aperture_capacity` of its
                    // reach, which the array step 6 sizes must hold.
                    let mut buffer = 4096;
                    while map_buffer_fits(buffer, pages)
                    {
                        let reach = uefi::map_buffer_descriptor_reach(buffer);
                        assert!(
                            memory_map::aperture_capacity(reach, seeds) <= apertures,
                            "{stride} {descriptors} {slack}: reach {reach}"
                        );
                        buffer += 4096;
                    }
                }
            }
        }
    }

    // Defect caught: one of the fixed boot allocations (the CPU-id pages, for
    // one) dropped from the identity map at kernel entry or mapped short, which
    // no boot exposes while the kernel reads it only through its direct map.
    #[test]
    fn fixed_boot_allocations_are_identity_mapped_whole()
    {
        let allocs = sample_allocations();
        let regions = allocation_regions(&allocs);
        for region in [
            (0x1_0000, 4096),
            (0x2_0000, 4096),
            (0x3_0000, 3 * 4096),
            (0x4_0000, 3 * 4096),
            (0x5_1000, (KERNEL_STACK_PAGES as u64) * 4096),
            (0x7_0000, 4096),
            (0x8_0000, 2 * 4096),
        ]
        {
            assert!(
                regions.contains(&region),
                "{region:x?} is not identity-mapped"
            );
        }
    }

    // Defect caught: a push past the reclaim array's page, or one that records
    // an empty range.
    #[test]
    fn a_full_reclaim_array_refuses_a_push_and_an_empty_range_is_skipped()
    {
        let empty = ReclaimRange {
            phys_base: 0,
            page_count: 0,
            flags: 0,
        };
        let one = ReclaimRange {
            phys_base: 0x1000,
            page_count: 1,
            flags: 0,
        };
        let mut ranges = [empty; 2];
        let mut len = 0;
        assert!(push_reclaim_range(&mut ranges, &mut len, empty).is_ok());
        assert_eq!(len, 0);
        assert!(push_reclaim_range(&mut ranges, &mut len, one).is_ok());
        assert!(push_reclaim_range(&mut ranges, &mut len, one).is_ok());
        assert!(matches!(
            push_reclaim_range(&mut ranges, &mut len, one),
            Err(BootError::ReclaimRangesOverflow)
        ));
        assert_eq!(len, 2);
    }

    // Defect caught: a body whose offset plus size wraps `usize` or ends past
    // the file passing as a slice of it (or panicking).
    #[test]
    fn a_bundle_body_past_the_file_or_overflowing_is_refused()
    {
        let bytes = [1u8, 2, 3, 4];
        assert_eq!(bundle_body(&bytes, 1, 2), Some(&bytes[1..3]));
        assert_eq!(bundle_body(&bytes, 4, 0), Some(&bytes[4..4]));
        assert_eq!(bundle_body(&bytes, 2, 3), None);
        assert_eq!(bundle_body(&bytes, 5, 0), None);
        assert_eq!(bundle_body(&bytes, usize::MAX, 2), None);
    }

    // Defect caught: a framebuffer whose span wraps the address space seeding
    // a wrapped aperture (or panicking in debug builds).
    #[test]
    fn a_framebuffer_span_past_the_address_space_seeds_no_aperture()
    {
        let fb = |physical_base, stride, height| boot_protocol::FramebufferInfo {
            physical_base,
            width: 0,
            height,
            stride,
            pixel_format: boot_protocol::PixelFormat::Bgrx8,
        };
        let seeded = framebuffer_aperture(&fb(0x8000_0123, 4096, 3)).expect("in range");
        assert_eq!(seeded.phys_base, 0x8000_0000);
        assert_eq!(seeded.size, 0x4000);
        assert!(framebuffer_aperture(&fb(u64::MAX - 0x10, 4096, 3)).is_none());
    }

    #[test]
    fn scrub_zeroes_every_byte()
    {
        let mut secret = [0xA5u8; 32];
        scrub(&mut secret);
        assert_eq!(secret, [0u8; 32]);
    }

    #[test]
    fn scrub_accepts_an_empty_slice()
    {
        let mut empty: [u8; 0] = [];
        scrub(&mut empty);
    }
}
