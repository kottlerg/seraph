// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/uefi.rs

//! UEFI raw type definitions and safe wrapper functions.
//!
//! All UEFI types are hand-written `#[repr(C)]` structures — no external crate
//! is used. Function pointer types use `extern "efiapi"`, which resolves to the
//! Microsoft x64 ABI on x86-64 and to the target's C ABI on RISC-V (lp64 for
//! the soft-float `riscv64imac-seraph-uefi` target; no UEFI call made here
//! passes floating-point arguments).
//!
//! Fallible public wrappers return `Result<T, BootError>`; best-effort lookups
//! (`query_gop`, `find_config_table`) return `Option`, and
//! `connect_all_controllers` ignores per-handle failures and returns nothing.
//! All of them keep raw pointer manipulation behind documented `// SAFETY:`
//! contracts.

use crate::error::BootError;
use boot_protocol::FramebufferInfo;
use boot_protocol::PixelFormat;

// ── Basic UEFI types ──────────────────────────────────────────────────────────

pub type EfiHandle = *mut core::ffi::c_void;
pub type EfiStatus = usize;
pub type EfiBool = u8;

pub const EFI_SUCCESS: EfiStatus = 0;
pub const EFI_BUFFER_TOO_SMALL: EfiStatus = 0x8000_0000_0000_0005;
pub const EFI_INVALID_PARAMETER: EfiStatus = 0x8000_0000_0000_0002;
pub const EFI_UNSUPPORTED: EfiStatus = 0x8000_0000_0000_0003;
pub const EFI_NOT_FOUND: EfiStatus = 0x8000_0000_0000_000E;
/// `EFI_NOT_READY`: `ReadKeyStroke` found no key waiting.
pub const EFI_NOT_READY: EfiStatus = 0x8000_0000_0000_0006;

/// `EFI_VARIABLE_NON_VOLATILE`: the variable is kept across resets.
pub const EFI_VARIABLE_NON_VOLATILE: u32 = 0x0000_0001;
/// `EFI_VARIABLE_BOOTSERVICE_ACCESS`: the variable is reachable before
/// `ExitBootServices`. Without [`EFI_VARIABLE_RUNTIME_ACCESS`], which no
/// Seraph variable carries, it is reachable then alone.
pub const EFI_VARIABLE_BOOTSERVICE_ACCESS: u32 = 0x0000_0002;
/// `EFI_VARIABLE_RUNTIME_ACCESS`: the variable is reachable after
/// `ExitBootServices` too, as the firmware's Secure Boot state variables are.
pub const EFI_VARIABLE_RUNTIME_ACCESS: u32 = 0x0000_0004;

/// Allocate pages at any available physical address.
pub const ALLOCATE_ANY_PAGES: u32 = 0;
/// Allocate pages at or below a specified maximum physical address
/// (`AllocateMaxAddress`). Referenced only by `allocate_typed_max_addr`.
pub const ALLOCATE_MAX_ADDRESS: u32 = 1;

/// Memory type used for every bootloader allocation but the x86-64 LA57
/// toggle page ([`allocate_code_pages_max_addr`]).
///
/// `EfiLoaderData` regions appear in the final memory map as `Loaded` in the
/// boot protocol, notifying to the kernel that these regions are in-use.
pub const EFI_LOADER_DATA: u32 = 2;

// ── GUIDs ─────────────────────────────────────────────────────────────────────

/// `EFI_LOADED_IMAGE_PROTOCOL_GUID`
/// `{5B1B31A1-9562-11D2-8E3F-00A0C969723B}`
pub static EFI_LOADED_IMAGE_PROTOCOL_GUID: EfiGuid = EfiGuid {
    data1: 0x5B1B_31A1,
    data2: 0x9562,
    data3: 0x11D2,
    data4: [0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
};

/// `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID`
/// `{964E5B22-6459-11D2-8E39-00A0C969723B}`
pub static EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID: EfiGuid = EfiGuid {
    data1: 0x964E_5B22,
    data2: 0x6459,
    data3: 0x11D2,
    data4: [0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
};

/// `EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID`
/// `{9042A9DE-23DC-4A38-96FB-7ADED080516A}`
pub static EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID: EfiGuid = EfiGuid {
    data1: 0x9042_A9DE,
    data2: 0x23DC,
    data3: 0x4A38,
    data4: [0x96, 0xFB, 0x7A, 0xDE, 0xD0, 0x80, 0x51, 0x6A],
};

/// `EFI_DEVICE_PATH_PROTOCOL_GUID`
/// `{09576E91-6D3F-11D2-8E39-00A0C969723B}`
pub static EFI_DEVICE_PATH_PROTOCOL_GUID: EfiGuid = EfiGuid {
    data1: 0x0957_6E91,
    data2: 0x6D3F,
    data3: 0x11D2,
    data4: [0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
};

/// `EFI_PCI_IO_PROTOCOL_GUID`
/// `{4CF5B200-68B8-4CA5-9EEC-B23E3F50029A}`
pub static EFI_PCI_IO_PROTOCOL_GUID: EfiGuid = EfiGuid {
    data1: 0x4CF5_B200,
    data2: 0x68B8,
    data3: 0x4CA5,
    data4: [0x9E, 0xEC, 0xB2, 0x3E, 0x3F, 0x50, 0x02, 0x9A],
};

/// `EFI_ACPI_20_TABLE_GUID` (ACPI 2.0 RSDP)
/// `{8868E871-E4F1-11D3-BC22-0080C73C8881}`
pub static EFI_ACPI_20_TABLE_GUID: EfiGuid = EfiGuid {
    data1: 0x8868_E871,
    data2: 0xE4F1,
    data3: 0x11D3,
    data4: [0xBC, 0x22, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81],
};

/// `EFI_DTB_TABLE_GUID` (Device Tree Blob)
/// `{B1B621D5-F19C-41A5-830B-D9152C69AAE0}`
pub static EFI_DTB_TABLE_GUID: EfiGuid = EfiGuid {
    data1: 0xB1B6_21D5,
    data2: 0xF19C,
    data3: 0x41A5,
    data4: [0x83, 0x0B, 0xD9, 0x15, 0x2C, 0x69, 0xAA, 0xE0],
};

/// `EFI_FILE_INFO_ID` GUID
/// `{09576E92-6D3F-11D2-8E39-00A0C969723B}`
pub static EFI_FILE_INFO_ID: EfiGuid = EfiGuid {
    data1: 0x0957_6E92,
    data2: 0x6D3F,
    data3: 0x11D2,
    data4: [0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
};

/// `EFI_RNG_PROTOCOL_GUID`
/// `{3152BCA5-EADE-433D-862E-C01CDC291F44}`
pub static EFI_RNG_PROTOCOL_GUID: EfiGuid = EfiGuid {
    data1: 0x3152_BCA5,
    data2: 0xEADE,
    data3: 0x433D,
    data4: [0x86, 0x2E, 0xC0, 0x1C, 0xDC, 0x29, 0x1F, 0x44],
};

/// `EFI_GLOBAL_VARIABLE`, the vendor GUID of the variables the UEFI
/// specification defines, the Secure Boot state among them
/// `{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}`
pub static EFI_GLOBAL_VARIABLE_GUID: EfiGuid = EfiGuid {
    data1: 0x8BE4_DF61,
    data2: 0x93CA,
    data3: 0x11D2,
    data4: [0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C],
};

/// The Seraph vendor GUID, which names every Seraph UEFI variable
/// (docs/signing.md § Rollback Floor)
/// `{A53C3964-9D31-4F44-843A-526BAA1271B8}`
pub static SERAPH_VENDOR_GUID: EfiGuid = EfiGuid {
    data1: 0xA53C_3964,
    data2: 0x9D31,
    data3: 0x4F44,
    data4: [0x84, 0x3A, 0x52, 0x6B, 0xAA, 0x12, 0x71, 0xB8],
};

// ── Structs ────────────────────────────────────────────────────────────────────

/// A 128-bit UEFI GUID.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EfiGuid
{
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

/// Standard UEFI table header, present at the start of all UEFI tables.
#[repr(C)]
pub struct EfiTableHeader
{
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

/// Entry in the UEFI configuration table (`SystemTable->ConfigurationTable`).
#[repr(C)]
pub struct EfiConfigurationTable
{
    pub vendor_guid: EfiGuid,
    pub vendor_table: *mut core::ffi::c_void,
}

/// Top-level UEFI system table passed to the EFI application entry point.
#[repr(C)]
pub struct EfiSystemTable
{
    pub hdr: EfiTableHeader,
    pub firmware_vendor: *mut u16,
    pub firmware_revision: u32,
    pub console_in_handle: EfiHandle,
    pub con_in: *mut EfiSimpleTextInput,
    pub console_out_handle: EfiHandle,
    pub con_out: *mut EfiSimpleTextOutput,
    pub standard_error_handle: EfiHandle,
    pub std_err: *mut core::ffi::c_void,
    pub runtime_services: *mut EfiRuntimeServices,
    pub boot_services: *mut EfiBootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: *mut EfiConfigurationTable,
}

/// Leading prefix of the UEFI Runtime Services table, through
/// `QueryVariableInfo`: the six time and virtual-addressing services before
/// `GetVariable`, `GetNextVariableName`, and the four services between
/// `SetVariable` and `QueryVariableInfo` as padding. `QueryVariableInfo`,
/// which UEFI 2.0 added, lies inside a table whose header size covers it
/// alone ([`query_variable_info`]). The bootloader calls the variable
/// services before `ExitBootServices` alone ([`get_variable`],
/// [`set_variable`];
/// [`core/boot/docs/uefi-environment.md`](../docs/uefi-environment.md)
/// § Variable Services).
#[repr(C)]
pub struct EfiRuntimeServices
{
    pub hdr: EfiTableHeader,
    // GetTime, SetTime, GetWakeupTime, SetWakeupTime, SetVirtualAddressMap and
    // ConvertPointer, not used by the bootloader.
    _pad_time: [usize; 6],
    pub get_variable: unsafe extern "efiapi" fn(
        name: *const u16,
        vendor: *const EfiGuid,
        attributes: *mut u32,
        data_size: *mut usize,
        data: *mut core::ffi::c_void,
    ) -> EfiStatus,
    // GetNextVariableName, not used by the bootloader.
    _pad_next_name: usize,
    pub set_variable: unsafe extern "efiapi" fn(
        name: *const u16,
        vendor: *const EfiGuid,
        attributes: u32,
        data_size: usize,
        data: *const core::ffi::c_void,
    ) -> EfiStatus,
    // GetNextHighMonotonicCount, ResetSystem, UpdateCapsule and
    // QueryCapsuleCapabilities, not used by the bootloader.
    _pad_capsule: [usize; 4],
    pub query_variable_info: unsafe extern "efiapi" fn(
        attributes: u32,
        maximum_variable_storage_size: *mut u64,
        remaining_variable_storage_size: *mut u64,
        maximum_variable_size: *mut u64,
    ) -> EfiStatus,
}

/// A UEFI event handle.
pub type EfiEvent = *mut core::ffi::c_void;

/// A keystroke as `ReadKeyStroke` returns it: a scan code for a key with no
/// character, else the character as UTF-16.
#[repr(C)]
pub struct EfiInputKey
{
    pub scan_code: u16,
    pub unicode_char: u16,
}

/// The UEFI Simple Text Input Protocol (`ConIn`): `Reset`, `ReadKeyStroke`
/// and the `WaitForKey` event, signalled while a keystroke is waiting. The
/// bootloader reads it only to ask for the confirmation of a trust request
/// ([`read_console_line`]).
#[repr(C)]
pub struct EfiSimpleTextInput
{
    pub reset: unsafe extern "efiapi" fn(this: *mut Self, extended: EfiBool) -> EfiStatus,
    pub read_key_stroke:
        unsafe extern "efiapi" fn(this: *mut Self, key: *mut EfiInputKey) -> EfiStatus,
    pub wait_for_key: EfiEvent,
}

/// Leading function-pointer prefix of the UEFI Simple Text Output Protocol
/// (`ConOut`): `Reset`, `OutputString`, and the protocol's seven further function
/// pointers as padding; the trailing `Mode` pointer is omitted. The bootloader
/// never dereferences `EfiSystemTable::con_out`; boot output goes through the
/// console backends (see
/// [`core/boot/docs/uefi-environment.md`](../docs/uefi-environment.md) § Console Output).
#[repr(C)]
pub struct EfiSimpleTextOutput
{
    pub reset: unsafe extern "efiapi" fn(this: *mut Self, extended: EfiBool) -> EfiStatus,
    pub output_string: unsafe extern "efiapi" fn(this: *mut Self, string: *const u16) -> EfiStatus,
    // Remaining function pointers not used by the bootloader.
    _pad: [usize; 7],
}

/// UEFI descriptor for a single physical memory region returned by `GetMemoryMap`.
#[repr(C)]
pub struct EfiMemoryDescriptor
{
    pub memory_type: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

/// UEFI memory types referenced by the memory map translation and the
/// aperture derivation (`EFI_LOADER_CODE` also by
/// [`allocate_code_pages_max_addr`]).
pub const EFI_CONVENTIONAL_MEMORY: u32 = 7;
pub const EFI_LOADER_CODE: u32 = 1;
// EFI_LOADER_DATA is 2, shared with the allocation constant above.
pub const EFI_BOOT_SERVICES_CODE: u32 = 3;
pub const EFI_BOOT_SERVICES_DATA: u32 = 4;
pub const EFI_RUNTIME_SERVICES_CODE: u32 = 5;
pub const EFI_RUNTIME_SERVICES_DATA: u32 = 6;
pub const EFI_ACPI_RECLAIM_MEMORY: u32 = 9;
pub const EFI_ACPI_MEMORY_NVS: u32 = 10;
pub const EFI_MEMORY_MAPPED_IO: u32 = 11;
pub const EFI_MEMORY_MAPPED_IO_PORT_SPACE: u32 = 12;
pub const EFI_PERSISTENT_MEMORY: u32 = 14;

/// Return value from `GetMemoryMap`, bundling the key and descriptor metadata.
pub struct MemoryMapResult
{
    /// Physical address of the memory map buffer (allocated by caller).
    pub buffer_phys: u64,
    /// Allocated capacity of the buffer, in bytes. Distinct from `map_size`:
    /// `GetMemoryMap` overwrites its size in-param with the (smaller) actual map
    /// size on success, so a re-query must pass this capacity, not `map_size`.
    pub buffer_size: usize,
    /// Size of the map currently in the buffer, in bytes (the value `GetMemoryMap`
    /// reported it wrote). This is what `translate_memory_map` iterates over.
    pub map_size: usize,
    /// Map key used by `ExitBootServices`.
    pub map_key: usize,
    /// Size of each `EfiMemoryDescriptor` entry (may exceed `size_of::<EfiMemoryDescriptor>()`).
    pub descriptor_size: usize,
}

/// UEFI Boot Services table.
///
/// Only the function pointers used by the bootloader are named; the rest are
/// represented as padding `usize` fields to preserve the correct layout.
#[repr(C)]
pub struct EfiBootServices
{
    pub hdr: EfiTableHeader,

    // Task priority services (2 entries, unused)
    _tpl: [usize; 2],

    // Memory services
    pub allocate_pages: unsafe extern "efiapi" fn(
        allocate_type: u32,
        memory_type: u32,
        pages: usize,
        memory: *mut u64,
    ) -> EfiStatus,
    pub free_pages: unsafe extern "efiapi" fn(memory: u64, pages: usize) -> EfiStatus,
    pub get_memory_map: unsafe extern "efiapi" fn(
        memory_map_size: *mut usize,
        memory_map: *mut EfiMemoryDescriptor,
        map_key: *mut usize,
        descriptor_size: *mut usize,
        descriptor_version: *mut u32,
    ) -> EfiStatus,
    pub allocate_pool: unsafe extern "efiapi" fn(
        pool_type: u32,
        size: usize,
        buffer: *mut *mut core::ffi::c_void,
    ) -> EfiStatus,
    pub free_pool: unsafe extern "efiapi" fn(buffer: *mut core::ffi::c_void) -> EfiStatus,

    // Event and timer services
    pub create_event: unsafe extern "efiapi" fn(
        event_type: u32,
        notify_tpl: usize,
        notify_function: usize,
        notify_context: *mut core::ffi::c_void,
        event: *mut EfiEvent,
    ) -> EfiStatus,
    pub set_timer:
        unsafe extern "efiapi" fn(event: EfiEvent, timer_type: u32, trigger_time: u64) -> EfiStatus,
    pub wait_for_event: unsafe extern "efiapi" fn(
        number_of_events: usize,
        events: *const EfiEvent,
        index: *mut usize,
    ) -> EfiStatus,
    _signal_event: usize,
    pub close_event: unsafe extern "efiapi" fn(event: EfiEvent) -> EfiStatus,
    _check_event: usize,

    // Protocol handler services
    pub install_protocol_interface: usize,
    pub reinstall_protocol_interface: usize,
    pub uninstall_protocol_interface: usize,
    pub handle_protocol: unsafe extern "efiapi" fn(
        handle: EfiHandle,
        protocol: *const EfiGuid,
        interface: *mut *mut core::ffi::c_void,
    ) -> EfiStatus,
    _reserved: usize,
    pub register_protocol_notify: usize,
    pub locate_handle: usize,
    pub locate_device_path: unsafe extern "efiapi" fn(
        protocol: *const EfiGuid,
        device_path: *mut *mut EfiDevicePathProtocol,
        device: *mut EfiHandle,
    ) -> EfiStatus,
    pub install_configuration_table: usize,

    // Image services (LoadImage, StartImage — 2 entries, unused)
    _image: [usize; 2],

    // Image services (Exit, UnloadImage, ExitBootServices)
    pub exit: usize,
    pub unload_image: usize,
    pub exit_boot_services:
        unsafe extern "efiapi" fn(image_handle: EfiHandle, map_key: usize) -> EfiStatus,

    // Miscellaneous services
    _misc_pre: [usize; 3], // GetNextMonotonicCount, Stall, SetWatchdogTimer

    pub connect_controller: unsafe extern "efiapi" fn(
        controller_handle: EfiHandle,
        driver_image_handle: *mut EfiHandle,
        remaining_device_path: *mut core::ffi::c_void,
        recursive: EfiBool,
    ) -> EfiStatus,

    _disconnect_controller: usize,

    // Open protocol services
    pub open_protocol: unsafe extern "efiapi" fn(
        handle: EfiHandle,
        protocol: *const EfiGuid,
        interface: *mut *mut core::ffi::c_void,
        agent_handle: EfiHandle,
        controller_handle: EfiHandle,
        attributes: u32,
    ) -> EfiStatus,
    pub close_protocol: usize,
    pub open_protocol_information: usize,

    _protocols_per_handle: usize,

    pub locate_handle_buffer: unsafe extern "efiapi" fn(
        search_type: u32,
        protocol: *const EfiGuid,
        search_key: *mut core::ffi::c_void,
        no_handles: *mut usize,
        buffer: *mut *mut EfiHandle,
    ) -> EfiStatus,

    pub locate_protocol: unsafe extern "efiapi" fn(
        protocol: *const EfiGuid,
        registration: *mut core::ffi::c_void,
        interface: *mut *mut core::ffi::c_void,
    ) -> EfiStatus,
}

/// `EFI_RNG_PROTOCOL` — UEFI random number generator (UEFI specification).
///
/// Located via `LocateProtocol` using [`EFI_RNG_PROTOCOL_GUID`]. Only `GetRNG`
/// is used; `GetInfo` (the first member) is an unused slot kept as padding to
/// preserve the C member offsets.
#[repr(C)]
pub struct EfiRngProtocol
{
    /// `GetInfo` — unused here; kept as padding to preserve `get_rng`'s offset.
    pub get_info: usize,
    /// `GetRNG`: draw `value_len` random bytes into `value`. `algorithm` is
    /// optional; a null pointer selects the implementation's default algorithm.
    pub get_rng: unsafe extern "efiapi" fn(
        this: *mut EfiRngProtocol,
        algorithm: *const EfiGuid,
        value_len: usize,
        value: *mut u8,
    ) -> EfiStatus,
}

/// `EFI_LOADED_IMAGE_PROTOCOL` — provides information about the running image.
#[repr(C)]
pub struct EfiLoadedImageProtocol
{
    pub revision: u32,
    pub parent_handle: EfiHandle,
    pub system_table: *mut EfiSystemTable,
    pub device_handle: EfiHandle,
    pub file_path: *mut core::ffi::c_void,
    pub reserved: *mut core::ffi::c_void,
    pub load_options_size: u32,
    pub load_options: *mut core::ffi::c_void,
    pub image_base: *mut core::ffi::c_void,
    pub image_size: u64,
    pub image_code_type: u32,
    pub image_data_type: u32,
    pub unload: usize,
}

/// `EFI_DEVICE_PATH_PROTOCOL` — the header of a device path's first node; the
/// path's nodes follow one another to its End Entire node
/// (`crate::boot_device::path_len`).
#[repr(C)]
pub struct EfiDevicePathProtocol
{
    pub node_type: u8,
    pub sub_type: u8,
    pub length: [u8; 2],
}

/// `EFI_PCI_IO_PROTOCOL` — only `GetLocation` is named; the entries before
/// it (`PollMem`, `PollIo`, `Mem`, `Io` and `Pci` of two each, `CopyMem`,
/// `Map`, `Unmap`, `AllocateBuffer`, `FreeBuffer`, `Flush`) are padding, and
/// the table goes on past it.
#[repr(C)]
pub struct EfiPciIoProtocol
{
    _before_get_location: [usize; 14],
    pub get_location: unsafe extern "efiapi" fn(
        this: *mut Self,
        segment: *mut usize,
        bus: *mut usize,
        device: *mut usize,
        function: *mut usize,
    ) -> EfiStatus,
}

/// `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL` — opens the ESP volume.
#[repr(C)]
pub struct EfiSimpleFileSystemProtocol
{
    pub revision: u64,
    pub open_volume:
        unsafe extern "efiapi" fn(this: *mut Self, root: *mut *mut EfiFileProtocol) -> EfiStatus,
}

/// `EFI_FILE_PROTOCOL` — file I/O on the ESP.
#[repr(C)]
pub struct EfiFileProtocol
{
    pub revision: u64,
    pub open: unsafe extern "efiapi" fn(
        this: *mut Self,
        new_handle: *mut *mut EfiFileProtocol,
        file_name: *const u16,
        open_mode: u64,
        attributes: u64,
    ) -> EfiStatus,
    pub close: unsafe extern "efiapi" fn(this: *mut Self) -> EfiStatus,
    pub delete: usize,
    pub read: unsafe extern "efiapi" fn(
        this: *mut Self,
        buffer_size: *mut usize,
        buffer: *mut core::ffi::c_void,
    ) -> EfiStatus,
    pub write: usize,
    pub get_position: usize,
    pub set_position: unsafe extern "efiapi" fn(this: *mut Self, position: u64) -> EfiStatus,
    pub get_info: unsafe extern "efiapi" fn(
        this: *mut Self,
        information_type: *const EfiGuid,
        buffer_size: *mut usize,
        buffer: *mut core::ffi::c_void,
    ) -> EfiStatus,
    pub set_info: usize,
    pub flush: usize,
}

/// `EFI_FILE_INFO` — metadata returned by `EFI_FILE_PROTOCOL->GetInfo`.
///
/// `file_name` is a variable-length UTF-16 string; the struct here covers only
/// the fixed-length prefix. For size queries, only `file_size` is needed.
#[repr(C)]
pub struct EfiFileInfo
{
    pub size: u64,
    pub file_size: u64,
    pub physical_size: u64,
    pub create_time: [u8; 16],
    pub last_access_time: [u8; 16],
    pub modification_time: [u8; 16],
    pub attribute: u64,
    // Variable-length file_name (UTF-16) follows; omitted here.
}

/// Pixel format constants for GOP `pixel_format` field.
const GOP_PIXEL_RED_GREEN_BLUE_RESERVED_8BIT_PER_COLOR: u32 = 0;
const GOP_PIXEL_BLUE_GREEN_RED_RESERVED_8BIT_PER_COLOR: u32 = 1;
const GOP_PIXEL_BIT_MASK: u32 = 2;

// Standard 8bpc bitmask layouts used by `pixel_information[4]` when
// `pixel_format == GOP_PIXEL_BIT_MASK`. Map to Rgbx8 / Bgrx8 respectively.
// Any other layout is non-standard and skipped.
const BITMASK_RGBX8: [u32; 4] = [0x0000_00FF, 0x0000_FF00, 0x00FF_0000, 0xFF00_0000];
const BITMASK_BGRX8: [u32; 4] = [0x00FF_0000, 0x0000_FF00, 0x0000_00FF, 0xFF00_0000];

/// Mode info structure returned by `EFI_GRAPHICS_OUTPUT_PROTOCOL`.
#[repr(C)]
pub struct EfiGopModeInfo
{
    pub version: u32,
    pub horizontal_resolution: u32,
    pub vertical_resolution: u32,
    pub pixel_format: u32,
    pub pixel_information: [u32; 4],
    pub pixels_per_scan_line: u32,
}

/// Current mode details, embedded in `EFI_GRAPHICS_OUTPUT_PROTOCOL`.
#[repr(C)]
pub struct EfiGopMode
{
    pub max_mode: u32,
    pub mode: u32,
    pub info: *mut EfiGopModeInfo,
    pub size_of_info: usize,
    pub frame_buffer_base: u64,
    pub frame_buffer_size: usize,
}

/// `EFI_GRAPHICS_OUTPUT_PROTOCOL` — provides framebuffer information.
#[repr(C)]
pub struct EfiGraphicsOutputProtocol
{
    pub query_mode: unsafe extern "efiapi" fn(
        this: *mut Self,
        mode_number: u32,
        size_of_info: *mut usize,
        info: *mut *mut EfiGopModeInfo,
    ) -> EfiStatus,
    pub set_mode: unsafe extern "efiapi" fn(this: *mut Self, mode_number: u32) -> EfiStatus,
    pub blt: usize,
    pub mode: *mut EfiGopMode,
}

// ── UEFI open-protocol attribute ──────────────────────────────────────────────

/// `EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL` attribute for `OpenProtocol`.
const EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL: u32 = 0x0000_0001;

/// `LocateHandleBuffer` search type: return all handles in the system.
const LOCATE_ALL_HANDLES: u32 = 0;

/// `LocateHandleBuffer` search type: return handles supporting a given protocol.
const LOCATE_BY_PROTOCOL: u32 = 2;

/// Read-only file open mode.
const EFI_FILE_MODE_READ: u64 = 0x0000_0000_0000_0001;

// ── Safe wrappers ─────────────────────────────────────────────────────────────

/// Locate `EFI_LOADED_IMAGE_PROTOCOL` for the given image handle.
///
/// # Errors
/// `BootError::ProtocolNotFound` when `OpenProtocol` fails for
/// `EFI_LOADED_IMAGE_PROTOCOL`.
///
/// # Safety
/// `bs` must be a valid pointer to UEFI boot services, `image` must be a valid
/// loaded-image handle.
pub unsafe fn get_loaded_image(
    bs: *mut EfiBootServices,
    image: EfiHandle,
) -> Result<*mut EfiLoadedImageProtocol, BootError>
{
    let mut iface: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: `bs` points to valid boot services (caller contract), so the `open_protocol` entry is
    // readable.
    let open_protocol_fn = unsafe { (*bs).open_protocol };
    // SAFETY: caller guarantees bs and image are valid.
    let status = unsafe {
        open_protocol_fn(
            image,
            core::ptr::addr_of!(EFI_LOADED_IMAGE_PROTOCOL_GUID),
            core::ptr::addr_of_mut!(iface),
            image,
            core::ptr::null_mut(),
            EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL,
        )
    };
    if status != EFI_SUCCESS
    {
        return Err(BootError::ProtocolNotFound("EFI_LOADED_IMAGE_PROTOCOL"));
    }
    Ok(iface.cast::<EfiLoadedImageProtocol>())
}

/// Open the ESP root volume via `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL`.
///
/// # Errors
/// `BootError::ProtocolNotFound` when the device has no
/// `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL`, and `BootError::UefiError` carrying the
/// status when `OpenVolume` fails.
///
/// # Safety
/// `bs` must be valid boot services, `device` must be the device handle from
/// the loaded image protocol.
pub unsafe fn open_esp_volume(
    bs: *mut EfiBootServices,
    device: EfiHandle,
) -> Result<*mut EfiFileProtocol, BootError>
{
    let mut iface: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: `bs` points to valid boot services (caller contract), so the `handle_protocol` entry
    // is readable.
    let handle_protocol_fn = unsafe { (*bs).handle_protocol };
    // SAFETY: caller guarantees bs and device are valid.
    let status = unsafe {
        handle_protocol_fn(
            device,
            core::ptr::addr_of!(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID),
            core::ptr::addr_of_mut!(iface),
        )
    };
    if status != EFI_SUCCESS
    {
        return Err(BootError::ProtocolNotFound(
            "EFI_SIMPLE_FILE_SYSTEM_PROTOCOL",
        ));
    }
    let fs = iface.cast::<EfiSimpleFileSystemProtocol>();
    let mut root: *mut EfiFileProtocol = core::ptr::null_mut();
    // SAFETY: `fs` is the simple-file-system protocol returned by `handle_protocol` above, so the
    // `open_volume` entry is readable.
    let open_volume_fn = unsafe { (*fs).open_volume };
    // SAFETY: fs is a valid protocol pointer.
    let status = unsafe { open_volume_fn(fs, core::ptr::addr_of_mut!(root)) };
    if status != EFI_SUCCESS
    {
        return Err(BootError::UefiError(status));
    }
    Ok(root)
}

/// The boot ESP's GPT descriptor and its controller's PCI location, read from
/// the device path of `device`, the loaded image's device handle
/// ([boot-flow.md](../docs/boot-flow.md) § Step 1).
///
/// The descriptor is the reduction of the device's whole device path
/// (`crate::boot_device::reduce`), or the reason there is none. The location
/// is that of the deepest handle on the path with `EFI_PCI_IO_PROTOCOL`,
/// which `LocateDevicePath` finds, from its `GetLocation`; `None` when no
/// handle on the path has the protocol, a call fails, or a value lies outside
/// its PCI range. The bootloader goes on without either; vfsd, which takes the
/// boot disk from them, finds none without the descriptor (docs/storage.md
/// § GPT Role-GUID Discovery).
///
/// # Safety
/// `bs` must be valid boot services and `device` the device handle from the
/// loaded image protocol.
pub unsafe fn boot_device(
    bs: *mut EfiBootServices,
    device: EfiHandle,
) -> (
    Result<crate::boot_device::EspDescriptor, crate::boot_device::NoEsp>,
    Option<crate::boot_device::PciLocation>,
)
{
    use crate::boot_device::{NoEsp, path_len, pci_location, reduce};

    let mut iface: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: `bs` points to valid boot services (caller contract), so the `handle_protocol` entry
    // is readable.
    let handle_protocol_fn = unsafe { (*bs).handle_protocol };
    // SAFETY: caller guarantees bs and device are valid.
    let status = unsafe {
        handle_protocol_fn(
            device,
            core::ptr::addr_of!(EFI_DEVICE_PATH_PROTOCOL_GUID),
            core::ptr::addr_of_mut!(iface),
        )
    };
    if status != EFI_SUCCESS || iface.is_null()
    {
        return (Err(NoEsp::Malformed), None);
    }
    let path = iface.cast::<EfiDevicePathProtocol>();
    let base = path.cast::<u8>().cast_const();
    let len = path_len(|offset| {
        // SAFETY: the firmware's device path is a run of nodes, each at least
        // a header long, ending in an End Entire node; `path_len` asks only
        // for the header of a node it reached, which lies inside that run,
        // and no farther than `MAX_PATH_BYTES`.
        let header = unsafe { base.add(offset) };
        // SAFETY: `header` points at the node's four header bytes (above),
        // which have no alignment, so the read is unaligned.
        unsafe { core::ptr::read_unaligned(header.cast::<[u8; 4]>()) }
    });
    let esp = len.and_then(|len| {
        // SAFETY: `path_len` walked the path's nodes to its End Entire node,
        // `len` bytes from `base`; the firmware keeps the device path
        // protocol's interface, and so the path, while boot services run,
        // and this slice does not outlive this call.
        let bytes = unsafe { core::slice::from_raw_parts(base, len) };
        reduce(bytes)
    });

    let mut remaining = path;
    let mut pci_handle: EfiHandle = core::ptr::null_mut();
    // SAFETY: `bs` points to valid boot services (caller contract), so the `locate_device_path`
    // entry is readable.
    let locate_device_path_fn = unsafe { (*bs).locate_device_path };
    // SAFETY: bs is valid; `remaining` is a copy of the device's path pointer,
    // which LocateDevicePath advances past the matched prefix, leaving the
    // firmware's path itself unchanged.
    let status = unsafe {
        locate_device_path_fn(
            core::ptr::addr_of!(EFI_PCI_IO_PROTOCOL_GUID),
            core::ptr::addr_of_mut!(remaining),
            core::ptr::addr_of_mut!(pci_handle),
        )
    };
    if status != EFI_SUCCESS || pci_handle.is_null()
    {
        return (esp, None);
    }
    let mut pci_iface: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: bs is valid; pci_handle is the handle LocateDevicePath returned
    // for the PCI I/O protocol.
    let status = unsafe {
        handle_protocol_fn(
            pci_handle,
            core::ptr::addr_of!(EFI_PCI_IO_PROTOCOL_GUID),
            core::ptr::addr_of_mut!(pci_iface),
        )
    };
    if status != EFI_SUCCESS || pci_iface.is_null()
    {
        return (esp, None);
    }
    let pci_io = pci_iface.cast::<EfiPciIoProtocol>();
    let (mut segment, mut bus, mut dev, mut function) = (0usize, 0usize, 0usize, 0usize);
    // SAFETY: `pci_io` is the PCI I/O protocol HandleProtocol returned, so
    // the `get_location` entry is readable.
    let get_location_fn = unsafe { (*pci_io).get_location };
    // SAFETY: pci_io is a valid PCI I/O protocol; the four outputs are live
    // locals.
    let status = unsafe {
        get_location_fn(
            pci_io,
            core::ptr::addr_of_mut!(segment),
            core::ptr::addr_of_mut!(bus),
            core::ptr::addr_of_mut!(dev),
            core::ptr::addr_of_mut!(function),
        )
    };
    if status != EFI_SUCCESS
    {
        return (esp, None);
    }
    (esp, pci_location(segment, bus, dev, function))
}

/// Open a file on the ESP by path.
///
/// `path` must be a UEFI-style path with backslash separators, encoded as a
/// null-terminated UTF-16 slice.
///
/// # Errors
/// `BootError::FileNotFound` carrying `name` when `Open` fails.
///
/// # Safety
/// `root` must be a valid `EFI_FILE_PROTOCOL` handle pointing to the ESP root.
pub unsafe fn open_file(
    root: *mut EfiFileProtocol,
    path: *const u16,
    name: &'static str,
) -> Result<*mut EfiFileProtocol, BootError>
{
    let mut file: *mut EfiFileProtocol = core::ptr::null_mut();
    // SAFETY: `root` is a valid file protocol (caller contract), so the `open` entry is readable.
    let open_fn = unsafe { (*root).open };
    // SAFETY: root is valid; path is a null-terminated UTF-16 string.
    let status = unsafe {
        open_fn(
            root,
            core::ptr::addr_of_mut!(file),
            path,
            EFI_FILE_MODE_READ,
            0,
        )
    };
    if status != EFI_SUCCESS
    {
        return Err(BootError::FileNotFound(name));
    }
    Ok(file)
}

/// Byte length of [`FileInfoBuf`]: an `EfiFileInfo` plus room for a short
/// UTF-16 file name. Provably sufficient: [`file_size`] queries only the
/// bootloader's own fixed ESP files (`kernel`, `bootstrap.bundle`), far below
/// 128 UTF-16 units, and a longer name fails the call rather than truncating.
const FILE_INFO_BUF_LEN: usize = core::mem::size_of::<EfiFileInfo>() + 256;

/// Receive buffer for `GetInfo(EFI_FILE_INFO_ID)`, aligned so its filled
/// `EfiFileInfo` prefix can be read in place through an aligned pointer.
#[repr(C, align(8))]
struct FileInfoBuf([u8; FILE_INFO_BUF_LEN]);

// `file_size` reads the `EfiFileInfo` prefix through a pointer to the buffer,
// which is sound only while the buffer is at least as aligned as the struct.
const _: () = assert!(core::mem::align_of::<FileInfoBuf>() >= core::mem::align_of::<EfiFileInfo>());

/// Query the file size in bytes using `EFI_FILE_INFO`.
///
/// # Errors
/// `BootError::UefiError` carrying the status when `GetInfo` fails.
///
/// # Safety
/// `file` must be a valid open `EFI_FILE_PROTOCOL` handle.
pub unsafe fn file_size(file: *mut EfiFileProtocol) -> Result<u64, BootError>
{
    // First call: get required buffer size.
    let mut info_size: usize = 0;
    // SAFETY: `file` is a valid file protocol (caller contract), so the `get_info` entry is
    // readable.
    let get_info_fn = unsafe { (*file).get_info };
    // SAFETY: file is valid; passing null buffer with zero size requests the required size.
    let status = unsafe {
        get_info_fn(
            file,
            core::ptr::addr_of!(EFI_FILE_INFO_ID),
            core::ptr::addr_of_mut!(info_size),
            core::ptr::null_mut(),
        )
    };
    // BUFFER_TOO_SMALL is the expected return when querying the required size.
    if status != EFI_BUFFER_TOO_SMALL && status != EFI_SUCCESS
    {
        return Err(BootError::UefiError(status));
    }

    // Stack-allocate a buffer large enough for EfiFileInfo plus a short name.
    let mut buf = FileInfoBuf([0u8; FILE_INFO_BUF_LEN]);
    let mut buf_size = FILE_INFO_BUF_LEN;
    // SAFETY: `file` is a valid file protocol (caller contract), so the `get_info` entry is
    // readable.
    let get_info_fn = unsafe { (*file).get_info };
    // SAFETY: buf is FILE_INFO_BUF_LEN writable bytes; file is valid.
    let status = unsafe {
        get_info_fn(
            file,
            core::ptr::addr_of!(EFI_FILE_INFO_ID),
            core::ptr::addr_of_mut!(buf_size),
            core::ptr::from_mut(&mut buf).cast::<core::ffi::c_void>(),
        )
    };
    if status != EFI_SUCCESS
    {
        return Err(BootError::UefiError(status));
    }

    // SAFETY: `get_info` succeeded, so `buf` starts with a filled
    // `EfiFileInfo`, whose plain-integer fields are valid for any bytes. The
    // pointer is aligned for `EfiFileInfo` because `FileInfoBuf` carries at
    // least its alignment (the const assertion on `FileInfoBuf`), and the
    // buffer is larger than `EfiFileInfo`, so the read stays in bounds.
    let info = unsafe { &*core::ptr::from_ref(&buf).cast::<EfiFileInfo>() };
    Ok(info.file_size)
}

/// Read bytes from a file into a caller-provided buffer.
///
/// Reads exactly `buffer.len()` bytes starting from the current file position.
///
/// # Errors
/// `BootError::UefiError` carrying the status when `Read` fails.
///
/// # Safety
/// `file` must be a valid open `EFI_FILE_PROTOCOL` handle. The file's current
/// position must be set appropriately before calling.
pub unsafe fn file_read(file: *mut EfiFileProtocol, buffer: &mut [u8]) -> Result<(), BootError>
{
    let mut size = buffer.len();
    // SAFETY: `file` is a valid file protocol (caller contract), so the `read` entry is readable.
    // SAFETY: con_in is the firmware's ConIn, valid before ExitBootServices (caller contract).
    let read_fn = unsafe { (*file).read };
    // SAFETY: file is valid; buffer is a valid writable slice.
    let status = unsafe {
        read_fn(
            file,
            core::ptr::addr_of_mut!(size),
            buffer.as_mut_ptr().cast::<core::ffi::c_void>(),
        )
    };
    if status != EFI_SUCCESS
    {
        return Err(BootError::UefiError(status));
    }
    Ok(())
}

/// Allocate `count` pages at any available physical address.
///
/// Returns the physical address of the allocated region. Uses `EfiLoaderData`
/// memory type so the region appears as `Loaded` in the boot protocol memory map.
///
/// # Errors
/// `BootError::OutOfMemory` when `AllocatePages` fails.
///
/// # Safety
/// `bs` must be a valid pointer to UEFI boot services (before `ExitBootServices`).
pub unsafe fn allocate_pages(bs: *mut EfiBootServices, count: usize) -> Result<u64, BootError>
{
    let mut addr: u64 = 0;
    // SAFETY: `bs` points to valid boot services (caller contract), so the `allocate_pages` entry
    // is readable.
    let allocate_pages_fn = unsafe { (*bs).allocate_pages };
    // SAFETY: bs is valid; addr is an output parameter.
    let status = unsafe {
        allocate_pages_fn(
            ALLOCATE_ANY_PAGES,
            EFI_LOADER_DATA,
            count,
            core::ptr::addr_of_mut!(addr),
        )
    };
    if status != EFI_SUCCESS
    {
        return Err(BootError::OutOfMemory);
    }
    Ok(addr)
}

/// Allocate `count` pages lying wholly at or below the `max_phys` physical
/// address.
///
/// Uses `AllocateMaxAddress` UEFI policy: the allocator picks any available
/// range whose uppermost address is ≤ `max_phys`. The firmware's `Memory`
/// argument is in-out: it is seeded with `max_phys`, and on success it holds
/// the allocated physical base, which this function returns.
///
/// This is the arch-neutral UEFI wrapper. Its callers are x86-64's
/// `arch::current::allocate_ap_trampoline`, whose SIPI-vector constraint
/// requires a frame below 1 MiB, x86-64's
/// `arch::current::allocate_kernel_span`, which keeps the kernel image below
/// 4 GiB, and the x86-64 boot page-table frame pool, whose first frame is the
/// root the LA57 toggle trampoline loads with a 32-bit move; the helper is not
/// gated on architecture because `AllocateMaxAddress` is part of the UEFI spec
/// on every supported platform.
///
/// # Errors
/// `BootError::OutOfMemory` when `AllocatePages` fails.
///
/// # Safety
/// `bs` must be valid boot services.
#[cfg_attr(
    target_arch = "riscv64",
    expect(
        dead_code,
        reason = "only the x86-64 `arch::current` allocation hooks call it, so riscv64 has no \
                  caller"
    )
)]
pub unsafe fn allocate_pages_max_addr(
    bs: *mut EfiBootServices,
    max_phys: u64,
    count: usize,
) -> Result<u64, BootError>
{
    // SAFETY: forwarded caller contract.
    unsafe { allocate_typed_max_addr(bs, EFI_LOADER_DATA, max_phys, count) }
}

/// Allocate `count` pages of `EfiLoaderCode` lying wholly at or below the
/// `max_phys` physical address.
///
/// The firmware's NX policy (`PcdDxeNxMemoryProtectionPolicy`) may map
/// `EfiLoaderData` pages non-executable under its own tables, never
/// `EfiLoaderCode` ones, so code the bootloader runs under those tables
/// from an allocated page (the x86-64 LA57 toggle trampoline) needs this type.
/// The region appears as `Loaded` in the boot protocol memory map.
///
/// # Errors
/// `BootError::OutOfMemory` when `AllocatePages` fails.
///
/// # Safety
/// `bs` must be valid boot services.
#[cfg_attr(
    any(target_arch = "riscv64", test),
    expect(
        dead_code,
        reason = "only the x86-64 LA57 toggle installation calls it, so riscv64 has no caller, \
                  and host tests compile that installation with no caller"
    )
)]
pub unsafe fn allocate_code_pages_max_addr(
    bs: *mut EfiBootServices,
    max_phys: u64,
    count: usize,
) -> Result<u64, BootError>
{
    // SAFETY: forwarded caller contract.
    unsafe { allocate_typed_max_addr(bs, EFI_LOADER_CODE, max_phys, count) }
}

/// `AllocatePages(AllocateMaxAddress, memory_type, count)` with the address
/// seeded to `max_phys`; returns the allocated physical base.
///
/// # Safety
/// `bs` must be valid boot services.
#[cfg_attr(
    target_arch = "riscv64",
    expect(
        dead_code,
        reason = "only the x86-64 max-address wrappers call it, so riscv64 has no caller"
    )
)]
unsafe fn allocate_typed_max_addr(
    bs: *mut EfiBootServices,
    memory_type: u32,
    max_phys: u64,
    count: usize,
) -> Result<u64, BootError>
{
    let mut addr: u64 = max_phys;
    // SAFETY: `bs` points to valid boot services (caller contract), so the `allocate_pages` entry
    // is readable.
    let allocate_pages_fn = unsafe { (*bs).allocate_pages };
    // SAFETY: bs is valid; addr is an in-out parameter.
    let status = unsafe {
        allocate_pages_fn(
            ALLOCATE_MAX_ADDRESS,
            memory_type,
            count,
            core::ptr::addr_of_mut!(addr),
        )
    };
    if status != EFI_SUCCESS
    {
        return Err(BootError::OutOfMemory);
    }
    Ok(addr)
}

/// Return `count` pages at `phys` to the firmware with `FreePages`.
///
/// # Errors
/// `BootError::UefiError` carrying the status when the firmware rejects the
/// call (the range was not allocated by `AllocatePages`, or is misaligned).
///
/// # Safety
/// `bs` must be valid boot services (before `ExitBootServices`). The range
/// must be one this bootloader allocated and must not be accessed again.
pub unsafe fn free_pages(bs: *mut EfiBootServices, phys: u64, count: usize)
-> Result<(), BootError>
{
    // SAFETY: `bs` points to valid boot services (caller contract), so the `free_pages` entry is
    // readable.
    let free_pages_fn = unsafe { (*bs).free_pages };
    // SAFETY: bs is valid; the range is an allocation the caller owns.
    let status = unsafe { free_pages_fn(phys, count) };
    if status != EFI_SUCCESS
    {
        return Err(BootError::UefiError(status));
    }
    Ok(())
}

/// Check a descriptor size the firmware reported: a stride below
/// `EFI_MEMORY_DESCRIPTOR`'s would make every reader of the map read past each
/// descriptor and, at the last stride, past the map.
///
/// # Errors
/// [`BootError::InvalidMemoryMap`] for a size below the descriptor's.
pub fn check_descriptor_size(descriptor_size: usize) -> Result<(), BootError>
{
    if descriptor_size < core::mem::size_of::<EfiMemoryDescriptor>()
    {
        return Err(BootError::InvalidMemoryMap(
            "descriptor size below EFI_MEMORY_DESCRIPTOR",
        ));
    }
    Ok(())
}

/// The `(map_size, descriptor_size)` the firmware's memory map needs now, from
/// the size query `GetMemoryMap` answers with a null buffer; nothing is
/// allocated.
///
/// # Safety
/// `bs` must be valid boot services.
unsafe fn query_memory_map_size(bs: *mut EfiBootServices) -> Result<(usize, usize), BootError>
{
    let mut map_size: usize = 0;
    let mut map_key: usize = 0;
    let mut descriptor_size: usize = 0;
    let mut descriptor_version: u32 = 0;
    // SAFETY: `bs` points to valid boot services (caller contract), so the `get_memory_map` entry
    // is readable.
    let get_memory_map_fn = unsafe { (*bs).get_memory_map };
    // SAFETY: Null map pointer with zero size requests the required size.
    let status = unsafe {
        get_memory_map_fn(
            core::ptr::addr_of_mut!(map_size),
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(map_key),
            core::ptr::addr_of_mut!(descriptor_size),
            core::ptr::addr_of_mut!(descriptor_version),
        )
    };
    // EFI_BUFFER_TOO_SMALL is the expected result when querying the size.
    if status != EFI_BUFFER_TOO_SMALL && status != EFI_SUCCESS
    {
        return Err(BootError::UefiError(status));
    }
    Ok((map_size, descriptor_size))
}

/// Descriptors of slack [`get_memory_map`]'s buffer carries above the map the
/// size query reports: the buffer's own allocation adds at least one, and the
/// rest absorbs growth before the fill and in `ExitBootServices`' re-query.
pub const MAP_BUFFER_SLACK_DESCRIPTORS: usize = 16;

/// Bytes of the buffer [`get_memory_map`] allocates for a map of `map_bytes`
/// at a stride of `descriptor_size`: the map plus
/// [`MAP_BUFFER_SLACK_DESCRIPTORS`] descriptors, rounded up to whole pages.
pub const fn map_buffer_bytes(map_bytes: usize, descriptor_size: usize) -> usize
{
    // A map too large to size saturates, which no allocation satisfies.
    map_bytes
        .saturating_add(MAP_BUFFER_SLACK_DESCRIPTORS.saturating_mul(descriptor_size))
        .div_ceil(4096)
        .saturating_mul(4096)
}

/// Most descriptors a map buffer of `buffer_bytes` can hold at any stride
/// [`check_descriptor_size`] accepts, the smallest being
/// `EFI_MEMORY_DESCRIPTOR`'s: the bound on every map read into it, the
/// `ExitBootServices` re-query's included, since that re-query writes into
/// the same buffer.
pub const fn map_buffer_descriptor_reach(buffer_bytes: usize) -> usize
{
    match buffer_bytes.checked_div(core::mem::size_of::<EfiMemoryDescriptor>())
    {
        Some(reach) => reach,
        // `EfiMemoryDescriptor` is not zero-sized; no descriptor fits a zero size.
        None => 0,
    }
}

/// The firmware's memory map now, as `(descriptor count, descriptor size)`
/// ([`query_memory_map_size`]); nothing is allocated.
///
/// # Errors
/// Returns `BootError::UefiError` when the query fails, and
/// `BootError::InvalidMemoryMap` when it reports a descriptor size below
/// `EFI_MEMORY_DESCRIPTOR`'s.
///
/// # Safety
/// `bs` must be valid boot services.
pub unsafe fn memory_map_shape(bs: *mut EfiBootServices) -> Result<(usize, usize), BootError>
{
    // SAFETY: forwarded caller contract.
    let (map_size, descriptor_size) = unsafe { query_memory_map_size(bs)? };
    check_descriptor_size(descriptor_size)?;
    let count = map_size
        .checked_div(descriptor_size)
        .ok_or(BootError::InvalidMemoryMap("descriptor size is zero"))?;
    Ok((count, descriptor_size))
}

/// Query the UEFI memory map into a freshly allocated buffer sized with
/// [`MAP_BUFFER_SLACK_DESCRIPTORS`] descriptors of slack
/// ([`map_buffer_bytes`]). Returns the buffer address and capacity, map size,
/// map key, and descriptor size. The acquisition protocol (key invalidation,
/// final-allocation ordering, slack sizing) is specified in
/// [`core/boot/docs/uefi-environment.md`](../docs/uefi-environment.md) § Memory Map Acquisition.
///
/// # Errors
/// Returns `BootError::UefiError` when the size query or the fill call fails,
/// `BootError::OutOfMemory` when the buffer cannot be allocated, and
/// `BootError::InvalidMemoryMap` when the fill call reports a descriptor size
/// below `EFI_MEMORY_DESCRIPTOR`'s.
///
/// # Safety
/// `bs` must be valid boot services.
pub unsafe fn get_memory_map(bs: *mut EfiBootServices) -> Result<MemoryMapResult, BootError>
{
    // First call: obtain required buffer size.
    // SAFETY: bs is valid (caller contract).
    let (mut map_size, mut descriptor_size) = unsafe { query_memory_map_size(bs)? };
    let mut map_key: usize = 0;
    let mut descriptor_version: u32 = 0;

    // Slack for the buffer allocation itself (which creates one new entry).
    let buffer_size = map_buffer_bytes(map_size, descriptor_size);
    // SAFETY: bs is valid.
    let buffer_phys = unsafe { allocate_pages(bs, buffer_size / 4096)? };

    // Second call: fill the buffer. This call's map_key is the one to use.
    map_size = buffer_size;
    // SAFETY: `bs` points to valid boot services (caller contract), so the `get_memory_map` entry
    // is readable.
    let get_memory_map_fn = unsafe { (*bs).get_memory_map };
    // SAFETY: buffer_phys is a valid allocated region of map_size bytes.
    let status = unsafe {
        get_memory_map_fn(
            core::ptr::addr_of_mut!(map_size),
            buffer_phys as *mut EfiMemoryDescriptor,
            core::ptr::addr_of_mut!(map_key),
            core::ptr::addr_of_mut!(descriptor_size),
            core::ptr::addr_of_mut!(descriptor_version),
        )
    };
    if status != EFI_SUCCESS
    {
        return Err(BootError::UefiError(status));
    }
    check_descriptor_size(descriptor_size)?;

    Ok(MemoryMapResult {
        buffer_phys,
        buffer_size,
        map_size,
        map_key,
        descriptor_size,
    })
}

/// Maximum number of `ExitBootServices` attempts before giving up. The
/// stale-key failure this bounds, and why one retry is insufficient, are
/// specified in
/// [`core/boot/docs/uefi-environment.md`](../docs/uefi-environment.md) § `ExitBootServices`.
///
/// The observed two-attempt failure rate (≈0.2–1.7%) implies a per-attempt
/// failure probability of roughly 0.045–0.13; 16 attempts drive the residual
/// below ~1e-14 even at the high end, with wide margin for correlated
/// contention bursts. Each extra attempt is one cheap firmware call pair into
/// the existing buffer, so the bound is generous rather than tuned.
const EXIT_BOOT_SERVICES_MAX_ATTEMPTS: u32 = 16;

/// Call `ExitBootServices`, retrying on stale-key failure up to
/// [`EXIT_BOOT_SERVICES_MAX_ATTEMPTS`] times.
///
/// After a successful call, UEFI boot services are permanently unavailable.
/// No UEFI calls may be made after this function returns `Ok(())`.
///
/// The retry protocol (re-query into the existing buffer at its full
/// capacity, then retry) is specified in
/// [`core/boot/docs/uefi-environment.md`](../docs/uefi-environment.md) § `ExitBootServices`.
///
/// # Errors
/// `BootError::ExitBootServicesFailed` for a status other than a stale key,
/// a failed re-query, or a stale key on every attempt; and
/// `BootError::InvalidMemoryMap` when a re-query reports a descriptor size
/// below `EFI_MEMORY_DESCRIPTOR`'s.
///
/// # Safety
/// `bs` must be valid boot services. `image` must be a valid image handle.
/// `map` must be a `MemoryMapResult` from the most recent `get_memory_map` call.
/// No UEFI calls may be made between the last `get_memory_map` and this call.
pub unsafe fn exit_boot_services(
    bs: *mut EfiBootServices,
    image: EfiHandle,
    map: &mut MemoryMapResult,
) -> Result<(), BootError>
{
    let mut attempt: u32 = 0;
    loop
    {
        // SAFETY: `bs` points to valid boot services (caller contract), so the `exit_boot_services`
        // entry is readable.
        let exit_boot_services_fn = unsafe { (*bs).exit_boot_services };
        // SAFETY: bs, image, and map_key are valid.
        let status = unsafe { exit_boot_services_fn(image, map.map_key) };
        if status == EFI_SUCCESS
        {
            return Ok(());
        }
        // EFI_INVALID_PARAMETER is the only status that means "stale key"; any
        // other status is a genuine error that a retry cannot resolve.
        if status != EFI_INVALID_PARAMETER
        {
            return Err(BootError::ExitBootServicesFailed);
        }
        // `attempt` is below `EXIT_BOOT_SERVICES_MAX_ATTEMPTS` here, so it cannot overflow.
        attempt = attempt.saturating_add(1);
        if attempt >= EXIT_BOOT_SERVICES_MAX_ATTEMPTS
        {
            return Err(BootError::ExitBootServicesFailed);
        }

        // Stale key: re-query per the retry protocol in the rustdoc above;
        // `map_size` is reset to `buffer_size` because GetMemoryMap overwrote it.
        let mut descriptor_size: usize = map.descriptor_size;
        let mut descriptor_version: u32 = 0;
        let mut map_size = map.buffer_size;
        // SAFETY: `bs` points to valid boot services (caller contract), so the `get_memory_map`
        // entry is readable.
        let get_memory_map_fn = unsafe { (*bs).get_memory_map };
        // SAFETY: buffer_phys is the existing allocated buffer of buffer_size bytes.
        let status = unsafe {
            get_memory_map_fn(
                core::ptr::addr_of_mut!(map_size),
                map.buffer_phys as *mut EfiMemoryDescriptor,
                core::ptr::addr_of_mut!(map.map_key),
                core::ptr::addr_of_mut!(descriptor_size),
                core::ptr::addr_of_mut!(descriptor_version),
            )
        };
        if status != EFI_SUCCESS
        {
            return Err(BootError::ExitBootServicesFailed);
        }
        // The re-query rewrote the map body at the stride it reports, which is
        // the one the body must be read at.
        check_descriptor_size(descriptor_size)?;
        map.map_size = map_size;
        map.descriptor_size = descriptor_size;
    }
}

/// Framebuffer resolution the bootloader requests from GOP at boot; the
/// fixed-mode policy is specified in
/// [`core/boot/docs/uefi-environment.md`](../docs/uefi-environment.md) § UEFI Protocol Usage.
/// 1280x720 (720p) is present in both arches' std VGA GOP mode table
/// (`QemuVideoDxe`). The request is best-effort policy and bounds no
/// capacity: without a matching mode the firmware's current mode is kept.
const TARGET_FB_WIDTH: u32 = 1280;
const TARGET_FB_HEIGHT: u32 = 720;

/// Classify a GOP mode's pixel layout as a supported [`PixelFormat`].
///
/// Returns `None` for layouts the framebuffer console cannot consume:
/// `PixelBltOnly` (no linear buffer) or a `PixelBitMask` whose channel masks
/// are neither of the two standard 8bpc RGBX / BGRX layouts.
fn classify_pixel_format(info: &EfiGopModeInfo) -> Option<PixelFormat>
{
    if info.pixel_format == GOP_PIXEL_RED_GREEN_BLUE_RESERVED_8BIT_PER_COLOR
    {
        Some(PixelFormat::Rgbx8)
    }
    else if info.pixel_format == GOP_PIXEL_BLUE_GREEN_RED_RESERVED_8BIT_PER_COLOR
    {
        Some(PixelFormat::Bgrx8)
    }
    else if info.pixel_format == GOP_PIXEL_BIT_MASK
    {
        let masks = info.pixel_information;
        if masks == BITMASK_RGBX8
        {
            Some(PixelFormat::Rgbx8)
        }
        else if masks == BITMASK_BGRX8
        {
            Some(PixelFormat::Bgrx8)
        }
        else
        {
            None
        }
    }
    else
    {
        None
    }
}

/// Request [`TARGET_FB_WIDTH`]×[`TARGET_FB_HEIGHT`] on `gop`, best-effort.
///
/// Scans the GOP mode list; on the first mode that matches the target
/// resolution with a console-supported pixel format, issues `SetMode` unless
/// it is already active. Any `QueryMode` / `SetMode` failure — or no match —
/// leaves the firmware's current mode in place; the caller then hands off
/// whatever mode is active. `QueryMode` allocates each info buffer from pool,
/// so every successful query is paired with a `FreePool`.
///
/// # Safety
/// `bs` must be valid boot services; `gop` must point to a valid
/// `EFI_GRAPHICS_OUTPUT_PROTOCOL` whose `mode` is populated by firmware.
unsafe fn set_target_mode(bs: *mut EfiBootServices, gop: *mut EfiGraphicsOutputProtocol)
{
    // SAFETY: `gop` is valid (caller contract), so its `mode` field is readable.
    let mode = unsafe { (*gop).mode };
    // SAFETY: Firmware populates `mode` for a valid GOP instance, so `max_mode` is readable.
    let max_mode = unsafe { (*mode).max_mode };
    // SAFETY: Firmware populates `mode` for a valid GOP instance, so its current mode number is
    // readable.
    let current = unsafe { (*mode).mode };

    for i in 0..max_mode
    {
        let mut size: usize = 0;
        let mut info: *mut EfiGopModeInfo = core::ptr::null_mut();
        // SAFETY: `gop` is valid (caller contract), so the `query_mode` entry is readable.
        let query_mode_fn = unsafe { (*gop).query_mode };
        // SAFETY: gop is valid; query_mode writes size/info on success.
        let status = unsafe {
            query_mode_fn(
                gop,
                i,
                core::ptr::addr_of_mut!(size),
                core::ptr::addr_of_mut!(info),
            )
        };
        if status != EFI_SUCCESS || info.is_null()
        {
            continue;
        }

        let is_target = {
            // SAFETY: query_mode populated info on success.
            let mode_info = unsafe { &*info };
            mode_info.horizontal_resolution == TARGET_FB_WIDTH
                && mode_info.vertical_resolution == TARGET_FB_HEIGHT
                && classify_pixel_format(mode_info).is_some()
        };

        // SAFETY: `bs` points to valid boot services (caller contract), so the `free_pool` entry is
        // readable.
        let free_pool_fn = unsafe { (*bs).free_pool };
        // QueryMode allocated the info buffer from pool; release it before the
        // next iteration regardless of match.
        // SAFETY: info came from query_mode and is unused after this point.
        unsafe {
            free_pool_fn(info.cast::<core::ffi::c_void>());
        }

        if is_target
        {
            if i != current
            {
                // SAFETY: `gop` is valid (caller contract), so the `set_mode` entry is readable.
                let set_mode_fn = unsafe { (*gop).set_mode };
                // SAFETY: gop is valid; i < max_mode is a valid mode number.
                let _ = unsafe { set_mode_fn(gop, i) };
            }
            return;
        }
    }
}

/// Locate a usable `EFI_GRAPHICS_OUTPUT_PROTOCOL` and return framebuffer information.
///
/// Enumerates all handles supporting GOP via `LocateHandleBuffer(ByProtocol)` and
/// returns the first that exposes a linear framebuffer with a supported pixel format
/// (RGBX or BGRX). Handles reporting `PixelBltOnly` (format 3, no physical address)
/// are skipped, as are `PixelBitMask` (format 2) layouts other than the standard
/// 8bpc RGBX / BGRX masks (see `classify_pixel_format`).
///
/// Returns `None` if no usable GOP handle exists; the meaning of an absent
/// framebuffer is specified in
/// [`core/boot/docs/console.md`](../docs/console.md) § Best-Effort Discovery.
///
/// # Safety
/// `bs` must be valid boot services.
pub unsafe fn query_gop(bs: *mut EfiBootServices) -> Option<FramebufferInfo>
{
    let mut count: usize = 0;
    let mut handles: *mut EfiHandle = core::ptr::null_mut();

    // SAFETY: `bs` points to valid boot services (caller contract), so the `locate_handle_buffer`
    // entry is readable.
    let locate_handle_buffer_fn = unsafe { (*bs).locate_handle_buffer };
    // SAFETY: bs is valid; ByProtocol with the GOP GUID returns all GOP handles.
    let status = unsafe {
        locate_handle_buffer_fn(
            LOCATE_BY_PROTOCOL,
            core::ptr::addr_of!(EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID),
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(count),
            core::ptr::addr_of_mut!(handles),
        )
    };
    if status != EFI_SUCCESS || handles.is_null()
    {
        return None;
    }

    let mut result: Option<FramebufferInfo> = None;

    for i in 0..count
    {
        // SAFETY: `i < count`, so the offset stays inside the `count`-entry array
        // `LocateHandleBuffer` returned.
        let slot = unsafe { handles.add(i) };
        // SAFETY: `slot` is inside that array, which holds initialised handles.
        let handle = unsafe { *slot };
        let mut iface: *mut core::ffi::c_void = core::ptr::null_mut();
        // SAFETY: `bs` points to valid boot services (caller contract), so the `handle_protocol`
        // entry is readable.
        let handle_protocol_fn = unsafe { (*bs).handle_protocol };
        // SAFETY: bs is valid; handle is from the LocateHandleBuffer result.
        let s = unsafe {
            handle_protocol_fn(
                handle,
                core::ptr::addr_of!(EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID),
                core::ptr::addr_of_mut!(iface),
            )
        };
        if s != EFI_SUCCESS || iface.is_null()
        {
            continue;
        }
        let gop = iface.cast::<EfiGraphicsOutputProtocol>();
        // Request the target mode before reading the active one, so the
        // framebuffer (and the QEMU window) is the same size on both arches.
        // Best-effort: on failure the firmware's current mode is kept.
        // SAFETY: bs is valid; gop is a valid GOP protocol pointer.
        unsafe {
            set_target_mode(bs, gop);
        }

        // SAFETY: `gop` is a valid protocol pointer, so its `mode` field is readable.
        let mode_ptr = unsafe { (*gop).mode };
        // SAFETY: gop is a valid protocol pointer; mode/info are populated by
        // firmware and reflect the now-active mode.
        let mode = unsafe { &*mode_ptr };
        // SAFETY: mode.info is populated by firmware.
        let info = unsafe { &*mode.info };

        let Some(pixel_format) = classify_pixel_format(info)
        else
        {
            continue;
        };

        if mode.frame_buffer_base == 0
        {
            continue;
        }

        // Four bytes per pixel; a scan line too wide for `u32` bytes is no usable mode.
        let Some(stride) = info.pixels_per_scan_line.checked_mul(4)
        else
        {
            continue;
        };

        result = Some(FramebufferInfo {
            physical_base: mode.frame_buffer_base,
            width: info.horizontal_resolution,
            height: info.vertical_resolution,
            stride,
            pixel_format,
        });
        break;
    }

    // SAFETY: `bs` points to valid boot services (caller contract), so the `free_pool` entry is
    // readable.
    let free_pool_fn = unsafe { (*bs).free_pool };
    // SAFETY: handles was allocated by LocateHandleBuffer; must be freed with FreePool.
    unsafe {
        free_pool_fn(handles.cast::<core::ffi::c_void>());
    }

    result
}

/// Connect drivers to all handles in the system.
///
/// Enumerates every handle via `LocateHandleBuffer(AllHandles)` and calls
/// `ConnectController(handle, NULL, NULL, TRUE)` on each. This forces EDK2
/// to bind device drivers (e.g. virtio-gpu → GOP) that aren't auto-connected
/// during BDS on some platforms (notably RISC-V).
///
/// Failures are silently ignored — individual handles may legitimately fail
/// to connect. The handle buffer is freed before returning.
///
/// # Safety
/// `bs` must be a valid pointer to UEFI boot services.
pub unsafe fn connect_all_controllers(bs: *mut EfiBootServices)
{
    let mut count: usize = 0;
    let mut handles: *mut EfiHandle = core::ptr::null_mut();

    // SAFETY: `bs` points to valid boot services (caller contract), so the `locate_handle_buffer`
    // entry is readable.
    let locate_handle_buffer_fn = unsafe { (*bs).locate_handle_buffer };
    // SAFETY: bs is valid; NULL protocol + NULL key with AllHandles returns all handles.
    let status = unsafe {
        locate_handle_buffer_fn(
            LOCATE_ALL_HANDLES,
            core::ptr::null(),
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(count),
            core::ptr::addr_of_mut!(handles),
        )
    };
    if status != EFI_SUCCESS || handles.is_null()
    {
        return;
    }

    for i in 0..count
    {
        // SAFETY: `i < count`, so the offset stays inside the `count`-entry array
        // `LocateHandleBuffer` returned.
        let slot = unsafe { handles.add(i) };
        // SAFETY: `slot` is inside that array, which holds initialised handles.
        let handle = unsafe { *slot };
        // SAFETY: `bs` points to valid boot services (caller contract), so the `connect_controller`
        // entry is readable.
        let connect_controller_fn = unsafe { (*bs).connect_controller };
        // SAFETY: recursive=TRUE (1) connects all child controllers.
        // Errors are expected for handles with no bindable drivers.
        unsafe {
            connect_controller_fn(
                handle,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                1, // TRUE — recursive
            );
        }
    }

    // SAFETY: `bs` points to valid boot services (caller contract), so the `free_pool` entry is
    // readable.
    let free_pool_fn = unsafe { (*bs).free_pool };
    // SAFETY: handles was allocated by LocateHandleBuffer; must be freed.
    unsafe {
        free_pool_fn(handles.cast::<core::ffi::c_void>());
    }
}

/// What `GetVariable` returned for one variable ([`get_variable`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VariableRead
{
    /// The variable exists: its `len` bytes are at the start of the buffer,
    /// and it carries `attributes`.
    Found
    {
        len: usize, attributes: u32
    },
    /// No variable of that name exists under that GUID.
    NotFound,
    /// The variable holds `len` bytes, more than the buffer: none was read.
    TooLarge
    {
        len: usize
    },
    /// The read failed with this status: the firmware has no variable
    /// services, or its store failed.
    Failed(EfiStatus),
}

/// Classify a `GetVariable` call into a buffer of `capacity` bytes that
/// returned `status`, `data_size` and `attributes`. A success that reports
/// more bytes than the buffer holds breaks the UEFI contract, and is read as
/// a variable too large for it.
pub const fn classify_variable_read(
    status: EfiStatus,
    data_size: usize,
    attributes: u32,
    capacity: usize,
) -> VariableRead
{
    match status
    {
        EFI_SUCCESS if data_size <= capacity => VariableRead::Found {
            len: data_size,
            attributes,
        },
        EFI_SUCCESS | EFI_BUFFER_TOO_SMALL => VariableRead::TooLarge { len: data_size },
        EFI_NOT_FOUND => VariableRead::NotFound,
        other => VariableRead::Failed(other),
    }
}

/// Whether `name` is a variable name UEFI takes: UTF-16 that ends in its
/// one NUL.
fn variable_name_is_terminated(name: &[u16]) -> bool
{
    match name.split_last()
    {
        Some((&0, rest)) => !rest.contains(&0),
        _ => false,
    }
}

/// Read the variable `name` (NUL-terminated UTF-16) under `vendor` into
/// `buffer` with `GetVariable`: [`FirmwareVariables::get`].
///
/// A name that is not NUL-terminated, or a system table with no runtime
/// services, reads as [`VariableRead::Failed`], without a call.
///
/// # Safety
/// `st` must be a valid pointer to the UEFI system table, and boot services
/// must not have exited.
unsafe fn get_variable(
    st: *mut EfiSystemTable,
    name: &[u16],
    vendor: &EfiGuid,
    buffer: &mut [u8],
) -> VariableRead
{
    if !variable_name_is_terminated(name)
    {
        return VariableRead::Failed(EFI_INVALID_PARAMETER);
    }
    // SAFETY: st is valid (caller contract).
    let rt = unsafe { (*st).runtime_services };
    if rt.is_null()
    {
        return VariableRead::Failed(EFI_UNSUPPORTED);
    }
    // SAFETY: `rt` is the firmware's runtime services table, valid before
    // ExitBootServices (caller contract), so the `get_variable` entry is readable.
    let get_variable_fn = unsafe { (*rt).get_variable };
    let mut attributes: u32 = 0;
    let mut data_size = buffer.len();
    // SAFETY: `name` is NUL-terminated (checked above); `vendor`, `attributes`
    // and `data_size` are live for the call; `buffer` holds `data_size` writable
    // bytes, the bound the firmware writes within.
    let status = unsafe {
        get_variable_fn(
            name.as_ptr(),
            core::ptr::from_ref(vendor),
            core::ptr::addr_of_mut!(attributes),
            core::ptr::addr_of_mut!(data_size),
            buffer.as_mut_ptr().cast::<core::ffi::c_void>(),
        )
    };
    classify_variable_read(status, data_size, attributes, buffer.len())
}

/// Write `data` to the variable `name` (NUL-terminated UTF-16) under
/// `vendor` with `attributes`, through `SetVariable`:
/// [`FirmwareVariables::set`].
///
/// # Errors
/// The status the firmware refused the write with; `EFI_INVALID_PARAMETER`
/// for a name that is not NUL-terminated, and `EFI_UNSUPPORTED` for a system
/// table with no runtime services, without a call.
///
/// # Safety
/// `st` must be a valid pointer to the UEFI system table, and boot services
/// must not have exited.
unsafe fn set_variable(
    st: *mut EfiSystemTable,
    name: &[u16],
    vendor: &EfiGuid,
    attributes: u32,
    data: &[u8],
) -> Result<(), EfiStatus>
{
    if !variable_name_is_terminated(name)
    {
        return Err(EFI_INVALID_PARAMETER);
    }
    // SAFETY: st is valid (caller contract).
    let rt = unsafe { (*st).runtime_services };
    if rt.is_null()
    {
        return Err(EFI_UNSUPPORTED);
    }
    // SAFETY: `rt` is the firmware's runtime services table, valid before
    // ExitBootServices (caller contract), so the `set_variable` entry is readable.
    let set_variable_fn = unsafe { (*rt).set_variable };
    // SAFETY: `name` is NUL-terminated (checked above); `vendor` and `data`
    // are live for the call, and the firmware reads `data.len()` bytes of it.
    let status = unsafe {
        set_variable_fn(
            name.as_ptr(),
            core::ptr::from_ref(vendor),
            attributes,
            data.len(),
            data.as_ptr().cast::<core::ffi::c_void>(),
        )
    };
    if status == EFI_SUCCESS
    {
        Ok(())
    }
    else
    {
        Err(status)
    }
}

/// What `QueryVariableInfo` reports of the store for one set of attributes,
/// in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VariableInfo
{
    /// The size of the store for variables of these attributes.
    pub max_storage: u64,
    /// The room left in it.
    pub remaining: u64,
    /// The largest variable, its name and data, the store takes.
    pub max_variable: u64,
}

/// The byte offset of `QueryVariableInfo` in the runtime services table: a
/// table whose header size does not reach past it predates UEFI 2.0 and has
/// none.
const QUERY_VARIABLE_INFO_END: usize =
    core::mem::offset_of!(EfiRuntimeServices, query_variable_info) + core::mem::size_of::<usize>();

/// Ask the firmware's store about variables of `attributes` through
/// `QueryVariableInfo`: [`FirmwareVariables::query`].
///
/// # Errors
/// The status the firmware failed the call with; `EFI_UNSUPPORTED`, without
/// a call, for a system table with no runtime services or a runtime services
/// table too short to hold the service.
///
/// # Safety
/// `st` must be a valid pointer to the UEFI system table, and boot services
/// must not have exited.
unsafe fn query_variable_info(
    st: *mut EfiSystemTable,
    attributes: u32,
) -> Result<VariableInfo, EfiStatus>
{
    // SAFETY: st is valid (caller contract).
    let rt = unsafe { (*st).runtime_services };
    if rt.is_null()
    {
        return Err(EFI_UNSUPPORTED);
    }
    // SAFETY: `rt` is the firmware's runtime services table, valid before
    // ExitBootServices (caller contract); its header is always present.
    let header_size = unsafe { (*rt).hdr.header_size };
    if usize::try_from(header_size).is_ok_and(|size| size < QUERY_VARIABLE_INFO_END)
    {
        return Err(EFI_UNSUPPORTED);
    }
    // SAFETY: the table's header size covers the `query_variable_info` entry
    // (checked above), so it is readable.
    let query_fn = unsafe { (*rt).query_variable_info };
    let mut info = VariableInfo {
        max_storage: 0,
        remaining: 0,
        max_variable: 0,
    };
    // SAFETY: the three out-pointers name live fields of `info` for the call.
    let status = unsafe {
        query_fn(
            attributes,
            core::ptr::addr_of_mut!(info.max_storage),
            core::ptr::addr_of_mut!(info.remaining),
            core::ptr::addr_of_mut!(info.max_variable),
        )
    };
    if status == EFI_SUCCESS
    {
        Ok(info)
    }
    else
    {
        Err(status)
    }
}

/// The UEFI variable services as the bootloader uses them, before
/// `ExitBootServices` alone: the firmware's ([`FirmwareVariables`]), or a
/// host test's store. Every Seraph variable is read and written through it
/// ([core/boot/docs/uefi-environment.md](../docs/uefi-environment.md)
/// § Variable Services).
pub trait VariableServices
{
    /// Read the variable `name` (NUL-terminated UTF-16) under `vendor` into
    /// `buffer`. A name that is not NUL-terminated reads as
    /// [`VariableRead::Failed`].
    fn get(&mut self, name: &[u16], vendor: &EfiGuid, buffer: &mut [u8]) -> VariableRead;

    /// Write `data` to the variable `name` (NUL-terminated UTF-16) under
    /// `vendor` with `attributes`.
    ///
    /// # Errors
    /// The status the write was refused with.
    fn set(
        &mut self,
        name: &[u16],
        vendor: &EfiGuid,
        attributes: u32,
        data: &[u8],
    ) -> Result<(), EfiStatus>;

    /// What the store reports for variables of `attributes`.
    ///
    /// # Errors
    /// The status the query failed with; `EFI_UNSUPPORTED` where the
    /// firmware has no such service.
    fn query(&mut self, attributes: u32) -> Result<VariableInfo, EfiStatus>;
}

/// The firmware's variable services, reached through the system table's
/// runtime services before `ExitBootServices`.
pub struct FirmwareVariables
{
    st: *mut EfiSystemTable,
}

impl FirmwareVariables
{
    /// The variable services of the system table `st`.
    ///
    /// # Safety
    /// `st` must be a valid pointer to the UEFI system table, and boot
    /// services must not exit while the value lives: it is made where a call
    /// is made, and dropped there.
    pub const unsafe fn new(st: *mut EfiSystemTable) -> Self
    {
        Self { st }
    }
}

impl VariableServices for FirmwareVariables
{
    fn get(&mut self, name: &[u16], vendor: &EfiGuid, buffer: &mut [u8]) -> VariableRead
    {
        // SAFETY: self.st is valid and boot services have not exited (the
        // contract of FirmwareVariables::new).
        unsafe { get_variable(self.st, name, vendor, buffer) }
    }

    fn set(
        &mut self,
        name: &[u16],
        vendor: &EfiGuid,
        attributes: u32,
        data: &[u8],
    ) -> Result<(), EfiStatus>
    {
        // SAFETY: self.st is valid and boot services have not exited (the
        // contract of FirmwareVariables::new).
        unsafe { set_variable(self.st, name, vendor, attributes, data) }
    }

    fn query(&mut self, attributes: u32) -> Result<VariableInfo, EfiStatus>
    {
        // SAFETY: self.st is valid and boot services have not exited (the
        // contract of FirmwareVariables::new).
        unsafe { query_variable_info(self.st, attributes) }
    }
}

/// `EVT_TIMER`: an event a timer signals.
const EVT_TIMER: u32 = 0x8000_0000;

/// `TimerRelative`: a timer that fires once, its trigger time from now.
const TIMER_RELATIVE: u32 = 2;

/// A line typed at the console ([`ConsoleInput::read_line`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineRead
{
    /// Enter was pressed: the line held `len` characters, of which those
    /// that fit are at the start of the buffer.
    Line
    {
        len: usize
    },
    /// The time ran out before Enter.
    Timeout,
    /// The console cannot be read: there is no console input, or a call
    /// failed with this status.
    Unavailable(EfiStatus),
}

/// Console input as the bootloader uses it, before `ExitBootServices`
/// alone: the firmware's `ConIn` ([`FirmwareConsole`]), or a host test's
/// script.
pub trait ConsoleInput
{
    /// Discard the keys typed so far, print `prompt` as one line, then read
    /// one line of typed ASCII into `buffer`, echoing each character, until
    /// Enter or until `seconds` have passed, whichever comes first.
    /// Backspace removes the last character; a key with no ASCII character
    /// is ignored.
    fn read_line(&mut self, prompt: &str, buffer: &mut [u8], seconds: u64) -> LineRead;
}

/// The firmware's console input, reached through the system table's `ConIn`
/// and timed by a timer event of the boot services, never by `Stall`, which
/// some firmware returns from at once.
pub struct FirmwareConsole
{
    st: *mut EfiSystemTable,
}

impl FirmwareConsole
{
    /// The console input of the system table `st`.
    ///
    /// # Safety
    /// `st` must be a valid pointer to the UEFI system table, and boot
    /// services must not exit while the value lives.
    pub const unsafe fn new(st: *mut EfiSystemTable) -> Self
    {
        Self { st }
    }
}

impl ConsoleInput for FirmwareConsole
{
    fn read_line(&mut self, prompt: &str, buffer: &mut [u8], seconds: u64) -> LineRead
    {
        // SAFETY: self.st is valid and boot services have not exited (the
        // contract of FirmwareConsole::new).
        unsafe { read_console_line(self.st, prompt, buffer, seconds) }
    }
}

/// [`ConsoleInput::read_line`] on the firmware's `ConIn`: the keys waiting
/// from before the prompt are discarded, and the line ends at Enter or at a
/// one-shot timer event `seconds` from the prompt.
///
/// # Safety
/// `st` must be a valid pointer to the UEFI system table, and boot services
/// must not have exited.
unsafe fn read_console_line(
    st: *mut EfiSystemTable,
    prompt: &str,
    buffer: &mut [u8],
    seconds: u64,
) -> LineRead
{
    // SAFETY: st is valid (caller contract).
    let con_in = unsafe { (*st).con_in };
    // SAFETY: st is valid (caller contract).
    let bs = unsafe { (*st).boot_services };
    if con_in.is_null()
    {
        return LineRead::Unavailable(EFI_UNSUPPORTED);
    }
    // SAFETY: con_in is the firmware's ConIn, valid before ExitBootServices (caller contract).
    let reset_fn = unsafe { (*con_in).reset };
    // SAFETY: con_in is the firmware's ConIn, valid before ExitBootServices (caller contract).
    let read_fn = unsafe { (*con_in).read_key_stroke };
    // SAFETY: con_in is the firmware's ConIn, valid before ExitBootServices (caller contract).
    let wait_for_key = unsafe { (*con_in).wait_for_key };
    // SAFETY: bs is the firmware's boot services, valid before ExitBootServices (caller contract).
    let create_fn = unsafe { (*bs).create_event };
    // SAFETY: bs is the firmware's boot services, valid before ExitBootServices (caller contract).
    let set_timer_fn = unsafe { (*bs).set_timer };
    // SAFETY: bs is the firmware's boot services, valid before ExitBootServices (caller contract).
    let wait_fn = unsafe { (*bs).wait_for_event };
    // SAFETY: bs is the firmware's boot services, valid before ExitBootServices (caller contract).
    let close_fn = unsafe { (*bs).close_event };
    // Keys typed before the question are no answer to it: discard them, then
    // ask.
    // SAFETY: con_in is valid; a failed reset leaves the keys to be read.
    let _ = unsafe { reset_fn(con_in, 0) };
    crate::bprintln!("{prompt}");
    let mut timer: EfiEvent = core::ptr::null_mut();
    // SAFETY: a timer event with no notification; `timer` is live for the call.
    let status = unsafe {
        create_fn(
            EVT_TIMER,
            0,
            0,
            core::ptr::null_mut(),
            core::ptr::addr_of_mut!(timer),
        )
    };
    if status != EFI_SUCCESS
    {
        return LineRead::Unavailable(status);
    }
    // Trigger time in 100 ns units.
    let trigger = seconds.saturating_mul(10_000_000);
    // SAFETY: timer is the event created above.
    let status = unsafe { set_timer_fn(timer, TIMER_RELATIVE, trigger) };
    let result = if status == EFI_SUCCESS
    {
        // SAFETY: con_in is valid; wait_for_key and timer are live events.
        unsafe { collect_line(con_in, read_fn, wait_fn, wait_for_key, timer, buffer) }
    }
    else
    {
        LineRead::Unavailable(status)
    };
    // SAFETY: timer is the event created above, closed once; closing a timer
    // event also cancels it.
    let _ = unsafe { close_fn(timer) };
    result
}

/// The type of `ReadKeyStroke`.
type ReadKeyStroke =
    unsafe extern "efiapi" fn(this: *mut EfiSimpleTextInput, key: *mut EfiInputKey) -> EfiStatus;

/// The type of `WaitForEvent`.
type WaitForEvent = unsafe extern "efiapi" fn(
    count: usize,
    events: *const EfiEvent,
    index: *mut usize,
) -> EfiStatus;

/// The loop of [`read_console_line`]: wait for a key or the timer, then take
/// the key.
///
/// The timer is the first event of the wait: `WaitForEvent` returns the
/// first signalled event in its array's order, so a fired timer ends the wait
/// even while keys keep arriving. A `ReadKeyStroke` that finds no key
/// (`EFI_NOT_READY`: the key event fired for a key another reader took)
/// waits again; any other failure ends the read as
/// [`LineRead::Unavailable`].
///
/// # Safety
/// `con_in` must be the firmware's `ConIn`, `read_fn` its `ReadKeyStroke`,
/// `wait_fn` the boot services' `WaitForEvent`, `wait_for_key` its
/// `WaitForKey`, and `timer` a live timer event, before `ExitBootServices`.
unsafe fn collect_line(
    con_in: *mut EfiSimpleTextInput,
    read_fn: ReadKeyStroke,
    wait_fn: WaitForEvent,
    wait_for_key: EfiEvent,
    timer: EfiEvent,
    buffer: &mut [u8],
) -> LineRead
{
    let events = [timer, wait_for_key];
    let mut len = 0usize;
    loop
    {
        let mut index = 0usize;
        // SAFETY: both events are live (caller contract); index is live.
        let status = unsafe { wait_fn(2, events.as_ptr(), core::ptr::addr_of_mut!(index)) };
        if status != EFI_SUCCESS
        {
            return LineRead::Unavailable(status);
        }
        if index == 0
        {
            crate::bprintln!();
            return LineRead::Timeout;
        }
        let mut key = EfiInputKey {
            scan_code: 0,
            unicode_char: 0,
        };
        // SAFETY: con_in is valid (caller contract); key is live.
        match unsafe { read_fn(con_in, core::ptr::addr_of_mut!(key)) }
        {
            EFI_SUCCESS =>
            {}
            // The key event fired for no key (a key another reader took):
            // wait again.
            EFI_NOT_READY => continue,
            status => return LineRead::Unavailable(status),
        }
        match line_key(key.unicode_char)
        {
            LineKey::Enter =>
            {
                crate::bprintln!();
                return LineRead::Line { len };
            }
            LineKey::Backspace =>
            {
                if len > 0
                {
                    len = len.saturating_sub(1);
                    crate::bprint!("\x08 \x08");
                }
            }
            LineKey::Char(byte) =>
            {
                if let Some(slot) = buffer.get_mut(len)
                {
                    *slot = byte;
                }
                len = len.saturating_add(1);
                crate::bprint!("{}", char::from(byte));
            }
            LineKey::Other =>
            {}
        }
    }
}

/// What a keystroke's character does to a line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LineKey
{
    /// Carriage return or line feed: the line ends.
    Enter,
    /// Backspace or DEL: the last character goes.
    Backspace,
    /// A printable ASCII character.
    Char(u8),
    /// Anything else: ignored.
    Other,
}

/// Classify the UTF-16 character `unicode` of a keystroke.
fn line_key(unicode: u16) -> LineKey
{
    match unicode
    {
        0x0d | 0x0a => LineKey::Enter,
        0x08 | 0x7f => LineKey::Backspace,
        0x20..=0x7e => u8::try_from(unicode).map_or(LineKey::Other, LineKey::Char),
        _ => LineKey::Other,
    }
}

/// Search the UEFI configuration table for an entry matching `guid`.
///
/// Returns the vendor table pointer on success, or `None` if not found.
///
/// # Safety
/// `st` must be a valid pointer to the UEFI system table.
pub unsafe fn find_config_table(
    st: *mut EfiSystemTable,
    guid: &EfiGuid,
) -> Option<*mut core::ffi::c_void>
{
    // SAFETY: st is valid; configuration_table points to a valid array of
    // number_of_table_entries entries.
    let count = unsafe { (*st).number_of_table_entries };
    // SAFETY: st is valid.
    let table = unsafe { (*st).configuration_table };
    for i in 0..count
    {
        // SAFETY: `i < count`, so the offset stays inside the `number_of_table_entries`-entry
        // configuration table of `st`.
        let entry_ptr = unsafe { table.add(i) };
        // SAFETY: `entry_ptr` is inside that table, whose entries firmware initialised.
        let entry = unsafe { &*entry_ptr };
        if &entry.vendor_guid == guid
        {
            return Some(entry.vendor_table);
        }
    }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::{
        BootError, EFI_BUFFER_TOO_SMALL, EFI_NOT_FOUND, EFI_SUCCESS, EFI_UNSUPPORTED,
        EfiMemoryDescriptor, MAP_BUFFER_SLACK_DESCRIPTORS, VariableRead, check_descriptor_size,
        classify_variable_read, map_buffer_bytes, map_buffer_descriptor_reach,
        variable_name_is_terminated,
    };
    use super::{EFI_NOT_READY, EfiEvent, EfiInputKey, EfiStatus, LineRead, collect_line};
    use super::{EfiBootServices, EfiRuntimeServices, EfiSimpleTextInput, LineKey, line_key};

    /// `EFI_DEVICE_ERROR`.
    const EFI_DEVICE_ERROR: EfiStatus = 0x8000_0000_0000_0007;

    // Defect caught: a service called through the wrong slot of its table
    // (the UEFI specification's order), which calls another service with
    // the arguments of this one.
    #[test]
    fn the_services_lie_at_the_specifications_slots()
    {
        let slot = |offset: usize| offset / core::mem::size_of::<usize>();
        assert_eq!(
            slot(core::mem::offset_of!(EfiRuntimeServices, get_variable)),
            9
        );
        assert_eq!(
            slot(core::mem::offset_of!(EfiRuntimeServices, set_variable)),
            11
        );
        assert_eq!(
            slot(core::mem::offset_of!(
                EfiRuntimeServices,
                query_variable_info
            )),
            16
        );
        assert_eq!(
            slot(core::mem::offset_of!(EfiBootServices, allocate_pool)),
            8
        );
        assert_eq!(
            slot(core::mem::offset_of!(EfiBootServices, create_event)),
            10
        );
        assert_eq!(slot(core::mem::offset_of!(EfiBootServices, set_timer)), 11);
        assert_eq!(
            slot(core::mem::offset_of!(EfiBootServices, wait_for_event)),
            12
        );
        assert_eq!(
            slot(core::mem::offset_of!(EfiBootServices, close_event)),
            14
        );
        assert_eq!(
            slot(core::mem::offset_of!(EfiBootServices, handle_protocol)),
            19
        );
        assert_eq!(
            slot(core::mem::offset_of!(EfiSimpleTextInput, read_key_stroke)),
            1
        );
        assert_eq!(
            slot(core::mem::offset_of!(EfiSimpleTextInput, wait_for_key)),
            2
        );
    }

    // Defect caught: Enter from a serial terminal (CR) or a keyboard not
    // ending the line, or a control character taken into the answer.
    #[test]
    fn a_keystroke_is_enter_backspace_a_character_or_nothing()
    {
        assert_eq!(line_key(0x0d), LineKey::Enter);
        assert_eq!(line_key(0x0a), LineKey::Enter);
        assert_eq!(line_key(0x08), LineKey::Backspace);
        assert_eq!(line_key(0x7f), LineKey::Backspace);
        assert_eq!(line_key(u16::from(b'y')), LineKey::Char(b'y'));
        assert_eq!(line_key(u16::from(b' ')), LineKey::Char(b' '));
        for other in [0u16, 0x1b, 0x09, 0xe9, 0x4e00]
        {
            assert_eq!(line_key(other), LineKey::Other, "{other:#x}");
        }
    }

    // Defect caught: a GetVariable outcome read as another (a missing
    // variable as a failed read, a variable too large for the buffer as
    // one read whole, or a success past the buffer trusted), so the floor
    // logic decides on bytes the firmware never wrote.
    #[test]
    fn every_get_variable_outcome_is_classified()
    {
        assert_eq!(
            classify_variable_read(EFI_SUCCESS, 4, 3, 4),
            VariableRead::Found {
                len: 4,
                attributes: 3
            }
        );
        assert_eq!(
            classify_variable_read(EFI_SUCCESS, 2, 7, 4),
            VariableRead::Found {
                len: 2,
                attributes: 7
            }
        );
        assert_eq!(
            classify_variable_read(EFI_BUFFER_TOO_SMALL, 9, 0, 4),
            VariableRead::TooLarge { len: 9 }
        );
        assert_eq!(
            classify_variable_read(EFI_SUCCESS, 5, 3, 4),
            VariableRead::TooLarge { len: 5 }
        );
        assert_eq!(
            classify_variable_read(EFI_NOT_FOUND, 4, 0, 4),
            VariableRead::NotFound
        );
        assert_eq!(
            classify_variable_read(EFI_UNSUPPORTED, 4, 0, 4),
            VariableRead::Failed(EFI_UNSUPPORTED)
        );
    }

    // Defect caught: a name passed to the firmware without its NUL, which it
    // would read past, or with an embedded one, which names another variable.
    #[test]
    fn a_variable_name_ends_in_its_one_nul()
    {
        assert!(variable_name_is_terminated(&[u16::from(b'F'), 0]));
        assert!(!variable_name_is_terminated(&[u16::from(b'F')]));
        assert!(!variable_name_is_terminated(&[]));
        assert!(!variable_name_is_terminated(&[0, u16::from(b'F'), 0]));
    }

    // Defect caught: an entry array sized for a map that a buffer allocated
    // for a map no larger can outgrow (at the queried stride or any smaller
    // one a re-query may report), so a map past the array reaches step 9.
    #[test]
    fn a_buffer_for_a_smaller_map_never_reaches_past_one_for_a_larger()
    {
        let min = core::mem::size_of::<EfiMemoryDescriptor>();
        for stride in [min, 48, 56, 64, 80]
        {
            for sized_for in [0usize, 1, 50, 85, 86, 200, 1000]
            {
                let reach =
                    map_buffer_descriptor_reach(map_buffer_bytes(sized_for * stride, stride));
                assert!(reach >= sized_for + MAP_BUFFER_SLACK_DESCRIPTORS);
                for actual in 0..=sized_for
                {
                    let buffer = map_buffer_bytes(actual * stride, stride);
                    assert_eq!(buffer % 4096, 0);
                    assert!(buffer >= (actual + MAP_BUFFER_SLACK_DESCRIPTORS) * stride);
                    assert!(
                        map_buffer_descriptor_reach(buffer) <= reach,
                        "{stride} {actual}"
                    );
                }
            }
        }
    }

    // Defect caught: a stride below the descriptor accepted, so the map
    // readers read past each descriptor; or a conforming stride refused.
    #[test]
    fn only_a_stride_below_the_descriptor_is_refused()
    {
        let full = core::mem::size_of::<EfiMemoryDescriptor>();
        for short in [0, 8, full - 1]
        {
            assert!(matches!(
                check_descriptor_size(short),
                Err(BootError::InvalidMemoryMap(_))
            ));
        }
        check_descriptor_size(full).unwrap();
        check_descriptor_size(full + 8).unwrap();
    }

    /// The fake firmware of the `collect_line` tests, one per test thread:
    /// the key event is always signalled, the timer is signalled from the
    /// `timer_after`-th wait on, and `ReadKeyStroke` returns `reads` in
    /// turn, then `EFI_NOT_READY`.
    struct FakeConsole
    {
        waits: usize,
        timer_after: usize,
        reads: Vec<(EfiStatus, u16)>,
        next_read: usize,
    }

    std::thread_local! {
        static FAKE: core::cell::RefCell<FakeConsole> = const {
            core::cell::RefCell::new(FakeConsole {
                waits: 0,
                timer_after: usize::MAX,
                reads: Vec::new(),
                next_read: 0,
            })
        };
    }

    /// The fake key event and timer event.
    const KEY_EVENT: EfiEvent = core::ptr::without_provenance_mut(1);
    const TIMER_EVENT: EfiEvent = core::ptr::without_provenance_mut(2);
    /// Waits after which a test that has not ended the read fails.
    const WAIT_LIMIT: usize = 1000;

    /// `WaitForEvent` as the UEFI specification gives it: the index of the
    /// first signalled event in the array's order.
    unsafe extern "efiapi" fn fake_wait(
        count: usize,
        events: *const EfiEvent,
        index: *mut usize,
    ) -> EfiStatus
    {
        let timer_fired = FAKE.with_borrow_mut(|fake| {
            fake.waits += 1;
            assert!(fake.waits < WAIT_LIMIT, "the read never ended");
            fake.waits >= fake.timer_after
        });
        // SAFETY: collect_line passes count live events and a live index.
        let events = unsafe { core::slice::from_raw_parts(events, count) };
        let first = events
            .iter()
            .position(|&event| event == KEY_EVENT || (event == TIMER_EVENT && timer_fired))
            .unwrap();
        // SAFETY: as above.
        unsafe { index.write(first) };
        EFI_SUCCESS
    }

    /// `ReadKeyStroke` returning the scripted statuses and characters.
    unsafe extern "efiapi" fn fake_read(
        _: *mut EfiSimpleTextInput,
        key: *mut EfiInputKey,
    ) -> EfiStatus
    {
        let (status, unicode_char) = FAKE.with_borrow_mut(|fake| {
            let read = fake.reads.get(fake.next_read).copied();
            fake.next_read += 1;
            read.unwrap_or((EFI_NOT_READY, 0))
        });
        // SAFETY: collect_line passes a live key.
        unsafe {
            key.write(EfiInputKey {
                scan_code: 0,
                unicode_char,
            });
        }
        status
    }

    /// Run `collect_line` on the fake firmware.
    fn read_fake(timer_after: usize, reads: &[(EfiStatus, u16)]) -> LineRead
    {
        FAKE.with_borrow_mut(|fake| {
            *fake = FakeConsole {
                waits: 0,
                timer_after,
                reads: reads.to_vec(),
                next_read: 0,
            };
        });
        let mut buffer = [0u8; 8];
        // SAFETY: the fakes stand for the firmware's functions and events.
        unsafe {
            collect_line(
                core::ptr::null_mut(),
                fake_read,
                fake_wait,
                KEY_EVENT,
                TIMER_EVENT,
                &mut buffer,
            )
        }
    }

    // Defect caught: the key event first in the wait's array, so keys that
    // keep arriving hide a fired timer and the wait never ends.
    #[test]
    fn a_fired_timer_ends_the_wait_while_keys_keep_coming()
    {
        let keys = [(EFI_SUCCESS, u16::from(b'n')); 64];
        assert_eq!(read_fake(5, &keys), LineRead::Timeout);
    }

    // Defect caught: a ReadKeyStroke failure other than EFI_NOT_READY retried
    // for ever while the key event stays signalled.
    #[test]
    fn a_failing_key_read_ends_the_read()
    {
        assert_eq!(
            read_fake(usize::MAX, &[(EFI_DEVICE_ERROR, 0)]),
            LineRead::Unavailable(EFI_DEVICE_ERROR)
        );
    }

    // Defect caught: a key event that fired for a key another reader took
    // (EFI_NOT_READY) taken as a failure, or the line not read after it.
    #[test]
    fn a_key_event_with_no_key_waits_again()
    {
        let reads = [
            (EFI_NOT_READY, 0),
            (EFI_SUCCESS, u16::from(b'y')),
            (EFI_SUCCESS, u16::from(b'e')),
            (EFI_SUCCESS, u16::from(b's')),
            (EFI_SUCCESS, u16::from(b'\r')),
        ];
        assert_eq!(read_fake(usize::MAX, &reads), LineRead::Line { len: 3 });
    }
}
