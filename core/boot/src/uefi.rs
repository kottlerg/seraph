// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// boot/src/uefi.rs

//! UEFI raw type definitions and safe wrapper functions.
//!
//! All UEFI types are hand-written `#[repr(C)]` structures — no external crate
//! is used. Function pointer types use `extern "efiapi"`, which resolves to the
//! Microsoft x64 ABI on x86-64 and the standard lp64d calling convention on
//! RISC-V, matching the UEFI specification for each architecture.
//!
//! Public wrapper functions return `Result<T, BootError>` and encapsulate all
//! raw pointer manipulation behind documented `// SAFETY:` contracts.

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
#[allow(dead_code)] // Defined for completeness; not all EFI error codes are used in every boot path.
pub const EFI_NOT_FOUND: EfiStatus = 0x8000_0000_0000_000E;

/// Allocate pages at any available physical address.
pub const ALLOCATE_ANY_PAGES: u32 = 0;
/// Allocate pages at or below a specified maximum physical address.
///
/// Used by the x86-64 arch module to reserve a < 1 MiB page for the AP
/// SIPI trampoline. Public because the x86-64 helper in
/// `arch::current::allocate_ap_trampoline` lives in a different module.
pub const ALLOCATE_MAX_ADDRESS: u32 = 1;
/// Allocate pages at a specified physical address.
pub const ALLOCATE_ADDRESS: u32 = 2;

/// Memory type used for all bootloader allocations.
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
    pub con_in: *mut core::ffi::c_void,
    pub console_out_handle: EfiHandle,
    pub con_out: *mut EfiSimpleTextOutput,
    pub standard_error_handle: EfiHandle,
    pub std_err: *mut core::ffi::c_void,
    pub runtime_services: *mut core::ffi::c_void,
    pub boot_services: *mut EfiBootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: *mut EfiConfigurationTable,
}

/// UEFI Simple Text Output Protocol, used to print boot messages.
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

/// UEFI Memory types referenced in the memory map translation.
pub const EFI_CONVENTIONAL_MEMORY: u32 = 7;
pub const EFI_LOADER_CODE: u32 = 1;
// EFI_LOADER_DATA is 2, shared with the allocation constant above.
pub const EFI_BOOT_SERVICES_CODE: u32 = 3;
pub const EFI_BOOT_SERVICES_DATA: u32 = 4;
// Defined for completeness — used by memory_map translation logic that matches on all types.
#[allow(dead_code)]
pub const EFI_RUNTIME_SERVICES_CODE: u32 = 5;
#[allow(dead_code)]
pub const EFI_RUNTIME_SERVICES_DATA: u32 = 6;
pub const EFI_ACPI_RECLAIM_MEMORY: u32 = 9;
#[allow(dead_code)]
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

    // Event and timer services (6 entries, unused)
    _events: [usize; 6],

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
    pub locate_device_path: usize,
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
/// # Safety
/// `bs` must be a valid pointer to UEFI boot services, `image` must be a valid
/// loaded-image handle.
pub unsafe fn get_loaded_image(
    bs: *mut EfiBootServices,
    image: EfiHandle,
) -> Result<*mut EfiLoadedImageProtocol, BootError>
{
    let mut iface: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: caller guarantees bs and image are valid.
    let status = unsafe {
        ((*bs).open_protocol)(
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
/// # Safety
/// `bs` must be valid boot services, `device` must be the device handle from
/// the loaded image protocol.
pub unsafe fn open_esp_volume(
    bs: *mut EfiBootServices,
    device: EfiHandle,
) -> Result<*mut EfiFileProtocol, BootError>
{
    let mut iface: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: caller guarantees bs and device are valid.
    let status = unsafe {
        ((*bs).handle_protocol)(
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
    // SAFETY: fs is a valid protocol pointer.
    let status = unsafe { ((*fs).open_volume)(fs, core::ptr::addr_of_mut!(root)) };
    if status != EFI_SUCCESS
    {
        return Err(BootError::UefiError(status));
    }
    Ok(root)
}

/// Open a file on the ESP by path.
///
/// `path` must be a UEFI-style path with backslash separators, encoded as a
/// null-terminated UTF-16 slice.
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
    // SAFETY: root is valid; path is a null-terminated UTF-16 string.
    let status = unsafe {
        ((*root).open)(
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

/// Query the file size in bytes using `EFI_FILE_INFO`.
///
/// # Safety
/// `file` must be a valid open `EFI_FILE_PROTOCOL` handle.
pub unsafe fn file_size(file: *mut EfiFileProtocol) -> Result<u64, BootError>
{
    // First call: get required buffer size.
    let mut info_size: usize = 0;
    // SAFETY: file is valid; passing null buffer with zero size requests the required size.
    let status = unsafe {
        ((*file).get_info)(
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
    let mut buf = [0u8; core::mem::size_of::<EfiFileInfo>() + 256];
    let mut buf_size = buf.len();
    // SAFETY: buf is correctly sized; file is valid.
    let status = unsafe {
        ((*file).get_info)(
            file,
            core::ptr::addr_of!(EFI_FILE_INFO_ID),
            core::ptr::addr_of_mut!(buf_size),
            buf.as_mut_ptr().cast::<core::ffi::c_void>(),
        )
    };
    if status != EFI_SUCCESS
    {
        return Err(BootError::UefiError(status));
    }

    // SAFETY: buf starts with EfiFileInfo, which is correctly laid out.
    // cast_ptr_alignment: the stack buffer is not guaranteed 8-byte aligned; EfiFileInfo
    // fields are accessed individually through the reference, which the compiler handles.
    #[allow(clippy::cast_ptr_alignment)]
    let info = unsafe { &*(buf.as_ptr().cast::<EfiFileInfo>()) };
    Ok(info.file_size)
}

/// Read bytes from a file into a caller-provided buffer.
///
/// Reads exactly `buffer.len()` bytes starting from the current file position.
///
/// # Safety
/// `file` must be a valid open `EFI_FILE_PROTOCOL` handle. The file's current
/// position must be set appropriately before calling.
pub unsafe fn file_read(file: *mut EfiFileProtocol, buffer: &mut [u8]) -> Result<(), BootError>
{
    let mut size = buffer.len();
    // SAFETY: file is valid; buffer is a valid writable slice.
    let status = unsafe {
        ((*file).read)(
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
/// # Safety
/// `bs` must be a valid pointer to UEFI boot services (before `ExitBootServices`).
pub unsafe fn allocate_pages(bs: *mut EfiBootServices, count: usize) -> Result<u64, BootError>
{
    let mut addr: u64 = 0;
    // SAFETY: bs is valid; addr is an output parameter.
    let status = unsafe {
        ((*bs).allocate_pages)(
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

/// Allocate `count` pages at the specified physical address.
///
/// Fails if the address range is already in use. Uses `EfiLoaderData`.
///
/// # Safety
/// `bs` must be valid boot services. `addr` must be page-aligned.
pub unsafe fn allocate_address(
    bs: *mut EfiBootServices,
    addr: u64,
    count: usize,
) -> Result<(), BootError>
{
    let mut out_addr = addr;
    // SAFETY: bs is valid; out_addr is an in-out parameter (ALLOCATE_ADDRESS mode).
    let status = unsafe {
        ((*bs).allocate_pages)(
            ALLOCATE_ADDRESS,
            EFI_LOADER_DATA,
            count,
            core::ptr::addr_of_mut!(out_addr),
        )
    };
    if status != EFI_SUCCESS
    {
        return Err(BootError::OutOfMemory);
    }
    Ok(())
}

/// Allocate `count` pages at or below `max_phys` physical address.
///
/// Uses `AllocateMaxAddress` UEFI policy: the allocator picks any available
/// pages with physical base ≤ `max_phys`. `max_phys` is an in-out parameter;
/// on success it holds the actual allocated physical base.
///
/// This is the arch-neutral UEFI wrapper. The only current caller is
/// x86-64's `arch::current::allocate_ap_trampoline`, whose SIPI-vector
/// constraint requires a frame below 1 MiB; the helper is not gated on
/// architecture because `AllocateMaxAddress` is part of the UEFI spec on
/// every supported platform.
///
/// # Safety
/// `bs` must be valid boot services.
#[allow(dead_code)] // Used only by x86-64 arch::current::allocate_ap_trampoline.
pub unsafe fn allocate_pages_max_addr(
    bs: *mut EfiBootServices,
    max_phys: u64,
    count: usize,
) -> Result<u64, BootError>
{
    let mut addr: u64 = max_phys;
    // SAFETY: bs is valid; addr is an in-out parameter.
    let status = unsafe {
        ((*bs).allocate_pages)(
            ALLOCATE_MAX_ADDRESS,
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

/// Query the UEFI memory map.
///
/// Allocates the map buffer from `AllocatePages` (which invalidates any prior
/// map key). Returns the buffer address, map size, map key, and descriptor size.
/// The caller must use this as the final allocation before `ExitBootServices`.
///
/// Sizes the buffer with 16 entries of slack beyond the reported requirement.
/// The buffer allocation itself adds at least one descriptor; the extra margin
/// also absorbs further growth seen when `exit_boot_services` re-queries under
/// contention (see [`exit_boot_services`]).
///
/// # Safety
/// `bs` must be valid boot services.
pub unsafe fn get_memory_map(bs: *mut EfiBootServices) -> Result<MemoryMapResult, BootError>
{
    // First call: obtain required buffer size.
    let mut map_size: usize = 0;
    let mut map_key: usize = 0;
    let mut descriptor_size: usize = 0;
    let mut descriptor_version: u32 = 0;

    // SAFETY: Null map pointer with zero size requests the required size.
    let status = unsafe {
        ((*bs).get_memory_map)(
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

    // Add slack for the buffer allocation itself (which creates one new entry).
    map_size += 16 * descriptor_size;

    let pages = map_size.div_ceil(4096);
    // SAFETY: bs is valid.
    let buffer_phys = unsafe { allocate_pages(bs, pages)? };
    let buffer_size = pages * 4096;

    // Second call: fill the buffer. This call's map_key is the one to use.
    map_size = buffer_size;
    // SAFETY: buffer_phys is a valid allocated region of map_size bytes.
    // cast_possible_truncation: buffer_phys is a UEFI physical address; on all supported
    // targets (x86_64, riscv64) usize is 64-bit, so the cast is exact.
    #[allow(clippy::cast_possible_truncation)]
    let status = unsafe {
        ((*bs).get_memory_map)(
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

    Ok(MemoryMapResult {
        buffer_phys,
        buffer_size,
        map_size,
        map_key,
        descriptor_size,
    })
}

/// Maximum number of `ExitBootServices` attempts before giving up.
///
/// UEFI may invalidate the map key between `GetMemoryMap` and `ExitBootServices`
/// when a firmware event allocates memory in that window; the call then returns
/// `EFI_INVALID_PARAMETER`. Under host CPU contention (parallel QEMU/OVMF) the
/// vCPU can be descheduled in that window repeatedly, so the invalidation can
/// recur across consecutive attempts. A bounded loop retries until a tight
/// `GetMemoryMap`→`ExitBootServices` pair lands without an intervening
/// allocation.
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
/// Each retry re-queries the map into the existing buffer (no new allocation,
/// which would invalidate the key again) to obtain a fresh key. The re-query
/// passes the allocated buffer capacity, so it tolerates a map that grew since
/// the previous query.
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
        // SAFETY: bs, image, and map_key are valid.
        let status = unsafe { ((*bs).exit_boot_services)(image, map.map_key) };
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
        attempt += 1;
        if attempt >= EXIT_BOOT_SERVICES_MAX_ATTEMPTS
        {
            return Err(BootError::ExitBootServicesFailed);
        }

        // Stale key: re-query the map using the existing buffer (no new
        // allocation). map_size is reset to the full buffer capacity each
        // iteration because GetMemoryMap overwrites it with the smaller actual
        // size on success; passing the prior actual size could fail with
        // EFI_BUFFER_TOO_SMALL if the map grew under contention.
        let mut descriptor_size: usize = map.descriptor_size;
        let mut descriptor_version: u32 = 0;
        let mut map_size = map.buffer_size;
        // SAFETY: buffer_phys is the existing allocated buffer of buffer_size bytes.
        // cast_possible_truncation: buffer_phys is a UEFI u64 address; usize is 64-bit on all
        // supported targets, so the cast to *mut is exact.
        #[allow(clippy::cast_possible_truncation)]
        let status = unsafe {
            ((*bs).get_memory_map)(
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
        map.map_size = map_size;
    }
}

/// Framebuffer resolution the bootloader requests from GOP at boot.
///
/// Both architectures acquire the framebuffer through the same UEFI GOP path,
/// so issuing one `SetMode` request here gives a consistent framebuffer — and
/// QEMU window — size across x86-64 and RISC-V, independent of firmware or
/// QEMU-version defaults. 1024x768 is the largest mode QEMU's RISC-V `ramfb`
/// GOP (`QemuRamfbDxe`) offers and is also present in x86-64 OVMF's mode list;
/// when a firmware does not offer it, `set_target_mode` leaves the active mode
/// untouched and boot proceeds at whatever resolution firmware selected.
const TARGET_FB_WIDTH: u32 = 1024;
const TARGET_FB_HEIGHT: u32 = 768;

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
    // SAFETY: gop is valid; mode is populated by firmware.
    let max_mode = unsafe { (*(*gop).mode).max_mode };
    // SAFETY: gop is valid; mode is populated by firmware.
    let current = unsafe { (*(*gop).mode).mode };

    for i in 0..max_mode
    {
        let mut size: usize = 0;
        let mut info: *mut EfiGopModeInfo = core::ptr::null_mut();
        // SAFETY: gop is valid; query_mode writes size/info on success.
        let status = unsafe {
            ((*gop).query_mode)(
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

        // QueryMode allocated the info buffer from pool; release it before the
        // next iteration regardless of match.
        // SAFETY: info came from query_mode and is unused after this point.
        unsafe {
            ((*bs).free_pool)(info.cast::<core::ffi::c_void>());
        }

        if is_target
        {
            if i != current
            {
                // SAFETY: gop is valid; i < max_mode is a valid mode number.
                let _ = unsafe { ((*gop).set_mode)(gop, i) };
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
/// or `PixelBitMask` (format 2, custom layout) are skipped.
///
/// Returns `None` if no usable GOP handle exists. This is not an error — the boot
/// proceeds with `framebuffer.physical_base == 0`.
///
/// # Safety
/// `bs` must be valid boot services.
pub unsafe fn query_gop(bs: *mut EfiBootServices) -> Option<FramebufferInfo>
{
    let mut count: usize = 0;
    let mut handles: *mut EfiHandle = core::ptr::null_mut();

    // SAFETY: bs is valid; ByProtocol with the GOP GUID returns all GOP handles.
    let status = unsafe {
        ((*bs).locate_handle_buffer)(
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
        // SAFETY: i < count; handles[i] is a valid EfiHandle from LocateHandleBuffer.
        let handle = unsafe { *handles.add(i) };
        let mut iface: *mut core::ffi::c_void = core::ptr::null_mut();
        // SAFETY: bs is valid; handle is from the LocateHandleBuffer result.
        let s = unsafe {
            ((*bs).handle_protocol)(
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

        // SAFETY: gop is a valid protocol pointer; mode/info are populated by
        // firmware and reflect the now-active mode.
        let mode = unsafe { &*(*gop).mode };
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

        result = Some(FramebufferInfo {
            physical_base: mode.frame_buffer_base,
            width: info.horizontal_resolution,
            height: info.vertical_resolution,
            stride: info.pixels_per_scan_line * 4,
            pixel_format,
        });
        break;
    }

    // SAFETY: handles was allocated by LocateHandleBuffer; must be freed with FreePool.
    unsafe {
        ((*bs).free_pool)(handles.cast::<core::ffi::c_void>());
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

    // SAFETY: bs is valid; NULL protocol + NULL key with AllHandles returns all handles.
    let status = unsafe {
        ((*bs).locate_handle_buffer)(
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
        // SAFETY: handles[i] is valid; i < count.
        let handle = unsafe { *handles.add(i) };
        // SAFETY: recursive=TRUE (1) connects all child controllers.
        // Errors are expected for handles with no bindable drivers.
        unsafe {
            ((*bs).connect_controller)(
                handle,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                1, // TRUE — recursive
            );
        }
    }

    // SAFETY: handles was allocated by LocateHandleBuffer; must be freed.
    unsafe {
        ((*bs).free_pool)(handles.cast::<core::ffi::c_void>());
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
        // SAFETY: i < count, so this is within the valid array range.
        let entry = unsafe { &*table.add(i) };
        if &entry.vendor_guid == guid
        {
            return Some(entry.vendor_table);
        }
    }
    None
}
