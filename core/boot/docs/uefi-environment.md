# UEFI Environment

The bootloader is a UEFI application. Before `ExitBootServices`, all hardware access
and memory allocation goes through UEFI firmware services. After `ExitBootServices`,
UEFI boot services are permanently unavailable; the bootloader operates exclusively
from pre-allocated memory.

This document covers the UEFI protocols used, allocation strategy, memory map
acquisition, `ExitBootServices`, and error handling.

---

## UEFI Protocol Usage

| Protocol | Handle method | Purpose | Required |
|---|---|---|---|
| `EFI_LOADED_IMAGE_PROTOCOL` | `OpenProtocol(image_handle, BY_HANDLE_PROTOCOL)` | Obtain device handle for the boot volume | Yes |
| `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL` | `HandleProtocol(device_handle)` | Open the ESP root directory | Yes |
| `EFI_GRAPHICS_OUTPUT_PROTOCOL` | `LocateHandleBuffer(ByProtocol)` | Select a fixed mode; record framebuffer address, dimensions, format | No |
| `EFI_GET_MEMORY_MAP` | `BootServices->GetMemoryMap` | Query physical memory layout | Yes |
| `EFI_ALLOCATE_PAGES` | `BootServices->AllocatePages` | Allocate physical memory for all loaded data | Yes |
| `EFI_CONFIGURATION_TABLE` | `SystemTable->ConfigurationTable` | Locate the ACPI RSDP and/or Device Tree blob (both GUIDs searched on both architectures) | No (each table optional) |
| `EFI_RNG_PROTOCOL` | `LocateProtocol` | Draw the 32-byte entropy-pool seed and an independent 16-byte KASLR word (step 5c) | No |
| `EFI_RISCV_BOOT_PROTOCOL` | `LocateProtocol` | Read the boot hart ID (RISC-V only; 0 when absent) | No |
| All handles | `LocateHandleBuffer(AllHandles)` + `ConnectController` | Bind drivers (e.g. virtio-gpu to GOP) not auto-connected during BDS, before the GOP query | No |

`EFI_GRAPHICS_OUTPUT_PROTOCOL` is optional — its absence is handled gracefully by
zeroing the `framebuffer.physical_base` field in `BootInfo`. A headless system or a
virtual machine without a GOP framebuffer is a valid configuration.

When GOP is present, the bootloader requests a fixed 1280x720 mode via `SetMode`
before recording the active mode for handoff (`TARGET_FB_WIDTH` /
`TARGET_FB_HEIGHT` in [`core/boot/src/uefi.rs`](../src/uefi.rs)). Both architectures
acquire the framebuffer through this same GOP path, so the fixed request yields a
consistent framebuffer size across x86-64 and RISC-V rather than one dependent on
per-firmware or per-QEMU defaults. The request is best-effort: if the firmware's
GOP does not offer the target mode, the active mode is left unchanged.

`EFI_CONFIGURATION_TABLE` entries are needed for firmware table parsing: the bootloader
searches the table for both `EFI_ACPI_20_TABLE_GUID` (ACPI RSDP) and `EFI_DTB_TABLE_GUID`
(Device Tree blob) on both architectures and records whichever the firmware installs; x86-64
and QEMU+EDK2 RISC-V publish ACPI, and DTB-only RISC-V firmware publishes the FDT. The
parsing itself is specified in [firmware-parsing.md](firmware-parsing.md).

---

## ESP Volume Discovery

The EFI System Partition is accessed as follows:

```
1. image_handle → EFI_LOADED_IMAGE_PROTOCOL → DeviceHandle
2. DeviceHandle → EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
3. SimpleFileSystem->OpenVolume() → root EFI_FILE_PROTOCOL handle
4. root->Open("\EFI\seraph\bootstrap.bundle") → bundle file handle (step 2)
5. root->Open("\EFI\seraph\kernel") → kernel file handle (step 3)
6. root->Open("\EFI\seraph\nokaslr") → presence probe only; the handle is closed at once (step 5d)
```

All files are opened as read-only. Sizes are determined via `EFI_FILE_INFO` before
reading. Files are read into physical memory allocated by `AllocatePages`; see
[elf-loading.md](elf-loading.md) for how segment placement works.

The bootloader carries three ESP path constants — `\EFI\seraph\kernel`,
`\EFI\seraph\bootstrap.bundle`, and the presence-only KASLR override knob
`\EFI\seraph\nokaslr` — all hardcoded in [`core/boot/src/main.rs`](../src/main.rs) (see
[elf-loading.md](elf-loading.md) § File Paths). There is no on-disk
boot configuration file; the bundle is the single composed artifact
that carries init plus every userspace module the system needs (see
[elf-loading.md](elf-loading.md) for how its entries are loaded). The
bundle format itself is specified in
[`abi/boot-protocol/src/bundle.rs`](../../../abi/boot-protocol/src/bundle.rs).

---

## Memory Allocation Strategy

All bootloader-owned allocation before `ExitBootServices` goes through `AllocatePages`. Two
allocation
modes are used:

**`AllocateAnyPages`** — the firmware selects a free physical page range. Used for
everything whose absolute address does not matter: the bundle buffer (boot modules are
referenced in place inside it), the kernel file buffer and kernel image span, init image
segments, page-table frames (and, on RISC-V, the paging-mode probe root and the AP trampoline
page), the `BootInfo` page, the module descriptor array, the `MemoryMapEntry` array, the
`MmioAperture` array, the kernel stack, the reclaim-range array, and the memory map buffer.
The kernel
image is placed as one contiguous span and its base recorded in
`BootInfo.kernel_physical_base`, so kernel placement tolerates any firmware memory
layout; see [elf-loading.md](elf-loading.md) for the placement sequence.

**`AllocateMaxAddress`** — the firmware selects a free range with a physical base at or
below a bound. Used only by the x86-64 AP-startup trampoline, whose SIPI vector must
reside below 1 MiB; see [boot-flow.md](boot-flow.md) for the trampoline-page step.

All allocation uses memory type `EfiLoaderData`. UEFI memory map entries for
`EfiLoaderData` regions translate to `MemoryType::Loaded` in the boot protocol,
notifying to the kernel that these regions are in use and must not be reused until
explicitly reclaimed; [memory-map.md](memory-map.md) owns the full translation policy.

The bootloader never frees its own `AllocatePages` allocations; the only deallocation
before `ExitBootServices` is `FreePool` on the pool buffers firmware returns from
`LocateHandleBuffer` and GOP `QueryMode`. Memory is allocated once and used; the bootloader
does not implement a heap. UEFI boot services terminate
before any reclamation would be relevant.

---

## Memory Map Acquisition

The acquisition protocol (map-key lifecycle, retry on stale key) lives
here; the translation policy from UEFI memory types into
`BootInfo.memory_map` entries and the per-entry invariants the kernel
can assume at handoff are owned by [memory-map.md](memory-map.md).


The UEFI memory map must be queried as the last action before `ExitBootServices`.
Every call to `AllocatePages` (or any other `BootServices` function that allocates
memory) invalidates the previous map key. Querying the map early and then allocating
more memory produces a stale key that causes `ExitBootServices` to fail.

The acquisition sequence:

```
1. Call GetMemoryMap(0, NULL, &map_key, &desc_size, &desc_version)
   to obtain the required buffer size.
2. AllocatePages(AllocateAnyPages, EfiLoaderData, pages_needed, &buf_addr)
   Note: this allocation itself invalidates any prior map key.
3. Call GetMemoryMap(buf_size, buf_addr, &map_key, &desc_size, &desc_version)
   to fill the buffer. The map_key from this call is the correct one to use.
```

Translation into `MemoryType` and the ascending sort by `physical_base` run after
`ExitBootServices`, in step 9 (`translate_memory_map`, `insertion_sort_memory_map`), per the
policy in [memory-map.md](memory-map.md).

The buffer allocation in step 2 increases the map size by at least one entry (the new
`EfiLoaderData` region). The buffer must be sized to accommodate this; the bootloader
adds 16 entries of slack, a prudent margin that also absorbs the further growth seen
when `ExitBootServices` re-queries the map under contention (see below).

### UEFI Memory Type Translation

The per-type translation policy and the post-translation invariants the
kernel may assume live in [memory-map.md](memory-map.md). This document
only owns the *acquisition* sequence above; the *meaning* of each UEFI
type in Seraph's memory model is authoritative there.

---

## ExitBootServices

The call sequence:

```
1. Perform the final memory map acquisition (above).
2. Call BootServices->ExitBootServices(image_handle, map_key).
3. If the call returns EFI_INVALID_PARAMETER (stale map key):
   a. Call GetMemoryMap again with the existing buffer (no new allocation),
      passing the full allocated buffer capacity as the size in-param.
   b. Update map_key from the new call.
   c. Retry ExitBootServices.
   d. Repeat from step 3 up to EXIT_BOOT_SERVICES_MAX_ATTEMPTS times total.
   e. If still failing after the bound: halt — the environment is unrecoverable.
4. Any status other than EFI_SUCCESS or EFI_INVALID_PARAMETER: halt immediately
   (not a stale-key condition, so retrying cannot help).
5. On success: UEFI boot services are now permanently unavailable.
```

The retry handles the case where UEFI performs an internal allocation between the
final query and the exit call — some firmware does this for housekeeping, and under
host CPU contention (e.g. parallel QEMU/OVMF instances sharing host cores) the vCPU
can be descheduled in that window, letting a firmware event allocate and invalidate
the key repeatedly across attempts. A *single* retry is therefore insufficient; the
loop is bounded at `EXIT_BOOT_SERVICES_MAX_ATTEMPTS` (16) attempts. Each re-query
reuses the existing buffer — allocating a new one would invalidate the key again —
and passes the allocated buffer capacity, so it tolerates a map that grew since the
previous query. No delay is inserted between the query and the exit call: that would
only widen the invalidation window.

### Post-Exit Constraints

After `ExitBootServices` returns:

- `BootServices` pointer is invalid; calling any boot service causes undefined behaviour
- `RuntimeServices` pointer remains technically valid (UEFI runtime services), but
  Seraph does not use runtime services and makes no runtime calls
- Memory descriptors in the acquired map buffer remain valid; the buffer was allocated
  as `EfiLoaderData` and is not reclaimed by UEFI
- Only pre-allocated memory (from `AllocatePages` calls made before the exit) is
  available; no further allocation is possible

The bootloader performs no allocation-dependent operations after `ExitBootServices`.
`BootInfo` population and kernel handoff use only data gathered before the exit.

---

## Error Handling Strategy

Every `BootError` is fatal. A few optional resources degrade instead of failing: an absent
GOP (headless), an absent or failing `EFI_RNG_PROTOCOL` (DTB `/chosen/rng-seed` fallback, else
no seed and the deterministic layout), and a failed AP-trampoline allocation (logged as a
warning). There is no recovery path for a `BootError`, no retry beyond the bounded
`ExitBootServices` retry loop described above, and no fallback configuration.

### BootError Type

Every fatal error is a `BootError`, returned as `Result<T, BootError>`,
defined in [`core/boot/src/error.rs`](../src/error.rs). The variant set covers
protocol-location failure, UEFI status-code propagation, ESP file-not-found,
ELF validation failure, W^X violation, allocation failure, `ExitBootServices`
failure after the bounded retry loop, bundle parse/validation failure (`InvalidBundle`),
and, on RISC-V, no supported paging mode passing the satp probe (`PagingModeUnsupported`);
the source is the authority on the variant list and payloads.

The top-level `efi_main` propagates every `BootError` to a single fatal handler
(`error::fatal_error`) that reports the error and halts. Two halts bypass it: a
`reclaim_ranges` overflow in step 9 prints
`[--------] boot: FATAL: reclaim_ranges overflow (bump MAX_RECLAIM_RANGES)` and spins in
place, and a panic prints `SERAPH BOOT PANIC: <panic info>` from the panic handler.

### Error Reporting

Error messages are written through the boot console (serial + framebuffer; see
[console.md](console.md)), which does not depend on UEFI boot services and so
remains available after `ExitBootServices`. A fatal `ExitBootServices` failure is
therefore reported the same way as any earlier failure.

Error reporting writes a short descriptive message and halts:

```
SERAPH BOOT FATAL: <error description>
```

No elaborate formatting, no stack traces, no recovery prompts. The message is
sufficient to identify which step failed and why.

---

## Console Output

The boot console (serial + framebuffer; see [console.md](console.md) for the
backends) reaches the hardware directly and never uses the firmware text-output
protocol (`ConOut`). The property that matters here is that neither backend
depends on UEFI boot services.

### After ExitBootServices

Because the console is boot-services-independent, output continues right up to
kernel handoff: the `step 9/10` and `step 10/10` progress lines, and any fatal
message, are emitted after the exit call.

---

## Summarized By

[core/boot/README.md](../README.md), [Boot Flow](boot-flow.md), [Early Console](console.md),
[ELF Loading](elf-loading.md), [Memory Map Translation](memory-map.md)
