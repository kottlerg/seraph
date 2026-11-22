# UEFI Environment

The bootloader is a UEFI application. Before `ExitBootServices`, all hardware access
and memory allocation goes through UEFI firmware services. After `ExitBootServices`,
UEFI boot services are permanently unavailable; the bootloader operates exclusively
from pre-allocated memory.

This document covers the UEFI protocols used, allocation strategy, the stack the
bootloader runs on, memory map acquisition, `ExitBootServices`, and error handling.

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
| `EFI_RNG_PROTOCOL` | `LocateProtocol` | Draw the 32-byte entropy-pool seed and an independent 16-byte KASLR draw (two words; step 5c) | No |
| `EFI_RISCV_BOOT_PROTOCOL` | `LocateProtocol` | Read the boot hart ID (RISC-V only; 0 when absent) | No |
| All handles | `LocateHandleBuffer(AllHandles)` + `ConnectController` | Bind drivers (e.g. virtio-gpu to GOP) not auto-connected during BDS, before the GOP query | No |
| Variable services | `RuntimeServices->GetVariable` / `SetVariable` / `QueryVariableInfo` | Read the firmware's Secure Boot state; read and raise the machine's security floor; read and write the enrolled trust store (§ Variable Services) | No |
| `EFI_SIMPLE_TEXT_INPUT_PROTOCOL` | `SystemTable->ConIn` | Read the console's answer to a trust request no signature authorizes (§ Console Input) | No |
| Timer events | `BootServices->CreateEvent` / `SetTimer` / `WaitForEvent` / `CloseEvent` | Bound the wait for that answer (§ Console Input) | No |

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
6. root->Open("\EFI\seraph\trust-request") → optional; read whole when present (step 3)
7. root->Open("\EFI\seraph\nokaslr") → presence probe only; the handle is closed at once (step 5d)
8. root->Open("\EFI\seraph\mapredo") → presence probe only; the handle is closed at once (step 6)
```

All files are opened as read-only. Sizes are determined via `EFI_FILE_INFO` before
reading. Files are read into physical memory allocated by `AllocatePages`; see
[elf-loading.md](elf-loading.md) for how segment placement works.

The bootloader carries five ESP path constants — `\EFI\seraph\kernel`,
`\EFI\seraph\bootstrap.bundle`, the presence-only KASLR override knob
`\EFI\seraph\nokaslr`, the presence-only steps 6 and 7 redo test knob
`\EFI\seraph\mapredo`, and the optional trust request `\EFI\seraph\trust-request`
([docs/signing.md](../../../docs/signing.md) § Trust Store) — all hardcoded in
[`core/boot/src/main.rs`](../src/main.rs) (see [elf-loading.md](elf-loading.md) § File Paths).
There is no on-disk boot configuration file; the bundle is the single composed artifact
that carries init plus every userspace module the system needs (see
[elf-loading.md](elf-loading.md) for how its entries are loaded). The
bundle format itself is specified in
[`abi/boot-protocol/src/bundle.rs`](../../../abi/boot-protocol/src/bundle.rs).

---

## Memory Allocation Strategy

All bootloader-owned allocation before `ExitBootServices` goes through `AllocatePages`. Two
allocation modes are used:

**`AllocateAnyPages`** — the firmware selects a free physical page range. Used for
everything whose absolute address does not matter: the bundle buffer (boot modules are
referenced in place inside it), the kernel file buffer, the kernel image span on RISC-V,
init image segments, the page-table frame pool on RISC-V (and the paging-mode probe root
and the AP trampoline page), the `BootInfo` page, the module
descriptor array, the `MemoryMapEntry` array, the `MmioAperture` array, the kernel stack,
the reclaim-range array, and the memory map buffer. The kernel image is placed as one
contiguous span and its base recorded in `BootInfo.kernel_physical_base`, so kernel
placement does not depend on a fixed firmware layout; see [elf-loading.md](elf-loading.md)
for the placement sequence.

**`AllocateMaxAddress`** — the firmware selects a free range whose uppermost address is at
or below a bound. Used only on x86-64: for the AP-startup trampoline, whose SIPI vector must
reside below 1 MiB (see [boot-flow.md](boot-flow.md) for the trampoline-page step); for
the kernel image span, which must lie wholly below 4 GiB because the kernel's root page
table sits in the image's BSS and the AP trampoline loads it into CR3 with a 32-bit move
(`BootInfo.kernel_physical_base` in
[abi/boot-protocol](../../../abi/boot-protocol/src/lib.rs)); and, below 4 GiB, for the
page-table frame pool, whose first frame is the initial root page table, and the LA57
toggle page, since the toggle trampoline runs with 32-bit addresses and loads that root
with a 32-bit move
([page-tables.md](page-tables.md) § x86-64: Negotiated Paging Depth).

Every allocation uses memory type `EfiLoaderData` except the x86-64 LA57 toggle page, which
is `EfiLoaderCode` because the bootloader executes it under the firmware's tables, whose NX
policy may cover `EfiLoaderData`. UEFI memory map entries for `EfiLoaderCode` and
`EfiLoaderData` regions translate to `MemoryType::Loaded` in the boot protocol,
notifying to the kernel that these regions are in use and must not be reused until
explicitly reclaimed; [memory-map.md](memory-map.md) owns the full translation policy.

Two `AllocatePages` allocations are returned with `FreePages` before `ExitBootServices`,
each zeroed first: the kernel ELF file buffer, once step 3 has copied the image out, and,
on RISC-V, the paging-mode probe root, once the mode is negotiated
([memory-map.md](memory-map.md) § Allocation-Class Classification). The only other
deallocation before `ExitBootServices` is `FreePool` on the pool buffers firmware returns
from `LocateHandleBuffer` and GOP `QueryMode`. Every other allocation is made once and
kept; the bootloader does not implement a heap, and the scratch it keeps past
`ExitBootServices` is recorded in `BootInfo.reclaim_ranges` for the kernel to reclaim.

---

## Stack

The bootloader runs on the stack the firmware enters `efi_main` on, before and after
`ExitBootServices`, until step 10 switches to the kernel handoff stack it allocated
([boot-flow.md](boot-flow.md)). It allocates no stack of its own. The UEFI specification
guarantees an image 128 KiB or more of available stack space during boot services, in the
calling convention it sets for each of x64 and RISC-V, so 128 KiB bounds the bootloader's
deepest call chain. A quarter of it, 32768 bytes, is the bootloader's `large_stack_frames`
threshold (`stack-size-threshold` in `core/boot/clippy.toml`;
[docs/coding-standards.md](../../../docs/coding-standards.md) § Clippy). A signature
verification, its certificate's included, was measured at under 11 KiB of the 128 KiB
([docs/signing.md](../../../docs/signing.md) § Composite Signature). The firmware's stack
lies in `EfiBootServicesData` memory, which the kernel zeroes before minting it to userspace
([memory-map.md](memory-map.md)).

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
   A desc_size below EFI_MEMORY_DESCRIPTOR's fails the boot
   (BootError::InvalidMemoryMap): every reader steps through the map at it.
```

Translation into `MemoryType` and the ascending sort by `physical_base` run after
`ExitBootServices`, in step 9 (`translate_memory_map`, `insertion_sort_memory_map`), per the
policy in [memory-map.md](memory-map.md).

The buffer allocation in step 2 increases the map size by at least one entry (the new
`EfiLoaderData` region). The buffer must be sized to accommodate this; the bootloader
adds 16 entries of slack (`uefi::MAP_BUFFER_SLACK_DESCRIPTORS`), a prudent margin that
also absorbs the further growth seen when `ExitBootServices` re-queries the map under
contention (see below). The buffer, rounded to whole pages, bounds every map read into
it, and step 6 sizes the translated entry array to that bound
([memory-map.md](memory-map.md) § Sizing the Entry Array).

### UEFI Memory Type Translation

The per-type translation policy and the post-translation invariants the
kernel may assume live in [memory-map.md](memory-map.md). This document
only owns the *acquisition* sequence above; the *meaning* of each UEFI
type in Seraph's memory model is authoritative there.

---

## Variable Services

The bootloader reads the firmware's UEFI Secure Boot state
([docs/signing.md](../../../docs/signing.md) § Secure Boot), reads and writes the machine's security
floor ([docs/signing.md](../../../docs/signing.md) § Rollback Floor), and reads and writes the
enrolled trust store ([docs/signing.md](../../../docs/signing.md) § Trust Store), through the
`VariableServices` trait of [`core/boot/src/uefi.rs`](../src/uefi.rs). `FirmwareVariables`
implements it over the system table's `RuntimeServices->GetVariable`, `SetVariable` and
`QueryVariableInfo`; host tests implement it over a store in memory. `GetVariable` returns one of
four outcomes (`VariableRead`): the variable and its attributes, no such variable, a variable larger
than the caller's buffer (with its length), or a failure status. A system table with no runtime
services, or a name without its terminating NUL, fails without a call. `QueryVariableInfo` reports
the storage the firmware has for variables of the given attributes: its total, what remains, and its
largest variable. A runtime services table whose header size does not reach the entry lacks it, and
the call fails without being made.

Every Seraph variable is named under the Seraph vendor GUID (`SERAPH_VENDOR_GUID`) and carries
`NON_VOLATILE | BOOTSERVICE_ACCESS` and never `RUNTIME_ACCESS`, so nothing reaches it once boot
services have exited. The Secure Boot state is the firmware's `SecureBoot` and `SetupMode`,
under the global variable GUID (`EFI_GLOBAL_VARIABLE_GUID`), each one byte of 0 or 1 with
`BOOTSERVICE_ACCESS | RUNTIME_ACCESS` and not `NON_VOLATILE`, as the firmware sets them; the
bootloader reads them and never writes them. A `SecureBoot` of another shape, a non-volatile
copy among them, reads as `unknown`, never as `on`; with `SecureBoot` at 0, a `SetupMode` of
another shape, or none, reads as `off` with that as its reason
(`core/boot/src/secure_boot.rs`). Every variable call is made before `ExitBootServices`, and none
after it: the state is read right after step 1 of [boot-flow.md](boot-flow.md), the floor
once the trust store parses, the enrolled store once the kernel and the bundle are read (step 3),
the enrolled store written when a trust request is applied, before any object is verified for
loading, and the floor written once every object has verified (step 4), ahead of the memory-map
reads of steps 6 and 7. The enrolled store is the variable `TrustStore`; before writing it the
bootloader queries the firmware's largest variable, where `QueryVariableInfo` answers, and refuses
the request when the store would not fit. A variable service the firmware lacks or fails is a
warning, a logged state or a refused request, not a halt; only a floor that refuses the
bootloader, a malformed floor, or a malformed enrolled store is fatal.

---

## ExitBootServices

The call sequence:

```
1. Perform the final memory map acquisition (above).
2. Call BootServices->ExitBootServices(image_handle, map_key).
3. If the call returns EFI_INVALID_PARAMETER (stale map key):
   a. Call GetMemoryMap again with the existing buffer (no new allocation),
      passing the full allocated buffer capacity as the size in-param.
   b. Update map_key, the map size and the descriptor size from the new call,
      rejecting a descriptor size below EFI_MEMORY_DESCRIPTOR's (the body it
      rewrote is read at that stride).
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
  Seraph makes no runtime-services call after the exit; its variable calls all come
  before it (§ Variable Services)
- Memory descriptors in the acquired map buffer remain valid; the buffer was allocated
  as `EfiLoaderData` and is not reclaimed by UEFI. Step 9 zeroes it after its last read
  and records it in `BootInfo.reclaim_ranges`
- Only pre-allocated memory (from `AllocatePages` calls made before the exit) is
  available; no further allocation is possible

The bootloader performs no allocation-dependent operations after `ExitBootServices`.
`BootInfo` population and kernel handoff use only data gathered before the exit.

---

## Error Handling Strategy

Every `BootError` that reaches `efi_main` is fatal. Five sites consume a `BootError` instead of
returning it: a failed open of `\EFI\seraph\nokaslr` reads as an absent knob
([boot-flow.md § Step 5d](boot-flow.md#step-5d-apply-the-kaslr-slide)), as does a failed open of
`\EFI\seraph\mapredo`
([memory-map.md § Sizing the Entry Array](memory-map.md#sizing-the-entry-array)); a failed open
of `\EFI\seraph\trust-request` reads as no request, and a kernel or bundle entry that would not
verify under the store a trust request gives refuses the request
([boot-flow.md § Step 3](boot-flow.md#step-3-load-kernel-elf)); and a failed AP-trampoline
allocation is logged as a warning and records zero
([boot-flow.md § Step 5b](boot-flow.md#step-5b-allocate-the-ap-trampoline-page)). Optional
resources degrade instead of failing: an absent GOP leaves the system headless, and an absent or
failing entropy source falls back as
[boot-flow.md § Step 5c](boot-flow.md#step-5c-boot-entropy-seed) describes. There is no recovery
path for a `BootError` that reaches `efi_main`, no retry beyond the bounded `ExitBootServices`
retry loop described above and the bounded redo of steps 6 and 7 on a memory map that outgrew
its entry array ([memory-map.md](memory-map.md) § Sizing the Entry Array), and no fallback
configuration.

### BootError Type

Every fatal error returned through `Result` is a `BootError` (`Result<T, BootError>`), defined in
[`core/boot/src/error.rs`](../src/error.rs). The variant set covers protocol-location failure, UEFI
status-code propagation, ESP file-not-found, ELF validation failure, W^X violation, allocation
failure, `ExitBootServices` failure after the bounded retry loop, bundle parse/validation failure
(`InvalidBundle`), an embedded trust store that does not parse (`TrustStore`), a malformed enrolled
trust store (`EnrolledMalformed`, naming the recovery), the verifier's
refusal of the kernel or a bundle entry (`SignatureRefused`, naming the object;
[docs/signing.md](../../../docs/signing.md) § Verifier Discipline), on RISC-V no supported paging
mode passing the satp probe (`PagingModeUnsupported`), a firmware memory map that violates the UEFI
contract (`InvalidMemoryMap`), a memory map that outgrows its entry array on every run of steps 6
and 7 (`MemoryMapKeptGrowing`, [memory-map.md](memory-map.md) § Sizing the Entry Array), in step 6 a
range to map that runs past the end of the address space (`MapAddressRange`), and, in step 9, a
`reclaim_ranges` overflow (`ReclaimRangesOverflow`, unreachable while the compile-time entry count
holds); the source is the authority on the variant list and payloads.

The top-level `efi_main` propagates every `BootError` to a single fatal handler
(`error::fatal_error`) that reports the error and halts; it needs no boot service, so
the step 9 failures, after `ExitBootServices`, reach it too. Only a panic bypasses it,
printing `SERAPH BOOT PANIC: <panic info>` from the panic handler.

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

## Console Input

The bootloader reads the console once, and only to confirm a trust request that no signature
authorizes ([docs/signing.md](../../../docs/signing.md) § Trust Store). It reads through the
`ConsoleInput` trait of [`core/boot/src/uefi.rs`](../src/uefi.rs); `FirmwareConsole` implements it
over the system table's `ConIn` (`EFI_SIMPLE_TEXT_INPUT_PROTOCOL`), which the firmware feeds from
every console it has, the serial port among them; host tests implement it over keys in memory. It
resets `ConIn`, discarding keys typed before the question, prints the question, and waits on
`ConIn`'s key event and a relative timer event of 60 seconds with `WaitForEvent`. Each printable key
read with `ReadKeyStroke` is added to the line and echoed, Backspace removes the last character,
other keys are ignored, and Enter ends the line, which confirms the request only when it is exactly
`yes`; the timer's firing ends the wait as no answer. The timer is the first event of the wait,
since `WaitForEvent` returns the first signalled event in its array's order: keys that keep arriving
do not hold the wait past it. The timer, not `Stall`, bounds the wait, since a firmware may run
`Stall` on no clock. The timer event is closed on every path. A `ReadKeyStroke` that finds no key
(`EFI_NOT_READY`) waits again. A `ConIn` that is absent, or any other call that fails, refuses the
request.

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
