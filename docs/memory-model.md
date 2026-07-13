# Memory Model

System-scope virtual address space layout, paging, and physical memory
management for both supported architectures.

---

## Overview

Seraph uses a conventional higher-half kernel layout on both supported architectures.
The kernel occupies the upper portion of the virtual address space; userspace processes
occupy the lower portion. Each process has its own isolated address space. The kernel
address space is mapped into every address space but is inaccessible from userspace.

Physical memory is managed by a buddy allocator. The kernel heap uses a slab allocator
with a general size-class path for variable-size allocations.

---

## Virtual Address Space Layout

### x86-64

x86-64 with 4-level paging provides 48-bit virtual addresses. Only addresses in two
canonical ranges are valid — the hardware raises a fault on any access to a
non-canonical address, providing a natural guard between userspace and kernel space.

```
  0xFFFFFFFFFFFFFFFF ┐
                     │  Kernel space (128 TiB)
  0xFFFF800000000000 ┘
  ~~~~~~~~~~~~~~~~~~~~  (non-canonical gap — hardware enforced)
  0x00007FFFFFFFFFFF ┐
                     │  Userspace (128 TiB)
  0x0000000000000000 ┘
```

Kernel space is divided into regions:

```
  0xFFFFFFFFFFFFFFFF ┐
                     │  Kernel heap (slab + size-class allocator)
                     │
                     │  Kernel image (text, rodata, data, bss)
                     │
  0xFFFF800000000000 ┘  Physical memory direct map (all RAM, read/write)
```

The physical memory direct map gives the kernel a virtual address for every physical
page. Large pages (2 MiB) are used where alignment allows.

Exact region boundaries are an implementation detail and will be fixed at the time
the kernel memory layout is initialised. They are not ABI.

### RISC-V (Sv39 / Sv48 / Sv57)

RISC-V supports three address-translation modes on this port, negotiated at
boot: the bootloader reads the DTB `mmu-type` claim, confirms it with a
`satp` write-probe (falling back mode by mode), and the kernel recovers the
active mode from `satp` at entry. Sv39 is the RVA23 platform minimum, Sv48
the standing default (aligning with x86-64's address-space size), Sv57 a
wider expansion ([platform-requirements.md](platform-requirements.md)). One
kernel binary supports all three; every VA-layout constant that varies with
the mode is derived from it at runtime.

Each mode mirrors the x86-64 structure — a canonical split with userspace in
the lower half and the kernel in the upper half, whose base is root page-table
entry 256 in every mode:

```
  Mode   Levels  VA bits  Userspace (lower half)      Kernel space (upper half)
  Sv39   3       39       [0, 0x0000004000000000)     [0xFFFFFFC000000000, top]
  Sv48   4       48       [0, 0x0000800000000000)     [0xFFFF800000000000, top]
  Sv57   5       57       [0, 0x0100000000000000)     [0xFF00000000000000, top]
  ~~~~~~~~~~~~~~~~~~~~ (non-canonical gap between the halves — hardware enforced)
```

The physical direct map starts at the active mode's kernel-half base; the
kernel image stays at the top 2 GiB, canonical in every mode. Under Sv39 the
kernel half is 256 GiB total, capping direct-mappable RAM at 254 GiB — the
kernel refuses to boot beyond that rather than overlap the image mapping.
All fixed userspace-layout zones sit below 2^38, the smallest user half, so
one static userspace layout is canonical in every mode
([userspace-memory-model.md](userspace-memory-model.md)).

### Userspace Layout

Each process address space begins empty. The program loader (running in userspace)
maps segments as directed by the binary format. The general convention is:

```
  (user VA ceiling)  ┐
                     │  Stack (grows downward)
                     │  (guard page below stack)
                     │
                     │  Shared mappings / mmap region
                     │
                     │  Heap (grows upward)
  (low VA)           ┘  Program image (text, rodata, data, bss)
```

The diagram shows the ordering convention only: each region's base is
randomised per process within a fixed window (ASLR,
[#39](https://github.com/kottlerg/seraph/issues/39)). Concrete VA management
surfaces, the per-region randomisation windows, the frame-allocation
contract, and ownership boundaries between the kernel, memmgr, procmgr, and
`std::sys::seraph` are documented in
[userspace-memory-model.md](userspace-memory-model.md). The userspace boot
order and the process-creation/death flow are in
[process-lifecycle.md](process-lifecycle.md).

---

## Paging

### Page Sizes

The base page size is 4 KiB on both architectures. Large pages (2 MiB on x86-64,
megapages on RISC-V) are used where beneficial — primarily the kernel direct map
and large contiguous device mappings. Huge pages (1 GiB) may be used for the direct
map on systems with sufficient RAM.

Userspace mappings use 4 KiB pages by default. Large page support for userspace is
a future optimisation.

### W^X Enforcement

No page is simultaneously writable and executable. This is enforced at the page table
level using the NX bit (x86-64) and the equivalent execute permission control on
RISC-V. The kernel image itself follows W^X: text is executable but not writable;
data and heap are writable but not executable.

On x86-64, kernel-side W^X additionally depends on `CR0.WP` (supervisor write-protect);
without it a ring-0 write would bypass a read-only page permission. `CR0.WP` is required by
the platform baseline ([platform-requirements.md](platform-requirements.md)) and set on every CPU.

### TLB Management

Address-space tags (x86-64 PCID, RISC-V ASID) are required by the platform baseline
([platform-requirements.md](platform-requirements.md)). The kernel assigns a tag per address space
so a context switch loads the outgoing space's page-table root **without** flushing the TLB —
cached translations survive across switches. A switch between threads that share an address space
requires no TLB operation either way. On RISC-V a hart without ASID support is refused at boot; on
x86-64 the kernel retains a full-flush fallback for emulated environments that do not implement
PCID.

Eliding the per-switch flush requires keeping tagged entries coherent without it. Two
generation counters do this:

- A global tag allocator stamps each tag claim with a unique generation. A CPU records, per
  tag, the generation it last loaded; when it loads a tag whose recorded generation differs,
  the tag was reissued to a different address space and the CPU flushes just that tag. This
  is the cross-CPU invalidation-before-reissue guarantee, so a finite tag pool can be
  recycled safely — on exhaustion the least-recently-claimed tag whose owner is not active
  on any CPU is evicted.
- Each address space carries a TLB generation bumped on every unmap or permission
  narrowing. A CPU that was switched away when the change happened flushes the tag on its
  next reactivation if its synced generation lags; CPUs currently running the space are
  reached directly by the SMP shootdown.

Tag 0 is reserved for the kernel/idle context and the full-flush fallback and is never
assigned to a user space. Single-address invalidation after a mapping change uses `invlpg`
(x86-64) or `sfence.vma <va>` (RISC-V) on the current space; cross-CPU shootdown uses the
tag-targeted forms (`invpcid` / `sfence.vma <va>, <asid>`) so a CPU that has since switched
spaces still invalidates the right translation. Cross-CPU invalidation uses the SMP
shootdown protocol described in the kernel memory-internals document.

The `CAP_INFO_TLB_ELIDED` / `CAP_INFO_TLB_PERFORMED` `cap_info` selectors expose system-wide
counts of context switches that elided versus performed the flush — the
emulation-independent measure of the optimization.

### Kernel Isolation — SMEP and SMAP

On x86-64, SMEP (Supervisor Mode Execution Prevention) and SMAP (Supervisor Mode
Access Prevention) are required by the platform baseline
([platform-requirements.md](platform-requirements.md)) and enabled unconditionally. SMEP
prevents the kernel from executing userspace pages; SMAP prevents the kernel from reading or
writing userspace memory except through designated safe copy routines. Together these
mitigate a class of privilege escalation exploits.

RISC-V enforces equivalent isolation through the PMP (Physical Memory Protection)
unit and the `SUM` bit in `sstatus`, which controls supervisor access to user pages.

---

## Physical Memory Management

### Boot-Time Memory Map

At boot, the bootloader provides a memory map via the `BootInfo` structure
(see [`abi/boot-protocol/`](../abi/boot-protocol/)) describing which physical address ranges
are usable RAM, reserved, or used by firmware. The kernel parses this map during early
initialisation before the frame allocator is active. Memory used by the kernel image,
boot modules, and reserved regions is marked unavailable.

### Bootloader Scratch Reclamation

Pages the bootloader allocated for its own scratch use are recorded in
`BootInfo.reclaim_ranges` and minted as reclaimable Memory caps into
init's CSpace by the kernel-initialisation reclaim-minting steps. See
[`core/kernel/docs/initialization.md`](../core/kernel/docs/initialization.md)
Phase 7 (standard reclaim mint) and Phase 8 (`RECLAIM_FLAG_LATE`
late-mint for the AP SIPI trampoline page) for the authoritative
mechanism.

### Buddy Allocator

Physical frames are managed by a buddy allocator. Memory is divided into blocks whose
sizes are powers of two (in pages). Allocation of `n` pages returns the smallest
available power-of-two block that fits. When a block is freed, it is merged with its
adjacent "buddy" block if that buddy is also free, recursively coalescing up to the
maximum order.

Properties:
- O(log n) allocation and deallocation
- Bounded external fragmentation
- Internal fragmentation bounded at 50%

The allocator manages a single zone covering all usable RAM. Physical-address-range
constraints (e.g. DMA-accessible memory below a certain physical address) are not a
kernel concern: DMA isolation and placement are handled in userspace by devmgr and
the memory authority (see [architecture.md](architecture.md) and
[device-management.md](device-management.md)).

Physical frame 0 (the zero page) is excluded from the allocator. The page-table and
CSpace growth pools use a physical address of 0 as their free-list "empty" sentinel,
so admitting frame 0 as a pool page would make an occupied list indistinguishable from
an empty one. Excluding it (one frame) keeps the sentinel unambiguous regardless of
how firmware classifies `[0, PAGE_SIZE)`.

### Frame Allocation is Fallible

Frame allocation can fail. Every call site must handle `None` or an error result
explicitly. There is no OOM killer; a failed allocation propagates as an error to
the caller. This applies inside the kernel as well as in userspace allocation paths.

---

## Kernel Heap

The kernel heap provides dynamic allocation for internal kernel objects. It is built
on top of the buddy allocator and never exposed to userspace.

### Slab Allocator

Fixed-size kernel objects — capability entries, thread control blocks, IPC endpoints,
address space descriptors, page table nodes — are managed by a slab allocator. Each
object type has a dedicated slab cache:

- The cache holds one or more slabs, each a physically contiguous set of pages
- Each slab is divided into fixed-size slots for that object type
- Allocation and deallocation within a slab are O(1)
- Free slots are tracked with a free list embedded in unused object memory

### General Size-Class Allocator

For the occasional variable-size allocation (e.g. dynamic arrays, strings in kernel
paths), a size-class allocator provides bins at powers of two (16, 32, 64, 128, ...
bytes). Each bin is backed by slab pages from the buddy allocator. This provides
O(1) allocation with bounded fragmentation for the general case without implementing
a full general-purpose allocator.

Allocations larger than the largest bin size are served directly from the buddy
allocator.

### Kernel Heap Allocation is Fallible

Kernel heap allocation MUST be handled as fallible at every call site.

---

## Summarized By

[README.md](../README.md), [Architecture Overview](architecture.md)
