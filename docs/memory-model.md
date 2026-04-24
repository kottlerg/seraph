# Memory Model

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

### RISC-V (Sv48)

RISC-V with the Sv48 paging mode mirrors the x86-64 layout: 48-bit virtual addresses,
the same canonical split, and 4-level page tables. The kernel is placed in the upper
half at the same logical positions as on x86-64, enabling shared reasoning about the
memory layout across architectures.

```
  0xFFFFFFFFFFFFFFFF ┐
                     │  Kernel space (128 TiB)
  0xFFFF800000000000 ┘
  ~~~~~~~~~~~~~~~~~~~~  (Sv48 upper/lower split)
  0x00007FFFFFFFFFFF ┐
                     │  Userspace (128 TiB)
  0x0000000000000000 ┘
```

Sv48 is chosen to align with x86-64's address space size.

### Userspace Layout

Each process address space begins empty. The program loader (running in userspace)
maps segments as directed by the binary format. The general convention is:

```
  0x00007FFFFFFFFFFF ┐
                     │  Stack (grows downward)
                     │  (guard page below stack)
                     │
                     │  Shared mappings / mmap region
                     │
                     │  Heap (grows upward)
                     │
  0x0000000000400000 ┘  Program image (text, rodata, data, bss)
```

Stack and heap placement will be randomised (ASLR) once the kernel's random number
source is available. Exact base addresses are not fixed at this stage.

Concrete VA zone assignments, the heap-grow protocol, and ownership boundaries
between the kernel, procmgr, and `std::sys::seraph` are documented in
[userspace-memory-model.md](userspace-memory-model.md).

---

## Paging

### Page Sizes

The base page size is 4 KiB on both architectures. Large pages (2 MiB on x86-64,
megapages on RISC-V Sv48) are used where beneficial — primarily the kernel direct map
and large contiguous device mappings. Huge pages (1 GiB) may be used for the direct
map on systems with sufficient RAM.

Userspace mappings use 4 KiB pages by default. Large page support for userspace is
a future optimisation.

### W^X Enforcement

No page is simultaneously writable and executable. This is enforced at the page table
level using the NX bit (x86-64) and the equivalent execute permission control on
RISC-V. The kernel image itself follows W^X: text is executable but not writable;
data and heap are writable but not executable.

### TLB Management — PCIDs and ASIDs

Context switches between processes normally require a full TLB flush, discarding all
cached address translations. This is expensive on multi-core systems with large working
sets.

Both architectures provide hardware tags for TLB entries:
- **x86-64:** Process-Context Identifiers (PCIDs) — 12-bit tag per address space
- **RISC-V:** Address Space Identifiers (ASIDs) — width is implementation-defined,
  typically 16 bits on RV64

The kernel assigns a PCID/ASID to each address space. On context switch, the
incoming PCID/ASID is loaded without a full flush — the hardware retains and correctly
disambiguates cached translations from multiple address spaces. A global flush is only
required when an address space's PCID/ASID is recycled.

PCID/ASID availability is detected at boot. The kernel falls back to full TLB flushes
on hardware that does not support them.

### Kernel Isolation — SMEP and SMAP

On x86-64, SMEP (Supervisor Mode Execution Prevention) and SMAP (Supervisor Mode
Access Prevention) are enabled unconditionally where available. SMEP prevents the
kernel from executing userspace pages; SMAP prevents the kernel from reading or
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

The allocator is organised into zones if the hardware requires it (e.g. DMA-accessible
memory below a certain physical address). The common case is a single zone covering
all usable RAM.

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

[Architecture Overview](architecture.md)
