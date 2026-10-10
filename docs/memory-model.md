# Memory Model

System-scope virtual address space layout, paging, and physical memory
management for both supported architectures.

---

## Overview

Seraph uses a conventional higher-half kernel layout on both supported architectures.
The kernel occupies the upper portion of the virtual address space; userspace processes
occupy the lower portion. Each process has its own isolated address space. The kernel
address space is mapped into every address space but is inaccessible from userspace.

Physical memory is managed by a buddy allocator until the Phase 7 handoff, after which
every page of RAM is either a fixed kernel reserve or a userspace Memory capability;
kernel objects are carved out of Memory capabilities by retype (see Kernel Object
Memory).

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
                     │  Kernel image (text, rodata, data, bss) — top 2 GiB window,
                     │    base randomized per boot (KASLR)
                     │
                     │  Physical memory direct map (all RAM, read/write),
  0xFFFF800000000000 ┘    base randomized per boot at or above this floor (KASLR)
```

The physical memory direct map gives the kernel a virtual address for every physical
page. The RAM portion is mapped with 2 MiB large pages; a framebuffer or kernel MMIO
region above the RAM ceiling gets 4 KiB pages.

Both the kernel image base and the direct-map base are randomized at boot behind
the boot-entropy source (KASLR,
[#252](https://github.com/kottlerg/seraph/issues/252)): the image slides within
the top 2 GiB at 2 MiB granularity, and the direct map is placed at a 1 GiB-aligned
base at or above the kernel-half floor, below the image. With no boot entropy, or with
the bootloader's `nokaslr` override knob present, the layout falls back to the fixed
defaults shown above. Exact region boundaries are an
implementation detail, not ABI.

### RISC-V (Sv39 / Sv48 / Sv57)

RISC-V supports three address-translation modes on this port, negotiated at boot by the bootloader
([core/boot/docs/page-tables.md](../core/boot/docs/page-tables.md) § Mode negotiation); the kernel
recovers the active mode from `satp` at entry. Sv39 is the RVA23 platform minimum, Sv48 the standing
default in CI and development (`cargo xtask` caps the QEMU guest at Sv48 by default, aligning with
x86-64's address-space size; its `--riscv-mmu` flag selects another mode, per
[xtask/README.md](../xtask/README.md)), Sv57 a wider expansion
([platform-requirements.md](platform-requirements.md)). One kernel binary supports all three; every
VA-layout constant that varies with the mode is derived from it at runtime.

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

The physical direct map is placed at a 1 GiB-aligned base at or above the active
mode's kernel-half base (randomized per boot, KASLR); the kernel image slides
within the top 2 GiB, canonical in every mode. Under Sv39 the kernel half is
256 GiB total, so the direct map cannot exceed 254 GiB without overlapping the image
window, and the kernel refuses to boot rather than overlap (the Phase-3 boot page-table
pool, `BOOT_TABLE_POOL_SIZE`, independently limits direct-mapped RAM to about 248 GiB in
every mode); a near-full Sv39 half narrows
the direct-map randomization window (falling back to the kernel-half floor when
fewer than two 1 GiB slots remain).
All fixed userspace-layout zones sit below 2^38, the smallest user half, so
one static userspace layout is canonical in every mode
([userspace-memory-model.md](userspace-memory-model.md)).

### Userspace Layout

Each process address space begins empty. The process creator (the kernel for init,
init for memmgr and procmgr, procmgr for everything else) maps segments as directed by
the binary format. The general convention is:

```
  2^38 (layout ceiling) ┐
                        │  Program image (PIE load-bias window)
                        │  Main-thread stack (guard page below), handover page,
                        │    IPC buffer, main-thread TLS
                        │  Page-reservation arena (foreign mappings)
                        │  Byte heap (grows upward)
  (low VA)              ┘
```

The diagram shows the ordering convention only: each region's base is randomised per
process within a fixed window (ASLR, [#39](https://github.com/kottlerg/seraph/issues/39)).
When an entropy draw fails, the byte heap, the page-reservation arena, and the program image
fall back to their window bases, while the bootstrap VAs fall back to fixed `DEFAULT_*`
addresses above the image window, so the ordering above does not hold for them (see
[userspace-memory-model.md](userspace-memory-model.md) § Bootstrap Cross-Boundary VAs).
Concrete VA management surfaces, the per-region randomisation windows, the frame-allocation
contract, and ownership boundaries between the kernel, memmgr, procmgr, and
`std::sys::seraph` are documented in [userspace-memory-model.md](userspace-memory-model.md).
The userspace boot order and the process-creation/death flow are in
[process-lifecycle.md](process-lifecycle.md).

---

## Paging

### Page Sizes

The base page size is 4 KiB on both architectures. The kernel direct map is built
from 2 MiB large pages (x86-64) / megapages (RISC-V); the randomized direct-map base
is 1 GiB-aligned, which preserves the 2 MiB VA≡PA congruence these leaves require and
reserves the natural granule for a future 1 GiB gigapage direct map (not used today).

Userspace mappings use 4 KiB pages by default. Large page support for userspace is
a future optimisation. On RISC-V, uncacheable (MMIO) user mappings additionally use
the Svnapot 64 KiB contiguity hint where a mapping produces an eligible aligned,
physically-contiguous group of 4 KiB leaves — a TLB-reach optimisation that keeps
4 KiB granularity at the API (see
[memory-internals.md](../core/kernel/docs/memory-internals.md) § NAPOT Contiguity (RISC-V)).

### W^X Enforcement

No page is simultaneously writable and executable, with one boot-time exception: the AP
trampoline page is identity-mapped read/write/execute from Phase 3 until SMP bringup
retires it in Phase 8. This is enforced at the page table level using the NX bit (x86-64)
and the equivalent execute permission control on RISC-V. The kernel image itself follows
W^X: text is executable but not writable; data is writable but not executable.

On x86-64, kernel-side W^X additionally depends on `CR0.WP` (supervisor write-protect);
without it a ring-0 write would bypass a read-only page permission. `CR0.WP` is required by
the platform baseline ([platform-requirements.md](platform-requirements.md)) and set on every CPU.

### TLB Management

Address-space tags (x86-64 PCID, RISC-V ASID) are required by the platform baseline
([platform-requirements.md](platform-requirements.md)). The kernel assigns a tag per address space
so a context switch loads the outgoing space's page-table root **without** flushing the TLB —
cached translations survive across switches. A switch between threads that share an address space
requires no TLB operation either way. On RISC-V a hart with a zero-width ASID field is refused at
boot. On both architectures the kernel keeps a full-flush fallback, used on x86-64 where PCID is
absent (emulated environments) and wherever the tag field is too narrow to provide more usable
tags than CPUs.

Eliding the per-switch flush requires keeping tagged entries coherent without it. Two
generation counters do this:

- A global tag allocator stamps each tag claim with a unique generation. A CPU records, per
  tag, the generation it last loaded; when it loads a tag whose recorded generation differs,
  the tag was reissued to a different address space and the CPU flushes just that tag. This
  is the cross-CPU invalidation-before-reissue guarantee, so a finite tag pool can be
  recycled safely — on exhaustion the least-recently-claimed tag whose owner is not active
  on any CPU is evicted.
- Each address space carries a TLB generation bumped on every unmap, remap to a different
  frame, or permission narrowing. A CPU that was switched away when the change happened
  flushes the tag on its next reactivation if its synced generation lags; CPUs currently
  running the space are reached directly by the SMP shootdown.

Tag 0 is reserved for the kernel/idle context and the full-flush fallback and is never
assigned to a user space. Single-address invalidation after a mapping change uses `invlpg`
(x86-64) or `sfence.vma <va>` (RISC-V) on the current space; cross-CPU shootdown uses the
tag-targeted forms (`invpcid` / `sfence.vma <va>, <asid>`) so a CPU that has since switched
spaces still invalidates the right translation. Multi-page range invalidation batches
per-address invalidations: on RISC-V the Svinval sequence (`sfence.w.inval`, a `sinval.vma`
per page, `sfence.inval.ir`) pays the fence cost once per batch; on x86-64 the same surface
degenerates to an `invlpg` loop. Spans larger than a small ceiling fall back to a full
flush, which is cheaper than per-page invalidation at that size (see
[memory-internals.md](../core/kernel/docs/memory-internals.md) § TLB Management). Cross-CPU
invalidation uses the SMP shootdown protocol described in
[memory-internals.md](../core/kernel/docs/memory-internals.md) § SMP TLB Shootdown.

The `CAP_INFO_TLB_ELIDED` / `CAP_INFO_TLB_PERFORMED` `cap_info` selectors expose system-wide
counts of context switches that elided versus performed the flush — the
emulation-independent measure of the optimization.

### Kernel Isolation — SMEP and SMAP

On x86-64, SMEP (Supervisor Mode Execution Prevention) and SMAP (Supervisor Mode
Access Prevention) are required by the platform baseline
([platform-requirements.md](platform-requirements.md)) and enabled unconditionally. SMEP
prevents the kernel from executing userspace pages; SMAP prevents the kernel from reading or
writing userspace memory except through designated safe copy routines. Together these
mitigate a class of privilege escalation exploits. SMAP enforcement has a gap at every ring-3
kernel entry: on SYSCALL, `IA32_SFMASK` does not clear RFLAGS.AC and the syscall entry stub
runs no `clac`; on an interrupt or exception taken from ring 3, delivery does not clear AC and
the IDT entry stubs run no `clac`. A user-set AC therefore leaves SMAP unenforced for explicit
kernel accesses on that entry until the first user copy's `clac` clears it (a defect,
[#443](https://github.com/kottlerg/seraph/issues/443)).

On RISC-V, S-mode can never execute from user (U=1) pages, and the kernel keeps
`sstatus.SUM` clear except inside its user-copy routines, so supervisor loads and stores
to user pages fault. PMP is established by M-mode firmware and protects firmware memory,
not user pages.

---

## Physical Memory Management

### Boot-Time Memory Map

At boot, the bootloader provides a memory map via the `BootInfo` structure
(see [abi/boot-protocol/README.md](../abi/boot-protocol/README.md); type classification in
[core/boot/docs/memory-map.md](../core/boot/docs/memory-map.md)) describing which physical
address ranges are usable RAM, reserved, or used by firmware. The kernel parses this map and
populates the buddy allocator in Phase 2, excluding the frames the boot payload occupies; see
[initialization.md](../core/kernel/docs/initialization.md) § Phase 2.

### Bootloader Scratch Reclamation

Pages the bootloader allocated for its own scratch use are recorded in
`BootInfo.reclaim_ranges` and minted as reclaimable Memory caps into
init's CSpace by the kernel-initialisation reclaim-minting steps. See
[`core/kernel/docs/initialization.md`](../core/kernel/docs/initialization.md)
Phase 7 (standard reclaim mint) and Phase 8 (`RECLAIM_FLAG_LATE`
late-mint for the AP trampoline page) for the authoritative
mechanism.

### Buddy Allocator

Physical frames are managed by a buddy allocator. Memory is divided into blocks whose
sizes are powers of two (in pages). Allocation of `n` pages returns the smallest
available power-of-two block that fits. When a block is freed, it is merged with its
adjacent "buddy" block if that buddy is also free, recursively coalescing up to the
maximum order.

Properties:
- Allocation and coalescing bounded by `MAX_ORDER` levels (per-level cost in
  [memory-internals.md](../core/kernel/docs/memory-internals.md) § Allocation and
  Deallocation Properties)
- Bounded external fragmentation
- Internal fragmentation bounded at 50%

The allocator manages a single zone covering all usable RAM. Physical-address-range
constraints (e.g. DMA-accessible memory below a certain physical address) are not a
kernel concern: DMA placement and isolation belong to devmgr and the memory authority
in userspace (see [architecture.md](architecture.md)). Physical-range (DMA-reachable)
placement by the userspace memory authority is design intent; not yet implemented:
memmgr's only allocation flag is `REQUIRE_CONTIGUOUS`. IOMMU-based DMA isolation by
devmgr is design intent; not yet implemented, so DMA currently runs unconfined (see
[device-management.md](device-management.md) § DMA Safety Model).

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

## Kernel Object Memory

The kernel has no heap: it runs no `GlobalAlloc`, and every kernel object —
capability slot pages, thread control blocks, IPC endpoints and notifications,
event queues, wait sets, address spaces, CSpaces — is carved out of a Memory
capability by retype and returned to it when the object's reference count
reaches zero (its capabilities and every kernel-internal reference released); see
[capability-model.md](capability-model.md) § Auto-reclaim. The
kernel's own objects come from the SEED reserve pinned at the Phase 7
handoff, after which the buddy is sealed and every page of RAM is either a
bounded fixed kernel reserve or a userspace Memory capability. The reserves
are the Phase 4 per-CPU storage, the Phase 5 per-CPU tag-state slab, and the
Phase 7 contributors, in the order
[initialization.md](../core/kernel/docs/initialization.md) § Phase 4,
§ Phase 5, and § Phase 7 give.

Address spaces and CSpaces additionally own a pool that their page tables or
slot pages come from, carved from a Memory capability with the object and grown
only by further donations from Memory capabilities; see
[capability-model.md](capability-model.md) § Address-space and CSpace growth
budgets.

### Kernel Allocation is Fallible

Retype and pool allocation MUST be handled as fallible at every call site.

---

## Summarized By

[abi/boot-protocol/README.md](../abi/boot-protocol/README.md),
[ELF Loading](../core/boot/docs/elf-loading.md),
[Memory Map Translation](../core/boot/docs/memory-map.md),
[Page Tables](../core/boot/docs/page-tables.md),
[core/kernel/README.md](../core/kernel/README.md),
[Architecture Abstraction Layer](../core/kernel/docs/arch-interface.md),
[Kernel Cross-Boundary Disclosure Inventory](../core/kernel/docs/cross-boundary-disclosure.md),
[Kernel Initialization Sequence](../core/kernel/docs/initialization.md),
[Memory Subsystem Internals](../core/kernel/docs/memory-internals.md),
[Architecture Overview](architecture.md), [Platform Requirements](platform-requirements.md),
[xtask/README.md](../xtask/README.md)
