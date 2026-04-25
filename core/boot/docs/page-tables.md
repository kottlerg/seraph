# Page Tables

The bootloader establishes minimal initial page tables before kernel handoff: enough
for the kernel to execute at its ELF virtual addresses and read `BootInfo` before its
own page tables are ready. The kernel replaces them during Phase 3.

All page table frames MUST be allocated via `AllocatePages` before `ExitBootServices`;
no page table allocation occurs after the firmware exits.

---

## Contract at Kernel Entry

The state the **kernel may assume** at entry — distinct from what the
bootloader *builds*, described in later sections — is:

- The kernel image is mapped at its ELF-specified virtual addresses
  (text, rodata, data, bss), with page permissions matching each
  segment's ELF flags (W^X enforced).
- An identity map covers the physical memory region containing the
  `BootInfo` structure and every physical region it references
  (memory-map buffer, `MmioAperture` array, `InitImage` segments,
  all boot modules), so the kernel can read them using physical
  addresses before its own direct-physical map is established.
- The bootloader's stack in use at handoff is mapped at its current
  virtual address, read-write, non-executable.
- Nothing else is mapped. Any access outside these ranges faults.

The initial tables are **not** intended to be permanent. The kernel
replaces them during Phase 3. The CPU state at the moment of jump —
paging bit set, interrupts disabled, BootInfo pointer in the
first-argument register — is specified in
[kernel-handoff.md](kernel-handoff.md).

---

## What Gets Mapped

The initial page tables contain exactly three categories of mappings. Nothing else is
mapped; an access outside these ranges faults.

**Kernel ELF segments** — each LOAD segment is mapped at its ELF virtual address with
permissions derived from the ELF segment flags. This allows the kernel to execute from
the first instruction.

**Identity map of the boot region** — the `BootInfo` structure, the `MmioAperture`
array, the memory map buffer, and all boot modules are identity-mapped (virtual address
equals physical address). This allows the kernel to read them using physical addresses
before its direct physical map is established in Phase 3.

**Bootloader stack** — the stack in use at the point of kernel handoff is mapped at
its current virtual address. On x86-64 and RISC-V, the stack is allocated by UEFI
and its virtual address equals its physical address (UEFI runs with a 1:1 mapping
or a well-defined identity region). The stack mapping uses read-write, non-executable
permissions.

The UEFI firmware's own page tables (before `ExitBootServices`) already contain a
full 1:1 mapping of physical memory. After `ExitBootServices`, those page tables are
no longer in use; the bootloader installs its own minimal tables.

---

## Architecture Abstraction

Within the bootloader, page table construction is separated into an arch-neutral
interface and architecture-specific implementations. The trait, its error type,
and the permission-flags record are defined in [`boot/src/paging.rs`](../src/paging.rs)
and re-used by each arch implementation without duplication.

The trait exposes three operations: allocate a fresh root table, map a
virtual range onto a physical range with requested permissions, and
return the root's physical address (the value written to `CR3` on x86-64
or encoded into the `satp` PPN on RISC-V). All page table frames are
obtained from UEFI `AllocatePages`; no allocation occurs after
`ExitBootServices`.

Permissions carry only *writable* and *executable* booleans. Every
mapping is implicitly readable — the architectures have no way to mark
a present page unreadable while keeping it present — so a dedicated
`readable` flag would be dead weight. W^X is rejected at the trait
contract: any call requesting both `writable` and `executable` returns
an error without modifying any table. This check is redundant with the
ELF loading check in [elf-loading.md](elf-loading.md), but both sites
enforce W^X independently to prevent a single failure mode from being
missed.

Intermediate-frame allocation failures and W^X violations are the only
two map-error variants; both are fatal. The arch implementations live
in [`boot/src/arch/x86_64/paging.rs`](../src/arch/x86_64/paging.rs) and
[`boot/src/arch/riscv64/paging.rs`](../src/arch/riscv64/paging.rs);
[`boot/src/paging.rs`](../src/paging.rs) re-exports the active
architecture's implementation.

---

## x86-64: 4-Level Paging

### Hierarchy

x86-64 with 4-level paging uses a four-level hierarchy indexed by bits of the virtual
address:

```
Virtual address bits:
  [47:39] → PML4 index (512 entries, 4 KiB table)
  [38:30] → PML3 (PDPT) index (512 entries, 4 KiB table)
  [29:21] → PML2 (PD) index (512 entries, 4 KiB table)
  [20:12] → PML1 (PT) index (512 entries, 4 KiB table)
  [11:0]  → Byte offset within the 4 KiB page
```

The root table (PML4) occupies one 4 KiB frame. Each entry is a 64-bit value. Present
entries in PML4 and PML3 point to the next-level table's physical frame. PML1 entries
(PTEs) point to the final 4 KiB data frame.

### PTE Format

```
Bit 0    (P):   Present
Bit 1    (R/W): 1 = Writable; 0 = Read-only
Bit 2    (U/S): 0 = Supervisor only (all bootloader mappings are supervisor-only)
Bit 3    (PWT): 0 (write-back caching; no special caching for kernel mappings)
Bit 4    (PCD): 0
Bit 5    (A):   Accessed (set by hardware; initialised to 0)
Bit 6    (D):   Dirty (PTE only; initialised to 0)
Bit 12–51:      Physical frame number (PFN, physical address >> 12)
Bit 63   (NX):  1 = No-execute (set for all non-executable mappings)
```

Permission mapping:

| `PageFlags` | R/W bit | NX bit |
|---|---|---|
| Readable only | 0 (read-only) | 1 (NX) |
| Readable + Writable | 1 | 1 (NX) |
| Readable + Executable | 0 (read-only) | 0 (executable) |

W^X: the combination Writable=1 and NX=0 is never written; `map` returns
`MapError::WxViolation` before any table is modified.

### Intermediate Table Allocation

Each new PML3, PML2, or PML1 table requires one 4 KiB frame. Frames are allocated
via `AllocatePages(AllocateAnyPages, EfiLoaderData, 1, &addr)` and zeroed before use.
Zeroing ensures absent entries have `P=0` (not present); the hardware never walks
an absent entry regardless of other bits.

### Activation

Activation writes the root PML4's physical address to `CR3`. The write
flushes all non-global TLB entries; because the bootloader never sets
the Global bit (`G=0` in every PTE), the flush is complete. Interrupts
are disabled at activation time; the required mappings are all present
before `CR3` is written. See
[`boot/src/arch/x86_64/paging.rs`](../src/arch/x86_64/paging.rs) for the
asm and the full SAFETY justification.

---

## RISC-V: Sv48 Paging

### Hierarchy

RISC-V with Sv48 uses a four-level hierarchy (root, level-2, level-1, level-0):

```
Virtual address bits (Sv48):
  [47:39] → Root table index (512 entries)
  [38:30] → Level-2 table index (512 entries)
  [29:21] → Level-1 table index (512 entries)
  [20:12] → Level-0 table index (512 entries)
  [11:0]  → Byte offset within the 4 KiB page
```

Each table is 4 KiB and holds 512 eight-byte PTEs. The root table physical address
is right-shifted by 12 bits to produce the PPN for the `satp` register.

### PTE Format (RISC-V Sv48)

```
Bit 0    (V):   Valid
Bit 1    (R):   Readable
Bit 2    (W):   Writable
Bit 3    (X):   Executable
Bit 4    (U):   User-accessible (0 for all bootloader mappings — S-mode only)
Bit 5    (G):   Global (0; not used by the bootloader)
Bit 6    (A):   Accessed (initialised to 1 to avoid access-flag faults on hardware
                that does not set A/D bits in hardware and would fault instead)
Bit 7    (D):   Dirty (initialised to 1 for writable pages; same rationale as A)
Bits 10:8 (RSW): Reserved for software; set to 0
Bits 53:10 (PPN): Physical page number (physical address >> 12)
Bits 63:54: Reserved; must be 0
```

A PTE is a leaf if R=1 or X=1 (or both). A PTE is a pointer to the next-level table
if R=0, W=0, X=0, and V=1.

Permission mapping:

| `PageFlags` | R | W | X |
|---|---|---|---|
| Readable only | 1 | 0 | 0 |
| Readable + Writable | 1 | 1 | 0 |
| Readable + Executable | 1 | 0 | 1 |

W^X: W=1 and X=1 is rejected by `map` before any table is modified.

### Intermediate Table Allocation

Intermediate table frames are allocated and zeroed identically to x86-64. A zeroed
PTE has V=0 and is invalid, which is the correct initial state.

### Activation

Activation constructs `satp` from `MODE = 9` (Sv48), `ASID = 0`, and
`PPN = root_phys >> 12`, writes it via `csrw satp`, then issues
`sfence.vma` to flush stale TLB entries before the new translation
takes effect. All mappings required for continued execution are present
before `satp` is written. See
[`boot/src/arch/riscv64/paging.rs`](../src/arch/riscv64/paging.rs) for
the asm and the full SAFETY justification.

ASID 0 is used for the bootloader's tables. The kernel uses ASID 0 for
its own initial context (per the boot protocol's description of kernel
entry state) and reassigns ASIDs when it brings up its own page table
management in Phase 3.

---

## W^X Enforcement

W^X is checked at two levels:

1. **ELF loading** ([elf-loading.md](elf-loading.md)) — any segment with `PF_W | PF_X`
   is fatal before any frame is allocated.
2. **Page table mapping** — the `map` function rejects `PageFlags { writable: true,
   executable: true }` with `MapError::WxViolation`.

Both checks are present because ELF loading and page table construction are separate
steps, and a violation at either point is equally dangerous. A writable+executable
mapping that reaches the kernel is a security defect, not just a policy violation.

---

## Page Table Frame Tracking

The bootloader does not free page table frames. All intermediate table frames
allocated by `AllocatePages` appear in the UEFI memory map as `EfiLoaderData`
regions, which translate to `MemoryType::Loaded` in `BootInfo`. The kernel sees
these regions as in-use and does not reclaim them until it establishes its own page
tables in Phase 3, after which it can safely free the bootloader's intermediate
frames via its buddy allocator.

The bootloader records the root page table's physical address but does not
separately track intermediate frames. The kernel does not need to enumerate them
— it simply replaces the entire page table structure during Phase 3 and the old
frames become reclaimable as `EfiLoaderData` entries in the memory map are processed.

---

## Summarized By

[boot/README.md](../README.md)
