# Page Tables

The bootloader establishes minimal initial page tables before kernel handoff: enough
for the kernel to execute at its ELF virtual addresses and read `BootInfo` before its
own page tables are ready. The kernel replaces them during
[Phase 3](../../kernel/docs/initialization.md#phase-3-kernel-page-tables).

All page table frames MUST be allocated via `AllocatePages` before `ExitBootServices`;
no page table allocation occurs after the firmware exits.

---

## Contract at Kernel Entry

The state the **kernel may assume** at entry — distinct from what the
bootloader *builds*, described in later sections — is:

- The kernel image is mapped at its KASLR-biased virtual addresses
  (text, rodata, data, bss; ELF virtual base + slide), with page
  permissions matching each segment's ELF flags (W^X enforced). The
  bootloader has already applied the image's `RELATIVE` relocations for
  the chosen slide ([boot-flow.md](boot-flow.md#step-5d-apply-the-kaslr-slide)),
  so the mapped image is internally consistent.
- An identity map, read-write and non-executable, covers every page touched by the
  `BootInfo` page, the boot-module array page, the translated `MemoryMapEntry` array
  (`BootInfo.memory_map`), the `MmioAperture` array pages, the reclaim-range array page, the
  CPU-id pages (`BootInfo.cpu_ids`), the handoff stack (not the guard page below it), the
  `InitImage` segments (whose `phys_addr` carries the `p_vaddr` in-page offset), the kernel
  segments' physical frames, the bundle blob (every boot module body), the framebuffer when
  present, and the UART MMIO page on RISC-V, so the kernel can read them using physical
  addresses before its own direct-physical map is established.
- The handoff trampoline's page or pages are identity-mapped read-execute, so execution
  continues across the root-table switch (on x86-64, the LA57 toggle trampoline's page when
  the handoff changes the paging depth, § x86-64: Negotiated Paging Depth).
- Nothing else is mapped; an access outside these ranges faults. The ACPI RSDP and the
  device tree, which `BootInfo` references, are not mapped.

The initial tables are **not** intended to be permanent. The kernel
replaces them during
[Phase 3](../../kernel/docs/initialization.md#phase-3-kernel-page-tables).
The CPU state at the moment of jump —
paging bit set, interrupts disabled, BootInfo pointer in the
first-argument register — is specified in
[kernel-handoff.md](kernel-handoff.md).

---

## What Gets Mapped

The initial page tables contain the categories of mappings below. Nothing else is
mapped; an access outside these ranges faults.

**Kernel ELF segments** — each LOAD segment is mapped at its KASLR-biased virtual
address (ELF virtual base + slide) with permissions derived from the ELF segment flags.
This allows the kernel to execute from the first instruction.

**Identity map of the boot region** — every read-write region the entry contract above
lists is identity-mapped (virtual address equals physical address), non-executable.
This allows the kernel to read them using physical addresses before its direct physical
map is established in
[Phase 3](../../kernel/docs/initialization.md#phase-3-kernel-page-tables).

**Handoff trampoline** — the page or pages holding the handoff trampoline (on x86-64, the
LA57 toggle page when the handoff changes the paging depth) are identity-mapped
read-execute, so the instruction fetch after the root-table switch resolves.

**Handoff stack** — the bootloader allocates the kernel's entry stack
(`KERNEL_STACK_PAGES`, 64 KiB) through `AllocatePages` with one more page below it, its
guard, identity-maps the stack with read-write, non-executable permissions and leaves the
guard out of every identity-map region ([boot-flow.md](boot-flow.md) § Step 6), and switches
the stack pointer to the stack's top in the
[handoff sequence](kernel-handoff.md#handoff-sequence) before jumping to the kernel.

The firmware's own translation (a 1:1 mapping of physical memory under UEFI) stays active
across `ExitBootServices`, and step 9 runs under it; the bootloader's minimal tables replace
it only when the handoff trampoline writes `CR3` or `satp`.

---

## Architecture Abstraction

Within the bootloader, page table construction is separated into an arch-neutral
interface and architecture-specific implementations. The trait, its error type,
and the permission-flags record are defined in
[`core/boot/src/paging.rs`](../src/paging.rs) and re-used by each arch implementation
without duplication.

The trait exposes five operations: report the paging mode's translation
levels, allocate a frame pool and take a fresh root table from it, map a
virtual range onto a physical range with requested permissions, return
the root's physical address (the value written to `CR3` on x86-64 or
encoded into the `satp` PPN on RISC-V), and list the spans the builder
allocated (`reclaim_spans`, § Page Table Frame Tracking). All page table frames come
from the one pool obtained from UEFI `AllocatePages`; no allocation occurs after
`ExitBootServices`.

Permissions carry only *writable* and *executable* booleans. Every
mapping is implicitly readable — x86-64 cannot mark a present page
unreadable, and the RISC-V builder sets R on every leaf — so a dedicated
`readable` flag would carry no information. W^X is rejected at the trait
contract: any call requesting both `writable` and `executable` returns
an error without modifying any table. For the kernel image this is the
only W^X check: kernel segments have no load-time check. Init segments
are checked once, at load time by `init_segment_flags`
([elf-loading.md](elf-loading.md#load-segment-processing)), and are
identity-mapped read-write, non-executable here, so their ELF flags
never reach `map`.

Intermediate-frame allocation failures and W^X violations are the only
two map-error variants; both are fatal. The arch implementations live
in [`core/boot/src/arch/x86_64/paging.rs`](../src/arch/x86_64/paging.rs) and
[`core/boot/src/arch/riscv64/paging.rs`](../src/arch/riscv64/paging.rs);
[`core/boot/src/arch/mod.rs`](../src/arch/mod.rs) selects the active
architecture's module as `arch::current`, whose `mod.rs` re-exports its
`BootPageTable`.

---

## x86-64: Negotiated Paging Depth

### Depth negotiation

The paging depth is selected at boot, before the tables are built: 5-level paging
(`CR4.LA57`) when `CPUID.(EAX=07H,ECX=0):ECX[16]` reports LA57, 4-level otherwise. The
bootloader has no override knob of its own; a test host selects the depth by the CPU it
presents (`cargo xtask --x86-paging`, [xtask/README.md](../../../xtask/README.md)). The
firmware runs one of the two depths itself, which the bootloader reads from its `CR4.LA57`.
When the negotiated depth differs from the firmware's, the handoff must change `CR4.LA57`,
which the CPU accepts only outside IA-32e mode; the bootloader then reserves one
`EfiLoaderCode` page below 4 GiB and copies the LA57 toggle trampoline into it (§ Activation).
When no such page can be allocated, or the assembled trampoline does not fit one (the page is
then freed), the bootloader keeps the firmware's depth, which needs no toggle. The negotiated
depth, the firmware's, and the handoff path are printed at step 5.

### Hierarchy

The negotiated depth fixes the hierarchy: four levels at 4-level paging, five at 5-level.
Every level indexes 512 eight-byte entries with 9 VA bits above the 12-bit page offset:

```
Virtual address bits:
  [56:48] → PML5 index (512 entries, 4 KiB table; 5-level only)
  [47:39] → PML4 index (512 entries, 4 KiB table)
  [38:30] → PML3 (PDPT) index (512 entries, 4 KiB table)
  [29:21] → PML2 (PD) index (512 entries, 4 KiB table)
  [20:12] → PML1 (PT) index (512 entries, 4 KiB table)
  [11:0]  → Byte offset within the 4 KiB page
```

The root table (PML5 or PML4) occupies one 4 KiB frame, allocated below 4 GiB because the
LA57 toggle trampoline loads it into `CR3` with paging off, in legacy protected mode, with a
32-bit move. Each entry is a 64-bit value. Present entries above PML1 point to the next-level
table's physical frame. PML1 entries (PTEs) point to the final 4 KiB data frame.

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

W^X: no leaf PTE is written with Writable=1 and NX=0 (intermediate entries are present +
writable with NX=0, leaving the permission to the leaf); `map` returns
`MapError::WxViolation` before any table is modified. A range whose end runs past the end
of the address space returns `MapError::AddressRange`.

### Intermediate Table Allocation

Each new intermediate table requires one 4 KiB frame. Frames are allocated
via `AllocatePages(AllocateAnyPages, EfiLoaderData, 1, &addr)` and zeroed before use.
Zeroing ensures absent entries have `P=0` (not present); the hardware never walks
an absent entry regardless of other bits.

### Activation

When the negotiated depth equals the firmware's, activation writes the root table's physical
address to `CR3`. The write flushes all non-global TLB entries; the bootloader sets no
Global bit (`G=0` in every PTE), so none of its translations is global, and the
trampoline does not toggle `CR4.PGE`, so a global entry left by the firmware's tables is not
flushed by this write.

When the depths differ, the handoff jumps, under the firmware's tables, to the LA57 toggle
trampoline in its page below 4 GiB, which is identity-mapped read-execute in the new tables
(§ Contract at Kernel Entry). The trampoline:

1. stores the root address, the `CR4.LA57` value, the kernel entry, the `BootInfo` address,
   and the stack top into its page's parameter block, since the upper halves of the
   general-purpose registers are undefined after a pass through legacy protected mode;
2. clears `CR4.PCIDE` (paging cannot be disabled while it is set), loads a GDT held in its
   page (64-bit code, 32-bit code, and flat data descriptors, written with the accessed bit
   set so no segment load writes the page once it is read-only), and far-jumps to the 32-bit
   code segment, entering compatibility mode;
3. clears `CR0.PG`, which leaves IA-32e mode (`IA32_EFER.LMA = 0`) and turns paging off;
4. sets or clears `CR4.LA57` and loads `CR3` with the new root;
5. sets `CR0.PG`, which re-enters IA-32e mode (`IA32_EFER.LME` stayed set) on the new tables
   at the negotiated depth, and far-jumps to the 64-bit code segment;
6. loads the stack pointer and the `BootInfo` argument and jumps to the kernel entry.

Turning paging off flushes every TLB entry, global ones included. The kernel is then entered
with `GDTR` naming the trampoline page's GDT, which it replaces in Phase 5
([kernel-handoff.md](kernel-handoff.md)). Interrupts are disabled at activation on either
path, and the required mappings are all present before `CR3` is written. See
[`core/boot/src/arch/x86_64/handoff.rs`](../src/arch/x86_64/handoff.rs)
(`_handoff_trampoline`, `_la57_toggle`, `perform_handoff`) for the asm and its SAFETY
justification.

---

## RISC-V: Negotiated Paging Mode

### Mode negotiation

The paging mode is selected at boot, before the tables are built. The boot
CPU's DTB `mmu-type` property names the candidate (`riscv,sv39` /
`riscv,sv48` / `riscv,sv57`; the widest advertised across enabled CPU nodes
is used when the boot hart's node is silent, and Sv57 — the widest supported
mode — when no DTB is published or no enabled CPU node advertises `mmu-type`).
A `satp` write-probe confirms the
candidate: the RISC-V Privileged ISA specifies that a `satp` write selecting
an unimplemented MODE has no effect, so a readback that retains the prior
value falls the candidate back to the next-narrower mode. Probe failure
below Sv39 is fatal — Sv39 is the platform minimum
([platform-requirements.md](../../../docs/platform-requirements.md)). The
probe runs under a one-frame identity table with S-mode interrupts masked
and restores the live `satp` (UEFI may run with its own translation active);
the frame is zeroed and freed once the mode is chosen.

### Hierarchy

The negotiated mode fixes the hierarchy depth: three levels under Sv39,
four under Sv48, five under Sv57. Every level indexes 512 eight-byte PTEs
with 9 VA bits above the 12-bit page offset:

```
Virtual address bits:
  [top:top-8] → Root table index (512 entries; top = 38 / 47 / 56)
  ...          → one 9-bit index per intermediate level
  [20:12]     → Level-0 table index (512 entries)
  [11:0]      → Byte offset within the 4 KiB page
```

Each table is 4 KiB and holds 512 eight-byte PTEs. The root table physical address
is right-shifted by 12 bits to produce the PPN for the `satp` register.

### PTE Format (identical in every mode)

```
Bit 0    (V):   Valid
Bit 1    (R):   Readable
Bit 2    (W):   Writable
Bit 3    (X):   Executable
Bit 4    (U):   User-accessible (0 for all bootloader mappings — S-mode only)
Bit 5    (G):   Global (0; not used by the bootloader)
Bit 6    (A):   Accessed (initialised to 1 in every leaf PTE, 0 in non-leaf PTEs, to avoid
                access-flag faults on hardware
                that does not set A/D bits in hardware and would fault instead)
Bit 7    (D):   Dirty (initialised to 1 for writable pages; same rationale as A)
Bits 9:8 (RSW): Reserved for software; set to 0
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

Activation constructs `satp` from the negotiated mode's MODE value (8 =
Sv39, 9 = Sv48, 10 = Sv57), `ASID = 0`, and `PPN = root_phys >> 12`, writes
it via `csrw satp`, then issues `sfence.vma` to flush stale TLB entries
before the new translation takes effect. All mappings required for
continued execution are present before `satp` is written. See
[`core/boot/src/arch/riscv64/handoff.rs`](../src/arch/riscv64/handoff.rs)
(`perform_handoff`, `_handoff_trampoline`) for the asm and its SAFETY justification.

ASID 0 is used for the bootloader's tables. The kernel keeps ASID 0 for its own root: in
[Phase 3](../../kernel/docs/initialization.md#phase-3-kernel-page-tables) its untagged
`activate` writes `satp` with ASID 0, as every untagged switch does. Once it enables ASID
tagging, it assigns each address space an ASID on its first tagged activation (see
[Context Switch TLB Handling](../../kernel/docs/memory-internals.md#context-switch-tlb-handling)
and [TLB Management](../../../docs/memory-model.md#tlb-management)).

---

## W^X Enforcement

W^X is checked at two levels:

1. **ELF loading** ([elf-loading.md](elf-loading.md#load-segment-processing)) — an init
   segment with `PF_W | PF_X` is rejected by `init_segment_flags` before any frame is
   allocated for it; kernel segments have no load-time check.
2. **Page table mapping** — the `map` function rejects `PageFlags { writable: true,
   executable: true }` with `MapError::WxViolation`. This is the only check on kernel
   segments, which reach it after their span has been allocated and copied.

Each image is checked at exactly one site: init at load time, the kernel at map time.
A writable+executable mapping that reaches the kernel is a security defect, not just a
policy violation.

---

## Page Table Frame Tracking

Each arch-specific `BootPageTable` takes every frame it uses, the root table
and every intermediate table allocated during `map`, from one contiguous pool
it allocates from `AllocatePages` at construction (below 4 GiB on x86-64, where
the LA57 toggle loads the root with a 32-bit move). `build_initial_tables`
sizes the pool with `paging::table_frame_bound`, an upper bound on the tables
the kernel segments, the identity regions, and the handoff trampoline's pages
need at the negotiated paging depth, so the pool never runs out and no frame
count is capped. The x86-64 builder also records the LA57 toggle page when one
is installed, which is dead once the kernel has replaced the boot GDT and
tables. After [step 8](boot-flow.md#step-8-exitbootservices),
[step 9](boot-flow.md#step-9-populate-bootinfo) reads these spans via the trait
method `PageTableBuilder::reclaim_spans` and appends one
`boot_protocol::ReclaimRange` per span, the whole pool as one, to
`BootInfo.reclaim_ranges`.
The kernel mints reclaimable Memory caps over the recorded frames during
[Phase 7](../../kernel/docs/initialization.md#phase-7-capability-system)
(`cap::mint_reclaim_memory_caps`), so they flow into userspace
through the standard `CapDescriptor` path rather than being orphaned as
`MemoryType::Loaded` pages outside the buddy.

---

## Summarized By

[core/boot/README.md](../README.md), [Boot Flow](boot-flow.md), [ELF Loading](elf-loading.md),
[Kernel Initialization Sequence](../../kernel/docs/initialization.md),
[Memory Subsystem Internals](../../kernel/docs/memory-internals.md),
[Memory Model](../../../docs/memory-model.md),
[Platform Requirements](../../../docs/platform-requirements.md),
[xtask/README.md](../../../xtask/README.md)
