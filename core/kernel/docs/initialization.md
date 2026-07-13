# Kernel Initialization Sequence

This document describes the kernel's initialization sequence from `kernel_entry()` to
the first userspace instruction of init. The sequence is divided into numbered phases,
each with a completion criterion and a defined failure mode.

Any phase failure is fatal; the kernel halts with a diagnostic message.

For the boot protocol contract (CPU state and register contents, BootInfo
layout) that Phase 0 depends on, see
[`boot/docs/kernel-handoff.md`](../../boot/docs/kernel-handoff.md) and the
[`abi/boot-protocol/`](../../../abi/boot-protocol/) crate.

---

## Phase 0: Entry Validation

**Entry point:** `kernel_entry(boot_info: *const BootInfo)`

```
1. Verify boot_info pointer is non-null and naturally aligned for BootInfo
2. Read boot_info.version
3. Compare against BOOT_PROTOCOL_VERSION
4. If mismatch: halt immediately (cannot trust any other BootInfo fields)
5. Validate memory_map.count > 0 and memory_map.entries is non-null
6. Validate init_image.segment_count > 0 (init must have at least one segment)
7. Validate init_image.entry_point != 0
```

No output before step 1 succeeds; console is not yet available.

**Failure mode:** Infinite halt (`loop {}` / `wfi` loop). On x86-64, the halt
instruction is used in a loop to handle spurious wakeups.

**Completion criterion:** `boot_info` pointer is valid and `version` matches.

---

## Phase 1: Early Console

```
1. Call console::init(&boot_info)
   - x86-64: checks boot_info.framebuffer.physical_base; if non-zero,
     initialises a simple pixel-writing framebuffer console;
     also attempts to initialise a COM1 serial port at 115200 8N1
   - RISC-V: uses SBI console (sbi_console_putchar) as fallback;
     framebuffer initialisation same as x86-64 if present
2. Emit a startup banner identifying the kernel and the protocol version
3. Emit: CPU architecture identifier and core count if detectable at this stage
```

The early console is allocation-free and output-only.

**Failure mode:** If no output device is found, initialisation continues silently.
This is not fatal — a headless system is valid.

**Completion criterion:** `console::init()` has returned.

---

## Phase 2: Memory Map Parsing and Buddy Allocator

```
1. Iterate boot_info.memory_map.entries
2. For each entry with memory_type == MemoryType::Usable:
   a. Align start address up to PAGE_SIZE boundary
   b. Align end address down to PAGE_SIZE boundary
   c. Skip ranges smaller than PAGE_SIZE
   d. Add to candidate pool
3. Remove from the candidate pool:
   a. Frames containing the kernel image
      (boot_info.kernel_physical_base .. kernel_physical_base + kernel_size)
   b. Frames containing init segments
      (boot_info.init_image.segments[i].phys_addr + size for each i)
   bb. Frames containing boot modules
      (boot_info.modules.entries[i].physical_base + size for each i)
   c. Frames containing the BootInfo structure itself
   d. Frames containing the bootloader's page tables (if identifiable)
4. Determine buddy allocator order range:
   - Minimum order: 0 (one 4 KiB page)
   - Maximum order: implementation constant `MAX_ORDER` = 11 (2048 pages =
     8 MiB), sized so the largest per-CPU boot slab at `MAX_CPUS` fits one
     block (see memory-internals.md)
5. Call mm::buddy::BuddyAllocator::new(max_order) — this is a static or
   early-heap allocation using only the bootloader-provided stack
6. For each candidate range, call BuddyAllocator::add_region(phys_start, phys_end)
7. Emit: total usable RAM in MiB
```

The buddy allocator MUST be initialized from a static buffer or boot stack, not
from itself.

**Memory at this point:** Only the buddy allocator metadata is allocated. No kernel
heap exists yet.

**Failure mode:** If total usable RAM is zero after exclusions, halt with message
"fatal: no usable physical memory". This indicates a corrupt memory map.

**Completion criterion:** `BuddyAllocator` is initialised and reports usable frames.

---

## Phase 3: Kernel Page Tables

```
1. Allocate a root page table frame via BuddyAllocator::alloc(order=0)
2. Zero the frame
3. Map the kernel image at its virtual addresses:
   - Text segment: readable, executable, not writable
   - Rodata segment: readable, not writable, not executable
   - Data/BSS segment: readable, writable, not executable
   (Segment addresses from ELF headers, sizes from BootInfo)
4. Map the direct physical map:
   - For each usable physical range: map at PHYSMAP_BASE + phys_addr
   - Use 2 MiB large pages where alignment permits
   - Use 1 GiB huge pages where alignment permits and range is large enough
   - Permissions: readable, writable, not executable
   PHYSMAP_BASE = 0xFFFF800000000000 (both architectures)
5. Map the BootInfo structure and boot modules (needed until they are consumed)
6. Install the new page table:
   arch::current::paging::activate(root_phys)
7. The bootloader page table is no longer referenced; its frames are
   recorded in `BootInfo.reclaim_ranges` (boot protocol v7) and minted
   as reclaimable Memory caps into init's CSpace during Phase 7 by
   `cap::mint_reclaim_memory_caps`, alongside the other bootloader
   scratch pages (`BootInfo` page, descriptor arrays, MMIO aperture
   array, reclaim-array page) and the bundle's non-module pages
   (header + entry table + 4 KiB pad, init ELF source body, and any
   inter-module or trailing slack — module bodies are excluded because
   `mint_module_memory_caps` already covers them).
8. Emit: "page tables established, physmap at 0xFFFF800000000000"
```

After this phase, the kernel can access any physical frame at `PHYSMAP_BASE + phys`.
All kernel pointers derived from physical addresses use this translation.

**Failure mode:** Frame allocation failure during page table construction is fatal.
Emit "fatal: cannot build kernel page tables (OOM)" and halt.

**Completion criterion:** The kernel is executing with its own page tables active.

---

## Phase 4: Slab Allocator and Kernel Heap

```
1. Initialise the general size-class allocator:
   - Bins at power-of-two sizes (exact range determined at implementation time)
   - Each bin backed by slab pages from the buddy allocator on demand
2. Register slab caches for core kernel objects:
   - CapabilitySlot (fixed size)
   - ThreadControlBlock (fixed size)
   - Endpoint (fixed size)
   - Notification (fixed size)
   - EventQueue header (fixed size; ring buffer body from size-class allocator)
   - WaitSet (fixed size)
   - AddressSpace (fixed size)
   - PageTableNode (fixed size; one per level-below-root page table frame)
3. Install the kernel allocator (implements the `GlobalAlloc` trait via the
   size-class path; used by any `alloc::*` usage in the kernel)
4. Emit: "kernel heap active"
5. Allocate per-CPU subsystem storage from the buddy allocator while it still
   holds large contiguous blocks (before the Phase-7 user-cap drain): scheduler
   per-CPU state and idle stacks, and the entropy subsystem's per-CPU CSPRNGs,
   central pool, and jitter accumulators (see entropy.md)
```

After this phase, `Box`, `Vec`, and other heap types work in kernel code.

**Failure mode:** If slab initialisation fails to allocate its first backing pages,
halt with "fatal: cannot initialise kernel heap".

**Completion criterion:** The kernel allocator is active and `alloc::boxed::Box`
allocations succeed.

---

## Phase 5: Architecture Hardware Initialisation

Architecture-specific hardware initialization; x86-64 and RISC-V diverge here.

### x86-64

```
1. Construct and install a permanent GDT:
   - Null descriptor (index 0)
   - Kernel code segment (64-bit, DPL 0)
   - Kernel data segment (DPL 0)
   - User data segment (DPL 3)
   - User code segment (64-bit, DPL 3)
   - TSS descriptor (per CPU)
2. For each CPU, construct a TSS:
   - RSP0: kernel stack pointer for privilege transitions
   - IST1..IST7: interrupt stack table entries (for NMI, double fault, etc.)
3. Construct and install the IDT:
   - Exception handlers for vectors 0–31 (divide error, page fault, etc.)
   - APIC timer vector (preemption)
   - Spurious interrupt vector
   - Syscall vector (though SYSCALL/SYSRET bypasses the IDT)
4. Enable SMEP and SMAP in CR4 if CPUID reports support
5. Configure SYSCALL/SYSRET:
   - Write kernel entry point to LSTAR MSR
   - Write segment selectors to STAR MSR
   - Write SFMASK to clear IF on entry
6. Initialise the local APIC on the BSP
7. Configure the preemption timer (period from scheduler policy):
   TSC-deadline mode where CPUID advertises it, periodic APIC timer otherwise
8. Enable interrupts (STI)
```

### RISC-V

```
1. Write trap handler address to stvec (direct mode)
2. Configure sstatus:
   - Clear SIE (interrupts remain disabled until scheduler starts)
   - Clear SPP (so sret returns to U-mode by default)
   - Clear SUM (no supervisor access to user pages)
3. Enable SEIP, STIP in sie (external and timer interrupt enables)
4. Initialise PLIC for this hart: configure priorities and enables
5. Arm stimecmp (Sstc) for the initial tick, using the bootloader-discovered
   timebase; halts if Sstc or the timebase was not discovered
6. Enable interrupts (set sstatus.SIE)
```

After the architecture hardware path, the BSP seeds the entropy pool from the
hardware RNG (health-gated where present) and boot-time jitter and opens the
kernel draw API; without a hardware RNG (RISC-V under default firmware) this
degrades to jitter only. See [entropy.md](entropy.md).

**Failure mode:** Hardware initialisation failures (e.g. CPUID indicates a required
feature is absent) halt with a descriptive message. The specific required features
are checked against constants defined in `arch/x86_64/cpu.rs` and
`arch/riscv64/cpu.rs`.

**Completion criterion:** Interrupts are enabled, the preemption timer is running,
and the syscall entry mechanism is installed.

---

## Phase 6: Platform Resource Validation

Caches `kernel_mmio` and validates `mmio_apertures` before Phase 7 mints
capabilities from it.

```
1. Copy BootInfo.kernel_mmio into the kernel-local KERNEL_MMIO cache.
2. If mmio_apertures.count == 0: skip aperture validation, proceed with empty set.
3. Verify mmio_apertures.entries is non-null (required when count > 0).
4. Verify the slice falls within boot-provided physical memory:
   - The entire range [entries, entries + count * size_of::<MmioAperture>())
     must be within regions the memory map marks as Usable or Loaded.
5. For each MmioAperture entry:
   - Verify phys_base is page-aligned; skip with warning if not.
   - Verify size > 0 and size is page-aligned; skip with warning if not.
   - Verify phys_base + size does not wrap u64; skip with warning if not.
6. Emit: "mmio apertures: N validated (M skipped)".
```

**Failure mode:** Null `entries` when `count > 0`: halt with "fatal:
mmio_apertures.entries is null with non-zero count". Individual bad
entries: emit a warning and skip.

**Completion criterion:** The validated aperture list is available to
Phase 7, and `KERNEL_MMIO` is populated.

---

## Phase 7: Capability System

```
1. Initialise the global derivation tree (initially empty)
2. Allocate the root CSpace:
   - Initial capacity: ROOT_CSPACE_INITIAL_SLOTS (e.g. 1024 slots)
   - Slot 0 is permanently null
3. Populate the root CSpace with initial capabilities:
   a. Memory capabilities for all usable physical memory ranges
      (one capability per contiguous usable region from the memory map)
   b. One Mmio capability (Map | Write rights) per validated
      `BootInfo.mmio_apertures` entry. Userspace narrows these into
      per-device sub-caps and distributes them to drivers.
   c. One root IoPort capability (x86-64 only, Use rights) covering
      the full 64K I/O port space; init subdivides for services that
      need port I/O.
   d. One SchedControl capability spanning the full userspace priority range
      `[1, PRIORITY_MAX]` — holding it (plus its band) authorises setting thread
      priorities within that band. Init splits it into a baseline band and an
      elevated remainder and delegates copies per policy (see
      [capability-model.md § SchedControl](../../../docs/capability-model.md))
   e. One SbiControl capability (RISC-V only) carrying every sanctioned SBI
      right, for init to forward sanctioned SBI extensions and attenuate
      per-consumer copies.
   f. (Thread and process capabilities for init are added in Phase 9)
4. Mint reclaimable Memory caps from `BootInfo.reclaim_ranges` via
   `cap::mint_reclaim_memory_caps`:
   - One cap per range with `owns_memory = true` and full byte ledger;
     inserted into the root CSpace so the cap reaches init through the
     standard `CapDescriptor` walk in Phase 9.
   - The buddy ledger records each range's pages in `total_pages` via
     `register_owned_range`; the range is never placed on the free
     list. Init donates every reclaim cap to memmgr's pool at reap,
     and the buddy is sealed after handoff, so no reclaim page returns
     to it.
   - Ranges flagged `RECLAIM_FLAG_LATE` are skipped here and minted in
     Phase 8 (see Late-Reclaim below).
5. Record the root CSpace pointer in a global for use in Phase 9
6. Emit: "capability system initialised, N slots populated"
```

**Failure mode:** Allocation failure during CSpace construction halts with
"fatal: cannot initialise capability system".

**Completion criterion:** Root CSpace exists and contains capabilities for all
boot-provided hardware resources, including the reclaimable Memory caps
covering bootloader scratch pages (`BootInfo` page, descriptor arrays,
MMIO aperture array, reclaim-array page, transient page-table frames)
and the bundle's non-module pages (header + entry table + 4 KiB pad,
init ELF source body, inter-module and trailing slack — module bodies
are excluded because `mint_module_memory_caps` already covers them).

---

## Phase 8: Scheduler and SMP Bringup

```
1. Initialise per-CPU run queues:
   - NUM_PRIORITY_LEVELS priority queues per CPU (e.g. 32 levels)
   - Each queue is an intrusive doubly-linked list of TCBs
2. For each CPU (including the BSP):
   a. Use the idle kernel stack pre-allocated at per-CPU storage init
      (Phase 4); read its top from the IDLE_STACK_TOPS slab
   b. Allocate and initialise an idle TCB:
      - Priority: IDLE_PRIORITY (lowest, reserved; never preempted)
      - Entry: arch::current::context::new_state(idle_entry, stack_top, cpu_id, false)
      - Idle thread entry calls cpu::halt_until_interrupt() in a loop,
        checking for pending work before each halt
   c. Set the per-CPU current_thread pointer to the idle TCB
3. Emit: "scheduler initialised, N CPUs"
4. For each AP listed in BootInfo.cpu_ids[1..cpu_count]:
   a. Patch per-AP startup parameters into the trampoline page
   b. Send SIPI (x86-64) / SBI HSM hart_start (RISC-V)
   c. Wait for APS_READY.fetch_add(1) before launching the next AP
      (the Acquire load doubles as the barrier guaranteeing the AP has
      jumped from the trampoline page to its kernel-VA entry)
5. Tear down the low-VA identity mapping at the trampoline PA via
   mm::paging::unmap_identity_page (TLB shootdown to all other CPUs).
6. Mint a late-reclaim Memory cap over the trampoline page via
   cap::mint_late_reclaim_memory_caps; the descriptor lands in
   cspace_layout so init sees the cap through the standard CSpace
   handoff in Phase 9.
7. Run the entropy power-on self-test across all online CPUs: each CPU captured
   a sample from its generator during bringup, and the BSP now checks per-CPU
   independence and basic sanity, printing PASS/FAIL (see entropy.md).
```

The AP SIPI trampoline page is flagged `RECLAIM_FLAG_LATE` in
`BootInfo.reclaim_ranges`. `cap::mint_reclaim_memory_caps` skips it in
Phase 7; this phase mints it after SMP bringup completes and
`mm::paging::unmap_identity_page` retires the low-VA identity-RWX
mapping. (Both arches install this identity mapping in Phase 3 — the
trampoline must remain executable at its PA while PC walks the
post-`csrw satp` / post-CR3-write instructions.) The late-mint
completes before Phase 9 consumes `cspace_layout`, so the descriptor
still flows through the standard CSpace handoff.

APs depend only on Phase 5/8 state (interrupts, percpu, scheduler
idle threads); they never touch init's address space or any Phase-9
state, so SMP bringup completes within Phase 8 and the trampoline page
is reclaim-safe by the time Phase 9 consumes `cspace_layout`.

**Failure mode:** Allocation failure for any idle stack or TCB halts with
"fatal: cannot initialise scheduler". `start_ap` failure for an
individual AP is logged and skipped (that CPU stays offline).

**Completion criterion:** Per-CPU scheduler state and idle threads are
initialised for all CPUs, every AP has incremented `APS_READY`, the
trampoline identity mapping is torn down, and its Memory cap is in init's
CSpace descriptor table.

---

## Phase 9: Init Creation and Scheduler Entry

**Status: Implemented.**

Creates init's AddressSpace and Thread from `BootInfo.init_image` segments, then
calls `sched::enter()`.

```
1. Validate boot_info.init_image:
   a. Verify segment_count > 0
   b. Verify entry_point != 0
   c. PIE rebase (INIT_IMAGE_FLAG_PIE set — every init image since the
      #39 target flip): draw the load bias from the entropy pool
      (process_layout::choose_image_bias; window base if unseeded),
      validate the biased span (validate_image_placement), apply the
      .rela.dyn RELATIVE relocations through the direct map
      (mm/init_reloc.rs; targets must fall in writable segments, anything
      unresolvable is fatal), bias every segment virt_addr and the
      entry point, then seal PT_GNU_RELRO: writable segments covered by
      the relro range flip to Read (splitting at the range end if it
      lands mid-segment). Logged as "init: PIE bias=0x… (N relocations)".
2. Create the init address space (AddressSpace::new_user):
   a. Allocate a new root page table frame from the buddy allocator
   b. Zero the frame
   c. Copy kernel root entries 256–511 (the kernel half in every paging
      mode) from the active root so the kernel
      remains reachable from init's address space
3. Map init segments into the init address space:
   a. For each InitSegment in init_image.segments[0..segment_count]:
      - Align virt_addr and phys_addr to page boundaries before mapping
      - Map the page-aligned virtual address to the page-aligned physical frame
      - The in-page offset (virt_addr & 0xFFF) is preserved implicitly: the CPU
        adds it to the physical frame address at translation time
      - Apply permissions from segment.flags (Read → RO, ReadWrite → RW,
        ReadExecute → RX); W^X is enforced (ReadWrite cannot also be executable)
4. Allocate init's user stack (inlined in `kernel_entry`):
   a. Allocate INIT_STACK_PAGES (4) frames from the buddy allocator
      one at a time so each phys address is captured for the reclaim
      Memory cap minted alongside it
   b. Zero each frame
   c. Map below the chosen init stack top (`choose_init_layout().init_stack_top`,
      drawn per boot from the init-stack-guard window in `process-layout`;
      deterministic default only if entropy is unavailable) with read/write
      permissions
   d. Mint a reclaimable Memory cap per stack page into the root CSpace
      so init can donate the pages to memmgr on reap
   e. Guard page (unmapped) sits immediately below the stack; stack overflows fault
5. Create init's TCB:
   a. Allocate a kernel stack for init (KERNEL_STACK_PAGES = 4 pages = 16 KiB)
   b. new_state(entry=init_image.entry_point, stack_top=kstack_top,
      arg=choose_init_layout().init_info_va, is_user=true) stores entry_point in
      saved_state.rip (x86-64) or .ra (RISC-V) and the InitInfo VA as the arg
      forwarded to init's a0/rdi on first entry
   c. Priority: INIT_PRIORITY (15)
   d. cspace: set to ROOT_CSPACE raw pointer (handed off at `sched::enter()` start)
6. Enqueue the init TCB on the BSP's run queue at INIT_PRIORITY
7. Call sched::enter() — does not return:
   a. Dequeue the highest-priority ready thread (init)
   b. Build an initial user-mode TrapFrame on init's kernel stack:
      rip/sepc=entry_point, rsp/sp=chosen init stack top, cs=USER_CS, ss=USER_DS,
      rflags=0x202 (IF=1)
   c. x86-64: call switch_and_enter_user(root_phys, tf_ptr) — atomically
      switches RSP to init's kernel stack, writes CR3, builds iretq frame, iretq
   d. RISC-V: activate init's address space (satp write + sfence.vma),
      then return_to_user(tf_ptr) — restores registers and executes sret
```

**Implementation notes:**
- CSpace hand-off (step 5d): `sched::enter()` calls `set_current(init_tcb)` so `current_tcb()` returns the init TCB during init's syscalls; init receives ROOT_CSPACE.
- The x86-64 `switch_and_enter_user` function atomically switches the stack pointer
  BEFORE writing CR3. This is required because the boot stack is identity-mapped in
  PML4 entries 0–255 (the lower half), which are not copied into init's page tables.
  Any function call/return on the boot stack after the CR3 write would page-fault.
- Init segment frames are NOT reclaimed — they remain mapped in init's address space.

**Failure mode:** Allocation failure halts with a diagnostic message identifying the
failed step. Invalid init_image (zero segment_count or zero entry_point) halts with
"Phase 9: init image missing or has no entry point".

**Completion criterion:** Init is executing in user mode (ring-3 / U-mode).

---

## Fatal Boot Failure Handling

At any phase, if the kernel cannot continue:

```rust
fn fatal(msg: &str) -> !
{
    // Disable interrupts to prevent re-entrant failure handling.
    arch::current::interrupts::disable();
    console::panic_write_fmt(format_args!("KERNEL FATAL: {msg}\n"));
    loop
    {
        // Halt until the next interrupt (hlt on x86-64; wfi on RISC-V).
        // Interrupts are left disabled — this CPU is not taking further work.
        arch::current::cpu::halt_until_interrupt();
    }
}
```

Secondary CPU failures after Phase 9 (user-mode entry) are handled by `fatal()` on
that CPU only; the BSP and other CPUs continue.

---

## Initialization Summary

| Phase | Key Action | Failure |
|---|---|---|
| 0 | Validate BootInfo version | Silent halt |
| 1 | Early console | Non-fatal (continues silently) |
| 2 | Buddy allocator from memory map | Halt: no usable RAM |
| 3 | Kernel page tables + direct map | Halt: OOM during PT construction |
| 4 | Slab allocator + kernel heap | Halt: cannot init heap |
| 5 | CPU hardware (IDT/GDT/TSS/stvec); seed entropy pool | Halt: missing required feature |
| 6 | Platform resource validation | Halt if entries pointer is null with non-zero count; bad entries skipped |
| 7 | Capability system + root CSpace | Halt: OOM |
| 8 | Scheduler + idle threads, SMP bringup, AP trampoline reclaim, entropy self-test | Halt: OOM (idle stack/TCB); start_ap failure per CPU is logged and skipped |
| 9 | Init creation + scheduler entry (user mode) | Halt: invalid InitImage or OOM |

---

## Summarized By

[kernel/README.md](../README.md)
