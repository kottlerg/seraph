# Kernel Initialization Sequence

This document describes the kernel's initialization sequence from `kernel_entry()` to
the first userspace instruction of init. The sequence is divided into numbered phases,
each with a completion criterion and a defined failure mode.

A phase failure halts the kernel with a diagnostic message unless the phase's
failure mode states otherwise: Phase 0 halts silently (no console yet), a headless boot
continues (§ Phase 1), a bad aperture entry is skipped and valid entries beyond
`MAX_MMIO_APERTURES` are dropped (§ Phase 6), an entropy self-test FAIL is reported and the
boot continues, and a started CPU that never announces itself leaves the BSP waiting at
`APS_READY` (both § Phase 8).

For the boot protocol contract (CPU state and register contents, BootInfo
layout) that Phase 0 depends on, see
[`core/boot/docs/kernel-handoff.md`](../../boot/docs/kernel-handoff.md) and the
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
8. Validate kernel_virtual_base: at or an IMAGE_SLIDE_ALIGN multiple above KERNEL_LINK_BASE,
   and kernel_virtual_base + kernel_size does not wrap
9. Validate direct_map_base: in the kernel half and 1 GiB-aligned
10. Validate that the direct map (direct_map_base + boot_protocol::direct_map_ceiling) ends
    at or below kernel_virtual_base
11. Validate that a slid image (kernel_virtual_base above KERNEL_LINK_BASE) carries
    KASLR_IMAGE_RANDOMIZED in kaslr_flags
12. arch::current::paging::init_paging_mode: halt if direct_map_base is below the active
    paging mode's kernel-half base (RISC-V: also if satp names no supported mode), then
    publish direct_map_base
```

Phase 0 produces no output; the console is not available until Phase 1.

**Failure mode:** Infinite halt via `arch::current::cpu::halt_loop`: interrupts are
disabled, then `hlt` (x86-64) or `wfi` (RISC-V) runs in a loop, so a spurious wakeup halts
again.

**Completion criterion:** `boot_info` pointer is valid, `version` matches, the KASLR layout
(image base, direct-map base, no overlap) is accepted by `validate_boot_info` and
`init_paging_mode`, and `init_paging_mode` has published the direct-map base.

---

## Phase 1: Early Console

```
1. Call console::init(&boot_info)
   - x86-64: checks boot_info.framebuffer.physical_base; if non-zero,
     initialises a simple pixel-writing framebuffer console;
     also attempts to initialise a COM1 serial port at 115200 8N1
   - RISC-V: initialises the ns16550 UART over MMIO at BootInfo.kernel_mmio.uart_base
     (the platform default when zero), rebased to the direct map after Phase 3;
     framebuffer initialisation same as x86-64 if present
2. Emit a startup banner with the kernel version (KERNEL_VERSION) and architecture name
   (ARCH_NAME), then the boot protocol version
3. Report the KASLR layout, then run the platform feature gate
   (arch::current::cpu::verify_baseline): refuse hardware missing a required
   baseline feature with a diagnostic, before any subsystem that assumes the
   baseline runs
```

The step-3 gate and the baseline it enforces are defined in
[platform-requirements.md](../../../docs/platform-requirements.md) § Boot-Time Feature Gate.

The early console is allocation-free and output-only.

**Failure mode:** If no output device is found, initialisation continues silently.
This is not fatal — a headless system is valid. A missing required feature halts
with a descriptive message.

**Completion criterion:** `console::init()` has returned and `verify_baseline`
has accepted the platform.

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
   c. Frames containing boot modules
      (boot_info.modules.entries[i].physical_base + size for each i)
   d. Frames containing the BootInfo structure itself
   e. The AP trampoline page (boot_info.ap_trampoline_page, when non-zero)
   f. The DTB blob pages (boot_info.device_tree, sized by the FDT totalsize, when valid)
   Exclusions are rounded outward to page boundaries.
4. The buddy allocator is the static mm::FRAME_ALLOCATOR, built at compile time by the
   const BuddyAllocator::new(); orders run from 0 (one 4 KiB page) to the compile-time
   constant `MAX_ORDER` = 11 (2048 pages = 8 MiB), sized so the largest per-CPU boot slab
   at `MAX_CPUS` fits one block
5. For each candidate range, call BuddyAllocator::add_region(phys_start, phys_end)
6. Emit the merged memory map and a DRAM summary (usable, loaded, firmware-reserved,
   ACPI-reclaimable, plus persistent and MMIO-window totals when present) in scaled
   KiB/MiB/GiB units (mm::init::print_memory_map)
```

`MAX_ORDER` and the per-CPU boot slab sizing it accommodates are specified in
[memory-internals.md](memory-internals.md) § Buddy Allocator.

The buddy allocator MUST be initialized from a static buffer or boot stack, not
from itself.

**Memory at this point:** Only the buddy allocator metadata is allocated. The kernel
has no heap (see Phase 4).

**Failure mode:** If total usable RAM is zero after exclusions, halt with message
"FATAL: no usable physical memory after exclusions". This indicates a corrupt memory map.

**Completion criterion:** `BuddyAllocator` is initialised and reports usable frames.

---

## Phase 3: Kernel Page Tables

```
1. Allocate a root page table frame from the BSS `BOOT_TABLE_POOL` (BOOT_TABLE_POOL_SIZE =
   256 frames); every Phase 3 page-table frame comes from this pool, not the buddy allocator
2. Zero the frame
3. Map the kernel image at its virtual addresses:
   - Text segment: readable, executable, not writable
   - Rodata segment: readable, not writable, not executable
   - Data/BSS segment: readable, writable, not executable
   (Section bounds from the linker-script symbols __text_start..__bss_end; physical
   addresses from the BootInfo kernel_virtual_base / kernel_physical_base offset; 4 KiB pages)
4. Map the direct physical map:
   - Map [0, max RAM address) rounded up to 2 MiB — the top of every Usable, Loaded,
     AcpiReclaimable, and Persistent entry, holes included (boot_protocol::max_ram_address)
     — at direct_map_base() + phys
   - Use 2 MiB large pages (megapages on RISC-V); 1 GiB gigapages are not used
   - Permissions: readable, writable, not executable
   direct_map_base() is the runtime KASLR-chosen base from BootInfo — a
   1 GiB-aligned base at or above the paging mode's kernel-half floor
   (0xFFFF800000000000 on x86-64 / Sv48), published by init_paging_mode
   at kernel entry after validation. Before mapping, a guard re-checks that
   the whole direct map (RAM plus any framebuffer / kernel MMIO above the RAM
   ceiling — the shared boot_protocol::direct_map_ceiling) ends at or below
   the kernel image base; overlap is fatal.
5. Map the remaining boot-time windows: a 64 KiB identity window (VA == PA) around the boot
   stack pointer, used until the stack is rebased onto the direct map right after
   activation; the framebuffer at direct_map_base() + phys when it lies above the RAM
   ceiling; the arch kernel MMIO regions above that ceiling (xAPIC and I/O APIC on x86-64;
   none on RISC-V); and the AP trampoline page as a 4 KiB RWX identity page, retired in
   Phase 8. BootInfo and boot modules are not mapped: after activation the kernel reaches
   them through the direct map.
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
8. Emit: "page tables active" (the direct-map base is a KASLR secret and is
   reported only on the serial-only path at Phase 1, never via the
   framebuffer-mirrored console)
```

The direct-map page sizes, the kernel-half floor, and the KASLR placement of the direct map
are defined in [memory-model.md](../../../docs/memory-model.md) § Virtual Address Space Layout
and § Paging. The bootloader page table retired in step 7 is described in
[page-tables.md](../../boot/docs/page-tables.md), and the scratch pages and bundle layout
reclaimed alongside it in [boot-flow.md](../../boot/docs/boot-flow.md). The step-8 disclosure
rule is recorded in [cross-boundary-disclosure.md](cross-boundary-disclosure.md).

After this phase, the kernel can access any physical frame at `direct_map_base() + phys`.
All kernel pointers derived from physical addresses use this translation.

**Failure mode:** Exhausting `BOOT_TABLE_POOL` during page table construction is fatal:
"FATAL: Phase 3: boot page table pool exhausted (RAM > 248 GiB?)". A direct map that would
overlap the kernel image window halts with
"FATAL: Phase 3: direct map would overlap the kernel image window".

**Completion criterion:** The kernel is executing with its own page tables active.

---

## Phase 4: Typed-Memory Cap Surface

```
1. No kernel heap is set up: the kernel runs no `GlobalAlloc`, and every
   kernel-object body is carved out of a Memory capability by retype
   (`core/kernel/src/cap/retype.rs`) — the SEED reserve for the kernel's own objects from
   Phase 7 on, a caller-supplied capability at each `cap_create_*` syscall.
   The phase carries no setup cost; the machinery is live once `SEED_MEMORY`
   is installed in Phase 7.
2. Emit: "Phase 4: Typed-Memory Cap Surface (no kernel heap)"
3. Cache the bootloader-discovered kernel MMIO bases from `BootInfo` for
   Phase 5 (`platform::capture_kernel_mmio`)
4. Allocate per-CPU subsystem storage from the buddy allocator while it still
   holds large contiguous blocks (before the Phase-7 user-cap drain): the scheduler
   slabs (per-CPU schedulers, idle TCBs, idle-stack tops plus one idle kernel stack per
   CPU, watchdog ticks), the PerCpuData and APIC-ID slabs, and on x86-64 the per-AP
   GDT/TSS, IST stacks, and NMI-backtrace storage (`sched::init_storage`); then the
   entropy subsystem's per-CPU CSPRNGs, central pool, jitter accumulators, and
   self-test sample slab (`entropy::init_storage`)
```

Retype-based kernel object memory, which replaces a kernel heap, is specified in
[memory-internals.md](memory-internals.md) § Kernel Object Memory; the entropy
subsystem's per-CPU state is described in [entropy.md](entropy.md).

**Failure mode:** a failed per-CPU storage allocation halts the kernel.

**Completion criterion:** per-CPU storage is allocated; there is no kernel
allocator to activate.

---

## Phase 5: Architecture Hardware Initialisation

Architecture-specific hardware initialization; x86-64 and RISC-V diverge here.

### x86-64

```
1. Enable SMEP and SMAP in CR4 (fatal if CPUID lacks either; both are required and
   already gated in Phase 1)
2. Enable XSAVE (x87 | SSE | AVX in XCR0) and set CR0.TS for lazy FPU/SIMD save-restore
3. Construct and install the permanent GDT and the BSP's TSS:
   - Null descriptor (index 0)
   - Kernel code segment (64-bit, DPL 0)
   - Kernel data segment (DPL 0)
   - User data segment (DPL 3)
   - User code segment (64-bit, DPL 3)
   - TSS descriptor (per CPU)
   - BSP TSS: RSP0 = the current kernel stack pointer; IST1 = double-fault stack,
     IST2 = NMI stack (carved from BSS BSP_IST_STACKS)
   Each AP installs its own GDT/TSS from the Phase 4 per-AP storage when it starts in
   Phase 8.
4. Construct and install the IDT:
   - Exception handlers for vectors 0–31 (double fault on IST1, NMI on IST2)
   - APIC timer vector (32) and spurious vector (255)
   - TLB-shootdown (250) and wakeup (251) IPI vectors
   - Device IRQ vectors 33–55 (I/O APIC GSIs 0–22)
5. Switch to x2APIC mode where CPUID advertises it, software-enable the BSP local APIC
   with every LVT masked, and mask every I/O APIC entry
6. Configure SYSCALL/SYSRET: set EFER.SCE; write LSTAR, STAR, SFMASK (clears IF on entry)
7. Configure the preemption timer at a fixed 1 ms period (`timer::init(1_000)`):
   TSC-deadline mode where CPUID advertises it, periodic APIC timer otherwise
8. Enable interrupts (STI)
```

The step-7 timer mode selection is specified in [arch-interface.md](arch-interface.md)
§ `timer`.

### RISC-V

```
1. Write trap handler address to stvec (direct mode) and clear sscratch
2. Configure sstatus:
   - Clear SIE (interrupts stay disabled until timer::init sets SIE at the end of this phase)
   - Clear SPP (so sret returns to U-mode by default)
   - Clear SUM (no supervisor access to user pages)
   - Set FS and VS Off for lazy FPU/vector save-restore and cache vlenb (halts without
     the V extension)
3. Enable SSIP, STIP, SEIP in sie (software-IPI, timer, and external interrupt enables)
4. Grant U-mode the cycle counter (scounteren.CY)
5. Initialise the PLIC for the BSP context: priority 1 for every source, all enables
   cleared, threshold 0
6. Arm stimecmp (Sstc) for the initial tick, using the bootloader-discovered
   timebase; halts if Sstc or the timebase was not discovered
7. Enable interrupts (set sstatus.SIE)
```

Within the architecture hardware path, after interrupt and per-CPU setup and before the
syscall entry and preemption timer are configured, the BSP checks the boot-gated paging
extensions, then enables hardware address-space tags (x86-64 PCID with INVPCID where present,
RISC-V ASID, whose absence is fatal) and allocates the per-CPU tag-state slab
(`PER_CPU_TAG_STATE`), sized to the boot CPU count, from the buddy allocator. Where
PCID/INVPCID is absent (x86-64), or the tags are too few for the CPU count (either
architecture), no slab is allocated and context switch keeps the full-flush path; a RISC-V
hart without ASIDs is refused. The slab is a fixed kernel reserve allocated before the
Phase 7 drain; see
[memory-model.md](../../../docs/memory-model.md) § TLB Management.

After the architecture hardware path, the BSP seeds the entropy pool from the
firmware boot seed in `BootInfo`, the hardware RNG (health-gated where present),
and boot-time jitter, and opens the kernel draw API; with neither a firmware
seed nor a hardware RNG this degrades to jitter only. The BSP reads the seed in
place from the `BootInfo` page (no kernel-side copy is made), then scrubs the
seed, its length, and the two KASLR bases from that page (a Phase-7 reclaim
range). See [entropy.md](entropy.md).

**Failure mode:** Hardware initialisation failures halt with a descriptive
message. The x86-64 required-feature baseline is checked in Phase 1. On RISC-V, Phase 1
gates only the SBI HSM extension; the Vector extension, the ASID-tagged TLB, Sstc and the
timebase, and the Svpbmt/Svinval/Svnapot paging extensions are refused here, at their
initialization sites
([platform-requirements.md](../../../docs/platform-requirements.md) § Boot-Time Feature Gate).

**Completion criterion:** Interrupts are enabled, the preemption timer is running,
and the syscall entry mechanism is installed.

---

## Phase 6: Platform Resource Validation

Validates `mmio_apertures` before Phase 7 mints capabilities from it
(`kernel_mmio` was captured into the kernel-local cache in Phase 4).

```
1. If mmio_apertures.count == 0: skip aperture validation, proceed with empty set.
2. Verify mmio_apertures.entries is non-null (required when count > 0).
3. Verify the slice falls within boot-provided physical memory:
   - The entire range [entries, entries + count * size_of::<MmioAperture>())
     must be within regions the memory map marks as Usable or Loaded.
4. For each MmioAperture entry:
   - Verify phys_base is page-aligned; skip with warning if not.
   - Verify size > 0 and size is page-aligned; skip with warning if not.
   - Verify phys_base + size does not wrap u64; skip with warning if not.
   - Accept at most MAX_MMIO_APERTURES (64) valid entries; any further valid entry is
     dropped and counted.
5. Emit: "mmio apertures: N validated (M skipped)", or "mmio apertures: N validated
   (M skipped, D dropped — exceeded MAX_MMIO_APERTURES)" when entries were dropped.
```

**Failure mode:** Null `entries` when `count > 0` halts with
"FATAL: Phase 6: mmio_apertures.entries is null with non-zero count"; an entries slice not
wholly inside Usable/Loaded memory halts with
"FATAL: Phase 6: mmio_apertures slice falls outside Usable/Loaded memory". Individual bad
entries: emit a warning and skip.

**Completion criterion:** The validated aperture list is available to
Phase 7.

---

## Phase 7: Capability System

```
1. Reserve init's Phase 9 backing (the InitInfo block and INIT_STACK_PAGES stack frames)
   and seed the kernel page-table pool from the pristine buddy, then drain the remaining
   buddy RAM, seal the buddy, and install SEED_MEMORY over the front SEED_RESERVE_BYTES of
   the largest drained block (`cap::drain_and_install_seed`)
2. Boot-retype the root CSpace from SEED_MEMORY (`boot_retype_cspace`, ROOT_CSPACE_INIT_PAGES
   pages: one wrapper page plus a slot-page pool holding at least
   ROOT_CSPACE_INIT_SLOT_CAPACITY = 1536 slots) and register it as CSpace id 0:
   - Slot 0 is permanently null
3. Populate the root CSpace with initial capabilities:
   a. Memory capabilities for the RAM drained from the buddy allocator in step 1: one per
      contiguous extent after physically adjacent drained blocks are coalesced, the seed
      block contributing only its tail past SEED_RESERVE_BYTES
   b. Mmio capabilities (Map | Write rights): on RISC-V, first one over the
      kernel console UART (`BootInfo.kernel_mmio.uart_base`, or the platform
      default when that is zero; the range can also lie inside an aperture), then one per
      validated `BootInfo.mmio_apertures` entry.
      Userspace narrows these into per-device sub-caps and distributes them
      to drivers.
   c. One SchedControl capability spanning the full userspace priority range
      `[1, PRIORITY_MAX]` — holding it (plus its band) authorises setting thread
      priorities within that band. Init splits it into a baseline band and an
      elevated remainder and delegates copies per policy (see
      [capability-model.md § SchedControl](../../../docs/capability-model.md))
   d. One root Interrupt range capability (Notify rights) covering every valid
      IRQ id on the architecture (ROOT_IRQ_COUNT: 256 on x86-64, 1024 on RISC-V);
      userspace narrows it to single-IRQ children via SYS_IRQ_SPLIT.
   e. Map-only Memory capabilities over firmware tables (not retypable, not
      buddy-backed): one per `AcpiReclaimable` memory-map region (up to
      eight), then the page holding `BootInfo.acpi_rsdp`, then the
      `BootInfo.device_tree` blob.
   f. One root IoPort capability (x86-64 only, Use rights) covering the full
      64K I/O port space, which init subdivides for services that need port
      I/O; or one SbiControl capability (RISC-V only) carrying every
      sanctioned SBI right, for init to forward sanctioned SBI extensions and
      attenuate per-consumer copies.
   g. Memory capabilities for the boot module images, via
      `cap::mint_module_memory_caps` (one per `BootInfo.modules` entry).
   h. (Init's AddressSpace, Thread, and CSpace capabilities and the Memory capabilities
      for its segments, InitInfo pages, and stack pages are added in Phase 9)

   Because step 1 reserves Phase 9's backing before the drain takes the
   remainder, Phase 9 consumes only pages already accounted as kernel-reserved.
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

The SbiControl rights are defined in
[capability-model.md § SbiControl](../../../docs/capability-model.md#sbicontrol-risc-v-only).
Init's reap-time donation of the reclaim caps is described in
[process-lifecycle.md § Init reap](../../../docs/process-lifecycle.md#init-reap), and the
sealed buddy in
[userspace-memory-model.md § Ownership Boundaries](../../../docs/userspace-memory-model.md#ownership-boundaries).

**Failure mode:** An allocation or insertion failure during CSpace construction halts
through `fatal` with a message naming the failed site (for example "Phase 7: cannot allocate
Mmio capability for aperture").

**Completion criterion:** Root CSpace exists and contains capabilities for all
boot-provided hardware resources, including the reclaimable Memory caps
covering bootloader scratch pages (`BootInfo` page, descriptor arrays,
MMIO aperture array, reclaim-array page, transient page-table frames)
and the bundle's non-module pages (header + entry table + 4 KiB pad,
init ELF source body, inter-module and trailing slack — module bodies
are excluded because `mint_module_memory_caps` already covers them).
The scratch pages and bundle layout are described in
[boot-flow.md](../../boot/docs/boot-flow.md).

---

## Phase 8: Scheduler and SMP Bringup

```
1. Use the per-CPU run queues initialised with the scheduler slab in Phase 4:
   NUM_PRIORITY_LEVELS (32) queues per CPU, each an intrusive singly-linked FIFO of TCBs
   (head/tail, linked through run_queue_next)
2. For each CPU (including the BSP):
   a. Use the idle kernel stack pre-allocated at per-CPU storage init
      (Phase 4); read its top from the IDLE_STACK_TOPS slab
   b. Initialise the CPU's idle TCB in place in its slot of the IDLE_TCBS slab (allocated in
      Phase 4):
      - Priority: IDLE_PRIORITY (lowest, reserved; never preempted)
      - Entry: arch::current::context::new_state(idle_thread_entry, stack_top, cpu_id, false)
      - Idle thread entry calls cpu::halt_until_interrupt() in a loop,
        checking for pending work before each halt
   c. Register the idle TCB as the CPU scheduler's idle and current thread (set_idle,
      set_current)
3. Emit: "scheduler initialised, N CPUs"
4. For each AP listed in BootInfo.cpu_ids[1..cpu_count]:
   a. Patch per-AP startup parameters into the trampoline page
   b. Send SIPI (x86-64) / SBI HSM hart_start (RISC-V)
   c. Spin on an Acquire load of APS_READY until it reaches this AP's index (the AP
      increments it with a Release fetch_add once online) before launching the next AP
      (the Acquire load doubles as the barrier guaranteeing the AP has
      jumped from the trampoline page to its kernel-VA entry)
5. Run the entropy power-on self-test across all online CPUs: each CPU captured
   a sample from its generator during bringup, and the BSP now checks per-CPU
   independence and basic sanity, printing PASS/FAIL.
6. Tear down the low-VA identity mapping at the trampoline PA via
   mm::paging::unmap_identity_page (TLB shootdown to all other CPUs), then
   zero the page through the direct map: its parameter block carried the
   AP entry point and idle-stack VAs, which would reveal the layout.
7. Mint a late-reclaim Memory cap over the trampoline page via
   cap::mint_late_reclaim_memory_caps; the descriptor lands in
   cspace_layout so init sees the cap through the standard CSpace
   handoff in Phase 9.
```

The run-queue structure, idle priority, and idle-thread loop are specified in
[scheduler.md](scheduler.md) § Run Queue Structure and § Idle Thread; the step-5
self-test in [entropy.md](entropy.md) § Boot wiring and lifecycle.

The AP SIPI trampoline page is flagged `RECLAIM_FLAG_LATE` in
`BootInfo.reclaim_ranges` ([boot-flow.md](../../boot/docs/boot-flow.md) § Step 9: Populate
BootInfo). `cap::mint_reclaim_memory_caps` skips it in Phase 7; this phase mints it
after SMP bringup completes and `mm::paging::unmap_identity_page` retires the low-VA identity-RWX
mapping. (Both arches install this identity mapping in Phase 3 — the
trampoline must remain executable at its PA while PC walks the
post-`csrw satp` / post-CR3-write instructions.) The late-mint
completes before Phase 9 consumes `cspace_layout`, so the descriptor
still flows through the standard CSpace handoff.

APs depend only on Phase 3–8 state (direct map, per-CPU storage, interrupts, the entropy
pool, scheduler idle threads); they never touch init's address space or any Phase-9
state, so SMP bringup completes within Phase 8 and the trampoline page
is reclaim-safe by the time Phase 9 consumes `cspace_layout`.

**Failure mode:** Phase 8 allocates nothing from the buddy: the scheduler slab, the idle TCB
slab, and the idle stacks come from the Phase 4 per-CPU storage, and a failure to allocate
them halts in Phase 4. Step 7 retypes the late-reclaim Memory cap's body from `SEED_MEMORY`
and inserts the cap into the root CSpace; a SEED or CSpace failure there halts through
`fatal`. A rejected `start_ap` (riscv64, where SBI reports a hart it cannot start), or a zero
`BootInfo.ap_trampoline_page` with more than one CPU listed, is fatal: every CPU the boot
reported is assumed online from Phase 8 on (IPI targets, scheduler placement, affinity), so a
CPU that cannot be started halts the boot with a descriptive message.
A started CPU that never announces itself leaves the BSP waiting at
`APS_READY` on either architecture; on x86-64 that wait is the only signal,
since SIPI delivery is unacknowledged and `start_ap` cannot report a failure.
An AP that provides fewer hardware TLB tags than the BSP configured halts itself with
"AP provides fewer hardware TLB tags than the BSP configured" before announcing itself,
which leaves the BSP waiting at `APS_READY`.
An entropy self-test FAIL (step 5) is printed and the boot continues; the
marker is matched by the `run-parallel` fail regex, which turns a QEMU run red
(see [entropy.md](entropy.md) § Testing).

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
   c. PIE rebase (INIT_IMAGE_FLAG_PIE set — the userspace targets link init as a static
      PIE, #39): draw the load bias from the entropy pool
      (process_layout::choose_image_bias; window base if unseeded),
      validate the biased span (validate_image_placement), apply the
      .rela.dyn RELATIVE relocations through the direct map
      (mm/init_reloc.rs; targets must fall in writable segments, anything
      unresolvable is fatal), bias every segment virt_addr and the
      entry point, then seal PT_GNU_RELRO: writable segments covered by
      the relro range flip to Read (splitting at the range end if it
      lands mid-segment). Logged as "init: PIE bias=0x… (N relocations)".
2. Create the init address space (`boot_retype_aspace`): carve a slab from
   the SEED Memory cap; page 0 holds the wrapper object and the in-place
   `AddressSpace`, page 1 the zeroed root page table with kernel root
   entries 256–511 (the kernel half in every paging mode) copied from the
   active root so the kernel remains reachable from init's address space,
   and the remaining pages seed the space's page-table pool
3. Map init segments into the init address space:
   a. For each InitSegment in init_image.segments[0..segment_count]:
      - Align virt_addr and phys_addr to page boundaries before mapping
      - Map the page-aligned virtual address to the page-aligned physical frame
      - The in-page offset (virt_addr & 0xFFF) is preserved implicitly: the CPU
        adds it to the physical frame address at translation time
      - Apply permissions from segment.flags (Read → RO, ReadWrite → RW,
        ReadExecute → RX); W^X is enforced (ReadWrite cannot also be executable)
   b. Mint the AddressSpace cap (MAP | READ) for init's address space into
      the root CSpace, then a reclaimable Memory cap per init segment
      (page-aligned base and size, full rights, `owns_memory = true`, the
      range added to the buddy ledger by `register_owned_range`) so init can
      donate the frames to memmgr on reap
   c. Fill the InitInfo region (InitInfo header, CapDescriptor array) in the
      contiguous block reserved in Phase 7, map it read-only at the chosen
      InitInfo VA (`choose_init_layout().init_info_va`), and mint a
      reclaimable Memory cap per mapped InitInfo page into the root CSpace
4. Map init's user stack (inlined in `kernel_entry_post_rebase`):
   a. Take the INIT_STACK_PAGES (4) frames reserved from the buddy in
      Phase 7, before the user-cap drain, one at a time so each phys
      address is captured for the reclaim Memory cap minted alongside it
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
   c. Priority: INIT_PRIORITY (30)
   d. Mint the Thread cap (CONTROL) for init's thread into the root CSpace
   e. Mint the CSpace cap (INSERT | DELETE | DERIVE) for the root CSpace into
      itself, then patch both slots into InitInfo
   f. cspace: take the root CSpace pointer with `cap::take_root_cspace` (which clears
      ROOT_CSPACE) and store it, with its id and registry epoch, in the init TCB
6. Enqueue the init TCB on the BSP's run queue at INIT_PRIORITY
7. Call sched::enter() — does not return:
   a. Dequeue the highest-priority ready thread (init)
   b. Build an initial user-mode TrapFrame on init's kernel stack:
      rip/sepc=entry_point, rsp/sp=chosen init stack top, cs=USER_CS, ss=USER_DS,
      rflags=0x202 (IF=1)
   c. x86-64: `first_entry_to_user` composes the CR3 value (init's root, OR'd with its
      claimed PCID when tagging is enabled) and calls switch_and_enter_user(cr3, tf_ptr),
      which switches RSP to init's kernel stack, writes CR3, builds the iretq frame, and
      executes iretq
   d. RISC-V: `first_entry_to_user` activates init's address space (`AddressSpace::activate`:
      a satp write, ASID-tagged when tagging is enabled, with a flush only when the per-CPU
      generation check requires one), then calls return_to_user(tf_ptr), which restores
      registers and executes sret
```

The PIE bias window, relocation rules, and init stack placement are defined in
[userspace-memory-model.md](../../../docs/userspace-memory-model.md) § Image Placement and
§ Bootstrap Cross-Boundary VAs; the kernel-half root entries and W^X rule in
[memory-model.md](../../../docs/memory-model.md) § Virtual Address Space Layout and § Paging;
the reap-time donation of the segment, InitInfo, and stack pages in
[process-lifecycle.md § Init reap](../../../docs/process-lifecycle.md#init-reap).

**Implementation notes:**
- CSpace hand-off (step 5f): `sched::enter()` calls `set_current(init_tcb)` so
  `current_tcb()` returns the init TCB during init's syscalls; init's TCB holds the former
  root CSpace (step 5f).
- The x86-64 `switch_and_enter_user` function switches the stack pointer to init's kernel
  stack before writing CR3 and builds the `iretq` frame there. The boot stack was rebased
  onto the direct map in Phase 3 (`rebase_boot_stack`), and init's page tables share that
  mapping through the copied kernel root entries 256–511.
- Init segment frames stay mapped in init's address space; their reclaimable Memory
  caps (step 3b) are donated at reap
  ([process-lifecycle.md § Init reap](../../../docs/process-lifecycle.md#init-reap)).

**Failure mode:** Allocation failure halts with a diagnostic message identifying the
failed step. Invalid init_image (zero segment_count or zero entry_point) halts with
"Phase 9: init image missing or has no entry point".

**Completion criterion:** Init is executing in user mode (ring-3 / U-mode).

---

## Fatal Boot Failure Handling

At any phase, if the kernel cannot continue:

```rust
pub(crate) fn fatal(msg: &str) -> !
{
    kprintln!("FATAL: {}", msg);
    arch::current::cpu::halt_loop();
}
```

`halt_loop` disables interrupts and halts the calling CPU permanently (`hlt` on x86-64,
`wfi` on RISC-V).

Secondary CPU failures after Phase 9 (user-mode entry) are handled by `fatal()` on
that CPU only; the BSP and other CPUs continue.

---

## Initialization Summary

| Phase | Key Action | Failure |
|---|---|---|
| 0 | Validate BootInfo version | Silent halt |
| 1 | Early console; platform feature gate | Halt: missing required baseline feature (no console is non-fatal) |
| 2 | Buddy allocator from memory map | Halt: no usable RAM |
| 3 | Kernel page tables + direct map | Halt: BOOT_TABLE_POOL exhausted; direct map would overlap the kernel image window |
| 4 | Typed-memory cap surface; per-CPU storage | Halt: per-CPU storage allocation failed |
| 5 | CPU hardware (IDT/GDT/TSS/stvec); seed entropy pool | Halt: hardware initialisation failure |
| 6 | Platform resource validation | Halt: null entries with non-zero count, or entries slice outside Usable/Loaded memory; bad entries skipped, entries beyond MAX_MMIO_APERTURES dropped |
| 7 | Capability system + root CSpace | Halt: OOM |
| 8 | Scheduler + idle threads, SMP bringup, AP trampoline reclaim, entropy self-test | Halt: rejected start_ap (riscv64); zero ap_trampoline_page with more than one CPU listed; late-reclaim cap mint failure (SEED / CSpace). A started CPU that never announces itself leaves the BSP waiting (x86-64 cannot detect this earlier: SIPI is unacknowledged); an entropy self-test FAIL is printed and the boot continues |
| 9 | Init creation + scheduler entry (user mode) | Halt: invalid InitImage or OOM |

---

## Summarized By

[abi/boot-protocol/README.md](../../../abi/boot-protocol/README.md),
[core/boot/README.md](../../boot/README.md), [Boot Flow](../../boot/docs/boot-flow.md),
[ELF Loading](../../boot/docs/elf-loading.md),
[Firmware Parsing](../../boot/docs/firmware-parsing.md),
[Kernel Handoff Contract](../../boot/docs/kernel-handoff.md),
[Memory Map Translation](../../boot/docs/memory-map.md),
[Page Tables](../../boot/docs/page-tables.md), [core/kernel/README.md](../README.md),
[Capability Subsystem Internals](capability-internals.md),
[Kernel Cross-Boundary Disclosure Inventory](cross-boundary-disclosure.md),
[Kernel Entropy Subsystem](entropy.md), [Memory Subsystem Internals](memory-internals.md),
[SMP Scheduling and Locking Invariants](scheduling-internals.md),
[System Bootstrap](../../../docs/bootstrap.md),
[Capability Model](../../../docs/capability-model.md),
[Device Management](../../../docs/device-management.md),
[Memory Model](../../../docs/memory-model.md),
[Userspace Memory Model](../../../docs/userspace-memory-model.md),
[shared/elf/README.md](../../../shared/elf/README.md)
