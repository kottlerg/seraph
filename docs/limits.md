# Limits

Catalogue of every in-tree number or type width that bounds what Seraph can do or hold,
classified against the hardware-realistic-ceiling principle.

---

## Authority and Scope

This document is authoritative for the principle every in-tree bound is judged against, for the
test that applies it, and for each bound's classification and recommendation below. The values
themselves are owned by the code, cited here by stable identifier. The behaviour each bound
governs is owned by the subsystem's own design document. Where a value in a table disagrees with
the code, the code governs and the row is stale.

The scope is every constant, fixed-size array, field or type width, loop bound, length limit,
spin or poll count, and compile-time assert in `abi/`, `core/`, `runtime/`, `services/`, and
`shared/` that bounds a kernel-managed or service-managed pool, a per-message or per-object
count, an identifier's lifetime, a buffer or page budget, a walk or retry depth, a name or path
length, or a timeout. Register layouts, bit masks, error codes, syscall numbers and protocol labels
are out of scope unless they bound a count. Items compiled only for host tests are out of scope.

### Principle

The principle is quoted from
[#177](https://github.com/kottlerg/seraph/issues/177) § The principle:

> The constant SHOULD be high enough that no realistic workload running on plausibly-sized
> hardware ever hits it, *without* paying for that ceiling in static BSS / cache footprint
> that's wasted in the 99.99% case.

The patterns that meet it are recycling with epoch validation for freshness-only identifiers
(retire-on-wrap is acceptable for these), widening to `u64` for identity-bearing identifiers,
growable structures sourced from typed memory in place of fixed arrays, and per-instance rather
than global pools.

### Governing test

Every entry is judged by one question: **if the machine had more RAM, CPUs, devices, or address
space, would this bound still stop the system first?**

- If it would, the entry is a defect against the principle, whatever its headroom today, and is
  classed `raise`, `make pay-as-you-go`, or `needs a design`.
- `correct as is` is reserved for a bound set by a hardware or format specification, by a
  committed ABI width, or by provable unreachability on any plausible hardware. A bound whose
  overflow only splits work into more rounds (a batch size, a streaming chunk, a per-message
  count that every protocol iterates over, a refillable seed) or that bounds no capacity at all (a
  tuning threshold, a diagnostic output cap) cannot stop the system first and is
  `correct as is` under the provable-unreachability arm. The reason is meant to be stated at the
  constant, in its doc comment or in the comment at its definition; an entry whose constant does
  not state it is a documentation gap to be recorded.

### Columns

| Column | Content |
|---|---|
| Item | The constant, static, field (`Type.field`), type width, or loop bound |
| Location | The file that declares it |
| Value | Its current value, with the derivation where it is derived |
| Set by | What fixes the value today: a hardware or format spec, an ABI width, an encoding artefact, a static-footprint budget (BSS, a fixed allocation, or a stack array), current peak plus headroom, or provable unreachability |
| Up-front cost | The static, per-object, or eager cost paid for the ceiling whether or not it is reached |
| Class | `correct as is`, `raise` (raise the value or widen the type), `make pay-as-you-go` (keep the ceiling, pay only for use), or `needs a design` |
| Recommendation | One line |

The Issue that tracks a section's non-`correct as is` entries is named under the section heading.
An entry an existing open Issue already names cites it in the recommendation.

---

## Cross-Cutting Findings

- **RAM ceiling.** Within a 4-level or Sv48 kernel half no kernel memory-management
  structure bounds RAM: the Phase 3 tables come from a carve of RAM sized to the machine, the
  frame map's and the `CSpace` registry's chunk tables are sized from the memory map, and the
  buddy allocator keeps its free-list links in the free blocks. What binds there is the address
  space: x86_64's 4-level paging gives the direct map a 128 TiB kernel half, and where the CPU
  reports LA57 (5-level paging, negotiated at boot) or under Sv57 the half is 64 PiB; the
  stage-1 seed (`BOOT_TABLE_POOL_SIZE`) maps only the image and the carve's first two chunks,
  so it does not grow with RAM. The `u32` `CSpaceId` stops the registry at 16 TiB of DRAM.
- **CPU ceiling.** The binding CPU ceiling is `MAX_CPUS` itself, the kernel's `CpuMask` width
  (`BootInfo.cpu_ids` is an array in its own pages, so the page no longer bounds it); shipping
  two-socket servers already exceed 512 logical CPUs. A per-CPU slab may span several buddy
  blocks, so `MAX_ORDER` no longer caps the CPU count.
- **Process ceiling.** No table caps live processes: procmgr's grows on its heap, memmgr's is
  RAM-bound, and the kernel's `CSpace` registry is sized from RAM and does not bind first. The
  death queues' observer pools grow too: procmgr and svcmgr each add a queue, funded from their
  own memory, when every pool is out of nodes, and logd's queue needs none, since procmgr posts
  each death to it. The death correlators are the full `u64` badge or table index. A further
  queue is one contiguous memmgr grant, retried at half the pool down to the first pool's
  size, and the main wait set that holds the queues doubles up to 1024 members. Each wait set
  is one contiguous grant too, so RAM that refuses every request above three pages stops the
  set at 256 members, where the queues still hold about 16 K live processes: the death-queue
  set's floor, not a cap a system meets, since such RAM refuses each spawn's own contiguous
  grants (a 48-page `AddressSpace`, a `Thread` slot of six pages or more) first. The
  first bound past RAM is procmgr's `CSpace` (about 1 M children, `MAX_SLOTS_STRUCTURAL`), and
  behind it sits the cap handle's 8-bit wrapping generation.
- **Per-process address space.** The surfaces a creator places stay in one static map below
  Sv39's 2^38 on every architecture; the heap and reservation arena a process places itself are
  sized to its user half (tens of GiB under Sv39, 32 TiB each under 2^47), and the main stack and
  TLS block each reach 1 GiB of VA.
- **Unpinned couplings.** Bounds that depend on each other are tied only by comments or literal
  copies: `REAPER_SLOTS` and `GEN_BITS`, the ktest mirrors of `L2_SIZE` (in `unit::cap_info`),
  `MAX_IRQ_BINDINGS` and `KERNEL_STACK_PAGES`, and vfsd gpt's `MAX_BLOCK_SIZE` and virtio-blk's.
- **Spin-count timeouts.** Several device polls are counted in loop iterations, whose wall time
  depends on CPU and MMIO speed. `wait_for_ack` and the kernel lock detectors
  (`bounded_wait::DEADLOCK_BUDGET_US`) are the time-based model.
- **Hidden global pools.** None in the kernel's capability subsystem: SEED holds only the boot
  footprint, sized from the `InitInfo` block's descriptor capacity, and the bodies a syscall
  creates (split children, Mmio, IoPort, and Interrupt copies, spilled Mmio mapping records, IOPB
  tables) are funded by a `CSpace` pool the call names.

## Catalogue

### Kernel: memory management

Tracked by [#636](https://github.com/kottlerg/seraph/issues/636).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `BuddyAllocator.free_lists` (`FreeHeader` in each free block) | `core/kernel/src/mm/buddy.rs` | none: one 16 B header inside each free block, linked by physical address | provable unreachability (no metadata outside the free pages) | 96 B BSS (the 12 list heads) | correct as is | None |
| `MAX_ORDER` | `core/kernel/src/mm/buddy.rs` | 11 (8 MiB largest block) | tuning (block granularity; a boot allocation past one block takes a run of blocks, `alloc_contiguous`) | none | correct as is | None |
| `BOOT_TABLE_POOL_SIZE` (`BootTablePool.frames`) | `core/kernel/src/mm/paging.rs` | 64 frames | static-footprint (BSS) budget (stage 1 maps only the image, the handoff stack window and the carve's first two 2 MiB chunks, whose frames map the rest of the carve, `map_carve_rest`; the need is fixed by the image, not by RAM) | 256 KiB BSS | correct as is | None; a seed too small for the image fails Phase 3 by name |
| Phase 3 stage-2 carve (`stage2_table_bound`, `find_boot_table_carve`) | `core/kernel/src/mm/paging.rs`, `init.rs` | an upper bound on the stage-2 tables, about one frame per GiB of direct map | provable unreachability (sized from the machine; a host test checks the bound against a real allocation) | about 4 KiB per GiB of RAM | correct as is | None |
| `LARGE_PAGE_SIZE` | `core/kernel/src/mm/paging.rs` | 2 MiB | hardware spec (x86-64 and Sv39 large leaf) | none | correct as is | None |
| `init_kernel_page_tables` `mmio_regions` | `core/kernel/src/mm/paging.rs` | `[(u64, u64); MMIO_DIRECT_MAP_REGIONS]`: `1 + MAX_IOAPICS` (129) on x86_64, 0 on riscv64 | ABI width (derived from the producer's own bound) | about 2 KiB stack | correct as is | None |
| `map_boot_stack` identity window (`handoff_stack_window`) | `core/kernel/src/mm/paging.rs` | `2 x HANDOFF_STACK_BYTES` from the derived stack base | ABI width (the entry contract's guaranteed stack, `HANDOFF_STACK_BYTES`) | 32 PTEs | correct as is | None |
| `FrameMap` chunk table (`chunk_slots`) | `core/kernel/src/mm/frame_map.rs` | one slot per GiB of DRAM span; a chunk per GiB that holds RAM | provable unreachability (sized from the memory map at boot) | 8 B per GiB of span plus 1 MiB per GiB of RAM | correct as is | None |
| `FrameMap` per-frame counter | `core/kernel/src/mm/frame_map.rs` | `AtomicU32`, saturating | provably unreachable (2^32 leaf PTEs to one frame need 32 GiB of page tables, and saturation refuses the map) | 4 B per frame | correct as is | None |
| `RELEASE_RUNS` (`ReleaseBatch.runs`) | `core/kernel/src/mm/frame_map.rs` | 16 | batch size (a full batch flushes, never fails) | 256 B stack | correct as is | None |
| `FRAMES_PER_CHUNK` geometry assert | `core/kernel/src/mm/frame_map.rs` | 1 GiB per chunk, 1 MiB counter block | encoding artefact | none | correct as is | Keep |
| Free-range stream (`for_each_payload_free_piece`) | `core/kernel/src/mm/init.rs` | none: each usable entry is cut against the boot payload's extents as it is read | provable unreachability (nothing is stored; the cost is pieces times exclusions) | none | correct as is | None |
| `fdt_extent` DTB size check | `core/kernel/src/mm/init.rs` | FDT `u32` `totalsize`, at least the 40-byte header, inside the direct-mapped span | hardware or format spec (FDT header) | none | correct as is | None; a blob outside the bounds halts the boot at Phase 3 |
| `TagPool` storage (`MAX_HW_TAGS`) | `core/kernel/src/mm/tag_allocator.rs` | buddy-allocated, sized to the probed tag count, at most 2^16 | hardware spec (the 16-bit `satp.ASID`; x86 PCID is 12 bits) | 16 B per tag plus the bitmap | correct as is | None |
| `TAG_STATE_BUDGET_BYTES` tag trim | `core/kernel/src/mm/tag_allocator.rs` | 8 MiB of per-CPU tag state, never below `cpu_count + 2` tags | tuning (a claim always succeeds; fewer tags only means more evictions) | `cpu_count` x tags x 16 B | correct as is | None |
| `AddressSpace.tag`, `TlbShootdownRequest.tag` | `core/kernel/src/mm/address_space.rs`, `tlb_shootdown.rs` | `AtomicU16` | hardware spec (PCID and ASID widths) | 2 B each | correct as is | None |
| `alloc_gen`, `tag_gen`, `tlb_gen` | `core/kernel/src/mm/tag_allocator.rs`, `address_space.rs` | `u64` | provably unreachable (no wrap at any claim rate) | 8 B each | correct as is | None |
| `acquire_tag_pool_lock` wait bound | `core/kernel/src/mm/tag_allocator.rs` | `DEADLOCK_BUDGET_US` (5 s elapsed), then fatal | tuning (bounds no capacity) | none | correct as is | None |
| `claim` eviction retry bound | `core/kernel/src/mm/tag_allocator.rs` | `DEADLOCK_BUDGET_US` (5 s elapsed), then fatal | tuning (bounds no capacity) | none | correct as is | None |
| `acquire_frame_alloc_lock` wait bound | `core/kernel/src/mm/mod.rs` | `DEADLOCK_BUDGET_US` (5 s elapsed), then fatal | tuning (bounds no capacity) | none | correct as is | None |
| TLB-shootdown request slab (`TLB_REQUESTS_PTR`) | `core/kernel/src/mm/tlb_shootdown.rs` | `cpu_count`-sized | ABI width (`MAX_CPUS` upper bound) | `cpu_count` x about 96 B | correct as is | Already pay-as-you-go |
| `RANGE_FLUSH_CEILING_PAGES` | `core/kernel/src/mm/tlb_shootdown.rs` | 32 | tuning threshold (bounds no capacity) | none | correct as is | None |
| `CPU_MASK_WORDS` (`CpuMask`) | `core/kernel/src/cpu_mask.rs` | `MAX_CPUS.div_ceil(64)` = 8 | ABI width (`MAX_CPUS`) | 64 B in every `AddressSpace` and TLB request | make pay-as-you-go | Decided: a per-boot width (`cpu_count.div_ceil(64)` words held with their object) once `MAX_CPUS` leaves `BootInfo` (#640); a hierarchical mask is rejected (reasons at the constant) |
| `AddressSpace.death_observers` | `core/kernel/src/mm/address_space.rs` | unbounded chain of queue-funded nodes | none (each node is funded by the observing queue) | 8 B per `AddressSpace` | correct as is | None |
| `DEFAULT_INIT_INFO_VA`, `DEFAULT_INIT_STACK_TOP` | `core/kernel/src/mm/address_space.rs` | fixed VAs under the Sv39 user top | encoding artefact (fallback layout) | none | correct as is | Not a count |
| `INIT_MAX_SEGMENTS` RELRO split | `core/kernel/src/mm/init_reloc.rs` | 8 | ABI width (boot protocol) | none | correct as is | A split past 8 is a clean error |
| `kernel_pt_pool` seed | `core/kernel/src/mm/kernel_pt_pool.rs` | 64 pages (`POOL_SEED_PAGES`), never returned | provable unreachability (only the Phase 9 bootstrap maps of init's image, `InitInfo` and stack draw from it, measured 6 to 7 pages; no map syscall does, since every address space records its create-time donation before it is published and `AddressSpaceObject::require_create_donation` refuses a map otherwise) | 256 KiB | correct as is | None |
| x86_64 paging depth (`user_va_top`) | `core/kernel/src/arch/x86_64/paging.rs` | 4-level: user 128 TiB, kernel half 128 TiB; 5-level (LA57): 64 PiB each | hardware spec (4-level paging, or 5-level when CPUID reports LA57, negotiated at boot as riscv64 negotiates Sv57; docs/platform-requirements.md) | none | correct as is | 5-level meets the #177 target of 526 TB; a CPU without LA57 stays below it |
| `PerCpuData`, `CPU_APIC_IDS` slabs | `core/kernel/src/percpu.rs` | `cpu_count`-sized | ABI width (`MAX_CPUS` upper bound) | `cpu_count` x about 76 B | correct as is | Already pay-as-you-go |
| `CPU_APIC_IDS` element | `core/kernel/src/percpu.rs` | `u32` | ABI width (`BootInfo.cpu_ids`; x2APIC IDs are 32-bit) | 4 B per CPU | correct as is | riscv64 `mhartid` is XLEN-wide; a hart id above 2^32 is refused |
| `PerCpuData.cpu_id`, `preempt_count` | `core/kernel/src/percpu.rs` | `u32` | provably unreachable (CPUs and nesting are far below 2^32) | embedded | correct as is | None |
| `Spinlock.next_ticket`, `now_serving` | `core/kernel/src/sync.rs` | `AtomicU32`, wrapping | provably unreachable (equality compare; waiters at most CPUs) | 8 B per lock | correct as is | None |
| `boot_cpu_ids` | `core/kernel/src/main.rs` | the `cpu_count` ids at `BootInfo.cpu_ids` (at most `MAX_CPUS`), read in place through the direct map | ABI width (`BootInfo.cpu_ids`, `MAX_CPUS`) | none (no copy) | correct as is | None: Phase 0 checks the array lies in RAM |
| `INIT_ASPACE_PAGES` | `core/kernel/src/cap/mod.rs` | 18 | provably unreachable (init's fixed footprint: temp-map scratch and one UART page; augment can refill it, as ktest does) | 72 KiB from SEED | correct as is | None |
| `thread_slot_bytes` (Thread retype slot, `sched::thread_slot`) | `core/kernel/src/sched/thread_slot.rs` | `KERNEL_STACK_PAGES` + 1 TCB page + the save-area pages, at least one: six pages on x86-64 (the 832 B x87, SSE and AVX XSAVE area) and on riscv64 up to `vlenb` 118, 70 pages at VLEN 65536 | encoding artefact (stack, TCB, and a save area sized at boot from the boot CPU: CPUID 0xD on x86-64, `304 + 32 * vlenb` on riscv64) | per thread; init's from SEED | correct as is | None |
| `page_ptrs`, `page_phys` | `core/kernel/src/main.rs` | `[_; INIT_INFO_MAX_PAGES]` | ABI width (init protocol) | 64 B stack | correct as is | None; the descriptor capacity keeps the region within them |
| `backtrace_scan` extent | `core/kernel/src/main.rs` | the thread's stack, SP to `stack_top` | provable unreachability (the stack's own extent) | none | correct as is | None |
| `backtrace_scan` `MAX_HITS` | `core/kernel/src/main.rs` | 24 | diagnostic output cap | none | correct as is | None |
| `APS_READY` wait (`AP_ONLINE_BUDGET_US`) | `core/kernel/src/main.rs` | 10 s per AP, then fatal naming the CPU | tuning (bounds no capacity) | none | correct as is | None |
| `timer::init(1_000)` tick period | `core/kernel/src/main.rs` | 1000 us | tuning (bounds no capacity) | none | correct as is | None |
| `print_timestamp` `sec_buf` | `core/kernel/src/console.rs` | 20 B | ABI width (`u64::MAX` has 20 digits) | 20 B stack | correct as is | None |
| `FramebufferWriter` geometry fields | `core/kernel/src/framebuffer.rs` | `u32` | ABI width (boot-protocol `FramebufferInfo`) | embedded | correct as is | None |
| `platform::ValidatedApertures` | `core/kernel/src/platform.rs` | none: a filtered view of `BootInfo`'s aperture list | provable unreachability (nothing is copied) | none | correct as is | None |

### Kernel: capabilities

Tracked by [#637](https://github.com/kottlerg/seraph/issues/637); the Phase 7 boot buffers by
[#636](https://github.com/kottlerg/seraph/issues/636).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `CSPACE_REGISTRY` arena (`chunks_for_ram`, `init_cspace_registry`) | `core/kernel/src/cap/registry.rs` | one 16 B entry per page of DRAM | provably unreachable (every `CSpace` costs its creator at least one page, so the id space never binds before RAM does) | about 0.4 % of DRAM, carved at boot | correct as is | None |
| `REGISTRY_CHUNK_ORDER` | `core/kernel/src/cap/registry.rs` | 8 (1 MiB chunks) | encoding artefact (chunk granularity of the two-level arena) | none | correct as is | None |
| `CSpaceRegistry` chunk table (`chunks_for_ram`, `MAX_ID_CHUNKS`) | `core/kernel/src/cap/registry.rs` | one slot per 256 MiB of DRAM, at most `MAX_ID_CHUNKS` (the `u32` id space, 16 TiB of DRAM) | encoding artefact (`CSpaceId` width) | 8 B per 256 MiB of DRAM | correct as is | None |
| `RegistryEntry.epoch`, `SlotId.epoch` | `core/kernel/src/cap/registry.rs`, `slot.rs` | `u32`, redrawn on recycle | encoding artefact (12 B `SlotId`, 72 B slot) | 4 B per `SlotId` | correct as is | Freshness-only; the residual per recycle is documented |
| `CapabilitySlot.pad[1]` (handle generation) | `core/kernel/src/cap/slot.rs` | `u8`, wrapping | ABI width (`u32` handle: 8 generation + 24 index bits) | 1 B per slot | raise | Wraps after 256 recycles of one index. Retiring the index at wrap instead leaks one 72 B slot per 256 frees, which cap-churning workloads exhaust their `CSpace` pools with in seconds, so widen handles; decide with `CAP_INDEX_BITS` |
| `CAP_INDEX_BITS` | `abi/syscall/src/lib.rs` | 24 | ABI width (`u32` handle) | none | needs a design | About 16.7 M slots per CSpace; decide with the generation (#41) |
| `L2_SIZE` | `core/kernel/src/cap/cspace.rs` | 56 | encoding artefact (56 x 72 B in one page, asserted; published as `CSPACE_SLOTS_PER_PAGE`) | none | correct as is | None |
| `L1_DIRECT`, `L1_INDIRECT` | `core/kernel/src/cap/cspace.rs` | 128 / 128 | encoding artefact (two-level directory inline in the CSpace) | 2 KiB per CSpace | correct as is | Add a level, not inline pointers, if `MAX_SLOTS_STRUCTURAL` ever binds (#41) |
| `MAX_LEAVES`, `MAX_SLOTS_STRUCTURAL` | `core/kernel/src/cap/cspace.rs` | 65 664 leaves, 3 677 184 slots per CSpace | encoding artefact (directory geometry) | none (growth is pool-funded) | needs a design | procmgr's CSpace bounds its children near 1 M; decide with `CAP_INDEX_BITS` |
| CSpace geometry asserts | `core/kernel/src/cap/cspace.rs` | `MAX_SLOTS_STRUCTURAL <= 1 << CAP_INDEX_BITS`, page fits | encoding artefact | none | correct as is | Keep |
| `CSpace.next_leaf`, `pool_exhaustions` | `core/kernel/src/cap/cspace.rs` | `u32` | encoding artefact (`next_leaf` asserted against `MAX_LEAVES`); `pool_exhaustions` is a wrapping diagnostic counter | embedded | correct as is | None |
| `ROOT_CSPACE_INIT_SLOT_CAPACITY` | `core/kernel/src/cap/mod.rs` | 1536 slots | ABI width (the boot mint, `BOOT_BODY_BOUND`, about 550 caps, from `INIT_INFO_MAX_PAGES` = 4) and a round split (init's forward to memmgr stops at `INIT_FORWARD_HEADROOM`, 512 general slots, a stated rather than asserted budget for what init mints after it, and the rest rides the reap round); init never augments this `CSpace` | about 29 pages | correct as is | Re-class when #640's `InitInfo` sizing lifts `BOOT_BODY_BOUND` |
| `ROOT_CSPACE_BODY_PAGES` | `core/kernel/src/cap/mod.rs` | 16 pages (496 bodies, 31 per page) | current peak plus headroom (init's per-page split bodies, about twice its peak; init never augments its own `CSpace`) | 64 KiB of SEED | make pay-as-you-go | Have init top its own `CSpace` up (`cspace_topup_pages`) from its RAM caps instead of a fixed SEED seed (#637) |
| `seed_reserve_bytes` (`SEED_MEMORY`) | `core/kernel/src/cap/mod.rs` | about 365 KiB: `SEED_FIXED_RESERVE_BYTES` (the root `CSpace` and init address-space slabs, one 128 B body per `InitInfo` descriptor and per Phase-9 Memory cap (`BOOT_BODY_BOUND`, 551), and 4 pages of alignment slack) plus init's Thread slot (`thread_slot_bytes`) | ABI width (the boot mint is bounded by `INIT_INFO_DESCRIPTOR_CAPACITY`; nothing draws on SEED after boot) | about 365 KiB pinned | correct as is | None; a boot past the bound, a map of more than about 520 ACPI regions among them, halts by name |
| `INIT_INFO_DESCRIPTOR_CAPACITY` (the `InitInfo` descriptor array) | `core/kernel/src/cap/mod.rs` | the descriptors `INIT_INFO_MAX_PAGES` pages hold past the header, 535 | ABI width (`INIT_INFO_MAX_PAGES`; the drain writes its RAM extents and Phases 7 and 8 every boot descriptor straight into the reserved `InitInfo` block) | none (in the `InitInfo` block init receives) | correct as is | None here; the drain and `push_descriptor` halt the boot by name past it, a map of more than about 520 ACPI regions and MMIO apertures together among the causes; raising it is the `INIT_INFO_MAX_PAGES` row |
| `CSpaceLayout.module_names` | `core/kernel/src/cap/mod.rs` | 85 (`INIT_MAX_NAMED_MODULES`) | ABI width (init protocol; equals `MAX_BOOT_MODULES`, const-asserted) | embedded | correct as is | None: a boot listing more modules halts at Phase 7 by name |
| `INIT_STACK_PHYS`, `INIT_INFO_RESERVE_ORDER` | `core/kernel/src/cap/mod.rs` | `INIT_STACK_PAGES`, `INIT_INFO_MAX_PAGES` | ABI width (init protocol) | 32 B | correct as is | None |
| `POOL_SEED_PAGES` | `core/kernel/src/cap/mod.rs` | 64 | provable unreachability (the Phase 9 bootstrap footprint, measured 6 to 7; see `kernel_pt_pool` in the memory-management section) | 256 KiB | correct as is | None |
| Phase 7 ACPI region caps (`mint_acpi_region_caps`) | `core/kernel/src/cap/mod.rs` | one per `AcpiReclaimable` boot memory-map entry | provable unreachability (bounded by the memory map's length; an overflow of the root `CSpace` or the `InitInfo` descriptor array halts the boot with a message) | none | correct as is | None |
| `ROOT_IRQ_COUNT` | `core/kernel/src/cap/mod.rs` | arch `ROOT_IRQ_COUNT` | hardware spec (the GSIs of `MAX_IOAPICS` I/O APICs; the PLIC id space) | none | correct as is | None |
| `RECLAIM_ARRAY_MAX_SPAN_PAGES` | `core/kernel/src/cap/mod.rs` | from `MAX_RECLAIM_RANGES` | ABI width (boot protocol) | none | correct as is | None |
| `MAX_IOPORT_BINDINGS` (`IoPortBindings.records`) | `core/kernel/src/cap/ioport_bindings.rs` | 252 per thread, the records the table's page holds after its header | encoding artefact (one page funded by the bound thread's `CSpace`; each binding needs a distinct `IoPort` object) | the record page of a bound thread | correct as is | None |
| `TABLE_PAGES` (`IoPortBindings` and its `ThreadIopb` parts) | `core/kernel/src/cap/ioport_bindings.rs` | 3 pages | hardware spec (the 8 KiB x86 IOPB, plus the record page) | three pages of the bound thread's `CSpace` pool per bound thread | correct as is | None |
| `CHUNK_BYTES`, `CHUNKS_PER_PAGE` (body arena) | `core/kernel/src/cap/arena.rs` | 128; 32 per page, chunk 0 the page's `ArenaPage` header | encoding artefact (the size class of every runtime body, asserted at `alloc_body`) | 128 B per body, from the funder's pool | correct as is | None |
| `SORT_BINS` (`sort_list`) | `core/kernel/src/cap/arena.rs` | 64 sorted runs | provable unreachability (bin `i` holds `2^i` nodes, so 64 bins sort any list a 64-bit address space holds) | 512 B stack during a dead `CSpace`'s cut | correct as is | None |
| `BIN_128`, `BIN_512`, `NUM_SUBPAGE_BINS` | `core/kernel/src/cap/retype.rs` | 128, 512; 2 | encoding artefact (object size classes) | 16 B per Memory object | correct as is | None |
| Page free-list walk (`try_alloc_page_block`, `PageCursor::insert`, `page_node_ok`) | `core/kernel/src/cap/retype.rs` | `size / PAGE_SIZE` nodes | provably unreachable (the list is address-ordered and coalesced, so a well-formed walk visits at most one node per page; a node below its predecessor's end is corruption, reported once per boot) | none | correct as is | None |
| EventQueue, Notification size asserts | `core/kernel/src/cap/retype.rs` | wrapper 24, header 16 | encoding artefact | none | correct as is | Keep |
| `MAX_REVOKE_EDITS` (`REVOKE_OBJECTS`) | `core/kernel/src/cap/derivation.rs` | 256 | batch size (subtrees of any size revoke in batches) | 2 KiB BSS | correct as is | None |
| `MAX_REPARENT_EDITS` | `core/kernel/src/cap/derivation.rs` | 256 | batch size | none | correct as is | None |
| `MAX_REPARENT_BATCHES` | `core/kernel/src/cap/derivation.rs` | `1 << 20` | batch size (a per-call bound of about 2.7e8 children re-linked: delete, split and move keep every child already moved when it trips, so a retry continues from the rest) | none | correct as is | None |
| `DerivationLock` reader count | `core/kernel/src/cap/derivation.rs` | `u32`, `u32::MAX` = writer | provably unreachable (readers at most CPUs) | 4 B | correct as is | None |
| `KernelObjectHeader.ref_count` (`REF_COUNT_LIMIT`) | `core/kernel/src/cap/object.rs` | `AtomicU32`; new slots refused at 2^31 by `try_inc_ref`, retypes by `retype_allocate`'s `at_ref_limit` check | provably unreachable (every userspace-amplifiable reference costs a 72-byte slot or a retype child of at least 128 bytes, so 2^31 references hold at least 144 GiB against one object, and reaching the ceiling refuses with `QuotaExceeded` instead of wrapping; the unchecked owners fit the 2^31 headroom) | 4 B per object | correct as is | None |
| `RANGE_COPY_LIMIT` | `core/kernel/src/cap/object.rs` | 2^31 - 1 per lineage | encoding artefact (the lineage count below `ROOT_SHARE`; each copy costs its funder a slot and a chunk, so the limit's copies hold over 400 GiB) | none | correct as is | None |
| `ROOT_SHARE` (`RangeLineage.live`) | `core/kernel/src/cap/object.rs` | `1 << 31` in `u32` | encoding artefact | embedded | correct as is | None |
| `MMIO_INLINE_MAPPINGS` (`MmioObject.mappings`, `MmioSpill`) | `core/kernel/src/cap/object.rs` | 4 inline, then chained chunks of 7 | encoding artefact (`MmioObject` fits the 128 B class; each spill chunk is funded by the mapper's `CSpace`) | 64 B per Mmio object | correct as is | None |
| `INLINE_RECORDS` (`PagePool.inline`) | `core/kernel/src/cap/object.rs` | 16 | encoding artefact (spills to record pages beyond) | 512 B per pool | correct as is | Unbounded through record pages |
| `SEED_BATCH_PAGES` | `core/kernel/src/cap/object.rs` | 64 | batch size (lock-hold bound) | none | correct as is | The total window is #434 |
| `RECORDS_PER_PAGE` | `core/kernel/src/cap/object.rs` | 127 | encoding artefact | none | correct as is | None |
| `CascadeStack` (`dealloc_object` cascade) | `core/kernel/src/cap/object.rs` | none: a LIFO linked through the queued objects' headers | provable unreachability (no storage outside the refcount-0 objects it holds) | 8 B stack | correct as is | None |
| `MAX_DRAIN_EDITS` | `core/kernel/src/cap/object.rs` | 256 | batch size | none | correct as is | None |
| `FRAME_WRITE_LOCKED` reader count | `core/kernel/src/cap/object.rs` | `u32` | provably unreachable (readers at most CPUs) | embedded | correct as is | None |

### Kernel: IPC and scheduling

Tracked by [#638](https://github.com/kottlerg/seraph/issues/638).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `Message.data` | `core/kernel/src/ipc/message.rs` | 64 words (`MSG_DATA_WORDS_MAX`) | ABI width (IPC buffer layout) | 512 B per TCB | correct as is | Bulk data moves through Memory caps |
| `Message.cap_slots` | `core/kernel/src/ipc/message.rs` | 4 (`MSG_CAP_SLOTS_MAX`) | encoding artefact (two registers of two `u32` handles) | 16 B per TCB | correct as is | See the Syscall ABI entry |
| `EventQueueState` counters | `core/kernel/src/ipc/event_queue.rs` | `u32` | encoding artefact (capacity at most `EVENT_QUEUE_MAX_CAPACITY`) | embedded | correct as is | None |
| `NotificationState.bits` | `core/kernel/src/ipc/notification.rs` | `u64` | ABI width (64 signal bits) | embedded | correct as is | None |
| Endpoint, Notification, EventQueue state size asserts | `core/kernel/src/ipc/*.rs` | 128 B bin | encoding artefact | none | correct as is | Keep |
| `WAIT_SET_MAX_MEMBERS` | `abi/syscall/src/lib.rs` | 1024, caller-sized below it | per-call bound (the interrupts-off level-readiness walk over every member) | 24 B per member, caller-funded | correct as is | A server with more sources splits them across sets |
| Wait-set member indices | `core/kernel/src/ipc/wait_set.rs` | `u16` | encoding artefact (above `WAIT_SET_MAX_MEMBERS`, asserted) | embedded | correct as is | None |
| `WaitSetState.waiters` | `core/kernel/src/ipc/wait_set.rs` | 1 | unknown | none | needs a design | A second waiter is refused (#464) |
| One wait set per source | `core/kernel/src/ipc/wait_set.rs` | 1 | design choice (bounds no capacity) | 8 B per source | correct as is | None |
| Wait-set size asserts | `core/kernel/src/ipc/wait_set.rs` | member 24 B, state 40 B | encoding artefact | none | correct as is | Keep |
| Bound-source backoff | `core/kernel/src/ipc/mod.rs` | 64 spins | tuning (a backoff, not a bound) | none | correct as is | None |
| `SLEEP_LIST` (deadline heap) | `core/kernel/src/sched/mod.rs` | unbounded, one node per TCB | none (intrusive through the TCB) | about 72 B per TCB (heap node and expiry snapshot) | correct as is | One global heap under `SLEEP_LIST_LOCK`, popped on the BSP |
| `NUM_PRIORITY_LEVELS` | `core/kernel/src/sched/mod.rs` | 32 | ABI width (`u32` `non_empty` mask; `PRIORITY_MAX` 30) | 32 run queues per CPU | correct as is | None (#215) |
| `TIME_SLICE_TICKS` | `core/kernel/src/sched/mod.rs` | 10 | tuning | none | correct as is | None |
| `KERNEL_STACK_PAGES` | `core/kernel/src/sched/mod.rs` | 4 (16 KiB) | stack budget, measured (the bound at the constant; ktest after Tier S, both arches): debug at 4, 16 and 128 CPUs peaks at 3784 B (thread) and 1664 B (idle), and release at 4, 16 and 128 CPUs at 4304 B and 2080 B | 4 pages per thread, caller-funded | needs a design | Add a guard page below each kernel stack (a measured depth bounds no path the tests do not run, and an overflow now corrupts the page beneath) |
| `MAX_CPUS` | `core/kernel/src/sched/mod.rs` | 512 (`boot_protocol::MAX_CPUS`) | ABI width (boot protocol) | see the per-CPU rows | needs a design | See the boot section |
| Watchdog breadcrumbs (`CpuDiag`, `CPU_DIAG_PTR`) | `core/kernel/src/sched/mod.rs` | `cpu_count`-sized slab | ABI width (`MAX_CPUS` upper bound) | `cpu_count` x 32 B | correct as is | Already pay-as-you-go |
| `stop_threads_bound_to` `prod` (`mark_bound_threads`) | `core/kernel/src/sched/mod.rs` | a `CpuMask` | ABI width (`CPU_MASK_WORDS`) | 64 B kernel stack | correct as is | None |
| `WATCHDOG_THRESHOLD_SECONDS`, `DETECTOR_SCAN_INTERVAL_MS` | `core/kernel/src/sched/mod.rs` | 3 s / 500 ms, converted at `ticks_per_second()` | tuning (a diagnostic threshold at any tick rate) | none | correct as is | None |
| `WEDGE_GRACE_SECONDS` | `core/kernel/src/sched/mod.rs` | 8, scaled per 128 CPUs | tuning (scales with CPU count) | none | correct as is | None |
| `OWED_WAKE_MAX` (`OWED_WAKE_LAST`) | `core/kernel/src/sched/mod.rs` | 8, keyed by TCB pointer | diagnostic output cap | 128 B BSS | correct as is | None |
| `WATCHDOG_SLEEP_ENTRIES` | `core/kernel/src/sched/mod.rs` | 8 | diagnostic output cap | about 128 B stack | correct as is | None |
| `CS_SPIN_WARN_US` | `core/kernel/src/sched/mod.rs` | 100 000 us | diagnostic threshold | none | correct as is | None |
| `LOAD_BALANCE_IMBALANCE_THRESHOLD` | `core/kernel/src/sched/mod.rs` | 2 | tuning | none | correct as is | None |
| `PerCpuScheduler.load`, `non_empty` | `core/kernel/src/sched/run_queue.rs` | `AtomicU32` | provably unreachable (load at most threads, mask 32 bits) | per CPU | correct as is | None |
| `ThreadControlBlock.death_observers` | `core/kernel/src/sched/thread.rs` | unbounded chain of queue-funded nodes | none (each node is funded by the observing queue) | 8 B per TCB | correct as is | None |
| `EventQueueState.observer_count` | `core/kernel/src/ipc/event_queue.rs` | caller-chosen, at most `EVENT_QUEUE_MAX_CAPACITY` | caller-funded per queue (24 B per node) | none up front | correct as is | Bindings past the pool return `OutOfMemory` until a bound owner is destroyed |
| `DeathObserver.correlator`, posted exit reason | `core/kernel/src/sched/thread.rs` | `u64` correlator, full `u64` reason (one two-word EQ entry) | ABI width | embedded | correct as is | None: procmgr, svcmgr and devmgr pass the full badge or table index |
| `ThreadControlBlock.thread_id` | `core/kernel/src/sched/thread.rs` | random `u32` | provably unreachable as an identity (diagnostic only; no lookup, not exposed) | 4 B per TCB | correct as is | Widen if ever exposed |
| `park_seq`, `start_seq`, `park_episode`, `deposit_episode` | `core/kernel/src/sched/thread.rs` | `u32` | provably unreachable (freshness inside one short window) | embedded | correct as is | None |
| `ThreadControlBlock.cspace_epoch` | `core/kernel/src/sched/thread.rs` | `u32` | encoding artefact (mirrors the registry epoch) | 4 B per TCB | correct as is | None |
| `ThreadControlBlock.cpu_affinity` | `core/kernel/src/sched/thread.rs` | one CPU index or none | design choice | embedded | correct as is | A set affinity would need a `CpuMask` |
| `MAX_GROW_LEAVES_PER_HOLD` | `core/kernel/src/syscall/cap.rs` | 64 | batch size (lock-hold bound) | none | correct as is | None |
| `MAX_REVOKE_BATCHES` | `core/kernel/src/syscall/cap.rs` | `1 << 20` | batch size (a retry after `Interrupted` resumes; revoked nodes stay revoked) | none | correct as is | None |
| `TRAMPOLINE_FRAME_SIZE` | `core/kernel/src/syscall/cap.rs` | 512 B | encoding artefact (fixed trampoline frame) | none | correct as is | None |
| `sys_ipc_recv` cap-slot preallocation | `core/kernel/src/syscall/ipc.rs` | `MSG_CAP_SLOTS_MAX` slots | encoding artefact | none | correct as is | Follows `MSG_CAP_SLOTS_MAX` |

### Kernel: interrupts and architecture

The entries left open are tracked by the Issue each recommendation names: the vector space by
[#325](https://github.com/kottlerg/seraph/issues/325), the per-CPU slabs by
[#636](https://github.com/kottlerg/seraph/issues/636), and `IOAPICS` by the boot section's Issue.

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| IRQ routing table (`irq::init_table`) | `core/kernel/src/irq.rs` | one entry per line the discovered controllers implement (`interrupts::irq_line_count`) | hardware (the discovered I/O APICs' GSIs; the PLIC's `riscv,ndev`) | 40 B per line from the buddy at Phase 5 (`table_bytes`: `size_of::<IrqRoute>()` = 32 B, const-asserted beside the struct: an 8 B binding-list head, a 4 B in-flight count and the 4 B recorded mode, and the 8 B bound and 8 B owing masks; plus the routed-line set's 2 x 4 B) | correct as is | None |
| `unregister_notification` walk | `core/kernel/src/irq.rs` | the routed lines (`LineSet`), and each one's bindings | provable unreachability (scales with the bindings) | none | correct as is | None |
| `MAX_IRQ_BINDINGS` (`LineMasks`) | `core/kernel/src/irq.rs` | 64 bindings per line | provable unreachability (plausible hardware; one bit per binding in an atomic word) | none (one bit per binding in the routing-table entry; each binding lives in its Interrupt object) | correct as is | None: PCI Express requires every interrupting function to support MSI or MSI-X, SR-IOV virtual functions have no `INTx`, and once message-signalled delivery is served (#325, design intent) only legacy-only functions stay on wired lines, so more than 64 on one line is not plausible hardware (Linux's `IRQF_ONESHOT` `threads_oneshot` bitmask refuses a sharer past `BITS_PER_LONG`); a registration past it returns `QuotaExceeded` |
| x86_64 `DEVICE_VECTOR_COUNT` (`VECTOR_GSI`) | `core/kernel/src/arch/x86_64/ioapic.rs` | 217 device vectors (33-249), one generated stub each | hardware spec (x86 vector space less the exception, timer, IPI and spurious vectors), on one destination's vector space | 868 B BSS, 217 stubs of 16 B | needs a design | GSIs routed at once stop at 217; per-CPU vector spaces belong with the MSI work (#325) |
| x86_64 `ROOT_IRQ_COUNT`, `MAX_IRQ_ID` | `core/kernel/src/arch/x86_64/mod.rs` | `MAX_IOAPICS` x `IOAPIC_MAX_PINS` = 32768 / 32767 | ABI width (boot protocol) times hardware spec (8-bit redirection-entry count) | none | correct as is | Follows `MAX_IOAPICS`; a GSI above it is logged at boot |
| `IOAPIC_MAX_PINS` | `core/kernel/src/arch/x86_64/ioapic.rs` | 256 | hardware spec (I/O APIC version register) | none | correct as is | None |
| `DEVICE_VECTOR_BASE`, `DEVICE_VECTOR_LAST` and vector-range assert | `core/kernel/src/arch/x86_64/ioapic.rs`, `idt.rs` | 33, 249 | hardware spec (between the timer and IPI vectors) | none | correct as is | None |
| `IOAPICS` | `core/kernel/src/arch/x86_64/ioapic.rs` | `MAX_IOAPICS` = 128 | ABI width (boot protocol) | 2 KiB BSS | correct as is | None |
| `IDT` | `core/kernel/src/arch/x86_64/idt.rs` | 256 entries | hardware spec (x86 vector space) | 4 KiB BSS | correct as is | None |
| `GDT`, AP GDTs | `core/kernel/src/arch/x86_64/gdt.rs` | 7 descriptors | hardware spec (fixed descriptor layout) | 56 B per CPU | correct as is | None |
| `IOPB_SIZE` (`TssWithIopb.iopb`) | `core/kernel/src/arch/x86_64/gdt.rs` | 8192 B | hardware spec (65536 ports / 8) | about 8.3 KiB per CPU | correct as is | None |
| `IST_STACK_SIZE` (`BSP_IST_STACKS`) | `core/kernel/src/arch/x86_64/interrupts.rs` | 8 KiB x 2 | stack budget for the fixed NMI, #DF and #MC paths, audited: worst case under 3.7 KiB, debug and release builds | 16 KiB BSS | correct as is | None |
| `AP_IST_PAIR_SIZE` | `core/kernel/src/arch/x86_64/ap_trampoline.rs` | 16384 | encoding artefact (two IST stacks) | `cpu_count` x 16 KiB | correct as is | Derive as `2 * IST_STACK_SIZE` |
| Trampoline template and SIPI widths | `core/kernel/src/arch/x86_64/ap_trampoline.rs` | page-sized; root table (PML4 or PML5) below 4 GiB | hardware spec (real-mode SIPI, 32-bit CR3 load) | one page | correct as is | None |
| `wait_icr_idle` (`ICR_IDLE_BUDGET_US`) | `core/kernel/src/arch/x86_64/interrupts.rs` | 1 s | tuning (time-based) | none | correct as is | None |
| `wait_for_ack` ladder | `core/kernel/src/arch/*/interrupts.rs` | 250 / 750 / 5000 ms, on the spin-count estimate before the timer is calibrated | tuning (time-based) | none | correct as is | None |
| `MAX_SPINS_PER_UNIT` | `core/kernel/src/bounded_wait.rs` | 10 000 spins per us | provable unreachability (a 10 GHz clock), so the fallback never times out early | none | correct as is | None |
| `start_ap` delays | `core/kernel/src/arch/x86_64/interrupts.rs` | 10 ms, 200 us | hardware spec (Intel SDM INIT-SIPI-SIPI) | none | correct as is | None |
| `delay_us` pre-calibration spin | `core/kernel/src/arch/x86_64/timer.rs` | `us * 200` iterations | tuning (early boot only) | none | correct as is | None |
| `PIT_CALIBRATION_MS` | `core/kernel/src/arch/x86_64/timer.rs` | 10 ms | hardware spec (PIT) | none | correct as is | None |
| `PIT_POLL_BUDGET_TSC_TICKS` | `core/kernel/src/arch/x86_64/timer.rs` | 2^32 TSC ticks (0.43 s at 10 GHz), then fatal | tuning (bounds no capacity) | none | correct as is | None |
| `rdseed_u64`, `rdrand_u64` retry | `core/kernel/src/arch/x86_64/entropy.rs` | 32 | tolerance (above the Intel DRNG RDRAND guidance of 10; RDSEED has no fixed count) | none | correct as is | None |
| `enable_tagged_tlb` | `core/kernel/src/arch/x86_64/paging.rs` | 4096 | hardware spec (12-bit PCID) | none | correct as is | None |
| `TrapFrame::arg` | `core/kernel/src/arch/*/trap_frame.rs` | 6 arguments | ABI width (syscall register convention) | none | correct as is | None |
| riscv64 `MAX_IRQ_ID`, `PLIC_MAX_SOURCES` | `core/kernel/src/arch/riscv64/mod.rs`, `encoding.rs` | 1023 | hardware spec (PLIC) | none | correct as is | None |
| riscv64 `plic_ndev` | `core/kernel/src/arch/riscv64/platform.rs` | the firmware's `riscv,ndev`, clamped to 1023; 1023 when unreported | hardware (discovered) | none | correct as is | None |
| riscv64 `SOURCE_TARGET` | `core/kernel/src/arch/riscv64/interrupts.rs` | 1024 entries | hardware spec (PLIC id space) | 4 KiB BSS | correct as is | None |
| riscv64 `ROOT_IRQ_COUNT` | `core/kernel/src/arch/riscv64/mod.rs` | 1024 | hardware spec (PLIC id space) | none | correct as is | None |
| riscv64 `DEFAULT_PLIC_SIZE` | `core/kernel/src/arch/riscv64/encoding.rs` | 64 MiB | hardware spec (PLIC register map, 15 872 contexts) | none | correct as is | None |
| device IRQ destination (`irq::next_target_cpu`) | `core/kernel/src/irq.rs` | one CPU per line, the CPUs in turn at route time; x86_64 only APIC ids below 255 | hardware spec (one PLIC context per source; the 8-bit physical destination of an I/O APIC entry without interrupt remapping, 255 being broadcast) | none | correct as is | None |
| riscv64 ASID mask | `core/kernel/src/arch/riscv64/cpu.rs` | 16 bits | hardware spec (`satp`) | none | correct as is | None; the tag pool takes every probed ASID |
| riscv64 `sbi_hart_mask` window | `core/kernel/src/arch/riscv64/encoding.rs` | 64 harts per call | hardware spec (SBI `hart_mask`) | none | correct as is | None |
| riscv64 `NAPOT_64K_PAGES` | `core/kernel/src/arch/riscv64/paging.rs` | 16 | hardware spec (Svnapot) | none | correct as is | None |
| riscv64 `VLENB_SPEC_MAX` | `core/kernel/src/arch/riscv64/fpu.rs` | 8192 (VLEN 65536) | hardware spec (the V extension's largest VLEN; a larger, or non-power-of-two, `vlenb` is refused at boot) | none | correct as is | None |
| riscv64 `V_REGS_OFFSET` | `core/kernel/src/arch/riscv64/fpu.rs` | 304 | encoding artefact (the F/D registers, `fcsr` and the vector CSRs before `v0` in the save area; the save and restore asm and the area size read it) | none | correct as is | None |
| riscv64 `timebase_freq` check | `core/kernel/src/arch/riscv64/timer.rs` | at most `u32::MAX` Hz | encoding artefact (overflow-free tick math) | none | correct as is | None |

### Kernel: entropy

Every entry here is `correct as is`; none is tracked.

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| Boot hardware-RNG draw cap | `core/kernel/src/entropy/mod.rs` | 512 words | provably unreachable (start-up needs 128) | none | correct as is | None |
| `boot_jitter_scrape` | `core/kernel/src/entropy/mod.rs` | 64 samples | tuning (supplementary source) | none | correct as is | None (#393) |
| Health-test constants (`RCT_CUTOFF`, `APT_WINDOW`, `APT_CUTOFF`, `STARTUP_BYTES`) | `core/kernel/src/entropy/health.rs` | 31 / 512 / 384 / 1024 | hardware spec (NIST SP 800-90B), with `APT_CUTOFF` a stricter tuning than the standard's table | none | correct as is | None |
| Keccak tables, `LANES`, `RATE` | `core/kernel/src/entropy/keccak.rs`, `sponge.rs` | 24, 25, 136 | hardware spec (Keccak-f[1600], SHAKE256) | rodata | correct as is | None |
| `RESEED_DRAW_INTERVAL`, `RESEED_TIME_BUDGET_US`, `RESEED_OVERDUE_FACTOR` | `core/kernel/src/entropy/reseed_policy.rs` | 256 / 1 s / 2 | tuning | none | correct as is | None |
| `RESEED_BYTES`, `CpuRng.guid_seen` | `core/kernel/src/entropy/cpurng.rs` | 32 / 16 | hardware spec (256-bit reseed, 128-bit VMGENID) | per CPU | correct as is | None |
| `ACC_WORDS` | `core/kernel/src/entropy/jitter.rs` | 4 | encoding artefact (256-bit accumulator) | `cpu_count` x 40 B | correct as is | None |
| `SAMPLE` | `core/kernel/src/entropy/selftest.rs` | 32 | encoding artefact (one 256-bit sample) | `cpu_count` x 33 B | correct as is | None |
| `LAST_SEEN` | `core/kernel/src/entropy/vmgenid.rs` | 2 words | hardware spec (128-bit GUID) | 16 B BSS | correct as is | None |

### Syscall ABI

Tracked by [#638](https://github.com/kottlerg/seraph/issues/638); `CAP_INDEX_BITS` and the handle
generation by [#637](https://github.com/kottlerg/seraph/issues/637).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `MSG_CAP_SLOTS_MAX` | `abi/syscall/src/lib.rs` | 4 | encoding artefact (two transfer registers of two `u32` handles each) | 16 B per TCB message | correct as is | Bounds caps per message, not per transfer: every protocol that moves more iterates (`shared/ipc` bootstrap rounds, DONATE rounds); the protocols that do not are tracked in their own sections |
| `MSG_CAP_SLOTS_MAX <= 4` assert | `abi/syscall/src/lib.rs` | compile time | encoding artefact | none | correct as is | Keep |
| `CSPACE_IPC_RECV_RESERVE` | `abi/syscall/src/lib.rs` | `MSG_CAP_SLOTS_MAX` (4) free slots per CSpace | ABI width (one message's caps) | 4 slots per CSpace | correct as is | None: general allocations fail first, receives keep landing caps (#41) |
| `CSPACE_SLOTS_PER_PAGE` | `abi/syscall/src/lib.rs` | 56 | encoding artefact (kernel `L2_SIZE`, asserted equal) | none | correct as is | None |
| `MSG_DATA_WORDS_MAX` | `abi/syscall/src/lib.rs` | 64 | ABI width (IPC buffer layout) | about 550 B per TCB | correct as is | Bulk data moves through Memory caps (#36, #40) |
| IPC buffer layout | `abi/syscall/src/lib.rs` | data words 0..64, count at 64, handles 65..69, in one page | ABI width | 4 KiB per thread | correct as is | None |
| `CAP_INDEX_BITS + 8 <= 32` assert | `abi/syscall/src/lib.rs` | compile time | ABI width | none | correct as is | Keep |
| `EVENT_QUEUE_MAX_CAPACITY` | `abi/syscall/src/lib.rs` | 2^20 entries and observer nodes | per-call bound (one create zeroes the ring and links the nodes in the kernel; the queue is caller-funded) | none | correct as is | More is had with more queues |
| `PRIORITY_MIN`, `PRIORITY_MAX` | `abi/syscall/src/lib.rs` | 1 / 30 | ABI width (32-level mask: 0 idle, 31 reserved) | none | correct as is | None (#215) |
| `MAX_GETRANDOM_LEN` | `abi/syscall/src/lib.rs` | 256 B | per-call bound (callers loop; it bounds the interrupts-off window) | 256 B stack | correct as is | None |
| `CAP_INFO_MEMORY_MAPPINGS_MAX_PAGES` | `abi/syscall/src/lib.rs` | 512 pages per window | batch size (a larger region is read window by window) | none | correct as is | None |
| `encode_exit_code` range | `abi/syscall/src/lib.rs` | 12-bit code below `EXIT_FAULT_BASE` | encoding artefact (flat exit-reason space) | none | correct as is | Saturates; never aliases success |
| `KERNEL_VERSION` packing | `abi/syscall/src/lib.rs` | 32 / 16 / 16 bits | encoding artefact | none | correct as is | None |

### Bootloader and boot ABIs

Tracked by [#640](https://github.com/kottlerg/seraph/issues/640).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `MAX_CPUS` (`BootInfo.cpu_count`) | `abi/boot-protocol/src/lib.rs` | 512 | ABI width (the kernel's CPU-count width: `CpuMask` holds `MAX_CPUS` bits); `cpu_ids` is an array of `cpu_count` ids in its own pages, so `BootInfo` no longer bounds it | `MAX_CPUS`-wide kernel `CpuMask`s | needs a design | Shipping two-socket servers have 768 logical CPUs; the per-boot `CpuMask` width (#640) lifts it |
| `INIT_MAX_SEGMENTS` (`InitImage.segments`) | `abi/boot-protocol/src/lib.rs` | 8 | provably unreachable (the in-tree init has 4 LOAD segments on x86_64; overflow is an error) | 256 B in `BootInfo` | correct as is | None |
| `BOOT_MODULE_NAME_LEN`, `ENTRY_NAME_LEN` | `abi/boot-protocol/src/lib.rs`, `bundle.rs` | 32 | ABI width (bundle wire format) | per module | correct as is | None: tied by a const assert in `core/boot/src/main.rs` |
| `BundleHeader.entry_count` | `abi/boot-protocol/src/bundle.rs` | `u32` | ABI width | none | correct as is | The binding cap is `MAX_BOOT_MODULES` |
| `MAX_IOAPICS` (`KernelMmio.ioapics`) | `abi/boot-protocol/src/lib.rs` | 128 | provably unreachable on real hardware (one or a few I/O APICs per PCI Express root complex, a few dozen on the largest servers); a larger MADT is truncated with a diagnostic | 3 KiB in `BootInfo` | correct as is | None |
| `MAX_MMIO_DIRECT_MAP_REGIONS` | `abi/boot-protocol/src/layout.rs` | `1 + MAX_IOAPICS` (129) on x86_64, 0 on riscv64 | ABI width (derived from `MAX_IOAPICS`) | about 2 KiB stack on x86_64, none on riscv64 | correct as is | None |
| Aperture array (`aperture_capacity`) | `core/boot/src/memory_map.rs` | `2 x` the step 6 descriptor count plus slack, plus the two seed buffers (`2 x MAX_SEEDS_PER_CLASS`) | provable unreachability (every aperture starts at a descriptor base, a seed base, or a clipped descriptor's end; host-tested) | 16 B per entry, reclaimed | correct as is | None: past it (a map grown past the step 6 slack) the highest are dropped with a diagnostic. Each aperture also takes an `InitInfo` descriptor, so a map with more apertures than the descriptor array has room for halts the boot at Phase 7 by name first (the `INIT_INFO_DESCRIPTOR_CAPACITY` row) |
| `MAX_RECLAIM_RANGES` | `abi/boot-protocol/src/lib.rs` | 256 | provably unreachable (the bootloader records at most `MAX_RECLAIM_ENTRIES`, 96: its fixed scratch, the CPU-id pages, one page-table pool and the bundle gaps; const-asserted in `core/boot/src/main.rs`) | one page, reclaimed | correct as is | None |
| `ReclaimRange.page_count` | `abi/boot-protocol/src/lib.rs` | `u32` pages | ABI width (16 B entry) | embedded | correct as is | 16 TiB per range |
| `BootInfo.boot_entropy_seed` | `abi/boot-protocol/src/lib.rs` | 32 B | hardware spec (256-bit seed) | 32 B | correct as is | None |
| `IMAGE_WINDOW_SIZE` | `abi/boot-protocol/src/layout.rs` | 2 GiB | hardware spec (small and medany code-model reach) | none | correct as is | None |
| `INIT_MAX_NAMED_MODULES` (`InitInfo.module_names`) | `abi/init-protocol/src/lib.rs` | 85 | ABI width (equals `MAX_BOOT_MODULES`, const-asserted in the kernel) | 3400 B of the `InitInfo` header | correct as is | None |
| `INIT_MODULE_NAME_LEN` | `abi/init-protocol/src/lib.rs` | 32 | ABI width (equals `BOOT_MODULE_NAME_LEN`) | per name | correct as is | None: tied by a const assert in `core/kernel/src/cap/mod.rs` |
| `INIT_INFO_MAX_PAGES` | `abi/init-protocol/src/lib.rs` | 4 | unknown | none (allocated at actual size) | raise | Phases 7 and 8 halt past its descriptor capacity, 535 (`INIT_INFO_DESCRIPTOR_CAPACITY`) since the header holds the 85-entry module name table; size from the count (#640) |
| `INIT_STACK_PAGES` | `abi/init-protocol/src/lib.rs` | 4 | provably unreachable (init's own stack, whose depth the in-tree init fixes) | 16 KiB | correct as is | None |
| `InitInfo` count and slot fields | `abi/init-protocol/src/lib.rs` | `u32` | ABI width (cap handle) | embedded | correct as is | None |
| `InitInfo` size assert | `abi/init-protocol/src/lib.rs` | the header fits the region's first page | ABI width | none | correct as is | None |
| `MAX_BOOT_MODULES` (`BootInfo.modules`; core/boot `MAX_MODULES`) | `abi/boot-protocol/src/lib.rs` | 85 | static-footprint budget (the `BootModule` entries the one-page module array holds) | 4 KiB stack in core/boot, one page reclaimed | correct as is | None: a larger bundle is refused by name by the bootloader, and the kernel halts by name |
| `MEM_MAP_SLACK_ENTRIES` (`MemoryMapEntry` array) | `core/boot/src/main.rs` | the firmware's descriptor count at step 6 plus 32 | current peak plus headroom (the eight later bootloader allocations add at most 16 descriptors; the other 16 absorb firmware housekeeping, which nothing bounds) | 24 B per descriptor, reclaimed | needs a design | Check the final map's count against the array before `ExitBootServices` and regrow it, which needs the regrown array identity-mapped after step 6; until then a RAM descriptor past the array fails the boot by name, any other is dropped with a diagnostic |
| `KERNEL_STACK_PAGES` (bootloader) | `core/boot/src/main.rs` | 16 (64 KiB) | stack budget, measured (the bound at `HANDOFF_STACK_BYTES`; ktest, both arches): the kernel's boot phases peak in debug at 15304 B on x86_64 at 4, 16 and 128 CPUs, and on riscv64 at 14176 B (16 CPUs), 14160 B (4) and 13856 B (128); in release, measured at 4 CPUs, at 14856 B on x86_64 and 13672 B on riscv64 | 64 KiB plus a 4 KiB guard page | needs a design | Its size is the shared `HANDOFF_STACK_BYTES`; the unmapped guard page below it faults an overflow until Phase 3 rebases the stack into the direct map, which maps the guard frame (#666) |
| `MAX_IDENTITY_REGIONS` | `core/boot/src/main.rs` | 64 | provably unreachable (`MAX_LOAD_SEGMENTS + INIT_MAX_SEGMENTS + 10` = 26 at most) | 1 KiB stack | correct as is | Pin the sum with a const assert |
| `MAX_APERTURE_SEEDS` | `core/boot/src/main.rs` | 256 (`MAX_SEEDS_PER_CLASS`) | current peak plus headroom (a few named windows per interrupt controller, UART, ECAM segment or DTB node) | 4 KiB stack | make pay-as-you-go | Count the seeds before `ExitBootServices` and size the buffer from them; drops are diagnosed |
| `MAX_HEURISTIC_SEEDS` | `core/boot/src/main.rs` | 256 (`MAX_SEEDS_PER_CLASS`) | current peak plus headroom (two windows per MCFG segment) | 4 KiB stack | make pay-as-you-go | As `MAX_APERTURE_SEEDS`; drops are diagnosed |
| `get_memory_map` slack | `core/boot/src/uefi.rs` | 16 descriptors | provably unreachable (only the buffer's own allocation lands between the size query and the fill; overflow fails the boot loudly) | a few hundred bytes | correct as is | None |
| `EXIT_BOOT_SERVICES_MAX_ATTEMPTS` | `core/boot/src/uefi.rs` | 16 | provably unreachable (residual failure odds below 1e-14) | none | correct as is | None |
| `FILE_INFO_BUF_LEN` | `core/boot/src/uefi.rs` | `size_of::<EfiFileInfo>() + 256` | provably unreachable (fixed short ESP file names) | about 350 B stack | correct as is | None |
| `TARGET_FB_WIDTH`, `TARGET_FB_HEIGHT` | `core/boot/src/uefi.rs` | 1280 x 720 | policy (bounds no capacity) | none | correct as is | None |
| `MAX_LOAD_SEGMENTS` (`KernelInfo.segments`) | `core/boot/src/elf.rs` | 8 | provably unreachable (the in-tree kernel has 5 LOAD segments on x86_64; overflow is an error) | embedded | correct as is | None |
| Boot page-table pool (`table_frame_bound`) | `core/boot/src/paging.rs`, `arch/x86_64/paging.rs`, `arch/riscv64/paging.rs` | an upper bound on the boot tables, from the kernel segments, identity regions and trampoline pages they map | provably unreachable (sized from the mappings; a host test checks the bound against the tables the ranges need) | about one frame per 2 MiB of mapped span, reclaimed as one range | correct as is | None |
| dtb `MAX_DEPTH` | `core/boot/src/dtb.rs` | 32 | provably unreachable on real trees (under 8 deep); deeper nodes' properties are skipped with a diagnostic | about 6 KiB stack per walk | correct as is | None |
| dtb `MAX_REG_ENTRIES`, `MAX_IRQ_ENTRIES` | `core/boot/src/dtb.rs` | 8 / 4 | provably unreachable (only a node's first `reg` entry is consumed and no `interrupts` value is; surplus entries are dropped with a diagnostic) | embedded per node | correct as is | None |
| dtb PCI `ranges` (`Fdt::pci_ranges`) | `core/boot/src/dtb.rs` | none: a node records where its `ranges` lies and the entries are read from the blob | provable unreachability (no bound) | 8 B per node | correct as is | None |
| `cpu_ids` array (`cpu_id_capacity`) | `core/boot/src/firmware.rs` | the firmware table's enabled CPU entries plus one, at most `MAX_CPUS` | ABI width (`MAX_CPUS`) | 4 B per CPU, reclaimed | correct as is | None: past `MAX_CPUS` the surplus is dropped with a diagnostic; follows `MAX_CPUS` |

### Process layout and ruststd

Tracked by [#641](https://github.com/kottlerg/seraph/issues/641).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `LAYOUT_VA_CEILING` | `shared/process-layout/src/lib.rs` | `1 << 38` | hardware spec (Sv39 user half), for the fixed tier only: the surfaces a creator places without knowing the paging mode; the heap and arena zones follow the user half | none | correct as is | None |
| `IMAGE_MAX_SPAN` | `shared/process-layout/src/lib.rs` | 28 GiB, derived (`FIXED_IMAGE_ZONE_END` less the image window's end); procmgr's children get `image_max_span` of their user half's image zone (`H/8` less the window's end) | encoding artefact (fixed-tier zone map) | none | correct as is | None |
| Window `slots_log2` values | `shared/process-layout/src/lib.rs` | 21, 23 | encoding artefact (ASLR budget under the ceiling) | none | correct as is | None |
| `MAX_WINDOW_REGION_PAGES` | `shared/process-layout/src/lib.rs` | `1 << 18` (1 GiB) | encoding artefact (the 9 GiB stride less the 8 GiB draw span) | none | correct as is | None; const asserts pin the stack reservation and the main TLS block to it |
| Heap zone (`growth_zones`) | `shared/process-layout/src/lib.rs` | Sv39: base window `[1 GiB, 3 GiB)`, 60 GiB span; user half `H` above 2^38: `H/4` span (32 TiB at 2^47) | hardware spec (user half) | none (VA only) | correct as is | None |
| Arena zone (`growth_zones`) | `shared/process-layout/src/lib.rs` | Sv39: base window `[64 GiB, 96 GiB)`, 32 GiB span; user half `H` above 2^38: `H/4` span | hardware spec (user half) | none (VA only) | correct as is | None |
| Zone-map asserts | `shared/process-layout/src/lib.rs` | stride chain, defaults, fixed image zone, and the growth zones under every supported paging mode | encoding artefact | none | correct as is | Keep |
| `LAYOUT_ENTROPY_BYTES` | `shared/process-layout/src/lib.rs` | 32 | provably unreachable (exactly four surfaces) | none | correct as is | None |
| `DEFAULT_PROCESS_STACK_PAGES` | `abi/process-abi/src/lib.rs` | 8 | default (per-binary override exists) | 32 KiB per process | correct as is | None |
| `MAX_PROCESS_STACK_PAGES` | `abi/process-abi/src/lib.rs` | `(1 << 18) - 1` (just under 1 GiB) | encoding artefact (the window region tail less the guard page) | none (VA only; loaders map the declared stack) | correct as is | None; loaders refuse a larger note |
| `PROCESS_MAIN_TLS_MAX_PAGES` | `abi/process-abi/src/lib.rs` | `1 << 18` (1 GiB) | encoding artefact (the TLS window's region tail) | none (loaders map the `PT_TLS` size) | correct as is | None |
| `ProcessInfo` page (argv and env blobs share it) | `abi/process-abi/src/lib.rs` | 4096 B less the struct | BSS budget (one page) | 4 KiB per process | needs a design | See the argv entries in the procmgr section (#672) |
| `ProcessInfo.initial_priority` | `abi/process-abi/src/lib.rs` | `u8` | ABI width (`PRIORITY_MAX` 30) | none | correct as is | None |
| `ProcessInfo` cap fields | `abi/process-abi/src/lib.rs` | `u32` | ABI width (cap handle) | embedded | correct as is | Follows the handle-width decision (#637) |
| Growth-zone window `slots_log2` | `shared/process-layout/src/lib.rs` | Sv39: 19 (heap), 23 (arena); user half `H` above 2^38: `log2(H) - 18` | encoding artefact (ASLR window) | none | correct as is | None |
| `HEAP_INITIAL_PAGES` | `runtime/ruststd/src/sys/alloc/seraph.rs` | 512 (2 MiB) | default (a floor that avoids early grows) | demand-paged process: VA, and frames as the allocator hands them out; pinned process: 2 MiB eager | correct as is | None |
| `GROW_MIN_PAGES` | `runtime/ruststd/src/sys/alloc/seraph.rs` | 16 | tuning | none | correct as is | None |
| `MAX_ROUNDS` (`grow_exact`) | `runtime/ruststd/src/sys/alloc/seraph.rs` | 16 | tuning (anti-wedge bound; a partial grant takes another round, so one grow spans up to 64 runs and keeps what it mapped past that) | none | correct as is | None |
| `PT_FUND_ROUNDS` | `runtime/ruststd/src/sys/alloc/seraph.rs` | 2 | provably unreachable (record-page argument) | none | correct as is | None |
| `CSPACE_FUND_ROUNDS` | `runtime/ruststd/src/sys/alloc/seraph.rs` | 2 | provably unreachable (record-page argument) | none | correct as is | None |
| `SLAB_SHELF_SIZE` | `runtime/ruststd/src/sys/alloc/seraph.rs` | 4 | tuning (overflow strands a run until exit, bounded) | 192 B static | correct as is | None |
| `ALLOCATOR_METADATA_RESERVE` | `runtime/ruststd/src/sys/alloc/seraph.rs` | 64 | tuning (slack) | none | correct as is | None |
| reserve `INLINE_RUNS` (`Arena.inline`) | `runtime/ruststd/src/sys/reserve/seraph.rs` | 64 | tuning (the static run table before it grows into the byte heap) | 1 KiB static | correct as is | None; a process without a heap fails its 64th live reservation instead of losing freed VA |
| `REAPER_SLOTS` (`Registry.slots`) | `runtime/ruststd/src/sys/thread/seraph.rs` | 64 | unknown | about 6 KiB static | make pay-as-you-go | Detached threads past 64 leak until exit |
| thread `EQ_CAPACITY` | `runtime/ruststd/src/sys/thread/seraph.rs` | 128 | unknown | about 2.1 KiB retype | raise | Overflow drops death posts |
| `GEN_BITS` correlator | `runtime/ruststd/src/sys/thread/seraph.rs` | 26-bit generation, 6-bit slot | encoding artefact (packed in 32 bits of the `u64` correlator) | none | correct as is | Freshness-only; pin `REAPER_SLOTS` against it with a const assert |
| `DEFAULT_DEMAND_STACK_PAGES` | `runtime/ruststd/src/sys/thread/seraph.rs` | 512 (2 MiB) | default (VA only, lazy) | none | correct as is | Multiplies against the reserve arena (#46) |
| `GUARD_PAGES` | `runtime/ruststd/src/sys/thread/seraph.rs` | 1 | default (inline stack probes, #503, touch every page of a larger frame) | VA only | correct as is | None |
| `DEFAULT_MIN_STACK_SIZE` | `runtime/ruststd/src/sys/thread/seraph.rs` | 64 KiB | default (matches the upstream platform layer) | eager on the fallback path | correct as is | None |
| `SystemInfoType::ThreadRetypeBytes` | `abi/syscall/src/lib.rs` | the kernel's Thread slot (`thread_slot_bytes`), six pages or more | encoding artefact (the kernel's `dispatch_for(Thread)`: kernel stack, TCB page, extended-state pages, read at boot) | one slot per thread | correct as is | None |
| `DEATH_EQ_CAPACITY` (process) | `runtime/ruststd/src/sys/process/seraph.rs` | 4 | provably unreachable (four post sources, each posting at most once per child) | about 168 B per child | correct as is | None |
| `DEATH_EQ_OBSERVERS` (process) | `runtime/ruststd/src/sys/process/seraph.rs` | 2 nodes | provably unreachable (the main-thread bind and procmgr's relay bind) | 48 B per child | correct as is | None |
| `Process::id` | `runtime/ruststd/src/sys/process/seraph.rs` | `u32` | ABI width (upstream `Child::id` is `u32`) | none | correct as is | None |
| pipe `RING_CAPACITY` | `runtime/ruststd/src/sys/pipe/seraph.rs` | 2048 | encoding artefact (largest power of two in one page after the header) | 4 KiB per direction | correct as is | None |
| `STDIN_BUF_SIZE` | `runtime/ruststd/src/sys/stdio/seraph.rs` | 512 | streaming chunk (a longer read refills from the stdin pipe) | 512 B | correct as is | None |
| `READ_INLINE_THRESHOLD`, `WRITE_INLINE_THRESHOLD` | `runtime/ruststd/src/sys/fs/seraph.rs` | 504 | ABI width (`MSG_DATA_WORDS_MAX`) | none | correct as is | Larger transfers use frames (#87) |
| Rename name-sum limit | `runtime/ruststd/src/sys/fs/seraph.rs` | 496 B | ABI width (`MSG_DATA_WORDS_MAX`) | none | correct as is | None (#89) |
| Path component limit | `runtime/ruststd/src/sys/fs/seraph.rs` | 255 (`MAX_NAME_LEN`) | ABI width (namespace protocol) | none | correct as is | None |
| `READ_WAIT` | `runtime/ruststd/src/sys/fs/release_handler.rs` | 100 ms | ABI width (the driver's cooperative-release window) | none | correct as is | None |
| `RESOLVE_WAIT_US` | `runtime/ruststd/src/sys/time/seraph.rs` | 100 ms | tuning (many registry round trips, on the kernel's clock) | none | correct as is | None |
| `Mutex::spin` count | `runtime/ruststd/src/sys/sync/mutex/seraph.rs` | 100 | tuning (a backoff before parking) | none | correct as is | None |
| `MAX_READERS` | `runtime/ruststd/src/sys/sync/rwlock/seraph.rs` | `2^30 - 2` | provably unreachable short of leaked guards (more than any thread count; past it readers wait) | 4 B per lock | correct as is | None |

### Shared IPC and protocol crates

Tracked by [#672](https://github.com/kottlerg/seraph/issues/672) (argv) and
[#645](https://github.com/kottlerg/seraph/issues/645) (log).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `ARGS_BLOB_MAX` | `shared/ipc/src/lib.rs` | 256 B | current peak plus headroom; inline in one message | none | needs a design | argv and env through a Memory cap (#672) |
| CREATE_FROM_FILE `args_bytes`, `env_bytes` | `shared/ipc/src/lib.rs` | `u16` | encoding artefact (label bit packing) | none | needs a design | Widen with the blob design (#672) |
| CREATE_FROM_FILE `args_count`, `env_count` | `shared/ipc/src/lib.rs` | `u8` | encoding artefact (label bit packing) | none | needs a design | Unreachable at 256 B blobs; binds once blobs grow |
| `MAX_PATH_LEN` | `shared/ipc/src/lib.rs` | 4096 | provably unreachable (recipe paths in the tree are tens of bytes; no message carries a whole path, and svcmgr stores each at its length) | none | correct as is | None: svcmgr's one recipe path limit, the POSIX `PATH_MAX` value |
| `svcmgr_labels::NAME_MAX`, `NAME_WORDS` | `shared/ipc/src/lib.rs` | 64 B / 8 words | encoding artefact (a name beside the label and round header fits one message; longest name in use 15 B) | none | correct as is | None: the one svcmgr name limit, which the registry, its client, svcmgr, its parser and init's endowment share with the `pack_name` codec |
| `QUERY_LIVE_PROCESSES` page | `shared/ipc/src/lib.rs` (`LIVE_PROCESSES_PAGE`) | `MSG_DATA_WORDS_MAX - 1` = 63 badges | per-message bound (the caller pages on) | none | correct as is | None |
| `CREATE_SCHED_FIELD_MASK` | `shared/ipc/src/lib.rs` | 5 bits | ABI width (32 priority levels) | none | correct as is | None |
| `BASELINE_PRIORITY_MAX`, `DEVMGR_BAND_MAX` | `shared/ipc/src/lib.rs` | 28 / 26 | encoding artefact (policy placement in 32 levels) | none | correct as is | None |
| `INIT_REAP_CORRELATOR`, per-child correlator | `shared/ipc/src/lib.rs` | `u64::MAX`; the full process badge | ABI width (the kernel correlator is `u64`; the sentinel carries every verb bit, so no minted badge equals it) | none | correct as is | None |
| `memmgr_grant_layout` caps per reply | `shared/ipc/src/lib.rs` | `MSG_CAP_SLOTS_MAX` | ABI width (4 caps per reply); a request spread over more runs gets a partial grant the caller requests again | none | correct as is | None |
| phys-table index constants (`FACTS_*`, `IN_USE_*`) | `shared/ipc/src/lib.rs` | 0 to 3 | encoding artefact (one-page layout) | none | correct as is | None |
| `MAX_IN_USE`, `IN_USE_WORDS` | `shared/ipc/src/lib.rs` | 4 / 3 | provably unreachable (three tier-1 producers; the page fit is const-asserted) | none | correct as is | None |
| svcmgr and namespace label name lengths | `shared/ipc/src/lib.rs` | 16-bit fields | encoding artefact | none | correct as is | The binding limits are the name constants |
| FS_WRITE, FS_READ inline payloads | `shared/ipc/src/lib.rs` | 504 B per call | ABI width (`MSG_DATA_WORDS_MAX`) | none | correct as is | Large transfers use the memory verbs (#87) |
| FS_READ_MEMORY, FS_WRITE_MEMORY | `shared/ipc/src/lib.rs` | one page per call | encoding artefact (one slot cap per reply) | none | correct as is | Callers iterate; batching is a throughput question (#229) |
| FS_READ_MEMORY release cookie | `shared/ipc/src/lib.rs` | `u64`, client-chosen | ABI width | none | correct as is | None (#530) |
| QUERY_DEVICE_INFO badge | `shared/ipc/src/lib.rs` | `u64` | encoding artefact (catalog index plus one, never recycled) | none | correct as is | None |
| `blk_labels` partition badges | `shared/ipc/src/lib.rs` | `u64`, one per distinct registered range | ABI width | none | correct as is | None |
| `INVALID_MEMORY_CAP` byte limit | `shared/ipc/src/lib.rs` | `count * block_size <= u32::MAX` | hardware spec (VirtIO descriptor `u32` length) | none | correct as is | 4 GiB per request |
| serial, framebuffer and stream byte counts | `shared/ipc/src/lib.rs` | 512 B per call | ABI width (`MSG_DATA_WORDS_MAX * 8`) | none | correct as is | Callers iterate |
| `INPUT_MAX_EVENTS_PER_READ` | `shared/ipc/src/lib.rs` | 32 | per-message bound (readers loop) | 256 B stack | correct as is | Could use 63 words at no cost |
| `keysym::pack_event` widths | `shared/ipc/src/lib.rs` | 32 / 31 bits | encoding artefact (one word per event) | none | correct as is | None |
| `VERB_BIT_MASK` | `shared/ipc/src/lib.rs` | bits 59..63 | encoding artefact (badge high bits) | none | correct as is | None (#76) |
| `LOG_BADGE_FIRST_CHILD` | `shared/ipc/src/lib.rs` | 16 | encoding artefact (reserved specials) | none | correct as is | None |
| `IpcMessage.data`, `cap_slots` | `shared/ipc/src/lib.rs` | `MSG_DATA_WORDS_MAX`, `MSG_CAP_SLOTS_MAX` | ABI width | about 552 B per message on the stack | correct as is | None |
| `IpcMessage.data_len`, `cap_count` | `shared/ipc/src/lib.rs` | `u8` | provably unreachable (at most 64 and 4) | 2 B | correct as is | Pin both against `u8::MAX` with a const assert |
| `from_ipc_buf` layout bound | `shared/ipc/src/lib.rs` | 69 words of 512 | ABI width | none | correct as is | Turn the comment into a const assert |
| bootstrap reply-label fields | `shared/ipc/src/bootstrap.rs` | 8-bit base, caps, words | encoding artefact | none | correct as is | Pin against the ABI maxima |
| `BootstrapRound.caps`, `data` | `shared/ipc/src/bootstrap.rs` | `[u32; 4]`, `[u64; 64]` | ABI width | about 560 B stack | correct as is | None |
| `PackedSlots.presence` | `shared/ipc/src/bootstrap.rs` | `u64` mask | ABI width (`MSG_CAP_SLOTS_MAX <= 64`) | none | correct as is | Pin with a const assert |
| `SlotAccumulator<N>.slots` | `shared/ipc/src/bootstrap.rs` | caller's `N` | per-instance | `4 * N` B | correct as is | None |
| `request_slots` round loop | `shared/ipc/src/bootstrap.rs` | unbounded until DONE | provably unreachable (the creator is trusted) | none | correct as is | None |
| `RECV_FAILURE_FATAL_STREAK`, `RECV_FAILURE_BACKOFF_CAP_MS`, `RecvGuard.streak` | `shared/ipc/src/recv_guard.rs` | 32 / 128 ms / `u32` | tuning (bounds no capacity) | 4 B | correct as is | None |
| `registry::NAME_MAX` | `shared/registry/src/lib.rs` | `svcmgr_labels::NAME_MAX` (64) | the shared svcmgr name limit | per entry | correct as is | None |
| `Registry.entries` | `shared/registry/src/lib.rs` | heap `Vec`, one entry per published name | per-instance (a publish fails only when the heap cannot grow it) | none | correct as is | None |
| `Entry.name_len`, `Entry.cap` | `shared/registry/src/lib.rs` | `u8`, `u32` | ABI width (cap handle); length unreachable | 5 B per entry | correct as is | None |
| `registry-client` `NAME_MAX`, `NAME_WORDS` | `shared/registry-client/src/lib.rs` | re-export of `svcmgr_labels::NAME_MAX` / `NAME_WORDS` | the shared svcmgr name limit | 64 B stack | correct as is | None |
| `REGISTRY_CAP`, `BADGEED_CAP` | `shared/registry-client`, `shared/log` | `AtomicU32` | ABI width (cap handle) | 4 B | correct as is | None (#74) |
| log `CHUNK_SIZE` | `shared/log/src/lib.rs` | 512 | ABI width (`MSG_DATA_WORDS_MAX * 8`) | none | correct as is | None |
| log `STACK_BUF_LEN` | `shared/log/src/lib.rs` | 512 | ABI width (one `STREAM_BYTES` payload; a longer message is sent in chunks as the buffer fills) | 512 B stack per call | correct as is | None |
| `SharedBuffer.page_count` | `shared/shmem/src/lib.rs` | `u64` | ABI width (`mem_map` page count) | 8 B | correct as is | None |
| `SpscHeader.head`, `tail` | `shared/shmem/src/lib.rs` | `u32`, free-running | provably unreachable (modular index, correct across wrap for capacity up to 2^31) | 16 B per ring | correct as is | None |
| `SpscHeader.capacity` | `shared/shmem/src/lib.rs` | `u32` power of two | ABI width (shared header layout) | none | correct as is | None |
| `MAX_NAME_LEN` (`EntryName`) | `shared/namespace-protocol/src/name.rs` | 255 | ABI width (`u8` length; the POSIX `NAME_MAX` convention) | 255 B per name | correct as is | None |
| `MIN_NAME_LEN` | `shared/namespace-protocol/src/name.rs` | 1 | encoding artefact (an empty name is meaningless) | none | correct as is | None |
| `NODE_ID_BITS` | `shared/namespace-protocol/src/badge.rs` | 40 | encoding artefact (40 node plus 24 rights bits in a `u64` badge) | none | correct as is | Safe while backends never recycle a live `NodeId` (#27) |
| `RIGHTS_BITS` | `shared/namespace-protocol/src/rights.rs` | 24 | encoding artefact | none | correct as is | None |
| readdir index, `nth_visible_entry` | `shared/namespace-protocol/src/lib.rs` | `u32` | provably unreachable (no directory holds 2^32 entries) | none | correct as is | None |
| `MemoryReply.bytes_valid`, `memory_data_offset` | `shared/namespace-protocol/src/lib.rs` | `u32` | provably unreachable (at most a page) | none | correct as is | None |
| ns-client component bound | `shared/ns-client/src/lib.rs` | literal 255 | copy of `MAX_NAME_LEN` | none | correct as is | Import the constant |
| ns-client `hop_count` | `shared/ns-client/src/lib.rs` | unbounded `usize` | provably unreachable (bounded by the path length) | none | correct as is | None |
| `cap_revoke_all` `MAX_RETRIES` | `shared/syscall/src/lib.rs` | 4096 | provably unreachable (only an adversarial deriver exhausts it) | none | correct as is | None |
| syscall wrapper argument widths | `shared/syscall/src/lib.rs` | `u32`, `u16`, `u8` | ABI width (syscall ABI) | none | correct as is | None |
| `MAX_RELA_TABLE_SIZE` | `shared/elf/src/lib.rs` | 4 MiB, applied only by the kernel to init's table | provably unreachable (init is an in-tree binary with a few thousand relocations; its table size arrives from the bootloader) | none | correct as is | None: the table locators bound a table by its `PT_LOAD` file data and the file instead |
| `MAX_STREAMING_DYNAMIC`, `MAX_STREAMING_STRTAB`, `MAX_STREAMING_NOTE` | `shared/elf/src/lib.rs` | 4096 / 4096 / 64 | provably unreachable (lld output is far smaller; only fixed sections) | stack | correct as is | None |
| `Elf64Ehdr.e_phnum`, `e_shnum` | `shared/elf/src/lib.rs` | `u16` | hardware spec (ELF64 header) | none | correct as is | None |
| ed25519 `MSG_SCRATCH` | `shared/crypto/src/ed25519.rs` | 1024 | provably unreachable (largest RFC 8032 vector 1023 B) | 2 KiB stack | correct as is | None |
| `Sha512.total_len` | `shared/crypto/src/sha512.rs` | `u128` | hardware spec (FIPS 180-4 length field) | 16 B | correct as is | None |
| `FONT_9X20` | `shared/font/src/lib.rs` | 256 glyphs | hardware spec (CP437) | 10 KiB rodata | correct as is | None |
| `FONT_9X20_EXT_COUNT` | `shared/font/src/lib.rs` | 20 | encoding artefact (code points the tree renders) | 800 B rodata | correct as is | Pin the map against the count |
| `Utf8Decoder.buf` | `shared/text/src/utf8.rs` | 4 B | hardware spec (UTF-8 sequence length) | 5 B | correct as is | None |
| `ANSI_RGB` | `shared/ansi/src/lib.rs` | 16 colours | feature scope (16-colour SGR baseline; bounds no capacity) | 48 B rodata | correct as is | 256-colour and RGB SGR are feature work, not a limit |
| `AnsiParser.acc` | `shared/ansi/src/lib.rs` | `u16`, saturating | provably unreachable (SGR codes below 256) | 2 B | correct as is | None |

### memmgr

Every entry here is `correct as is`; none is tracked.

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| process table (`ProcessIndex`, `Node::Process`) | `services/memmgr/free-pool/src/index.rs` | arena-backed records, linear-hash badge index | provably unreachable (no constant: records are arena nodes, grown from the pool) | none | correct as is | None |
| `PROCESS_INDEX_VA`, `PROCESS_INDEX_END` | `services/memmgr/src/main.rs` | 1 GiB bucket window (2^27 buckets) | tuning (past it buckets stop splitting and chains lengthen; bounds no capacity) | none | correct as is | None |
| `MAX_LOAD` | `services/memmgr/free-pool/src/index.rs` | 2 | tuning (mean chain length before a split) | none | correct as is | None |
| Arena node index (`NodeIdx`, `NODE_NULL`) | `services/memmgr/free-pool/src/arena.rs` | `u64`, sentinel `u64::MAX` | provably unreachable (2^64 slots exceed any address space) | 8 B per link | correct as is | None |
| `META_ARENA_LOW_END`, `META_ARENA_HIGH_BASE`, `META_ARENA_HIGH_END` | `services/memmgr/src/main.rs` | low zone to `MAIN_TLS_WINDOW.base` (about 115 GiB of VA), high zone from 2^38 to the boot's user-half top | hardware spec (the paging mode's user half) | none | correct as is | None |
| `META_ARENA_SLOTS_LOG2`, `PHYS_TABLE_TEMP_SLOTS_LOG2` | `services/memmgr/src/main.rs` | 21 | encoding artefact (ASLR window, asserted) | none | correct as is | None |
| zone-map assert | `services/memmgr/src/main.rs` | compile time | encoding artefact | none | correct as is | None |
| `SLOTS_PER_PAGE`, `SLOT_SIZE` | `services/memmgr/free-pool/src/arena.rs` | `PAGE_SIZE / size_of::<Slot>()` | encoding artefact (no slot straddles a page) | none | correct as is | None |
| free pool (`FreePool`, `Node::Run`) | `services/memmgr/free-pool/src/pool.rs` | arena-backed runs sorted by physical base | provably unreachable (no constant: runs are arena nodes, grown from the pool) | none | correct as is | None |
| `DEMAND_CHUNK_PAGES` | `services/memmgr/free-pool/src/lib.rs` | 16 | tuning (fault-around window) | none | correct as is | Adaptive window is #236 |
| `FreeRun.page_count` | `services/memmgr/free-pool/src/lib.rs` | `u64` pages | provably unreachable (2^64 pages exceed any physical address space) | embedded | correct as is | None |
| `FrameDesc.page_count`, REQUEST_MEMORY_CAPS `want_pages` | `services/memmgr/free-pool/src/arena.rs`, `services/memmgr/src/main.rs` | `u32` pages per grant | encoding artefact (wire packs a request's pages in 32 bits) | none | correct as is | Callers loop |
| `MAX_GRANT_RUNS` (`Grant`) | `services/memmgr/free-pool/src/pool.rs` | `MSG_CAP_SLOTS_MAX` | ABI width | 64 B stack | correct as is | None: a grant over more runs is partial and the caller loops |
| `MEMMGR_FORWARD_HEADROOM`, `INIT_FORWARD_HEADROOM` | `services/init/src/bootstrap.rs` | 512 slots each, in memmgr's and init's `CSpace` | tuning (caps past either reach memmgr at init's reap) | none | correct as is | None |
| `ARENA_RETURN_RESERVE` | `services/memmgr/src/main.rs` | 1 slot | tuning (held back from every other allocation, so the arena grows first; spent only when growth is ruled out; a further last-resort return then leaves one run out of circulation) | one arena slot | correct as is | None |
| `InitBootstrap.in_use` | `services/memmgr/src/main.rs` | `MAX_IN_USE` = 4 | provably unreachable (three tier-1 producers) | 96 B stack | correct as is | None |
| process badges | `services/memmgr/src/main.rs` | random `u64` | ABI width | none | correct as is | None |
| `POOL_TOTAL_PAGES` | `services/memmgr/src/main.rs` | `u64`, saturating | ABI width | 8 B | correct as is | None |
| memmgr CSpace slots | `services/init/src/main.rs` (`CSPACE_RETYPE_PAGES`) | 8231-slot seed, self-augmented from memmgr's pool | refillable seed (augment) | 149 pages | correct as is | None (#642, #41) |
| memmgr page tables | `services/init/src/main.rs` (`ASPACE_RETYPE_PAGES`) | 48-page seed, self-augmented from memmgr's pool | refillable seed (augment) | 48 pages | correct as is | None |
| `ASPACE_TOPUP_PAGES`, `PT_FUND_ROUNDS` | `services/memmgr/src/main.rs` | 4 pages / 4 rounds | tuning (page-table top-up step and retries per map) | none | correct as is | None |
| `CSPACE_LOW_WATER`, `CSPACE_TOPUP_PAGES` | `services/memmgr/src/main.rs` | 256 slots / 16 pages | tuning (headroom over a burst of grants) | none | correct as is | None |

### procmgr

Tracked by [#672](https://github.com/kottlerg/seraph/issues/672) (argv) and
[#666](https://github.com/kottlerg/seraph/issues/666) (address-space fault read-back).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `ProcessTable.entries` | `services/procmgr/process-table/src/lib.rs` | heap `Vec` sorted by badge | per-instance (the table fails only when the heap cannot grow it) | none | correct as is | None |
| `DEATH_EQ_CAPACITY` | `services/procmgr/src/death_queues.rs` | 256 per death queue | tuning (a drain of a full queue's worth rescans every live entry's main-thread state, recovering any dropped main-thread post) | about 4.1 KiB per queue | needs a design | A dropped address-space terminal-fault post (a worker thread's fault) is not recovered: no kernel state reports an address space's terminal fault (#666) |
| `FIRST_POOL_OBSERVERS` (`DeathQueues`) | `services/procmgr/process-table/src/death_queues.rs`, `services/procmgr/src/death_queues.rs` | 64 nodes in the first queue, each further queue twice the last up to `EVENT_QUEUE_MAX_CAPACITY`; a refused grant retried at half, down to 64; at most 1023 queues (the wait set's) | per-call bound (two nodes per live process; each further queue is one contiguous memmgr grant, about 24 MiB at the kernel maximum; 1023 queues at normal growth hold far past twice the about 1 M children procmgr's `CSpace` holds; a slab request is the class-rounded size plus a page, so the first pool's is three pages, and RAM that refuses every request above that stops the main wait set at 256 members (a 512-member set is a five-page request) and leaves 255 queues, the later ones of 128 nodes, about 16 K live processes: the set's floor, not a cap a system meets, since such RAM refuses each spawn's own contiguous grants, a 48-page `AddressSpace` among them, first) | 1.5 KiB of nodes up front; a further queue only when every pool is out | correct as is | Hoist `DeathQueues` into the runtime with svcmgr's copy (#677) |
| `FIRST_WAIT_SET_MEMBERS` (procmgr main wait set, `DeathSet`) | `services/procmgr/process-table/src/death_queues.rs`, `services/procmgr/src/death_queues.rs` | 2 members first (the service endpoint and the first queue), doubled and migrated when the queues fill it, up to `WAIT_SET_MAX_MEMBERS` (1024) | per-call bound (one wait set; the 1024-member one is an eight-page request; a replaced sub-page set's bytes return to the runtime's pooled object-slab page, and a page-sized set's (32 members or more) dedicated grant to memmgr through `std::os::seraph::object_slab_release`) | 120 B up front | correct as is | None |
| `DmaHolds.held` | `services/procmgr/process-table/src/dma_holds.rs` | heap `Vec`, one record per torn-down `CREATE_DMA_HOLD` child of any creator that has not been released (one whose creator never releases it, or dies first, stays for the boot); the room for each is reserved when its create arms the hold | per-instance (one record per held child; a creator that holds its children back pins no more memory than keeping them alive would, plus 24 B each; a create the heap cannot reserve the room for fails with `OUT_OF_MEMORY`, so no teardown frees a held child's frames for want of a record; today only devmgr's `VirtIO` drivers, one per device, and svctest's fixtures set the flag) | 24 B reserved per armed child | correct as is | None |
| `RECENT_EXIT_RETENTION_NS` (`RecentExits.ring`) | `services/procmgr/process-table/src/lib.rs` | 30 s, heap deque | tuning (a time bound; the ring is the death rate times the window) | none up front | correct as is | None |
| death correlator | `services/procmgr/src/process.rs` (`finalize_creation`) | the full `u64` process badge | ABI width (`SYS_THREAD_BIND_NOTIFICATION`'s `u64` correlator) | none | correct as is | None |
| `dispatch_death` exit reason | `services/procmgr/src/main.rs` | full `u64` (`DeathEvent.exit_reason`, kept whole by `RecentExits::record` and the forward to logd) | ABI width | none | correct as is | None |
| `CreateBlobs.args_buf`, `env_buf` | `services/procmgr/process-table/src/create_blobs.rs` | 256 B each | encoding artefact (one message) | about 530 B stack | needs a design | argv and env through a Memory cap (#672) |
| blob counts and lengths | `services/procmgr/process-table/src/create_blobs.rs` | `u8`, `u16` | encoding artefact | none | needs a design | Follows the blob design (#672) |
| `VFS_CHUNK_SIZE` | `services/procmgr/src/process.rs` | 504 | ABI width (`MSG_DATA_WORDS_MAX - 1` words) | none | correct as is | Derive from the ABI constant |
| `RELA_CHUNK_RECORDS` | `services/procmgr/src/process.rs` | 128 | batch size (streaming chunk) | 3 KiB stack | correct as is | None |
| `MAX_PROCESS_STACK_PAGES` check | `services/procmgr/src/process.rs` | notes outside `1..=MAX_PROCESS_STACK_PAGES` refused | see the process-layout section | none | correct as is | None |
| `thread_retype_pages` | `services/procmgr/src/main.rs` | `SystemInfoType::ThreadRetypeBytes` in pages, queried once and cached | encoding artefact (kernel stack, TCB and save-area pages) | none | correct as is | None |
| `ASPACE_RETYPE_PAGES`, `CSPACE_RETYPE_PAGES` (per child) | `services/procmgr/src/main.rs` | 48 / 7 | refillable seed (augment) | per child | correct as is | None |
| `CSPACE_LOW_WATER`, `CSPACE_TOPUP_SLOTS` | `services/procmgr/src/main.rs` | 256 / 1024 slots | tuning (headroom over a burst of spawns) | none | correct as is | None |
| `INIT_THREADS`, `FIRST_ROUND_CAPS` | `services/procmgr/process-table/src/init_reap.rs` | 2 / 4 | provably unreachable (fixed init protocol) | none | correct as is | None |
| DONATE round size | `services/procmgr/src/init_reap.rs` | `MSG_CAP_SLOTS_MAX` | ABI width | none | correct as is | Loops over every cap |
| `PROBE_SETTLE_BUDGET_NS` | `services/procmgr/src/init_reap.rs` | 500 ms of wall-clock time, a yield between reads | tuning (bounds no capacity; time-based, so load does not shorten it) | none | correct as is | None |
| memory cookie, process badge | `services/procmgr/src/process.rs` | random `u64` | ABI width | none | correct as is | None |

### svcmgr and registry

Tracked by [#672](https://github.com/kottlerg/seraph/issues/672) (argv).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `ServiceTable.services`, `recipes` | `services/svcmgr/src/definitions/reconcile.rs` | heap `Vec`s, one slot per supervised service, never reused | per-instance (the tables fail only when the heap cannot grow them) | none | correct as is | None |
| `SvcmgrState.registry` | `services/svcmgr/src/main.rs` | growable `Registry` | per-instance | none | correct as is | None (#75) |
| `SvcmgrState.pending` | `services/svcmgr/src/main.rs` | heap `Vec`, one per substrate round | per-instance | none | correct as is | None |
| `DEATHS_EQ_CAPACITY` | `services/svcmgr/src/death_queues.rs` | 64 per death queue | tuning (a drain of a full queue's worth rescans every active service's thread state) | about 1.1 KiB per queue | correct as is | None |
| `FIRST_POOL_OBSERVERS` (`DeathQueues`) | `services/svcmgr/src/death_queues.rs`, `services/svcmgr/svc-defs/src/death_queues.rs` | 4 nodes in the first queue, each further queue twice the last up to `EVENT_QUEUE_MAX_CAPACITY`; a refused grant retried at half, down to 4; at most 1023 queues (the wait set's) | per-call bound (one node per supervised service, plus restarts in flight; each further queue is one contiguous memmgr grant; 1023 queues at normal growth hold far more nodes than the 3.6 M slots svcmgr's `CSpace` holds; the first pool's request is two pages, and RAM that refuses every request above that stops the main wait set at 128 members and leaves 127 queues, the later ones of 64 nodes, about 8 K services: the set's floor, not a cap a system meets, since such RAM refuses each launch's own contiguous spawn grants first) | 96 B of nodes up front; a further queue only when every pool is out (every boot's seven supervised and adopted services grow the set) | correct as is | Hoist `DeathQueues` into the runtime with procmgr's copy (#677) |
| `FIRST_WAIT_SET_MEMBERS` (svcmgr main wait set, `DeathSet`) | `services/svcmgr/svc-defs/src/death_queues.rs`, `services/svcmgr/src/death_queues.rs` | 2 members first, doubled and migrated when the queues fill it, up to `WAIT_SET_MAX_MEMBERS` (1024); every boot widens it | per-call bound (one wait set; the 1024-member one is an eight-page request; a replaced sub-page set's bytes return to the runtime's pooled object-slab page, and a page-sized set's (32 members or more) dedicated grant to memmgr through `std::os::seraph::object_slab_release`) | 120 B up front | correct as is | None |
| `RESTART_BURST`, `RESTART_WINDOW_NS` (`RestartBudget`) | `services/svcmgr/svc-defs/src/restart_budget.rs` | 3 restarts per 60 s window | tuning (stops a crash loop; a rarer crash always restarts) | 16 B per service | correct as is | None (#262 for clean cap-holder restart) |
| `ServiceEntry.vfs_path`, `ns_subtree_path` | `services/svcmgr/src/service.rs` | heap strings, at most `MAX_PATH_LEN` (4096) | the shared recipe path limit | their length | correct as is | None |
| `ServiceEntry.name`, `PendingRegistration.name` | `services/svcmgr/src/service.rs` | heap strings, at most `svcmgr_labels::NAME_MAX` (64) | the shared svcmgr name limit | their length | correct as is | None |
| svc-defs argv and env limits | `services/svcmgr/svc-defs/src/parse.rs` | 255 / 256 B / 64 words | encoding artefact (procmgr wire) | none | needs a design | Follows the blob design (#672) |
| restart create word check | `services/svcmgr/src/restart.rs` | `MSG_DATA_WORDS_MAX` | ABI width | none | correct as is | None |
| reconcile correlator (`ServiceTable::reserve`) | `services/svcmgr/src/definitions/reconcile.rs` | table index, `u64` | encoding artefact (slots are never reused; a stale post for a restarted instance is dropped on its live thread state) | none | correct as is | None |
| endowment `CAPS_SLOTS`, `ROUND_DATA_WORDS`, `CAPS_ROUNDS` | `services/svcmgr/endowment/src/lib.rs` | 6 / 4 / derived | provably unreachable (enumerated roles) | none | correct as is | None |
| bootstrap badge | `services/svcmgr/src/restart.rs` | random `u64` | ABI width | none | correct as is | None |

### vfsd and namespace

Every entry here is `correct as is`; none is tracked.

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `VfsdRootBackend.nodes` | `services/vfsd/root-backend/src/lib.rs` | heap `Vec`, one node per installed path component, never freed (no unmount) | per-instance (grows with the mount tree; an allocation failure refuses the install) | none | correct as is | None |
| tree node index (`NONE`) | `services/vfsd/root-backend/src/lib.rs` | `u32` | provably unreachable (`install` refuses a pool of `u32::MAX` nodes, each a heap allocation) | 4 B per link | correct as is | None |
| tree component limit (`validate_name`) | `services/vfsd/root-backend/src/lib.rs` | `MAX_NAME_LEN` (255) | ABI width (the namespace protocol's name rule) | none (names are heap-allocated to their length) | correct as is | None |
| `MAX_MOUNT_PATH_LEN` | `services/vfsd/src/main.rs` | `(MSG_DATA_WORDS_MAX - 2) * 8` = 496 | ABI width (the path bytes one MOUNT message carries) | none | correct as is | None |
| `discover_disks` disk list | `services/vfsd/src/partition.rs` | heap `Vec`, one `Disk` per block driver devmgr serves, found once at startup | per-instance (devmgr's block-driver count, one per virtio-blk device; an allocation failure stops discovery with a log, keeping the disks found before it) | none | correct as is | None |
| `collect_partitions` entry list | `services/vfsd/gpt/src/lib.rs` | heap `Vec`, every used entry of the header's `num_parts` array | hardware spec (UEFI GPT: `parse_header` requires the array to lie between LBA 2 and the header's own `first_usable_lba`); a header that also inflates `first_usable_lba` is bounded by the device capacity, and a read or allocation failure stops the walk with a log | none | correct as is | None |
| gpt `MAX_BLOCK_SIZE` | `services/vfsd/gpt/src/lib.rs` | 4096; the block size itself comes from `BLK_GET_GEOMETRY` | hardware spec (the block driver's `MAX_BLOCK_SIZE`, one page) | 4 KiB stack during a walk | correct as is | None |
| `GptHeader.num_parts`, `entry_size` | `services/vfsd/gpt/src/lib.rs` | `u32` | hardware spec (UEFI GPT) | none | correct as is | None |
| `BootstrapState.pending`, `ActiveState.queue` | `services/vfsd/src/worker_pool.rs` | heap `Vec` and `VecDeque`, one entry per in-flight fatfs spawn | per-instance (an allocation failure refuses the order and releases its caps) | none | correct as is | None |
| `ACTIVE_WORKER_COUNT` | `services/vfsd/src/worker_pool.rs` | 2 | tuning (concurrency knob) | 2 thread stacks | correct as is | None (#254) |
| `SERVICE_THREAD_COUNT` | `services/vfsd/src/main.rs` | 4 | tuning (concurrency knob; no service-endpoint request waits on another) | 4 thread stacks | correct as is | None (#254) |

### init and logd

The entries left open are tracked by the Issue each recommendation names.

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `HISTORY_RING_BYTES` (`HISTORY`) | `services/init/src/logging.rs` | 16 KiB, lines packed by length (about 160 boot lines; peak about 50) | tuning (boot-history retention: a full ring drops its oldest lines, never a sender) | 16 KiB BSS | correct as is | None |
| `MAX_SENDERS` (`SENDERS`) | `services/init/src/logging.rs` | 32 | provably unreachable as a ceiling (boot window; slots are evicted, not refused) | about 10.5 KiB BSS | correct as is | None |
| `LINE_BUF_SIZE`, `MAX_NAME_LEN` | `services/logd/codec/src/lib.rs` | 256 / 48 | line and label length, one definition for init-logd and logd (an over-long line is split, a long name truncated) | per sender slot | correct as is | None |
| `HistoryRing` record length | `services/logd/codec/src/history.rs` | `u16` | provably unreachable (at most `LINE_BUF_SIZE`, const-asserted) | 2 B per line | correct as is | None |
| `HistoryRing.total`, `first_seq` | `services/logd/codec/src/history.rs` | `u64` sequence | ABI width | 16 B | correct as is | None |
| `LOG_THREAD_STACK_PAGES` | `services/init/src/logging.rs` | 4 | BSS budget (the tables live in BSS, not on this stack) | 16 KiB | correct as is | None |
| `STREAM_CHUNK_SIZE` | `services/init/src/logging.rs`, `services/logd/src/main.rs` | 512 | ABI width | 512 B stack | correct as is | None |
| `MAX_ORPHAN_MEMORY_CAPS` | `services/init/src/main.rs` | `INIT_INFO_MAX_PAGES * PAGE_SIZE / size_of::<CapDescriptor>()` = 682 | provably unreachable (at most one orphan per usable-RAM cap, each of which has an `InitInfo` descriptor; `memory_count` is clamped to it) | about 2.7 KiB BSS, reclaimed at init's reap | correct as is | None |
| `CSPACE_RETYPE_PAGES` (tier-1) | `services/init/src/main.rs` | 149 pages (8231 slots) | refillable seed (augment) | 149 pages each for memmgr and procmgr | correct as is | None: both self-augment (#642, #643, #41) |
| `thread_retype_pages` (tier-1) | `services/init/src/main.rs` | `SystemInfoType::ThreadRetypeBytes` in pages | encoding artefact (kernel stack, TCB and save-area pages) | per tier-1 service | correct as is | None |
| `ASPACE_RETYPE_PAGES` (tier-1) | `services/init/src/main.rs` | 48 | refillable seed (augment) | 48 pages per tier-1 service | correct as is | None: memmgr and procmgr both self-augment (#642) |
| `init_retype_reserve_pages` | `services/init/src/bootstrap.rs` | 2 + the Thread slot's pages (`thread_retype_pages`): 8 at a six-page slot | provably unreachable (asserted against the fixed endpoint count) | 8 pages at a six-page slot | correct as is | None |
| `retype_reserve_pages` | `services/init/src/bootstrap.rs` | 197 + the Thread slot's pages (`thread_retype_pages`): 203 at a six-page slot | encoding artefact (sum) | per tier-1 service | correct as is | None |
| `MODULE_SCRATCH_MAX_PAGES` | `services/init/src/bootstrap.rs` | 65536 (256 MiB) | encoding artefact (init VA layout) | none | correct as is | Caps one boot module at 256 MiB |
| ACPI region rounds (`acpi_region_caps`) | `services/init/src/service.rs` | every cap `InitInfo` reports (`acpi_region_memory_count`), streamed four per round | provable unreachability (nothing is stored) | none | correct as is | None |
| substrate name packing | `services/init/src/service.rs` | `svcmgr_labels::NAME_MAX` (64), `pack_name` | the shared svcmgr name limit | 64 B stack | correct as is | None |
| `mm_boot_data` | `services/init/src/main.rs` | literal 64 | ABI width (`MSG_DATA_WORDS_MAX`) | 512 B stack | correct as is | Use the constant |
| `log_hex` buffer | `services/init/src/bootstrap.rs` | 96 B | diagnostic output cap | 96 B stack | correct as is | None |
| `SlotTable.slots` | `services/logd/src/slot.rs` | unbounded map | none | none | correct as is | Already pay-as-you-go |
| `PER_SLOT_HISTORY` | `services/logd/src/slot.rs` | 16 lines | tuning (per-sender retention) | none up front | correct as is | None |
| `DEATH_EQ_CAPACITY` | `services/logd/src/main.rs` | 128 | tuning (a drain of a full queue's worth starts a resync from procmgr's `QUERY_LIVE_PROCESSES`, which evicts the slots a dropped post left) | about 2.1 KiB | correct as is | None |
| eviction by the death correlator (`drain_deaths`) | `services/logd/src/main.rs` | the full `u64` badge procmgr posts; no death-observer nodes | ABI width | none | correct as is | None |
| death exit reason | `services/logd/src/main.rs` | full `u64` (`DeathEvent.exit_reason`, logged whole in the `reclaim:` line) | ABI width | none | correct as is | None |
| handover `MAX_ITERS` | `services/logd/src/handover.rs` | 2048 | provably unreachable (init's 32 senders plus at most about 860 lines in its 16 KiB ring) | none | correct as is | Derive from those constants |
| `RELEASE_RETRY_BUDGET_US` (`send_release`) | `services/logd/codec/src/handover.rs` | 1 s of wall-clock time | tuning (bounds no capacity; time-based, so load does not shorten it) | none | correct as is | None |
| `MAX_RELEASE_DEFERRALS` | `services/logd/codec/src/handover.rs` | 8 | tuning (liveness bound against name churn) | none | correct as is | None |
| `NameResend.pending` | `services/logd/codec/src/handover.rs` | init `MAX_SENDERS` | encoding artefact (mirror) | 32 B | correct as is | None |
| `LineBuf.buf`, `SerialFmt` | `services/logd/src/main.rs` | 512 / 256 | ABI width; line length | stack | correct as is | Use `SERIAL_CHUNK` |

### Other services

Every entry here is `correct as is`; none is tracked. services/netd has no code.

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `RESET_GRACE` | `services/pwrmgr/src/main.rs` | 1 s | tuning (platform reset latency) | none | correct as is | None |
| `SLP_TYP_MAX` | `services/pwrmgr/acpi/src/lib.rs` | 7 | hardware spec (ACPI 3-bit `SLP_TYPx`) | none | correct as is | None |
| SDT length | `services/pwrmgr/acpi/src/lib.rs` | `u32` | hardware spec (ACPI SDT header) | none | correct as is | None |
| wall time | `services/timed/src/main.rs` | `u64` microseconds | ABI width (about 584 000 years) | none | correct as is | None |
| `forward_lines` buffer | `services/usertest/src/main.rs` | 512 B read chunk | batch size (lines accumulate unbounded) | 512 B stack | correct as is | None |
| crasher settle sleep | `services/crasher/src/main.rs` | 500 ms | tuning (under the 3 s softlockup window) | none | correct as is | None |

### devmgr

Every entry here is `correct as is`; none is tracked.

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| PCI function list (`scan` output) | `services/devmgr/firmware/src/scan.rs` | growable `Vec` | provably unreachable (grows to every function the ECAM windows hold) | about 190 B per function | correct as is | None; a failed growth stops the scan with a log naming the function |
| `MAX_BARS` | `services/devmgr/firmware/src/scan.rs` | 6 | hardware spec (PCI type-0 header) | about 108 B per device | correct as is | None |
| `MAX_CAPABILITIES` | `services/devmgr/firmware/src/scan.rs` | 48 | hardware spec ((256 - 64) / 4 capability slots) | none | correct as is | None |
| `scan` device, function, bus widths | `services/devmgr/firmware/src/scan.rs` | 32 / 8 / 256 | hardware spec (PCI BDF) | none | correct as is | None |
| `DevmgrCaps.apertures` (`SpanTable`) | `services/devmgr/src/caps.rs` | growable | provably unreachable (one span per held aperture cap) | 24 B per span | correct as is | None; an aperture the table cannot hold is logged and released, and a carve keeps both remainders |
| `DevmgrCaps.acpi_regions` | `services/devmgr/src/caps.rs` | growable `Vec` | provably unreachable (one entry per delivered region) | 24 B per region | correct as is | None; a region the list cannot hold is logged and released |
| `DevmgrCaps.driver_modules` | `services/devmgr/src/caps.rs` | `module_kind::COUNT` = 3 | encoding artefact (one module per kind) | 12 B | correct as is | None; an unknown or duplicate kind is logged and released |
| absorb rounds `.min(4)` | `services/devmgr/src/caps.rs` | literal 4 | ABI width (`MSG_CAP_SLOTS_MAX`) | none | correct as is | Use the constant |
| ACPI table window (`table_window`) | `services/devmgr/firmware/src/acpi.rs` | the table's own pages, clamped to its region | firmware spec (the table's reported length) | VA for one table per read | correct as is | None; the per-process reservation arena bounds it, and a failed reservation is logged |
| `MAX_DEVICE_INFO_PAYLOAD` | `services/devmgr/src/main.rs` | 64 | encoding artefact (largest payload type 56 B) | 76 B per entry | correct as is | None |
| `DeviceCatalog.entries` | `services/devmgr/src/main.rs` | growable `Vec` | provably unreachable (one entry per enumerated device given a catalog entry, spawned or not, and one with no startup info for each of the serial and RTC drivers whose spawn devmgr attempts and for each `test-fault` fixture of the test-only fault batch, TODO(#165); never removed) | 76 B per entry | correct as is | None; an entry the catalog cannot hold is logged and its device not spawned |
| `device_badge` | `services/devmgr/src/main.rs` | `u64` | provably unreachable | none | correct as is | None |
| `IrqRangeAllocator.ranges` (`RANGE_END_BOUND`) | `services/devmgr/src/main.rs` | growable, 2^32 lines | ABI width (`SYS_IRQ_SPLIT`'s `u32` line) | 24 B per span | correct as is | None; lines below and above each carve stay held |
| virtio-blk and virtio-input instances | `services/devmgr/src/main.rs` | every device (virtio-blk: every one devmgr can give an IRQ cap, a line another device holds included); registry ordinal in `data[1]`, fixed when the class settles, a withdrawn driver's ordinal held by a tombstone | provably unreachable (`u64` ordinal) | one driver per device | correct as is | None |
| Driver death queue (`DriverWatch::new`) | `services/devmgr/src/settle.rs` | sized at enumeration to every driver the boot can spawn (one per virtio-blk and virtio-input device, plus the serial, framebuffer, and RTC drivers, plus the `TEST_FAULT_DRIVERS` = 3 fixtures of the test-only fault batch, which runs at most once per boot, TODO(#165)), in entries and observer nodes, at most `EVENT_QUEUE_MAX_CAPACITY` = 2^20 | provably unreachable (devmgr spawns each driver at most once and binds one observer on it; paid as the boot's devices are, with no ceiling below the kernel's) | 40 B per driver (a 16 B entry and a 24 B observer node) | correct as is | None while the driver set is fixed at enumeration; hotplug takes the growable `DeathQueues` policy whose hoist #677 records |
| `SETTLE_TIMEOUT` | `services/devmgr/src/settle.rs` | 10 s from the start of a batch's settle, `2 * RESET_TIMEOUT`: the longest bounded wait of a driver's setup, plus one more as margin; the test-only fault batch settles under `TEST_FAULT_SETTLE_TIMEOUT_MS` = 1 s instead, its fixtures making no bounded wait (TODO(#165)) | tuning (bounds no capacity; derived so a settle never ends before a driver's own reset timeout) | one timer thread (64 KiB stack) per settle | correct as is | None; a driver still pending at it is destroyed and withdrawn, with a log |
| Settle roster (`Roster`) | `services/devmgr/firmware/src/roster.rs` | growable `Vec` | provably unreachable (one entry per spawned driver of a batch) | about 24 B plus the caller's record per driver | correct as is | None; a driver the roster cannot record is not spawned, with a log |
| Served-driver ordinal table (`Served`) | `services/devmgr/firmware/src/served.rs` | growable `Vec`, one slot per served driver of a class, a withdrawn one's kept as a tombstone | provably unreachable (one slot per driver a settle served; devmgr restarts none) | about 16 B plus the caller's record per slot | correct as is | None; a driver the table cannot hold is destroyed, with a log |
| `VirtIO` driver process handles (`ServedDriver.process_handle`) | `services/devmgr/src/main.rs` | one badged procmgr handle kept per `VirtIO` driver for the boot, to destroy the driver and release its held memory (`RELEASE_HOLD`) when it is withdrawn | provably unreachable (one per `VirtIO` device; devmgr spawns each driver at most once and restarts none) | one cap slot per `VirtIO` driver | correct as is | None |
| `DevmgrCaps.config_space`, `DevmgrCaps.ecam_windows` | `services/devmgr/src/caps.rs` | growable `SpanTable` of the scanned ECAM windows' caps, less the configuration page carved for each `VirtIO` function, and a growable `Vec` of their locations | provably unreachable (one span per window plus at most one per carve's remainder, one location per window) | 24 B per span and per window, plus one cap slot per carved configuration page | correct as is | None; a window the tables cannot hold is logged, and its `VirtIO` functions get no driver |
| Death-observer correlator | `services/devmgr/src/spawn.rs` | the full `u64` device badge | ABI width (`SYS_THREAD_BIND_NOTIFICATION`'s `u64` correlator) | none | correct as is | None |
| Held interrupt lines (`HeldLines`) | `services/devmgr/firmware/src/lines.rs` | growable `Vec`, one held single-line cap per GSI a device uses; each device on a line gets its own derivation | provably unreachable (one entry per distinct device GSI; the drivers sharing a line are bounded by the kernel's `MAX_IRQ_BINDINGS`, 64 bindings per line) | about 8 B per held line, plus one cap slot per device's derivation | correct as is | None; a line the table cannot record is not split, and its device gets no IRQ cap, with a log |
| `mcfg_ecams` | `services/devmgr/firmware/src/acpi.rs` | every entry | firmware spec (MCFG length) | none | correct as is | None |
| `find_pci_ecams` | `services/devmgr/firmware/src/dtb.rs` | every node | firmware spec (structure block) | 24 B per window | correct as is | None |
| firmware dtb `MAX_DEPTH` | `services/devmgr/firmware/src/dtb.rs` | 16 | provably unreachable on real trees (under 8 deep) | 256 B stack | correct as is | None |
| `mint_bootstrap_badge` redraw | `services/devmgr/src/spawn.rs` | unbounded | provably unreachable (2^-64 per draw) | none | correct as is | None |
| riscv64 platform defaults | `services/devmgr/src/arch/riscv64/mod.rs` | QEMU `virt` constants | hardware spec (QEMU `virt`) | none | correct as is | Data-driven binding is #165 |

### Drivers

Every entry here is `correct as is`; none is tracked.

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `MAX_VIRTIO_BARS` | `services/drivers/virtio/core/src/lib.rs` | 4 BARs per device, at most `MSG_CAP_SLOTS_MAX` (const-asserted) so one bootstrap round carries them | hardware spec (one BAR per `VirtIO` 1.2 § 4.1.4 register region: common, notification, ISR, device configuration) | about 170 B per driver and 40 B per device in devmgr | correct as is | None |
| `MAX_QUEUE_SIZE` | `services/drivers/virtio/core/src/virtqueue.rs` | 32768; the bookkeeping is sized to the negotiated queue | hardware spec (VirtIO split ring) | 4 B per negotiated descriptor | correct as is | None |
| `last_used_idx`, `avail.idx` | `services/drivers/virtio/core/src/virtqueue.rs` | `u16` | hardware spec (VirtIO split ring; `new` refuses a queue size that is not a power of two) | none | correct as is | None |
| `RESET_TIMEOUT` | `services/drivers/virtio/core/src/pci.rs` | 5 s on the monotonic clock: a driver's wait for its device's reset, and devmgr's when it resets a withdrawn driver's device | tuning | none in memory; devmgr's thread (a settle, or the registry loop) is held up to 5 s per withdrawn device, all of it for one whose status does not read 0 within the bound | correct as is | None |
| `ISR_POLL_MS` | `services/drivers/virtio/core/src/isr.rs` | 50 ms | tuning (how late an interrupt is seen whose edge an x86-64 I/O APIC entry programmed edge-triggered dropped while its line was masked, against idle wakeups) | one wakeup and one ISR read per 50 ms per IRQ-bound `VirtIO` driver while idle | correct as is | None |
| virtio-blk `QUEUE_SIZE` | `services/drivers/virtio/blk/src/main.rs` | 4 | provably unreachable (one request in flight by design; one three-descriptor chain) | one ring page | correct as is | None |
| `PartitionTable.entries` | `services/drivers/virtio/blk/src/lib.rs` | heap `Vec`, one entry per distinct registered range (a remount reuses its entry) | per-instance | none | correct as is | None |
| `PartitionTable.next_badge` | `services/drivers/virtio/blk/src/lib.rs` | `u64`, one per distinct range | provably unreachable (2^63 ranges) | none | correct as is | None |
| `MAX_BLOCK_SIZE` | `services/drivers/virtio/blk/src/lib.rs` | 4096 | hardware spec (one page, the unit clients read into) | none | correct as is | None |
| `transfer_len` bound | `services/drivers/virtio/blk/src/lib.rs` | `u32::MAX / block_size` blocks | hardware spec (VirtIO descriptor length) | none | correct as is | None |
| `REQUEST_TIMEOUT` | `services/drivers/virtio/blk/src/io.rs` | 50 s | tuning | none | correct as is | None |
| `IRQ_WAIT_TIMEOUT_MS` | `services/drivers/virtio/blk/src/io.rs` | 50 ms | tuning | none | correct as is | None |
| `POLL_BURST` | `services/drivers/virtio/blk/src/io.rs` | 500 us on the monotonic clock | tuning | none | correct as is | None |
| `EVENT_QUEUE_SIZE` | `services/drivers/virtio/input/src/input.rs` | 64 | BSS budget (64 x 8 B buffers in one DMA page) | one DMA page | correct as is | None |
| `POLL_INTERVAL_MS` | `services/drivers/virtio/input/src/main.rs` | 20 | tuning (human input rate) | none | correct as is | None |
| `MAX_READ_BYTES` | `services/drivers/serial/src/main.rs` | 512 | ABI width (`MSG_DATA_WORDS_MAX * 8`) | 512 B stack | correct as is | Derive from the constant |
| serial and framebuffer write `byte_len` | `services/drivers/serial/src/main.rs`, `services/drivers/framebuffer/src/main.rs` | 16 bits | encoding artefact | none | correct as is | None |
| cmos `MAX_ATTEMPTS` | `services/drivers/cmos/src/lib.rs` | 16 | hardware spec (MC146818 update cadence) | none | correct as is | None |
| cmos `UIP_POLL_LIMIT` | `services/drivers/cmos/src/lib.rs` | 10 000 | hardware spec (UIP held at most about 2 ms) | none | correct as is | None |
| cmos `FALLBACK_CENTURY` | `services/drivers/cmos/src/lib.rs` | 2000 to 2099, only without a century register (FADT `CENTURY` 0) | hardware spec (two-digit year) | none | correct as is | None |
| test-orphan `RESERVE_BYTES` | `services/drivers/test-orphan/src/main.rs` | 1 MiB | test fixture | 1 MiB heap | correct as is | None |
| test-fault `NEVER_READY_RESERVE_BYTES` | `shared/ipc/src/lib.rs` (`test_fault_labels`) | 4 MiB | test fixture (held by the never-ready fixture until devmgr destroys it; svctest watches it return) | 4 MiB heap while the fixture hangs | correct as is | None |

### fs-fat

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `node_slab::MAX_ENTRIES` (`NodeTable`) | `services/fs/fat/fat-parse/src/node_slab.rs` | 2^24 - 1 live nodes, one per distinct live entry looked up; freed when the entry is removed or renamed and recycled under a 16-bit generation, retired at wrap | encoding artefact (40-bit `NodeId`) | heap, per live node | correct as is | None |
| `NO_OPEN_SLOT` | `services/fs/fat/src/backend.rs` | `u32::MAX` | provably unreachable | none | correct as is | None |
| open-file table | `services/fs/fat/src/main.rs` | heap `Vec`, at most one slot per live node, closed slots reused | per-instance | none | correct as is | Key by open instance (#530) |
| `track_outstanding` limit | `services/fs/fat/src/file.rs` | the cache's slot ceiling, pages per file, the table grown on demand | follows the cache | none | correct as is | None |
| eviction queue | `services/fs/fat/src/eviction.rs` | heap `VecDeque`, one entry per outstanding page at most | provably unreachable (each page is queued at most once) | none | correct as is | None |
| `RELEASE_TIMEOUT_MS` | `services/fs/fat/src/eviction.rs` | 100 ms | tuning | none | correct as is | None |
| `MAX_WATCHDOGS` | `services/fs/fat/src/eviction.rs` | 4 watchdog threads alive at once | tuning (past it a release skips the advisory round trip) | none | correct as is | Cancel a blocked call (#31) |
| `SLOT_COUNT`, `SLOT_RAM_DIVISOR`, `slot_ceiling` (`PageCache.slots`) | `services/fs/fat/fat-parse/src/lib.rs` | one slot per 512 pages of RAM, at least 256, fixed at init; each page taken from memmgr on its slot's first use | per-instance, RAM-scaled | a slot table entry per slot, and the slots filled | correct as is | None |
| `QUARANTINE_MAX` | `services/fs/fat/fat-parse/src/lib.rs` | 32 | tuning (bounds what non-unmapping clients cost) | 256 B | correct as is | None (#52) |
| `cache_cspace_funding` | `services/fs/fat/src/cache.rs` | slot ceiling `+ QUARANTINE_MAX + 1 + 64` slots | follows its factors, plus run-time headroom | the slot pages it funds | correct as is | None |
| `PageCache::sectors_per_page` | `services/fs/fat/src/cache.rs` | `PAGE_SIZE` over the device block size, 1 to 8 | hardware spec (page over sector) | none | correct as is | None |
| `SCRATCH_MEMORY` | `services/fs/fat/src/cache.rs` | one page | encoding artefact (block DMA from offset 0) | one page | correct as is | None (#83) |
| `FatState.cached_fat_sector` | `services/fs/fat/src/bpb.rs` | one sector | tuning (memo above the cache) | 4 KiB | correct as is | None |
| `NEXT_BADGE` | `services/fs/fat/src/main.rs` | `u64`, monotonic | provably unreachable | none | correct as is | None |
| FS_READ reply size | `services/fs/fat/src/main.rs` | 504 B | ABI width | 512 B stack | correct as is | None |
| memory verbs | `services/fs/fat/src/main.rs` | one page per call | encoding artefact | none | correct as is | None |
| cluster-chain walk | `services/fs/fat/src/main.rs`, `fat.rs` | at most file size over cluster size | encoding artefact (`u32` file size) | none | correct as is | Add a cycle guard |
| `next_dir_cluster` step guard | `services/fs/fat/src/dir.rs` | `total_clusters` | provably unreachable (longer chains must cycle) | none | correct as is | None |
| allocator scans | `services/fs/fat/src/alloc.rs` | `total_clusters`, one wrap | encoding artefact | none | correct as is | None |
| `MAX_NUMERIC_TAIL` | `services/fs/fat/fat-parse/src/lib.rs` | 999 999, the lowest free tail taken | hardware spec (FAT numeric tail; a directory's 65536 entries always leave one) | 8 KiB heap per insert | correct as is | None |
| on-disk `u32` fields | `services/fs/fat/src/dir.rs` | `u32` | hardware spec (FAT32) | none | correct as is | None |
| LFN write (`encode_lfn`) | `services/fs/fat/fat-parse/src/lib.rs` | 255 UTF-16 code units | hardware spec (FAT LFN) | 510 B stack | correct as is | None |
| `MAX_LFN_CHARS`, `MAX_LFN_UTF8` | `services/fs/fat/fat-parse/src/lib.rs` | 255 / 765 | hardware spec (FAT LFN) | embedded | correct as is | None |
| `MAX_SLOT_RUN` | `services/fs/fat/fat-parse/src/lib.rs` | 21 | hardware spec (FAT LFN) | embedded | correct as is | None |
| fat-parse `MAX_SECTOR_SIZE` | `services/fs/fat/fat-parse/src/lib.rs` | 4096; the volume's sector size must equal the device block size | hardware spec (FAT sector sizes 512 to 4096) | 4 KiB per sector buffer | correct as is | None |

### Test harnesses

Harness bounds limit only what a test exercises, so every entry is `correct as is`; none is
tracked. The mirrors of production constants are noted because they desync silently when the
production value is raised.

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `ChildStack` | `core/ktest/src/main.rs` | 16 KiB | test fixture | 16 KiB per static | correct as is | None |
| `IPC_BUF`, `IpcPage` | `core/ktest/src/main.rs` | one page | ABI width | 4 KiB each | correct as is | None |
| `MAX_STRESS_THREADS` | `core/ktest/src/stress/mod.rs` | 64 | ABI width (one notification bit per worker) | 1 MiB BSS | correct as is | None |
| `POOL_SIZE` (frame pool) | `core/ktest/src/frame_pool.rs` | 64 | ABI width (`u64` availability bitmap) | 256 B plus 64 pages | correct as is | Pin `POOL_SIZE <= 64` with a const assert |
| `UNSCALED_CPUS`, `scaled_polls` | `core/ktest/src/main.rs` | 16, `u32` saturating | test fixture | none | correct as is | None |
| `REPORT_SLICES`, `REPORT_SLICE_MS` | `core/ktest/src/tally.rs` | 1000 x 5 ms | test fixture | none | correct as is | None |
| `await_all` mask | `core/ktest/src/tally.rs` | 64 children | ABI width (notification word) | none | correct as is | None |
| `MAX_POLLS` (14 copies) | `core/ktest/src/` | 2000 x 1 ms, scaled | test fixture | none | correct as is | Hoist to one constant |
| `LIVE` (`HANDLES`) | `core/ktest/src/stress/cspace_registry_arena.rs` | 4097 | test fixture (one past the former 4096-entry registry; funded at the ABI's `CSPACE_SLOTS_PER_PAGE` slots a page) | about 16 KiB BSS | correct as is | None |
| `HOLDERS`, `WAKERS` | `core/ktest/src/stress/sleep_list_wide.rs` | 192 / 64 | test fixture (past the former 128-entry sleep list) | 1 MiB BSS | correct as is | None |
| `MAX_IRQ_BINDINGS` (`Held`) | `core/ktest/src/integration/irq_shared_line.rs` | 64 | mirror of kernel `MAX_IRQ_BINDINGS` | about 540 B stack (`Held` and the bound-cap array) | correct as is | Reference the kernel constant if it moves to an ABI crate |
| `MAX_PINNED` | `core/ktest/src/bench/tlb.rs` | 7 | test fixture | 224 KiB BSS | correct as is | None |
| `EVERY_CPU_MAX`, `LOW_CPUS` | `core/ktest/src/arch/x86_64/umip.rs` | 16 / 8 | test fixture | none | correct as is | None |
| `MIGRATION_GUARD_MAX_CPUS` | `core/ktest/src/stress/load_balance_handoff_steal.rs` | 32 | ABI width (one-hot `u32` witness) | none | correct as is | None |
| `fund_boot_aspace_pt` budgets | `core/ktest/src/main.rs` | 256 KiB / 64 / 16 pages | test fixture | none | correct as is | None |
| `DEPTH` | `core/ktest/src/integration/cspace_nested_teardown.rs` | 256 | test fixture (past the kernel-stack recursion depth) | none | correct as is | None |
| `CHILDREN` | `core/ktest/src/integration/cap_transfer_large.rs` | 300 | test fixture (more than one reparent batch) | none | correct as is | None |
| `MANY`, `P_PAGES`, `T_PAGES` | `core/ktest/src/integration/arena_reclaim.rs` | 70 / 16 / 8 | test fixture (three arena pages of bodies; a donation past the inline records; a slab holding a port-binding table) | 280 B BSS | correct as is | None |
| `fatfs_slot_ceiling`, `FATFS_QUARANTINE_MAX` | `services/svctest/src/phases/fs_ipc.rs` | fs-fat's `slot_ceiling` of the RAM memmgr reports / `QUARANTINE_MAX`, imported | follows fs-fat | none | correct as is | None |
| `GROWTH_CHILDREN` | `services/svctest/src/phases/procmgr.rs` | half procmgr's `FIRST_POOL_OBSERVERS` (32), imported | follows procmgr | none | correct as is | None |
| `INLINE_CHUNK` | `services/svctest/src/phases/fs_ipc.rs` | 504 | ABI width | none | correct as is | Use the derived constant |
| `SYSTEM_TIME_BEFORE_2100_SECS` | `services/svctest/src/phases/timed.rs` | 4 102 444 800 | mirror of the cmos century fallback | none | correct as is | None |
| svctest poll counts | `services/svctest/src/phases/*.rs` | 256 to 5000 | test fixture | none | correct as is | None |
| ramdisk `MAX_SECTORS_PER_REQUEST`, `CLUSTERS` | `services/svctest/src/phases/fs_faults/ramdisk.rs` | 8 / 4096 | test fixture | none | correct as is | None |

---

## Summarized By

[Architecture Overview](architecture.md)
