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
| Set by | What fixes the value today: a hardware or format spec, an ABI width, an encoding artefact, a static-footprint (BSS) budget, current peak plus headroom, or provable unreachability |
| Up-front cost | The static, per-object, or eager cost paid for the ceiling whether or not it is reached |
| Class | `correct as is`, `raise` (raise the value or widen the type), `make pay-as-you-go` (keep the ceiling, pay only for use), or `needs a design` |
| Recommendation | One line |

The Issue that tracks a section's non-`correct as is` entries is named under the section heading.
An entry an existing open Issue already names cites it in the recommendation.

---

## Cross-Cutting Findings

- **RAM ceiling.** The binding RAM ceiling today is about 248 GiB of top RAM address, set by the
  boot direct map's table pool (`BOOT_TABLE_POOL_SIZE`), just before the frame map's 256 GiB
  (`MAX_CHUNKS`). The buddy allocator keeps its free-list links in the free blocks and has no
  RAM ceiling of its own.
- **CPU ceiling.** The binding CPU ceiling is `MAX_ORDER`: every per-CPU slab must fit one buddy
  block, and `AP_IST_STACKS` is exactly 8 MiB at `MAX_CPUS = 512`. `MAX_CPUS` itself is inline
  in the one-page `BootInfo`, and shipping two-socket servers already exceed 512 logical CPUs.
- **Process ceiling.** Live processes stop at 32 (procmgr `MAX_PROCESSES`), then 64 (memmgr);
  the kernel's `CSpace` registry is sized from RAM and does not bind first. Behind those sit
  the per-process `u32` death correlator, `badge as u32` in procmgr, logd and svcmgr, which
  collides once tables grow, and the cap handle's 8-bit wrapping generation.
- **Per-process address space.** One static VA map sized to Sv39's 2^38 is used on every
  architecture. It caps each process's heap at 1 GiB, its reservation arena at 256 MiB, and its
  main stack at 1 MiB.
- **Silent truncation.** Many tables drop entries past their bound with no diagnostic: boot
  memory-map entries, usable RAM ranges, apertures, ACPI regions, DTB nodes and ranges, named
  modules, PCI functions, and reserve free runs. Each needs a diagnostic as well as a better
  bound.
- **Unpinned couplings.** Bounds that depend on each other are tied only by comments or literal
  copies: `MAX_EXCL` and core/boot `MAX_MODULES`, `MAX_MODULES` and `INIT_MAX_NAMED_MODULES`
  (16 against 12), `MAX_MMIO_DIRECT_MAP_REGIONS` and `MAX_IOAPICS`, `REAPER_SLOTS` and
  `GEN_BITS`, the `registry` and `registry-client` copies of `NAME_MAX`, the ktest mirrors of
  `MAX_SLEEPING` and `L2_SIZE`, and the svctest mirrors of the fs-fat cache constants.
- **Spin-count timeouts.** Several deadlock detectors and device polls are counted in loop
  iterations, whose wall time depends on CPU and MMIO speed. `wait_for_ack` is the time-based
  model.
- **Hidden global pools.** The kernel's 512 KiB SEED also funds split bodies, Mmio and IoPort
  copies, and IOPB tables at runtime; the memmgr and procmgr CSpaces are seeded once with
  8231 slots and have no augment path.

## Catalogue

### Kernel: memory management

Tracked by [#636](https://github.com/kottlerg/seraph/issues/636).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `BuddyAllocator.free_lists` (`FreeHeader` in each free block) | `core/kernel/src/mm/buddy.rs` | none: one 16 B header inside each free block, linked by physical address | provable unreachability (no metadata outside the free pages) | 96 B BSS (the 12 list heads) | correct as is | None |
| `MAX_ORDER` | `core/kernel/src/mm/buddy.rs` | 11 (8 MiB largest block) | BSS budget (the 512-CPU `AP_IST_STACKS` slab fits one block) | none | needs a design | With the one-block rule of `alloc_zeroed_slab` it is the effective `MAX_CPUS` ceiling; allocate per-CPU slabs in several blocks |
| `BOOT_TABLE_POOL_SIZE` (`BootTablePool.frames`) | `core/kernel/src/mm/paging.rs` | 256 frames | BSS budget | 1 MiB BSS | make pay-as-you-go | Halts above about 248 GiB of top RAM address; 1 GiB leaves or tables carved from usable RAM |
| `LARGE_PAGE_SIZE` | `core/kernel/src/mm/paging.rs` | 2 MiB | hardware spec (x86-64 and Sv39 large leaf) | none | correct as is | None |
| `init_kernel_page_tables` `mmio_regions` | `core/kernel/src/mm/paging.rs` | `[(u64, u64); 16]` | current peak plus headroom (LAPIC plus `MAX_IOAPICS` = 9) | 256 B stack | raise | Pin `1 + MAX_IOAPICS <= 16` with a const assert or derive the length |
| `map_boot_stack` identity window | `core/kernel/src/mm/paging.rs` | 64 KiB aligned down around SP | unknown | 16 PTEs | raise | The bootloader stack is only 4 KiB-aligned; map the reported stack range |
| `MAX_CHUNKS` (`FrameMap.chunks`) | `core/kernel/src/mm/frame_map.rs` | 256 (1 GiB per chunk) | BSS budget (matched to the boot pool) | 2 KiB BSS | make pay-as-you-go | Fatal past 256 GiB of DRAM span; size from `dram_bounds()` and skip holes |
| `FrameMap` per-frame counter | `core/kernel/src/mm/frame_map.rs` | `AtomicU32`, saturating | provably unreachable (2^32 leaf PTEs to one frame need 32 GiB of page tables, and saturation refuses the map) | 4 B per frame | correct as is | None |
| `RELEASE_RUNS` (`ReleaseBatch.runs`) | `core/kernel/src/mm/frame_map.rs` | 16 | batch size (a full batch flushes, never fails) | 256 B stack | correct as is | None |
| `FRAMES_PER_CHUNK` geometry assert | `core/kernel/src/mm/frame_map.rs` | 1 GiB per chunk, 1 MiB counter block | encoding artefact | none | correct as is | Keep |
| `MAX_RANGES` (`RangeList` usable and work lists) | `core/kernel/src/mm/init.rs` | 64 | current peak plus headroom | about 1 KiB stack per list | raise | `push` drops RAM ranges past 64 silently; size from `memory_map.count` or fail loudly |
| `MAX_EXCL` | `core/kernel/src/mm/init.rs` | 32 | provably unreachable today (27 at most) only through core/boot's private `MAX_MODULES` | 512 B stack | needs a design | Derive from an ABI constant with a const assert; make overflow fatal |
| `FREE_RANGE_CAP` (`FREE_RANGES`) | `core/kernel/src/mm/init.rs` | `MAX_RANGES + MAX_EXCL + 1` = 97 | provable unreachability (the usable ranges are disjoint, so each subtracted extent adds at most one piece; `push_counted` asserts it) | about 1.5 KiB BSS | correct as is | None |
| `fdt_extent` DTB size check | `core/kernel/src/mm/init.rs` | FDT `u32` `totalsize`, at least the 40-byte header, inside the direct-mapped span | hardware or format spec (FDT header) | none | correct as is | None; a blob outside the bounds halts the boot at Phase 3 |
| `TAG_CAP` (`TagPool`) | `core/kernel/src/mm/tag_allocator.rs` | 4096 | hardware spec (x86 12-bit PCID); clips riscv64's 16-bit ASID | about 64.5 KiB BSS | make pay-as-you-go | Allocate from the buddy, sized to the probed tag count |
| `enable` `max_fit` tag trim | `core/kernel/src/mm/tag_allocator.rs` | `2^MAX_ORDER` pages / (`cpu_count` x 16) | BSS budget (one-block slab) | `cpu_count` x tags x 16 B | needs a design | Follows the per-CPU slab design |
| `AddressSpace.tag`, `TlbShootdownRequest.tag` | `core/kernel/src/mm/address_space.rs`, `tlb_shootdown.rs` | `AtomicU16` | hardware spec (PCID and ASID widths) | 2 B each | correct as is | None |
| `alloc_gen`, `tag_gen`, `tlb_gen` | `core/kernel/src/mm/tag_allocator.rs`, `address_space.rs` | `u64` | provably unreachable (no wrap at any claim rate) | 8 B each | correct as is | None |
| `acquire_tag_pool_lock` spin bound | `core/kernel/src/mm/tag_allocator.rs` | 500 000 spins, then hang | unknown (spin count) | none | needs a design | Time-based bound or the softlockup watchdog |
| `claim` eviction retry bound | `core/kernel/src/mm/tag_allocator.rs` | 10 000 000 passes, then fatal | unknown (spin count) | none | needs a design | Time-based bound |
| `acquire_frame_alloc_lock` spin bound | `core/kernel/src/mm/mod.rs` | 500 000 spins, then hang | unknown (spin count) | none | needs a design | Time-based bound or the softlockup watchdog |
| `TLB_REQUESTS` | `core/kernel/src/mm/tlb_shootdown.rs` | `[TlbShootdownRequest; MAX_CPUS]` | ABI width (`MAX_CPUS`) | about 48 KiB BSS | make pay-as-you-go | Allocate with the `cpu_count`-sized per-CPU slabs |
| `RANGE_FLUSH_CEILING_PAGES` | `core/kernel/src/mm/tlb_shootdown.rs` | 32 | tuning threshold (bounds no capacity) | none | correct as is | None |
| `CPU_MASK_WORDS` (`CpuMask`) | `core/kernel/src/cpu_mask.rs` | `MAX_CPUS.div_ceil(64)` = 8 | ABI width (`MAX_CPUS`) | 64 B in every `AddressSpace` and TLB request | needs a design | Per-boot width or a hierarchical mask before `MAX_CPUS` rises |
| `AddressSpace.death_observers` | `core/kernel/src/mm/address_space.rs` | 4 (`MAX_DEATH_OBSERVERS`) | current peak plus headroom | 64 B per `AddressSpace` | make pay-as-you-go | See the thread-side entry |
| `DEFAULT_INIT_INFO_VA`, `DEFAULT_INIT_STACK_TOP` | `core/kernel/src/mm/address_space.rs` | fixed VAs under the Sv39 user top | encoding artefact (fallback layout) | none | correct as is | Not a count |
| `INIT_MAX_SEGMENTS` RELRO split | `core/kernel/src/mm/init_reloc.rs` | 8 | ABI width (boot protocol) | none | correct as is | A split past 8 is a clean error |
| `kernel_pt_pool` seed | `core/kernel/src/mm/kernel_pt_pool.rs` | 64 pages (`POOL_SEED_PAGES`), never returned | current peak plus headroom | 256 KiB | needs a design | Also the fallback for address spaces with no donation; confirm it is unreachable after boot |
| x86_64 4-level paging (`user_va_top`) | `core/kernel/src/arch/x86_64/paging.rs` | user 128 TiB, kernel half 128 TiB | hardware spec (4-level paging chosen; no LA57) | none | needs a design | Below the #177 target of 526 TB; decide on LA57 |
| `PerCpuData`, `CPU_APIC_IDS` slabs | `core/kernel/src/percpu.rs` | `cpu_count`-sized | ABI width (`MAX_CPUS` upper bound) | `cpu_count` x about 76 B | correct as is | Already pay-as-you-go |
| `CPU_APIC_IDS` element | `core/kernel/src/percpu.rs` | `u32` | ABI width (`BootInfo.cpu_ids`; x2APIC IDs are 32-bit) | 4 B per CPU | correct as is | riscv64 `mhartid` is XLEN-wide; a hart id above 2^32 is refused |
| `PerCpuData.cpu_id`, `preempt_count` | `core/kernel/src/percpu.rs` | `u32` | provably unreachable (CPUs and nesting are far below 2^32) | embedded | correct as is | None |
| `Spinlock.next_ticket`, `now_serving` | `core/kernel/src/sync.rs` | `AtomicU32`, wrapping | provably unreachable (equality compare; waiters at most CPUs) | 8 B per lock | correct as is | None |
| `boot_cpu_ids` (by value) | `core/kernel/src/main.rs` | `[u32; MAX_CPUS]` | ABI width (`MAX_CPUS`) | 2 KiB boot stack | make pay-as-you-go | Pass a slice into `BootInfo` |
| `INIT_ASPACE_PAGES` | `core/kernel/src/main.rs` | 18 | provably unreachable (init's fixed footprint: temp-map scratch and one UART page; augment can refill it, as ktest does) | 72 KiB from SEED | correct as is | None |
| `INIT_THREAD_PAGES` | `core/kernel/src/main.rs` | `KERNEL_STACK_PAGES + 2` = 6 | encoding artefact (stack, TCB, FPU page) | 24 KiB from SEED | correct as is | None |
| `page_ptrs`, `page_phys` | `core/kernel/src/main.rs` | `[_; INIT_INFO_MAX_PAGES]` | ABI width (init protocol) | 64 B stack | correct as is | Overflow is fatal above it |
| `backtrace_scan` `MAX_BYTES` | `core/kernel/src/main.rs` | 8 KiB | unknown | none | raise | Half the 16 KiB kernel stack; bound by `stack_top` |
| `backtrace_scan` `MAX_HITS` | `core/kernel/src/main.rs` | 24 | diagnostic output cap | none | correct as is | None |
| `APS_READY` wait | `core/kernel/src/main.rs` | unbounded | unknown | none | needs a design | Time bound and a fatal naming the CPU |
| `timer::init(1_000)` tick period | `core/kernel/src/main.rs` | 1000 us | tuning (bounds no capacity) | none | correct as is | None |
| `print_timestamp` `sec_buf` | `core/kernel/src/console.rs` | 20 B | ABI width (`u64::MAX` has 20 digits) | 20 B stack | correct as is | None |
| `FramebufferWriter` geometry fields | `core/kernel/src/framebuffer.rs` | `u32` | ABI width (boot-protocol `FramebufferInfo`) | embedded | correct as is | None |
| `platform::MAX_MMIO_APERTURES` (`VALIDATED_APERTURES`) | `core/kernel/src/platform.rs` | 64 | current peak plus headroom | 1 KiB BSS | raise | Apertures past 64 are dropped with a warning; size from the boot count |

### Kernel: capabilities

Tracked by [#637](https://github.com/kottlerg/seraph/issues/637); the Phase 7 boot buffers by
[#636](https://github.com/kottlerg/seraph/issues/636); the reference-count wrap by
[#633](https://github.com/kottlerg/seraph/issues/633); the page free-list walk by
[#634](https://github.com/kottlerg/seraph/issues/634).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `CSPACE_REGISTRY` arena (`chunks_for_ram`, `init_cspace_registry`) | `core/kernel/src/cap/registry.rs` | one 16 B entry per page of DRAM | provably unreachable (every `CSpace` costs its creator at least one page, so the id space never binds before RAM does) | about 0.4 % of DRAM, carved at boot | correct as is | None |
| `REGISTRY_CHUNK_ORDER` | `core/kernel/src/cap/registry.rs` | 8 (1 MiB chunks) | encoding artefact (chunk granularity of the two-level arena) | none | correct as is | None |
| `MAX_REGISTRY_CHUNKS` | `core/kernel/src/cap/registry.rs` | 1024 (one entry per page of 256 GiB) | encoding artefact (matched to `frame_map::MAX_CHUNKS`, asserted) | 8 KiB BSS | needs a design | Fatal past 256 GiB of DRAM; follows `MAX_CHUNKS` (#636) |
| `RegistryEntry.epoch`, `SlotId.epoch` | `core/kernel/src/cap/registry.rs`, `slot.rs` | `u32`, redrawn on recycle | encoding artefact (12 B `SlotId`, 72 B slot) | 4 B per `SlotId` | correct as is | Freshness-only; the residual per recycle is documented |
| `CapabilitySlot.pad[1]` (handle generation) | `core/kernel/src/cap/slot.rs` | `u8`, wrapping | ABI width (`u32` handle: 8 generation + 24 index bits) | 1 B per slot | raise | Wraps after 256 recycles of one index; retire at wrap or widen handles |
| `CAP_INDEX_BITS` | `abi/syscall/src/lib.rs` | 24 | ABI width (`u32` handle) | none | needs a design | About 16.7 M slots per CSpace; decide with the generation (#41) |
| `L2_SIZE` | `core/kernel/src/cap/cspace.rs` | 56 | encoding artefact (56 x 72 B in one page, asserted) | none | correct as is | None |
| `L1_DIRECT`, `L1_INDIRECT` | `core/kernel/src/cap/cspace.rs` | 128 / 128 | encoding artefact (two-level directory inline in the CSpace) | 2 KiB per CSpace | correct as is | Add a level, not inline pointers, if `MAX_SLOTS_STRUCTURAL` ever binds (#41) |
| `MAX_LEAVES`, `MAX_SLOTS_STRUCTURAL` | `core/kernel/src/cap/cspace.rs` | 65 664 leaves, 3 677 184 slots per CSpace | encoding artefact (directory geometry) | none (growth is pool-funded) | needs a design | procmgr's CSpace bounds its children near 1 M; decide with `CAP_INDEX_BITS` |
| CSpace geometry asserts | `core/kernel/src/cap/cspace.rs` | `MAX_SLOTS_STRUCTURAL <= 1 << CAP_INDEX_BITS`, page fits | encoding artefact | none | correct as is | Keep |
| `CSpace.next_leaf`, `pool_exhaustions` | `core/kernel/src/cap/cspace.rs` | `u32` | encoding artefact (`next_leaf` asserted against `MAX_LEAVES`); `pool_exhaustions` is a wrapping diagnostic counter | embedded | correct as is | None |
| `ROOT_CSPACE_INIT_SLOT_CAPACITY` | `core/kernel/src/cap/mod.rs` | 1536 slots | refillable seed (init augments) | about 29 pages | correct as is | None |
| `SEED_RESERVE_BYTES` (`SEED_MEMORY`) | `core/kernel/src/cap/mod.rs` | 512 KiB | current peak plus headroom (boot footprint) | 512 KiB pinned | needs a design | Also funds split bodies, Mmio and IoPort copies and IOPB tables at runtime; fund them from the caller (#260) |
| `MAX_DRAIN_BLOCKS` | `core/kernel/src/cap/mod.rs` | 4096 coalesced extents | current peak plus headroom (the fragmentation of free RAM, not its size) | 64 KiB BSS, used once | needs a design | Overflow is fatal with the count; size the buffer from the drained extent count, or write straight into the InitInfo block (#636) |
| `CSPACE_LAYOUT_MAX_DESCRIPTORS` | `core/kernel/src/cap/mod.rs` | 4480 | encoding artefact (sum of other ceilings) | about 105 KiB BSS | needs a design | About 6x what InitInfo holds; write straight into the InitInfo block |
| `CSpaceLayout.module_names` | `core/kernel/src/cap/mod.rs` | 12 (`INIT_MAX_NAMED_MODULES`) | ABI width (init protocol) | embedded | needs a design | Names past 12 are dropped without a message; see the boot section |
| `INIT_STACK_PHYS`, `INIT_INFO_RESERVE_ORDER` | `core/kernel/src/cap/mod.rs` | `INIT_STACK_PAGES`, `INIT_INFO_MAX_PAGES` | ABI width (init protocol) | 32 B | correct as is | None |
| `POOL_SEED_PAGES` | `core/kernel/src/cap/mod.rs` | 64 | current peak plus headroom (measured 6 to 7) | 256 KiB | needs a design | See `kernel_pt_pool` in the memory-management section |
| Phase 7 `MAX_ACPI_REGIONS` | `core/kernel/src/cap/mod.rs` | 8 | current peak plus headroom | none | raise | Truncates with a log; raise to the boot-protocol bound |
| `ROOT_IRQ_COUNT` | `core/kernel/src/cap/mod.rs` | arch `ROOT_IRQ_COUNT` | hardware spec (the GSIs of `MAX_IOAPICS` I/O APICs; the PLIC id space) | none | correct as is | None |
| `RECLAIM_ARRAY_MAX_SPAN_PAGES` | `core/kernel/src/cap/mod.rs` | from `MAX_RECLAIM_RANGES` | ABI width (boot protocol) | none | correct as is | None |
| `MAX_IOPORT_BINDINGS` (`IoPortBindings.records`) | `core/kernel/src/cap/ioport_bindings.rs` | 16 per thread | unknown | 256 B per bound thread | raise | Spill to a caller-funded page |
| `TABLE_BYTES` (`IoPortBindings` with `bitmap[IOPB_SIZE]`) | `core/kernel/src/cap/ioport_bindings.rs` | about 8.4 KiB | hardware spec (x86 IOPB) | one SEED allocation per bound thread | needs a design | About 40 bound threads exhaust SEED; fund from the caller |
| `BIN_128`, `BIN_512`, `NUM_SUBPAGE_BINS` | `core/kernel/src/cap/retype.rs` | 128, 512; 2 | encoding artefact (object size classes) | 16 B per Memory object | correct as is | None |
| `try_alloc_page_block` walk bound | `core/kernel/src/cap/retype.rs` | 1024 nodes | unknown | none | needs a design | A longer legitimate list is reported as a cycle and gives a false OOM (#634) |
| EventQueue, Notification size asserts | `core/kernel/src/cap/retype.rs` | wrapper 24, header 16 | encoding artefact | none | correct as is | Keep |
| `MAX_REVOKE_EDITS` (`REVOKE_OBJECTS`) | `core/kernel/src/cap/derivation.rs` | 256 | batch size (subtrees of any size revoke in batches) | 2 KiB BSS | correct as is | None |
| `MAX_REPARENT_EDITS` | `core/kernel/src/cap/derivation.rs` | 256 | batch size | none | correct as is | None |
| `MAX_REPARENT_BATCHES` | `core/kernel/src/cap/derivation.rs` | `1 << 20` | current peak plus headroom (a split rolls back on hitting it, so a retry repeats the work) | none | needs a design | A node with more than about 2.7e8 children (about 19 GiB of slots) can never be split; keep progress across retries |
| `DerivationLock` reader count | `core/kernel/src/cap/derivation.rs` | `u32`, `u32::MAX` = writer | provably unreachable (readers at most CPUs) | 4 B | correct as is | None |
| `KernelObjectHeader.ref_count` | `core/kernel/src/cap/object.rs` | `AtomicU32`, unchecked increment | unknown | 4 B per object | needs a design | 2^32 references are reachable from userspace on large machines; wrap frees a live object (#633) |
| `RANGE_COPY_LIMIT` | `core/kernel/src/cap/object.rs` | 64 per lineage | BSS budget (protects SEED) | none | needs a design | Lift once copies are caller-funded |
| `ROOT_SHARE` (`RangeLineage.live`) | `core/kernel/src/cap/object.rs` | `1 << 31` in `u32` | encoding artefact | embedded | correct as is | None |
| `MMIO_MAX_MAPPINGS` (`MmioObject.mappings`) | `core/kernel/src/cap/object.rs` | 4 | BSS budget (`MmioObject` fits the 128 B bin) | 64 B per Mmio object | needs a design | Spill records to a caller-funded page |
| `INLINE_RECORDS` (`PagePool.inline`) | `core/kernel/src/cap/object.rs` | 16 | encoding artefact (spills to record pages beyond) | 384 B per pool | correct as is | Unbounded through record pages |
| `SEED_BATCH_PAGES` | `core/kernel/src/cap/object.rs` | 64 | batch size (lock-hold bound) | none | correct as is | The total window is #434 |
| `RECORDS_PER_PAGE` | `core/kernel/src/cap/object.rs` | 170 | encoding artefact | none | correct as is | None |
| `MAX_CASCADE` (`dealloc_object` worklist) | `core/kernel/src/cap/object.rs` | 32 | current peak plus headroom (fan-out 16 plus ancestors) | 256 B stack | needs a design | Overflow drops entries silently; make the worklist intrusive or const-assert the fan-out sum |
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
| `WAIT_SET_MAX_MEMBERS` | `core/kernel/src/ipc/wait_set.rs` | 16 | BSS budget (512 B retype bin) | about 400 B per wait set | make pay-as-you-go | Caller-sized at create, as EventQueue capacity is |
| Wait-set member indices | `core/kernel/src/ipc/wait_set.rs` | `u8` | encoding artefact (at most 255 members) | embedded | correct as is | Widen with caller-sized sets |
| `WaitSetState.waiters` | `core/kernel/src/ipc/wait_set.rs` | 1 | unknown | none | needs a design | A second waiter is refused (#464) |
| One wait set per source | `core/kernel/src/ipc/wait_set.rs` | 1 | design choice (bounds no capacity) | 8 B per source | correct as is | None |
| Wait-set size asserts | `core/kernel/src/ipc/wait_set.rs` | member 24 B, state at most 440 B | encoding artefact | none | correct as is | Keep |
| Bound-source backoff | `core/kernel/src/ipc/mod.rs` | 64 spins | tuning (a backoff, not a bound) | none | correct as is | None |
| `MAX_SLEEPING` (`SLEEP_LIST`, `EXPIRED_SCRATCH`) | `core/kernel/src/sched/mod.rs` | 128 | current peak plus headroom | about 5 KiB BSS | needs a design | Caps sleepers and timed IPC waits system-wide; intrusive per-CPU deadline structure |
| `NUM_PRIORITY_LEVELS` | `core/kernel/src/sched/mod.rs` | 32 | ABI width (`u32` `non_empty` mask; `PRIORITY_MAX` 30) | 32 run queues per CPU | correct as is | None (#215) |
| `TIME_SLICE_TICKS` | `core/kernel/src/sched/mod.rs` | 10 | tuning | none | correct as is | None |
| `KERNEL_STACK_PAGES` | `core/kernel/src/sched/mod.rs` | 4 (16 KiB) | stack budget (call depth unaudited) | 4 pages per thread, caller-funded | needs a design | Audit kernel call depth and the stack locals that scale with `MAX_CPUS` (#636) |
| `MAX_CPUS` | `core/kernel/src/sched/mod.rs` | 512 (`boot_protocol::MAX_CPUS`) | ABI width (boot protocol) | see the per-CPU rows | needs a design | See the boot section |
| `TICK_HEARTBEAT`, `SPIN_SITE`, `LOCK_WAIT_KIND`, `LOCK_WAIT_WORD`, `CPU_SYSCALL_NR` | `core/kernel/src/sched/mod.rs` | `[_; MAX_CPUS]` | ABI width (`MAX_CPUS`) | about 16 KiB BSS | make pay-as-you-go | Move into the per-CPU slab (#636) |
| `stop_threads_bound_to` `prod` | `core/kernel/src/sched/mod.rs` | `[bool; MAX_CPUS]` | ABI width (`MAX_CPUS`) | 512 B kernel stack | make pay-as-you-go | Use a `CpuMask` (#636) |
| `WATCHDOG_THRESHOLD_TICKS`, `DETECTOR_SCAN_INTERVAL_TICKS` | `core/kernel/src/sched/mod.rs` | 3000 / 512 ticks | unknown (assumes a 1 ms tick) | none | needs a design | Express in seconds times `ticks_per_second()` |
| `WEDGE_GRACE_SECONDS` | `core/kernel/src/sched/mod.rs` | 8, scaled per 128 CPUs | tuning (scales with CPU count) | none | correct as is | None |
| `OWED_WAKE_MAX` (`OWED_WAKE_LAST`) | `core/kernel/src/sched/mod.rs` | 8 | diagnostic output cap | 64 B BSS | needs a design | Keyed by a random `u32` thread id; key by TCB pointer |
| `WATCHDOG_SLEEP_ENTRIES` | `core/kernel/src/sched/mod.rs` | 8 | diagnostic output cap | about 128 B stack | correct as is | None |
| `CS_SPIN_WARN_US` | `core/kernel/src/sched/mod.rs` | 100 000 us | diagnostic threshold | none | correct as is | None |
| `LOAD_BALANCE_IMBALANCE_THRESHOLD` | `core/kernel/src/sched/mod.rs` | 2 | tuning | none | correct as is | None |
| `PerCpuScheduler.load`, `non_empty` | `core/kernel/src/sched/run_queue.rs` | `AtomicU32` | provably unreachable (load at most threads, mask 32 bits) | per CPU | correct as is | None |
| `MAX_DEATH_OBSERVERS` (`ThreadControlBlock.death_observers`) | `core/kernel/src/sched/thread.rs` | 4 | current peak plus headroom (three binders) | 64 B per TCB | make pay-as-you-go | Chain caller-funded observer nodes |
| `DeathObserver.correlator`, posted exit reason | `core/kernel/src/sched/thread.rs` | `u32` correlator, low 32 bits of the reason | encoding artefact (one-word EQ entry) | embedded | needs a design | Userspace passes `badge as u32` as an identity; widen before process tables grow |
| `ThreadControlBlock.thread_id` | `core/kernel/src/sched/thread.rs` | random `u32` | provably unreachable as an identity (diagnostic only; no lookup, not exposed) | 4 B per TCB | correct as is | Widen if ever exposed |
| `park_seq`, `start_seq`, `park_episode`, `deposit_episode` | `core/kernel/src/sched/thread.rs` | `u32` | provably unreachable (freshness inside one short window) | embedded | correct as is | None |
| `ThreadControlBlock.cspace_epoch` | `core/kernel/src/sched/thread.rs` | `u32` | encoding artefact (mirrors the registry epoch) | 4 B per TCB | correct as is | None |
| `ThreadControlBlock.cpu_affinity` | `core/kernel/src/sched/thread.rs` | one CPU index or none | design choice | embedded | correct as is | A set affinity would need a `CpuMask` |
| `death_observer_count` | `core/kernel/src/sched/thread.rs` | `u8` | encoding artefact (at most `MAX_DEATH_OBSERVERS`) | 1 B per TCB | correct as is | None |
| `MAX_GROW_LEAVES_PER_HOLD` | `core/kernel/src/syscall/cap.rs` | 64 | batch size (lock-hold bound) | none | correct as is | None |
| `MAX_REVOKE_BATCHES` | `core/kernel/src/syscall/cap.rs` | `1 << 20` | batch size (a retry after `Interrupted` resumes; revoked nodes stay revoked) | none | correct as is | None |
| `TRAMPOLINE_FRAME_SIZE` | `core/kernel/src/syscall/cap.rs` | 512 B | encoding artefact (fixed trampoline frame) | none | correct as is | None |
| `sys_ipc_recv` cap-slot preallocation | `core/kernel/src/syscall/ipc.rs` | `MSG_CAP_SLOTS_MAX` slots | encoding artefact | none | correct as is | Follows `MSG_CAP_SLOTS_MAX` |

### Kernel: interrupts and architecture

The entries left open are tracked by the Issue each recommendation names: the vector space by
[#325](https://github.com/kottlerg/seraph/issues/325), the per-CPU slabs by
[#636](https://github.com/kottlerg/seraph/issues/636), the vector-register save area by
[#658](https://github.com/kottlerg/seraph/issues/658), and `IOAPICS` by the boot section's Issue.

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| IRQ routing table (`irq::init_table`) | `core/kernel/src/irq.rs` | one entry per line the discovered controllers implement (`interrupts::irq_line_count`) | hardware (the discovered I/O APICs' GSIs; the PLIC's `riscv,ndev`) | 24 B per line from the buddy at Phase 5 | correct as is | None |
| `unregister_notification` walk | `core/kernel/src/irq.rs` | the routed lines (`LineSet`) | provable unreachability (scales with the registrations) | none | correct as is | None |
| `IrqRoute.notification` | `core/kernel/src/irq.rs` | one per line | single owner per wired line: devmgr delegates no shared `INTx` line, and shared sources get message-signaled interrupts (#325) | none | correct as is | None |
| x86_64 `DEVICE_VECTOR_COUNT` (`VECTOR_GSI`) | `core/kernel/src/arch/x86_64/ioapic.rs` | 217 device vectors (33-249), one generated stub each | hardware spec (x86 vector space less the exception, timer, IPI and spurious vectors), on one destination's vector space | 868 B BSS, 217 stubs of 16 B | needs a design | GSIs routed at once stop at 217; per-CPU vector spaces belong with the MSI work (#325) |
| x86_64 `ROOT_IRQ_COUNT`, `MAX_IRQ_ID` | `core/kernel/src/arch/x86_64/mod.rs` | `MAX_IOAPICS` x `IOAPIC_MAX_PINS` = 2048 / 2047 | ABI width (boot protocol) times hardware spec (8-bit redirection-entry count) | none | correct as is | Follows `MAX_IOAPICS`; a GSI above it is logged at boot |
| `IOAPIC_MAX_PINS` | `core/kernel/src/arch/x86_64/ioapic.rs` | 256 | hardware spec (I/O APIC version register) | none | correct as is | None |
| `DEVICE_VECTOR_BASE`, `DEVICE_VECTOR_LAST` and vector-range assert | `core/kernel/src/arch/x86_64/ioapic.rs`, `idt.rs` | 33, 249 | hardware spec (between the timer and IPI vectors) | none | correct as is | None |
| `IOAPICS` | `core/kernel/src/arch/x86_64/ioapic.rs` | `MAX_IOAPICS` = 8 | ABI width (boot protocol) | 128 B BSS | raise | See the boot section |
| `IDT` | `core/kernel/src/arch/x86_64/idt.rs` | 256 entries | hardware spec (x86 vector space) | 4 KiB BSS | correct as is | None |
| `GDT`, AP GDTs | `core/kernel/src/arch/x86_64/gdt.rs` | 7 descriptors | hardware spec (fixed descriptor layout) | 56 B per CPU | correct as is | None |
| `IOPB_SIZE` (`TssWithIopb.iopb`) | `core/kernel/src/arch/x86_64/gdt.rs` | 8192 B | hardware spec (65536 ports / 8) | about 8.3 KiB per CPU | correct as is | None |
| TSS slab assert | `core/kernel/src/arch/x86_64/gdt.rs` | `MAX_CPUS` x TSS within `2^MAX_ORDER` pages | BSS budget (one-block slab) | none | needs a design | Follows the per-CPU slab design (#636) |
| `IST_STACK_SIZE` (`BSP_IST_STACKS`) | `core/kernel/src/arch/x86_64/interrupts.rs` | 8 KiB x 2 | stack budget for the fixed NMI, #DF and #MC paths, audited: worst case under 3.7 KiB, debug and release builds | 16 KiB BSS | correct as is | None |
| `AP_IST_PAIR_SIZE` | `core/kernel/src/arch/x86_64/ap_trampoline.rs` | 16384 | encoding artefact (two IST stacks) | `cpu_count` x 16 KiB | correct as is | Derive as `2 * IST_STACK_SIZE` |
| AP IST slab assert | `core/kernel/src/arch/x86_64/ap_trampoline.rs` | 512 x 16 KiB = 8 MiB, at the limit | BSS budget (one-block slab) | none | needs a design | The binding `MAX_CPUS` constraint (#636) |
| Trampoline template and SIPI widths | `core/kernel/src/arch/x86_64/ap_trampoline.rs` | page-sized; PML4 below 4 GiB | hardware spec (real-mode SIPI, 32-bit CR3 load) | one page | correct as is | None |
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
| riscv64 `MAX_IRQ_ID`, `PLIC_MAX_SOURCES` | `core/kernel/src/arch/riscv64/mod.rs`, `interrupts.rs` | 1023 | hardware spec (PLIC) | none | correct as is | None |
| riscv64 `plic_ndev` | `core/kernel/src/arch/riscv64/platform.rs` | the firmware's `riscv,ndev`, clamped to 1023; 1023 when unreported | hardware (discovered) | none | correct as is | None |
| riscv64 `SOURCE_TARGET` | `core/kernel/src/arch/riscv64/interrupts.rs` | 1024 entries | hardware spec (PLIC id space) | 4 KiB BSS | correct as is | None |
| riscv64 `ROOT_IRQ_COUNT` | `core/kernel/src/arch/riscv64/mod.rs` | 1024 | hardware spec (PLIC id space) | none | correct as is | None |
| riscv64 `DEFAULT_PLIC_SIZE` | `core/kernel/src/arch/riscv64/platform.rs` | 64 MiB | hardware spec (PLIC register map, 15 872 contexts) | none | correct as is | None |
| device IRQ destination (`irq::next_target_cpu`) | `core/kernel/src/irq.rs` | one CPU per line, the CPUs in turn at route time; x86_64 only APIC ids below 255 | hardware spec (one PLIC context per source; the 8-bit physical destination of an I/O APIC entry without interrupt remapping, 255 being broadcast) | none | correct as is | None |
| riscv64 `MAX_VLENB` | `core/kernel/src/arch/riscv64/fpu.rs` | 64 (VLEN 512) | BSS budget (one 4 KiB save page per thread) | one page per thread | make pay-as-you-go | Boot halts at VLEN above 512; size the save area from `vlenb` (#658) |
| riscv64 ASID mask | `core/kernel/src/arch/riscv64/cpu.rs` | 16 bits | hardware spec (`satp`) | none | correct as is | Clipped by `TAG_CAP` |
| riscv64 `sbi_hart_mask` window | `core/kernel/src/arch/riscv64/interrupts.rs` | 64 harts per call | hardware spec (SBI `hart_mask`) | none | correct as is | None |
| riscv64 `NAPOT_64K_PAGES` | `core/kernel/src/arch/riscv64/paging.rs` | 16 | hardware spec (Svnapot) | none | correct as is | None |
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
| `MSG_DATA_WORDS_MAX` | `abi/syscall/src/lib.rs` | 64 | ABI width (IPC buffer layout) | about 550 B per TCB | correct as is | Bulk data moves through Memory caps (#36, #40) |
| IPC buffer layout | `abi/syscall/src/lib.rs` | data words 0..64, count at 64, handles 65..69, in one page | ABI width | 4 KiB per thread | correct as is | None |
| `CAP_INDEX_BITS + 8 <= 32` assert | `abi/syscall/src/lib.rs` | compile time | ABI width | none | correct as is | Keep |
| `EVENT_QUEUE_MAX_CAPACITY` | `abi/syscall/src/lib.rs` | 4096 | unknown (the ring is caller-funded) | none | raise | A supervisor watching more deaths drops posts; raise to the retype limit |
| `PRIORITY_MIN`, `PRIORITY_MAX` | `abi/syscall/src/lib.rs` | 1 / 30 | ABI width (32-level mask: 0 idle, 31 reserved) | none | correct as is | None (#215) |
| `MAX_GETRANDOM_LEN` | `abi/syscall/src/lib.rs` | 256 B | per-call bound (callers loop; it bounds the interrupts-off window) | 256 B stack | correct as is | None |
| `CAP_INFO_MEMORY_MAPPINGS_MAX_PAGES` | `abi/syscall/src/lib.rs` | 512 pages | per-call bound on the `frame_map` scan | none | raise | A Memory cap over 2 MiB is refused; take an offset window |
| `encode_exit_code` range | `abi/syscall/src/lib.rs` | 12-bit code below `EXIT_FAULT_BASE` | encoding artefact (flat exit-reason space) | none | correct as is | Saturates; never aliases success |
| `KERNEL_VERSION` packing | `abi/syscall/src/lib.rs` | 32 / 16 / 16 bits | encoding artefact | none | correct as is | None |

### Bootloader and boot ABIs

Tracked by [#640](https://github.com/kottlerg/seraph/issues/640).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `MAX_CPUS` (`BootInfo.cpu_ids`) | `abi/boot-protocol/src/lib.rs` | 512 | BSS budget (`BootInfo` fits one page) | 2 KiB of the `BootInfo` page plus kernel `[_; MAX_CPUS]` statics | needs a design | Shipping two-socket servers have 768 logical CPUs; a slice in its own pages |
| `INIT_MAX_SEGMENTS` (`InitImage.segments`) | `abi/boot-protocol/src/lib.rs` | 8 | provably unreachable (the in-tree init has 4 LOAD segments on x86_64; overflow is an error) | 256 B in `BootInfo` | correct as is | None |
| `BOOT_MODULE_NAME_LEN`, `ENTRY_NAME_LEN` | `abi/boot-protocol/src/lib.rs`, `bundle.rs` | 32 | ABI width (bundle wire format) | per module | correct as is | Tie the copies with a const assert |
| `BundleHeader.entry_count` | `abi/boot-protocol/src/bundle.rs` | `u32` | ABI width | none | correct as is | The binding cap is core/boot `MAX_MODULES` |
| `MAX_IOAPICS` (`KernelMmio.ioapics`) | `abi/boot-protocol/src/lib.rs` | 8 | unknown | 192 B in `BootInfo` | raise | Truncation loses GSIs on multi-socket servers |
| `MAX_MMIO_DIRECT_MAP_REGIONS` | `abi/boot-protocol/src/layout.rs` | 16 | provably unreachable today (`1 + MAX_IOAPICS` = 9), unasserted | 256 B stack | correct as is | Pin with a const assert |
| `MAX_APERTURES` | `abi/boot-protocol/src/lib.rs` | 16 | unknown | 256 B of a dedicated page | raise | The page holds 256; the surplus is dropped today |
| `MAX_RECLAIM_RANGES` | `abi/boot-protocol/src/lib.rs` | 256 | BSS budget (one page) | one page, reclaimed | needs a design | The bootloader spin-halts on overflow; tie to `FRAME_LOG_CAP` |
| `ReclaimRange.page_count` | `abi/boot-protocol/src/lib.rs` | `u32` pages | ABI width (16 B entry) | embedded | correct as is | 16 TiB per range |
| `BootInfo.boot_entropy_seed` | `abi/boot-protocol/src/lib.rs` | 32 B | hardware spec (256-bit seed) | 32 B | correct as is | None |
| `IMAGE_WINDOW_SIZE` | `abi/boot-protocol/src/layout.rs` | 2 GiB | hardware spec (small and medany code-model reach) | none | correct as is | None |
| `INIT_MAX_NAMED_MODULES` (`InitInfo.module_names`) | `abi/init-protocol/src/lib.rs` | 12 | current peak plus headroom (8 in use) | 480 B | raise | The bootloader accepts 16; unify with `MAX_MODULES` and fail loudly |
| `INIT_MODULE_NAME_LEN` | `abi/init-protocol/src/lib.rs` | 32 | ABI width (equals `BOOT_MODULE_NAME_LEN`) | per name | correct as is | Const-assert equality at the kernel boundary |
| `INIT_INFO_MAX_PAGES` | `abi/init-protocol/src/lib.rs` | 4 | unknown | none (allocated at actual size) | raise | Phase 9 fatals past about 650 descriptors; size from the count |
| `INIT_STACK_PAGES` | `abi/init-protocol/src/lib.rs` | 4 | provably unreachable (init's own stack, whose depth the in-tree init fixes) | 16 KiB | correct as is | None |
| `InitInfo` count and slot fields | `abi/init-protocol/src/lib.rs` | `u32` | ABI width (cap handle) | embedded | correct as is | None |
| `InitInfo` size assert | `abi/init-protocol/src/lib.rs` | at most `INIT_INFO_MAX_PAGES` pages | ABI width | none | correct as is | Also assert the header fits page 1 |
| `MAX_MODULES` (`ModulesLoad.modules`) | `core/boot/src/main.rs` | 16 | current peak plus headroom (8 in use) | 768 B stack | raise | The output page holds 85; unify with `INIT_MAX_NAMED_MODULES` (#183) |
| `MEM_MAP_ENTRY_PAGES` | `core/boot/src/main.rs` | 4 (about 682 entries) | unknown | 16 KiB, reclaimed | raise | `translate_memory_map` truncates silently; size from the firmware count |
| `KERNEL_STACK_PAGES` (bootloader) | `core/boot/src/main.rs` | 16 (64 KiB) | stack budget (the kernel runs its boot phases on this stack; depth unaudited) | 64 KiB | needs a design | Audit with the kernel stack (#636) |
| `MAX_IDENTITY_REGIONS` | `core/boot/src/main.rs` | 64 | provably unreachable (`MAX_LOAD_SEGMENTS + INIT_MAX_SEGMENTS + 9` = 25 at most) | 1 KiB stack | correct as is | Pin the sum with a const assert |
| `MAX_APERTURE_SEEDS` | `core/boot/src/main.rs` | 64 | unknown | 1 KiB stack | raise | Silent drop past `out.len()` |
| `MAX_HEURISTIC_SEEDS` | `core/boot/src/main.rs` | 16 | current peak plus headroom | 256 B stack | raise | More than about 7 MCFG segments drop windows |
| `derive_mmio_apertures` `SCRATCH` | `core/boot/src/memory_map.rs` | `MAX_APERTURES * 4` = 64 | current peak plus headroom | 1 KiB stack | raise | Raise with `MAX_APERTURES` |
| `get_memory_map` slack | `core/boot/src/uefi.rs` | 16 descriptors | provably unreachable (only the buffer's own allocation lands between the size query and the fill; overflow fails the boot loudly) | a few hundred bytes | correct as is | None |
| `EXIT_BOOT_SERVICES_MAX_ATTEMPTS` | `core/boot/src/uefi.rs` | 16 | provably unreachable (residual failure odds below 1e-14) | none | correct as is | None |
| `FILE_INFO_BUF_LEN` | `core/boot/src/uefi.rs` | `size_of::<EfiFileInfo>() + 256` | provably unreachable (fixed short ESP file names) | about 350 B stack | correct as is | None |
| `TARGET_FB_WIDTH`, `TARGET_FB_HEIGHT` | `core/boot/src/uefi.rs` | 1280 x 720 | policy (bounds no capacity) | none | correct as is | None |
| `MAX_LOAD_SEGMENTS` (`KernelInfo.segments`) | `core/boot/src/elf.rs` | 8 | provably unreachable (the in-tree kernel has 5 LOAD segments on x86_64; overflow is an error) | embedded | correct as is | None |
| `FRAME_LOG_CAP` | `core/boot/src/arch/x86_64/paging.rs`, `arch/riscv64/paging.rs` | 128 / 160 | current peak plus headroom | about 1 KiB embedded | raise | Grows with framebuffer and bundle size; 2 MiB leaves or coalescing |
| dtb `MAX_DEPTH` | `core/boot/src/dtb.rs` | 8 | unknown | stack | raise | Deeper nodes are skipped silently |
| dtb `MAX_REG_ENTRIES`, `MAX_IRQ_ENTRIES` | `core/boot/src/dtb.rs` | 8 / 4 | unknown | embedded per node | needs a design | Truncation is silent; diagnose |
| dtb `MAX_RANGES_ENTRIES` | `core/boot/src/dtb.rs` | 4 | unknown | 96 B per node | raise | Host-bridge `ranges` can carry more windows |
| `cpu_ids` truncation arrays | `core/boot/src/acpi.rs`, `dtb.rs`, `firmware.rs` | `[u32; MAX_CPUS]` | ABI width (`MAX_CPUS`) | 2 KiB stack each | needs a design | Follows the `MAX_CPUS` design |

### Process layout and ruststd

Tracked by [#641](https://github.com/kottlerg/seraph/issues/641).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `LAYOUT_VA_CEILING` | `shared/process-layout/src/lib.rs` | `1 << 38` | hardware spec (Sv39 user half), applied on every architecture | none | needs a design | Per-architecture, per-paging-mode ceiling |
| `IMAGE_MAX_SPAN` | `shared/process-layout/src/lib.rs` | 1 GiB | unknown | none | raise | Derive from the per-architecture ceiling |
| Window `slots_log2` values | `shared/process-layout/src/lib.rs` | 21, 23 | encoding artefact (ASLR budget under the ceiling) | none | correct as is | None |
| `MAX_WINDOW_REGION_PAGES` | `shared/process-layout/src/lib.rs` | 512 | current peak plus headroom (stack 1 + 256) | none | needs a design | Pin against `MAX_PROCESS_STACK_PAGES` with a const assert |
| `HEAP_ZONE_END`, ruststd `HEAP_SPAN` | `shared/process-layout/src/lib.rs`, `runtime/ruststd/src/sys/alloc/seraph.rs` | zone end 4 GiB (`0x1_0000_0000`); span 1 GiB | encoding artefact (zone map under 2^38) | none (VA only) | needs a design | No process can hold more than 1 GiB of heap |
| `RESERVE_ARENA_ZONE_END`, `RESERVE_ARENA_PAGES` | `shared/process-layout/src/lib.rs`, `runtime/ruststd/src/sys/reserve/seraph.rs` | zone end `0x20_1000_0000`; arena 256 MiB | current peak plus headroom | none (VA only) | raise | About 120 demand stacks exhaust it, then stacks fall back unguarded |
| Zone-map asserts | `shared/process-layout/src/lib.rs` | 10 asserts | encoding artefact | none | correct as is | Keep |
| `LAYOUT_ENTROPY_BYTES` | `shared/process-layout/src/lib.rs` | 32 | provably unreachable (exactly four surfaces) | none | correct as is | None |
| `DEFAULT_PROCESS_STACK_PAGES` | `abi/process-abi/src/lib.rs` | 8 | default (per-binary override exists) | 32 KiB per process | correct as is | None |
| `MAX_PROCESS_STACK_PAGES` | `abi/process-abi/src/lib.rs` | 256 (1 MiB) | unknown | none | raise | Raise (VA-only cost) and reject instead of clamping (#46) |
| `PROCESS_MAIN_TLS_MAX_PAGES` | `abi/process-abi/src/lib.rs` | 4 | unknown | none | raise | Size from `PT_TLS` |
| `ProcessInfo` page (argv and env blobs share it) | `abi/process-abi/src/lib.rs` | 4096 B less the struct | BSS budget (one page) | 4 KiB per process | needs a design | See the argv entries in the procmgr section (#643) |
| `ProcessInfo.initial_priority` | `abi/process-abi/src/lib.rs` | `u8` | ABI width (`PRIORITY_MAX` 30) | none | correct as is | None |
| `ProcessInfo` cap fields | `abi/process-abi/src/lib.rs` | `u32` | ABI width (cap handle) | embedded | correct as is | Follows the handle-width decision (#637) |
| `HEAP_BASE_SLOTS_LOG2` | `runtime/ruststd/src/sys/alloc/seraph.rs` | 19 | encoding artefact (ASLR window) | none | correct as is | Revisit with `HEAP_SPAN` |
| `HEAP_INITIAL_PAGES` | `runtime/ruststd/src/sys/alloc/seraph.rs` | 512 (2 MiB) | current peak plus headroom | 2 MiB eager RAM per std process | make pay-as-you-go | Demand-back the heap floor |
| `GROW_MAX_PAGES` | `runtime/ruststd/src/sys/alloc/seraph.rs` | 256 (1 MiB) | unknown | none | raise | One allocation above the tail plus 1 MiB fails; grow to fit |
| `GROW_MIN_PAGES` | `runtime/ruststd/src/sys/alloc/seraph.rs` | 16 | tuning | none | correct as is | None |
| `MAX_ROUNDS` (`grow_exact`) | `runtime/ruststd/src/sys/alloc/seraph.rs` | 16 | provably unreachable (anti-wedge bound) | none | correct as is | None |
| `PT_FUND_ROUNDS` | `runtime/ruststd/src/sys/alloc/seraph.rs` | 2 | provably unreachable (record-page argument) | none | correct as is | None |
| `SLAB_SHELF_SIZE` | `runtime/ruststd/src/sys/alloc/seraph.rs` | 4 | tuning (overflow strands a run until exit, bounded) | 192 B static | correct as is | None |
| `ALLOCATOR_METADATA_RESERVE` | `runtime/ruststd/src/sys/alloc/seraph.rs` | 64 | tuning (slack) | none | correct as is | None |
| `RESERVE_ARENA_SLOTS_LOG2` | `runtime/ruststd/src/sys/reserve/seraph.rs` | 24 | encoding artefact (ASLR window) | none | correct as is | Revisit with the arena zone |
| reserve `MAX_FREE_RUNS` (`Arena.runs`) | `runtime/ruststd/src/sys/reserve/seraph.rs` | 64 | unknown | about 1.5 KiB static | make pay-as-you-go | A full table leaks freed VA silently |
| `REAPER_SLOTS` (`Registry.slots`) | `runtime/ruststd/src/sys/thread/seraph.rs` | 64 | unknown | about 6 KiB static | make pay-as-you-go | Detached threads past 64 leak until exit |
| thread `EQ_CAPACITY` | `runtime/ruststd/src/sys/thread/seraph.rs` | 128 | unknown | about 1 KiB retype | raise | Overflow drops death posts |
| `GEN_BITS` correlator | `runtime/ruststd/src/sys/thread/seraph.rs` | 26-bit generation, 6-bit slot | encoding artefact (`u32` payload half) | none | correct as is | Freshness-only; pin `REAPER_SLOTS` against it with a const assert |
| `DEFAULT_DEMAND_STACK_PAGES` | `runtime/ruststd/src/sys/thread/seraph.rs` | 512 (2 MiB) | default (VA only, lazy) | none | correct as is | Multiplies against the reserve arena (#46) |
| `GUARD_PAGES` | `runtime/ruststd/src/sys/thread/seraph.rs` | 1 | unknown | VA only | raise | A frame over 4 KiB can step over it |
| `DEFAULT_MIN_STACK_SIZE` | `runtime/ruststd/src/sys/thread/seraph.rs` | 64 KiB | default (matches the upstream platform layer) | eager on the fallback path | correct as is | None |
| `THREAD_RETYPE_BYTES` | `runtime/ruststd/src/sys/thread/seraph.rs` | 5 pages | encoding artefact, short of the kernel's 6-page `dispatch_for(Thread)`; it works only because `ALLOCATOR_METADATA_RESERVE` rounds the request up to 6 pages | 24 KiB per thread | needs a design | Export the size from abi/syscall so it cannot drift |
| `DEATH_EQ_CAPACITY` (process) | `runtime/ruststd/src/sys/process/seraph.rs` | 4 | provably unreachable (four post sources, each posting at most once per child) | about 112 B per child | correct as is | None |
| `Process::id` | `runtime/ruststd/src/sys/process/seraph.rs` | `u32` | ABI width (upstream `Child::id` is `u32`) | none | correct as is | None |
| pipe `RING_CAPACITY` | `runtime/ruststd/src/sys/pipe/seraph.rs` | 2048 | encoding artefact (largest power of two in one page after the header) | 4 KiB per direction | correct as is | None |
| `STDIN_BUF_SIZE` | `runtime/ruststd/src/sys/stdio/seraph.rs` | 512 | streaming chunk (a longer read refills from the stdin pipe) | 512 B | correct as is | None |
| `READ_INLINE_THRESHOLD`, `WRITE_INLINE_THRESHOLD` | `runtime/ruststd/src/sys/fs/seraph.rs` | 504 | ABI width (`MSG_DATA_WORDS_MAX`) | none | correct as is | Larger transfers use frames (#87) |
| Rename name-sum limit | `runtime/ruststd/src/sys/fs/seraph.rs` | 496 B | ABI width (`MSG_DATA_WORDS_MAX`) | none | correct as is | None (#89) |
| Path component limit | `runtime/ruststd/src/sys/fs/seraph.rs` | 255 (`MAX_NAME_LEN`) | ABI width (namespace protocol) | none | correct as is | None |
| `READ_WAIT` | `runtime/ruststd/src/sys/fs/release_handler.rs` | 100 ms | ABI width (the driver's cooperative-release window) | none | correct as is | None |
| `SPIN_BUDGET` | `runtime/ruststd/src/sys/time/seraph.rs` | `1 << 20` | unknown (spin count) | none | needs a design | Time-based bound |
| `Mutex::spin` count | `runtime/ruststd/src/sys/sync/mutex/seraph.rs` | 100 | tuning (a backoff before parking) | none | correct as is | None |
| `MAX_READERS` | `runtime/ruststd/src/sys/sync/rwlock/seraph.rs` | `2^30 - 2` | provably unreachable short of leaked guards (more than any thread count; past it readers wait) | 4 B per lock | correct as is | None |

### Shared IPC and protocol crates

Tracked by [#643](https://github.com/kottlerg/seraph/issues/643) (argv, names, registry, elf),
[#641](https://github.com/kottlerg/seraph/issues/641) (shmem), and
[#645](https://github.com/kottlerg/seraph/issues/645) (log).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `ARGS_BLOB_MAX` | `shared/ipc/src/lib.rs` | 256 B | current peak plus headroom; inline in one message | none | needs a design | argv and env through a Memory cap |
| CREATE_FROM_FILE `args_bytes`, `env_bytes` | `shared/ipc/src/lib.rs` | `u16` | encoding artefact (label bit packing) | none | needs a design | Widen with the blob design |
| CREATE_FROM_FILE `args_count`, `env_count` | `shared/ipc/src/lib.rs` | `u8` | encoding artefact (label bit packing) | none | needs a design | Unreachable at 256 B blobs; binds once blobs grow |
| `MAX_PATH_LEN` | `shared/ipc/src/lib.rs` | 48 | unknown (the "6 IPC words" rationale is stale) | 96 B per svcmgr service | raise | One path limit |
| `CREATE_SCHED_FIELD_MASK` | `shared/ipc/src/lib.rs` | 5 bits | ABI width (32 priority levels) | none | correct as is | None |
| `BASELINE_PRIORITY_MAX`, `DEVMGR_BAND_MAX` | `shared/ipc/src/lib.rs` | 28 / 26 | encoding artefact (policy placement in 32 levels) | none | correct as is | None |
| `INIT_REAP_CORRELATOR`, per-child correlator | `shared/ipc/src/lib.rs` | `u32` | ABI width (kernel death correlator) | none | needs a design | Collides once tables grow (#638) |
| `memmgr_grant_layout` caps per reply | `shared/ipc/src/lib.rs` | `MSG_CAP_SLOTS_MAX` | ABI width (4 caps per reply); a request spread over more runs fails | none | needs a design | memmgr returns a partial best-effort grant and callers loop (#642) |
| `memmgr_bootstrap::MAX_MEMORY_CAPS` | `shared/ipc/src/lib.rs` | `(MSG_DATA_WORDS_MAX - 3) * 2` = 122 | encoding artefact (one bootstrap round) | none | needs a design | Overflow spills through init's reap donation; confirm it loses nothing (#642) |
| phys-table index constants (`FACTS_*`, `IN_USE_*`) | `shared/ipc/src/lib.rs` | 128 to 131 | encoding artefact (one-page layout) | none | correct as is | Pin `MAX_MEMORY_CAPS <= FACTS_SYSTEM_RAM_IDX` with a const assert |
| `MAX_IN_USE`, `IN_USE_WORDS` | `shared/ipc/src/lib.rs` | 4 / 3 | provably unreachable (three tier-1 producers) | none | correct as is | Pin the page fit with a const assert |
| svcmgr and namespace label name lengths | `shared/ipc/src/lib.rs` | 16-bit fields | encoding artefact | none | correct as is | The binding limits are the name constants |
| FS_WRITE, FS_READ inline payloads | `shared/ipc/src/lib.rs` | 504 B per call | ABI width (`MSG_DATA_WORDS_MAX`) | none | correct as is | Large transfers use the memory verbs (#87) |
| FS_READ_MEMORY, FS_WRITE_MEMORY | `shared/ipc/src/lib.rs` | one page per call | encoding artefact (one slot cap per reply) | none | correct as is | Callers iterate; batching is a throughput question (#229) |
| FS_READ_MEMORY release cookie | `shared/ipc/src/lib.rs` | `u64`, client-chosen | ABI width | none | correct as is | None (#530) |
| QUERY_DEVICE_INFO badge | `shared/ipc/src/lib.rs` | `u64` | encoding artefact (catalog index plus one, never recycled once delivered) | none | correct as is | None |
| `blk_labels` partition badges | `shared/ipc/src/lib.rs` | `u64`, monotonic | ABI width | none | correct as is | None |
| `INVALID_MEMORY_CAP` byte limit | `shared/ipc/src/lib.rs` | `count * 512 <= u32::MAX` | hardware spec (VirtIO descriptor `u32` length) | none | correct as is | 4 GiB per request |
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
| `registry::NAME_MAX` | `shared/registry/src/lib.rs` | 16 | current peak plus headroom (longest name 15 B) | per entry | raise | One name limit |
| `Registry<N>.entries` | `shared/registry/src/lib.rs` | caller's `N` (svcmgr 16) | current peak plus headroom (set by svcmgr) | about 24 B per entry | make pay-as-you-go | Growable registry |
| `Entry.name_len`, `Entry.cap` | `shared/registry/src/lib.rs` | `u8`, `u32` | ABI width (cap handle); length unreachable | 5 B per entry | correct as is | None |
| `registry-client` `NAME_MAX`, `NAME_WORDS` | `shared/registry-client/src/lib.rs` | 16 / 2 | copy of `registry::NAME_MAX` | 16 B stack | raise | Share one constant or pin with a test |
| `REGISTRY_CAP`, `BADGEED_CAP` | `shared/registry-client`, `shared/log` | `AtomicU32` | ABI width (cap handle) | 4 B | correct as is | None (#74) |
| log `CHUNK_SIZE` | `shared/log/src/lib.rs` | 512 | ABI width (`MSG_DATA_WORDS_MAX * 8`) | none | correct as is | None |
| log `STACK_BUF_LEN` | `shared/log/src/lib.rs` | 512 | ABI width | 512 B stack per call | raise | Messages over 512 B are truncated; flush in chunks |
| shmem `MAX_PAGES` | `shared/shmem/src/lib.rs` | 4 (16 KiB) | ABI width (one single-page cap per slot) | none | needs a design | Multi-page caps or several rounds |
| `SharedBuffer.page_count` | `shared/shmem/src/lib.rs` | `u32` | provably unreachable (at most `MAX_PAGES`) | 4 B | correct as is | None |
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
| `MAX_RELA_TABLE_SIZE` | `shared/elf/src/lib.rs` | 4 MiB | current peak plus headroom and a hostile-input bound | none | raise | Streamed; bound by file size |
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

Tracked by [#642](https://github.com/kottlerg/seraph/issues/642).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `MAX_PROCESSES` (`ProcessTable.records`) | `services/memmgr/src/main.rs` | 64 | current peak plus headroom | about 1.5 KiB BSS | make pay-as-you-go | Arena-backed records with a badge index (#209) |
| `ProcessRecord` lookup | `services/memmgr/src/main.rs` | linear scan | BSS budget | none | needs a design | Hashed or indexed lookup with the dynamic table |
| Arena node index (`NODE_NULL`) | `services/memmgr/src/main.rs` | `u32`, sentinel `u32::MAX` | encoding artefact | 4 B per link | raise | Covers about 256 TiB of demand chunks, below the #177 target |
| `META_ARENA_CEILING` | `services/memmgr/src/main.rs` | about 39 GiB of VA above the base | encoding artefact (zone map under 2^38) | none | needs a design | About 64 TiB of demand-backed RAM; widen with the process layout |
| `META_ARENA_SLOTS_LOG2`, `PHYS_TABLE_TEMP_SLOTS_LOG2` | `services/memmgr/src/main.rs` | 21 | encoding artefact (ASLR window, asserted) | none | correct as is | None |
| zone-map assert | `services/memmgr/src/main.rs` | compile time | encoding artefact | none | correct as is | Extend when the arena widens |
| `NODES_PER_PAGE`, `NODE_SIZE` | `services/memmgr/src/main.rs` | `PAGE_SIZE / size_of::<Slot>()` | encoding artefact (no slot straddles a page) | none | correct as is | None |
| free-pool `MAX_FREE_RUNS` (`FreePool.runs`) | `services/memmgr/free-pool/src/lib.rs` | 512 | current peak plus headroom | about 12 KiB BSS | make pay-as-you-go | Parked runs are never allocatable; arena-backed (#209) |
| `coalesce_with` `order` | `services/memmgr/free-pool/src/lib.rs` | `[u16; MAX_FREE_RUNS]` | encoding artefact | 1 KiB stack | raise | Caps the pool at 65536 runs |
| `DEMAND_CHUNK_PAGES` | `services/memmgr/free-pool/src/lib.rs` | 16 | tuning (fault-around window) | none | correct as is | Adaptive window is #236 |
| `FreeRun.page_count` | `services/memmgr/free-pool/src/lib.rs` | `u32` pages (16 TiB per run) | ABI width (wire packs pages in 32 bits) | embedded | needs a design | `handle_donate_memory_caps` truncates silently; split oversized donations |
| REQUEST_MEMORY_CAPS `want_pages` | `services/memmgr/src/main.rs` | `u32` pages per request | encoding artefact | none | correct as is | Callers loop |
| `MAX_REPLY_CAPS` (`GrantArray`) | `services/memmgr/src/main.rs` | `MSG_CAP_SLOTS_MAX` | ABI width | 64 B stack | needs a design | A best-effort grant over more than 4 runs fails although RAM exists |
| `BOOTSTRAP_MAX_MEMORY_CAPS` | `services/memmgr/src/main.rs` | 122 | encoding artefact (one bootstrap round) | about 1.5 KiB stack | needs a design | Confirm the reap-donation spill loses nothing |
| `InitBootstrap.in_use` | `services/memmgr/src/main.rs` | `MAX_IN_USE` = 4 | provably unreachable (three tier-1 producers) | 96 B stack | correct as is | None |
| process badges | `services/memmgr/src/main.rs` | random `u64` | ABI width | none | correct as is | None |
| `POOL_TOTAL_PAGES` | `services/memmgr/src/main.rs` | `u64`, saturating | ABI width | 8 B | correct as is | None |
| memmgr CSpace slots | `services/init/src/main.rs` (`CSPACE_RETYPE_PAGES`) | 8231 slots, no augment | current peak plus headroom | 149 pages | needs a design | Caps outstanding grants, runs and chunks at about 8 k system-wide |

### procmgr

Tracked by [#643](https://github.com/kottlerg/seraph/issues/643).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `MAX_PROCESSES` (`ProcessTable.entries`) | `services/procmgr/process-table/src/lib.rs` | 32 | current peak plus headroom | about 2.8 KiB stack | make pay-as-you-go | Caps live user processes at 32; growable table after the correlator widening |
| death EQ capacity | `services/procmgr/src/main.rs` | `MAX_PROCESSES * 2` | provably unreachable while the table is fixed | about 0.6 KiB | needs a design | Growable or resync-on-full with a dynamic table |
| `RECENT_EXITS_SLOTS` | `services/procmgr/process-table/src/lib.rs` | 16 | unknown | 384 B | raise | Rotation turns a query into UNKNOWN; size from the death rate |
| death correlator `badge as u32` | `services/procmgr/src/process.rs`, `process-table/src/lib.rs` | low 32 bits | ABI width (kernel correlator) | none | needs a design | Accepted at 32 live; collides as the table grows (#638) |
| `dispatch_death` exit reason | `services/procmgr/src/main.rs` | `u32` | encoding artefact | none | correct as is | None |
| `CreateBlobs.args_buf`, `env_buf` | `services/procmgr/process-table/src/create_blobs.rs` | 256 B each | encoding artefact (one message) | about 530 B stack | needs a design | argv and env through a Memory cap |
| blob counts and lengths | `services/procmgr/process-table/src/create_blobs.rs` | `u8`, `u16` | encoding artefact | none | needs a design | Follows the blob design |
| `VFS_CHUNK_SIZE` | `services/procmgr/src/process.rs` | 504 | ABI width (`MSG_DATA_WORDS_MAX - 1` words) | none | correct as is | Derive from the ABI constant |
| `RELA_CHUNK_RECORDS` | `services/procmgr/src/process.rs` | 128 | batch size (streaming chunk) | 3 KiB stack | correct as is | None |
| `MAX_PROCESS_STACK_PAGES` clamp | `services/procmgr/src/process.rs` | 256 | see the process-layout section | none | raise | Reject, do not clamp (#641) |
| `THREAD_RETYPE_PAGES` | `services/procmgr/src/main.rs` | 6 | encoding artefact (kernel stack, TCB and FPU pages) | none | correct as is | Share with init |
| `ASPACE_RETYPE_PAGES`, `CSPACE_RETYPE_PAGES` (per child) | `services/procmgr/src/main.rs` | 48 / 7 | refillable seed (augment) | per child | correct as is | None |
| `INIT_THREADS`, `FIRST_ROUND_CAPS` | `services/procmgr/process-table/src/init_reap.rs` | 2 / 4 | provably unreachable (fixed init protocol) | none | correct as is | None |
| DONATE round size | `services/procmgr/src/init_reap.rs` | `MSG_CAP_SLOTS_MAX` | ABI width | none | correct as is | Loops over every cap |
| `PROBE_SETTLE_READS` | `services/procmgr/src/init_reap.rs` | 64 reads with a yield between | unknown (yield count) | none | needs a design | When it runs out, the probe page stays out of memmgr's pool; its wall time depends on scheduling. Use a time-based bound |
| memory cookie, process badge | `services/procmgr/src/process.rs` | random `u64` | ABI width | none | correct as is | None |

### svcmgr and registry

Tracked by [#643](https://github.com/kottlerg/seraph/issues/643).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `MAX_SERVICES` | `services/svcmgr/src/service.rs` | 16 | current peak plus headroom | about 3.5 KiB stack | make pay-as-you-go | `.svc` definitions past 16 are refused |
| `REGISTRY_CAPACITY` | `services/svcmgr/src/main.rs` | 16 | current peak plus headroom | per entry | make pay-as-you-go | Growable registry (#75) |
| `MAX_PENDING_REGISTRATIONS` | `services/svcmgr/src/main.rs` | `MAX_SERVICES` | encoding artefact (mirror) | about 640 B | make pay-as-you-go | Follows `MAX_SERVICES` |
| death EQ capacity | `services/svcmgr/src/main.rs` | `MAX_SERVICES * 2` | provably unreachable while the table is fixed | small | needs a design | Re-tie to the growable table |
| `MAX_RESTARTS` | `services/svcmgr/src/service.rs` | 1 per boot, never reset | unknown | none | needs a design | Windowed budget (#262) |
| `ServiceEntry.vfs_path`, `ns_subtree_path` | `services/svcmgr/src/service.rs` | 48 B (`MAX_PATH_LEN`) | unknown | 96 B per service | raise | One path limit |
| `ServiceEntry.name`, `PendingRegistration.name` | `services/svcmgr/src/service.rs` | 32 B | unknown | 32 B each | raise | Disagrees with `registry::NAME_MAX` (16); one name limit |
| svc-defs argv and env limits | `services/svcmgr/svc-defs/src/parse.rs` | 255 / 256 B / 64 words | encoding artefact (procmgr wire) | none | needs a design | Follows the blob design |
| restart create word check | `services/svcmgr/src/restart.rs` | `MSG_DATA_WORDS_MAX` | ABI width | none | correct as is | None |
| reconcile correlator `idx as u32` | `services/svcmgr/src/definitions/reconcile.rs` | table index | encoding artefact | none | correct as is | A dynamic table needs a generation |
| endowment `CAPS_SLOTS`, `ROUND_DATA_WORDS`, `CAPS_ROUNDS` | `services/svcmgr/endowment/src/lib.rs` | 6 / 4 / derived | provably unreachable (enumerated roles) | none | correct as is | None |
| bootstrap badge | `services/svcmgr/src/restart.rs` | random `u64` | ABI width | none | correct as is | None |

### vfsd and namespace

Tracked by [#644](https://github.com/kottlerg/seraph/issues/644).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `MAX_TREE_NODES` | `services/vfsd/root-backend/src/lib.rs` | 32, never freed | current peak plus headroom | about 2.9 KiB | make pay-as-you-go | Growable mount tree |
| tree node index (`NONE`) | `services/vfsd/root-backend/src/lib.rs` | `u32` | provably unreachable (below `MAX_TREE_NODES`) | 4 B per link | correct as is | None |
| `MAX_ENTRY_NAME` | `services/vfsd/root-backend/src/lib.rs` | 64 | unknown | 64 B per node | raise | `MAX_NAME_LEN` is 255 |
| MOUNT path limit | `services/vfsd/src/main.rs` | literal 64 | unknown | 64 B stack | raise | One path limit |
| `populate_fallthrough_caps` `path_buf` | `services/vfsd/src/main.rs` | 256 B | unknown | 256 B stack | raise | Shorter than `path_of` can produce; the fall-through is skipped silently |
| `MAX_GPT_PARTS` | `services/vfsd/gpt/src/lib.rs` | 8 | unknown | about 450 B | raise | GPT defaults to 128 entries; size from `num_parts` |
| gpt `SECTOR_SIZE` | `services/vfsd/gpt/src/lib.rs` | 512 | hardware spec (512-byte logical sector only) | 512 B stack | needs a design | 4Kn disks |
| `GptHeader.num_parts`, `entry_size` | `services/vfsd/gpt/src/lib.rs` | `u32` | hardware spec (UEFI GPT) | none | correct as is | None |
| `MAX_PENDING_BOOTSTRAPS`, `MAX_PENDING_ACTIVE_JOBS` | `services/vfsd/src/worker_pool.rs` | 4 / 4 | current peak plus headroom | small | make pay-as-you-go | A fifth request is refused (#254) |
| `ACTIVE_WORKER_COUNT` | `services/vfsd/src/worker_pool.rs` | 2 | tuning (concurrency knob) | 2 thread stacks | correct as is | None (#254) |
| `SERVICE_THREAD_COUNT` | `services/vfsd/src/main.rs` | 4 | unknown (re-entrancy depth) | 4 thread stacks | needs a design | Re-entry deeper than 3 can deadlock (#464) |

### init and logd

Tracked by [#645](https://github.com/kottlerg/seraph/issues/645).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `HISTORY_RING_LEN` (`HISTORY`) | `services/init/src/logging.rs` | 512 lines | current peak plus headroom (about 50) | about 140 KiB BSS | make pay-as-you-go | Variable-length byte ring |
| `MAX_SENDERS` (`SENDERS`) | `services/init/src/logging.rs` | 32 | provably unreachable as a ceiling (boot window; slots are evicted, not refused) | about 10.5 KiB BSS | correct as is | None |
| sender-table `MAX_NAME_LEN`, `LINE_BUF_SIZE` | `services/init/sender-table/src/lib.rs` | 48 / 256 | unknown (duplicated in logd) | per slot | needs a design | Share one constant with logd |
| `HistoryLine.used` | `services/init/src/logging.rs` | `u16` | provably unreachable (at most `LINE_BUF_SIZE`) | 2 B per line | correct as is | None |
| `HISTORY_TOTAL`, `HISTORY_HEAD` | `services/init/src/logging.rs` | `u64` sequence | ABI width | 16 B | correct as is | None |
| `LOG_THREAD_STACK_PAGES` | `services/init/src/logging.rs` | 4 | BSS budget (the tables live in BSS, not on this stack) | 16 KiB | correct as is | None |
| `STREAM_CHUNK_SIZE` | `services/init/src/logging.rs`, `services/logd/src/main.rs` | 512 | ABI width | 512 B stack | correct as is | None |
| `MAX_ORPHAN_MEMORY_CAPS` | `services/init/src/main.rs` | 64 | current peak plus headroom | 256 B | raise | Halts on overflow; size from `memory_count` |
| `CSPACE_RETYPE_PAGES` (tier-1) | `services/init/src/main.rs` | 149 pages (8231 slots) | current peak plus headroom | 149 pages each for memmgr and procmgr | needs a design | Lifetime cap on tier-1 caps; self-augment path |
| `THREAD_RETYPE_PAGES` (tier-1) | `services/init/src/main.rs` | 6 | encoding artefact (kernel stack, TCB and FPU pages) | per tier-1 service | correct as is | Share with procmgr |
| `ASPACE_RETYPE_PAGES` (tier-1) | `services/init/src/main.rs` | 48 | refillable seed for procmgr; a static seed for memmgr, which has no augment path | 48 pages per tier-1 service | make pay-as-you-go | memmgr's page-table pool caps its metadata-arena growth; fund it from its pool (#642) |
| `INIT_RETYPE_RESERVE_PAGES` | `services/init/src/bootstrap.rs` | 8 | provably unreachable (asserted against the fixed endpoint count) | 8 pages | correct as is | None |
| `RETYPE_RESERVE_PAGES` | `services/init/src/bootstrap.rs` | 203 | encoding artefact (sum) | per tier-1 service | correct as is | None |
| `MODULE_SCRATCH_MAX_PAGES` | `services/init/src/bootstrap.rs` | 65536 (256 MiB) | encoding artefact (init VA layout) | none | correct as is | Caps one boot module at 256 MiB |
| `MAX_APERTURE_CAPS` (`HwCaps.apertures`) | `services/init/src/service.rs` | 32 | hardware spec mirror (boot `MAX_APERTURES` = 16) | 768 B | correct as is | Pin against the boot constant with a const assert |
| `MAX_ACPI_REGION_CAPS` (`HwCaps.acpi_regions`) | `services/init/src/service.rs` | 8 | mirror of the kernel's 8 | 192 B | raise | Raise with the kernel bound (#637) |
| `pack_svc_name` | `services/init/src/service.rs` | 16 B | encoding artefact (two words) | none | raise | One name limit (#643) |
| `mm_boot_data` | `services/init/src/main.rs` | literal 64 | ABI width (`MSG_DATA_WORDS_MAX`) | 512 B stack | correct as is | Use the constant |
| `log_hex` buffer | `services/init/src/bootstrap.rs` | 96 B | diagnostic output cap | 96 B stack | correct as is | None |
| `SlotTable.slots` | `services/logd/src/slot.rs` | unbounded map | none | none | correct as is | Already pay-as-you-go |
| `PER_SLOT_HISTORY` | `services/logd/src/slot.rs` | 16 lines | tuning (per-sender retention) | none up front | correct as is | None |
| logd `LINE_BUF_SIZE`, `MAX_NAME_LEN` | `services/logd/src/slot.rs` | 256 / 48 | duplicated with init | none | needs a design | Share one constant |
| `MAX_DEATHS_PER_BURST` | `services/logd/src/main.rs` | 64 | current peak plus headroom | about 0.6 KiB | needs a design | Overflow drops deaths and leaks slots |
| eviction by `t as u32` | `services/logd/src/main.rs` | low 32 bits | ABI width (kernel correlator) | none | needs a design | Evicts every slot sharing the low bits (#638) |
| death exit reason | `services/logd/src/main.rs` | `u32` | encoding artefact | none | correct as is | None |
| handover `MAX_ITERS` | `services/logd/src/handover.rs` | 2048 | provably unreachable (init's 32 senders plus 512 lines) | none | correct as is | Derive from those constants |
| `send_release` `MAX_RETRIES` | `services/logd/src/handover.rs` | 64 yields | unknown (yield count) | none | needs a design | Time-based bound |
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

Tracked by [#646](https://github.com/kottlerg/seraph/issues/646).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `MAX_DEVICES` | `services/devmgr/src/pci.rs` | 8 | current peak plus headroom | about 1.5 KiB stack | make pay-as-you-go | The scan drops functions past 8 silently (#165) |
| `MAX_BARS` | `services/devmgr/src/pci.rs` | 6 | hardware spec (PCI type-0 header) | about 108 B per device | correct as is | None |
| `read_virtio_pci_caps` loop bound | `services/devmgr/src/pci.rs` | literal 48 | hardware spec ((256 - 64) / 4 capability slots) | none | correct as is | Name it |
| `pci_enumerate` device, function, bus widths | `services/devmgr/src/pci.rs` | 32 / 8 / 256 | hardware spec (PCI BDF) | none | correct as is | None |
| caps `MAX_APERTURES` | `services/devmgr/src/caps.rs` | 32 | current peak plus headroom (mirrors init) | 768 B | make pay-as-you-go | Overflow drops apertures, and `carve_subrange` loses MMIO authority |
| caps `MAX_ACPI_REGIONS` | `services/devmgr/src/caps.rs` | 8 | current peak plus headroom | 192 B | make pay-as-you-go | Tables in a dropped region become unreachable |
| `driver_module_slots`, `driver_module_kinds` | `services/devmgr/src/caps.rs` | literal 8 | unknown | 96 B | needs a design | Silent drop; tie to the module-kind count |
| absorb rounds `.min(4)` | `services/devmgr/src/caps.rs` | literal 4 | ABI width (`MSG_CAP_SLOTS_MAX`) | none | correct as is | Use the constant |
| `FIRMWARE_MAP_MAX_PAGES` | `services/devmgr/src/main.rs` | 256 (1 MiB) | current peak plus headroom | VA per call | needs a design | Tables past 1 MiB into a region are unreadable |
| `MAX_DEVICE_INFO_PAYLOAD` | `services/devmgr/src/main.rs` | 64 | encoding artefact (largest payload type 56 B) | 76 B per entry | correct as is | None |
| `device_info` catalog | `services/devmgr/src/main.rs` | `MAX_DEVICES + 4` | current peak plus headroom | about 912 B stack | make pay-as-you-go | Follows `MAX_DEVICES` |
| `device_badge` | `services/devmgr/src/main.rs` | `u64` | provably unreachable | none | correct as is | None |
| `IrqRangeAllocator.next_start` | `services/devmgr/src/main.rs` | forward-only `u32` | encoding artefact | none | needs a design | A lower GSI after a higher one gets no IRQ |
| single virtio-blk, single virtio-input, one BAR | `services/devmgr/src/main.rs` | 1 | current peak plus headroom | none | needs a design | A second disk is ignored (#165) |
| `parse_mcfg_ecam` | `services/devmgr/firmware/src/acpi.rs` | first segment only | current peak plus headroom | none | needs a design | Multi-segment platforms lose segments |
| firmware dtb `MAX_DEPTH` | `services/devmgr/firmware/src/dtb.rs` | 16 | provably unreachable on real trees (under 8 deep) | 256 B stack | correct as is | None |
| `mint_bootstrap_badge` redraw | `services/devmgr/src/spawn.rs` | unbounded | provably unreachable (2^-64 per draw) | none | correct as is | None |
| riscv64 platform defaults | `services/devmgr/src/arch/riscv64/mod.rs` | QEMU `virt` constants | hardware spec (QEMU `virt`) | none | correct as is | Data-driven binding is #165 |

### Drivers

Tracked by [#647](https://github.com/kottlerg/seraph/issues/647).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `MAX_QUEUE_SIZE` | `services/drivers/virtio/core/src/virtqueue.rs` | 256 | current peak plus headroom (QEMU default) | 1 KiB per queue | make pay-as-you-go | The spec allows 32768; size to the negotiated queue |
| `last_used_idx`, `avail.idx` | `services/drivers/virtio/core/src/virtqueue.rs` | `u16` | hardware spec (VirtIO split ring) | none | correct as is | Assert a power-of-two queue size |
| `RESET_POLL_LIMIT` | `services/drivers/virtio/core/src/pci.rs` | 1 000 000 | unknown (spin count) | none | needs a design | Wall-clock bound |
| virtio-blk `QUEUE_SIZE` | `services/drivers/virtio/blk/src/main.rs` | 128 | unknown | two ring pages | needs a design | Effective depth is 1 |
| `PARTITION_TABLE_SIZE` | `services/drivers/virtio/blk/src/main.rs` | 16, cumulative | current peak plus headroom | 512 B | needs a design | No unregister path; recycle on cap death |
| `next_partition_badge` | `services/drivers/virtio/blk/src/main.rs` | `u64`, monotonic | provably unreachable (2^63 registrations) | none | correct as is | None |
| `transfer_len` bound | `services/drivers/virtio/blk/src/lib.rs` | `u32::MAX / 512` sectors | hardware spec (VirtIO descriptor length) | none | correct as is | None |
| `REQUEST_TIMEOUT` | `services/drivers/virtio/blk/src/io.rs` | 50 s | tuning | none | correct as is | None |
| `IRQ_WAIT_TIMEOUT_MS` | `services/drivers/virtio/blk/src/io.rs` | 50 ms | tuning | none | correct as is | None |
| poll burst | `services/drivers/virtio/blk/src/io.rs` | 100 000 spins | unknown (spin count) | none | needs a design | Wall-clock bound |
| `EVENT_QUEUE_SIZE` | `services/drivers/virtio/input/src/input.rs` | 64 | BSS budget (64 x 8 B buffers in one DMA page) | one DMA page | correct as is | None |
| `POLL_INTERVAL_MS` | `services/drivers/virtio/input/src/main.rs` | 20 | tuning (human input rate) | none | correct as is | None |
| `MAX_READ_BYTES` | `services/drivers/serial/src/main.rs` | 512 | ABI width (`MSG_DATA_WORDS_MAX * 8`) | 512 B stack | correct as is | Derive from the constant |
| serial and framebuffer write `byte_len` | `services/drivers/serial/src/main.rs`, `services/drivers/framebuffer/src/main.rs` | 16 bits | encoding artefact | none | correct as is | None |
| cmos `MAX_ATTEMPTS` | `services/drivers/cmos/src/lib.rs` | 16 | hardware spec (MC146818 update cadence) | none | correct as is | None |
| cmos `UIP_POLL_LIMIT` | `services/drivers/cmos/src/lib.rs` | 10 000 | hardware spec (UIP held at most about 2 ms) | none | correct as is | None |
| cmos century fallback | `services/drivers/cmos/src/main.rs` | 2000 to 2099 without a century register | hardware spec (QEMU) | none | needs a design | Read the FADT `CENTURY` index |
| test-orphan `RESERVE_BYTES` | `services/drivers/test-orphan/src/main.rs` | 1 MiB | test fixture | 1 MiB heap | correct as is | None |

### fs-fat

Tracked by [#647](https://github.com/kottlerg/seraph/issues/647).

| Item | Location | Value | Set by | Up-front cost | Class | Recommendation |
|---|---|---|---|---|---|---|
| `MAX_NODES` (`NodeTable.entries`) | `services/fs/fat/src/backend.rs` | 128, cumulative | current peak plus headroom | about 5 KiB stack | needs a design | Every lookup fails after 128 distinct entries (#27) |
| `NO_OPEN_SLOT` | `services/fs/fat/src/backend.rs` | `u32::MAX` | provably unreachable | none | correct as is | None |
| `MAX_OPEN_FILES` | `services/fs/fat/src/file.rs` | 8 | current peak plus headroom | about 4.2 KiB | make pay-as-you-go | A 9th concurrent file is refused (#530) |
| `MAX_OUTSTANDING` | `services/fs/fat/src/file.rs` | 16 pages per file | current peak plus headroom | about 512 B per file | raise | Scale with the cache |
| `MAX_PENDING_EVICTIONS` | `services/fs/fat/src/eviction.rs` | `MAX_OPEN_FILES * MAX_OUTSTANDING` | provably unreachable (each entry is queued at most once) | about 4 KiB | correct as is | Follows its factors |
| `RELEASE_TIMEOUT_MS` | `services/fs/fat/src/eviction.rs` | 100 ms | tuning | none | needs a design | Each timeout leaks one watchdog thread (#31) |
| `SLOT_COUNT` (`PageCache.slots`) | `services/fs/fat/src/cache.rs` | 128 pages | BSS budget | 512 KiB per mount | make pay-as-you-go | Grow lazily to a RAM-scaled ceiling (#52) |
| `QUARANTINE_MAX` | `services/fs/fat/src/cache.rs` | 32 | tuning (bounds what non-unmapping clients cost) | 256 B | correct as is | None (#52) |
| `SECTORS_PER_PAGE` | `services/fs/fat/src/cache.rs` | 8 | hardware spec (page over 512 B sector) | none | correct as is | None |
| `SCRATCH_MEMORY` | `services/fs/fat/src/cache.rs` | one page | encoding artefact (block DMA from offset 0) | one page | correct as is | None (#83) |
| `FatState.cached_fat_sector` | `services/fs/fat/src/bpb.rs` | one sector | tuning (memo above the cache) | 512 B | correct as is | None |
| `NEXT_BADGE` | `services/fs/fat/src/main.rs` | `u64`, monotonic | provably unreachable | none | correct as is | None |
| FS_READ reply size | `services/fs/fat/src/main.rs` | 504 B | ABI width | 512 B stack | correct as is | None |
| memory verbs | `services/fs/fat/src/main.rs` | one page per call | encoding artefact | none | correct as is | None |
| cluster-chain walk | `services/fs/fat/src/main.rs`, `fat.rs` | at most file size over cluster size | encoding artefact (`u32` file size) | none | correct as is | Add a cycle guard |
| `next_dir_cluster` step guard | `services/fs/fat/src/dir.rs` | `total_clusters` | provably unreachable (longer chains must cycle) | none | correct as is | None |
| allocator scans | `services/fs/fat/src/alloc.rs` | `total_clusters`, one wrap | encoding artefact | none | correct as is | None |
| `MAX_NUMERIC_TAIL` | `services/fs/fat/src/dir.rs` | 6 | current peak plus headroom | none | raise | The 7th colliding long name fails |
| on-disk `u32` fields | `services/fs/fat/src/dir.rs` | `u32` | hardware spec (FAT32) | none | correct as is | None |
| ASCII-only LFN write | `services/fs/fat/src/dir.rs` | ASCII | unknown | 510 B stack | needs a design | UCS-2 encoding |
| `MAX_LFN_CHARS`, `MAX_LFN_UTF8` | `services/fs/fat/fat-parse/src/lib.rs` | 255 / 765 | hardware spec (FAT LFN) | embedded | correct as is | None |
| `MAX_SLOT_RUN` | `services/fs/fat/fat-parse/src/lib.rs` | 21 | hardware spec (FAT LFN) | embedded | correct as is | None |
| fat-parse `SECTOR_SIZE` | `services/fs/fat/fat-parse/src/lib.rs` | 512 | encoding artefact (block IPC addresses 512 B sectors) | none | needs a design | 4Kn volumes are refused |

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
| `SLOTS_PER_PAGE`, `LIVE` (`HANDLES`) | `core/ktest/src/stress/cspace_registry_arena.rs` | 56 / 4097 | mirror of kernel `L2_SIZE`; one past the former 4096-entry registry | about 16 KiB BSS | correct as is | Reference or assert against `L2_SIZE` |
| `FILLERS` | `core/ktest/src/stress/sleep_list_full.rs` | 128 | mirror of kernel `MAX_SLEEPING` | 1 MiB BSS | correct as is | Reference or assert against `MAX_SLEEPING` (#638) |
| `MAX_PINNED` | `core/ktest/src/bench/tlb.rs` | 7 | test fixture | 224 KiB BSS | correct as is | None |
| `EVERY_CPU_MAX`, `LOW_CPUS` | `core/ktest/src/arch/x86_64/umip.rs` | 16 / 8 | test fixture | none | correct as is | None |
| `MIGRATION_GUARD_MAX_CPUS` | `core/ktest/src/stress/load_balance_handoff_steal.rs` | 32 | ABI width (one-hot `u32` witness) | none | correct as is | None |
| `fund_boot_aspace_pt` budgets | `core/ktest/src/main.rs` | 256 KiB / 64 / 16 pages | test fixture | none | correct as is | None |
| `DEPTH` | `core/ktest/src/integration/cspace_nested_teardown.rs` | 256 | test fixture (past the kernel-stack recursion depth) | none | correct as is | None |
| `CHILDREN` | `core/ktest/src/integration/cap_transfer_large.rs` | 300 | test fixture (more than one reparent batch) | none | correct as is | None |
| `FATFS_SLOT_COUNT`, `FATFS_QUARANTINE_MAX` | `services/svctest/src/phases/fs_ipc.rs` | 128 / 32 | mirror of fs-fat | none | correct as is | Import or assert (#647) |
| `INLINE_CHUNK` | `services/svctest/src/phases/fs_ipc.rs` | 504 | ABI width | none | correct as is | Use the derived constant |
| `SYSTEM_TIME_BEFORE_2100_SECS` | `services/svctest/src/phases/timed.rs` | 4 102 444 800 | mirror of the cmos century fallback | none | correct as is | None |
| svctest poll counts | `services/svctest/src/phases/*.rs` | 256 to 5000 | test fixture | none | correct as is | None |
| ramdisk `MAX_SECTORS_PER_REQUEST`, `CLUSTERS` | `services/svctest/src/phases/fs_faults/ramdisk.rs` | 8 / 4096 | test fixture | none | correct as is | None |

---

## Summarized By

[Architecture Overview](architecture.md)
