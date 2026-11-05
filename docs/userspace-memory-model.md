# Userspace Memory Model

How userspace processes in Seraph acquire, own, and manage memory.
This document is system-scope: it specifies the contracts between the
kernel, memmgr, procmgr, and `std::sys::seraph`, but leaves
component-internal mechanisms (memmgr's pool structure, procmgr's
ELF loader, std's allocator implementation) to those components' own
docs.

---

## Ownership Boundaries

Authority over memory is partitioned across four layers:

- **Kernel** — physical frame allocator (buddy), page tables, W^X,
  canonical-address enforcement. Does not track named regions; every
  mapping syscall takes an explicit caller-supplied virtual address.
- **memmgr** — tier-1 userspace service holding the userspace RAM
  frame pool. Allocates Memory capabilities to all std-built services
  on demand, tracks per-process ownership, reclaims on process death,
  coalesces freed runs. memmgr chooses no virtual addresses for its
  clients; as the demand pager it records each client's registered
  regions (`REGISTER_REGION`) and maps frames into delegated address
  spaces on fault ([Fault Handling](fault-handling.md)).
  See [`services/memmgr/README.md`](../services/memmgr/README.md).
- **procmgr** — tier-1 userspace service holding process lifecycle
  authority. Loads ELF images, allocates kernel objects (`AddressSpace`,
  `CSpace`, `Thread`), populates `ProcessInfo`, observes process death.
  procmgr is itself a memmgr client; its heap is backed by memmgr.
  See [`services/procmgr/README.md`](../services/procmgr/README.md).
- **`std::sys::seraph`** — per-process Rust standard library platform
  layer. Owns the process's virtual address space layout, provides the
  `GlobalAlloc` impl behind std's default `System` allocator, and hosts
  the page-granular reservation allocator for foreign Memory mappings.

The kernel hands the initial RAM memory caps to init at boot. Init
moves them to memmgr, which holds each one alone (see
[Process Lifecycle](process-lifecycle.md) § Init → memmgr and
[Capability Model](capability-model.md)). From that point on, memmgr is
the sole userspace authority over RAM frame allocation; the kernel does
not delegate further to anyone.

The handoff is total. By the end of Phase 7 the kernel has taken its
bounded reserves from the buddy (the Phase 4 guard-table reserve, per-CPU storage, frame map
table, and `CSpace` registry, the Phase 5 per-CPU tag-state slab, and the Phase 7
contributors, in the order [initialization.md](../core/kernel/docs/initialization.md) § Phase 4,
§ Phase 5, and § Phase 7 give), drains **every** remaining page into userspace Memory
caps — coalescing
physically-adjacent drained blocks into the fewest contiguous caps so the
cap count tracks memory-map fragmentation, not total RAM — and *seals* the
buddy.
After the seal the buddy is an inert boot artifact: it holds no free
pages, allocates nothing, and must receive no frees. Every page of RAM is
therefore either a bounded fixed kernel reserve or owned by memmgr's pool
— nothing is invisible. memmgr holds its `owns_memory` Memory caps
permanently (consumers receive `owns_memory=false` derivations that return
to the pool on death), so no cap ever cascades back to the kernel
allocator. A free into the sealed buddy means an `owns_memory` cap was
destroyed post-handoff — RAM leaked into an allocator nothing draws from —
and trips a kernel `debug_assert`; the same fault surfaces in the
closing identity `system_ram == kernel_reserved + pool_total` checked by
svctest.

A process maps into another process's address space only through that
space's AddressSpace capability: the process creator at creation time (see
[Bootstrap Cross-Boundary VAs](#bootstrap-cross-boundary-vas)), and memmgr as
pager for the regions a client registered. Sharing
between peers is explicit and capability-mediated: a Memory cap is sent over
IPC and the receiver maps it into its own address space at a VA the receiver
chose.

---

## VA Management Surfaces

Every process manages its own virtual address space through three
disjoint surfaces:

| Surface | Granularity | Owner | Used for |
|---|---|---|---|
| Byte heap | Bytes | `std::sys::seraph::alloc` (`GlobalAlloc` for `System`) | `Box`, `Vec`, `String`, all `alloc`/`std` collections |
| Page reservations | 4 KiB pages | `std::sys::seraph` | Foreign Memory mappings: MMIO, DMA, shmem, zero-copy file pages, ELF-load scratch, demand-paged spawned-thread stacks (heap-backed stacks and spawned-thread IPC buffers come from the byte heap) |
| Bootstrap cross-boundary VAs | 4 KiB pages | Process creator (kernel for init, init for memmgr/procmgr, procmgr for everyone else) | `ProcessInfo` page and `InitInfo` region, main-thread stack (with the demand-growth range `std::os::seraph::_start` registers inside its reservation), main-thread IPC buffer, main-thread TLS block |

Each surface is independent of the others; their VA ranges do not
overlap within a single address space.

`std::sys::seraph` is the single chooser of byte-heap and
page-reservation VAs within the running process. The creator picks
bootstrap-cross-boundary VAs once at process-creation time and
communicates them via `ProcessInfo` / `InitInfo`.

### Byte Heap

`std::sys::seraph::alloc` implements `GlobalAlloc` for std's default
`System` allocator, so with no `#[global_allocator]` override the full
`alloc` / `std` collections surface (`Box`, `Vec`, `String`,
`BTreeMap`, …) is available to every std-built service.

- **Backing store.** The allocator's grow path requests Memory caps
  from memmgr via `REQUEST_MEMORY_CAPS` on the process's
  `ProcessInfo.memmgr_endpoint_cap` and maps them at a contiguous VA
  range above its current high-water mark. Multi-page contiguous
  caps (one cap covering many pages) are returned whenever one free run
  covers a best-effort request (`flags` = 0); the multi-page-cap
  reply path collapses what would otherwise be
  many single-page IPCs into a single round. A grow covers the whole
  request beyond the free block at the heap's top, and an allocation
  grows again while each grow maps pages, so a single allocation is
  bounded only by the heap zone ([Growth Zones](#growth-zones)) and the
  pool.
- **Bootstrap.** Before `fn main()` runs, `std::os::seraph::_start`
  installs the heap floor at the process's heap base, drawn per process
  from the heap zone's window via one raw non-allocating `SYS_GETRANDOM`
  call (ASLR, [#39](https://github.com/kottlerg/seraph/issues/39)). In a
  demand-paged process the floor is a demand region registered with the
  pager (`REGISTER_REGION`), so it costs VA, and frames only for the
  pages first touched. A spawned thread's IPC buffer is a heap page, and
  the kernel's IPC-buffer copies fail on an unbacked page instead of
  faulting to the pager (a restartable syscall's copy faults to it;
  [Fault Handling § Kernel Copies](fault-handling.md#kernel-copies)), so
  `Thread::new` touches that page before the thread registers it.
  A process with no pager maps the floor eagerly through
  `REQUEST_MEMORY_CAPS`. The floor's size is a `std::sys::seraph`
  implementation detail.
- **Out-of-memory.** `GlobalAlloc::alloc` returns null and the `alloc`
  crate aborts through `handle_alloc_error` (std's abort path, which
  traps on seraph): a terminal fault that tears down the whole process
  (procmgr reaps it on the address-space death notification; when a
  full death queue dropped that post, procmgr's death resync recovers it
  from the address space's retained terminal-fault reason, see
  [services/procmgr/README.md](../services/procmgr/README.md) § Process
  table and death queues). svcmgr observes the death via its event queue
  and applies restart policy. No kernel panic.
- **Thread safety.** A spinlock guards the allocator. Multi-threaded
  services share one allocator instance. A contended waiter sleeps once a
  bounded spin is spent, so a lower-priority holder on its CPU still runs
  ([runtime/ruststd/README.md](../runtime/ruststd/README.md) § Byte heap
  (`System`)).
- **`no_std` exceptions.** `init` and `memmgr` are `no_std` and have
  no byte heap (no `GlobalAlloc`). They allocate frames (where applicable)
  via direct kernel object handling at boot, not via `REQUEST_MEMORY_CAPS`.

### Page Reservations

Foreign Memory caps (from devmgr for MMIO, from drivers for shmem
buffers, from fs drivers for zero-copy file pages, from memmgr for
heap-disjoint allocations like long-lived DMA regions) are mapped into
the process via the page-reservation allocator inside `std::sys::seraph`.

- **API surface.**
  `std::os::seraph::reserve_pages(n) → Result<ReservedRange, ReserveError>`
  returns a contiguous unmapped VA range of `n` pages.
  `unreserve_pages(range)` releases it. The caller maps owned Memory
  caps into the reservation with `mem_map`. The caller is responsible
  for `mem_unmap` before `unreserve_pages`.
- **Arena.** Each process carves its arena out of its own address space
  on first use, in the arena zone sized to its user half
  ([Growth Zones](#growth-zones)). The arena base is drawn per process
  from the zone's window (ASLR,
  [#39](https://github.com/kottlerg/seraph/issues/39)), degrading to the
  window base when the entropy draw fails. Everything placed through the
  arena — demand-paged thread stacks, MMIO, shmem, stdio/pipe rings, ELF scratch —
  inherits the randomised base.
- **Free runs.** Released ranges coalesce into a sorted run table, which
  each reservation first grows to hold one run more than the live
  reservations (into the byte heap once its static table is full), so a
  release always finds a slot and freed VA is never lost. A reservation
  that cannot grow the table fails with `OutOfSpace`.
- **Concurrency.** Reservations are independent across threads; the
  allocator serialises on a spinlock as needed, the byte heap's spin
  mutex type, whose waiters sleep past a bounded spin (§ Byte Heap).

The page-reservation allocator is a `std::sys::seraph` concern and is
not exposed to non-std runtimes. `init` and `memmgr` carry small
private VA choices for whatever scratch regions they need; memmgr draws
its metadata-arena and phys-table scratch bases per boot from fixed
windows of its own, places its process-index bucket array in a fixed
deterministic window (it holds only arena indices), and continues its
arena above 2^38 in a paging mode whose user half allows it, while init's
short-lived bootstrap scratch stays deterministic (init exits at reap and
serves no untrusted input). memmgr's windows are specified in
[`services/memmgr/docs/memory-pool.md`](../services/memmgr/docs/memory-pool.md)
§ Metadata Arena and § Per-Process Tracking.

### Bootstrap Cross-Boundary VAs

The handover pages (`ProcessInfo`, `InitInfo`), the main-thread stack,
the main-thread IPC buffer, and the main-thread TLS block must be
mapped into the new process's address space *before* the process runs
its first instruction. The creator chooses every one of these virtual
addresses per-process — none is a fixed ABI constant — and communicates
them either through the handover struct or, for the handover page itself,
through the entry register. Procmgr and init draw process layouts via
[`shared/process-layout`](../shared/process-layout/README.md)
(`choose_process_layout`, fed `SYS_GETRANDOM` entropy); the kernel draws
init's layout per boot via its own `choose_init_layout` over the same
window constants (`crate::entropy::fill_bytes`).

Every bootstrap surface is randomised independently (ASLR,
[#39](https://github.com/kottlerg/seraph/issues/39)): each is a
page-aligned draw from a fixed per-region window of 2²¹ slots (21 bits
of entropy per surface) on 9 GiB strides between the Sv39 reservation-arena
zone and the image window — TLS at `0x21_0000_0000`, IPC buffer at
`0x23_4000_0000`, `ProcessInfo` at `0x25_8000_0000`, stack guard at
`0x27_C000_0000`, and, kernel-drawn for init, `InitInfo` at
`0x2A_0000_0000` and the init stack guard at `0x2C_4000_0000`. The
stride spacing makes region ordering, pairwise disjointness, and the
unmapped guard page below every stack hold for all possible draws, so
no collision checking or redraw is ever needed. Each window's 8 GiB draw
span leaves a 1 GiB region tail in its stride (`MAX_WINDOW_REGION_PAGES`),
which bounds the largest stack reservation and TLS block a loader accepts and
the largest argv/env region a creator maps after the `ProcessInfo` page.
Every creator-placed surface ends below `LAYOUT_VA_CEILING` (2³⁸, the
smallest user half among the supported paging modes, riscv64 Sv39), since
the creator places them without knowing the paging mode, so one static
layout is canonical under every mode on both architectures; that ceiling
is what caps these windows at 21 bits. A creator whose entropy draw fails
(a kernel-contract violation once the pool is seeded) logs and degrades to
the deterministic `DEFAULT_*` addresses, which lie outside the windows,
between init's stack-guard zone and the image window, each with its
window's full region tail — the test harnesses' window assertions then
fail loudly by design. The default boot on both architectures is
firmware-seeded through `EFI_RNG_PROTOCOL` (OVMF natively on x86_64; the
firmware's `VirtioRngDxe` with `virtio-rng` on riscv64); a riscv64 boot
without that device, under the EDK2 firmware the default boot uses, seeds
from jitter alone
([#393](https://github.com/kottlerg/seraph/issues/393)); see
[`core/kernel/docs/entropy.md`](../core/kernel/docs/entropy.md) for the
quality caveat.

- **`ProcessInfo` page.** The creator (procmgr, or init for memmgr and
  procmgr) maps a read-only page at the chosen `process_info_va`,
  writes the `ProcessInfo` struct into it, and delivers
  that address to the child in its entry register (`rdi`/`a0`). The
  child's `_start` takes the address as its argument — it cannot read the
  address from the struct, since the address is what locates the struct.
  When the child receives argv or env, procmgr maps their pages read-only
  directly after the page, the argv/env region, inside the window's region
  tail (`process_abi::ARGV_ENV_MAX_PAGES`, see
  [abi/process-abi/README.md](../abi/process-abi/README.md) § argv / env
  region); the struct's offsets locate the two blobs.
- **`InitInfo` region.** The kernel maps a read-only region at its chosen
  `init_info_va` for init only, one or more pages sized from the boot's
  descriptor counts (`init_info_memory_count` pages, at most
  `INIT_INFO_MAX_PAGES`), and delivers the address in init's entry register
  the same way.
- **Main-thread stack.** The loader (procmgr or, for memmgr/procmgr,
  init) maps `ProcessInfo.stack_pages` pages ending at the chosen
  `ProcessInfo.stack_top_vaddr` and leaves the pages below them
  unmapped, so a guard page lies below every stack. The page
  count comes from the binary's optional `.note.seraph.stack` ELF note
  (declared via the `process_abi::stack_pages!` /
  `std::os::seraph::stack_pages!` macro; see
  [Stack-size note](../abi/process-abi/README.md#stack-size-note-noteseraphstack));
  binaries that omit the note inherit
  `DEFAULT_PROCESS_STACK_PAGES`. Loaders refuse a binary whose note
  declares zero pages or more than `MAX_PROCESS_STACK_PAGES`; the pool's
  available RAM is the remaining gate on the resulting
  `REQUEST_MEMORY_CAPS` calls (memmgr tracks per-process frames in a
  RAM-bound arena, not a fixed quota). For an `ET_DYN` image the
  creator leaves the `1 + MAX_PROCESS_STACK_PAGES` pages below
  `stack_top_vaddr` to the stack: it maps no other surface there, the
  layout's draw windows keep every other bootstrap surface out of them
  for every draw, and the image's placement check keeps the image out
  of them ([Image Placement](#image-placement)). The process's runtime
  may rely on this reservation. An `ET_EXEC` image loads at its link
  addresses unchecked against it, so the reservation does not hold for
  one.
- **Main-thread stack growth.** The mapped pages are the stack's
  committed part. In a demand-paged process whose image is `ET_DYN`,
  `std::os::seraph::_start` registers the pages below them, down to a 512-page
  (`DEFAULT_DEMAND_STACK_PAGES`, 2 MiB) stack, as a read-write demand
  region with the pager (`REGISTER_REGION`), so the stack grows on
  first touch; the page below that range stays unregistered as the
  guard, and an overflow past it faults on an address the pager
  declines, killing the process. A binary whose note declares 512 pages
  or more, a pinned process (no pager), an `ET_EXEC` image, and a
  process whose registration fails keep the committed pages alone, the page below
  which faults the same way. The growth range is the pager's demand
  region like any other: its frames are reclaimed at process death.
- **Main-thread IPC buffer.** The creator picks a per-process VA and
  writes it into `ProcessInfo.ipc_buffer_vaddr`.
- **Main-thread TLS block.** The creator maps the pages the binary's
  `PT_TLS` memsz needs, up to `PROCESS_MAIN_TLS_MAX_PAGES` (the TLS
  window's region tail), at the chosen base and records it in
  `ProcessInfo.main_tls_vaddr` (zero when the binary has no `PT_TLS`); the
  kernel installs the thread pointer, so
  `_start` reads the field only for introspection. Spawned threads
  allocate their TLS blocks from the heap.

These VAs are **runtime values**, not ABI constants: the handover-page
addresses ride the entry register, and the stack/TLS/IPC VAs are
`ProcessInfo` fields (`stack_top_vaddr`, `main_tls_vaddr`,
`ipc_buffer_vaddr`). The only handover constants the ABI crates still
declare are policy bounds — `DEFAULT_PROCESS_STACK_PAGES`,
`MAX_PROCESS_STACK_PAGES`, `PROCESS_MAIN_TLS_MAX_PAGES`,
`INIT_STACK_PAGES`, `INIT_INFO_MAX_PAGES` — not layout addresses. The
draw windows and the per-process degraded-fallback `DEFAULT_*` addresses
live in `shared/process-layout`, whose windows the kernel's
`choose_init_layout` shares; init's fallback addresses
(`DEFAULT_INIT_INFO_VA`, `DEFAULT_INIT_STACK_TOP`) are kernel constants in
`mm::address_space`.

See [`process-lifecycle.md`](process-lifecycle.md) for the full
handover discipline.

### Image Placement

Userspace binaries are position-independent executables (`ET_DYN`; the
kernel image is static-PIE too, with the bootloader biasing its base per
boot — KASLR, [#252](https://github.com/kottlerg/seraph/issues/252); see
[core/boot/docs/elf-loading.md](../core/boot/docs/elf-loading.md)). The creator
draws a load bias per spawn from a fixed window of 2²³ page-aligned
slots above `0x30_0000_0000` (23 bits of entropy; ASLR,
[#39](https://github.com/kottlerg/seraph/issues/39)) — procmgr for its
children, init for memmgr and procmgr, the kernel for init itself — and
applies the image's `RELATIVE` relocations while the segments are
staged, before the process exists. Placement is validated before
loading: the biased image must end inside its image zone, and its span
must fit the room between the window's last slot and the zone's end
(`process_layout::image_max_span`). The kernel (for init) and init (for
memmgr and procmgr) validate against the fixed-tier image zone, which ends
at `0x3F_0000_0000` (`IMAGE_MAX_SPAN`, 28 GiB), below the kernel's
fallback addresses for init; procmgr validates its children against the
image zone of its own user half ([Growth Zones](#growth-zones)), which
every process of the boot shares. A failed entropy draw degrades to the
window
base (never bias 0), keeping the single relocation path; loaders reject
any relocation format other than the architecture's `RELATIVE` type,
and every table record must land in exactly one loaded *writable*
segment (`RELATIVE` targets live in data; a text or rodata target means
a malformed or hostile image). Once relocations are applied, the pages
covered by the image's `PT_GNU_RELRO` region — the GOT, `.data.rel.ro`,
and the in-image TLS template — are mapped read-only (svctest's
`relro_write` phase asserts a write there faults).

`ET_EXEC` images remain accepted and load at their link VAs with bias
0 and no relocations — loader compatibility, not a build target.

The bias is deliberately not a `ProcessInfo` field. A process that
needs its own base reads the lld-synthesized `__ehdr_start` symbol's
address; debugging correlates through the creator's spawn log line
(procmgr: `spawn image bias=0x…`; init: `init: <svc> image bias=0x…`;
kernel Phase 9: `init: PIE bias=0x…`) and loads symbols with
`add-symbol-file <binary> -o <bias>` in GDB.

### Growth Zones

The byte heap and the reservation arena are placed by the process itself,
which knows its address space's size: `std::os::seraph::_start` reads the
exclusive top of the user half once (`SYS_SYSTEM_INFO` with
`SystemInfoType::UserVaTop`), and `process_layout::growth_zones` sizes
both zones, and the image zone procmgr validates against, to it. The
creator-placed surfaces above stay in the fixed tier below 2³⁸ at the same
addresses in every mode.

| User half | Heap zone | Arena zone | Image zone end |
|---|---|---|---|
| Sv39 (2³⁸), or unknown | base window `[1 GiB, 3 GiB)`, 60 GiB above the base | base window `[64 GiB, 96 GiB)`, 32 GiB above the base | `0x3F_0000_0000` |
| `H` = 2⁴⁷ (x86-64 4-level, Sv48) or 2⁵⁶ (x86-64 5-level, Sv57) | base window at `H/8`, `H/64` wide, `H/4` above the base | base window at `H/2`, `H/64` wide, `H/4` above the base | `H/8` |

Under Sv39 both zones lie below the bootstrap windows; in a wider half they
lie above the whole fixed tier, so they grow with the address space (32 TiB
each under 2⁴⁷). A runtime that cannot read the size uses the Sv39 zones,
which are valid in every mode. `shared/process-layout` const-asserts the
zones disjoint and inside the address space for every supported mode.

---

## Memory Allocation Contract

memmgr serves frame requests over IPC. The contract:

- **Request shape.** `REQUEST_MEMORY_CAPS(want_pages, flags)`. `flags`
  carries `REQUIRE_CONTIGUOUS`; unset means best-effort.
- **`REQUIRE_CONTIGUOUS` reply.** A single Memory cap covering exactly
  `want_pages`, or a `memmgr_errors::OUT_OF_MEMORY_CONTIGUOUS` error.
- **Best-effort reply.** One or more Memory caps whose page counts sum
  to at most `want_pages`. The reply carries each returned cap's page count
  and its region id alongside it, and no physical address. memmgr prefers
  fewer caps over many.
- **Reply cap-count bound.** A reply carries at most `MSG_CAP_SLOTS_MAX`
  (4) Memory caps, the IPC reply-side cap-slot capacity; a best-effort
  request no single free run covers is served largest-first across at
  most that many runs. When those runs fall short of `want_pages` but the
  pool's free pages cover it, the reply is a **partial grant**: success with
  fewer pages than asked. When the free pages do not cover `want_pages`, the
  request fails with `memmgr_errors::OUT_OF_MEMORY_BEST_EFFORT`.
- **Caller loops.** A best-effort caller MUST compare the granted page total
  with `want_pages` and request the remainder again (or release what it
  cannot use); a single reply is not guaranteed to cover the request.
- **Caller maps.** Every returned Memory cap is mapped at a caller-
  chosen VA via `mem_map` (which already accepts a multi-page
  `page_count` argument).
- **Caller releases.** `RELEASE_MEMORY_CAPS` returns a granted region to the
  pool mid-life, named by the opaque region id memmgr reported at grant (the caller
  need not still hold the cap — it may have retyped the region, deleted the
  objects, and dropped its copy; a region released while a capability to it, a
  live object, or a mapping remains is held out of the pool until all are gone).
  This keeps a per-unit-of-work retype loop (e.g. ruststd's Thread slab per
  spawn) at a bounded pool footprint; ruststd's pooled object-slab pages
  likewise recycle auto-reclaimed bytes in place and release a retired page's
  grant once every object retyped from it has died. Process death triggers
  automatic reclamation via procmgr's `PROCESS_DIED` notification to memmgr.

Authoritative wire shape lives in
[`services/memmgr/docs/ipc-interface.md`](../services/memmgr/docs/ipc-interface.md).

---

## Kernel-Side Non-Concerns

The kernel does not track per-process memory abstractions; userspace
owns them.

- **Heap** — the kernel only sees mappings of Memory caps at user-
  supplied VAs.
- **VA allocation policy** — the kernel enforces page alignment and
  the user-half bound; it does not track VAs, and allocates none except
  init's bootstrap layout and image bias, drawn once per boot.
- **Memory ownership beyond the derivation tree** — the kernel does
  not know which process "owns" a Memory.
- **Process death implications for memory** — when a process's
  `AddressSpace` is revoked, the kernel tears down threads and page
  tables. memmgr's reclamation runs separately, driven by procmgr's
  death notification. See [Process Lifecycle](process-lifecycle.md)
  § Process Death.

The userspace process abstraction itself is owned by
[`architecture.md`](architecture.md) §"Kernel Primitives vs.
Userspace Abstractions".

File-backed access via `mmap()` does not exist. Zero-copy file access
is via fs-driver IPC returning Memory caps for file pages, mapped by
the client through the page-reservation allocator.

Lazy or demand backing of a reservation — mapping frames only on first
access rather than up front — is a userspace-pager policy built on the
fault-handler protocol ([Fault Handling](fault-handling.md)), not a kernel
feature. memmgr implements it as the pager: a process reserves and
registers a range via `std::os::seraph::register_demand_paged`, and on each
first-touch fault memmgr backs the chunk of the registered region that
contains the faulting page (up to `DEMAND_CHUNK_PAGES` pages; see
[services/memmgr/docs/ipc-interface.md](../services/memmgr/docs/ipc-interface.md)).
Stacks grow the same way: a spawned thread's stack is a demand region above
an unregistered guard page
([ruststd § Spawned-thread stacks](../runtime/ruststd/README.md#spawned-thread-stacks)),
and the main thread's grows below its committed pages
([Bootstrap Cross-Boundary VAs](#bootstrap-cross-boundary-vas)).

---

## Summarized By

[abi/init-protocol/README.md](../abi/init-protocol/README.md),
[abi/process-abi/README.md](../abi/process-abi/README.md),
[Kernel Cross-Boundary Disclosure Inventory](../core/kernel/docs/cross-boundary-disclosure.md),
[Kernel Entropy Subsystem](../core/kernel/docs/entropy.md),
[Kernel Initialization Sequence](../core/kernel/docs/initialization.md),
[Architecture Overview](architecture.md), [Capability Model](capability-model.md),
[Fault Handling](fault-handling.md), [Memory Model](memory-model.md),
[Process Lifecycle](process-lifecycle.md),
[programs/demandpaged/README.md](../programs/demandpaged/README.md),
[programs/pipestress/README.md](../programs/pipestress/README.md),
[programs/relrofault/README.md](../programs/relrofault/README.md),
[programs/stackoverflow/README.md](../programs/stackoverflow/README.md),
[programs/threadchurn/README.md](../programs/threadchurn/README.md),
[programs/threadstack/README.md](../programs/threadstack/README.md),
[runtime/ruststd/README.md](../runtime/ruststd/README.md),
[services/memmgr/README.md](../services/memmgr/README.md),
[memmgr Memory Pool](../services/memmgr/docs/memory-pool.md),
[services/procmgr/README.md](../services/procmgr/README.md),
[shared/process-layout/README.md](../shared/process-layout/README.md),
[xtask/README.md](../xtask/README.md)
