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
  coalesces freed runs. memmgr knows nothing about virtual addresses.
  See [`services/memmgr/README.md`](../services/memmgr/README.md).
- **procmgr** — tier-1 userspace service holding process lifecycle
  authority. Loads ELF images, allocates kernel objects (`AddressSpace`,
  `CSpace`, `Thread`), populates `ProcessInfo`, observes process death.
  procmgr is itself a memmgr client; its heap is backed by memmgr.
  See [`services/procmgr/README.md`](../services/procmgr/README.md).
- **`std::sys::seraph`** — per-process Rust standard library platform
  layer. Owns the process's virtual address space layout, hosts the
  `#[global_allocator]`, and hosts the page-granular reservation
  allocator for foreign Memory mappings.

The kernel hands the initial RAM memory caps to init at boot. Init
transfers them to memmgr (derive-twice). From that point on, memmgr is
the sole userspace authority over RAM frame allocation; the kernel does
not delegate further to anyone.

The handoff is total. At Phase 7 the kernel reserves its fixed
contributors (PT-pool seed, idle-thread stacks, the `InitInfo` block,
init's user stack, the SEED arena) from the pristine buddy, then drains
**every** remaining page into userspace Memory caps — coalescing
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

No process manipulates another process's address space. Sharing is
explicit and capability-mediated: a Memory cap is sent over IPC and the
receiver maps it into its own address space at a VA the receiver chose.

---

## VA Management Surfaces

Every process manages its own virtual address space through three
disjoint surfaces:

| Surface | Granularity | Owner | Used for |
|---|---|---|---|
| Byte heap | Bytes | `std::sys::seraph::alloc` (`#[global_allocator]`) | `Box`, `Vec`, `String`, all `alloc`/`std` collections |
| Page reservations | 4 KiB pages | `std::sys::seraph` | Foreign Memory mappings: MMIO, DMA, shmem, zero-copy file pages, ELF-load scratch, per-thread stacks and IPC buffers when not heap-allocated |
| Bootstrap cross-boundary VAs | 4 KiB pages | Process creator (kernel for init, init for memmgr/procmgr, procmgr for everyone else) | `ProcessInfo`/`InitInfo` page, main-thread stack, main-thread IPC buffer, main-thread TLS block |

Each surface is independent of the others; their VA ranges do not
overlap within a single address space.

`std::sys::seraph` is the single chooser of byte-heap and
page-reservation VAs within the running process. The creator picks
bootstrap-cross-boundary VAs once at process-creation time and
communicates them via `ProcessInfo` / `InitInfo`.

### Byte Heap

`std::sys::seraph::alloc` declares `#[global_allocator]`, so the full
`alloc` / `std` collections surface (`Box`, `Vec`, `String`,
`BTreeMap`, …) is available to every std-built service.

- **Backing store.** The allocator's grow path requests Memory caps
  from memmgr via `REQUEST_MEMORY_CAPS` on the process's
  `ProcessInfo.memmgr_endpoint_cap` and maps them at a contiguous VA
  range above its current high-water mark. Multi-page contiguous
  caps (one cap covering many pages) are requested when available;
  the multi-page-cap reply path collapses what would otherwise be
  many single-page IPCs into a single round.
- **Bootstrap.** `std::os::seraph::_start` calls `REQUEST_MEMORY_CAPS`
  before `fn main()` runs and maps the returned caps at the process's
  initial heap base. The size of the initial bootstrap heap is a
  `std::sys::seraph` implementation detail.
- **Out-of-memory.** `GlobalAlloc::alloc` returns null; the `alloc`
  crate panics; the std panic handler exits the thread. svcmgr observes
  the death via its event queue and applies restart policy. No kernel
  panic.
- **Thread safety.** A spinlock guards the allocator. Multi-threaded
  services share one allocator instance.
- **`no_std` exceptions.** `init` and `memmgr` are `no_std` and have
  no `#[global_allocator]`. They allocate frames (where applicable)
  via direct kernel object handling at boot, not via `REQUEST_MEMORY_CAPS`.

### Page Reservations

Foreign Memory caps (from devmgr for MMIO, from drivers for shmem
buffers, from fs drivers for zero-copy file pages, from memmgr for
heap-disjoint allocations like long-lived DMA regions) are mapped into
the process via the page-reservation allocator inside `std::sys::seraph`.

- **API surface.** `std::os::seraph::reserve_pages(n) → ReservedRange`
  returns a contiguous unmapped VA range of `n` pages.
  `unreserve_pages(range)` releases it. The caller maps owned Memory
  caps into the reservation with `mem_map`. The caller is responsible
  for `mem_unmap` before `unreserve_pages`.
- **Arena.** Each process carves a fixed-size arena out of its own
  address space at `_start` time. The arena base is a deterministic
  constant.
- **Concurrency.** Reservations are independent across threads; the
  allocator serialises on a spinlock as needed.

The page-reservation allocator is a `std::sys::seraph` concern and is
not exposed to non-std runtimes. `init` and `memmgr` carry small
private VA constants for whatever scratch regions they need.

### Bootstrap Cross-Boundary VAs

The handover pages (`ProcessInfo`, `InitInfo`), the main-thread stack,
the main-thread IPC buffer, and the main-thread TLS block must be
mapped into the new process's address space *before* the process runs
its first instruction. The creator chooses every one of these virtual
addresses per-process — none is a fixed ABI constant — and communicates
them either through the handover struct or, for the handover page itself,
through the entry register. Procmgr and init choose process layouts via
[`shared/process-layout`](../shared/process-layout/)
(`choose_process_layout`); the kernel chooses init's layout via its own
`choose_init_layout`. Both are deterministic today and are the single
seam ASLR ([#39](https://github.com/kottlerg/seraph/issues/39)) replaces
with a per-process entropy draw.

- **`ProcessInfo` page.** Procmgr maps a read-only page at the chosen
  `process_info_va`, writes the `ProcessInfo` struct into it, and delivers
  that address to the child in its entry register (`rdi`/`a0`). The
  child's `_start` takes the address as its argument — it cannot read the
  address from the struct, since the address is what locates the struct.
- **`InitInfo` page.** The kernel maps a read-only page at its chosen
  `init_info_va` for init only, and delivers the address in init's entry
  register the same way.
- **Main-thread stack.** The loader (procmgr or, for memmgr/procmgr,
  init) maps `ProcessInfo.stack_pages` pages ending at the chosen
  `ProcessInfo.stack_top_vaddr` with a guard page below. The page
  count comes from the binary's optional `.note.seraph.stack` ELF note
  (declared via the `process_abi::stack_pages!` / `seraph::stack_pages!`
  macro); binaries that omit the note inherit
  `DEFAULT_PROCESS_STACK_PAGES`. Loaders clamp to
  `MAX_PROCESS_STACK_PAGES`; the pool's available RAM is the remaining
  gate on the resulting `REQUEST_MEMORY_CAPS` calls (memmgr tracks
  per-process frames in a RAM-bound arena, not a fixed quota).
- **Main-thread IPC buffer.** The creator picks a per-process VA and
  writes it into `ProcessInfo.ipc_buffer_vaddr`.
- **Main-thread TLS block.** The creator maps the block at the chosen
  base and records it in `ProcessInfo.main_tls_vaddr` (zero when the
  binary has no `PT_TLS`); the kernel installs the thread pointer, so
  `_start` reads the field only for introspection. Spawned threads
  allocate their TLS blocks from the heap.

These VAs are **runtime values**, not ABI constants: the handover-page
addresses ride the entry register, and the stack/TLS/IPC VAs are
`ProcessInfo` fields (`stack_top_vaddr`, `main_tls_vaddr`,
`ipc_buffer_vaddr`). The only handover constants the ABI crates still
declare are policy bounds — `DEFAULT_PROCESS_STACK_PAGES`,
`MAX_PROCESS_STACK_PAGES`, `PROCESS_MAIN_TLS_MAX_PAGES`,
`INIT_STACK_PAGES`, `INIT_INFO_MAX_PAGES` — not layout addresses. The
default addresses the deterministic choosers return live in
`shared/process-layout` (and the kernel's `choose_init_layout`).

See [`process-lifecycle.md`](process-lifecycle.md) for the full
handover discipline.

---

## Memory Allocation Contract

memmgr serves frame requests over IPC. The contract:

- **Request shape.** `REQUEST_MEMORY_CAPS(want_pages, flags)`. `flags`
  carries `REQUIRE_CONTIGUOUS`; unset means best-effort.
- **`REQUIRE_CONTIGUOUS` reply.** A single Memory cap covering exactly
  `want_pages`, or an `OutOfMemoryContiguous` error.
- **Best-effort reply.** One or more Memory caps whose page counts sum
  to `want_pages`. The reply carries each returned cap's page count
  alongside it. memmgr prefers fewer caps over many.
- **No fixed cap-count ceiling.** Replies may use the full IPC
  reply-side cap-slot capacity; there is no 4-cap limit.
- **Caller maps.** Every returned Memory cap is mapped at a caller-
  chosen VA via `mem_map` (which already accepts a multi-page
  `page_count` argument).
- **Caller releases.** `RELEASE_MEMORY_CAPS` returns a granted region to the
  pool mid-life, named by the `phys_base` memmgr reported at grant (the caller
  need not still hold the cap — it may have retyped the region and dropped its
  copy). This keeps a per-unit-of-work retype loop (e.g. ruststd's Thread
  slab per spawn) at a bounded pool footprint; ruststd's pooled object-slab
  pages likewise recycle auto-reclaimed bytes in place and release a retired
  page's grant once every object retyped from it has died. Process death
  triggers automatic reclamation via procmgr's `PROCESS_DIED` notification to
  memmgr.

Authoritative wire shape lives in
[`services/memmgr/docs/ipc-interface.md`](../services/memmgr/docs/ipc-interface.md).

---

## Kernel-Side Non-Concerns

The kernel does not track per-process memory abstractions; userspace
owns them.

- **Heap** — the kernel only sees mappings of Memory caps at user-
  supplied VAs.
- **VA allocation policy** — the kernel enforces page alignment and
  the user-half bound; it does not track or allocate VAs.
- **Memory ownership beyond the derivation tree** — the kernel does
  not know which process "owns" a Memory.
- **Process death implications for memory** — when a process's
  `AddressSpace` is revoked, the kernel tears down threads and page
  tables. memmgr's reclamation runs separately, driven by procmgr's
  death notification.

The userspace process abstraction itself is owned by
[`architecture.md`](architecture.md) §"Kernel Primitives vs.
Userspace Abstractions".

File-backed access via `mmap()` does not exist. Zero-copy file access
is via fs-driver IPC returning Memory caps for file pages, mapped by
the client through the page-reservation allocator.

Lazy or demand backing of a reservation — mapping frames only on first
access rather than up front — is a userspace-pager policy built on the
fault-handler protocol ([Fault Handling](fault-handling.md); specified, not
yet implemented), not a kernel feature.

---

## Summarized By

[README.md](../README.md), [Memory Model](memory-model.md), [Architecture Overview](architecture.md), [memmgr/README.md](../services/memmgr/README.md), [procmgr/README.md](../services/procmgr/README.md), [ruststd/README.md](../runtime/ruststd/README.md)
