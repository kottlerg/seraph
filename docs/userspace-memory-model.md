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
  frame pool. Allocates Frame capabilities to all std-built services
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
  allocator for foreign Frame mappings.

The kernel hands the initial RAM frame caps to init at boot. Init
transfers them to memmgr (derive-twice). From that point on, memmgr is
the sole userspace authority over RAM frame allocation; the kernel does
not delegate further to anyone.

No process manipulates another process's address space. Sharing is
explicit and capability-mediated: a Frame cap is sent over IPC and the
receiver maps it into its own address space at a VA the receiver chose.

---

## VA Management Surfaces

Every process manages its own virtual address space through three
disjoint surfaces:

| Surface | Granularity | Owner | Used for |
|---|---|---|---|
| Byte heap | Bytes | `std::sys::seraph::alloc` (`#[global_allocator]`) | `Box`, `Vec`, `String`, all `alloc`/`std` collections |
| Page reservations | 4 KiB pages | `std::sys::seraph` | Foreign Frame mappings: MMIO, DMA, shmem, zero-copy file pages, ELF-load scratch, per-thread stacks and IPC buffers when not heap-allocated |
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

- **Backing store.** The allocator's grow path requests Frame caps
  from memmgr via `REQUEST_FRAMES` on the process's
  `ProcessInfo.memmgr_endpoint_cap` and maps them at a contiguous VA
  range above its current high-water mark. Multi-page contiguous
  caps (one cap covering many pages) are requested when available;
  the multi-page-cap reply path collapses what would otherwise be
  many single-page IPCs into a single round.
- **Bootstrap.** `std::os::seraph::_start` calls `REQUEST_FRAMES`
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
  via direct kernel object handling at boot, not via `REQUEST_FRAMES`.

### Page Reservations

Foreign Frame caps (from devmgr for MMIO, from drivers for shmem
buffers, from fs drivers for zero-copy file pages, from memmgr for
heap-disjoint allocations like long-lived DMA regions) are mapped into
the process via the page-reservation allocator inside `std::sys::seraph`.

- **API surface.** `std::os::seraph::reserve_pages(n) → ReservedRange`
  returns a contiguous unmapped VA range of `n` pages.
  `unreserve_pages(range)` releases it. The caller maps owned Frame
  caps into the reservation with `mem_map`. The caller is responsible
  for `mem_unmap` before `unreserve_pages`.
- **Arena.** Each process carves a fixed-size arena out of its own
  address space at `_start` time. The arena base is a deterministic
  constant for the first cut and is structured so a one-line change
  switches to RNG-driven randomisation when the kernel RNG is
  available.
- **Concurrency.** Reservations are independent across threads; the
  allocator serialises on a spinlock as needed.

The page-reservation allocator is a `std::sys::seraph` concern and is
not exposed to non-std runtimes. `init` and `memmgr` carry small
private VA constants for whatever scratch regions they need.

### Bootstrap Cross-Boundary VAs

The handover pages (`ProcessInfo`, `InitInfo`), the main-thread stack,
the main-thread IPC buffer, and the main-thread TLS block must be
mapped into the new process's address space *before* the process runs
its first instruction. The creator picks the VAs and writes them where
the child's `_start` will find them.

- **`ProcessInfo` page.** Procmgr maps a read-only page at
  `PROCESS_INFO_VADDR` (today an ABI constant in
  [`abi/process-abi`](../abi/process-abi/)) and writes the
  `ProcessInfo` struct into it. The child's `_start` reads the
  struct from this VA.
- **`InitInfo` page.** The kernel maps a read-only page at
  `INIT_INFO_VADDR` (today an ABI constant in
  [`abi/init-protocol`](../abi/init-protocol/)) for init only.
- **Main-thread stack.** Procmgr maps `PROCESS_STACK_PAGES` pages
  ending at `PROCESS_STACK_TOP` (today an ABI constant) with a guard
  page below.
- **Main-thread IPC buffer.** Procmgr picks a per-process VA and writes
  it into `ProcessInfo.ipc_buffer_vaddr` — this is already a runtime
  field, not an ABI constant.
- **Main-thread TLS block.** Procmgr maps the block at
  `PROCESS_MAIN_TLS_VADDR` (today an ABI constant); spawned threads
  allocate their TLS blocks from the heap.

Today, the page locations are split between **runtime fields**
(`ipc_buffer_vaddr`) and **ABI constants** (`PROCESS_INFO_VADDR`,
`PROCESS_STACK_TOP`, `PROCESS_MAIN_TLS_VADDR`, `INIT_INFO_VADDR`). The
ASLR work (tracked separately) promotes the constants to runtime
fields: the creator draws each VA from the system RNG and writes it
into a typed field on the handover page, the child reads the field
to locate the page. The mechanism is identical to today's
`ipc_buffer_vaddr` path.

See [`process-lifecycle.md`](process-lifecycle.md) for the full
handover discipline.

---

## Frame Allocation Contract

memmgr serves frame requests over IPC. The contract:

- **Request shape.** `REQUEST_FRAMES(want_pages, flags)`. `flags`
  carries `REQUIRE_CONTIGUOUS`; unset means best-effort.
- **`REQUIRE_CONTIGUOUS` reply.** A single Frame cap covering exactly
  `want_pages`, or an `OutOfMemoryContiguous` error.
- **Best-effort reply.** One or more Frame caps whose page counts sum
  to `want_pages`. The reply carries each returned cap's page count
  alongside it. memmgr prefers fewer caps over many.
- **No fixed cap-count ceiling.** Replies may use the full IPC
  reply-side cap-slot capacity; there is no historical 4-cap limit.
- **Caller maps.** Every returned Frame cap is mapped at a caller-
  chosen VA via `mem_map` (which already accepts a multi-page
  `page_count` argument).
- **Caller releases.** `RELEASE_FRAMES` returns specific caps to the
  pool. Process death triggers automatic reclamation via procmgr's
  `PROCESS_DIED` notification to memmgr.

Authoritative wire shape lives in
[`services/memmgr/docs/ipc-interface.md`](../services/memmgr/docs/ipc-interface.md).

---

## What the Kernel Refuses to Learn

- **Process** — not a kernel object. A "process" is an `AddressSpace`
  plus a `CSpace` plus one or more `Thread`s, grouped by procmgr.
- **Heap** — unknown to the kernel. The kernel only sees mappings of
  Frame caps at user-supplied VAs.
- **VA allocation policy** — the kernel enforces page alignment and
  the user-half bound; it does not track or allocate VAs.
- **Frame ownership beyond the derivation tree** — the kernel does not
  know which process "owns" a Frame; that information lives in
  memmgr's per-process tracking.
- **Process death implications for memory** — when a process's
  `AddressSpace` is revoked, the kernel tears down threads and page
  tables. memmgr's reclamation runs separately, driven by procmgr's
  death notification.
- **Wall-clock time** — see [`memory-model.md`](memory-model.md) for
  the broader kernel-scope statement; not a memory concern, but
  related in spirit.

---

## ASLR Readiness

The system is ASLR-ready by design and ASLR-pending by implementation:

- The kernel never reads workspace VA constants; every mapping VA is
  user-supplied at `mem_map` time.
- memmgr never reads VA constants; it returns Frame caps that are VA-
  agnostic.
- `std::sys::seraph` chooses heap and page-reservation VAs at
  process-startup time, structured so substituting an RNG-derived base
  is a one-line change.
- The creator chooses `ProcessInfo`-runtime-field VAs per child today.
  ASLR promotes the remaining ABI-constant VAs to runtime fields
  identically.

The randomisation source is the kernel RNG. Until that exists, all
VAs are deterministic, but no compile-time VA constant lives outside
the ABI crates and per-component private modules.

---

## Non-Goals

These are rejected mechanisms, not deferred work.

- **Copy-on-write.** No kernel write-trap, no refcount-on-write
  frames, no frame-ownership ambiguity. Seraph does not implement
  `fork()`. Zero-copy buffer handoff is via Frame-cap moves over IPC.
- **POSIX file-backed `mmap()`.** No pager protocol, no page-fault
  delivery to userspace, no page cache as a kernel concern. Zero-copy
  file access is via fs-driver IPC returning Frame caps for file
  pages, mapped by the client through the page-reservation
  allocator.
- **Wall-clock in the kernel.** The kernel exposes only monotonic
  elapsed time. Wall-clock is a userspace `timed` service.

---

## Summarized By

[Memory Model](memory-model.md), [Process Lifecycle](process-lifecycle.md), [Architecture Overview](architecture.md), [memmgr/README.md](../services/memmgr/README.md), [procmgr/README.md](../services/procmgr/README.md), [ruststd/README.md](../runtime/ruststd/README.md)
