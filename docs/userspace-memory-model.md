# Userspace Memory Model

How userspace processes in Seraph acquire, own, and manage memory.

---

## Ownership boundaries

Memory authority flows downward:

- **Kernel** — physical frame allocator, page tables, W^X, canonical-address
  enforcement. Does not track named regions; every mapping syscall takes an
  explicit caller-supplied VA.
- **procmgr** — holds root authority over the userspace physical-frame pool
  (delegated by the kernel at the end of boot phase 7). Serves
  `REQUEST_FRAMES` over IPC. Knows nothing about VAs.
- **std::sys::seraph** — per-process. Owns the process's virtual address space
  layout, hosts the `#[global_allocator]`, and drives the `alloc` crate for
  every std-built service (shipped as the `ruststd/` overlay folded into
  `library/std`). procmgr keeps a bespoke `core + alloc`-free runtime (no
  heap, no std collections); see `procmgr/src/rt.rs`.

No process manipulates another process's aspace. Sharing is explicit and
capability-mediated: a `Frame` cap is sent over IPC and the receiver maps
it into its own aspace.

---

## Virtual address zones

Userspace uses the lower half of the 48-bit canonical address range
(`0x0000_0000_0000_0000` – `0x0000_7FFF_FFFF_FFFF`).
Zones are carved statically and exposed from `shared/va_layout`.
`const_assert!` enforces non-overlap.

Typical layout (high → low):

- `ProcessInfo` page (read-only, kernel-populated)
- Main-thread stack (with guard page below)
- Worker-thread stacks / IPC buffers (per-thread)
- Heap (grows upward from `HEAP_BASE`)
- Service-specific scratch (BAR, DMA, temp mappings)
- ELF load region (code / data / bss)

Exact constants live in `shared/va_layout/src/lib.rs`. No other file in
the workspace defines VA constants; every site imports from `va_layout`.

---

## The heap

`std::sys::seraph::alloc` declares `#[global_allocator]`, so the full
`alloc` / `std` collections surface (`Box`, `Vec`, `String`, `BTreeMap`,
…) is available to every std-built service.

- **Initial allocation** — `std::os::seraph::_start` bootstraps the heap
  against the process's `procmgr_endpoint` (delivered in `ProcessInfo`)
  before `fn main` runs. Initial frames are requested via `REQUEST_FRAMES`
  and mapped at `va_layout::HEAP_BASE`.
- **Out-of-memory** — `GlobalAlloc::alloc` returns null; the `alloc` crate
  panics; the std panic handler exits the thread. svcmgr observes the
  death via its event queue and applies restart policy. No kernel panic.
- **Thread safety** — a spinlock guards the allocator. Multi-threaded
  services (init main + log thread; vfsd main + worker) share a single
  allocator.
- **procmgr exception** — procmgr cannot bootstrap its heap against
  itself, so it ships without one: `procmgr/src/rt.rs` provides `_start`
  + panic handler and the service runs on `core` + raw syscalls only.

---

## What the kernel refuses to learn

- **Process** — not a kernel object. A "process" is an aspace + cspace +
  one or more threads, grouped by procmgr.
- **Heap** — unknown to the kernel. The kernel only sees mappings of
  frame caps at user-supplied VAs.
- **VA allocation policy** — the kernel enforces page alignment and the
  user-half bound; it does not track or allocate VAs.

---

## Non-goals

These are rejected mechanisms, not deferred work.

- **Copy-on-write.** No kernel write-trap, no refcount-on-write frames,
  no frame-ownership ambiguity. Seraph does not implement `fork()`.
- **POSIX file-backed `mmap()`.** No pager protocol, no page-fault
  delivery to userspace, no page cache as a kernel concern.

---

## Summarized By

[Memory Model](memory-model.md) — system-wide memory architecture.
