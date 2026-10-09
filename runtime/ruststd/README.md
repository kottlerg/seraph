# ruststd

Rust standard library platform layer for Seraph (`std::sys::seraph`).

This is the OS-specific backend that allows Rust's `std` to work on Seraph.
It implements the platform interface that `std` requires — threads, I/O,
filesystem, process management, time — using Seraph's native IPC and
syscall interfaces.

ruststd is shipped as an overlay over the upstream Rust source tree;
Seraph-specific files live under `src/sys/seraph` and `src/os/seraph` in the
overlay. The build pipeline applies the overlay onto a vendored
`library/std` checkout per
[`docs/build-system.md`](../../docs/build-system.md).

One overlay lists `seraph` among std's recognised target OSes (in
`library/std/build.rs`), so this `std` is built as a normal stable crate
rather than `restricted_std`-gated. Downstream seraph bins therefore consume
`std` with no `#![feature(restricted_std)]` opt-in (see
[`docs/build-system.md`](../../docs/build-system.md)).

---

## Source Layout

```
ruststd/
├── README.md
├── argv-env/                   # `ruststd-argv-env` crate: pure, host-tested argv/env
│   └── src/lib.rs              #   blob parsers; also a rustc-dep-of-std dep of overlaid std
├── patches/                    # upstream library/std patches applied during overlay assembly
└── src/                        # std PAL overlay, copied into vendored library/std at build time
    ├── os/
    │   └── seraph.rs           # std::os::seraph surface (startup info, caps, cwd)
    └── sys/                    # std::sys::seraph backends, one directory per area
        ├── alloc/              # byte heap (GlobalAlloc for System)
        ├── args/               # std::env::args — consumes argv_env::next_field
        ├── env/                # std::env::{var,vars,…} —
        │                         consumes argv_env::{next_field,split_key_value}
        ├── fs/                 # filesystem over the namespace protocol
        ├── pipe/               # stdio pipe backing
        ├── process/            # process spawn
        ├── reserve/            # page-reservation surface
        ├── stdio/              # stdout/stderr
        ├── sync/               # mutex / rwlock / once / condvar / thread parking
        ├── thread/             # thread spawn and join
        └── time/               # monotonic and system clocks
```

---

## VA Management Surfaces

`std::sys::seraph` is the per-process owner of virtual-address policy. It
exposes two distinct surfaces; the third (bootstrap-cross-boundary VAs) is
chosen by the process creator and only consumed by std at `_start`. See
[`docs/userspace-memory-model.md`](../../docs/userspace-memory-model.md) for
the full contract.

### Byte heap (`System`)

`std::sys::seraph::alloc` implements `GlobalAlloc` for std's default `System`
allocator, so no `#[global_allocator]` override is needed. Every `Box`, `Vec`,
`String`, and `alloc`/`std` collection allocates here. The grow path
requests Memory caps from memmgr via `memmgr_labels::REQUEST_MEMORY_CAPS` on
`ProcessInfo.memmgr_endpoint_cap`, mapping them at a contiguous VA above the
heap's high-water mark with a single multi-page `mem_map` per returned cap.
The bootstrap heap is allocated by `std::os::seraph::_start` before
`fn main()` runs. On OOM, `GlobalAlloc::alloc` returns null and the `alloc`
crate aborts through `handle_alloc_error`; nothing unwinds. See
[§ Byte Heap](../../docs/userspace-memory-model.md#byte-heap).

### Page reservations

For foreign Memory caps (MMIO from devmgr, DMA buffers from drivers, shmem
backings, zero-copy file pages from fs drivers, ELF-load scratch in
procmgr), `std::sys::seraph` exposes a page-granular reservation allocator:

```rust
let range = std::os::seraph::reserve_pages(n)?;     // unmapped VA range
std::os::seraph::fund_aspace_pt_budget(self_aspace, n); // fund PT growth
syscall::mem_map(memory_cap, self_aspace, range.va, 0, n, prot)?;
// ... use the mapping ...
syscall::mem_unmap(self_aspace, range.va, n)?;
std::os::seraph::unreserve_pages(range);
```

Mapping a foreign Memory cap into a retype-backed `AddressSpace` first funds
that AS's page-table growth budget: `fund_aspace_pt_budget(self_aspace, n)`
acquires a memmgr-backed RETYPE Memory cap and augments the AS's PT pool via
`cap_create_aspace`. It MUST be called after reserving VA and before
`mem_map`/`mmio_map`, or the map fails with `OutOfMemory`.

The arena is carved out of the process's address space on first use, at a
base drawn per process from a fixed 64 GiB window via `SYS_GETRANDOM`
(ASLR, [#39](https://github.com/kottlerg/seraph/issues/39); deterministic
default only if the draw fails). The caller owns `mem_map`/`mem_unmap`;
the allocator only manages VA space. See
[§ Page Reservations](../../docs/userspace-memory-model.md#page-reservations).

#### Spawned-thread stacks

`std::thread::spawn` gives each spawned thread its own stack, allocated by `sys/thread` as a
consumer of the page-reservation surface above. In a demand-paged process
(`StartupInfo.pager_endpoint_cap` non-zero) the stack is a page reservation of one guard page
below the usable pages. Only the usable pages are registered with memmgr through
[`REGISTER_REGION`](../../services/memmgr/docs/ipc-interface.md#label-7-register_region), so
memmgr backs each on first touch; the guard page stays unregistered. An overflow whose first
touch lands in the guard page faults on an address the pager declines, and the fault ends the
whole process, per [docs/fault-handling.md § Reply](../../docs/fault-handling.md#reply),
[docs/process-lifecycle.md § Process Death](../../docs/process-lifecycle.md#process-death), and
[Capability Model § "Kill process" pattern](../../docs/capability-model.md#kill-process-pattern).
The userspace targets emit no stack probes, so a frame larger than one page can skip the guard
and write into an adjacent registered region, such as another thread's stack, which memmgr
backs without a fault ([#445](https://github.com/kottlerg/seraph/issues/445)). The usable
size is the larger of the requested stack size (at least `DEFAULT_MIN_STACK_SIZE`, 64 KiB)
and 512 pages (2 MiB). If the reservation, the page-table funding, or the registration fails,
or the process is not demand-paged, the stack is instead an eager byte-heap allocation of the
requested size (at least 64 KiB, rounded up to whole pages) with no guard page. `join` frees
the stack once the thread has left user mode: a demand stack through
[`UNREGISTER_REGION`](../../services/memmgr/docs/ipc-interface.md#label-9-unregister_region)
and release of its reservation, a heap stack through `dealloc`. A detached thread's stack is
freed the same way by the next spawn, join, or detach in the process after the kernel posts
that thread's death, or leaks until process exit when the reaper could not register the
thread at spawn (no death queue, no free slot, or the observer bind failed) or the kernel
dropped the death post because the process's death queue (128 entries) was full.

### Bootstrap-cross-boundary VAs

`_start` reads `ProcessInfo` to learn the IPC-buffer VA, the memmgr/procmgr
endpoint slots, and other parent-chosen state. It does not allocate these
VAs — the process creator chose them (init for procmgr, procmgr for every
other std-built process; see the owner column of
[§ VA Management Surfaces](../../docs/userspace-memory-model.md#va-management-surfaces)).
Subsequent foreign mappings go through the page-reservation allocator above. See
[§ Bootstrap Cross-Boundary VAs](../../docs/userspace-memory-model.md#bootstrap-cross-boundary-vas).

---

## Namespace capabilities

`std::os::seraph` exposes two process-global namespace caps that anchor
`std::fs` path resolution:

- **System root cap** (`root_dir_cap()`) — badged SEND on vfsd's
  namespace endpoint addressing the synthetic system root. Absolute
  paths (leading `/`) start every per-component `NS_LOOKUP` walk
  here.
- **Current directory cap** (`current_dir_cap()`) — badged SEND on
  some namespace endpoint addressing a directory node. Relative paths
  resolve from this cap.

```rust
let root: u32 = std::os::seraph::root_dir_cap();    // 0 if no root attached
let cwd:  u32 = std::os::seraph::current_dir_cap(); // 0 if no cwd attached

// Walk the root cap to a path and install the resolved directory cap
// as the process's cwd. The walk fails iff the path is unreachable
// through the root.
std::os::seraph::set_current_dir("/data")?;
```

`_start` reads `ProcessInfo.system_root_cap` and
`ProcessInfo.current_dir_cap` and installs both before `fn main()`
runs. Caps are zero unless the spawner delivered them via
`procmgr_labels::CONFIGURE_NAMESPACE` (`caps[0]` = root, `caps[1]`
= cwd). A process given zero root has no filesystem access — `std::fs`
returns `Unsupported`. A process with a non-zero root but zero cwd
can open absolute paths only; relative paths return `Unsupported`
until `set_current_dir` installs a cwd cap.

The setter is the seraph-native cwd primitive. The env-dispatch overlay
(a patch to `library/std/src/env.rs`) bridges the upstream API to it:
`std::env::set_current_dir` delegates to `std::os::seraph::set_current_dir`,
which walks the root cap and installs the cwd cap and its path string
together. `std::env::current_dir` returns the recorded path, or
`Unsupported` until one is recorded, because the startup cwd cap carries
no path string.

`Command::spawn` defaults the child's root cap to a `cap_copy` of the
spawner's `root_dir_cap()` (parent-inherit); explicit override via
`std::os::seraph::process::CommandExt::namespace_cap` or
`cwd_dir_cap`. `Command::cwd("/data")` walks the spawner's root to the
path and delivers the resulting cap as the child's initial
`current_dir_cap`.

The cap-as-namespace model that defines this surface lives in
[`docs/namespace-model.md`](../../docs/namespace-model.md); the wire
protocol is in
[`shared/namespace-protocol/README.md`](../../shared/namespace-protocol/README.md).

---

## Implementation order

ruststd is implemented before [`libc/`](../libc/README.md), which is design intent and not
yet implemented. Native Rust `std` does not go through libc; it maps directly onto Seraph
primitives.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/userspace-memory-model.md](../../docs/userspace-memory-model.md) | Three-surface VA model, frame-allocation contract |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | ProcessInfo handover, `memmgr_endpoint_cap` discipline, process death |
| [docs/fault-handling.md](../../docs/fault-handling.md) | Pager fault reply: `FAULT_REPLY_KILL` declines an unregistered guard-page fault, killing the faulting thread as an unhandled fault |
| [docs/capability-model.md](../../docs/capability-model.md) | "Kill process" pattern: a terminal fault on any thread tears down the whole process |
| [services/memmgr/docs/ipc-interface.md](../../services/memmgr/docs/ipc-interface.md) | Wire shape of `REQUEST_MEMORY_CAPS`/`RELEASE_MEMORY_CAPS`, `REGISTER_REGION`/`UNREGISTER_REGION` |
| [abi/process-abi/README.md](../../abi/process-abi/README.md) | `ProcessInfo`, `StartupInfo`, `main()` signature |

---

## Summarized By

[abi/process-abi/README.md](../../abi/process-abi/README.md),
[Namespace Model](../../docs/namespace-model.md), [Storage](../../docs/storage.md),
[programs/threadstack/README.md](../../programs/threadstack/README.md),
[runtime/libc/README.md](../libc/README.md),
[`.svc` Service Definitions](../../services/svcmgr/docs/service-definitions.md)
