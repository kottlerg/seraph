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

---

## VA Management Surfaces

`std::sys::seraph` is the per-process owner of virtual-address policy. It
exposes two distinct surfaces; the third (bootstrap-cross-boundary VAs) is
chosen by the process creator and only consumed by std at `_start`. See
[`docs/userspace-memory-model.md`](../../docs/userspace-memory-model.md) for
the full contract.

### Byte heap (`#[global_allocator]`)

`std::sys::seraph::alloc` declares the global allocator. Every `Box`, `Vec`,
`String`, and `alloc`/`std` collection allocates here. The grow path
requests Frame caps from memmgr via `memmgr_labels::REQUEST_FRAMES` on
`ProcessInfo.memmgr_endpoint_cap`, mapping them at a contiguous VA above the
heap's high-water mark with a single multi-page `mem_map` per returned cap.
The bootstrap heap is allocated by `std::os::seraph::_start` before
`fn main()` runs; OOM panics the thread.

### Page reservations

For foreign Frame caps (MMIO from devmgr, DMA buffers from drivers, shmem
backings, zero-copy file pages from fs drivers, ELF-load scratch in
procmgr), `std::sys::seraph` exposes a page-granular reservation allocator:

```rust
let range = std::os::seraph::reserve_pages(n)?;     // unmapped VA range
syscall::mem_map(frame_cap, self_aspace, range.va, 0, n, prot)?;
// ... use the mapping ...
syscall::mem_unmap(self_aspace, range.va, n)?;
std::os::seraph::unreserve_pages(range);
```

The arena is carved out of the process's address space at `_start` time at
a deterministic constant base; the implementation is structured so a
one-line change switches to RNG-driven randomisation when the kernel RNG is
available. The caller owns `mem_map`/`mem_unmap`; the allocator only
manages VA space.

### Bootstrap-cross-boundary VAs

`_start` reads `ProcessInfo` to learn the IPC-buffer VA, the memmgr/procmgr
endpoint slots, and other parent-chosen state. It does not allocate these
VAs — procmgr (or for init, the kernel) chose them. Subsequent foreign
mappings go through the page-reservation allocator above.

---

## Namespace capabilities

`std::os::seraph` exposes two process-global namespace caps that anchor
`std::fs` path resolution:

- **System root cap** (`root_dir_cap()`) — tokened SEND on vfsd's
  namespace endpoint addressing the synthetic system root. Absolute
  paths (leading `/`) start every per-component `NS_LOOKUP` walk
  here.
- **Current directory cap** (`current_dir_cap()`) — tokened SEND on
  some namespace endpoint addressing a directory node. Relative paths
  resolve from this cap.

```rust
let root: u32 = std::os::seraph::root_dir_cap();    // 0 if no root attached
let cwd:  u32 = std::os::seraph::current_dir_cap(); // 0 if no cwd attached

// Walk the root cap to a path and install the resolved directory cap
// as the process's cwd. The walk fails iff the path is unreachable
// through the root.
std::os::seraph::set_current_dir("/srv")?;
```

`_start` reads `ProcessInfo.system_root_cap` and
`ProcessInfo.current_dir_cap` and installs both before `fn main()`
runs. Caps are zero unless the spawner delivered them via
`procmgr_labels::CONFIGURE_NAMESPACE` (`caps[0]` = root, `caps[1]`
= cwd). A process given zero root has no filesystem access — `std::fs`
returns `Unsupported`. A process with a non-zero root but zero cwd
can open absolute paths only; relative paths return `Unsupported`
until `set_current_dir` installs a cwd cap.

The setter is the seraph-native cwd primitive. The upstream
`std::env::set_current_dir` / `current_dir` currently return
`Unsupported` because seraph lacks a `pal/` entry that bridges to the
cap-native machinery.

`Command::spawn` defaults the child's root cap to a `cap_copy` of the
spawner's `root_dir_cap()` (parent-inherit); explicit override via
`std::os::seraph::process::CommandExt::namespace_cap` or
`cwd_dir_cap`. `Command::cwd("/srv")` walks the spawner's root to the
path and delivers the resulting cap as the child's initial
`current_dir_cap`.

The cap-as-namespace model that defines this surface lives in
[`docs/namespace-model.md`](../../docs/namespace-model.md); the wire
protocol is in
[`shared/namespace-protocol/README.md`](../../shared/namespace-protocol/README.md).

---

## Implementation order

ruststd is implemented before `libc/`. Native Rust `std` support does not
require a POSIX layer; it maps directly onto Seraph primitives.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/userspace-memory-model.md](../../docs/userspace-memory-model.md) | Three-surface VA model, frame-allocation contract |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | ProcessInfo handover, `memmgr_endpoint_cap` discipline |
| [services/memmgr/docs/ipc-interface.md](../../services/memmgr/docs/ipc-interface.md) | Wire shape of `REQUEST_FRAMES`/`RELEASE_FRAMES` |
| [abi/process-abi/README.md](../../abi/process-abi/README.md) | `ProcessInfo`, `StartupInfo`, `main()` signature |

---

## Summarized By

[Userspace Memory Model](../../docs/userspace-memory-model.md)
