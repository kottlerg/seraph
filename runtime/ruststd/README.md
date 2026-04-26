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
