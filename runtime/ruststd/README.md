# ruststd

Rust standard library platform layer for Seraph (`std::sys::seraph`).

This is the OS-specific backend that allows Rust's `std` to work on Seraph.
It implements the platform interface that `std` requires — threads, I/O,
filesystem, process management, time — using Seraph's native IPC and
syscall interfaces.

ruststd is shipped as an overlay over the upstream Rust source tree;
Seraph-specific files live under `src/sys/<area>/seraph.rs` and `src/os/seraph.rs` in the
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
│   └── src/lib.rs              #   blob parsers and the spawner's window fill; also a
│                               #   rustc-dep-of-std dep of overlaid std
├── death-queues/               # `ruststd-death-queues` crate: pure, host-tested death-queue
│   └── src/                    #   growth policy and thread-reaper slot registry; a
│                               #   rustc-dep-of-std dep of overlaid std (not re-exported),
│                               #   and the policy shared/death-set follows for services
├── heap-fit/                   # `ruststd-heap-fit` crate: pure, host-tested placement rule
│   └── src/lib.rs              #   of the byte heap (where a request lands in a free block,
│                               #   what stays free); a rustc-dep-of-std dep of overlaid std
├── spin-wait/                  # `ruststd-spin-wait` crate: pure, host-tested contended-wait
│   └── src/lib.rs              #   policy of the overlay's spin mutex (spin, then sleep); a
│                               #   rustc-dep-of-std dep of overlaid std
├── patches/                    # upstream library/std patches applied during overlay assembly
└── src/                        # std PAL overlay, copied into vendored library/std at build time
    ├── os/
    │   └── seraph.rs           # std::os::seraph surface (startup info, caps, cwd)
    └── sys/                    # std::sys::seraph backends, one directory per area
        ├── alloc/              # byte heap (the platform allocator behind std's allocators)
        ├── args/               # std::env::args — consumes argv_env field walks
        ├── env/                # std::env::{var,vars,…} —
        │                         consumes argv_env::{next_field,split_key_value}
        ├── fs/                 # filesystem over the namespace protocol
        ├── pipe/               # stdio pipe backing
        ├── process/            # process spawn
        ├── random/             # std::random and HashMap seeds over SYS_GETRANDOM
        ├── reserve/            # page-reservation surface
        ├── stdio/              # stdout/stderr
        ├── sync/               # mutex / rwlock / once / condvar / thread parking
        ├── thread/             # thread spawn, join, and spawn-time priority
        └── time/               # monotonic and system clocks
```

---

## Process Entry and `StartupInfo`

A std-built binary's ELF entry is `std::os::seraph::_start` (`src/os/seraph.rs`). It takes the
address of the read-only `ProcessInfo` page from the entry register and exits with a voluntary
startup-failure code (`STARTUP_FAIL_BAD_ABI`) when the page's version is not `PROCESS_ABI_VERSION`.
It then reads the top of its user half once (`SystemInfoType::UserVaTop`, exposed as
`std::os::seraph::user_va_top()`), which sizes the heap and reservation-arena zones
(`process_layout::growth_zones`), registers the IPC buffer, builds `std::os::seraph::StartupInfo`
from the page, wires stdio, the log and service-registry caps, and the namespace caps, and, when the
page carries a memmgr endpoint, bootstraps the heap against memmgr (exiting with `STARTUP_FAIL_HEAP`
if that fails), and, when the page carries a pager and the image is `ET_DYN`, registers the
main-thread stack's demand-growth range
([§ Bootstrap-cross-boundary VAs](#bootstrap-cross-boundary-vas)). Last it runs the
rustc-synthesised `main`, which drives `std::rt::lang_start` and the binary's idiomatic
`fn main()`; when `main` returns, `_start` sends `FS_CLOSE` for every `std::fs::File` still open,
closes the stdio pipes, and exits the process with its return code. `std::process::exit` runs
the same two steps before its exit syscall, so the fs driver drops the opens, and the release
SENDs they hold, of `File`s the process never drops
([services/fs/docs/fs-driver-protocol.md](../../services/fs/docs/fs-driver-protocol.md)
§ Label 18). A crash or a kill runs neither, and sends no `FS_CLOSE`. Each `File` holds its open's
liveness cap until its close, and the process's `CSpace` takes the cap with it, so the driver
releases such an open, with its release SEND, at its next sweep. Until then the endpoint that SEND
names outlives the process, and memmgr holds the frame it lives in out of its pool until the SEND
goes
([services/memmgr/docs/memory-pool.md](../../services/memmgr/docs/memory-pool.md#reclamation)
§ Reclamation).

`std::os::seraph::StartupInfo` is std's own type, not a re-export of `process_abi::StartupInfo`
(which only memmgr's bespoke runtime constructs); a binary reads it through
`std::os::seraph::startup_info()`, or `try_startup_info()` where `_start` may not have run. It
carries the fields of the process-abi type plus three that `ProcessInfo` delivers and that type
omits: `sched_control_cap`, `initial_priority`, and `log_send_cap`. The `ProcessInfo` layout and
its version gating are defined in [abi/process-abi/README.md](../../abi/process-abi/README.md).

---

## VA Management Surfaces

`std::sys::seraph` is the per-process owner of virtual-address policy. It
exposes two distinct surfaces; the third (bootstrap-cross-boundary VAs) is
chosen by the process creator and consumed by std at `_start`, which in a
demand-paged `ET_DYN` process extends the main-thread stack below its committed pages
([§ Bootstrap-cross-boundary VAs](#bootstrap-cross-boundary-vas)). See
[`docs/userspace-memory-model.md`](../../docs/userspace-memory-model.md) for
the full contract.

### Byte heap (`System`)

`std::sys::seraph::alloc` provides the platform allocator functions behind std's `System`
allocator and its default global allocator, so no `#[global_allocator]` override is needed.
Every `Box`, `Vec`, `String`, and `alloc`/`std` collection allocates here. The grow path
requests Memory caps from memmgr via `memmgr_labels::REQUEST_MEMORY_CAPS` on
`ProcessInfo.memmgr_endpoint_cap`, mapping them at a contiguous VA above the
heap's high-water mark with a single multi-page `mem_map` per returned cap;
a grow covers the whole request, and an allocation grows again while each
grow maps pages. The heap floor is installed by `std::os::seraph::_start`
before `fn main()` runs: a demand region registered with memmgr in a
demand-paged process, whose pages the pager backs on their first touch
(`Thread::new` touches a spawned thread's IPC buffer, a heap page, before the
thread registers it, since the kernel's IPC-buffer copies need it backed), and
an eager mapping otherwise. On OOM, the platform `alloc` returns null and the `alloc` crate
aborts through `handle_alloc_error`; nothing unwinds. See
[§ Byte Heap](../../docs/userspace-memory-model.md#byte-heap).

One spin mutex (`SpinMutex`, `src/sys/alloc/seraph.rs`) guards the byte heap.
The same type guards the object slabs, the page-reservation arena, and the thread reaper's
tables. A thread that finds it held spins through a bounded number of failed attempts, then
sleeps between attempts (the `ruststd-spin-wait` crate's `SPIN_ATTEMPTS` and `SLEEP_MS`). The
sleep lets a holder below the waiter run on the waiter's CPU. A waiter in the strict-priority
class runs before every fair thread, and before every lower-level strict-priority thread, on its
CPU ([core/kernel/docs/scheduler.md](../../core/kernel/docs/scheduler.md) § Scheduling Classes).
Such a waiter that only spun would starve a holder below it there and, with no other CPU idle to
pull the holder (that document's § Load Balancing), wait forever.

### Page reservations

For foreign Memory caps (MMIO from devmgr, DMA buffers from drivers, shmem
backings, zero-copy file pages from fs drivers, ELF-load scratch in
procmgr), `std::sys::seraph` exposes a page-granular reservation allocator:

```rust
let range = std::os::seraph::reserve_pages(n)?;     // unmapped VA range
std::os::seraph::fund_aspace_pt_budget(self_aspace, n); // fund PT growth
// SAFETY: `range` is an owned reservation; no Rust object or IPC page lies in it.
unsafe { syscall::mem_map(memory_cap, self_aspace, range.va, 0, n, prot)? };
// ... use the mapping ...
// SAFETY: no Rust reference into the range is live any more.
unsafe { syscall::mem_unmap(self_aspace, range.va, n)? };
std::os::seraph::unreserve_pages(range);
```

`mem_map`, `mem_unmap`, and `mmio_map` are `unsafe fn`: on the caller's own address space they
change the memory behind a span, so the caller states why no live Rust object or registered IPC
page lies in it, and, for `mmio_map`, that only raw pointers reach the mapping (the `# Safety`
sections the [`shared/syscall` README](../../shared/syscall/README.md) summarizes). A fresh
reservation discharges the first by construction.

Mapping a foreign Memory cap into a retype-backed `AddressSpace` first funds
that AS's page-table growth budget: `fund_aspace_pt_budget(self_aspace, n)`
acquires a memmgr-backed RETYPE Memory cap and augments the AS's PT pool via
`cap_create_aspace`. It MUST be called after reserving VA and before
`mem_map`/`mmio_map`, or the map fails with `OutOfMemory`.

The arena is carved out of the process's address space on first use, in the
arena zone sized to the user half, at a base drawn per process from the
zone's window via `SYS_GETRANDOM` (ASLR,
[#39](https://github.com/kottlerg/seraph/issues/39); deterministic default
only if the draw fails). The caller owns `mem_map`/`mem_unmap`; the
allocator only manages VA space, and a release never loses freed VA. See
[§ Page Reservations](../../docs/userspace-memory-model.md#page-reservations).

#### Spawned-thread stacks

`std::thread::spawn` gives each spawned thread its own stack, allocated by `sys/thread` as a
consumer of the page-reservation surface above. In a demand-paged process
(`StartupInfo.pager_endpoint_cap` non-zero) the stack is a page reservation of one guard page below
the usable pages. Only the usable pages are registered with memmgr through
[`REGISTER_REGION`](../../services/memmgr/docs/ipc-interface.md#label-7-register_region), so memmgr
backs each on first touch; the guard page stays unregistered. An overflow whose first touch lands in
the guard page faults on an address the pager declines, and the fault ends the whole process, per
[docs/fault-handling.md § Reply](../../docs/fault-handling.md#reply),
[docs/process-lifecycle.md § Process Death](../../docs/process-lifecycle.md#process-death), and
[Capability Model § "Kill process" pattern](../../docs/capability-model.md#kill-process-pattern).
The std userspace targets emit inline stack probes
([docs/build-system.md § Custom Targets](../../docs/build-system.md#custom-targets)), so a frame
larger than one page touches each of its pages in turn and faults on the guard page rather than
skipping it into an adjacent registered region, such as another thread's stack, which memmgr would
back without a fault. The usable size is the larger of the requested stack size (at least
`DEFAULT_MIN_STACK_SIZE`, 64 KiB) and 512 pages (`DEFAULT_DEMAND_STACK_PAGES`, 2 MiB). If the
reservation, the page-table funding, or the registration fails, or the process is not demand-paged,
the stack is instead an eager byte-heap allocation of the requested size (at least 64 KiB, rounded
up to whole pages) with no guard page. Before starting the thread, the spawn copies the spawning
thread's fault-handler bindings onto it (`SYS_THREAD_INHERIT_FAULT_HANDLER`), the pager of a
demand-paged process among them, and a refused copy fails the spawn with the error rather than
starting a thread whose demand faults (its stack's, when the stack is demand-backed) no pager would
serve. `join` frees the stack once the thread has left user mode: a demand stack through
[`UNREGISTER_REGION`](../../services/memmgr/docs/ipc-interface.md#label-9-unregister_region) and,
once memmgr has answered, release of its reservation (kept when no answer comes, since memmgr may
still hold the region), a heap stack through `dealloc`. A detached thread's stack, or that
of a joined thread whose join wait failed with an error other than `Interrupted` (its private
completion notification gone), is freed the same way by the next spawn, join, or detach in the
process after the kernel posts that thread's death (or at once by that detach or join, when the
death post has already landed), or leaks until process exit when the reaper could not register
the thread at spawn (its slot table could not grow, or no death queue could take the observer
bind). The slot table and the death queues grow on demand, each further queue with twice the last
one's observer nodes (the `ruststd-death-queues` crate), and each queue with one entry more than its
nodes. Every queue is drained before each bind, in the same lock hold, so a queue's pending posts
never exceed its nodes plus the one thread bound in that same hold, which is its entries, and no
death post is dropped.

### CSpace slot headroom

A `CSpace` keeps its last `CSPACE_IPC_RECV_RESERVE` free slots for IPC capability transfer, so
its general allocations (`cap_create_*`, `cap_copy`, `cap_derive`, splits) fail with
`OutOfMemory` before its receives do
([docs/capability-model.md](../../docs/capability-model.md) § Address-space and CSpace growth
budgets). Two functions of `std::os::seraph` keep that headroom funded, mirroring the page-table
budget's `fund_aspace_pt_budget`:

```rust
let free = std::os::seraph::cspace_slot_headroom(self_cspace);   // slots above the reserve
std::os::seraph::fund_cspace_slot_budget(self_cspace, n);       // ensure >= n of them
```

- **`cspace_slot_headroom`** returns `CAP_INFO_CSPACE_CAPACITY` less `CAP_INFO_CSPACE_USED`
  and the reserve.
- **`fund_cspace_slot_budget`** requests a memmgr-backed Memory cap through the object slab
  when the headroom falls short of `n` plus a page's slots, or the growth budget
  (`CAP_INFO_CSPACE_BUDGET`) below a page, and donates it with augment-mode `cap_create_cspace`,
  sized by `syscall_abi::cspace_topup_pages`. The page beyond `n` is for the `CSpace`'s body
  arena, which a split or a range-capability copy draws on. It returns `false` if either still
  falls short after the funding rounds.

A process calls it before a known burst of capability acquisitions; fatfs funds its page cache
this way. A long-lived service calls it when the headroom drops below a low-water mark, as
procmgr does ([services/procmgr/README.md](../../services/procmgr/README.md) § CSpace
headroom).

`std::thread::spawn` holds the headroom for the threads it creates itself. Before each spawn,
when the headroom is below `SPAWN_CSPACE_LOW_WATER` (32 slots, about a spawn's worth of caps
with margin) plus a page's slots, or the growth budget below a page
(`syscall_abi::cspace_topup_pages`), it calls `fund_cspace_slot_budget` for
`SPAWN_CSPACE_TOPUP_SLOTS` (128), so a process's live thread count is bound by the RAM memmgr
grants rather than by the `CSpace` its creator seeded, and a process that spawns no thread funds
nothing. A failed top-up does not fail the spawn, which then fails only if a capability
allocation it makes finds the headroom spent.

### Bootstrap-cross-boundary VAs

`_start` reads `ProcessInfo` to learn the IPC-buffer VA, the memmgr/procmgr
endpoint slots, and other parent-chosen state. It does not allocate these
VAs — the process creator chose them (init for procmgr, procmgr for every
other std-built process; see the owner column of
[§ VA Management Surfaces](../../docs/userspace-memory-model.md#va-management-surfaces)).
Subsequent foreign mappings go through the page-reservation allocator above. See
[§ Bootstrap Cross-Boundary VAs](../../docs/userspace-memory-model.md#bootstrap-cross-boundary-vas).

The main-thread stack is the one bootstrap surface std extends. The loader maps the stack's
committed pages (`ProcessInfo.stack_pages`) ending at `ProcessInfo.stack_top_vaddr`, inside the
reservation of `1 + MAX_PROCESS_STACK_PAGES` pages the creator's layout leaves below every stack
top, for every `ET_DYN` image. In a demand-paged process (`ProcessInfo.pager_endpoint_cap`
non-zero) whose image is `ET_DYN` (read from its own ELF header, `__ehdr_start`) `_start` funds the
address space's page-table budget for, and registers with memmgr through
[`REGISTER_REGION`](../../services/memmgr/docs/ipc-interface.md#label-7-register_region), the
pages below the committed ones down to a 512-page (`DEFAULT_DEMAND_STACK_PAGES`, 2 MiB) stack,
the range `process_layout::main_stack_growth` computes, so the main thread's stack grows on first
touch to the size a spawned thread's has. The page below the range stays unregistered as the
guard: an overflow past it faults on an address the pager declines and ends the whole process,
as an overflow of a spawned thread's stack does. A binary whose `stack_pages!` note declares 512
pages or more, a pinned process, an `ET_EXEC` image (which the loaders place at its link
addresses unchecked against the reservation), and a process whose funding or registration fails
keep the committed pages alone, the page below which faults the same way. The range is never
unregistered; memmgr reclaims its frames at process death.

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
let root: u64 = std::os::seraph::root_dir_cap();    // 0 if no root attached
let cwd:  u64 = std::os::seraph::current_dir_cap(); // 0 if no cwd attached

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

The setter is the seraph-native cwd primitive. The paths overlay (a seraph arm in
`library/std/src/sys/paths/mod.rs`) bridges the upstream API to it:
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

## Directory entries

`std::os::seraph::fs::DirEntryExt::file_name_ref` borrows a directory
entry's name from the entry. `DirEntry::file_name` and `DirEntry::path`
allocate a copy, so a caller that must handle out-of-memory reads a
listing's names through the extension (svcmgr's recipe scan does).

---

## Child process handles

`std::os::seraph::process::ChildExt::process_handle` returns a spawned child's
procmgr process-handle cap as the full `u64` capability handle, for the procmgr
labels that take one. `Child::id` returns only the handle's slot index, since
upstream fixes its width at `u32` and the handle's generation sits above that.
`ChildExt::main_thread_cap` returns the child's main-thread capability, which
the spawner keeps from procmgr's create reply until the `Child` drops; a debugger
passes it to the thread syscalls that inspect and modify the child
([docs/fault-handling.md](../../docs/fault-handling.md) § Debugging).

---

## argv and env

`Command::spawn` packs the child's argv and env into a Memory cap the spawner funds and
`CREATE_FROM_FILE` transfers with `CREATE_ARGV_ENV`
([procmgr's IPC interface](../../services/procmgr/docs/ipc-interface.md#label-1-create_process)
§ Label 1, **argv and env**). `std::os::seraph::process::ArgvEnvCap` builds that cap and its
header for any sender of a raw create request (svcmgr's launch and restart, svctest). After the
call the sender passes the reply label to `ArgvEnvCap::settle`, which withholds the run (it stays
charged to the sender) on `ARGV_ENV_STILL_MAPPED`, when procmgr may still map its pages, and
otherwise returns it to memmgr. `spawn` refuses with `ArgumentListTooLong` only when argv
and env together exceed `process_abi::ARGV_ENV_MAX_BYTES` or memmgr refuses the spawner the run
they fill. In the child, `_start` reads both blobs from the argv/env region after the
`ProcessInfo` page ([abi/process-abi/README.md](../../abi/process-abi/README.md) § argv / env
region), confined to that region by `argv_env::blob_span`.

---

## Spawned-thread priority

`std::thread::spawn` places each new thread at the process's `initial_priority`, the level its
spawner gave its initial thread. `std::os::seraph::thread::BuilderExt::spawn_at_priority`
places the thread at another level within the band of the process's `SchedControl` cap
(`StartupInfo::sched_control_cap`) instead, so a server thread that a higher-level client blocks
on runs at that client's level
([core/kernel/docs/scheduler.md](../../core/kernel/docs/scheduler.md) § Priority Inversion
Mitigation); devmgr's DMA thread runs at the boot drivers' level this way. A level of 0, a
process with no `SchedControl` cap, or a level outside the band fails the spawn.

---

## Thread capability

`std::os::seraph::thread::current_thread_cap` returns the calling thread's own Thread capability:
the cap the spawn created a spawned thread with, carrying `RIGHTS_THREAD`, or the initial thread's
`StartupInfo::self_thread`. A thread hands it to another thread of the process to have that thread
bind its fault or upcall handlers, read its registers, or post it an upcall
([fault-handling.md § Asynchronous Upcalls](../../docs/fault-handling.md#asynchronous-upcalls));
the `deadline` fixture's supervisor bounds a spinning worker this way
([programs/deadline/README.md](../../programs/deadline/README.md)).

The reclaim of a spawned thread, by its `join` or by the reaper after a detach, revokes every cap
derived from the spawned thread's cap before it deletes that cap: the copy the thread registered
with procmgr (§ Thread registration), the copies `ATTACH_PROCESS` derived from it for a debugger or
the crash service, and any a process derived itself. A derived cap is therefore gone once the
thread is reclaimed, and the Thread object and its slab run are freed then, as without one.

## Thread registration

Each thread `std::thread::spawn` creates registers itself with procmgr before it runs its code:
its trampoline, once its IPC buffer is set, derives a copy of its own cap with `RIGHTS_THREAD` and
sends it with `REGISTER_THREAD` on the process's procmgr cap
([procmgr IPC Interface](../../services/procmgr/docs/ipc-interface.md) § Label 22:
`REGISTER_THREAD`). procmgr keeps it, so `ATTACH_PROCESS` lists the thread to a debugger and to the
crash service, and binds the thread's exception class under a crash badge of its own, so a fault of
the thread names it (`register_with_procmgr` in `src/sys/thread/seraph.rs`). The registration costs
one IPC per spawn and nothing on any path that does not spawn. A process procmgr did not create,
whose `ProcessInfo` names no procmgr endpoint (procmgr and memmgr), sends none. A refusal or a
failed call leaves the thread unregistered, and it runs as before, its faults reported without
registers; a `NOT_ATTACHABLE` refusal, from a process that declared itself undebuggable
(`DECLARE_NO_DEBUG`), stops every later registration of the process, since the declaration is
one-way, so a declared process registers nothing.

The new thread makes the call, not its spawner, so a spawner never waits on procmgr. A thread
spawned while procmgr is blocked on a request to the same process waits in its registration until
procmgr returns, before running any of its code. Two such spawns exist, and neither can deadlock,
since procmgr's request does not wait on the new thread:

- **fatfs's release watchdog.** procmgr reads a binary through fatfs (`CREATE_FROM_FILE`), and
  fatfs's eviction worker spawns a watchdog thread to send a client `FS_RELEASE_MEMORY` and waits
  for it at most `RELEASE_TIMEOUT_MS` (100 ms) before it revokes the page anyway
  ([Filesystem Driver Protocol](../../services/fs/docs/fs-driver-protocol.md) § Driver-to-client
  release; `services/fs/fat/src/eviction.rs`). The read procmgr waits
  on is served by fatfs's main thread, which answers a request that finds the cache full with an
  error at once rather than waiting for the eviction worker, so procmgr's read returns whatever the
  watchdog does. A watchdog held in its registration past the worker's bound turns that release
  into the worker's revoke without the client's acknowledgement, the path a client that does not
  answer takes; it holds one of the worker's `MAX_WATCHDOGS` slots meanwhile, past which a release
  revokes at once.
- **logd's resync helper.** procmgr writes its log through logd, and logd's main thread spawns the
  helper that walks `QUERY_LIVE_PROCESSES` after its death queue may have dropped a post
  ([services/logd/docs/ipc-interface.md](../../services/logd/docs/ipc-interface.md) § Death-queue
  resync). logd declared itself undebuggable, so only its first spawned thread sends a registration,
  and the helper exists to call procmgr: its registration waits on procmgr exactly as its query
  would, while logd's main thread, which serves procmgr's write, goes on without it.

Two patterns would deadlock, and no in-tree process follows either: a spawner that waits on its new
thread without bound while procmgr waits on that spawner; and a process that hands procmgr a cap
which a newly spawned thread serves (a file or node for `CREATE_FROM_FILE`, say) before that
thread's registration has been served, so procmgr's call on the cap waits on a thread that waits on
procmgr.

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
| [docs/build-system.md](../../docs/build-system.md) | Std userspace target specs, including the inline stack probes that reach a thread stack's guard page |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | ProcessInfo handover, `memmgr_endpoint_cap` discipline, process death |
| [docs/fault-handling.md](../../docs/fault-handling.md) | Pager fault reply: `FAULT_REPLY_FORWARD` declines an unregistered guard-page fault, which the exception handler declines in turn, killing the faulting thread as an unhandled fault |
| [docs/capability-model.md](../../docs/capability-model.md) | "Kill process" pattern: a terminal fault on any thread tears down the whole process |
| [services/memmgr/docs/ipc-interface.md](../../services/memmgr/docs/ipc-interface.md) | Wire shape of `REQUEST_MEMORY_CAPS`/`RELEASE_MEMORY_CAPS`, `REGISTER_REGION`/`UNREGISTER_REGION` |
| [services/procmgr/docs/ipc-interface.md](../../services/procmgr/docs/ipc-interface.md) | `REGISTER_THREAD`, which each spawned thread sends, and the `CREATE_FROM_FILE` a spawn sends |
| [abi/process-abi/README.md](../../abi/process-abi/README.md) | `ProcessInfo` layout and version gating |
| [shared/process-layout/README.md](../../shared/process-layout/README.md) | The stack reservation below every main-thread stack top; `main_stack_growth` |

---

## Summarized By

[abi/process-abi/README.md](../../abi/process-abi/README.md),
[Fault Handling](../../docs/fault-handling.md),
[Namespace Model](../../docs/namespace-model.md),
[Process Lifecycle](../../docs/process-lifecycle.md), [Storage](../../docs/storage.md),
[Userspace Memory Model](../../docs/userspace-memory-model.md),
[programs/threadchurn/README.md](../../programs/threadchurn/README.md),
[programs/threadstack/README.md](../../programs/threadstack/README.md),
[runtime/libc/README.md](../libc/README.md),
[Filesystem Driver Protocol](../../services/fs/docs/fs-driver-protocol.md),
[procmgr IPC Interface](../../services/procmgr/docs/ipc-interface.md),
[`.svc` Service Definitions](../../services/svcmgr/docs/service-definitions.md)
