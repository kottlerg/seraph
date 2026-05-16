# procmgr

Userspace process lifecycle manager. After init transfers authority,
procmgr owns ELF loading, kernel-object allocation
(`AddressSpace`/`CSpace`/`Thread`), `ProcessInfo` population, and
process-death observation. All non-bootstrap process creation in the
running system goes through procmgr.

procmgr is itself a memmgr client: it is std-using and bootstraps its
heap by calling memmgr on its first IPC. Frame caps for child stacks,
IPC buffers, `ProcessInfo` pages, TLS blocks, and ELF segments come
from memmgr, not from a procmgr-owned pool.

---

## Source Layout

```
procmgr/
├── Cargo.toml                  # Workspace member; std-using binary
├── README.md
├── src/
│   ├── main.rs                 # _start() entry point, IPC dispatch loop
│   ├── loader.rs               # ELF load pipeline
│   └── process.rs              # Per-process state, kernel-object allocation
└── docs/
    └── ipc-interface.md        # procmgr IPC interface specification
```

---

## Responsibilities

- **ELF loading** — parse ELF images from boot modules or filesystem,
  request frames from memmgr, map LOAD segments with correct
  permissions.
- **Process creation** — create `AddressSpace`, `CSpace`, and `Thread`
  kernel objects; configure the thread's address space, CSpace, and
  IPC buffer bindings.
- **Capability delegation** — receive caps from callers (e.g. svcmgr,
  devmgr) for inclusion in the child's CSpace; mint and pass per-process
  initial caps to newly created processes via `ProcessInfo`.
- **memmgr coordination** — call `memmgr.REGISTER_PROCESS` before
  spawning a child to obtain the child's `memmgr_endpoint_cap`; call
  `memmgr.PROCESS_DIED` after a child exits so memmgr can reclaim.
- **Process teardown** — on exit or crash, revoke the process's
  `AddressSpace` capability (which stops all threads bound to it) and
  notify memmgr.
- **Process registry** — maintain a table of running processes; answer
  queries from svcmgr and other services.
- **Per-child log cap seeding** — derive a tokened SEND cap on the
  master log endpoint at every spawn (token = the child's process
  token) and install the slot at `ProcessInfo.log_send_cap`. The
  un-tokened source cap arrives in procmgr's bootstrap round from
  init. Children call `seraph::log!` directly through the seeded
  cap; no `GET_LOG_CAP` discovery roundtrip.
- **Death-notification fan-out to logd** — accept
  `REGISTER_DEATH_EQ` from real-logd (gated by the
  `DEATH_EQ_AUTHORITY` token), store logd's `EventQueue` cap, bind
  it retroactively on every existing thread, and bind it on every
  new spawn alongside procmgr's own death observer (correlator =
  process token, equal to logd's per-sender slot key).

---

## What procmgr does NOT do

- **Allocate or own frames.** memmgr holds the RAM frame pool. procmgr
  is a memmgr client like every other std-built service.
- **Track per-process frame ownership.** memmgr's per-process records
  cover this; procmgr only tracks the kernel objects it owns
  (`AddressSpace`, `Thread`, etc.) plus the procmgr-side process
  registry.
- **Choose virtual addresses inside the running child.** procmgr picks
  bootstrap-cross-boundary VAs (stack, IPC buffer, `ProcessInfo`, TLS
  block); the child's `std::sys::seraph` owns every other VA.
- **Hold or distribute namespace caps.** procmgr holds no system-root
  cap and has no broadcast path. A child's `ProcessInfo.system_root_cap`
  is sourced exclusively from the spawner's
  `CONFIGURE_NAMESPACE` call between create and start; if the spawner
  delivered no cap, the slot stays zero and the child has no
  namespace authority. See
  [`docs/namespace-model.md`](../../docs/namespace-model.md).
- **Walk paths.** procmgr never traverses the namespace tree.
  `CREATE_FROM_FILE` requires the caller to pre-walk and supply a
  resolved file cap.
- **Supervise services.** Crash detection and restart policy are
  svcmgr's role.

---

## IPC Interface

The full procmgr IPC specification is in
[`docs/ipc-interface.md`](docs/ipc-interface.md). Key operations:

- `CREATE_PROCESS(elf_module_cap)` → suspended process handle, child caps
- `CREATE_FROM_FILE(file_cap, file_size, …)` → suspended process handle,
  child caps. Caller has already walked its own namespace cap to the
  binary; procmgr issues `FS_READ` against the supplied file cap.
- `START_PROCESS(process_handle)` — start a previously created process
- `CONFIGURE_NAMESPACE(process_handle)` — install root and (optional)
  cwd caps on the child before start; the sole path that writes
  `ProcessInfo.system_root_cap` / `current_dir_cap`. Procmgr holds no
  namespace cap of its own.

Frame allocation is not part of procmgr's interface; see
[`services/memmgr/docs/ipc-interface.md`](../memmgr/docs/ipc-interface.md).

---

## Process Startup ABI

When procmgr creates a new process, it populates a `ProcessInfo`
handover struct at a well-known virtual address in the new process's
address space. This struct tells the process where to find its initial
capabilities, IPC buffer, memmgr endpoint, and startup context. The
handover contract is defined in
[`abi/process-abi`](../../abi/process-abi/README.md).

procmgr is the sole producer of `ProcessInfo` for all non-init
processes. Init and ktest use a different handover path
(kernel-produced `InitInfo` from
[`abi/init-protocol`](../../abi/init-protocol/README.md)) but share the
same `main()` signature defined in `abi/process-abi`.

---

## Relationship to memmgr

procmgr and memmgr are sister tier-1 services with disjoint authority.
memmgr owns the frame pool; procmgr owns process lifecycle. procmgr is
the only privileged caller of memmgr's procmgr-only labels
(`REGISTER_PROCESS`, `PROCESS_DIED`); no other service can mint or
retire process tokens against memmgr. See
[`docs/process-lifecycle.md`](../../docs/process-lifecycle.md) §"Authority
Boundaries Between memmgr and procmgr" for the full split.

---

## Relationship to svcmgr

svcmgr monitors services and requests restarts via procmgr's IPC
interface. svcmgr also holds raw process-creation syscall capabilities
as a fallback to restart procmgr itself if procmgr crashes. This is the
only case where a process is created without going through procmgr.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | System design, init/procmgr/svcmgr roles |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Boot order, ProcessInfo handover, process-death flow |
| [docs/userspace-memory-model.md](../../docs/userspace-memory-model.md) | Memory ownership, frame contract, page-reservation contract |
| [docs/capability-model.md](../../docs/capability-model.md) | CSpace, AddressSpace, Thread caps |
| [services/memmgr/README.md](../memmgr/README.md) | Sister tier-1 service for the frame pool |
| [abi/boot-protocol/](../../abi/boot-protocol/) | Boot module format (`BootModule` type) |
| [abi/process-abi](../../abi/process-abi/README.md) | Process startup ABI: ProcessInfo, StartupInfo, main() |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

[Architecture Overview](../../docs/architecture.md), [Process Lifecycle](../../docs/process-lifecycle.md)
