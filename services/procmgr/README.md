# procmgr

Userspace process lifecycle manager. The first service started by init during
bootstrap. All subsequent process creation, ELF loading, and teardown in the
running system goes through procmgr.

procmgr holds the authority to create address spaces, CSpaces, and threads
(delegated by init). It exposes an IPC interface for process creation and
teardown. init starts procmgr directly using its minimal built-in ELF parser;
all other services are started by requesting procmgr via IPC.

---

## Source Layout

```
procmgr/
├── Cargo.toml                  # Workspace member; no_std binary
├── README.md
├── src/
│   └── main.rs                 # _start() entry point, process manager stub
└── docs/
    └── ipc-interface.md        # procmgr IPC interface specification
```

---

## Responsibilities

- **ELF loading** — parse ELF images from boot modules or filesystem, allocate
  address spaces and frames, map segments with correct permissions
- **Process creation** — create AddressSpace, CSpace, and Thread kernel objects;
  configure the thread's address space, CSpace, and IPC buffer bindings
- **Capability delegation** — receive caps from callers (e.g. svcmgr, devmgr),
  mint and pass per-process initial caps to newly created processes
- **Process teardown** — on exit or crash, revoke the process's address space
  capability (which stops all threads bound to it) and reclaim resources
- **Process registry** — maintain a table of running processes; answer queries
  from svcmgr and other services

---

## IPC Interface

The full procmgr IPC specification is in
[`docs/ipc-interface.md`](docs/ipc-interface.md). Key operations:

- `create_process(elf_module_cap, initial_caps[]) → (process_handle, thread_handle)`
- `exit_process(process_handle)`
- `query_process(process_handle) → ProcessInfo`

---

## Process Startup ABI

When procmgr creates a new process, it populates a `ProcessInfo` handover
struct at a well-known virtual address in the new process's address space.
This struct tells the process where to find its initial capabilities, IPC
buffer, and startup context. The handover contract is defined in
[`abi/process-abi`](../abi/process-abi/README.md).

procmgr is the sole producer of `ProcessInfo` for all non-init processes.
Init and ktest use a different handover path (kernel-produced `InitInfo` from
[`abi/init-protocol`](../abi/init-protocol/README.md)) but share the same
`main()` signature defined in `abi/process-abi`.

---

## Relationship to svcmgr

svcmgr monitors services and requests restarts via procmgr's IPC interface.
svcmgr also holds raw process-creation syscall capabilities as a fallback to
restart procmgr itself if procmgr crashes. This is the only case where a
process is created without going through procmgr.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../docs/architecture.md) | System design, init/procmgr/svcmgr roles |
| [docs/capability-model.md](../docs/capability-model.md) | CSpace, AddressSpace, Thread caps |
| [procmgr/docs/frame-management.md](docs/frame-management.md) | Frame pool design, allocation, per-process accounting |
| [abi/boot-protocol/](../abi/boot-protocol/) | Boot module format (`BootModule` type) |
| [abi/process-abi](../abi/process-abi/README.md) | Process startup ABI: ProcessInfo, StartupInfo, main() |
| [docs/coding-standards.md](../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

None
