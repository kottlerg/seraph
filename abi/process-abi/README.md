# abi/process-abi

Userspace process startup ABI: the binary contract between a process creator
and the created process, plus the `main()` entry point convention for the
processes started through it.

---

## Overview

Process startup in Seraph has two layers:

1. **Handover struct** — a `#[repr(C)]`, version-gated structure the creator
   maps read-only before the new process runs, at a creator-chosen virtual
   address it delivers in the entry register. procmgr produces it for every
   process except memmgr and procmgr, whose `ProcessInfo` init populates. The
   struct provides the process with its initial capability layout, IPC
   buffer, and startup context.

2. **`main()` convention** — the entry point convention for a process started
   from a `ProcessInfo` page: `_start()` reads the handover struct, builds a
   Rust-native view of it, and enters `main()`. std-built services use an
   idiomatic `fn main()` that reads std's own `std::os::seraph::StartupInfo`
   through `std::os::seraph::startup_info()`. memmgr runs on a bespoke runtime
   whose `_start` constructs this crate's `StartupInfo` and passes
   `&StartupInfo` to its `main`. init and ktest consume `InitInfo` in their own
   `_start` and define no `main()` of either shape (see
   [`main()` Signature](#main-signature)).

This crate defines `ProcessInfo` and the memmgr runtime's `main(&StartupInfo) -> !` convention;
the std-built convention and its `StartupInfo` type are defined by
[`runtime/ruststd`](../../runtime/ruststd/README.md) (`std::os::seraph`). init and ktest sit
outside both conventions: their handover struct is `InitInfo` (from
[`abi/init-protocol`](../init-protocol/README.md)), populated by the kernel rather than
procmgr, and each consumes it in its own `_start` without constructing a `StartupInfo` or
calling a `main()`.

---

## ProcessInfo

The creator-to-process handover struct. The creator (procmgr, or init for memmgr and procmgr) places
it in a single read-only page at a virtual address it chooses per process (via `process-layout`) and
delivers it in the entry register (`rdi`/`a0`), analogous to how the kernel places `InitInfo` for
init. The address is not a fixed ABI constant — the process reads it as the argument to `_start`.

The struct MUST be `#[repr(C)]` with stable layout. The process MUST check
`version == PROCESS_ABI_VERSION` before accessing any other field.

The authoritative field list, with per-field doc comments and exact order, is
[`src/lib.rs`](src/lib.rs) (`struct ProcessInfo`). This README summarises the
field groups rather than mirroring every field, so the two cannot drift. As of
`PROCESS_ABI_VERSION` 22 the groups are:

- **Process identity** — `version`, `self_thread_cap`, `self_aspace_cap`,
  `self_cspace_cap`, `sched_control_cap`, `initial_priority` (the level the
  creator placed the initial thread at; the runtime spawns further threads
  at the same level).
- **IPC / bootstrap** — `ipc_buffer_vaddr` (creator-chosen per-process),
  `creator_endpoint_cap`.
- **Universal service endpoints** — `procmgr_endpoint_cap`, `memmgr_endpoint_cap`,
  `service_registry_cap` (the single system-wide service-discovery handle).
- **Stdio rings** — `stdin_memory_cap`, `stdout_memory_cap`, `stderr_memory_cap`
  and their six `*_data_notification_cap` / `*_space_notification_cap` wakeup slots.
- **TLS template** — `tls_template_vaddr`, `tls_template_filesz`,
  `tls_template_memsz`, `tls_template_align`.
- **argv / env blobs** — `args_offset`, `args_bytes`, `args_count`,
  `env_offset`, `env_bytes`, `env_count` (blobs are written into the same page
  after the fixed struct; their bounds are the create-request wire contract in
  [procmgr's IPC interface](../../services/procmgr/docs/ipc-interface.md#label-1-create_process)
  § CREATE_PROCESS).
- **Namespace** — `system_root_cap`, `current_dir_cap`.
- **Logging** — `log_send_cap` (deprecated; migrating to `service_registry_cap`).
- **Main-thread layout** — `stack_top_vaddr`, `stack_pages`, `main_tls_vaddr`
  (TLS block base, zero when the process has no `PT_TLS`). The creator chooses
  these VAs per-process (via `process-layout`), so they are runtime fields, not
  ABI constants.
- **Demand-paging pager** (v18, #34; default-on v19, #225) — `pager_endpoint_cap`,
  `pager_badge`. The `Endpoint` cap + badge of the process's pager (memmgr).
  Demand paging is the system-wide default (see
  [docs/fault-handling.md](../../docs/fault-handling.md)), so these are nonzero for ordinary
  processes and zero only for pinned ones (`procmgr_labels::CREATE_PINNED`, e.g.
  DMA drivers) and the pre-pager bootstrap. procmgr binds the main thread's fault
  handler to this endpoint at creation, and the runtime inherits it onto every
  thread it spawns. Consumers must tolerate zero.

Every cap field names a `CSpace` slot (`0` = absent); `*_vaddr` / size / count
fields are plain values.

### Fixed CSpace slot conventions

The fields listed above are the only well-known slots. Service-specific
capabilities (device handles, BAR/IRQ caps, block-device endpoints, registry
caps, …) are delivered by the creator to the child over the `ipc::bootstrap`
protocol on `creator_endpoint_cap`, not through `ProcessInfo`.

| Slot | Content |
|---|---|
| 0 | Null (permanently invalid, per [capability model](../../docs/capability-model.md)) |
| `self_thread_cap` | Thread capability (Control) |
| `self_aspace_cap` | AddressSpace capability |
| `self_cspace_cap` | CSpace capability |
| `sched_control_cap` | Baseline `SchedControl` cap, band `[1, band_max]` chosen by the creator (default a copy of the creator's band; if nonzero) |
| `creator_endpoint_cap` | Badged send cap back to the creator's bootstrap endpoint (if nonzero) |
| `memmgr_endpoint_cap` | Badged SEND cap on memmgr's service endpoint (if nonzero) |
| `procmgr_endpoint_cap` | Badged SEND cap on procmgr's service endpoint (if nonzero) |
| `service_registry_cap` | SEND cap on svcmgr's service-discovery endpoint (if nonzero) |
| `log_send_cap` | Badged SEND cap on the system log endpoint (deprecated; if nonzero) |
| `pager_endpoint_cap` | `Endpoint` cap on the demand-paging pager (if nonzero) |

---

## StartupInfo

The Rust-native view of the handover data. It is NOT `#[repr(C)]`. Only
memmgr's bespoke `_start` constructs `process_abi::StartupInfo`, from
`ProcessInfo`, and passes `&StartupInfo` to memmgr's `main`. std's `_start`
(`std::os::seraph::_start`, in `runtime/ruststd/src/os/seraph.rs`) builds its
own same-purpose type, `std::os::seraph::StartupInfo`: a `#[stable]`-attributed
superset that adds `sched_control_cap`, `initial_priority`, and `log_send_cap`,
which std-built binaries read through `std::os::seraph::startup_info()`. init
and ktest construct neither.

The authoritative definition is [`src/lib.rs`](src/lib.rs) (`struct StartupInfo`).
It carries the self caps (`self_thread`, `self_aspace`, `self_cspace`), the IPC
buffer, the creator, procmgr, memmgr, and service-registry endpoints, the stdio
rings and their notifications, the namespace caps, the TLS template, argv/env,
the main-thread layout including `main_tls_vaddr`, and the v18
`pager_endpoint_cap` / `pager_badge`. Cap slots are `u32` values, and
`args_blob` / `env_blob` are `&[u8]` slices; memmgr's `_start`, the only
constructor, leaves both empty, since init writes no argv or env for memmgr.

Values are copied out of the handover page verbatim, so the struct does
not borrow from it.

---

## main() Signature

A binary on the bespoke `StartupInfo` runtime (memmgr) MUST define `main` with
the following signature:

```rust
fn main(startup: &StartupInfo) -> !
```

`main()` receives a reference to the `StartupInfo` constructed by `_start()`.
It MUST NOT return — the process terminates by calling `sys_thread_exit`. A
std-built binary defines an idiomatic `fn main()` instead and reaches the same
data via `std::os::seraph::startup_info()`; init and ktest define neither.

`_start()` is provided by three distinct runtimes, chosen by build profile:

- **std-built services** — `std::os::seraph::_start` (shipped via the
  [`ruststd/`](../../runtime/ruststd/README.md) overlay) takes the `ProcessInfo` page
  address as its argument (entry register), reads `ProcessInfo`, registers the IPC buffer,
  bootstraps the heap against the `memmgr_endpoint` delivered in
  `ProcessInfo`, then jumps to `lang_start` → user `fn main`. procmgr
  is itself a std-built service and follows this path.
- **[memmgr](../../services/memmgr/README.md)** — bespoke `core`-only `_start` and panic
  handler. memmgr cannot heap-bootstrap against itself (it owns the frame pool) and
  uses no `alloc` collections. It is the only std-less process init spawns via raw
  syscalls.
- **init / ktest** — bespoke `_start` entries that consume `InitInfo`
  (defined in [`abi/init-protocol`](../init-protocol/README.md)) rather than `ProcessInfo`,
  because the kernel — not procmgr — is their producer. The kernel chooses the
  `InitInfo` page address and delivers it in the entry register, as procmgr
  does for `ProcessInfo`.

The std variant builds `std::os::seraph::StartupInfo` and the memmgr variant
this crate's `StartupInfo`, each from `ProcessInfo`; the init / ktest variant
builds none and defines no `main()` of either shape.

---

## Relationship to init-protocol

| | init-protocol | process-abi |
|---|---|---|
| Producer | Kernel (Phase 9) | procmgr (init for memmgr and procmgr) |
| Consumer | init, ktest | All other processes |
| Handover struct | `InitInfo` | `ProcessInfo` |
| Page address | Kernel-chosen, delivered in entry register | Creator-chosen, delivered in entry register |
| Contains platform-global state | Yes (all memory caps, all HW caps, firmware tables) | No |
| Contains parent endpoint | No (init has no parent) | Yes |
| `main()` | None (`_start` consumes `InitInfo` directly) | `fn main()` (std) or `fn main(&StartupInfo) -> !` (memmgr) |

[Init-protocol](../init-protocol/README.md) is the kernel-to-init contract: it carries the
full initial CSpace layout, including platform resources only init needs. Process-abi
carries only what a single service or application requires.

---

## Stack-size note (`.note.seraph.stack`)

A binary may declare its main-thread stack size by emitting a custom
ELF note in section `.note.seraph.stack`. The loader (init for
memmgr/procmgr; procmgr for everyone else) reads the note before
mapping the child's stack and substitutes the declared value for
`DEFAULT_PROCESS_STACK_PAGES`. Binaries that omit the note inherit
the default.

```rust
// In any std-built binary:
seraph::stack_pages!(12);   // declare a 48 KiB main-thread stack

// In any no_std binary that depends on `process-abi`:
process_abi::stack_pages!(12);
```

The note expands to a `#[used] #[link_section = ".note.seraph.stack"]`
static of type `StackNote` (defined in this crate). Both macro paths
emit identical bytes; the std re-export simply lets std-using binaries
declare a stack size without an extra Cargo dep on `process-abi`.

`MAX_PROCESS_STACK_PAGES` is a loader-side hard cap (256 pages = 1 MiB)
that catches a corrupt or hostile note. memmgr's existing per-process
quota remains the actual policy gate on the resulting `REQUEST_MEMORY_CAPS`
calls.

The on-disk shape is read by `elf::parse_stack_note` (full-bytes path,
used by init) and `elf::parse_stack_note_streaming` (header-page +
on-demand reads, used by procmgr's VFS-streaming spawn path).

---

## Versioning

`PROCESS_ABI_VERSION` MUST be incremented on any breaking change to the
`ProcessInfo` layout or field semantics. This mirrors the versioning discipline
in `abi/init-protocol`.

`StartupInfo` and the `main()` signature are source-level conventions, not
binary ABI. Changes to them require recompilation but not a version bump —
they are always compiled together with the consuming binary.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/capability-model.md](../../docs/capability-model.md) | Capability types, CSpace, derivation, rights |
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC buffer, message format, endpoints |
| [docs/architecture.md](../../docs/architecture.md) | Bootstrap sequence, memmgr/procmgr roles |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Userspace boot order, ProcessInfo handover, memmgr/procmgr authority split |
| [docs/fault-handling.md](../../docs/fault-handling.md) | Demand-paging default, pager binding, CREATE_PINNED exemption |
| [abi/init-protocol](../init-protocol/README.md) | Kernel-to-init handover contract |
| [services/memmgr/README.md](../../services/memmgr/README.md) | Producer of `memmgr_endpoint_cap` (via procmgr-issued REGISTER_PROCESS) |

---

## Summarized By

[Process Lifecycle](../../docs/process-lifecycle.md),
[Userspace Memory Model](../../docs/userspace-memory-model.md),
[Filesystem Driver Protocol](../../services/fs/docs/fs-driver-protocol.md),
[services/procmgr/README.md](../../services/procmgr/README.md),
[svcmgr IPC Interface](../../services/svcmgr/docs/ipc-interface.md),
[shared/process-layout/README.md](../../shared/process-layout/README.md),
[shared/registry-client/README.md](../../shared/registry-client/README.md)
