# abi/process-abi

Userspace process startup ABI: the binary contract between a process creator
and the created process, plus the universal `main()` entry point convention for
all Seraph userspace programs.

---

## Overview

Process startup in Seraph has two layers:

1. **Handover struct** — a `#[repr(C)]`, version-gated structure placed at a
   well-known virtual address before the new process runs. The producer is
   procmgr for all normal processes. The struct provides the process with its
   initial capability layout, IPC buffer, and startup context.

2. **`main()` convention** — the universal entry point signature. Every Seraph
   userspace binary defines `main()`; `_start()` reads the handover struct,
   constructs a `StartupInfo`, and calls `main()`. std-built services use an
   idiomatic `fn main()` that reaches the caps via `std::os::seraph::startup_info()`.
   procmgr, init, and ktest run on bespoke runtimes and take `&StartupInfo`
   directly.

Both layers are defined in this crate. Init is a special case: its handover
struct is `InitInfo` (from [`abi/init-protocol`](../init-protocol/README.md)),
populated by the kernel rather than procmgr. Init's `_start()` converts
`InitInfo` into `StartupInfo` before calling `main()`, so all processes —
including init and ktest — share the same `main()` signature.

---

## ProcessInfo

The procmgr-to-process handover struct. Placed by procmgr in a single read-only
page at a virtual address procmgr chooses per-process (via `process-layout`) and
delivers in the entry register (`rdi`/`a0`), analogous to how the kernel places
`InitInfo` for init. The address is not a fixed ABI constant — the process reads
it as the argument to `_start`.

The struct MUST be `#[repr(C)]` with stable layout. The process MUST check
`version == PROCESS_ABI_VERSION` before accessing any other field.

The authoritative field list, with per-field doc comments and exact order, is
[`src/lib.rs`](src/lib.rs) (`struct ProcessInfo`). This README summarises the
field groups rather than mirroring every field, so the two cannot drift. As of
`PROCESS_ABI_VERSION` 21 the groups are:

- **Process identity** — `version`, `self_thread_cap`, `self_aspace_cap`,
  `self_cspace_cap`, `sched_control_cap`.
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
  after the fixed struct, bounded by the page remainder).
- **Namespace** — `system_root_cap`, `current_dir_cap`.
- **Logging** — `log_send_cap` (deprecated; migrating to `service_registry_cap`).
- **Main-thread layout** — `stack_top_vaddr`, `stack_pages`, `main_tls_vaddr`
  (TLS block base, zero when the process has no `PT_TLS`). The creator chooses
  these VAs per-process (via `process-layout`), so they are runtime fields, not
  ABI constants.
- **Demand-paging pager** (v18, #34; default-on v19, #225) — `pager_endpoint_cap`,
  `pager_badge`. The `Endpoint` cap + badge of the process's pager (memmgr).
  Demand paging is the system-wide default, so these are nonzero for ordinary
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
| 0 | Null (permanently invalid, per capability model) |
| `self_thread_cap` | Thread capability (Control) |
| `self_aspace_cap` | AddressSpace capability |
| `self_cspace_cap` | CSpace capability |
| `sched_control_cap` | Baseline `SchedControl` cap, band `[1, 20]` (if nonzero) |
| `creator_endpoint_cap` | Badged send cap back to the creator's bootstrap endpoint (if nonzero) |
| `memmgr_endpoint_cap` | Badged SEND cap on memmgr's service endpoint (if nonzero) |
| `procmgr_endpoint_cap` | Badged SEND cap on procmgr's service endpoint (if nonzero) |
| `service_registry_cap` | SEND cap on svcmgr's service-discovery endpoint (if nonzero) |
| `log_send_cap` | Badged SEND cap on the system log endpoint (deprecated; if nonzero) |
| `pager_endpoint_cap` | `Endpoint` cap on the demand-paging pager (if nonzero) |

---

## StartupInfo

The struct passed to `main()`. This is a Rust-native type (NOT `#[repr(C)]`)
providing ergonomic access to the handover data. It is constructed by `_start()`
from either `ProcessInfo` (normal processes) or `InitInfo` (init/ktest).

The authoritative definition is [`src/lib.rs`](src/lib.rs) (`struct StartupInfo`);
the std overlay carries a `#[stable]`-attributed mirror at
`runtime/ruststd/src/os/seraph.rs`. It exposes the same groups as `ProcessInfo`
(identity, service endpoints, stdio rings + notifications, TLS template,
argv/env as resolved `&[u8]` slices, namespace, main-thread layout including
`main_tls_vaddr`, and the v18 `pager_endpoint_cap` / `pager_badge`), with cap
slots delivered as `u32` values
and `args_blob` / `env_blob` resolved from the handover page into slices.

Values are copied out of the handover page verbatim, so the struct does
not borrow from it (except the argv/env slices, which point into the
read-only handover page that lives for the process's lifetime).

---

## main() Signature

All Seraph userspace binaries MUST define `main` with the following signature:

```rust
fn main(startup: &StartupInfo) -> !
```

`main()` receives a reference to the `StartupInfo` constructed by `_start()`.
It MUST NOT return — processes terminate by calling `sys_thread_exit`. If
`main()` could return, the `_start()` stub calls `sys_thread_exit(0)` as a
safety net.

`_start()` is provided by three distinct runtimes, chosen by build profile:

- **std-built services** — `std::os::seraph::_start` (shipped via the
  `ruststd/` overlay) takes the `ProcessInfo` page address as its argument
  (entry register), reads `ProcessInfo`, registers the IPC buffer,
  bootstraps the heap against the `memmgr_endpoint` delivered in
  `ProcessInfo`, then jumps to `lang_start` → user `fn main`. procmgr
  is itself a std-built service and follows this path.
- **memmgr** — bespoke `core`-only `_start` and panic handler. memmgr
  cannot heap-bootstrap against itself (it owns the frame pool) and
  uses no `alloc` collections. It is the only std-less process spawned
  by init via raw syscalls besides init itself.
- **init / ktest** — bespoke `_start` entries that consume `InitInfo`
  (defined in `abi/init-protocol`) rather than `ProcessInfo`, because the
  kernel — not procmgr — is their producer. The kernel chooses the
  `InitInfo` page address and delivers it in the entry register, as procmgr
  does for `ProcessInfo`.

All variants produce the same `StartupInfo` shape and invoke `main()`,
then call `sys_thread_exit` if `main()` returns (defensive — should not
happen).

---

## Relationship to init-protocol

| | init-protocol | process-abi |
|---|---|---|
| Producer | Kernel (Phase 9) | procmgr |
| Consumer | init, ktest | All other processes |
| Handover struct | `InitInfo` | `ProcessInfo` |
| Page address | Kernel-chosen, delivered in entry register | Creator-chosen, delivered in entry register |
| Contains platform-global state | Yes (all memory caps, all HW caps, firmware tables) | No |
| Contains parent endpoint | No (init has no parent) | Yes |
| `main()` signature | Same (`&StartupInfo`) | Same (`&StartupInfo`) |

Init-protocol is a kernel-internal concern — it carries the full initial CSpace
layout including platform resources that only init needs. Process-abi carries
only what a single service or application requires.

The `CapDescriptor` type SHOULD be shared between the two crates (via a common
dependency or identical definition) to avoid divergence.

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
| [abi/init-protocol](../init-protocol/README.md) | Kernel-to-init handover contract |
| [services/memmgr/README.md](../../services/memmgr/README.md) | Producer of `memmgr_endpoint_cap` (via procmgr-issued REGISTER_PROCESS) |

---

## Summarized By

[process-layout/README.md](../../shared/process-layout/README.md)
