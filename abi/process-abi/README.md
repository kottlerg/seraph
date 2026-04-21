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

The procmgr-to-process handover struct. Placed by procmgr at
`PROCESS_INFO_VADDR` (a fixed virtual address in every new process's address
space) in a single read-only page, analogous to how the kernel places `InitInfo`
for init at `INIT_INFO_VADDR`.

The struct MUST be `#[repr(C)]` with stable layout. The process MUST check
`version == PROCESS_ABI_VERSION` before accessing any other field.

```rust
#[repr(C)]
pub struct ProcessInfo {
    /// Protocol version. Must equal `PROCESS_ABI_VERSION`.
    pub version: u32,

    // ── Process identity ────────────────────────────────────────────

    /// CSpace slot of the process's own Thread capability (Control right).
    pub self_thread_cap: u32,

    /// CSpace slot of the process's own AddressSpace capability.
    pub self_aspace_cap: u32,

    /// CSpace slot of the process's own CSpace capability.
    pub self_cspace_cap: u32,

    // ── IPC ─────────────────────────────────────────────────────────

    /// Virtual address of the pre-mapped IPC buffer page.
    ///
    /// Every thread requires a registered IPC buffer for extended message
    /// payloads. procmgr maps this page and registers it with the kernel
    /// before the process starts.
    pub ipc_buffer_vaddr: u64,

    /// CSpace slot of a tokened send cap to the creator's bootstrap
    /// endpoint.
    ///
    /// For processes created by procmgr directly, this points at procmgr's
    /// bootstrap endpoint or, for services created on behalf of another
    /// service (devmgr spawning a driver, vfsd spawning a filesystem
    /// driver), at that service's bootstrap endpoint. The child issues
    /// `ipc::bootstrap::REQUEST` rounds on this cap to collect its
    /// service-specific capability set. Zero when no creator endpoint is
    /// supplied (e.g. processes that receive all of their caps through
    /// `ProcessInfo` alone).
    pub creator_endpoint_cap: u32,

    // ── Universal service endpoints ─────────────────────────────────

    /// CSpace slot of a tokened SEND cap on procmgr's service endpoint.
    ///
    /// Populated for every procmgr-spawned child so `std::os::seraph::
    /// _start` can bootstrap the `System` allocator via `REQUEST_FRAMES`
    /// before the user's `fn main()` runs. Zero for processes with no
    /// procmgr above them (procmgr itself, or init/ktest which receive
    /// `InitInfo` instead).
    pub procmgr_endpoint_cap: u32,

    /// CSpace slot of a SEND cap on the system log endpoint.
    ///
    /// Bound to `Stdout`/`Stderr` by `std::os::seraph::_start`, so
    /// `println!`/`eprintln!` work without per-service bootstrap-round
    /// wiring. Zero when no log sink is available — consumers MUST
    /// tolerate zero (stdio writes are silently dropped, matching
    /// `unsupported` semantics).
    pub log_endpoint_cap: u32,
}
```

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
| `creator_endpoint_cap` | Tokened send cap back to the creator's bootstrap endpoint (if nonzero) |
| `procmgr_endpoint_cap` | Tokened SEND cap on procmgr's service endpoint (if nonzero) |
| `log_endpoint_cap` | SEND cap on the system log endpoint (if nonzero) |

---

## StartupInfo

The struct passed to `main()`. This is a Rust-native type (NOT `#[repr(C)]`)
providing ergonomic access to the handover data. It is constructed by `_start()`
from either `ProcessInfo` (normal processes) or `InitInfo` (init/ktest).

```rust
pub struct StartupInfo {
    /// Virtual address of the IPC buffer page.
    pub ipc_buffer: *mut u8,

    /// CSpace slot of the creator endpoint. Zero if none.
    pub creator_endpoint: u32,

    /// CSpace slot of own Thread capability.
    pub self_thread: u32,

    /// CSpace slot of own AddressSpace capability.
    pub self_aspace: u32,

    /// CSpace slot of own CSpace capability.
    pub self_cspace: u32,

    /// CSpace slot of a tokened SEND cap on procmgr's service endpoint.
    /// Zero when unreachable.
    pub procmgr_endpoint: u32,

    /// CSpace slot of a SEND cap on the system log endpoint. Zero when
    /// no log sink has been attached yet.
    pub log_endpoint: u32,
}
```

Values are copied out of the handover page verbatim, so the struct does
not borrow from it.

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
  `ruststd/` overlay) reads `ProcessInfo`, registers the IPC buffer,
  bootstraps the heap against the `procmgr_endpoint` delivered in
  `ProcessInfo`, then jumps to `lang_start` → user `fn main`.
- **procmgr** — `procmgr/src/rt.rs` ships a minimal `core`-only `_start`
  and panic handler. procmgr cannot heap-bootstrap against itself and
  uses no `alloc` collections.
- **init / ktest** — bespoke `_start` entries that consume `InitInfo`
  from `INIT_INFO_VADDR` (defined in `abi/init-protocol`) rather than
  `ProcessInfo`, because the kernel — not procmgr — is their producer.

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
| Placed at | `INIT_INFO_VADDR` | `PROCESS_INFO_VADDR` |
| Contains platform-global state | Yes (all memory frames, all HW caps, firmware tables) | No |
| Contains parent endpoint | No (init has no parent) | Yes |
| `main()` signature | Same (`&StartupInfo`) | Same (`&StartupInfo`) |

Init-protocol is a kernel-internal concern — it carries the full initial CSpace
layout including platform resources that only init needs. Process-abi carries
only what a single service or application requires.

The `CapDescriptor` type SHOULD be shared between the two crates (via a common
dependency or identical definition) to avoid divergence.

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
| [docs/architecture.md](../../docs/architecture.md) | Bootstrap sequence, procmgr role |
| [abi/init-protocol](../init-protocol/README.md) | Kernel-to-init handover contract |

---

## Summarized By

None
