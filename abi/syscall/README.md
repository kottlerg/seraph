# abi/syscall

Binary syscall ABI contract for Seraph.

---

## Overview

Defines the `SYS_*` syscall numbers, the `SyscallError` enum, and the constants that cross the
kernel/userspace boundary: the capability-handle encoding, the `CAP_INFO_*` selectors and
`CAP_TAG_*` discriminants, the `MAP_*` protection and unmap flags, the per-type `RIGHTS_*`
masks, the per-object retype costs (`*_RETYPE_BYTES`, `event_queue_retype_bytes`), the
scheduling and message limits, the exit-reason and fault-protocol constants, the register-file
layout, `KERNEL_VERSION`, and `SystemInfoType`.

**Constraints:** `no_std`; each cross-boundary type carries an explicit stable repr
(`#[repr(C)]` structs, fixed-width integer-repr enums); no dependencies outside `core` (the
optional `rustc-std-workspace-core` facade stands in for `core` when std builds the crate).
While the kernel is pre-stable the syscall ABI is fluid and may change freely between releases;
`KERNEL_VERSION` here tracks the project version (see
[docs/conventions.md](../../docs/conventions.md)), not syscall-ABI breaks. Where a protocol has a
handshake or handover point, its `*_VERSION` constant is checked there (see
[docs/conventions.md § ABI / wire-protocol versions](../../docs/conventions.md#abi--wire-protocol-versions)).

Both the kernel and all userspace components import this crate. The bootloader does not.

See [core/kernel/docs/syscalls.md](../../core/kernel/docs/syscalls.md) for the full
specification — per-syscall semantics, argument layouts, error conditions, and calling
convention.

---

## Source Layout

```
syscall/
├── Cargo.toml      # no_std library; rustc-dep-of-std feature for std's build
├── README.md
└── src/
    └── lib.rs      # syscall numbers, SyscallError, and every ABI constant
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [core/kernel/docs/syscalls.md](../../core/kernel/docs/syscalls.md) | Per-syscall specification and calling convention |
| [docs/capability-model.md](../../docs/capability-model.md) | Capability types, rights scoping, handles |
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC message format and limits |
| [docs/fault-handling.md](../../docs/fault-handling.md) | Fault-protocol constants |
| [docs/conventions.md](../../docs/conventions.md) | Versioning of the project and of wire protocols |

---

## Summarized By

[Syscall Interface Specification](../../core/kernel/docs/syscalls.md),
[Build System](../../docs/build-system.md),
[shared/syscall/README.md](../../shared/syscall/README.md)
