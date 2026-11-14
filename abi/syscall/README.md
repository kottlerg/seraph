# abi/syscall

Binary syscall ABI contract for Seraph.

---

## Overview

Defines the `SYS_*` syscall numbers and `SYSCALL_NR_BOUND`, one past the highest of them, the
`SyscallError` enum, and the constants that cross the kernel/userspace boundary: the
capability-handle encoding, the `CAP_INFO_*` selectors and `CAP_TAG_*` discriminants, the `MAP_*`
protection and unmap flags, the floor of the user range (`USER_VA_FLOOR`), the `SYS_THREAD_START`
flags (`THREAD_START_SUSPENDED`), the `SYS_THREAD_POST_UPCALL` flag (`UPCALL_ANY_INSTRUCTION`), the
`IRQ_MODE_*` interrupt-line mode bits, the per-type `RIGHTS_*` masks, the per-object retype costs
(`*_RETYPE_BYTES`, `event_queue_retype_bytes`, `wait_set_retype_bytes`), the `CSpace` funding
constants (`CSPACE_SLOTS_PER_PAGE`, `CSPACE_BODIES_PER_PAGE`, `IOPORT_BINDING_TABLE_PAGES`), the
scheduling, message, event-queue, and wait-set limits, the exit-reason and fault-protocol constants,
the register-file layout, `KERNEL_VERSION`, and `SystemInfoType`, and one helper over them:
`cspace_topup_pages`, the donation that leaves a `CSpace` a given slot headroom and a page of growth
budget beyond it for its body arena.

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
