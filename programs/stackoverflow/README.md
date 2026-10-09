# stackoverflow

Test fixture for the main-thread stack guard page. [`svctest`](../../services/svctest/README.md)'s
`stack_overflow` phase (`services/svctest/src/phases/process_faults.rs`) spawns it as
`/programs/stackoverflow` and waits for it to die. It is a pure `std` binary with no Seraph cap
awareness, prints nothing, and has no tester of its own; `cargo xtask build` installs it under
`/programs/` with the other fixtures the harnesses spawn, per
[docs/testing.md § Sysroot layout](../../docs/testing.md#sysroot-layout).

`overflow` (called from `main`) recurses without bound, and each of its frames holds a
page-sized local buffer, so the stack pointer descends at least one page per call. Once the
mapped stack is exhausted, the next write lands in the unmapped guard page below the stack
base, per
[docs/userspace-memory-model.md § Bootstrap Cross-Boundary VAs](../../docs/userspace-memory-model.md#bootstrap-cross-boundary-vas).
procmgr binds memmgr as the fixture's pager, per
[docs/fault-handling.md § Default System Pager](../../docs/fault-handling.md#default-system-pager),
so the fault is delivered to memmgr. The guard page lies outside every registered region, so
memmgr replies `FAULT_REPLY_KILL`, per
[memmgr IPC Interface § Kernel-origin fault message](../../services/memmgr/docs/ipc-interface.md#kernel-origin-fault-message-fault_label),
and the kernel kills the thread as an unhandled fault with a fault exit reason
(`EXIT_FAULT_BASE + <fault code>`), per
[docs/fault-handling.md § Delivery, Resume, and Kill](../../docs/fault-handling.md#delivery-resume-and-kill),
[docs/fault-handling.md § Reply](../../docs/fault-handling.md#reply), and
[docs/process-lifecycle.md § Exit reason](../../docs/process-lifecycle.md#exit-reason).

---

## Source Layout

```
stackoverflow/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Unbounded recursion with a page-sized frame
```

---

## What the Harness Checks

The `stack_overflow` phase passes when all of the following hold:

- The child does not exit cleanly.
- Its exit code lies in `EXIT_FAULT_BASE..EXIT_KILLED`, the fault range.
- procmgr's `QUERY_PROCESS` on the child reports `EXITED`, with the same exit reason the
  spawner saw.

`svctest`'s namespace phase also expects the name `stackoverflow` in the `NS_READDIR`
listing of `/programs`.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Harness model and where test fixtures install |
| [docs/userspace-memory-model.md](../../docs/userspace-memory-model.md) | Main-thread stack placement and the guard page below it |
| [docs/fault-handling.md](../../docs/fault-handling.md) | Pager fault delivery, `FAULT_REPLY_KILL`, and the fault exit reason |
| [services/memmgr/docs/ipc-interface.md](../../services/memmgr/docs/ipc-interface.md) | memmgr's fault reply: `FAULT_REPLY_KILL` for an address outside every registered region |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Exit-reason ranges and process death |

---

## Summarized By

None
