# shared/syscall

Userspace Rust wrapper functions for the Seraph syscall interface.

Thin `no_std` wrappers that issue the architecture-specific instruction
(`SYSCALL` on x86-64, `ECALL` on RISC-V) and return the kernel result, per the
[syscall specification](../../core/kernel/docs/syscalls.md). All
syscall numbers, error codes, and constants come from [`abi/syscall/`](../../abi/syscall/README.md).
Beyond the inline-assembly invocation layer, a few wrappers do work in userspace. One rejects,
without issuing the syscall, an argument the kernel would misread: `cap_insert` returns
`InvalidArgument` for a destination index of 0, which the kernel reads as "allocate a slot".
Others compose calls: `cap_revoke_all` retries `cap_revoke` while it reports `Interrupted`,
and `random_u64` draws through `getrandom` and returns `InvalidState` on a short count. Two
untyped entries, `raw_syscall3` and `raw_syscall4`, pass three or four argument registers as
given, for harness tests of the kernel's argument validation that need register values the
typed wrappers cannot express;
`getrandom_raw`, `thread_read_regs_raw`, `thread_write_regs_raw`, `thread_read_mem_raw`, and
`thread_write_mem_raw` likewise take a raw buffer pointer for the kernel's buffer-validation tests.

A wrapper is safe when nothing it can make the kernel do reaches memory a live Rust object
occupies: buffers the kernel writes or reads are slices (`getrandom`, `thread_read_regs`,
`thread_read_mem`). The
`cap_create_*` retype wrappers are safe on that rule because the kernel never carves a page some
address space maps, so a retype cannot overwrite bytes the caller reaches through a mapping; one
that would fails with `OutOfMemory`, as § Capability Syscalls of
[core/kernel/docs/syscalls.md](../../core/kernel/docs/syscalls.md#capability-syscalls)
states. The wrappers whose effect the types cannot bound are `unsafe fn`, each with a
`# Safety` contract:
`ipc_buffer_set` (the registered page is dedicated to the kernel's IPC access), `mem_map`,
`mem_unmap`, `mem_unmap_reclaim`, `mem_protect` and `mmio_map` (on the caller's own address
space, no live object or registered IPC page in the span; for `mmio_map`, also no Rust reference
into the mapping, which any ancestor holder can withdraw, so `cap_delete`, `cap_revoke` and
`mmio_split` stay safe), and `thread_configure`,
`thread_configure_with_tls` and `thread_write_regs` (a thread of the caller's address space
starts or resumes only on code, a stack, and a TLS block dedicated to it), and `thread_write_mem`
(when the thread runs in the caller's address space, the range holds no object the written bytes
invalidate, and no reference into it is live).

No stability obligation. Not used by the kernel.

---

## Source Layout

```
shared/syscall/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs                  # Public syscall wrappers
    └── arch/
        ├── mod.rs              # Per-architecture selection; the raw-wrapper safety contract
        ├── x86_64/mod.rs       # SYSCALL raw wrappers
        └── riscv64/mod.rs      # ECALL raw wrappers
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [core/kernel/docs/syscalls.md](../../core/kernel/docs/syscalls.md) | Syscall ABI the wrappers issue |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Arch-dispatch rule this crate follows |

---

## Summarized By

[Syscall Interface Specification](../../core/kernel/docs/syscalls.md),
[Build System](../../docs/build-system.md),
[Capability Model](../../docs/capability-model.md),
[runtime/ruststd/README.md](../../runtime/ruststd/README.md)
