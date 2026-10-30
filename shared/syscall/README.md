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
`getrandom_raw` likewise takes a raw buffer pointer for the kernel's buffer-validation tests.

A wrapper is safe when nothing it can make the kernel do reaches memory a live Rust object
occupies: buffers the kernel writes or reads are slices (`getrandom`, `thread_read_regs`). The
wrappers whose effect the types cannot bound are `unsafe fn`, each with a `# Safety` contract:
`ipc_buffer_set` (the registered page is dedicated to the kernel's IPC access), `mem_map`,
`mem_unmap`, `mem_unmap_reclaim`, `mem_protect` and `mmio_map` (on the caller's own address
space, no live object or registered IPC page in the span), and `thread_configure`,
`thread_configure_with_tls` and `thread_write_regs` (a thread of the caller's address space
starts or resumes only on code, a stack, and a TLS block dedicated to it).

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
[runtime/ruststd/README.md](../../runtime/ruststd/README.md)
