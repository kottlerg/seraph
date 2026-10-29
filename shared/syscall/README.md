# shared/syscall

Userspace Rust wrapper functions for the Seraph syscall interface.

Thin `no_std` wrappers that issue the architecture-specific instruction
(`SYSCALL` on x86-64, `ECALL` on RISC-V) and return the kernel result, per the
[syscall specification](../../core/kernel/docs/syscalls.md). All
syscall numbers, error codes, and constants come from [`abi/syscall/`](../../abi/syscall/README.md).
This crate adds only the inline-assembly invocation layer. One untyped entry,
`raw_syscall3`, passes three argument registers as given, for harness tests of the kernel's
argument validation that need register values the typed wrappers cannot express.

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
[Build System](../../docs/build-system.md)
