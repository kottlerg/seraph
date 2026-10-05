# shared/syscall

Userspace Rust wrapper functions for the Seraph syscall interface.

Thin `no_std` wrappers that issue the architecture-specific instruction
(`SYSCALL` on x86-64, `ECALL` on RISC-V) and return the kernel result, per the
[syscall specification](../../core/kernel/docs/syscalls.md). All
syscall numbers, error codes, and constants come from [`abi/syscall/`](../../abi/syscall/README.md).
This crate adds only the inline-assembly invocation layer.

No stability obligation. Not used by the kernel.

---

## Summarized By

[Syscall Interface Specification](../../core/kernel/docs/syscalls.md),
[Build System](../../docs/build-system.md)
