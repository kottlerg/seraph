# shared/syscall

Userspace Rust wrapper functions for the Seraph syscall interface.

Thin `no_std` wrappers that issue the architecture-specific instruction
(`SYSCALL` on x86-64, `ECALL` on RISC-V) and return the kernel result. All
syscall numbers, error codes, and constants come from [`abi/syscall/`](../../abi/syscall/).
This crate adds only the inline-assembly invocation layer.

No stability obligation. Not used by the kernel.

See [core/kernel/docs/syscalls.md](../../core/kernel/docs/syscalls.md) for the full
syscall specification.

---

## Summarized By

None
