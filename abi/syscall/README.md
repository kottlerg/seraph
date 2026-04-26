# abi/syscall

Binary syscall ABI contract for Seraph.

Defines `SYS_*` syscall number constants, the `SyscallError` enum, and all
scheduling and message constants that cross the kernel/userspace boundary.

**Constraints:** `no_std`, `#[repr(C)]` for all cross-boundary types, no
dependencies outside `core`. Changes to this crate are ABI breaks and MUST
increment the kernel version major or minor field accordingly.

Both the kernel and all userspace components import this crate. The bootloader
does not.

See [core/kernel/docs/syscalls.md](../../core/kernel/docs/syscalls.md) for the full
specification — per-syscall semantics, argument layouts, error conditions, and
calling convention.

---

## Summarized By

None
