# abi/syscall

Binary syscall ABI contract for Seraph.

Defines `SYS_*` syscall number constants, the `SyscallError` enum, and all
scheduling and message constants that cross the kernel/userspace boundary.

**Constraints:** `no_std`, `#[repr(C)]` for all cross-boundary types, no
dependencies outside `core`. While the kernel is pre-stable the syscall ABI is
fluid and may change freely between releases; `KERNEL_VERSION` here tracks the
project version (see [docs/conventions.md](../../docs/conventions.md)), not
syscall-ABI breaks. Protocols that carry an explicit `*_VERSION` constant are
gated by that constant.

Both the kernel and all userspace components import this crate. The bootloader
does not.

See [core/kernel/docs/syscalls.md](../../core/kernel/docs/syscalls.md) for the full
specification — per-syscall semantics, argument layouts, error conditions, and
calling convention.

---

## Summarized By

None
