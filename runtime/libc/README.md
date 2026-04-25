# libc

C standard library and POSIX compatibility layer for Seraph userspace.
Implements the C standard library (stdio, stdlib, string, math, etc.) and
standard POSIX interfaces for components written in C or targeting C-compatible
FFI. Wraps Seraph's native syscall ABI with a POSIX-shaped surface (file
descriptors, `read`/`write`, etc.).

Native Rust components use Seraph syscalls directly via `abi/syscall` and
`shared/syscall`; `ruststd` provides the `std` platform layer without going
through libc. libc is for C code and for maximum source compatibility with
existing POSIX software.

## Status

Not yet implemented.

---

## Summarized By

None
