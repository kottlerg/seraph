# libc

C standard library over Seraph's native interfaces for Seraph userspace (design intent; not yet
implemented). The design provides the C standard library (stdio, stdlib, string, math, etc.)
for components written in C or targeting C-compatible FFI. libc is a language runtime, not a
compatibility shim: it does not provide a POSIX compatibility layer, and POSIX API compatibility
is not a goal ([docs/architecture.md](../../docs/architecture.md) § Project Goals).

Native Rust code does not go through libc. For its syscall interface, see
[`abi/syscall`](../../abi/syscall/README.md) and
[`shared/syscall`](../../shared/syscall/README.md);
[`ruststd`](../ruststd/README.md) provides the `std` platform layer.

## Status

Not yet implemented.

---

## Summarized By

None
