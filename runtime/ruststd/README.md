# ruststd

Rust standard library platform layer for Seraph (`std::sys::seraph`).

This is the OS-specific backend that allows Rust's `std` to work on Seraph.
It implements the platform interface that `std` requires: threads, I/O, file
system access, process management, time, etc., using Seraph's native IPC and
syscall interfaces.

## Implementation order

ruststd will be implemented before `libc/`. Native Rust `std` support does not
require a POSIX layer; it maps directly onto Seraph primitives.

## Status

Not yet implemented.

---

## Summarized By

None
