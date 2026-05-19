# runtime

Language runtime layers linked into userspace binaries. Seraph-specific; not standalone processes.

## Source Layout

| Component | Purpose |
|---|---|
| `libc/` | C standard library / POSIX compatibility layer |
| `ruststd/` | Rust standard library platform layer (`std::sys::seraph`) |

Neither has a top-level `Cargo.toml`. See
[`docs/build-system.md`](../docs/build-system.md) for how `xtask`
materialises the `ruststd/` overlay at build time.

## Relevant Design Documents

| Document | Relevance |
|---|---|
| [`docs/architecture.md`](../docs/architecture.md) | Userspace-services / runtime layering. |
| [`docs/build-system.md`](../docs/build-system.md) | Toolchain, sysroot, and `ruststd/` materialisation. |
| [`runtime/libc/README.md`](libc/README.md) | libc surface, POSIX compatibility scope, build layout. |
| [`runtime/ruststd/README.md`](ruststd/README.md) | Rust std platform layer, `std::sys::seraph` integration. |

---

## Summarized By

None
