# runtime

Language runtime layers linked into userspace binaries. Seraph-specific; not standalone processes.

| Component | Purpose |
|---|---|
| `libc/` | C standard library / POSIX compatibility layer |
| `ruststd/` | Rust standard library platform layer (`std::sys::seraph`) |

Neither has a top-level `Cargo.toml`. `xtask` materialises the `ruststd/` overlay into a patched toolchain mirror at build time.

---

## Summarized By

None
