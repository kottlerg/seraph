# runtime

Language runtime layers linked into userspace binaries. Seraph-specific; not standalone processes.

| Component | Purpose |
|---|---|
| `libc/` | C standard library / POSIX compatibility layer |
| `ruststd/` | Rust standard library platform layer (`std::sys::seraph`) |

Neither has a top-level `Cargo.toml`. See
[`docs/build-system.md`](../docs/build-system.md) for how `xtask`
materialises the `ruststd/` overlay at build time.

---

## Summarized By

None
