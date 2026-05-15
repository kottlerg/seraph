# targets

Custom Rust target JSON specifications for cross-compilation. rustc resolves
target triples against this directory via `RUST_TARGET_PATH` (set in
`.cargo/config.toml`).

| File | Floor | Used by |
|---|---|---|
| `x86_64-seraph-none.json` | x86-64 baseline, soft-float | Kernel and low-level userspace (`os: none`) |
| `x86_64-seraph.json` | x86-64-v3 psABI (SSE/AVX/AVX2/FMA/BMI/F16C/XSAVE) | Std-enabled userspace (`os: seraph`) |
| `riscv64imac-seraph-none.json` | RV64IMAC, soft-float, lp64 | Kernel and low-level userspace (`os: none`) |
| `riscv64a23-seraph.json` | RVA23U64 subset (RV64GCV + Zba/Zbb/Zbs), lp64d | Std-enabled userspace (`os: seraph`) |
| `riscv64imac-seraph-uefi.json` | RV64IMAC, soft-float, lp64 | Bootloader |

`x86_64-unknown-uefi` is a built-in Rust target and has no JSON here.

See [../../docs/build-system.md](../../docs/build-system.md) for target properties and rationale.

---

## Summarized By

[../../docs/build-system.md](../../docs/build-system.md)
