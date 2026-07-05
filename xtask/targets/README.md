# targets

Custom Rust target JSON specifications for cross-compilation. rustc resolves
target triples against this directory via `RUST_TARGET_PATH` (set in
`.cargo/config.toml`).

| File | Floor | Used by |
|---|---|---|
| `x86_64-seraph-none.json` | x86-64 baseline, soft-float | Kernel (`os: none`, static) |
| `x86_64-seraph-lowuser.json` | x86-64 baseline, soft-float | Low-level userspace (`os: none`, PIE) |
| `x86_64-seraph.json` | x86-64-v3 psABI (SSE/AVX/AVX2/FMA/BMI/F16C/XSAVE) | Std-enabled userspace (`os: seraph`, PIE) |
| `riscv64imac-seraph-none.json` | RV64IMAC, soft-float, lp64 | Kernel (`os: none`, static) |
| `riscv64imac-seraph-lowuser.json` | RV64IMAC, soft-float, lp64 | Low-level userspace (`os: none`, PIE) |
| `riscv64a23-seraph.json` | RVA23U64 subset (RV64GCV + Zba/Zbb/Zbs), lp64d | Std-enabled userspace (`os: seraph`, PIE) |
| `riscv64imac-seraph-uefi.json` | RV64IMAC, soft-float, lp64 | Bootloader |

Userspace targets emit position-independent executables (`ET_DYN`,
`RELATIVE`-only relocations, `tls-model: local-exec` where TLS exists,
`PT_GNU_RELRO` sealed read-only by the loaders after relocation) so
loaders can randomize each image's base (ASLR, #39); the kernel targets stay
`relocation-model: static` (KASLR is #252). `x86_64-unknown-uefi` is a
built-in Rust target and has no JSON here.

See [../../docs/build-system.md](../../docs/build-system.md) for target properties and rationale.

---

## Summarized By

[../../docs/build-system.md](../../docs/build-system.md)
