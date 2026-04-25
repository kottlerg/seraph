# targets

Custom Rust target JSON specifications for cross-compilation. rustc resolves
target triples against this directory via `RUST_TARGET_PATH` (set in
`.cargo/config.toml`).

| File | Architecture | Used by |
|---|---|---|
| `x86_64-seraph-none.json` | x86-64 | Kernel |
| `riscv64gc-seraph-none.json` | RISC-V RV64GC | Kernel |
| `riscv64gc-seraph-uefi.json` | RISC-V RV64GC | Bootloader |

`x86_64-unknown-uefi` is a built-in Rust target and has no JSON here.

See [../docs/build-system.md](../docs/build-system.md) for target properties and rationale.

---

## Summarized By

None
