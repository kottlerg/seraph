# shared/mmio

Architecture-specific MMIO ordering barriers for device drivers. Callers use
`dma_to_mmio_barrier` (prior DMA-memory writes before a following MMIO write, e.g. a doorbell),
`mmio_to_mmio_barrier` (MMIO writes the device must observe in program order), and
`mmio_to_dma_barrier` (an MMIO status read before a following read of the memory it gates). The
per-architecture implementation is selected at compile time behind the `arch` module, so callers
carry no `#[cfg(target_arch)]`. On x86-64 the barriers are empty; on RISC-V they emit `fence`
instructions.

`no_std`, no dependencies.

---

## Source Layout

```
shared/mmio/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs                  # Public barrier functions and ordering contract
    └── arch/
        ├── mod.rs              # Per-architecture selection
        ├── x86_64/mod.rs       # No-op barriers (x86-64 ordering suffices)
        └── riscv64/mod.rs      # fence-based barriers
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/device-management.md](../../docs/device-management.md) | Driver model and DMA safety |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Arch-dispatch rule this crate follows |

---

## Summarized By

None
