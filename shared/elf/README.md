# shared/elf

ELF64 parser for Seraph userspace components.

`no_std`, no external dependencies. Provides header validation (`ET_EXEC` and
`ET_DYN` via `validate_executable`/`ElfKind`; `ET_EXEC`-only `validate` for
the kernel-image path), `PT_LOAD` segment enumeration, `PT_TLS` and
stack-note extraction, load-span computation, and `.rela.dyn` relocation
support for position-independent executables: `rela_table` /
`rela_table_metadata` locate the table through `PT_DYNAMIC`, and
`relative_relocs` decodes its `RELATIVE` records for a loader to apply at a
chosen load bias. Non-`RELATIVE` relocation formats are rejected, never
skipped. Does not allocate or perform I/O; `*_metadata` variants stream via
a caller-supplied reader holding only the ELF header page.

Used by `init` (loads memmgr and procmgr from boot modules), `procmgr`
(loads all other processes), and the kernel (Phase 9 `RELATIVE` relocation
of a PIE init via `mm/init_reloc`). No stability obligation; internal code
reuse only.

---

## Source Layout

```
shared/elf/
├── Cargo.toml                  # Workspace member; no_std library
├── README.md
└── src/
    └── lib.rs                  # ELF64 header validation, segment iteration
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | System design, init/procmgr roles |
| [abi/boot-protocol/](../../abi/boot-protocol/) | Boot module format (`BootModule` type) |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

None
