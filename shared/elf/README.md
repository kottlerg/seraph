# shared/elf

ELF64 parser shared by the bootloader, kernel, and userspace loaders.

`no_std`; its one dependency is `abi/process-abi` (the stack-note format). Provides header
validation (`ET_EXEC` and `ET_DYN` via `validate_executable`/`ElfKind`; `validate` additionally
restricts to `ET_EXEC` and has no in-tree caller), `PT_LOAD` segment enumeration, `PT_TLS` and
stack-note extraction, load-span computation, the `PT_GNU_RELRO` span (`relro_span`), and
`.rela.dyn` relocation support for position-independent executables: `rela_table` /
`rela_table_metadata` locate the table through `PT_DYNAMIC`, and `relative_relocs` decodes its
`RELATIVE` records for a loader to apply at a chosen load bias. Non-`RELATIVE` relocation formats
are rejected, never skipped. Does not allocate or perform I/O; the `*_metadata` variants need only
the ELF header page plus the declared file size, and `rela_table_metadata` and
`parse_stack_note_streaming` fetch further bytes through a caller-supplied reader. Headers are
decoded byte-wise, the file header returned by value, and every header read is bounds-checked
against the data it is given, so an image needs no alignment and a header paired with data it was
not validated against yields an error (the stack-note parsers, whose result is optional, read it
as no note), not an out-of-bounds read.

Used by the bootloader (validates and loads the kernel and init images, enumerates their
`PT_LOAD` segments, and validates and applies the kernel's `RELATIVE` relocations, per
[core/boot/docs/elf-loading.md](../../core/boot/docs/elf-loading.md)), by `init` (loads
memmgr and procmgr from boot modules) and `procmgr` (loads all other processes), per
[docs/process-lifecycle.md](../../docs/process-lifecycle.md#userspace-boot-order), and by the
kernel (Phase 9 `RELATIVE` relocation of a PIE init via `mm/init_reloc`, per
[core/kernel/docs/initialization.md](../../core/kernel/docs/initialization.md#phase-9-init-creation-and-scheduler-entry)).
No stability obligation; internal code reuse only.

---

## Source Layout

```
shared/elf/
├── Cargo.toml                  # Workspace member; no_std library
├── README.md
└── src/
    └── lib.rs                  # ELF64 header validation, segment iteration, stack note,
                                #   TLS and RELRO spans, RELATIVE relocations
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | System design, init/procmgr roles |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Userspace boot order; which loader loads which process |
| [abi/process-abi/README.md](../../abi/process-abi/README.md) | Stack-size note format (`.note.seraph.stack`) the stack-note parsers read |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

[core/boot/README.md](../../core/boot/README.md), [ELF Loading](../../core/boot/docs/elf-loading.md)
