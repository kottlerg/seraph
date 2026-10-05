# shared/elf

ELF64 parser shared by the bootloader, kernel, and userspace loaders.

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
    └── lib.rs                  # ELF64 header validation, segment iteration
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | System design, init/procmgr roles |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Userspace boot order; which loader loads which process |
| [abi/boot-protocol/](../../abi/boot-protocol/) | Boot module format (`BootModule` type) |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

[core/boot/README.md](../../core/boot/README.md), [ELF Loading](../../core/boot/docs/elf-loading.md)
