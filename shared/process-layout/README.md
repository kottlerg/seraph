# shared/process-layout

Per-process bootstrap virtual-address layout for Seraph process creators.

`no_std`, no external dependencies, no allocation, no I/O. Owns the choice of
where a new process's four bootstrap surfaces are placed — the `ProcessInfo`
handover page, the main-thread stack, the main-thread TLS block, and the
main-thread IPC buffer — so that choice lives in one place instead of being
pinned as ABI constants in `process-abi`.

Used by `init` (lays out memmgr and procmgr) and `procmgr` (lays out all other
processes). The creator calls `choose_process_layout` once per process and
writes the result into the handover surface and the entry register; the created
process reads the addresses back rather than assuming fixed values.

`choose_process_layout` is deterministic today. It is the single seam where
per-process randomisation (ASLR, [#39](https://github.com/kottlerg/seraph/issues/39))
substitutes an entropy draw for the default constants, mirroring the
deterministic-first reservation arena in
`runtime/ruststd/src/sys/reserve/seraph.rs`.

---

## Surface

| Item | Purpose |
|---|---|
| `ProcessLayout` | The four bootstrap base VAs for one new process. |
| `choose_process_layout() -> ProcessLayout` | Choose the layout; deterministic (the ASLR seam). |
| `DEFAULT_PROCESS_INFO_VA`, `DEFAULT_STACK_TOP`, `DEFAULT_MAIN_TLS_VA`, `DEFAULT_IPC_BUFFER_VA` | Default addresses; the single source of truth for the values that were formerly ABI constants. |

Page counts are not part of the layout: stack size comes from the binary's
`.note.seraph.stack` ELF note and TLS size from its `PT_TLS` segment, both
resolved by the creator.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/userspace-memory-model.md](../../docs/userspace-memory-model.md) | Three-surface VA model; "Bootstrap Cross-Boundary VAs" |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Handover discipline; `ProcessInfo`/`InitInfo` fields |
| [abi/process-abi/](../../abi/process-abi/) | `ProcessInfo` handover struct that records the chosen VAs |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

None
