# shared/process-layout

Per-process bootstrap virtual-address layout for Seraph process creators.

`no_std`, no allocation, no I/O; depends only on `process-abi` (for stack policy
bounds). Owns the choice of where a new process's four bootstrap surfaces are
placed — the `ProcessInfo` handover page, the main-thread stack, the main-thread
TLS block, and the main-thread IPC buffer — so that choice lives in one place
instead of being pinned as ABI constants in `process-abi`.

Used by `init` (lays out memmgr and procmgr) and `procmgr` (lays out all other
processes). The creator draws entropy, calls `choose_process_layout` once per
process, and writes the result into the handover surface and the entry register;
the created process reads the addresses back rather than assuming fixed values.

Each surface is drawn independently inside a fixed per-region `VaWindow`
(ASLR, [#39](https://github.com/kottlerg/seraph/issues/39)): 2^23 page-aligned
slots on 64 GiB strides in the top PML4/Sv48-root slot, so disjointness, region
ordering, and the stack guard gap hold for every possible draw. The crate is
pure: entropy is injected as pre-drawn bytes, and a creator whose entropy draw
failed passes `None` to fall back to the deterministic `DEFAULT_*` addresses.
The kernel reuses the `INIT_*` windows for init's per-boot layout, and the
`IMAGE_WINDOW` constants parameterise ET_DYN load-bias placement.

---

## Surface

| Item | Purpose |
|---|---|
| `ProcessLayout` | The four bootstrap base VAs for one new process. |
| `choose_process_layout(Option<&[u8; LAYOUT_ENTROPY_BYTES]>) -> ProcessLayout` | Draw the layout from injected entropy; `None` degrades to defaults. |
| `VaWindow` | A fixed randomisation window: power-of-two page slots at a constant base. |
| `MAIN_TLS_WINDOW`, `IPC_BUFFER_WINDOW`, `PROCESS_INFO_WINDOW`, `STACK_GUARD_WINDOW` | Per-surface draw windows used by `choose_process_layout`. |
| `INIT_INFO_WINDOW`, `INIT_STACK_GUARD_WINDOW` | Kernel-side windows for init's per-boot layout. |
| `IMAGE_WINDOW`, `IMAGE_MAX_SPAN`, `choose_image_bias`, `validate_image_placement` | ET_DYN load-bias window and placement validation. |
| `LAYOUT_ENTROPY_BYTES` | Entropy bytes one layout draw consumes. |
| `DEFAULT_PROCESS_INFO_VA`, `DEFAULT_STACK_TOP`, `DEFAULT_MAIN_TLS_VA`, `DEFAULT_IPC_BUFFER_VA` | Degraded-fallback addresses (outside the draw windows by design). |
| `USER_HALF_TOP` | Exclusive top of the canonical user half on both architectures. |

Page counts are not part of the layout: stack size comes from the binary's
`.note.seraph.stack` ELF note and TLS size from its `PT_TLS` segment, both
resolved by the creator.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/userspace-memory-model.md](../../docs/userspace-memory-model.md) | Three-surface VA model; "Bootstrap Cross-Boundary VAs"; zone map |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Handover discipline; `ProcessInfo`/`InitInfo` fields |
| [abi/process-abi/](../../abi/process-abi/) | `ProcessInfo` handover struct that records the chosen VAs |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

None
