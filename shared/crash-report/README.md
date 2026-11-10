# shared/crash-report

The crash block's emitter and parser, and the stack scan crashd's report walks with.

---

## Source Layout

```
crash-report/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs              # Report and its emitter; Arch, Thread, Status, Fault, Image
    ├── parse.rs            # parse, Block, Defect
    ├── walk.rs             # scan: the stack walk's candidate return addresses
    └── tests.rs            # Host tests
```

`no_std` with `alloc`. Pure logic, host-tested by `cargo xtask test`.

---

## Surface

| Item | Purpose |
|---|---|
| `Report` | One report as crashd fills it; `Report::emit` hands each line of its block to a sink, the end marker counting the field lines. |
| `parse(log)` | Every block in a log, by its begin marker, each a `Block`; a field line joins the open block whose id it carries, and a repeated line counts once. |
| `Block` | One block read back: `get`, `hex`, `frames`, `is_complete`, and `check`, which returns the first `Defect` against the fields the block's kind, thread, and status require. |
| `walk::scan` | The aligned stack words inside the image's text, in stack order, up to a limit. |
| `Arch::register_names` | The register file's word names per architecture, asserted at compile time against the register-file sizes `abi/syscall` publishes. |

The format is [services/crashd/docs/block-format.md](../../services/crashd/docs/block-format.md);
this crate implements it on both sides, so crashd, which emits it, and xtask's `test-crash-report`
and `symbolize --log`, which read it, cannot drift apart.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [services/crashd/docs/block-format.md](../../services/crashd/docs/block-format.md) | The block's lines, fields, and stack walk |
| [services/crashd/README.md](../../services/crashd/README.md) | The service that emits the blocks |

---

## Summarized By

None
