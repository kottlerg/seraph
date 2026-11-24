# spawn-target

Known-good program-role test image that svctest's phases create, spawn, read, and look up. It prints
one line and exits 0, whatever its arguments.

---

## Role

The fixture is its own binary so that svctest, which runs no other program, has a program-role
`std` image to hand procmgr. It is larger than one page, which the `procmgr_concurrent_spawn` phase
relies on when it lends procmgr the first page of the file and withholds the rest, and its name is
one the `namespace` phase looks up and lists under `/tests/fixtures/programs`. It installs at
`/tests/fixtures/programs/spawn-target`, whose `programs` component gives it the program role
([docs/signing.md](../../../docs/signing.md)).

---

## Source Layout

```
spawn-target/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # The one line
```

---

## Behaviour

| Argument | Output | Exit |
|---|---|---|
| any, or none | `spawn-target ran` | `0` |

The check that a program may start programs only
([docs/signing.md](../../../docs/signing.md) § Signature Policy in procmgr) is the `narrow` mode of
[program-modes](../program-modes/README.md#narrow).

---

## Driven By

The spawn target of the svctest phases in `services/svctest/src/phases/`: `procmgr.rs`,
`memmgr.rs`, `budget.rs`, `process_tree.rs`, `critical_creates.rs`, `pipes.rs`, `restore.rs`,
and `namespace.rs`. The phases that read its exit or output assert as follows.

- The `pipes` phase (section 1) spawns it with a piped stdout and asserts that stdout is not empty
  and that it exits cleanly; section 3 asserts the same of `Command::output()`.
- The `namespace` phase asserts that `NS_READDIR` of `/tests/fixtures/programs` surfaces
  `spawn-target` verbatim, that `NS_LOOKUP` of `SPAWN-TARGET` there finds a file and `NS_STAT` on it
  succeeds (the lookup is case-insensitive), and that the `fixtures-child` role's capability,
  rooted at `/tests/fixtures/programs`, opens `/spawn-target`.
- The `procmgr_concurrent_spawn` phase asserts that the file is longer than one page.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/signing.md](../../../docs/signing.md) | Signing roles and the creator policy `narrow` checks |
| [services/svctest/README.md](../../svctest/README.md) | The harness that runs the phases |
| [services/procmgr/README.md](../../procmgr/README.md) | The process creation the phases drive |

---

## Summarized By

[services/fixtures/README.md](../README.md)
