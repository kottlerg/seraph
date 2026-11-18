# hello

Hello-world program built against `std` with no `std::os::seraph` imports: it prints one line
through `println!` and exits `0`. Its per-program tester, which the `usertest` orchestrator
spawns, checks that line and that exit, and `svctest` phases use it as a known-good spawn
target. It installs at `/programs/hello`.

---

## Source Layout

```
programs/hello/
├── Cargo.toml
├── README.md
├── src/
│   └── main.rs            # Prints the greeting line and returns
└── tester/
    ├── Cargo.toml         # Crate hello-tester
    └── src/
        └── main.rs        # Spawns /programs/hello, checks its stdout line and exit,
                           # and that a program may not start a service
```

---

## Output

The program writes one line to stdout and returns from `main`:

```
hello from seraph userspace
```

---

## Tester

The `hello-tester` crate installs at `/tests/programs/hello`, per the
[per-program tester protocol](../../docs/testing.md#per-program-tester-protocol). It spawns
`/programs/hello` with a piped stdout, reads the stream to EOF, and waits for the child. Then,
being a program itself, it spawns the service `/tests/crasher`, which procmgr refuses, since
a program may start programs only
([docs/signing.md](../../docs/signing.md) § Signature Policy in procmgr).

| Check | On failure |
|---|---|
| A stdout line contains `hello from seraph userspace` | Prints `[hello-tester] FAIL expected line missing: …` and the captured stdout; exits `1` |
| The child exited successfully | Prints `[hello-tester] FAIL non-zero exit: …`; exits `2` |
| Spawning `/tests/crasher` fails with `PermissionDenied` | Prints `[hello-tester] FAIL starting /tests/crasher: …` and exits `3` on another error; kills it, prints `[hello-tester] FAIL a program started the service …` and exits `4` when it starts |

When every check passes it prints `[hello-tester] PASS` and exits `0`.

---

## svctest Use

[`svctest`](../../services/svctest/README.md) phases use `/programs/hello` as a known-good
spawn target:

- `spawn_phase` (`services/svctest/src/phases/procmgr.rs`) spawns it with argv and an
  environment variable, queries its procmgr state, and waits for a clean exit.
- `command_invalid_elf_loop_phase` spawns it after sixteen failed non-ELF spawns and expects
  exit code `0`.
- `stdio_file_unsupported_phase` expects a spawn with a `File` as stdout to fail with
  `Unsupported`.
- `command_from_spawned_thread_phase` captures its output through `Command::output()` from a
  spawned thread and expects a clean exit and non-empty stdout.
- `procmgr_refusals_phase` passes it as the file cap of raw `CREATE_FROM_FILE` requests (refused
  ones, one whose child takes the `CONFIGURE_PIPE` cells, and, from the
  `undeliverable-reply-child`, ones whose reply cannot be delivered), and spawns it to check
  that procmgr still serves after the refusals.
- `procmgr_dma_hold_phase` creates it through raw `CREATE_FROM_FILE` with `CREATE_DMA_HOLD`,
  destroys one child before its start and starts another to its exit, and checks that procmgr
  holds the started child's pages until `RELEASE_HOLD` on the child's release token, which its
  process handle cannot send.
- `create_process_verifies_module_phase` reads it into a memory grant and creates it from that
  grant through raw `CREATE_PROCESS` under its name and length, which runs to a clean exit, and
  under a wrong name, a wrong length, no name, and with one byte changed, which procmgr refuses.
- `create_from_file_refuses_wrong_name_phase` passes it as the file cap of a raw
  `CREATE_FROM_FILE` under a wrong name, which procmgr refuses with `SIGNATURE_REFUSED`.
- `memory_max_phase` (`services/svctest/src/phases/budget.rs`) passes it as the file cap of
  refused raw `CREATE_FROM_FILE` requests (one with a one-page memory max, which procmgr cannot
  load it under), and its `budget-child` creates it with a memory max above the child's own and
  destroys it unstarted, to check the max memmgr clamps it to.
- `pipes_phase` (`services/svctest/src/phases/pipes.rs`) captures its stdout through a pipe
  and through `Command::output()`, and expects bytes and a clean exit.

The namespace phases (`services/svctest/src/phases/namespace.rs`) use the installed binary as
a file only. `ns_phase` expects `hello` in the `/programs` listing and looks it up as `HELLO`,
and `ns_programs_subtree_phase` opens it as `/hello` through a cap rooted at `/programs`.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Per-program tester protocol, `usertest` harness, sysroot layout |
| [services/usertest/README.md](../../services/usertest/README.md) | Orchestrator that discovers and spawns the tester |

---

## Summarized By

None
