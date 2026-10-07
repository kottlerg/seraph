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
        └── main.rs        # Spawns /programs/hello, checks its stdout line and exit
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
`/programs/hello` with a piped stdout, reads the stream to EOF, and waits for the child.

| Check | On failure |
|---|---|
| A stdout line contains `hello from seraph userspace` | Prints `[hello-tester] FAIL expected line missing: …` and the captured stdout; exits `1` |
| The child exited successfully | Prints `[hello-tester] FAIL non-zero exit: …`; exits `2` |

When both checks pass it prints `[hello-tester] PASS` and exits `0`.

---

## svctest Use

`svctest` phases use `/programs/hello` as a known-good spawn target:

- `spawn_phase` (`services/svctest/src/phases/procmgr.rs`) spawns it with argv and an
  environment variable, queries its procmgr state, and waits for a clean exit.
- `command_invalid_elf_loop_phase` spawns it after sixteen failed non-ELF spawns and expects
  exit code `0`.
- `stdio_file_unsupported_phase` expects a spawn with a `File` as stdout to fail with
  `Unsupported`.
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
