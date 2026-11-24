# hello

Hello-world program built against `std` with no `std::os::seraph` imports: it prints one line
through `println!` and exits `0`. Its per-program tester, which the `usertest` orchestrator
spawns, checks that line and that exit. It installs at `/programs/hello`.

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
        └── main.rs        # Spawns /programs/hello, checks its stdout line and exit, its
                           # declared seed, and that usertest drains a tester's stderr
```

---

## Output

The program writes one line to stdout and returns from `main`:

```
hello from seraph userspace
```

---

## Tester

The `hello-tester` crate installs at `/tests/programs/hello`, per the [per-program tester
protocol](../../docs/testing.md#per-program-tester-protocol). It first takes the one seed
usertest's recipe declares for it, `pwrmgr.deny`, over the bootstrap protocol
([programs/usertest/README.md](../usertest/README.md) § Seeds), before any write, since usertest
drains a tester's streams only once its spawn has returned, and sends pwrmgr `SHUTDOWN` on it,
which pwrmgr refuses, so the cap that arrived is that seed. It then writes four 1024-byte lines
(4096 bytes, twice the 2048-byte pipe ring) to its own stderr while its stdout is open, which checks
that `usertest` drains a tester's two streams at once: an orchestrator that read stdout to EOF first
would leave the tester blocked on the full stderr ring, and the run would hang. Last, it spawns
`/programs/hello` with a piped stdout, reads the stream to EOF, and waits for the child. A failed
stderr write, spawn, read, or wait panics through `expect`, and the panic's non-zero exit is the
verdict.

| Check | On failure |
|---|---|
| The tester has a creator endpoint | Prints `[hello-tester] FAIL no creator endpoint for the declared seed`; exits `5` |
| Its one bootstrap slot holds a cap | Prints `[hello-tester] FAIL declared seed not delivered: …`; exits `6` |
| pwrmgr answers `SHUTDOWN` on that cap `UNAUTHORIZED` | Prints `[hello-tester] FAIL the declared seed's SHUTDOWN answered …` and exits `7` on another answer; prints `[hello-tester] FAIL the declared seed's SHUTDOWN call failed: …` and exits `8` when the call fails |
| A stdout line contains `hello from seraph userspace` | Prints `[hello-tester] FAIL expected line missing: …` and the captured stdout; exits `1` |
| The child exited successfully | Prints `[hello-tester] FAIL non-zero exit: …`; exits `2` |

When every check passes it prints `[hello-tester] PASS` and exits `0`.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Per-program tester protocol, `usertest` harness, sysroot layout |
| [programs/usertest/README.md](../usertest/README.md) | Orchestrator that discovers and spawns the tester |

---

## Summarized By

None