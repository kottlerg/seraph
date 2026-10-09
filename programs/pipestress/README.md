# pipestress

Spawn-exit-drain stress fixture for the pipe EOF-drain regression test. It writes one stdout
line and exits at once, so the gap between the write and process death is as short as the
runtime allows, the window in which a parent draining the pipe races the pipe's peer-death
signal. Its tester, `pipestress-tester`, is a per-program tester that `usertest` discovers at
`/tests/programs/pipestress` and runs, per the
[per-program tester protocol](../../docs/testing.md#per-program-tester-protocol). The fixture
itself installs at `/programs/pipestress`, is plain std Rust, and uses no Seraph capabilities.

---

## Source Layout

```
pipestress/
├── Cargo.toml
├── README.md
├── src/
│   └── main.rs            # Echoes argv[1] in one stdout line, then returns
└── tester/
    ├── Cargo.toml         # pipestress-tester; depends on syscall and syscall-abi
    └── src/
        └── main.rs        # Spawn-drain loop, output check, CSpace-slot growth bound
```

---

## Fixture Output

The fixture prints exactly one line, built from its first argument (empty when absent), and
exits `0`:

```
pipestress: <token> ok
```

---

## Tester

The tester runs `ITERATIONS` (250) trials. Each trial spawns `/programs/pipestress` with the
iteration index as its argument and a piped stdout, reads stdout to EOF, and waits for the
child. A trial fails when the child exits non-zero or when the captured output lacks the
expected `pipestress: <index> ok` line; a missing line means the reader saw EOF with bytes
still in the pipe.

The tester also bounds CSpace-slot growth, since each trial creates and destroys several
kernel objects in the tester's own process (the regression guard for ruststd's pooled
object-slab recycling, see
[docs/userspace-memory-model.md](../../docs/userspace-memory-model.md)). It reads the populated
slot count with `cap_info(self_cspace, CAP_INFO_CSPACE_USED)`, takes a baseline after `WARMUP`
(10) trials, and samples a peak every 50 trials and once after the last. Growth from baseline
to peak above `SLOT_SLACK` (8) fails the run.

All tester output goes to stdout. Every line except the `captured stdout:` line after a
`FAIL` carries the `[pipestress-tester]` prefix:

| Line | When |
|---|---|
| `<n> / 250 iterations` | Every 50 trials |
| `slots baseline <b> peak <p> growth <g>` | After the last trial |
| `PASS` | All trials and the slot bound passed |
| `FAIL <reason>` | First failure, followed by an unprefixed `captured stdout: <quoted string>` line (Debug-formatted) |

The tester exits `1` on a reported failure; a failed spawn, read, wait, or `cap_info` call
panics and also exits non-zero. The exit code is the verdict and the `PASS`/`FAIL` line is
advisory, per [docs/testing.md](../../docs/testing.md#contract).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Per-program tester protocol, sysroot layout, and harness gating |
| [docs/userspace-memory-model.md](../../docs/userspace-memory-model.md) | memmgr grants and ruststd's pooled object-slab recycling |
| [services/usertest/README.md](../../services/usertest/README.md) | The orchestrator that runs the tester |

---

## Summarized By

None
