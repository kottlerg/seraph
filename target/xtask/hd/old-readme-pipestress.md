# pipestress

Pipe fixture in two modes. By default it is the spawn-exit-drain stress fixture for the pipe
EOF-drain regression test: it writes one stdout line and exits at once, so the gap between the write
and process death is as short as the runtime allows, the window in which a parent draining the pipe
races the pipe's peer-death signal. Its `sink` mode is the reader of the doorbell trial.
The fixture installs at `/tests/fixtures/programs/pipestress`, is plain std Rust, and uses no Seraph
capabilities.

---

## Source Layout

```
pipestress/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Echoes argv[1] in one stdout line; the sink mode
```

---

## Fixture Output

The fixture prints exactly one line, built from its first argument (empty when absent), and
exits `0`:

```
pipestress: <token> ok
```

Given `sink` as its first argument, it prints `pipestress: sink ready`, reads its stdin to EOF,
then prints the bytes it read and the pipe notification sends and waits its thread made meanwhile
(`std::os::seraph::pipe`, [runtime/ruststd/README.md](../../../runtime/ruststd/README.md) § Pipes),
and exits `0`:

```
pipestress: sink <bytes> bytes <sends> sends <waits> waits
```

---

## Driven By

The `pipestress` phase of svctest (`services/svctest/src/phases/pipestress.rs`) spawns a fresh
child, `/tests/svctest pipestress-spawner`, with a piped stdout, so the slot bound measures that
process's own growth. It logs each line the child prints with a `pipestress-spawner:` prefix, waits
for it, and asserts that it exited successfully; otherwise it panics with `pipestress: spawner
exited non-zero`, the exit code, and the captured stdout. The child prints `pipestress: FAIL
<reason>` and the captured output of the failing trial, then exits `1`, on the first failed check
below, which it makes in this order:

- Spawn-drain loop: `ITERATIONS` (250) trials, each spawning
  `/tests/fixtures/programs/pipestress` with the iteration index as its argument and a piped stdout,
  reading stdout to EOF, and waiting for the child. A trial fails when the child exits non-zero or
  when the captured output lacks the line `pipestress: <index> ok`; a missing line means the reader
  saw EOF with bytes still in the pipe.
- CSpace-slot growth bound: each trial creates and destroys several kernel objects in the
  spawner's own process (the regression guard for ruststd's pooled object-slab recycling, see
  [docs/userspace-memory-model.md](../../../docs/userspace-memory-model.md)). The spawner reads the
  populated slot count with `cap_info(self_cspace, CAP_INFO_CSPACE_USED)`, takes a baseline after
  `WARMUP` (10) trials, and samples a peak every 50 trials and once after the last. Growth from
  baseline to peak above `SLOT_SLACK` (8) fails the run.
- Doorbell trial: it spawns the fixture's `sink` mode with piped stdin and stdout, waits for its
  `pipestress: sink ready` line, makes `DOORBELL_WRITES` (10000) writes of `DOORBELL_WRITE_BYTES`
  (16) bytes into its stdin, reads its own counters, closes the stdin, and reads the sink's report.
  The trial fails when the sink does not report ready, exits non-zero, or has no well-formed
  report, when it read other than every byte written, or when either end sent more notifications
  than the other announced waits, since a pipe end rings its peer only for a wait the peer
  announced ([shared/shmem/README.md](../../../shared/shmem/README.md) § Doorbell protocol). It
  logs the time from the first write to the sink's report, the throughput, and both ends' sends and
  waits.

After the child exits successfully the phase logs `pipestress phase passed`.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../../docs/testing.md) | Sysroot layout and harness gating |
| [docs/userspace-memory-model.md](../../../docs/userspace-memory-model.md) | memmgr grants and ruststd's pooled object-slab recycling |
| [services/svctest/README.md](../../svctest/README.md) | The service that runs the phase |

---

## Summarized By

None