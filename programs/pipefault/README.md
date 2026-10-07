# pipefault

Test fixture for the pipe death-bridge regression test. It writes a known prefix to a piped
stdout, then faults on purpose before its stdio pipes are closed, so the parent can see EOF only
through the spawner-side death bridge. It installs at `/programs/pipefault` as one of the
fixtures `svctest` phases spawn (see
[docs/testing.md § Sysroot layout](../../docs/testing.md#sysroot-layout)), and `svctest`'s
`pipe_fault_eof` phase spawns it.

---

## Source Layout

```
pipefault/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Writes and flushes the prefix, then the deliberate fault
```

---

## Behavior

1. Writes `prefix\n` to stdout and flushes it.
2. Writes through a NULL pointer. The fault kills the process inside `main`, so the
   [ruststd](../../runtime/ruststd/README.md) `_start` never reaches `close_all`, and the
   child's side of the pipe never sets the ring's `closed` flag.

The program prints nothing else and returns no exit code of its own; its exit reason is the
kernel's fault reason (the `EXIT_FAULT_BASE` range in
[docs/process-lifecycle.md § Exit reason](../../docs/process-lifecycle.md#exit-reason)).

The `pipe_fault_eof` phase in
[`services/svctest/src/phases/pipes.rs`](../../services/svctest/src/phases/pipes.rs) spawns
it with `Stdio::piped()` stdout and checks four things: `read_to_end` returns data that starts
with `prefix\n` and then reaches EOF without hanging; the `ExitStatus` code lies in the fault
range; procmgr's `QUERY_PROCESS` reports the process `EXITED`; and procmgr's exit reason matches
the one the spawner saw.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | How harnesses and the fixtures they spawn are staged |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Process death and the exit-reason ranges |
| [runtime/ruststd/README.md](../../runtime/ruststd/README.md) | The std backend that supplies `_start`, stdio pipes, and `Command::spawn` |

---

## Summarized By

None
