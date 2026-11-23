# fsbench

Test fixture that measures the cycles `std::fs::File` takes to read each of several sizes
through its two read paths, inline `FS_READ` and memory-cap `FS_READ_MEMORY`.

---

## Invocation

`fsbench [ITERS]` runs `ITERS` timed iterations per size and path (a positive integer; 256
when omitted, the full benchmark). The [`svctest`](../../services/svctest/README.md) phase
`fs_crossover_bench` ([fs_ipc.rs](../../services/svctest/src/phases/fs_ipc.rs)) spawns
`fsbench 8` from `/programs/fsbench`, enough to exercise both read paths at every size, and
passes when it exits cleanly; the full count is for a manual benchmark run. `fsbench` is one of
the test-only fixtures installed under `/programs/`, per
[docs/testing.md § Sysroot layout](../../docs/testing.md#sysroot-layout).

---

## Source Layout

```
programs/fsbench/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Fixture check, then the timed inline and memory-cap read loops
```

---

## Fixture

`fsbench` reads `/data/svctest/bench.bin`, a 64 KiB file that xtask synthesises into the
sysroot at build time rather than storing it under `rootfs/`
([rootfs/README.md](../../rootfs/README.md)). Byte `i` holds `i & 0xFF`. Before timing,
`fsbench` checks the first 64 bytes against that pattern and checks that a read starting at
offset 4080, which straddles a page tail, returns `0xF0` first.

---

## Method

The std client picks the read path itself: inline when the request fits the inline ceiling
without crossing a page tail, memory cap otherwise, per
[Inline-vs-memory-cap crossover](../../services/fs/docs/fs-driver-protocol.md#inline-vs-memory-cap-crossover-client-policy).
`fsbench` forces each path through the size of the buffer it passes to `read`:

| Path     | Buffer per `read` call                                        |
|----------|---------------------------------------------------------------|
| `inline` | At most 504 bytes, trimmed so the read ends at or before a page tail |
| `frame` (memory cap) | A full 4096-byte page                           |

For each size in 16 B, 1 KiB, 4 KiB, 16 KiB, and 64 KiB, and for each path, it runs 8 untimed
warm-up iterations, then the timed ones (256, or `ITERS`). Each iteration seeks to offset 0 and
reads the full size through as many `read` calls as the path's buffer needs: 144 inline or 16
memory-cap calls for 64 KiB. A memory-cap `read` that returns `Interrupted` (std discarded a copy
whose page the driver may have released during it) is read again inside the same timed iteration, so
such an iteration makes one more `read` call than the size needs for each retry, and its cycles
include them. Cycles come from [shared/bench](../../shared/bench/README.md)'s `Counters`, `rdtsc`
on x86_64 and `csrr cycle` on riscv64, opened once the thread is pinned. Each timed iteration
blocks on the filesystem driver, and riscv64 keeps no two harts' `cycle` counters in step, so
`fsbench` pins its thread to CPU 0 before it opens the fixture; the open, the fixture check and the
warm-up iterations, which block on the driver too, leave it running there. A timed iteration that
reads fewer bytes than the size panics.

---

## Output

Lines are logged under the name `fsbench`. The run opens with
`starting, fixture=/data/svctest/bench.bin iters=<n>`, emits one result line per size and path, and
closes with `done`. Each result line has the form
[shared/bench/README.md § Result line](../../shared/bench/README.md#result-line) specifies, where
`<bytes>` is the size, `<path>` is `inline` or `frame`, and `n=` is `ITERS`:

```text
bench fsbench.read size=<bytes> path=<path> arch=<arch> cpus=<k> unit=cycles
    n=<n> min=<v> p50=<v> p90=<v> p99=<v> max=<v>
```

The line is one line, wrapped above for width only.

Each sample is one timed iteration, which covers all the `read` calls that one size needs, not a
single call.

A failed pin, CPU-count read, open, fixture check, seek, or read, or an `ITERS` that is not a
positive integer, panics, so the process exits unsuccessfully and the `fs_crossover_bench` phase
fails; a memory-cap `read` that returns `Interrupted` is retried, not a failure.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Test fixtures under `/programs/` and the `/data/` fixtures |
| [Filesystem Driver Protocol](../../services/fs/docs/fs-driver-protocol.md) | `FS_READ` and `FS_READ_MEMORY`, the client read policy, and recorded `fsbench` results |
| [rootfs/README.md](../../rootfs/README.md) | Build-synthesised data fixtures |

---

## Summarized By

[Filesystem Driver Protocol](../../services/fs/docs/fs-driver-protocol.md)
