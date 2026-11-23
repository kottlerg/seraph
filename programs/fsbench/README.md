# fsbench

Test fixture that measures the cycles `std::fs::File` takes to read each of several sizes
through its two read paths, inline `FS_READ` and memory-cap `FS_READ_MEMORY`, and to rewrite
4 KiB and 64 KiB of a file in place through its memory-cap write path, `FS_WRITE_MEMORY`.

---

## Invocation

`fsbench [ITERS]` runs `ITERS` timed iterations per size and path of every case (a positive
integer). When it is omitted, the full benchmark runs 256 per read and 64 per write, since every
write goes through to the disk. The [`svctest`](../../services/svctest/README.md) phase
`fs_crossover_bench` ([fs_ipc.rs](../../services/svctest/src/phases/fs_ipc.rs)) spawns
`fsbench 8` from `/programs/fsbench`, enough to exercise every path at every size, and passes
when it exits cleanly. The [`ubench`](../ubench/README.md) suite spawns `fsbench` with no
count, the full benchmark, whose lines the `bench` cell compares. `fsbench` is one of
the test-only fixtures installed under `/programs/`, per
[docs/testing.md § Sysroot layout](../../docs/testing.md#sysroot-layout).

---

## Source Layout

```
programs/fsbench/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Fixture check, the timed inline and memory-cap read loops, then the
                           # timed write loops and their read-back
```

---

## Fixture

`fsbench` reads `/data/svctest/bench.bin`, a 64 KiB file that xtask synthesises into the
sysroot at build time rather than storing it under `rootfs/`
([rootfs/README.md](../../rootfs/README.md)). Byte `i` holds `i & 0xFF`. Before timing,
`fsbench` checks the first 64 bytes against that pattern and checks that a read starting at
offset 4080, which straddles a page tail, returns `0xF0` first.

The writes rewrite `/data/svctest/fsbench-write.bin`, a scratch file `fsbench` creates beside the
fixture, writes to 64 KiB before the first timed write, so no timed write extends the file, and
removes once the writes end. Its pages hold byte `i % 251` at offset `i` within the page, which
differs from every fixture page, so a write that reached the fixture instead fails its check.

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

The writes take the memory-cap path: the std client sends a `write` of more than 504 bytes as
`FS_WRITE_MEMORY`, per
[Inline-vs-memory-cap crossover](../../services/fs/docs/fs-driver-protocol.md#inline-vs-memory-cap-crossover-client-policy).
For each size, 4 KiB and 64 KiB, it runs 8 untimed warm-up iterations, then the timed ones (64,
or `ITERS`). Each iteration seeks to offset 0 and rewrites the size one page at a time, one
`write_all` of 4096 bytes each: 1 call for 4 KiB, 16 for 64 KiB. The filesystem writes each
through to the disk, so a sample includes the wait for the device's completions. Once the timed
writes end, `fsbench` reads the 64 KiB back and panics on any page that differs from what it
wrote.

---

## Output

Lines are logged under the name `fsbench`. The run opens with
`starting, fixture=/data/svctest/bench.bin read_iters=<n> write_iters=<n>`, emits one result line
per size and path of each case, and closes with `done`. Each result line has the form
[shared/bench/README.md § Result line](../../shared/bench/README.md#result-line) specifies, where
`<bytes>` is the size, `<path>` is `inline` or `frame` for a read and `frame` for a write, and
`n=` is the case's iteration count:

```text
bench fsbench.read size=<bytes> path=<path> arch=<arch> cpus=<k> unit=cycles
    n=<n> min=<v> p50=<v> p90=<v> p99=<v> max=<v>
bench fsbench.write size=<bytes> path=frame arch=<arch> cpus=<k> unit=cycles
    n=<n> min=<v> p50=<v> p90=<v> p99=<v> max=<v>
```

Each line is one line, wrapped above for width only.

Each sample is one timed iteration, which covers all the `read` or `write_all` calls that one
size needs, not a single call.

A failed pin, CPU-count read, open, fixture check, seek, read, create, write, write read-back, or
removal of the scratch file, or an `ITERS` that is not a positive integer, panics, so the process
exits unsuccessfully and the `fs_crossover_bench` phase fails, as does ubench's `fsbench`
benchmark; a memory-cap `read` that returns `Interrupted` is retried, not a failure.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Test fixtures under `/programs/` and the `/data/` fixtures |
| [Filesystem Driver Protocol](../../services/fs/docs/fs-driver-protocol.md) | `FS_READ`, `FS_READ_MEMORY` and `FS_WRITE_MEMORY`, the client read and write policy, and recorded `fsbench` results |
| [rootfs/README.md](../../rootfs/README.md) | Build-synthesised data fixtures |

---

## Summarized By

[programs/ubench/README.md](../ubench/README.md),
[Filesystem Driver Protocol](../../services/fs/docs/fs-driver-protocol.md)
