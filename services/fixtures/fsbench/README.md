# fsbench

Test fixture that measures the cycles `std::fs::File` takes to read each of several sizes
through its two read paths, inline `FS_READ` and memory-cap `FS_READ_MEMORY`, to rewrite 4 KiB
and 64 KiB of a file in place through its memory-cap write path, `FS_WRITE_MEMORY`, and to open a
three-component path.

---

## Invocation

`fsbench [ITERS]` runs `ITERS` timed iterations per size and path of every case (a positive
integer). When it is omitted, the full benchmark runs 256 per read and per open and 64 per write,
since every write goes through to the disk. The [`svctest`](../../svctest/README.md) phase
`fs_crossover_bench` ([fs_ipc.rs](../../svctest/src/phases/fs_ipc.rs)) spawns `fsbench 8` from
`/tests/fixtures/programs/fsbench`, enough to exercise every path at every size, and passes when it
exits cleanly. The [`ubench`](../../ubench/README.md) suite spawns `fsbench` with no count, the full
benchmark, whose lines the `bench` cell compares. `fsbench` is one of the test-only fixtures
installed under `/tests/fixtures/programs/`, per [docs/testing.md § Sysroot
layout](../../../docs/testing.md#sysroot-layout).

---

## Source Layout

```
services/fixtures/fsbench/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs            # Fixture check, the timed inline and memory-cap read loops, then the
    │                      # timed write loops and their read-back
    ├── open.rs            # The timed open of /services/fs/fatfs and its NS_LOOKUP count
    └── unpinned.rs        # The windows of a client with no affinity, at more than one CPU
```

---

## Fixture

`fsbench` reads `/data/svctest/bench.bin`, a 64 KiB file that xtask synthesises into the
sysroot at build time rather than storing it under `rootfs/`
([rootfs/README.md](../../../rootfs/README.md)). Byte `i` holds `i & 0xFF`. Before timing,
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
[Inline-vs-memory-cap crossover](../../fs/docs/fs-driver-protocol.md#inline-vs-memory-cap-crossover-client-policy).
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
include them. Cycles come from [shared/bench](../../../shared/bench/README.md)'s `Counters`, `rdtsc`
on x86_64 and `csrr cycle` on riscv64, opened once the thread is pinned. Each timed iteration
blocks on the filesystem driver, and riscv64 keeps no two harts' `cycle` counters in step, so
`fsbench` pins its thread to CPU 0 before it opens the fixture; the open, the fixture check and the
warm-up iterations, which block on the driver too, leave it running there. A timed iteration that
reads fewer bytes than the size panics.

The writes take the memory-cap path: the std client sends a `write` of more than 504 bytes as
`FS_WRITE_MEMORY`, per
[Inline-vs-memory-cap crossover](../../fs/docs/fs-driver-protocol.md#inline-vs-memory-cap-crossover-client-policy).
For each size, 4 KiB and 64 KiB, it runs 8 untimed warm-up iterations, then the timed ones (64,
or `ITERS`). Each iteration seeks to offset 0 and rewrites the size one page at a time, one
`write_all` of 4096 bytes each: 1 call for 4 KiB, 16 for 64 KiB. The filesystem writes each
through to the disk, so a sample includes the wait for the device's completions. Once the timed
writes end, `fsbench` reads the 64 KiB back and panics on any page that differs from what it
wrote.

The `open` case then opens `/services/fs/fatfs`, a file three components deep that the root
filesystem owns, after 8 untimed warm-up opens, the timed ones (as many as each read size: 256, or
`ITERS`). Each sample is one `File::open`: vfsd forwards the whole path to the root filesystem,
which walks all three components in one `NS_LOOKUP`
([shared/namespace-protocol/README.md](../../../shared/namespace-protocol/README.md#ns_lookup)
§ NS_LOOKUP), and the open's `FS_OPEN`; the file is closed outside the sample. An open whose
walk made other than one `NS_LOOKUP` call, by std's count
(`std::os::seraph::fs::ns_lookup_calls`), panics.

### A client with no affinity

Pinned to CPU 0, the thread is a caller the synchronous wake rule never places beside a receiver
that outranks it, so each round trip with fatfs, an RT server, wakes another CPU
([core/kernel/docs/scheduler.md § Thread
Assignment](../../../core/kernel/docs/scheduler.md#thread-assignment)).
At more than one CPU, `fsbench` therefore also measures the client real filesystem clients are,
one with no affinity, which the rule runs on one CPU with its server: after the pinned reads, the
16-byte inline read, and after the pinned opens, the open, each in the window-mean form
([shared/bench/README.md § Window-mean rows](../../../shared/bench/README.md#window-mean-rows)).
A sample cannot cover one operation once the thread may move between its two counter reads, so
each covers a window of 16 operations (all of them when `ITERS` is smaller), and the case's
iterations make its windows: 16 of 16 in the full benchmark.

After 8 untimed warm-up operations, each window runs one untimed operation pinned to CPU 0,
which blocks and so leaves the thread running there; then it opens the thread's idle-halt span
on CPU 0, clears the thread's affinity, reads the counters, runs the window's operations, reads
the counters again, closes the span, and pins the thread to CPU 0 again. Clearing an affinity, or
setting the one CPU the thread runs on, moves nothing, so no blocking call falls inside the
window but the measured operations. The window counts when the span closes on CPU 0 with no
halt: both reads ran on CPU 0, and its counter ran throughout
([docs/testing.md § Benchmarks](../../../docs/testing.md#benchmarks-bench-cell)). Its sample is
the window's cycles divided by its operations. A window whose span closed on another CPU, or
saw CPU 0 halt, is left out and counted. The open window keeps its files open and closes them
after its closing read, so, as in the pinned case, no close is measured.

---

## Output

Lines are logged under the name `fsbench`. The run opens with
`starting, fixture=/data/svctest/bench.bin read_iters=<n> write_iters=<n>`, emits one result line
per size and path of each case, then the `open` case's, and closes with `done`. Each result line
has the form
[shared/bench/README.md § Result line](../../../shared/bench/README.md#result-line) specifies, where
`<bytes>` is the size, `<path>` is `inline` or `frame` for a read and `frame` for a write, and
`n=` is the case's iteration count:

```text
bench fsbench.read size=<bytes> path=<path> arch=<arch> cpus=<k> unit=cycles
    n=<n> min=<v> p50=<v> p90=<v> p99=<v> max=<v> idle_halts=<n>
bench fsbench.write size=<bytes> path=frame arch=<arch> cpus=<k> unit=cycles
    n=<n> min=<v> p50=<v> p90=<v> p99=<v> max=<v> idle_halts=<n>
```

Each line is one line, wrapped above for width only. The `open` case's line has the same form,
with `depth=3`, the path's component count, in place of the size and path:

```text
bench fsbench.open depth=3 arch=<arch> cpus=<k> unit=cycles
    n=<n> min=<v> p50=<v> p90=<v> p99=<v> max=<v> idle_halts=<n>
```

At more than one CPU, the rows of a client with no affinity follow, each after its pinned case's
lines:

```text
bench fsbench.read size=16 path=inline affinity=any arch=<arch> cpus=<k> unit=cycles
    n=<n> min=<v> p50=<v> p90=<v> p99=<v> max=<v>
    window_ops=<n> moved=<n> halted=<n> idle_halts=<n> remote_wakes=<n>
bench fsbench.open depth=3 affinity=any arch=<arch> cpus=<k> unit=cycles
    n=<n> min=<v> p50=<v> p90=<v> p99=<v> max=<v>
    window_ops=<n> moved=<n> halted=<n> idle_halts=<n> remote_wakes=<n>
```

`n=` is the windows that counted, `window_ops=` the operations each sample is the mean of,
`moved=` and `halted=` the windows left out, `idle_halts=` CPU 0's halts over every window whose
span closed, and `remote_wakes=` the wakes of the thread, over the counted windows, that linked it
on another CPU than its waker's (`CAP_INFO_THREAD_PLACEMENT`): a reply from a server on another
CPU is one, so `0` with `idle_halts=0` says that every round trip ran on CPU 0. A failed placement
read leaves `remote_wakes=` out. When fewer than half the windows count, the row is no mean of
the case: `fsbench` logs no result line for it, and logs at WARN
`<name> affinity=any: counted windows below the floor` with the counts.

Each `read` or `write` sample is one timed iteration, which covers all the `read` or
`write_all` calls that one size needs, not a single call; each `open` sample is one
`File::open`. `idle_halts=` is the halts of CPU 0 over the case's timed loop, marked after its
warm-up and read after its last sample
([shared/bench/README.md § Idle halts](../../../shared/bench/README.md#idle-halts)); a read that
failed leaves it out.

A failed pin or affinity clear, CPU-count read, open, fixture check, seek, read, create, write,
write read-back, or removal of the scratch file, an `open` case walk of other than one
`NS_LOOKUP`, or an `ITERS` that is not a positive integer, panics, so the process exits
unsuccessfully and the `fs_crossover_bench` phase fails, as does ubench's `fsbench` benchmark; a
memory-cap `read` that returns `Interrupted` is retried, not a failure.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../../docs/testing.md) | Test fixtures under `/programs/` and the `/data/` fixtures |
| [Filesystem Driver Protocol](../../fs/docs/fs-driver-protocol.md) | `FS_READ`, `FS_READ_MEMORY` and `FS_WRITE_MEMORY`, the client read and write policy, and recorded `fsbench` results |
| [rootfs/README.md](../../../rootfs/README.md) | Build-synthesised data fixtures |

---

## Summarized By

[Filesystem Driver Protocol](../../fs/docs/fs-driver-protocol.md),
[services/ubench/README.md](../../ubench/README.md)
