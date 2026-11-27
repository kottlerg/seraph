# ubench

The userspace benchmark suite: it measures, in cycles, what the system's userspace paths cost a
process, and logs one result line per measurement. It is a harness, installed as `/tests/ubench`
([docs/testing.md § Sysroot layout](../../docs/testing.md#sysroot-layout)), and the CI `bench`
cell boots it under icount beside the ktest benchmarks
([docs/testing.md § Benchmarks](../../docs/testing.md#benchmarks-bench-cell)).

---

## Running

svcmgr spawns ubench from
[`rootfs/config/svcmgr/tests/ubench.svc`](../../rootfs/config/svcmgr/tests/ubench.svc), which
svcmgr does not scan. To run it, stage the recipe as svctest's is, with the terminal dropped so
that it adds no output of its own to the framebuffer `console_write` measures; logd's framebuffer
sink, at its default level of critical, draws no line of a run that fails nothing:

```sh
cargo xtask build --arch x86_64 --release
cp sysroot/config/svcmgr/tests/ubench.svc sysroot/config/svcmgr/services/
rm -f sysroot/config/svcmgr/services/terminal.svc
cargo xtask mkdisk --arch x86_64 --repack-only
cargo xtask run --arch x86_64 --icount --cpus 1 --display framebuffer --runs 1 --timeout 900 \
    --save-logs target/xtask/bench/ubench
```

`--icount` on the release build gives the counts the `bench` cell compares, since the cell boots
the release profile ([docs/testing.md § Benchmarks](../../docs/testing.md#benchmarks-bench-cell));
without `--icount` the counts are time on the host. A boot without `--display framebuffer` has no
framebuffer, and `console_write` logs a SKIP line. The recipe seeds `devmgr.class.framebuffer`, the
class `console_write` writes through, and `pwrmgr.shutdown`, through which ubench powers the system
off once it logged its pass marker.

---

## Source Layout

```
services/ubench/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs            # Seeds, the pin, the benchmark sequence, the marker, power-off
    ├── harness.rs         # The pin, the CPU count, the result and SKIP lines
    ├── ipc_rt.rs          # ipc_rt: call and reply with a server thread on the same CPU
    ├── fault.rs           # fault_fill and fault_scaling: demand faults and grants
    ├── shmem_ring.rs      # shmem_ring: the stdio pipe's byte ring
    ├── pipeline.rs        # pipeline: a producer and a consumer thread, neither pinned
    ├── console.rs         # console_write: FB_WRITE_BYTES to the framebuffer driver
    ├── fsbench.rs         # fsbench: /tests/fixtures/programs/fsbench at its full counts
    └── empty_window.rs    # empty_window: two counter reads with nothing between them
```

---

## Benchmarks

ubench runs its benchmarks in the order below, each to its end before the next. Every sample is
read from [shared/bench](../../shared/bench/README.md)'s `Counters`, `rdtsc` on x86_64 and
`csrr cycle` on riscv64. riscv64 keeps no two harts' `cycle` counters in step, so every thread
that measures is pinned to one CPU before it opens its counters: ubench's own thread to CPU 0,
and each `fault_scaling` worker to its own. Each benchmark runs untimed warm-up iterations before
its timed ones.

| Benchmark | Variant | One sample | Timed samples |
|---|---|---|---|
| `ipc_rt` | `words=0\|6\|7\|64` | One `ipc_call` to a server thread of ubench pinned to CPU 0, which receives with `ipc_recv` and answers with `ipc_reply` carrying the call's data words back ([shared/ipc](../../shared/ipc/README.md)). 6 is the most data words that travel in registers, 7 the first count past it, 64 the most a message holds | 1024 per count, after 64 |
| `fault_fill` | `path=fault\|grant pages=16`; `path=grant pages=16 affinity=any` at more than one CPU | The cost of one 16-page chunk, `DEMAND_CHUNK_PAGES`, the run memmgr backs on a demand fault when a free run covers it ([memmgr Memory Pool § Demand faults](../memmgr/docs/memory-pool.md#demand-faults)). `fault`: the first store into a chunk of a region `register_demand_paged` registered, which is the fault's delivery to memmgr, memmgr's backing of the chunk (run selection, zeroing, the map) and the resume; the registration funds the region's page tables, so no sample funds any. `grant`: `REQUEST_MEMORY_CAPS` for the chunk's pages with `REQUIRE_CONTIGUOUS`, the cap's map into a reservation with `mem_map_funded`, which funds page tables when the map is refused for want of them, and the first store into it | 64 per path, after 4; `affinity=any`: 128 grants in 8 windows of 16, after 4 |
| `fault_scaling` | `threads=1\|2\|4\|8 pages=16` | The `fault` sample of `fault_fill`, taken by k threads at once: thread i is pinned to CPU i, opens its own counters there and registers its own region, and all start their timed stores together. The line of k holds every thread's samples. A count above the CPUs online logs a SKIP line | 64 per thread, after 4 |
| `shmem_ring` | `bytes=64\|512\|4096\|65536 wrap=no\|yes` | `bytes` moved through a byte ring of the stdio pipe's capacity, 2048 bytes ([shared/shmem](../../shared/shmem/README.md), `runtime/ruststd/src/sys/pipe/seraph.rs`): `SpscWriter::write` of what fits, `SpscReader::read` of it, until every byte passed, as a pipe's writer and reader take turns. One thread does both, so a sample is the copies and the index updates, with no notification or IPC. The ring copies a write or a read as two segments where it passes the body's end, so every sample starts at a stated ring index, reached by an untimed transfer before it. `wrap=no` starts at index 0, where no copy splits. `wrap=yes` starts half the transfer, or half the ring when the transfer is larger, before the body's end: the first write and read split into halves, as does every ring-full of a larger transfer | 256 per size and `wrap`, after 16 |
| `pipeline` | `work=0\|1024\|8192\|65536` | A window of 64 items, 64 bytes each, passed from a producer thread to a consumer thread through a byte ring of the stdio pipe's capacity, 2048 bytes, with the pipe's doorbell protocol ([shared/shmem § Doorbell protocol](../../shared/shmem/README.md#doorbell-protocol)); each side runs `work` iterations of a multiply-add chain per item, a fixed instruction count wherever it runs. Neither thread is pinned: ubench's thread spawns the producer and the producer the consumer. ubench's thread times the window from CPU 0 (below) | 32 per `work`, after a calibration and 2 |
| `console_write` | `bytes=64\|4096` | `bytes` of text, lines of 63 letters and a newline, sent to the framebuffer driver as `FB_WRITE_BYTES` calls of at most 512 bytes each, as the terminal sends its child's output (`programs/terminal/src/output.rs`). Before each size's warm-up, untimed writes of 4096 bytes fill the screen, so every timed write of either size scrolls it, whatever the screen held before | 64 per size, after 16 |
| `fsbench` | — | [`/tests/fixtures/programs/fsbench`](../fixtures/fsbench/README.md) spawned with no iteration count, its full benchmark, which logs its own `fsbench.read`, `fsbench.write` and `fsbench.open` lines | as fsbench's |
| `empty_window` | — | Two counter reads with nothing between them: the offset every other line includes ([docs/testing.md § Benchmarks](../../docs/testing.md#benchmarks-bench-cell)) | 1024, after 64 |

The `fault` line of `fault_fill` carries two extras, read outside the timed window from ubench's
own charge, `QUERY_MEMORY_USAGE` before and after each store: `faults=`, the timed stores memmgr
backed pages for, and `backed_pages=`, the pages it backed for them. A store whose page an earlier
fault already backed adds to neither, so a fault that backs more than its own chunk shows as
`faults=` below `n=`.

The `path=grant affinity=any` line of `fault_fill` is a window row ([shared/bench/README.md § Window
rows](../../shared/bench/README.md#window-rows)): 128 grants of the `grant` sample in windows of
`window_ops=` 16, taken by ubench's thread with its affinity cleared between the window's two
counter reads, as fsbench's `affinity=any` rows take theirs. The pinned `grant` line measures a
caller the synchronous wake rule never places beside memmgr, which outranks it; this one measures
the caller it can place there ([core/kernel/docs/scheduler.md](../../core/kernel/docs/scheduler.md)
§ Thread Assignment). It carries `remote_wakes=`, the thread's wakes linked on another CPU than its
waker's over the counted windows (`CAP_INFO_THREAD_PLACEMENT`): one per grant while memmgr's reply
wakes it from another CPU, none while memmgr serves it on its own. At one CPU the case logs a SKIP
line.

`pipeline` measures where the kernel runs two threads that hand work to each other, as
[core/kernel/docs/scheduler.md § Thread
Assignment](../../core/kernel/docs/scheduler.md#thread-assignment) places them, so neither is
pinned, and neither can read a counter that times a window: either may move between two reads.
ubench's thread, pinned to CPU 0, is the pipeline's head and tail instead. Per window it reads its
counter, wakes the producer through a notification, waits on another for the consumer's word that
the window's 64 items have passed, and reads again, so a sample is the window's elapsed cycles on
CPU 0 wherever the pair ran, a window row ([shared/bench/README.md § Window
rows](../../shared/bench/README.md#window-rows)); throughput is `window_ops=` over the sample. The
window holds what the observer costs it: the producer's wake from CPU 0 at its start, which is the
first placement each window asks of the kernel, and the observer's own wake at its end, once per 64
items. The observer is blocked for the rest of the window and takes no CPU time from the pair. At
one CPU the three threads share the CPU and the window never idles; at more, CPU 0 halts when
nothing else runs there, and a window counts that time only if the counter runs through a halt.
Every window is therefore checked against the kernel's elapsed microseconds
([shared/bench/README.md § Window rate check](../../shared/bench/README.md#window-rate-check)): one
whose cycles fall short of its elapsed time, because the counter stopped or the thread was delayed
between a clock read and a counter read, is left out of the samples and counted in
`clock_stopped=`, and a line all of whose windows were left out is the benchmark's FAIL line, which
names `window_us=`. Each line's extras, after its summary: `window_ops=`, the items a sample holds;
`apart=`, the timed windows at whose end the two threads were last on different CPUs;
`clock_stopped=`; and `window_us=`, the mean elapsed microseconds of a timed window, over every
one, which gives the throughput even where every window was left out. The line at one CPU gates
like every other; the lines at more report. After each result line ubench logs `pipeline placement:
work=<n> cpus=<k>` with `remote_wakes=`, `idle_wakes=`, `wake_moves=` and `pulls=`: how much the
two threads' placement counters grew over the timed windows, summed, from the counters
[core/kernel/docs/scheduler.md § Placement
Counters](../../core/kernel/docs/scheduler.md#placement-counters) names. They take a line of their
own so that the result line stays within the bytes the log carries whole (below).

---

## Output

Lines are logged under the name `ubench`. The run opens with `starting`, and each benchmark then
logs one of:

- its result lines, in the form
  [shared/bench/README.md § Result line](../../shared/bench/README.md#result-line) specifies, with
  suite `ubench` (fsbench's under its own name and suite):

  ```text
  bench ubench.<name> <variant> arch=<arch> cpus=<k> unit=cycles n=<n> min=<v> p50=<v>
      p90=<v> p99=<v> max=<v> [faults=<n> backed_pages=<n>] [window_ops=<n> ...] idle_halts=<n>
  ```

  wrapped above for width only, `idle_halts=` being the halts of the measuring CPU over the
  measured loop ([shared/bench/README.md § Idle halts](../../shared/bench/README.md#idle-halts)):
  in `fault_fill path=grant affinity=any`, a window row whose reads the measured thread takes,
  over every window whose span closed, and in `pipeline`, whose reads its pinned observer takes,
  over one span around its calibration, warm-up and timed windows; a window row's `n=` is the
  windows that counted, and its other extras are those of § Benchmarks; a failed placement read
  leaves `remote_wakes=` out;
- for a window row whose reads the measured thread takes and whose counted windows fall below half
  its windows, no result line but a WARN line, `fault_fill path=grant affinity=any: counted windows
  below the floor`, with the counts (`pipeline` has no floor: it reports the windows that counted,
  however few, and fails when none did, § Benchmarks);
- `bench <name> SKIP (<why>)` for a case the boot cannot run (a thread count above the CPUs
  online, or no framebuffer), beside the lines of the cases it ran;
- `bench <name> FAIL (<why>)` when the benchmark failed: a failed call, a reply of the wrong
  size, data that did not round-trip, an unsuccessful exit of fsbench, or a result line longer
  than `LOG_LINE_BYTES` (256), the longest line logd carries whole (`LINE_BUF_SIZE`,
  [logd IPC Interface](../logd/docs/ipc-interface.md)), which the log would split.

The run ends with `ALL TESTS PASSED` when no benchmark failed and `SOME TESTS FAILED` after a
`failed=<n>` line otherwise
([docs/testing.md § Reporting marker](../../docs/testing.md#reporting-marker)), then powers the
system off. `cargo xtask bench-check` counts each FAIL line as a failure of the gate
([xtask/README.md § `cargo xtask bench-check`](../../xtask/README.md#cargo-xtask-bench-check)).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Harnesses, the sysroot layout, and the `bench` cell |
| [shared/bench/README.md](../../shared/bench/README.md) | Counters and the result line |
| [memmgr Memory Pool](../memmgr/docs/memory-pool.md) | Demand faults and the chunk |
| [xtask/README.md](../../xtask/README.md) | `bench-check` and `bench-baseline` |

---

## Summarized By

[Testing](../../docs/testing.md), [services/README.md](../README.md),
[memmgr Memory Pool](../memmgr/docs/memory-pool.md),
[shared/bench/README.md](../../shared/bench/README.md)
