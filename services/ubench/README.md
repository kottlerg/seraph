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
that it adds no output of its own to the framebuffer `console_write` measures; logd's mirror of
the log lines still draws through the same driver:

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
    ├── console.rs         # console_write: FB_WRITE_BYTES to the framebuffer driver
    └── fsbench.rs         # fsbench: /tests/fixtures/programs/fsbench at its full counts
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
| `fault_fill` | `path=fault\|grant pages=16` | The cost of one 16-page chunk, `DEMAND_CHUNK_PAGES`, the run memmgr backs on a demand fault when a free run covers it ([memmgr Memory Pool § Demand faults](../memmgr/docs/memory-pool.md#demand-faults)). `fault`: the first store into a chunk of a region `register_demand_paged` registered, which is the fault's delivery to memmgr, memmgr's backing of the chunk (run selection, zeroing, the map) and the resume; the registration funds the region's page tables, so no sample funds any. `grant`: `REQUEST_MEMORY_CAPS` for the chunk's pages with `REQUIRE_CONTIGUOUS`, the cap's map into a reservation with `mem_map_funded`, which funds page tables when the map is refused for want of them, and the first store into it | 64 per path, after 4 |
| `fault_scaling` | `threads=1\|2\|4\|8 pages=16` | The `fault` sample of `fault_fill`, taken by k threads at once: thread i is pinned to CPU i, opens its own counters there and registers its own region, and all start their timed stores together. The line of k holds every thread's samples. A count above the CPUs online logs a SKIP line | 64 per thread, after 4 |
| `shmem_ring` | `bytes=64\|512\|4096\|65536` | `bytes` moved through a byte ring of the stdio pipe's capacity, 2048 bytes ([shared/shmem](../../shared/shmem/README.md), `runtime/ruststd/src/sys/pipe/seraph.rs`): `SpscWriter::write` of what fits, `SpscReader::read` of it, until every byte passed, as a pipe's writer and reader take turns. One thread does both, so a sample is the copies and the index updates, with no notification or IPC | 256 per size, after 16 |
| `console_write` | `bytes=64\|4096` | `bytes` of text, lines of 63 letters and a newline, sent to the framebuffer driver as `FB_WRITE_BYTES` calls of at most 512 bytes each, as the terminal sends its child's output (`programs/terminal/src/output.rs`). The warm-up fills the screen, so every timed write of 4096 bytes scrolls it | 64 per size, after 16 |
| `fsbench` | — | [`/tests/fixtures/programs/fsbench`](../fixtures/fsbench/README.md) spawned with no iteration count, its full benchmark, which logs its own `fsbench.read`, `fsbench.write` and `fsbench.open` lines | as fsbench's |

The `fault` line of `fault_fill` carries two extras, read outside the timed window from ubench's
own charge, `QUERY_MEMORY_USAGE` before and after each store: `faults=`, the timed stores memmgr
backed pages for, and `backed_pages=`, the pages it backed for them. A store whose page an earlier
fault already backed adds to neither, so a fault that backs more than its own chunk shows as
`faults=` below `n=`.

---

## Output

Lines are logged under the name `ubench`. The run opens with `starting`, and each benchmark then
logs one of:

- its result lines, in the form
  [shared/bench/README.md § Result line](../../shared/bench/README.md#result-line) specifies, with
  suite `ubench` (fsbench's under its own name and suite):

  ```text
  bench ubench.<name> <variant> arch=<arch> cpus=<k> unit=cycles n=<n> min=<v> p50=<v>
      p90=<v> p99=<v> max=<v> [faults=<n> backed_pages=<n>] idle_halts=<n>
  ```

  wrapped above for width only, `idle_halts=` being the halts of the measuring CPU over the
  measured loop ([shared/bench/README.md § Idle halts](../../shared/bench/README.md#idle-halts));
- `bench <name> SKIP (<why>)` for a case the boot cannot run (a thread count above the CPUs
  online, or no framebuffer), beside the lines of the cases it ran;
- `bench <name> FAIL (<why>)` when the benchmark failed: a failed call, a reply of the wrong
  size, data that did not round-trip, or an unsuccessful exit of fsbench.

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
