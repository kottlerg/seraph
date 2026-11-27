# shared/bench

What every Seraph benchmark shares: the counters it reads around a measured operation, the
samples it records and their summary, and the one result line it reports, with the parser that
reads the line back.

---

## Source Layout

```
bench/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs              # Crate root and re-exports
    ├── counters.rs         # Counters, Reading
    ├── stats.rs            # Samples, Summary, summarize
    ├── line.rs             # Report, Unit, Value, parse_line, Parsed, LineError, ParseError
    ├── window.rs           # WindowShape, WindowEnd, WindowTally
    └── arch/
        ├── mod.rs          # Architecture dispatch
        ├── x86_64/mod.rs   # ARCH, the rdtsc read
        └── riscv64/mod.rs  # ARCH, the cycle read
```

`no_std`, no allocation, no dependency. Host-tested (`cargo xtask test`).

The counters, the architecture's name (`ARCH`) and `Report::write`, which writes that name,
exist only on the architectures Seraph runs on and come with the default `counters` feature. A
reader of result lines builds without it, on any host: xtask's `bench-check` and `bench-baseline`
([xtask/README.md](../../xtask/README.md#cargo-xtask-bench-check)) take the crate with
`default-features = false`.

---

## Counters

A thread opens its own `Counters` with `Counters::open()` after it is pinned to the CPU it
measures on, and reads them only there: each counter is a per-CPU register, and riscv64 keeps no
two harts' `cycle` counters in step. The handle is neither `Send` nor `Sync`. `read()`
returns a `Reading` of every column a result line can report: `cycles`, `instret`, and four
programmable `events`. The cycle counter is the only one read; the others read `None`.
`Reading::since` subtracts an earlier reading, column by column.

| Architecture | Cycle counter | User-mode access |
|---|---|---|
| x86-64 | `rdtsc`: reference cycles at a constant rate on a CPU with an invariant TSC | The kernel clears `CR4.TSD` on every CPU |
| riscv64 | `csrr cycle`: the hart's cycles | The kernel sets `scounteren.CY` on every hart |

A read bounds the region between two reads as
[docs/testing.md § Benchmarks](../../docs/testing.md#benchmarks-bench-cell) states. Its inline
assembly declares that it may read and write memory, so the compiler keeps each load and store on
the side of the read where the program puts it. On x86-64 the read is `mfence; lfence; rdtsc;
lfence`, so that the CPU orders it too. On riscv64 the hart orders `csrr cycle` only with itself.

---

## Samples and summary

A benchmark records one sample per measured operation into a buffer it owns, through
`Samples::new(&mut buf)`: ktest hands it a static array, a program a `Vec`. `record` refuses a
sample past the buffer's length rather than wrap over an earlier one, so a benchmark runs at most
`capacity()` iterations.

`Samples::summary()`, or `summarize` over a slice, sorts the samples in place and returns their
`Summary`: the count, the minimum, the maximum, and the 50th, 90th and 99th percentiles by
nearest rank. The p-th percentile of n sorted samples is the sample of rank ceil(p × n / 100),
ranks counted from 1, so every reported value is a sample that was taken. No sample gives no
summary.

---

## Result line

Every benchmark reports each measurement as one line:

```text
bench <suite>.<name> [<variant>=<word> ...] arch=<arch> cpus=<k> unit=<cycles|insns>
    n=<n> min=<v> p50=<v> p90=<v> p99=<v> max=<v> [<extra>=<u64> ...]
```

The line is a single line of space-separated tokens, wrapped above for width only.

| Part | Meaning |
|---|---|
| `<suite>` | The program that ran the benchmark: `ktest`, `fsbench`, `ubench` |
| `<name>` | The benchmark within the suite |
| Variant parameters | The case of the benchmark that ran (`pages=32`, `op=unmap`); before `arch=` |
| `arch=` | The architecture the reporting program is built for: `x86_64` or `riscv64` |
| `cpus=` | CPUs the system runs |
| `unit=` | The counter the samples were read from: `cycles` or `insns` (instructions retired) |
| `n=` to `max=` | The summary of the samples |
| Extras | Further measurements of the run (`tlb_elided=`, `workers=`, `idle_halts=` of § Idle halts); after `max=` |

The suite, the name and the variant parameters identify a measurement: a comparison of two runs
pairs their lines by them, and compares the columns from `arch=` on. The extras are measured
with the samples, never part of the identity.

A suite, a name and a parameter key are `[a-z][a-z0-9_]*`, and a variant value is
`[a-z0-9_]+`; every other value is a decimal `u64`. No parameter takes the key of a fixed column
(`arch`, `cpus`, `unit`, `n`, `min`, `p50`, `p90`, `p99`, `max`), and no two parameters of a
line share a key. A line's summary covers at least one sample and holds
`min <= p50 <= p90 <= p99 <= max`.

`Report::write` checks a report against these rules before it writes anything. `parse_line`
reads a line with any prefix before the `bench` token (a log timestamp, a process tag): a line
whose `bench` token, standing as a word, is followed by a token with a `.` carries a result
line, which parses or returns the first rule it breaks; any other line returns `Ok(None)`, so a
whole log can be scanned. A program logs no other text of the form `bench <word>.<word>`.

---

## Window rows

A benchmark that cannot time one operation per sample, because a thread of the measured path may
run on another CPU between two counter reads, times windows of several operations instead and
reports a window row: a result line of the form above, each of whose samples is one window's
whole count, the difference of two counter reads taken on one CPU, so `n=` counts windows. The
row carries the extra `window_ops=` (`WINDOW_OPS_KEY`), the operations each window holds, so a
sample's cost per operation is the sample divided by `window_ops=`, and names itself by a
variant parameter, so it never pairs with a per-operation row of the same case.
`WindowShape::for_ops` splits a benchmark's operations into windows of `WINDOW_OPS` (16), or
one window of all of them when there are fewer. Whether a row gates follows the rule of its CPU
count and benchmark, as for any row
([docs/testing.md § Benchmarks](../../docs/testing.md#benchmarks-bench-cell)).

A difference of two reads on one CPU measures the window, wherever the measured threads ran in
between, only when both reads ran on that CPU and the CPU did not halt between them
([docs/testing.md § Benchmarks](../../docs/testing.md#benchmarks-bench-cell)). A row whose reads are
taken by a thread pinned to the measuring CPU, which does not itself run the measured path, meets
the first condition by its pin. A row whose reads are taken by the measured thread, with no affinity
between them, cannot, and meets it as fsbench's rows do: pinned to the measuring CPU, the thread
opens its idle-halt span (§ Idle halts) and takes the opening read, then clears its affinity, which
moves nothing, so the window holds that syscall too; after the window's operations it takes the
closing read and closes the span at once, with no blocking call between, and `WindowEnd::from_close`
classifies the window by the close. A close that fails ran on another CPU than the open (`Moved`),
one that returns halts saw the CPU halt (`Halted`), and one that returns `0` counts the window
(`Counted`). Such a row carries the counts of the windows it left out, `moved=` (`MOVED`) and
`halted=` (`HALTED`), and a row whose counted windows are fewer than half its windows
(`WindowShape::floor`) does not measure its case, only the windows that happened to stay on the CPU,
so the benchmark logs no result line for it. fsbench's `affinity=any` rows are such rows
([services/fixtures/fsbench/README.md](../../services/fixtures/fsbench/README.md)).

---

## Idle halts

Under QEMU's icount (`cargo xtask run --icount`) a timed window that idles counts host time: while
every vCPU idles, the guest's clock follows the host's
([docs/testing.md § Benchmarks](../../docs/testing.md#benchmarks-bench-cell)). Every harness
therefore calls `SYS_SYSTEM_INFO(IdleHalts)` (`syscall::idle_halts`, which answers for the
calling CPU alone) right before a measured loop, which marks that CPU's idle-halt count in the
calling thread, and right after it, which returns the halts since the mark, both outside every
timed window, with the thread pinned to that CPU across both calls (a window row's thread,
unpinned between them, is held to the CPU by the close, § Window rows) and making no other
such call between them. The line reports that count as the extra `idle_halts=` (`IDLE_HALTS`):
the times the CPU found no thread to run while the loop ran. The kernel counts only from the mark:
a call that has none on its CPU (the thread's first, or one after a move) returns an error, and
the line then carries no count.

The span holds every timed window of the line and the untimed work of the loop between them (a
warm-up iteration, a check, a step that readies the next sample). A count of zero says that no
window idled; a count above zero says that a window, or the untimed work beside it, waited with
the CPU idle. `cargo xtask bench-check` fails a gating measurement whose line reports a halt, or
no count
([xtask/README.md § `cargo xtask bench-check`](../../xtask/README.md#cargo-xtask-bench-check)),
and reports the count of every other: a benchmark that idles by design (`ICOUNT_IO_BOUND`), a
measurement at more than one CPU, where only the measuring CPU's halts are counted, and host mode,
where a count says that the loop waited on an event.

| Harness | Span | CPU |
|---|---|---|
| [ktest](../../core/ktest/README.md) Tier 3 | `Harness::recorder`, taken right before the loop, to its `Recorder::summary`, right after | CPU 0 |
| [ubench](../../services/ubench/README.md) | `IdleSpan::open` and `close` around each loop, its warm-up iterations included; in `fault_scaling`, each worker around its own loop, the line summing them | `BENCH_CPU` (0); each worker's CPU |
| [fsbench](../../services/fixtures/fsbench/README.md) | Around each timed loop, after its warm-up; in a window row, around each window, the line summing the spans that closed (§ Window rows) | CPU 0 |

A line whose samples other threads took on their own CPUs (`ktest.tlb_shootdown_concurrent`)
carries no count.

---

## Consumers

| Consumer | Suite | What it reports |
|---|---|---|
| [`core/ktest`](../../core/ktest/README.md) | `ktest` | Tier 3, one line per kernel benchmark (§ Tier 3) |
| [`services/fixtures/fsbench`](../../services/fixtures/fsbench/README.md) | `fsbench` | `fsbench.read`, per read size and path; `fsbench.write`, per write size; `fsbench.open`, at `depth=3`; at more than one CPU, the window rows `fsbench.read size=16 path=inline affinity=any` and `fsbench.open depth=3 affinity=any` |
| [`services/ubench`](../../services/ubench/README.md) | `ubench` | `ubench.ipc_rt`, `ubench.fault_fill`, `ubench.fault_scaling`, `ubench.shmem_ring`, `ubench.console_write`, per variant, and `ubench.empty_window` |

---

## Summarized By

[core/ktest/README.md](../../core/ktest/README.md),
[services/fixtures/fsbench/README.md](../../services/fixtures/fsbench/README.md),
[services/ubench/README.md](../../services/ubench/README.md)
