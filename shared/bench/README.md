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
    ├── rate.rs             # CycleRate: the window rate check
    ├── line.rs             # Report, Unit, Value, parse_line, Parsed, LineError, ParseError
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

A window line's sample is one window of several operations: the cycles between two reads that
bracket all of them, the extra `window_ops=` naming the operations a window holds, so that `n=`
counts windows and one operation's mean cost is a sample over `window_ops=`. Its reads are taken
by a thread pinned to the CPU whose counter they read, which need not be a thread that runs the
operations (`ubench.pipeline`). The sample is the whole window's count, never the mean, so that
under icount it is the window's instructions, as every gated sample is
([xtask/README.md § `cargo xtask path-account`](../../xtask/README.md#cargo-xtask-path-account)).

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

## Idle halts

Under QEMU's icount (`cargo xtask run --icount`) a timed window that idles counts host time: while
every vCPU idles, the guest's clock follows the host's
([docs/testing.md § Benchmarks](../../docs/testing.md#benchmarks-bench-cell)). Every harness
therefore calls `SYS_SYSTEM_INFO(IdleHalts)` (`syscall::idle_halts`, which answers for the
calling CPU alone) right before a measured loop, which marks that CPU's idle-halt count in the
calling thread, and right after it, which returns the halts since the mark, both outside every
timed window, with the thread pinned to that CPU across both calls and making no other such call
between them. The line reports that count as the extra `idle_halts=` (`IDLE_HALTS`): the times
the CPU found no thread to run while the loop ran. The kernel counts only from the mark: a call
that has none on its CPU (the thread's first, or one after a move) returns an error, and the line
then carries no count.

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
| [fsbench](../../services/fixtures/fsbench/README.md) | Around each timed loop, after its warm-up | CPU 0 |

A line whose samples other threads took on their own CPUs (`ktest.tlb_shootdown_concurrent`)
carries no count.

---

## Window rate check

A window whose reading thread blocks while other threads do its work elsewhere
(`ubench.pipeline`) leaves the reading CPU with nothing to run, and the CPU halts in it. The
window then counts its elapsed time only if the counter runs through a halt:

| Counter | Through a halt |
|---|---|
| x86-64 `rdtsc`, a CPU with an invariant TSC | Runs at its constant rate in every C-state |
| x86-64 `rdtsc` under KVM | The host's TSC: runs |
| riscv64 `cycle` on hardware | Left to the implementation: a hart may stop it while it waits in `wfi` |
| riscv64 `cycle` under QEMU's TCG | Runs: the host's tick counter (from QEMU's source) |
| Either under icount | Runs: the shared icount clock, which follows the host's time while every vCPU idles ([docs/testing.md § Benchmarks](../../docs/testing.md#benchmarks-bench-cell)) |

riscv64's `time` runs through a halt, but U-mode does not read it: the kernel grants `cycle`
alone, as
[core/kernel/docs/cross-boundary-disclosure.md](../../core/kernel/docs/cross-boundary-disclosure.md)
records.
Such a benchmark therefore reads, around each window, a clock that runs through a halt, the
kernel's elapsed microseconds (`SYS_SYSTEM_INFO(ElapsedUs)`, from `rdtsc` on x86-64 and `time`
on riscv64), and measures the counter's rate against it over a span in which its CPU is kept
busy. `CycleRate::counted` takes a window whose cycles reach its elapsed microseconds at that
rate, less `RATE_SLACK_MICROS` (3) for the clock's truncation to whole microseconds and its
reads, within `RATE_TOLERANCE_PERCENT` (5); a window that falls short is left out of the samples,
so a counter that stops in a halt shows as windows left out, never as a sample short of its time.
The clock's reads bracket the counter's, so a window also falls short when its thread is delayed
between a clock read and the counter read beside it by more than the slack: under QEMU without
icount, where the host may stall a vCPU at any instruction, a short window is left out now and
then with its counter running (`ubench.pipeline` at `work=0` on riscv64). A left-out window
therefore says that its sample could not be shown whole, not that the counter stopped; a window
that counted its time is never left out. On x86-64 the elapsed clock is the TSC itself, so only
such a delay leaves a window out, and the check rests on the invariant TSC § Counters requires.

---

## Consumers

| Consumer | Suite | What it reports |
|---|---|---|
| [`core/ktest`](../../core/ktest/README.md) | `ktest` | Tier 3, one line per kernel benchmark (§ Tier 3) |
| [`services/fixtures/fsbench`](../../services/fixtures/fsbench/README.md) | `fsbench` | `fsbench.read`, per read size and path; `fsbench.write`, per write size; `fsbench.open`, at `depth=3` |
| [`services/ubench`](../../services/ubench/README.md) | `ubench` | `ubench.ipc_rt`, `ubench.fault_fill`, `ubench.fault_scaling`, `ubench.shmem_ring`, `ubench.pipeline`, `ubench.console_write`, per variant, and `ubench.empty_window` |

---

## Summarized By

[core/ktest/README.md](../../core/ktest/README.md),
[services/fixtures/fsbench/README.md](../../services/fixtures/fsbench/README.md),
[services/ubench/README.md](../../services/ubench/README.md)
