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
| Extras | Further measurements of the run (`tlb_elided=`, `workers=`); after `max=` |

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

## Consumers

| Consumer | Suite | What it reports |
|---|---|---|
| [`core/ktest`](../../core/ktest/README.md) | `ktest` | Tier 3, one line per kernel benchmark (§ Tier 3) |
| [`programs/fsbench`](../../programs/fsbench/README.md) | `fsbench` | `fsbench.read`, per read size and path; `fsbench.write`, per write size; `fsbench.open`, at `depth=3` |
| [`programs/ubench`](../../programs/ubench/README.md) | `ubench` | `ubench.ipc_rt`, `ubench.fault_fill`, `ubench.fault_scaling`, `ubench.shmem_ring` and `ubench.console_write`, per variant |

---

## Summarized By

[core/ktest/README.md](../../core/ktest/README.md),
[programs/fsbench/README.md](../../programs/fsbench/README.md),
[programs/ubench/README.md](../../programs/ubench/README.md)
