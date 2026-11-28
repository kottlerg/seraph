# Performance

How Seraph's performance is measured, what its measured paths are modelled to cost, the budgets
those paths are held to, and the benchmark line each performance claim rests on.

---

## Method

Every benchmark reports each measurement as one result line, its samples' summary, identified by
its suite, its name, its variant parameters and its CPU count
([shared/bench/README.md § Result line](../shared/bench/README.md#result-line)). A comparison
takes a measurement's p50, and over several runs the lowest of their p50s. The benchmarks are
ktest's Tier 3 ([core/ktest/README.md](../core/ktest/README.md) § Tier 3), which measures kernel
paths from ktest's own threads, and [ubench](../services/ubench/README.md), which measures
userspace paths and runs [fsbench](../services/fixtures/fsbench/README.md).

A line is read in one of two modes, both on the release build
([core/kernel/docs/hot-path-account.md](../core/kernel/docs/hot-path-account.md) § Profile), as
[testing.md § Benchmarks](testing.md#benchmarks-bench-cell) specifies:

| Mode | Counts | Where | Gates | Does not see |
|---|---|---|---|---|
| icount | Instructions retired, at one CPU exactly when the window does not idle | CI's `bench` cell, both architectures, at 1 and 4 CPUs | The one-CPU rows | Caches, TLBs, contention, IPI latency, device time, x2APIC paths |
| host | Reference cycles on the reference host, x86_64 under KVM | The reference host, at 4 CPUs, under the exclusive grant | Nothing: the report is read | Nothing it runs; riscv64, which has no host mode |

A question about instructions on a path is answered in icount mode, where one PR's change moves
the count by exactly what it added or removed. A question about time, and about any cost
icount does not see, is answered in host mode. A row at more than one CPU is answered in host
mode only: under icount its count includes the other CPUs' instructions. Where the
instructions of an icount row go, function by function, is the hot-path accounts'
([core/kernel/docs/hot-path-account.md](../core/kernel/docs/hot-path-account.md),
[core/kernel/docs/hot-path-account-userspace.md](../core/kernel/docs/hot-path-account-userspace.md)).
A kernel built with `sched-stages` adds the cost of its stamps to every switch, so no budget,
baseline or claim of a plain kernel's cost is taken from its lines
([core/kernel/docs/scheduler.md](../core/kernel/docs/scheduler.md#stage-breakdown) § Stage
Breakdown).

Measured numbers live in the baseline files (`xtask/baselines/bench/<mode>/<arch>/`) and in the
hot-path accounts, each of which names the head it was taken at; this document holds none.

---

## Cost Model

A primitive is a row that measures one mechanism; a composite row is modelled as a sum of
primitives measured in the same run, plus a remainder the model names. Each sample includes the
counter reads' own cost, which the suite's `empty_window` row measures
([testing.md § Benchmarks](testing.md#benchmarks-bench-cell)).

| Primitive | Row (`ktest.`) | Measures |
|---|---|---|
| Kernel entry and exit | `null_syscall_roundtrip` | One syscall that does no work |
| Switch pair | `context_switch_pair` | Two `thread_yield` calls and the two switches between them |
| Capability lookup | `cap_info_lookup` | One syscall that resolves and pins a handle |
| Map and unmap | `mem_map_unmap` | One `mem_map` and one `mem_unmap` |
| Counter offset | `empty_window` | Two counter reads with nothing between them |

| Composite | Model |
|---|---|
| `ipc_round_trip words=0` | Three kernel entries (the call; the server's reply and its next receive) and two switches, so about `context_switch_pair` + `null_syscall_roundtrip`; the remainder is the IPC path's own work: the endpoint's lookup and rendezvous and the reply |
| `ipc_round_trip words=k` | `words=0` + the copy of k data words each way: in the message registers up to 6, through the IPC buffer page from 7 |
| `ipc_round_trip words=0 server=reply_recv` | `words=0` less one kernel entry and exit, the server replying and receiving in one call |
| `fault_round_trip placement=same leg=total` | `leg=delivery` (the trap and the fault's delivery to the handler) + `leg=handler` (the handler's map) + `leg=resume` (the reply that resumes the faulting thread), each leg holding its own counter reads |
| `ubench.ipc_rt words=k` | `ktest.ipc_round_trip words=k` + what the userspace call path ([shared/ipc](../shared/ipc/README.md)) adds over ktest's syscall stubs |
| `ubench.fault_scaling threads=k` | `threads=1` + what k concurrent faulters cost each other in memmgr and the kernel |
| `ubench.pipeline work=w` | 64 items' transfer through the pipe's ring and its doorbells, and `w` iterations of work per item on each side; throughput is `window_ops=` over the sample |
| `ktest.tlb_reach pages=N` | 256 dependent loads; under host mode the growth over `pages=16` is the translations the TLBs no longer hold |

Each difference below isolates one mechanism, both rows running the same path otherwise:

| Difference | Isolates |
|---|---|
| `ipc_round_trip words=0 aspace=cross` − `aspace=same` | Two address-space switches |
| `ipc_round_trip words=0 placement=same` − `iopb=none` (x86_64) | The I/O permission bitmap on a round trip |
| `context_switch_pair iopb=bound` − `iopb=none` (x86_64) | A bound thread's I/O permission bitmap on a switch pair |
| `ipc_round_trip words=0 fpu=both` − `words=0` | Floating-point and vector state on a round trip |
| `ipc_round_trip words=0 placement=apart` − `placement=same` | A recipient on another CPU: the cross-CPU wake and its return |
| `notification_cross_cpu` − `notification_roundtrip` | A wake of a thread parked on an idle CPU |
| `ubench.fault_fill path=fault` − `path=grant` | A demand fault against an explicit grant of the same chunk |
| Any row − its suite's `empty_window` | The region alone; exact under icount only for a window on one CPU that does not idle and that no interrupt or other thread enters |

The `sched-stages` extras of `context_switch_pair` split a switch into its stages, under the
caveat of § Method.

---

## Budgets

A budget is a relation between rows of one run in one mode, so it holds on any host and in either
mode; a budget with a value states it as a ratio to `ktest.null_syscall_roundtrip` in the same run.
Host mode reads a relation through the bands (`xtask/baselines/bench/host/x86_64/BANDS`): two rows
whose p50s differ by less than the larger of their bands are equal within noise, so a `≤` between
them holds there, and a `<` between them is judged in icount mode alone. Icount mode judges a
relation on its rows' one-CPU lines (§ Method), which every `<` below has; a relation between
rows that exist only at 4 CPUs is judged in host mode. Each relation below holds in the host-mode
baselines read that way and in the icount baselines of both architectures, unless the table limits
it. A change that breaks one MUST say so in its PR body, with the Issue that the relation serves;
the review of a performance PR checks the relations against its host-mode report and its CI run's
icount report.

| Budget | Serves |
|---|---|
| `ipc_round_trip`: `words=0` < `words=1` ≤ `words=6` < `words=7` < `words=16` < `words=64` | #40: a message costs more with its size, and the register-carried sizes less than the buffer-carried |
| `ipc_round_trip words=0 placement=unpinned` ≤ `placement=apart` | #762: the kernel's placement of an unpinned recipient costs no more than a recipient pinned to another CPU |
| `ipc_round_trip words=0 server=reply_recv` < `words=0` | `SYS_IPC_REPLY_RECV` saves a kernel entry |
| `ipc_round_trip words=0 aspace=same` < `aspace=cross` | The address-space switch costs something, and only the switch differs |
| `ipc_round_trip words=0 iopb=none` ≤ `placement=same`, and `context_switch_pair iopb=none` ≤ `iopb=bound` (x86_64) | #1512: a thread with no port binding pays no bitmap |
| `ipc_round_trip words=0` ≤ `fpu=both` | #1508: extended state is paid by the threads that use it |
| `ktest.ipc_round_trip words=k` ≤ `ubench.ipc_rt words=k` | The userspace call path adds to the kernel's, never replaces it |

---

## Making a Claim

A performance claim names its rows, each by its full identity (suite, name, variant, CPU
count), its mode, and the head it was measured at. A claim about time is a host-mode report,
owed and accounted for as [testing.md § Benchmarks](testing.md#benchmarks-bench-cell) states for
a PR that states a performance purpose. A claim about a mechanism is made on the difference that
isolates it (§ Cost Model), measured in one run, rather than on a single row. A claim with a
target states the target as a budget (§ Budgets).

---

## Consumers

The Issues that state a performance claim, and the lines each states it on:

| Issue | Claim | Rows | Mode |
|---|---|---|---|
| #40 | The IPC register fast path for small messages | `ktest.ipc_round_trip words=0|1|6|7|16|64`, `ubench.ipc_rt` | icount and host |
| #762 | A synchronous IPC recipient runs on the caller's CPU | `ktest.ipc_round_trip words=0 placement=same|apart|unpinned|fan_in`, with `server=reply_recv` | host, pinned threads reported apart |
| #227 | The fault-IPC round trip | `ktest.fault_round_trip`, each `leg=`; `ubench.fault_fill path=fault` | icount and host |
| #236 | An adaptive demand fault window | `ubench.fault_fill path=fault`'s `faults=` and `backed_pages=` against the pages touched | icount |
| #266 | The SMP pager | `ubench.fault_scaling threads=1|2|4|8`, each thread pinned and set up on its own CPU | host, past 4 vCPUs under the grant |
| #44 | Transparent large pages | `ktest.tlb_reach pages=`, cycles per access | host |
| #321, #1483 | Throughput of the ring and render paths | `ubench.shmem_ring`, `ubench.console_write` | icount and host |
| #87 | The file write path's inline-versus-frame crossover | `fsbench.write`, `fsbench.read` per `path=` | host for `fsbench.write`, which icount reports only |
| #32, #824, #1514 | Wakes across CPUs | `ktest.notification_cross_cpu`, `ktest.ipc_round_trip words=0 placement=apart` | host, at 4 CPUs with the target CPU idle |
| #1508 | Extended state restored on switch-in | `ktest.ipc_round_trip words=0 fpu=both` against `words=0` | icount and host |
| #1512 | No I/O bitmap for a thread without port bindings | `ktest.context_switch_pair iopb=none|bound`, `ktest.ipc_round_trip words=0 iopb=none` | icount and host |
| #1531 | The instructions of the syscall, IPC and switch paths | Every gated icount row, through the hot-path accounts | icount, with the host-mode figure beside each cut |
| #265 | Hardware event counters | The `instret` and event columns of `Counters` and `EventCounters` ([shared/bench/README.md § Event counters](../shared/bench/README.md#event-counters)); no benchmark line carries them yet | host |

---

## Summarized By

None
