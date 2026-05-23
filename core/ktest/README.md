# ktest — Seraph kernel test binary

ktest is a `no_std` binary that runs as the kernel's "init" process for the
purpose of end-to-end kernel testing. It receives the same initial capability
set that real init would, exercises every kernel syscall, and reports results
to the serial console before exiting.

On completion ktest emits the cross-harness marker
`[ktest] ALL TESTS PASSED` (or `[ktest] SOME TESTS FAILED`) per
[docs/testing.md](../../docs/testing.md). CI scrapes the substring
`ALL TESTS PASSED` from the boot log.

## Activating ktest

Edit `rootfs/esp/EFI/seraph/boot.conf` and change the `init` field:

```
init=ktest
```

Then rebuild (`cargo xtask build`) and run (`cargo xtask run`). Restore
`init=init` when finished.

## Test structure

Tests are organised across four tiers (three plus the opt-in stress
tier). Each tier lives in its own source directory; each directory
codifies a "one file per surface/scenario/race" rule at the top of its
`mod.rs`.

### Tier 1 — `src/unit/`

Per-syscall isolation tests. Every kernel syscall has at least one positive-path
test and the most important negative paths (wrong rights, invalid arguments,
wrong object state). Files are grouped by kernel subsystem, mirroring the
kernel's own source layout.

| File | Syscalls / behaviour exercised |
|---|---|
| `cap.rs` | `SYS_CAP_CREATE_*`, `CAP_COPY`, `CAP_MOVE`, `CAP_INSERT`, `CAP_DERIVE`, `CAP_DERIVE_TOKEN`, `CAP_REVOKE`, `CAP_DELETE` |
| `cap_info.rs` | `SYS_CAP_INFO` (tag, rights, type-specific fields) |
| `retype.rs` | Retype primitive: CSpace/AddressSpace augmentation, page-table walk budget, kernel PT pool consumption |
| `mm.rs` | `SYS_MEM_MAP/UNMAP/PROTECT`, `SYS_FRAME_SPLIT`, `SYS_ASPACE_QUERY` |
| `signal.rs` | `SYS_SIGNAL_SEND`, `SYS_SIGNAL_WAIT` (blocking and `signal_wait_timeout`) |
| `event.rs` | `SYS_EVENT_POST`, `SYS_EVENT_RECV` (blocking, `try_recv`, timeout) |
| `wait_set.rs` | `SYS_WAIT_SET_ADD/REMOVE/WAIT` |
| `ipc.rs` | `SYS_IPC_CALL`, `SYS_IPC_REPLY`, `SYS_IPC_RECV`, `SYS_IPC_BUFFER_SET` |
| `thread.rs` | `SYS_THREAD_START/STOP/YIELD/EXIT/CONFIGURE/SET_PRIORITY/SET_AFFINITY/READ_REGS/WRITE_REGS/SLEEP/BIND_NOTIFICATION` |
| `fpu.rs` | FPU / SIMD / V extended-state isolation across preemption and cross-CPU migration |
| `hw.rs` | `SYS_MMIO_MAP`, `SYS_MMIO_SPLIT`, `SYS_IRQ_REGISTER/ACK`, `SYS_IRQ_SPLIT`, `SYS_IOPORT_BIND`, `SYS_IOPORT_SPLIT`, `SYS_SBI_CALL` |
| `sysinfo.rs` | `SYS_SYSTEM_INFO` |

Adding a new syscall means adding a section in the appropriate file here.

### Tier 2 — `src/integration/`

Cross-subsystem scenario tests that exercise realistic multi-syscall workflows.
These catch bugs that unit tests miss — e.g. capability rights surviving an IPC
transfer, thread state after stop+write_regs+resume, wait set ordering under
concurrent signal and queue events.

| File | Scenario |
|---|---|
| `thread_lifecycle.rs` | Full thread lifecycle: create → configure → start → stop → read\_regs → write\_regs → resume → exit |
| `cap_transfer.rs` | Cap rights flow through an IPC endpoint round-trip |
| `wait_concurrency.rs` | Wait set with concurrent signal + queue sources |
| `memory_lifecycle.rs` | Frame split → map → protect → unmap with aspace\_query at each step |
| `multi_caller_ipc_fifo.rs` | Three concurrent IPC callers verify FIFO send-queue ordering |
| `cap_delegation_chain.rs` | Multi-level rights attenuation and cascaded revocation |
| `tlb_coherency.rs` | Map/unmap cycles across CPUs to exercise TLB shootdown |
| `retype_reclaim.rs` | Auto-reclaim invariant for every retypable kernel object |
| `priority_preemption.rs` | Higher-priority runnable thread preempts a CPU-bound lower-priority spinner within a wall-clock budget |
| `shared_frame_two_aspaces.rs` | One frame mapped into two `AddressSpace` caps; `aspace_query` returns identical phys backing in both |
| `cap_move_into_fresh_cspace_then_ipc.rs` | `cap_move` an endpoint into a child cspace; the child IPC-calls through its local slot; parent receives via a sibling cap |

### Tier S — `src/stress/`

Stress and torture tests that exercise race conditions, resource exhaustion, deep
capability trees, and concurrent operations. **Not run by default**; enable with
`ktest.filter=stress` (see [Command line options](#command-line-options)).

Order matches `stress/mod.rs` dispatch order.

Concurrency knobs ramp every per-test worker count to the `u64` signal-
bitmask ceiling (64 workers) and iteration counts 5-10× higher than a
trivial smoke-test would need. The point is that one full
`ktest.filter=stress` boot exercises enough contention to surface latent
races, rather than needing tens of repeat runs to flake-mine. The
`u64` width caps per-test workers at 64; lifting that would require
re-encoding the per-worker bookkeeping from a bitmask to an atomic-
counter ledger. The `MAX_STRESS_THREADS = 64` cap in `stress/mod.rs`
mirrors that ceiling (64 × 16 KiB child-stack BSS = 1 MiB).

| File | Scenario | Knobs |
|---|---|---|
| `cap_tree_deep.rs` | 8-level derivation chain with cascading revocation | `CHAIN_DEPTH=8`, `PASSES=500` |
| `event_queue_fill_drain.rs` | Fill/drain cycles on a capacity-8 queue (ring buffer wrap-around) | `CAPACITY=8`, `CYCLES=2000` |
| `idle_wake_race.rs` | Race wake of an idle CPU with concurrent ready-queue entry under affinity migration | `ITERATIONS=50_000` |
| `thread_churn.rs` | Rapid thread create/destroy cycles (TCB and CSpace cleanup) | `ITERATIONS=1000` |
| `cap_delete_running.rs` | Delete capabilities while child threads actively spin | `NUM_CHILDREN=16` |
| `concurrent_signal.rs` | Multiple threads sending distinct bits to one signal simultaneously | `NUM_SENDERS=64`, `SEND_ITERATIONS=5000` |
| `concurrent_ipc.rs` | Multiple callers racing on one endpoint (send-queue safety) | `NUM_CALLERS=64`, `CYCLES=200` |
| `cap_revoke_under_use.rs` | Revoke root while child threads actively send on derived caps | `NUM_CHILDREN=64` |
| `concurrent_map_unmap.rs` | Multiple threads mapping/unmapping distinct VAs in the same address space | `NUM_CHILDREN=16`, `MAP_ITERATIONS=1000` |
| `retype_concurrent.rs` | Multiple workers retyping concurrently against one Frame-backed allocator | `NUM_WORKERS=64`, `ITERS_PER_WORKER=1000` |
| `fpu_migration_churn.rs` | 100 cycles of FPU-owner thread migration across CPUs; validates eager save / lazy restore under churn | `CYCLES=100` |
| `concurrent_event_producers.rs` | Multiple producers post concurrently to one event queue; consumer verifies every producer's full sequence | `NUM_PRODUCERS=4`, `MESSAGES_PER_PRODUCER=64` |

### Tier 3 — `src/bench/`

Cycle-accurate benchmarks using `rdtsc` (x86-64) or `csrr cycle` (RISC-V).
Each benchmark lives in its own file under `bench/`, mirroring
`unit/`'s one-file-per-surface rule (`bench/{null,ipc,signal,cap,mm,
thread,event,wait_set,tlb}.rs`). Each benchmark logs min/mean/max
cycle counts; no PASS/FAIL verdict.

| Benchmark | What it measures |
|---|---|
| `null_syscall_roundtrip` | Kernel entry/exit baseline (`SYS_SYSTEM_INFO`) |
| `ipc_round_trip` | Synchronous IPC call + reply, per-iteration |
| `signal_roundtrip` | Signal ping-pong between two threads, per-iteration |
| `cap_create_delete` | `cap_create_signal` + `cap_delete` cycle |
| `mem_map_unmap` | `mem_map` + `mem_unmap` cycle |
| `mem_protect_pair` | `mem_protect(READONLY)` + `mem_protect(WRITABLE)` round trip |
| `thread_lifecycle` | Full thread create → start → exit → cleanup |
| `context_switch` | Parent/child `thread_yield` ping-pong on one CPU; reports cycles per switch |
| `event_post_recv` | `event_post` + `event_recv` on a pre-created queue |
| `wait_set_cycle` | Wait set create → add → wait → remove → delete |
| `tlb_shootdown_unmap` | `mem_unmap` cost when ktest's aspace is `current` on every CPU (spinners pinned per CPU); logs `cpus=N` |

## Test infrastructure

Defined in `src/main.rs`:

- `TestResult` — `Result<(), &'static str>` — no heap, no allocation.
- `run_test!(name, body)` — macro that logs the test name, runs `body`,
  records PASS or FAIL (with reason), and never panics.
- `TestContext` — thin struct carrying `aspace_cap`, `cspace_cap`, the
  IPC buffer pointer, `memory_frame_base` (first RAM Frame cap), and
  `sbi_control_cap` (zero on x86-64). Passed by reference to every
  test function. `cspace_cap` is queried via
  `cap_info(_, CAP_INFO_CSPACE_CAPACITY)` by hardware tests whose
  scans must cover slots populated after `aspace_cap` (e.g. narrow
  `IoPortRange` caps carved by `ioport::bind_port_range` on `x86_64`).
- `PASS_COUNT` / `FAIL_COUNT` — atomic counters updated by `run_test!`.
- `log(msg)` / `log_u64(prefix, value)` — heap-free logging utilities.
- `spawn::new_child(ctx)` / `configure_and_start(child, …)` /
  `configure_and_start_pinned(child, …)` — child-thread spawn helper
  wrapping the cspace + thread + configure + start sequence that ~30
  sites duplicated.

## Command line options

ktest reads the kernel command line (passed via `boot.conf` `cmdline=`) for
options prefixed with `ktest.`. All options are optional; defaults preserve the
pre-shutdown behavior (halt in place, all tiers except stress).

| Option | Values | Default | Description |
|---|---|---|---|
| `ktest.shutdown` | `always`, `pass`, `never` | `never` | When to shut down the system after tests complete |
| `ktest.timeout` | decimal seconds | `0` | Seconds to wait before shutdown (allows reading output) |
| `ktest.filter` | comma-separated tier names | `unit,integration,bench` | Which tiers to run (see below) |
| `ktest.bench_iters` | decimal integer | `1000` | Number of iterations per benchmark |

### Shutdown

`ktest.shutdown=always` shuts down regardless of test outcome.
`ktest.shutdown=pass` shuts down only if all tests passed; halts otherwise.
`ktest.shutdown=never` halts in place after printing results.

On x86-64 shutdown uses ACPI S5 (parsed from FADT/DSDT in userspace).
On RISC-V shutdown uses SBI SRST via the `SYS_SBI_CALL` syscall.

### Tier filter

`ktest.filter` accepts a comma-separated list of tier names: `unit`,
`integration`, `stress`, `bench`. When present, only the listed tiers run.
When absent, the default is `unit,integration,bench` (stress tests are excluded
by default because they are slower).


### Examples

Default (unit + integration + benchmarks, no shutdown):

```
cmdline=ktest.shutdown=always ktest.timeout=3
```

Full run including stress tests:

```
cmdline=ktest.filter=unit,integration,stress,bench ktest.shutdown=pass ktest.timeout=3
```

---

## Summarized By

[docs/testing.md](../../docs/testing.md)
