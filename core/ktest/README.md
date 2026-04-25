# ktest — Seraph kernel test binary

ktest is a `no_std` binary that runs as the kernel's "init" process for the
purpose of end-to-end kernel testing. It receives the same initial capability
set that real init would, exercises every kernel syscall, and reports results
to the serial console before exiting.

## Activating ktest

Edit `rootfs/EFI/seraph/boot.conf` and change the `init` field:

```
init=ktest
```

Then rebuild (`cargo xtask build`) and run (`cargo xtask run`). Restore
`init=init` when finished.

## Test structure

Tests are organised across three tiers. Each tier lives in its own source
directory.

### Tier 1 — `src/unit/`

Per-syscall isolation tests. Every kernel syscall has at least one positive-path
test and the most important negative paths (wrong rights, invalid arguments,
wrong object state). Files are grouped by kernel subsystem, mirroring the
kernel's own source layout.

| File | Syscalls |
|---|---|
| `cap.rs` | `SYS_CAP_CREATE_*`, `CAP_COPY`, `CAP_MOVE`, `CAP_INSERT`, `CAP_DERIVE`, `CAP_REVOKE`, `CAP_DELETE` |
| `mm.rs` | `SYS_MEM_MAP/UNMAP/PROTECT`, `SYS_FRAME_SPLIT`, `SYS_ASPACE_QUERY` |
| `signal.rs` | `SYS_SIGNAL_SEND`, `SYS_SIGNAL_WAIT` |
| `event.rs` | `SYS_EVENT_POST`, `SYS_EVENT_RECV` |
| `wait_set.rs` | `SYS_WAIT_SET_ADD/REMOVE/WAIT` |
| `ipc.rs` | `SYS_IPC_CALL`, `SYS_IPC_REPLY`, `SYS_IPC_RECV`, `SYS_IPC_BUFFER_SET` |
| `thread.rs` | `SYS_THREAD_START/STOP/YIELD/EXIT/CONFIGURE/SET_PRIORITY/SET_AFFINITY/READ_REGS/WRITE_REGS` |
| `hw.rs` | `SYS_MMIO_MAP`, `SYS_DMA_GRANT`, `SYS_IRQ_REGISTER/ACK`, `SYS_IOPORT_BIND` |
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

### Tier S — `src/stress/`

Stress and torture tests that exercise race conditions, resource exhaustion, deep
capability trees, and concurrent operations. **Not run by default**; enable with
`ktest.filter=stress` (see [Command line options](#command-line-options)).

| File | Scenario |
|---|---|
| `cap_tree_deep.rs` | 8-level derivation chain with cascading revocation |
| `event_queue_fill_drain.rs` | Fill/drain cycles on a capacity-8 queue (ring buffer wrap-around) |
| `thread_churn.rs` | 20 rapid thread create/destroy cycles (TCB and CSpace cleanup) |
| `concurrent_signal.rs` | 4 threads sending distinct bits to one signal simultaneously |
| `concurrent_ipc.rs` | 4 callers racing on one endpoint, 10 cycles (send-queue safety) |
| `cap_revoke_under_use.rs` | Revoke root while 4 threads actively send on derived caps |
| `concurrent_map_unmap.rs` | 4 threads mapping/unmapping distinct VAs in the same address space |

### Tier 3 — `src/bench/`

Cycle-accurate benchmarks using `rdtsc` (x86-64) or `csrr cycle` (RISC-V).
Each benchmark logs min/mean/max cycle counts; no PASS/FAIL verdict.

| Benchmark | What it measures |
|---|---|
| `null_syscall_roundtrip` | Kernel entry/exit baseline (`SYS_SYSTEM_INFO`) |
| `ipc_round_trip` | Synchronous IPC call + reply |
| `signal_roundtrip` | Signal ping-pong between two threads |
| `cap_create_delete` | `cap_create_signal` + `cap_delete` cycle |
| `mem_map_unmap` | `mem_map` + `mem_unmap` cycle |
| `thread_lifecycle` | Full thread create → start → exit → cleanup |
| `event_post_recv` | `event_post` + `event_recv` on a pre-created queue |
| `wait_set_cycle` | Wait set create → add → wait → remove → delete |

## Test infrastructure

Defined in `src/main.rs`:

- `TestResult` — `Result<(), &'static str>` — no heap, no allocation.
- `run_test!(name, body)` — macro that logs the test name, runs `body`,
  records PASS or FAIL (with reason), and never panics.
- `TestContext` — thin struct carrying `aspace_cap` and the IPC buffer pointer,
  passed by reference to every test function.
- `PASS_COUNT` / `FAIL_COUNT` — atomic counters updated by `run_test!`.
- `log(msg)` / `log_u64(prefix, value)` — heap-free logging utilities.

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

None
