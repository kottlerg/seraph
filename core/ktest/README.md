# ktest — Seraph kernel test binary

ktest is a `no_std` binary that runs as the kernel's "init" process for the
purpose of end-to-end kernel testing. It receives the same initial capability
set that real init would, exercises every kernel syscall, and reports results
to the serial console before exiting.

On completion ktest emits the cross-harness marker
`[ktest] ALL TESTS PASSED` (or `[ktest] SOME TESTS FAILED`) per
[docs/testing.md](../../docs/testing.md). CI scrapes the substring
`ALL TESTS PASSED` from the boot log.

---

## Source Layout

```
core/ktest/
├── Cargo.toml
└── src/
    ├── main.rs                 # Entry point, TestContext, run_test!, tier dispatch, shutdown
    ├── cmdline.rs              # KtestConfig::DEFAULT compile-time configuration
    ├── spawn.rs                # Child-thread spawn helper, ArgBlock, exit/baseline polling
    ├── frame_pool.rs           # Pool of single-page Memory caps handed out to tests
    ├── framebuffer.rs          # Direct framebuffer output
    ├── serial.rs               # Direct serial output
    ├── ioport.rs               # Per-thread I/O port access (x86-64)
    ├── acpi_shutdown.rs        # ACPI S5 shutdown (x86-64)
    ├── sbi_shutdown.rs         # SBI SRST shutdown (RISC-V)
    ├── unit/                   # Tier 1: per-syscall isolation tests
    ├── integration/            # Tier 2: cross-subsystem scenario tests
    ├── stress/                 # Tier S: stress and race tests
    └── bench/                  # Tier 3: cycle-count benchmarks
```

## Activating ktest

Re-compose the bootloader bundle with ktest as the `init` entry:

```
cargo xtask compose-bundle --harness ktest
cargo xtask run
```

Restore the default-init harness with `cargo xtask compose-bundle
--harness init` (or any subsequent full `cargo xtask build`, which
re-authors the default-init bundle; a `--component` build leaves the
bundle unchanged). See
[`xtask/README.md`](../../xtask/README.md) for the bundle-vs-mkdisk
authoring discipline.

## Test structure

Tests are organised across four tiers (unit, integration, stress, and
bench), all of which run on every ktest boot under `KtestConfig::DEFAULT`.
Each tier lives in its own source directory; each directory
codifies a "one file per surface/scenario/race" rule at the top of its
`mod.rs`.

### Tier 1 — `src/unit/`

Per-syscall isolation tests. Every kernel syscall except `SYS_ASPACE_BIND_NOTIFICATION`,
`SYS_PROCESS_EXIT`, and `SYS_THREAD_SET_FAULT_HANDLER` has at least one positive-path
test and the most important negative paths (wrong rights, invalid arguments,
wrong object state). Those three are exercised in Tier 2, by
`aspace_fault_notification_late_bind.rs`, by `death_notification_late_bind.rs`, and by
`fault_pager_roundtrip.rs`, `fault_resume_modifies_pc.rs`, `fault_handler_declines_kills.rs`,
and `fault_exception_redirect.rs` respectively. Files are grouped by kernel subsystem,
mirroring the kernel's own source layout.

| File | Syscalls / behaviour exercised |
|---|---|
| `cap.rs` | `SYS_CAP_CREATE_*`, `SYS_CAP_COPY` (incl. the `cap_insert` explicit-slot form), `SYS_CAP_MOVE`, `SYS_CAP_DERIVE`, `SYS_CAP_DERIVE_BADGE`, `SYS_CAP_REVOKE`, `SYS_CAP_DELETE` |
| `cap_info.rs` | `SYS_CAP_INFO` (tag, rights, type-specific fields) |
| `retype.rs` | Retype primitive: augmentation and donation spill, PT walk budget, kernel PT pool |
| `mm.rs` | `SYS_MEM_MAP/UNMAP/PROTECT`, `SYS_MEMORY_SPLIT`, `SYS_MEMORY_MERGE`, `SYS_ASPACE_QUERY` |
| `notification.rs` | `SYS_NOTIFICATION_SEND`, `SYS_NOTIFICATION_WAIT` (blocking and `notification_wait_timeout`) |
| `event.rs` | `SYS_EVENT_POST`, `SYS_EVENT_RECV` (blocking, `try_recv`, timeout) |
| `wait_set.rs` | `SYS_WAIT_SET_ADD/REMOVE/WAIT` |
| `ipc.rs` | `SYS_IPC_CALL`, `SYS_IPC_REPLY`, `SYS_IPC_RECV`, `SYS_IPC_BUFFER_SET` |
| `thread.rs` | `SYS_THREAD_START/STOP/YIELD/EXIT/CONFIGURE/SET_PRIORITY/SET_AFFINITY/READ_REGS/WRITE_REGS/SLEEP/BIND_NOTIFICATION`; `SYS_SCHED_SPLIT` |
| `fpu.rs` | FPU / SIMD / V extended-state isolation across preemption and cross-CPU migration |
| `hw.rs` | `SYS_MMIO_MAP`, `SYS_MMIO_SPLIT`, `SYS_IRQ_REGISTER/ACK`, `SYS_IRQ_SPLIT`, `SYS_IOPORT_BIND`, `SYS_IOPORT_SPLIT`, `SYS_SBI_CALL` |
| `sysinfo.rs` | `SYS_SYSTEM_INFO` |
| `entropy.rs` | `SYS_GETRANDOM`, incl. user-copy fault recovery (unmapped or read-only buffer ⇒ `InvalidAddress`) and the over-max-length error |
| `init_layout.rs` | Kernel Phase 9 ASLR draws (#39): `InitInfo` VA, init stack, and PIE image-base window membership |
| `crypto.rs` | Shared `crypto` crate KATs (SHA-512, Ed25519 verify), on-target on both arches; not a syscall surface |

Adding a new syscall means adding a section in the appropriate file here.

### Tier 2 — `src/integration/`

Cross-subsystem scenario tests that exercise realistic multi-syscall workflows.
These catch bugs that unit tests miss — e.g. capability rights surviving an IPC
transfer, thread state after stop+write_regs+resume, wait set ordering under
concurrent notification and queue events.

| File | Scenario |
|---|---|
| `thread_lifecycle.rs` | Full thread lifecycle: create → configure → start → stop → read\_regs → write\_regs → resume → exit |
| `cap_transfer.rs` | Cap rights flow through an IPC endpoint round-trip |
| `cap_transfer_large.rs` | IPC transfer of a cap with a multi-batch child list, both directions |
| `wait_concurrency.rs` | Wait set with concurrent notification + queue sources |
| `memory_lifecycle.rs` | Pool-frame map → protect → unmap, with `aspace_query` after the map and after the unmap |
| `multi_caller_ipc_fifo.rs` | Three concurrent IPC callers verify FIFO send-queue ordering |
| `cap_delegation_chain.rs` | Multi-level rights attenuation and cascaded revocation |
| `tlb_coherency.rs` | Map/unmap cycles across CPUs to exercise TLB shootdown |
| `retype_reclaim.rs` | Auto-reclaim invariant for every retypable kernel object |
| `priority_preemption.rs` | Higher-priority runnable thread preempts a CPU-bound lower-priority spinner within a wall-clock budget |
| `shared_memory_two_aspaces.rs` | One Memory cap mapped into two `AddressSpace` caps; `aspace_query` returns identical phys backing in both |
| `cap_move_into_fresh_cspace_then_ipc.rs` | `cap_move` an endpoint into a child cspace; the child IPC-calls through its local slot; parent receives via a sibling cap |
| `sbi_gating.rs` | `SYS_SBI_CALL` extension gating: kernel floor and `SbiControl` rights (RISC-V) |
| `fault_kills_thread.rs` | A genuine userspace page fault (unmapped store) kills the thread with `EXIT_FAULT_BASE + <fault vector>` |
| `fault_pager_roundtrip.rs` | A userspace pager receives a `FAULT_KIND_VM` fault, maps the page, replies `FAULT_REPLY_RESUME`; the store completes |
| `fault_resume_modifies_pc.rs` | A fault handler edits a fault-blocked thread's registers and resumes it at a new instruction pointer |
| `fault_handler_declines_kills.rs` | A handler replying `FAULT_REPLY_KILL` terminates the faulting thread as an unhandled fault |
| `fault_exception_redirect.rs` | A non-page-fault CPU exception (illegal instruction) is redirected to a bound handler, which resumes at a new IP |
| `fault_exception_no_handler_kills.rs` | A non-page-fault CPU exception with no handler bound is terminal |
| `death_notification_late_bind.rs` | A death observer bound after the thread already exited or faulted still receives the retained exit reason |
| `aspace_fault_notification_late_bind.rs` | An address-space terminal-fault observer bound after a thread in that space faulted still receives the retained reason |
| `cap_generation_stale_handle.rs` | A same-`CSpace` stale cap handle replayed after its slot is recycled fails with `InvalidCapability` (#349) |
| `cross_cspace_revoke_no_alias.rs` | A cross-`CSpace` `cap_revoke` must not let a recipient's stale handle alias a recycled slot (#349) |
| `retype_subpage_clobber.rs` | The retype sub-page allocator rejects a free-list link clobbered through a userspace mapping of the cap region |
| `fpu_survives_ipc_call.rs` | FPU register file survives a raw `SYS_IPC_CALL` round trip across CPU migration |
| `irq_preserves_user_regs.rs` | A user thread's callee-saved registers survive timer preemption via the frame-authoritative IRQ path |
| `ipc_call_interrupted_stop_start.rs` | A client stopped while parked in `ipc_call` (`BlockedOnSend` or `BlockedOnReply`) and restarted returns `Interrupted` (#361) |
| `park_interrupted_stop_start.rs` | A thread stopped while parked in any non-call blocking syscall and restarted returns `Interrupted` (#363) |
| `tlb_widen_retry.rs` | A permission-widen elides its shootdown; a remote stale-TLB write still completes via spurious-fault retry |

### Tier S — `src/stress/`

Stress and torture tests that exercise race conditions, resource exhaustion, deep
capability trees, and concurrent operations. Runs on every ktest boot
(`KtestConfig::DEFAULT.run_stress` is `true`); turn it off by setting `run_stress: false`, then
rebuilding and re-composing (see [Compile-time options](#compile-time-options)).

Order matches `stress/mod.rs` dispatch order.

Per-test worker counts reach at most the `u64` notification-bitmask ceiling of 64 workers
(`concurrent_notification`, `concurrent_ipc`, `cap_revoke_under_use`, and `retype_concurrent`
run at it; the other cells run fewer, per the Knobs column), and iteration counts are
5-10× higher than a
trivial smoke-test would need. The point is that one full ktest boot
exercises enough contention to surface latent
races, rather than needing tens of repeat runs to flake-mine. The
`u64` width caps per-test workers at 64; lifting that would require
re-encoding the per-worker bookkeeping from a bitmask to an atomic-
counter ledger. The `MAX_STRESS_THREADS = 64` cap in `stress/mod.rs`
mirrors that ceiling (64 × 16 KiB child-stack BSS = 1 MiB).

| File | Scenario | Knobs |
|---|---|---|
| `cap_tree_deep.rs` | 8-level derivation chain with cascading revocation | `CHAIN_DEPTH=8`, `PASSES=500` |
| `cspace_recycle.rs` | Repeated `CSpace` create+delete past the live-count bound (free-list recycling) | `ITERATIONS=10_000` |
| `event_queue_fill_drain.rs` | Fill/drain cycles on a capacity-8 queue (ring buffer wrap-around) | `CAPACITY=8`, `CYCLES=2000` |
| `idle_wake_race.rs` | Worker pinned to CPU 1 parks in `notification_wait`; `ITERATIONS` notification round trips from CPU 0 exercise the cross-CPU idle-wake / wake-IPI path | `ITERATIONS=50_000` |
| `thread_churn.rs` | Rapid thread create/destroy cycles (TCB and CSpace cleanup) | `ITERATIONS=1000` |
| `cap_delete_running.rs` | Delete capabilities while child threads actively spin | `NUM_CHILDREN=16` |
| `cap_delete_reply_wake.rs` | `cap_delete` of a server a client is `BlockedOnReply` on must wake that client (#351, the dealloc deferred reply-wake liveness invariant) | `CYCLES=2000` |
| `priority_dealloc_race.rs` | Race `sys_thread_set_priority` against `cap_delete(Thread)` and affinity-driven migration (covers Scheduling-group all-locks discipline) | `NUM_WORKERS=16`, `CYCLES=200` |
| `stop_reply_race.rs` | Race `thread_stop` on a reply-blocked client against `cap_delete` of the server it is parked on (#317 cross-CPU UAF) | `CYCLES=300` |
| `stop_resume_race.rs` | Race `thread_stop` against a concurrent `thread_start` (resume) on a `Running` pinned victim across three CPUs (stop-drain liveness) | `CYCLES=256` |
| `double_enqueue_storm.rs` | Run-queue double-link guard regression (#244): wake + priority + affinity churn, then wake racing `cap_delete(Thread)` | `NUM_WORKERS=32`, `CYCLES=600` |
| `event_try_recv_post_race.rs` | A non-blocking `SYS_EVENT_RECV` try-once racing a concurrent `event_post` must never leave the poller wakeable (#352) | `CYCLES=1024` |
| `load_balance_handoff_steal.rs` | Arm the load-balancer mid-handoff steal (#314/#293): unpinned IPC clients vs round-robin-pinned servers expose `pull_unpinned_ready` stealing a `context_saved == 0` thread | `NUM_PAIRS=16`, `ITERS=16000` |
| `concurrent_notification.rs` | Multiple threads sending distinct bits to one notification simultaneously | `NUM_SENDERS=64`, `SEND_ITERATIONS=5000` |
| `concurrent_ipc.rs` | Multiple callers racing on one endpoint (send-queue safety) | `NUM_CALLERS=64`, `CYCLES=200` |
| `cap_revoke_under_use.rs` | Revoke root while child threads actively send on derived caps | `NUM_CHILDREN=64` |
| `concurrent_map_unmap.rs` | Multiple threads mapping/unmapping distinct VAs in the same address space | `NUM_CHILDREN=16`, `MAP_ITERATIONS=1000` |
| `retype_concurrent.rs` | Multiple workers retyping concurrently against one Memory-backed allocator | `NUM_WORKERS=64`, `ITERS_PER_WORKER=1000` |
| `split_delete_race.rs` | A same-CSpace sibling deletes the original while this thread splits it across three reparent batches; the split's result classifies each cycle and the slot count returns to baseline | `CYCLES=40`, `CHILDREN=600` |
| `fpu_migration_churn.rs` | 100 cycles of FPU-owner thread migration across CPUs; validates eager save / lazy restore under churn | `CYCLES=100` |
| `concurrent_event_producers.rs` | Multiple producers post concurrently to one event queue; consumer verifies every producer's full sequence | `NUM_PRODUCERS=4`, `MESSAGES_PER_PRODUCER=64` |

### Tier 3 — `src/bench/`

Cycle-accurate benchmarks using `rdtsc` (x86-64) or `csrr cycle` (RISC-V).
Each kernel surface measured has its own file under `bench/` (a file may hold several
benchmarks), mirroring
`unit/`'s one-file-per-surface rule (`bench/{null,ipc,notification,cap,mm,
thread,event,wait_set,tlb}.rs`). Benchmarks log min/mean/max cycle counts
(`context_switch` logs cycles per switch); none produces a PASS/FAIL verdict.

| Benchmark | What it measures |
|---|---|
| `null_syscall_roundtrip` | Kernel entry/exit baseline (`SYS_SYSTEM_INFO`) |
| `ipc_round_trip` | Synchronous IPC call + reply, per-iteration |
| `notification_roundtrip` | Notification ping-pong between two threads, per-iteration |
| `cap_create_delete` | `cap_create_notification` + `cap_delete` cycle |
| `mem_map_unmap` | `mem_map` + `mem_unmap` cycle |
| `mem_protect_pair` | `mem_protect(READONLY)` + `mem_protect(WRITABLE)` round trip |
| `thread_lifecycle` | Full thread create → start → exit → cleanup |
| `context_switch` | Parent/child `thread_yield` ping-pong on one CPU; reports cycles per switch |
| `event_post_recv` | `event_post` + `event_recv` on a pre-created queue |
| `wait_set_cycle` | Wait set create → add → wait → remove → delete |
| `tlb_shootdown_unmap` | `mem_unmap` cost when ktest's aspace is `current` on every CPU (spinners pinned per CPU); logs `cpus=N` |
| `tlb_shootdown_concurrent` | Every pinned worker is a concurrent `mem_map` + `mem_unmap` initiator; logs `cpus=N`, `conc_workers=`, and fresh-map and unmap cycle stats |

## Test infrastructure

Defined in `src/main.rs` (the `spawn::` items in `src/spawn.rs`):

- `TestResult` — `Result<(), &'static str>` — no heap, no allocation.
- `run_test!(name, body)` — macro that logs the test name, runs `body`,
  records PASS or FAIL (with reason), and never panics.
- `TestContext` — thin struct carrying `aspace_cap`, `cspace_cap`, `thread_cap`, the IPC
  buffer pointer (`ipc_buf`), `memory_base` (first RAM Memory cap), `sbi_control_cap` (zero
  on x86-64), `sched_control_cap` (root `SchedControl`), and `init_info_va` (the `InitInfo`
  page VA). Passed by reference to every
  test function. `cspace_cap` is queried via
  `cap_info(_, CAP_INFO_CSPACE_CAPACITY)` by hardware tests whose
  scans must cover slots populated after `aspace_cap` (e.g. narrow
  `IoPort` caps carved by `ioport::bind_port_range` on `x86_64`).
- `PASS_COUNT` / `FAIL_COUNT` — atomic counters updated by `run_test!`.
- `log(msg)` / `log_u64(prefix, value)` — heap-free logging utilities.
- `spawn::new_child(ctx)` / `configure_and_start(child, …)` /
  `configure_and_start_pinned(child, …)` — child-thread spawn helper
  wrapping the cspace + thread + configure + start sequence each
  spawning test would otherwise repeat.
- `spawn::ArgBlock` / `spawn::child_args` — per-test static argument
  entries a child receives by address. A child's single `u64` argument
  holds at most two 32-bit capability handles (as halves); anything more
  goes through an `ArgBlock`. Narrower packings truncate the handle's
  generation byte.
- `spawn::wait_until_exited(thread, max_polls)` /
  `spawn::wait_memory_baseline(memory, baseline, max_polls)` — poll a
  thread's `CAP_INFO_THREAD_STATE` until it reports `Exited`, or a Memory
  cap's available bytes until they return to a baseline; the way a test
  observes a deferred (off-CPU) reclaim completing.

## Compile-time options

The boot protocol carries no kernel command line
([core/boot/README.md](../boot/README.md) § What the Bootloader Does Not Do); ktest's runtime
knobs live in `KtestConfig::DEFAULT` in [`src/cmdline.rs`](src/cmdline.rs) and are baked in at
compile time. To flip them, edit the constant, rebuild ktest
(`cargo xtask build --component ktest`), then re-compose the bundle
(`cargo xtask compose-bundle --harness ktest`, per [§ Activating ktest](#activating-ktest))
before `cargo xtask run`; a single-component build does not re-compose the bundle (per
[xtask/README.md](../../xtask/README.md) § `cargo xtask compose-bundle`), so whatever
bundle was last composed (the previous ktest binary, or default init after a full build) boots
until it is re-composed.

| Field | Values | Default | Description |
|---|---|---|---|
| `shutdown_policy` | `Always`, `Pass`, `Never` | `Always` | When to shut down the system after tests complete |
| `timeout_secs` | `u32` | `0` | Seconds to wait before shutdown (allows reading output) |
| `run_unit` | `bool` | `true` | Run Tier 1 |
| `run_integration` | `bool` | `true` | Run Tier 2 |
| `run_stress` | `bool` | `true` | Run Tier S |
| `run_bench` | `bool` | `true` | Run Tier 3 |
| `bench_iters` | `u32` | `1000` | Number of iterations per benchmark |

The defaults are picked for CI: every tier runs, the VM exits cleanly
on completion, and no human-watch grace period is added. To keep QEMU
open after a local interactive run, set `shutdown_policy:
ShutdownPolicy::Never` and rebuild and re-compose as above.

### Shutdown

`ShutdownPolicy::Always` shuts down regardless of test outcome.
`ShutdownPolicy::Pass` shuts down only if all tests passed; otherwise the harness thread
exits (`thread_exit`) and the system idles. `ShutdownPolicy::Never` exits the harness thread
after printing results, leaving the system idle with QEMU open. A shutdown attempt that fails
also falls through to `thread_exit`.

On x86-64 shutdown uses ACPI S5 (parsed from FADT/DSDT in userspace).
On RISC-V shutdown uses SBI SRST via the `SYS_SBI_CALL` syscall.

### Tier filter

Four `bool` fields select the tiers: `run_unit`, `run_integration`, `run_stress`, and
`run_bench`. `KtestConfig::DEFAULT` sets all four to `true`, so every tier runs. Setting one or
more to `false`, then rebuilding and re-composing as above, is how a narrower-scope run is
produced.

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Tier taxonomy, cross-harness marker format, and gating |
| [docs/build-system.md](../../docs/build-system.md) | Toolchain, sysroot, and `cargo xtask` commands that build and boot ktest |
| [xtask/README.md](../../xtask/README.md) | `compose-bundle` harness selection and bundle-vs-mkdisk authoring |
| [core/boot/README.md](../boot/README.md) | Boot protocol that loads ktest as init; no kernel command line |

---

## Summarized By

[System Bootstrap](../../docs/bootstrap.md), [Build System](../../docs/build-system.md),
[Testing](../../docs/testing.md), [xtask/README.md](../../xtask/README.md)
