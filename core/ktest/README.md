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

Re-compose the bootloader bundle with ktest as the `init` entry:

```
cargo xtask compose-bundle --harness ktest
cargo xtask run
```

Restore the default-init harness with `cargo xtask compose-bundle
--harness init` (or any subsequent `cargo xtask build`, which always
re-authors the default-init bundle). See
[`xtask/README.md`](../../xtask/README.md) for the bundle-vs-mkdisk
authoring discipline.

## Source Layout

```
ktest/
├── Cargo.toml              # Workspace member; no_std binary
├── README.md
└── src/
    ├── main.rs             # _start, InitInfo intake, TestContext, run_test!, tier dispatch,
    │                       # summary, shutdown
    ├── cmdline.rs          # Compile-time configuration (KtestConfig::DEFAULT)
    ├── serial.rs           # Direct serial output
    ├── framebuffer.rs      # Direct framebuffer output
    ├── frame_pool.rs       # Memory capability pool for tests that map memory
    ├── spawn.rs            # Child-thread spawn helpers, argument blocks, exit probes
    ├── tally.rs            # Failure tallies and receive-guard diagnostics for stress cells
    ├── ioport.rs           # Per-thread I/O port access (x86-64)
    ├── acpi_shutdown.rs    # ACPI S5 shutdown (x86-64)
    ├── sbi_shutdown.rs     # SBI SRST shutdown (RISC-V)
    ├── arch/               # Arch-dispatch surface (see Test structure)
    │   ├── mod.rs          # Selects the active arch module by target_arch
    │   ├── x86_64/         # x86-64 entry points, constants, and arch-only tests
    │   └── riscv64/        # RISC-V entry points, constants, and arch-only tests
    ├── unit/               # Tier 1: per-syscall isolation tests, one file per surface
    ├── integration/        # Tier 2: cross-subsystem scenarios, one file per scenario
    ├── stress/             # Tier S: race and exhaustion cells, one file per race
    └── bench/              # Tier 3: cycle-count benchmarks, one file per surface
```

## Test structure

Tests are organised across four tiers (unit, integration, stress, and
benchmark), all run on every boot by default. Each tier lives in its own
source directory, which codifies a "one file per surface/scenario/race"
rule at the top of its `mod.rs`, except its architecture-only tests,
which live under `src/arch/<arch>/` (see below).

`src/arch/` is ktest's arch-dispatch surface: one module per architecture,
selected by `target_arch` in `src/arch/mod.rs`, each exposing the same
entry points and constants. Tier 1 reaches the tests behind it through
`crate::arch::run_unit` and Tier 2 through `crate::arch::run_integration`;
arch-neutral tests take the vector of a not-present user store from
`crate::arch::PAGE_FAULT_STORE_VECTOR` and that of an illegal-instruction
fault from `crate::arch::ILLEGAL_INSTRUCTION_VECTOR`, raise the latter through
`crate::arch::illegal_instruction`, and take the kernel `TrapFrame`'s size and
instruction-pointer offset from `crate::arch::TRAP_FRAME_BYTES` and
`crate::arch::IP_OFFSET`.
Per-arch helpers and branches inside arch-neutral tests, and other arch-specific
items elsewhere in ktest, are still gated in place with `#[cfg(target_arch)]`;
#460 tracks the move.

### Tier 1 — `src/unit/`

Per-syscall isolation tests. Every kernel syscall has at least one positive-path
test and the most important negative paths (wrong rights, invalid arguments,
wrong object state). Files are grouped by kernel subsystem, mirroring the
kernel's own source layout.

| File | Syscalls / behaviour exercised |
|---|---|
| `cap.rs` | `SYS_CAP_CREATE_*`, `CAP_COPY`, `CAP_MOVE`, `CAP_INSERT`, `CAP_DERIVE`, `CAP_DERIVE_BADGE`, `CAP_REVOKE`, `CAP_DELETE` |
| `cap_info.rs` | `SYS_CAP_INFO` (tag, rights, type-specific fields) |
| `retype.rs` | Retype primitive: augmentation and donation spill, PT walk budget, kernel PT pool |
| `mm.rs` | `SYS_MEM_MAP/UNMAP/PROTECT`, `SYS_MEMORY_SPLIT`, `SYS_ASPACE_QUERY` |
| `entropy.rs` | `SYS_GETRANDOM`, including an unmapped or read-only buffer refused with `InvalidAddress` |
| `notification.rs` | `SYS_NOTIFICATION_SEND`, `SYS_NOTIFICATION_WAIT` (blocking and `notification_wait_timeout`) |
| `event.rs` | `SYS_EVENT_POST`, `SYS_EVENT_RECV` (blocking, `try_recv`, timeout) |
| `wait_set.rs` | `SYS_WAIT_SET_ADD/REMOVE/WAIT`, including a second concurrent `wait_set_wait` refused with `InvalidState`, as [docs/ipc-design.md § Waiting on Multiple Sources](../../docs/ipc-design.md#waiting-on-multiple-sources) defines |
| `ipc.rs` | `SYS_IPC_CALL`, `SYS_IPC_REPLY`, `SYS_IPC_RECV`, `SYS_IPC_BUFFER_SET` |
| `thread.rs` | `SYS_THREAD_START/STOP/YIELD/EXIT/CONFIGURE/SET_PRIORITY/SET_AFFINITY/READ_REGS/WRITE_REGS/SLEEP/BIND_NOTIFICATION` |
| `fpu.rs` | FPU / SIMD / V extended-state isolation across preemption and cross-CPU migration |
| `hw.rs` | `SYS_MMIO_MAP`, `SYS_MMIO_SPLIT`, `SYS_IRQ_REGISTER/ACK`, `SYS_IRQ_SPLIT`, `SYS_IOPORT_BIND`, `SYS_IOPORT_SPLIT` (`SYS_SBI_CALL` is under `src/arch/<arch>/`) |
| `sysinfo.rs` | `SYS_SYSTEM_INFO` |
| `crypto.rs` | Shared `crypto` crate known-answer tests (SHA-512, Ed25519 verify) run on-target (not a syscall surface) |
| `init_layout.rs` | Kernel init-bootstrap ASLR draws: the `InitInfo` VA, init stack, and PIE image base lie in their windows |

Adding a new syscall means adding a section in the appropriate file here.

Architecture-only Tier 1 tests live under `src/arch/<arch>/` and run through
`crate::arch::run_unit`. On x86-64, `src/arch/x86_64/configure_wrapped_stack.rs` checks that
`thread_configure` refuses a stack top the entry alignment wraps below zero. Each
architecture's `sbi_call.rs` holds its `SYS_SBI_CALL` test: the call reaches the SBI firmware
on RISC-V and returns `NotSupported` on x86-64.

### Tier 2 — `src/integration/`

Cross-subsystem scenario tests that exercise realistic multi-syscall workflows, listed in
`integration/mod.rs` dispatch order.
These catch bugs that unit tests miss — e.g. capability rights surviving an IPC
transfer, thread state after stop+write_regs+resume, wait set ordering under
concurrent notification and queue events.

| File | Scenario |
|---|---|
| `thread_lifecycle.rs` | Full thread lifecycle: create → configure → start → stop → read\_regs → write\_regs → resume → exit |
| `stop_read_regs_remote.rs` | A thread spinning in user mode on another CPU is stopped, then its registers are read at once (never refused with `InvalidState`, since the stop returns only once that CPU has descheduled it and published its register save, as [core/kernel/docs/syscalls.md § `SYS_THREAD_READ_REGS`](../kernel/docs/syscalls.md#sys_thread_read_regs-39) defines), its saved instruction pointer lies in its spin code, and a register write redirecting it takes effect on restart, every round (≥ 2 CPUs) |
| `death_notification_late_bind.rs` | A death observer bound after the thread already died still receives the retained exit reason |
| `aspace_fault_notification_late_bind.rs` | An address-space terminal-fault observer bound after a thread in that space already faulted still receives the retained fault reason |
| `cap_transfer.rs` | Cap rights flow through an IPC endpoint round-trip |
| `cap_transfer_large.rs` | IPC transfer of a cap with a multi-batch child list, both directions |
| `wait_concurrency.rs` | Wait set with concurrent notification + queue sources |
| `memory_lifecycle.rs` | Memory split → map → protect → unmap with aspace\_query at each step |
| `multi_caller_ipc_fifo.rs` | Three concurrent IPC callers verify FIFO send-queue ordering ([docs/ipc-design.md § Endpoints](../../docs/ipc-design.md#endpoints)) |
| `ipc_call_interrupted_stop_start.rs` | A client stopped while parked in `ipc_call` and then restarted returns `Interrupted`, never a stale reply (#361) |
| `park_interrupted_stop_start.rs` | A thread stopped while parked in any non-call blocking syscall and then restarted returns `Interrupted`, never a stale wake deposit (#363) |
| `reply_binding_displaced.rs` | A server that receives again without replying releases the caller its earlier receive bound, as [docs/ipc-design.md § The Call/Reply Model](../../docs/ipc-design.md#the-callreply-model) defines: a released `ipc_call` returns `Interrupted` and the released caller stops and restarts; a released fault-blocked thread, still alive before the later receive, is killed with the fault exit reason; the later receive's caller gets its reply |
| `destroyed_source_interrupts.rs` | Every waiter parked on a notification (two untimed or two timed), an event queue (two), or a wait set (one) destroyed under it returns `Interrupted`, never a fabricated success, as [docs/ipc-design.md § Notifications](../../docs/ipc-design.md#notifications), [§ Event Queues](../../docs/ipc-design.md#event-queues), and [§ Waiting on Multiple Sources](../../docs/ipc-design.md#waiting-on-multiple-sources) define |
| `queued_waiters_fifo.rs` | Two threads waiting on one notification or event queue are woken in arrival order, as [docs/ipc-design.md § Notifications](../../docs/ipc-design.md#notifications) and [§ Event Queues](../../docs/ipc-design.md#event-queues) define: each delivery wakes the longest waiter only, and a queued waiter whose timed wait expires (at the head or the tail) leaves the other waiting for the next delivery |
| `cap_delegation_chain.rs` | Multi-level rights attenuation and cascaded revocation |
| `tlb_coherency.rs` | Map/unmap cycles across CPUs to exercise TLB shootdown, then the same with `mem_unmap_reclaim` |
| `retype_reclaim.rs` | Auto-reclaim invariant for every retypable kernel object |
| `retype_subpage_clobber.rs` | The retype sub-page allocator never dereferences a free-list link clobbered through a userspace mapping of the cap region |
| `priority_preemption.rs` | Higher-priority runnable thread preempts a CPU-bound lower-priority spinner within a wall-clock budget |
| `shared_memory_two_aspaces.rs` | One Memory cap mapped into two `AddressSpace` caps; `aspace_query` returns identical phys backing in both |
| `cap_move_into_fresh_cspace_then_ipc.rs` | `cap_move` an endpoint into a child cspace; the child IPC-calls through its local slot; parent receives via a sibling cap |
| `cross_cspace_revoke_no_alias.rs` | A cross-`CSpace` `cap_revoke` does not let a recipient's stale handle alias a recycled slot (#349) |
| `cap_generation_stale_handle.rs` | A same-`CSpace` stale cap handle fails closed after its slot is freed and recycled (#349) |
| `fpu_survives_ipc_call.rs` | The FPU register file survives a raw `SYS_IPC_CALL` round-trip across CPU migration |
| `fault_kills_thread.rs` | A genuine userspace page fault kills the thread |
| `fault_pager_roundtrip.rs` | A userspace pager resolves a page fault and resumes the thread |
| `fault_resume_modifies_pc.rs` | A fault handler edits the fault-blocked thread's registers and resumes it at a new instruction pointer |
| `fault_handler_declines_kills.rs` | A fault handler replying `FAULT_REPLY_KILL` terminates the faulting thread as an unhandled fault |
| `fault_exception_redirect.rs` | A non-page-fault CPU exception is redirected to a bound fault handler, which resumes the thread at a new instruction pointer |
| `fault_exception_no_handler_kills.rs` | A non-page-fault CPU exception with no handler bound is terminal |
| `irq_preserves_user_regs.rs` | A ring-3 thread's callee-saved registers survive a timer preemption through the frame-authoritative IRQ path |
| `tlb_widen_retry.rs` | A permission widen that elides its TLB shootdown still lets a remote CPU's stale-TLB write complete through the spurious-fault retry |

Architecture-only Tier 2 scenarios live under `src/arch/<arch>/` and run through
`crate::arch::run_integration`. On x86-64, `src/arch/x86_64/syscall_rflags_hardening.rs`
checks that a user-set DF and TF, and a GS base reloaded from the user selector, do not reach
the kernel across a SYSCALL. On RISC-V, `src/arch/riscv64/sbi_gating.rs` checks that
`SYS_SBI_CALL` refuses kernel-reserved SBI extensions and sanctioned ones the cap lacks the
right for.

### Tier S — `src/stress/`

Stress and torture tests that exercise race conditions, resource exhaustion, deep
capability trees, and concurrent operations. They run on every boot under
`KtestConfig::DEFAULT` (`run_stress: true`); see [Compile-time options](#compile-time-options)
to turn the tier off. SMP-dependent cells self-skip (logging `SKIP`) below their CPU minimum;
the rows below state it for the cells that pin their participants to CPUs.

Order matches `stress/mod.rs` dispatch order.

Concurrency knobs ramp worker-pool cells (`NUM_WORKERS`, `NUM_CHILDREN`, `NUM_SENDERS`,
`NUM_CALLERS`) toward the `u64` notification-bitmask ceiling of 64 workers, and iteration counts
5-10× higher than a trivial smoke-test would need. Race cells use a fixed set of a few participants
and scale through their iteration knob (`CYCLES`, `ITERATIONS`) instead. The point is that one ktest
boot exercises enough contention to surface latent races, rather than needing tens of repeat runs to
flake-mine. The `u64` width caps per-test workers at 64; lifting that would require re-encoding the
per-worker bookkeeping from a bitmask to an atomic-counter ledger. The `MAX_STRESS_THREADS = 64` cap
in `stress/mod.rs` mirrors that ceiling (64 × 16 KiB child-stack BSS = 1 MiB).

| File | Scenario | Knobs |
|---|---|---|
| `cap_tree_deep.rs` | 8-level derivation chain with cascading revocation | `CHAIN_DEPTH=8`, `PASSES=500` |
| `cspace_recycle.rs` | Repeated `CSpace` create+delete past the live-count bound (free-list recycling) | `ITERATIONS=10_000` |
| `event_queue_fill_drain.rs` | Fill/drain cycles on a capacity-8 queue (ring buffer wrap-around) | `CAPACITY=8`, `CYCLES=2000` |
| `idle_wake_race.rs` | Race wake of an idle CPU with concurrent ready-queue entry under affinity migration (≥ 2 CPUs) | `ITERATIONS=50_000` |
| `thread_churn.rs` | Rapid thread create/destroy cycles (TCB and CSpace cleanup) | `ITERATIONS=1000` |
| `cap_delete_running.rs` | Delete capabilities while child threads actively spin | `NUM_CHILDREN=16` |
| `cap_delete_reply_wake.rs` | `cap_delete` of a server a client is `BlockedOnReply` on must wake that client (#351, the dealloc deferred reply-wake liveness invariant) (≥ 2 CPUs) | `CYCLES=2000` |
| `priority_dealloc_race.rs` | Race `sys_thread_set_priority` against `cap_delete(Thread)` and affinity-driven migration (covers Scheduling-group all-locks discipline) | `NUM_WORKERS=16`, `CYCLES=200` |
| `stop_reply_race.rs` | Race `thread_stop` on a reply-blocked client against `cap_delete` of the server it is parked on (#317 cross-CPU UAF); with ≥ 4 CPUs a second stopper on its own CPU also stops the client, so two cancels race one reply-blocked client while the server is freed, and some second stop must commit (≥ 2 CPUs; the second stopper needs 4) | `CYCLES=300` |
| `stop_resume_race.rs` | Race `thread_stop` against a concurrent `thread_start` (resume) on a `Running` pinned victim across three CPUs (stop-drain liveness) (≥ 3 CPUs) | `CYCLES=256` |
| `configure_start_race.rs` | Reconfigure an already-configured `Created` thread on one CPU while another starts it, the two calls released together with a delay that sweeps both orders; the start returns `Ok`, the configure `Ok` or `InvalidArgument`, the thread exits voluntarily, and exactly one entry ran, with its own argument on its own stack: the reconfigured entry after `Ok`, the original after `InvalidArgument` (the configure's `Created` check and frame rebuild hold the target's `sched_lock`, which the start's commit takes); both outcomes must occur (≥ 2 CPUs; an unlocked check fails only when the start's commit lands inside configure's window between its check and its writes, running the old frame after an `Ok` or, if the dispatch overlaps the writes, a torn one, so the cell is a tripwire for it) | `CYCLES=200` |
| `stop_sleep_window.rs` | Stop and restart a thread looping `thread_sleep(1)` on the timer CPU, so stops land around the park commit, the sleep-list add, and the timer's claim; each sleep returns `Ok` or `Interrupted` (≥ 2 CPUs) | `CYCLES=2000` |
| `sleep_list_full.rs` | Hold the sleep list at capacity with one long sleeper per slot (confirmed by a probe sleep returning `OutOfMemory`), then stop and restart a thread looping `thread_sleep(1)` so stops land around its commit-to-withdrawal window; every sleep must return `OutOfMemory` or `Interrupted`, some must return `OutOfMemory`, and after the list drains the next sleep must return `Ok` (the full-list withdrawal and a stop's cancel claim the park through the same `sleep_list_remove`, so a cancelled sleep reports `Interrupted`; the lost-withdrawal interleaving is reached statistically) (≥ 2 CPUs) | `CYCLES=2000`, `FILLERS=128` |
| `stop_park_race.rs` | Stop and restart a peer entering a notification wait, an IPC call, or a sleep; each park returns its genuine result or `Interrupted`, and every kind sees a cancellation (≥ 2 CPUs) | `CYCLES=150`, `SLEEP_MS=2` |
| `stop_owed_wake.rs` | Stop and restart a notification waiter while a sender keeps claiming its wait (each round waits, bounded by `ENTRY_WAIT_US`, for the restarted waiter to enter a wait), alone and then (4+ CPUs) with a starter racing every restart, itself stopped and restarted by the controller every `STARTER_STOP_PERIOD` rounds; every wait returns bits or `Interrupted` and both occur; every start succeeds or returns `InvalidArgument` (or, for the starter's, `Interrupted`, tallied but not required), none returns `InvalidArgument` while the controller is alone, and with the starter racing it wins some restarts and its wins equal the controller's losses (one committed start per stop, none from an interrupted start); the kernel's wait-queue and owed-wake assertions hold (≥ 2 CPUs; the racing phase needs 4) | `CYCLES=2000` per phase, `STARTER_STOP_PERIOD=16` |
| `stop_fault_sender.rs` | Stop and restart a thread faulting in a loop while its fault handler dequeues each fault from the send queue and replies `RESUME`; a stop that cancels a fault no reply claimed gives it a kill outcome, so the restart kills the faulter, as [docs/fault-handling.md § Delivery, Resume, and Kill](../../docs/fault-handling.md#delivery-resume-and-kill) defines, and every `RESUME` reply that returned `Ok` must be honoured: the completed faults equal the `Ok` replies; after each death a syncer thread's call to the handler, whose answer the controller awaits bounded, orders the respawn after any service of the dead faulter (#443; ≥ 3 CPUs) | `CYCLES=1000` |
| `mutual_stop.rs` | Two children holding each other's Thread cap stop and restart each other in a loop while the controller restarts whichever pair a mutual stop left stopped; both must exit voluntarily, both must make progress, every stop and start must return an accepted result, per direction the `Ok` stops equal the `Ok` starts, and some round must find both stopped (the witness of a mutual stop) (needs ≥ 3 CPUs; on the unfixed kernel the first mutual stop wedges both CPUs) | `CYCLES=200` |
| `stop_repark.rs` | Stop and restart a waiter alternating between two notifications, then two event queues, while a sender delivers to whichever it is parked on, so a stop's cancellation races a wake that re-parks the waiter on the other source; every wait returns its own source's result or `Interrupted`, deliveries on both sources are consumed during and after the rounds, and some stop interrupts a wait (needs ≥ 3 CPUs) | `CYCLES=1000` per phase |
| `stop_claimed_delete.rs` | Each round parks a fresh waiter on a fresh notification, then event queue, while a sender serves each wait it enters; the controller stops the waiter around the sender's claim of its park, alone and then racing a second stopper whose stop lands concurrently (`Ok`, or `InvalidState` for a waiter the other stop reached first), waits the sender out, deletes the source's last capability, then the stopped waiter's Thread capability (the delete that would walk the freed source if a lost cancel left the waiter's binding for its waker, or a won cancel's tail left it when another stop commits between the claim and the tail, or a cancel that removed the waiter's fresh park on the same source, after the sender claimed the snapshotted one, left that park's binding uncleared); every wait returns the delivery or `Interrupted`, every delivery succeeds, deliveries are consumed, some stop lands on a waiter inside a wait, and with the second stopper some of its stops commit (the claimed-then-stopped interleavings are reached statistically; the kernel's debug assertions are the tripwires) (≥ 4 CPUs) | `CYCLES=1000` per phase (four phases) |
| `stop_target_vanishes.rs` | Stop a stopper while it drains a target it has stopped on a third CPU, then make its handle to that target vanish before restarting it: delete the target's last Thread cap (the target is torn down and respawned), then move the cap to a fresh slot (the target lives on), so the resumed drain re-resolves a slot that no longer names its target and returns at once; the stopper must loop again in every round and the target progress after it, every stop and start by the stopper must return an accepted result, some stop must land in the drain (the stopper's in-syscall flag with a probe stop answering `InvalidState`), and the stopper and the last target must exit voluntarily (≥ 3 CPUs; the cell reaches the stop-in-drain, vanish, restart interleaving the slot re-check guards, but cannot itself observe a drain that, without the re-check, reads a freed TCB: that read finds the `Exited` mark the target's dealloc wrote before the free, or the state of the fresh target that reused the TCB, either of which ends the drain, and no assertion catches the stale read, because the drain re-reads `state`, `current`, `context_saved` (and, in its slow-drain diagnostic, `thread_id`), and checks nothing on the magic word the free poisons) | `CYCLES=200` per phase |
| `timed_wait_source_delete.rs` | Destroy a notification or event queue around a timed waiter's deadlines; each wait ends in a timeout, `Interrupted`, or `InvalidCapability` (≥ 2 CPUs) | `CYCLES=200`, `WAIT_MS=1` |
| `timed_waiter_thread_delete.rs` | Delete a timed waiter's last Thread cap around its deadlines (plain sleep, notification, event queue) (≥ 2 CPUs) | `CYCLES=192`, `WAIT_MS=1` |
| `timed_wait_reuse.rs` | A timed wait claimed by a delivery at its deadline, followed by an untimed wait on the same source: the untimed wait never returns a timeout (≥ 2 CPUs) | `CYCLES=400`, `WAIT_MS=1` |
| `double_enqueue_storm.rs` | Run-queue double-link guard regression (#244): wake + priority + affinity churn, then wake racing `cap_delete(Thread)` | `NUM_WORKERS=32`, `CYCLES=600` |
| `event_try_recv_post_race.rs` | A non-blocking `SYS_EVENT_RECV` try-once racing a concurrent `event_post` must never leave the poller wakeable (#352) (≥ 2 CPUs) | `CYCLES=1024` |
| `load_balance_handoff_steal.rs` | Arm the load-balancer mid-handoff steal (#314/#293): unpinned IPC clients vs round-robin-pinned servers expose `pull_unpinned_ready` stealing a `context_saved == 0` thread (≥ 2 CPUs) | `NUM_PAIRS=16`, `ITERS=16000` |
| `concurrent_notification.rs` | Multiple threads sending distinct bits to one notification simultaneously | `NUM_SENDERS=64`, `SEND_ITERATIONS=5000` |
| `concurrent_ipc.rs` | Multiple callers racing on one endpoint (send-queue safety) | `NUM_CALLERS=64`, `CYCLES=200` |
| `cap_revoke_under_use.rs` | Revoke root while child threads actively send on derived caps | `NUM_CHILDREN=64` |
| `concurrent_map_unmap.rs` | Multiple threads mapping/unmapping distinct VAs in the same address space | `NUM_CHILDREN=16`, `MAP_ITERATIONS=1000` |
| `retype_concurrent.rs` | Multiple workers retyping concurrently against one Memory-backed allocator | `NUM_WORKERS=64`, `ITERS_PER_WORKER=1000` |
| `split_delete_race.rs` | A same-CSpace sibling deletes the original while this thread splits it across three reparent batches; the split's result classifies each cycle and the slot count returns to baseline | `CYCLES=40`, `CHILDREN=600` |
| `fpu_migration_churn.rs` | 100 cycles of FPU-owner thread migration across CPUs; validates eager save / lazy restore under churn (≥ 2 CPUs) | `CYCLES=100` |
| `concurrent_event_producers.rs` | Multiple producers post concurrently to one event queue; consumer verifies every producer's full sequence | `NUM_PRODUCERS=4`, `MESSAGES_PER_PRODUCER=64` |

### Tier 3 — `src/bench/`

Cycle-accurate benchmarks using `rdtsc` (x86-64) or `csrr cycle` (RISC-V).
Each benchmark lives in its own file under `bench/`, mirroring
`unit/`'s one-file-per-surface rule (`bench/{null,ipc,notification,cap,mm,
thread,event,wait_set,tlb}.rs`). Each benchmark logs min/mean/max
cycle counts; no PASS/FAIL verdict.

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

## Test infrastructure

Defined in `src/main.rs` (the `spawn::` items in `src/spawn.rs`, the `tally::` items in
`src/tally.rs`):

- `TestResult` — `Result<(), &'static str>` — no heap, no allocation.
- `run_test!(name, body)` — macro that logs the test name, runs `body`,
  records PASS or FAIL (with reason), and never panics.
- `TestContext` — thin struct carrying `aspace_cap`, `cspace_cap`,
  `thread_cap` (ktest's own Thread cap, through which a test pins or
  reprioritises the harness thread), the IPC buffer pointer `ipc_buf`,
  `memory_base` (first RAM Memory cap), `sbi_control_cap` (zero on
  x86-64), `sched_control_cap` (the root `SchedControl`), and
  `init_info_va` (the `InitInfo` page's VA). Passed by reference to
  every test function. `cspace_cap` is queried via
  `cap_info(_, CAP_INFO_CSPACE_CAPACITY)` by hardware tests whose
  scans must cover slots populated after `aspace_cap` (e.g. narrow
  `IoPort` caps carved by `ioport::bind_port_range` on `x86_64`).
- `PASS_COUNT` / `FAIL_COUNT` — atomic counters updated by `run_test!`.
- `log(msg)` / `log_u64(prefix, value)` — heap-free logging utilities.
- `spawn::new_child(ctx)` / `spawn::new_child_at(ctx, sched_cap, priority)` /
  `configure_and_start(child, …)` / `configure_and_start_pinned(child, …)` —
  child-thread spawn helper wrapping the cspace + thread + configure + start
  sequence that ~25 sites duplicated; `new_child` creates the thread at the
  floor priority, `new_child_at` at `priority` under `sched_cap`'s band.
- `spawn::ArgBlock` / `spawn::child_args` — per-test static argument
  entries a child receives by address. A child's single `u64` argument
  holds at most two 32-bit capability handles (as halves); anything more
  goes through an `ArgBlock`. Narrower packings truncate the handle's
  generation byte.
- `spawn::is_exited(thread)` / `spawn::wait_until_exited(thread, max_polls)` /
  `spawn::wait_memory_baseline(memory, baseline, max_polls)` — probe once
  whether a thread's `CAP_INFO_THREAD_STATE` reports `Exited`, poll it until
  it does, or poll a Memory cap's available bytes until they return to a
  baseline; the way a test observes a deferred (off-CPU) reclaim completing.
- `tally::BadTally` — a count of the results a stress cell's children
  recorded as bad, with one of the last such result words; a child cannot
  return a `TestResult`, so the cell's report `check`s each tally (logging
  the count and that result word under the cell's name) once the rounds are
  over. `tally::log_error(label, error)` logs a syscall error word,
  `tally::log_cell_u64(cell, suffix, value)` logs a value under a cell's
  name (`suffix` starts with the separating space), and
  `tally::recv_diag` is the diagnostic hook a cell's blocking receive loop
  hands its `ipc::recv_guard::RecvGuard`
  ([docs/ipc-design.md](../../docs/ipc-design.md) § Receive-Failure Policy).

## Compile-time options

The boot protocol carries no kernel command line
([core/boot/README.md](../boot/README.md) § What the Bootloader Does Not Do); ktest's runtime
knobs live in `KtestConfig::DEFAULT` in [`src/cmdline.rs`](src/cmdline.rs) and are baked in at
compile time. To flip them, edit the constant, rebuild ktest
(`cargo xtask build --component ktest`), then re-compose the bundle
(`cargo xtask compose-bundle --harness ktest`, per [§ Activating ktest](#activating-ktest))
before `cargo xtask run`; a single-component build does not re-compose the bundle, so whatever
bundle was last composed (the previous ktest binary, or default init after a full build) boots
until it is re-composed.

| Field | Values | Default | Description |
|---|---|---|---|
| `shutdown_policy` | `Always`, `Pass`, `Never` | `Always` | When to shut down the system after tests complete |
| `timeout_secs` | `u32` | `0` | Seconds to wait before shutdown (allows reading output) |
| `run_unit` | `bool` | `true` | Run Tier 1 (`src/unit/`) |
| `run_integration` | `bool` | `true` | Run Tier 2 (`src/integration/`) |
| `run_stress` | `bool` | `true` | Run Tier S (`src/stress/`) |
| `run_bench` | `bool` | `true` | Run Tier 3 (`src/bench/`) |
| `bench_iters` | `u32` | `1000` | Number of iterations per benchmark |

The defaults are picked for CI: every tier runs, the VM exits cleanly
on completion, and no human-watch grace period is added. To keep QEMU
open after a local interactive run, set `shutdown_policy:
ShutdownPolicy::Never` and rebuild and re-compose as above.

### Shutdown

`ShutdownPolicy::Always` shuts down regardless of test outcome.
`ShutdownPolicy::Pass` shuts down only if all tests passed; halts otherwise.
`ShutdownPolicy::Never` halts in place after printing results.

On x86-64 shutdown uses ACPI S5 (parsed from FADT/DSDT in userspace).
On RISC-V shutdown uses SBI SRST via the `SYS_SBI_CALL` syscall.

### Tier selection

Each tier has its own flag (`run_unit`, `run_integration`, `run_stress`,
`run_bench`), all `true` by default, so every tier runs. Clearing flags
before recompiling is how a narrower-scope run is produced.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Tier taxonomy, the `[ktest]` marker, sysroot layout, and gating |
| [docs/build-system.md](../../docs/build-system.md) | Toolchain, the sysroot, and the `cargo xtask` commands that build and boot ktest |
| [docs/bootstrap.md](../../docs/bootstrap.md) | The kernel's init handover ktest receives in place of init |
| [abi/init-protocol/README.md](../../abi/init-protocol/README.md) | `InitInfo`: the page and initial capability set ktest reads at `_start` |
| [core/kernel/docs/syscalls.md](../kernel/docs/syscalls.md) | The syscall surface Tier 1 exercises, with each call's errors |
| [core/kernel/docs/thread-lifecycle-and-sleep.md](../kernel/docs/thread-lifecycle-and-sleep.md) | The stop protocol and park semantics the stop and sleep stress cells race |
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC semantics and the receive-failure policy the cells' `RecvGuard`s follow |
| [docs/fault-handling.md](../../docs/fault-handling.md) | The pager protocol the fault integration tests and `stop_fault_sender` drive |
| [docs/console-model.md](../../docs/console-model.md) | ktest's direct serial and framebuffer output across boot |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety, and testing rules |

---

## Summarized By

[System Bootstrap](../../docs/bootstrap.md), [Build System](../../docs/build-system.md),
[Testing](../../docs/testing.md), [xtask/README.md](../../xtask/README.md)
