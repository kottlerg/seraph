# Scheduler Internals

The Seraph kernel scheduler is preemptive, priority-based, and SMP-aware, with two scheduling
classes (§ Scheduling Classes): the top levels are scheduled by strict fixed priority (RT), the
lower ones fairly, by weight. Whenever a CPU schedules (block, yield, slice expiry, or idle
wake), it selects the highest-level runnable RT thread, else the next thread of its fair queue. A
wake preempts the running thread of its CPU when the woken thread outranks it (an RT level outranks
a fair one, and a higher RT level a lower one), at that CPU's next return to user mode
(§ Wake Preemption). Otherwise a newly runnable thread waits until the running thread blocks or
yields or its slice expires. Among CPUs of equal load,
placement prefers one whose SMT siblings are idle, so threads spread across physical cores
before they share one (§ SMT Awareness).

The scheduler interacts with two subsystems:

- **IPC** — IPC parks and wakes threads through the scheduler's park, un-commit, wake and
  park-episode primitives and performs no direct context switch; the scheduler's timer path and
  death notification in turn call into IPC objects (see
  [ipc-internals.md § IPC Scheduling Interaction](ipc-internals.md#ipc-scheduling-interaction))
- **Architecture layer** — context save/restore and the preemption timer are implemented
  by the arch-dispatch surface defined in [arch-interface.md](arch-interface.md)

---

## Scheduling Algorithm

### Priority Levels

There are `NUM_PRIORITY_LEVELS` = 32 priority levels, numbered 0 (lowest) through
31 (highest):

- **Priority 0** — reserved for idle threads (one per CPU; never preempted).
- **Priorities 1–30** — available to userspace. `PRIORITY_MAX` = 30. Levels 1–20 are the fair
  class and levels 21–30 the strict-priority (RT) class (§ Scheduling Classes).
- **Priority 31** — reserved; cannot be requested by userspace.

Threads are created at an explicit priority stated at `SYS_CAP_CREATE_THREAD`
time through its `SchedControl`-cap and priority arguments: with no
`SchedControl` (both arguments zero) the thread is created at the floor
(`PRIORITY_MIN` = 1); with a `SchedControl` cap, priority 0 selects the cap's
band floor and a nonzero priority must lie within the cap's `[min, max]` band.
Priority is changed afterwards via `SYS_THREAD_SET_PRIORITY`. The kernel does
not implement dynamic priority adjustment or aging. Both syscalls' argument and error
contracts are in [syscalls.md](syscalls.md).

The one kernel-assigned exception is init's boot thread, created at
`INIT_PRIORITY` (= 30, the top settable level): init is the root of all
userspace authority and nothing may preempt it.

### Priority Authority

Assigning a priority is capability-gated. `SYS_THREAD_SET_PRIORITY` takes two
caps: a Thread cap with the Control right (selecting *which* thread) and a
`SchedControl` cap (governing *which level*). A `SchedControl` carries a
`[min, max]` priority band; the call succeeds only if the requested level lies
within that band. `SYS_CAP_CREATE_THREAD` applies the same rule at creation:
placing a new thread above the floor requires a `SchedControl` cap whose band
covers the level. There is no ambient authority — a process holding no
`SchedControl` (or one whose band excludes the level) cannot set that priority.
Lowering is not special-cased; every assignment is checked against the band. See
[syscalls.md](syscalls.md) § `SYS_THREAD_SET_PRIORITY` for the band check and its errors.

The kernel does **not** define a normal/elevated boundary. For authority the numeric
level space is uniform (how a level is scheduled is a separate matter, § Scheduling
Classes); any partition into tiers of authority is userspace policy, expressed by how
`SchedControl` bands are distributed:

- The root `SchedControl` spans `[1, PRIORITY_MAX]`, is created at boot, and is
  held by init.
- Init narrows it with `SYS_SCHED_SPLIT` into the baseline band `[1, 28]`
  (`sched_policy::BASELINE_PRIORITY_MAX` in `shared/ipc`) and an elevated
  remainder `[29, PRIORITY_MAX]` that never leaves init — init's own boot thread
  (kernel-placed at `INIT_PRIORITY` = 30) is the only occupant above the
  baseline. The remainder lives until init's reap, whose teardown of init's
  CSpace releases it, so from then on no process holds authority over
  `[29, PRIORITY_MAX]` (see
  [process-lifecycle.md § Init reap](../../../docs/process-lifecycle.md#init-reap)).
- Every spawned process receives a band through
  `ProcessInfo.sched_control_cap`. Init hands memmgr and procmgr each a copy of the
  baseline, and procmgr mints every other process's band from its copy at
  create time, whole or `SYS_SCHED_SPLIT`-narrowed to the `[1, band_max]` the
  spawner requested, and creates the child's initial thread at the requested
  level under its own baseline authority. The per-service level map is pure
  userspace policy — `shared/ipc`'s `sched_policy` module for the
  init/procmgr/devmgr/vfsd-assigned levels, svcmgr `.svc` recipes
  (`priority = ...` / `sched_max = ...`) for supervised services. The mint is specified in
  [procmgr ipc-interface.md](../../../services/procmgr/docs/ipc-interface.md) § Label 1:
  `CREATE_PROCESS`.

`SchedControl` is the sole authority; see
[capability-model.md § SchedControl](../../../docs/capability-model.md) for the
cap shape, `SYS_SCHED_SPLIT`-based band splitting, and delegation. `cap_derive`
cannot shrink a band — it attenuates rights only ([syscalls.md](syscalls.md) § `SYS_CAP_DERIVE`).

### Scheduling Classes

A level has two meanings. On the authority axis it is what a `SchedControl` band must cover
for a thread to be placed there (§ Priority Authority). On the discipline axis it also says how
the thread is scheduled once it is there, and here the kernel splits the settable levels at
`sched::RT_PRIORITY_MIN` (21) into two classes. That constant is a discipline boundary only: it
grants nothing, and which threads reach the RT levels is decided wholly by how `SchedControl`
bands are distributed. Userspace's level map places core services in the RT class and
applications in the fair one (`shared/ipc`'s `sched_policy`).

- **RT class, levels 21–30.** Strict fixed priority. A ready thread at a higher level always runs
  before one at a lower level, and threads at one level share the CPU round-robin, each with a
  slice of `TIME_SLICE_TICKS`. A thread that never blocks keeps every lower level on its CPU
  from running.
- **Fair class, levels 1–20.** Weighted round-robin. Every fair thread on a CPU is queued on one
  shared FIFO, whatever its level, and the level is its weight: its slice is its level in timer
  ticks (`sched::quantum_ticks`; 1 to 20 ticks). A turn of the queue gives each CPU-bound fair
  thread its level's worth of ticks, so CPU-bound fair threads on one CPU share it in proportion
  to their levels, and, while no RT thread is ready on its CPU, no fair thread waits more than
  one turn of the queue, however many threads sit at higher fair levels. The default spawn
  level, 10, has the same slice as an RT thread. A fair thread's level grants no precedence
  over another fair thread's.

Between the classes, RT always wins. Every scheduling decision takes a ready RT thread before
any fair one, and a running fair thread is preempted for an RT thread queued on its CPU at the
CPU's next return to user mode, as a running RT thread is for a higher RT level
(§ Wake Preemption). The preempted thread goes back to the head of its queue with the rest of
its slice, keeping its turn.

The fair accounting is per CPU: each thread's remaining slice in its TCB, and its place in its
CPU's fair queue. There is no global virtual time to keep in step across CPUs, and a migrated
thread carries its remaining slice with it. The load balancer and wake placement count queued
threads without weighing them (§ Load Balancing), so the proportional share holds between the
threads of one CPU. Across CPUs it holds only as far as the balancer evens out the counts.

Two refinements are not implemented: run-to-block scheduling within an RT level (`SCHED_FIFO`
semantics, a possible flag on the RT class) and CPU-time budgets on `SchedControl`.

### Run Queue Structure

Each CPU has 13 run queues (`NUM_RUN_QUEUES`): one per RT level (21 to the reserved 31), one
that every fair level shares, and one for the idle level. The excerpt below is abridged to the
fields this document discusses; `core/kernel/src/sched/run_queue.rs` holds the full definition:

```rust
pub struct PerCpuScheduler
{
    /// The run queues, indexed by `queue_index` of a level: the idle queue, the fair
    /// queue, then one per RT level. Each is an intrusive FIFO of ready TCBs; owned by `lock`.
    queues: UnsafeCell<[RunQueue; NUM_RUN_QUEUES]>,

    /// Bitmask with one bit set per non-empty run queue.
    /// Allows O(1) selection of the highest non-empty queue.
    non_empty: AtomicU32,

    /// Currently running TCB on this CPU.
    current: AtomicPtr<ThreadControlBlock>,

    /// The idle TCB for this CPU.
    idle: AtomicPtr<ThreadControlBlock>,

    /// Level of `current` as of its dispatch, which `timer_tick` reads for the slice
    /// bound and refill.
    current_level: AtomicU8,

    /// The `non_empty` bits of the queues above `current_level`'s, stored with it,
    /// which `outranked` ANDs with `non_empty` for the wake preemption; every bit
    /// while a priority change has left `current_level` stale (§ Wake Preemption).
    outranking: AtomicU32,

    /// Lock protecting the run queues. Held briefly during enqueue/dequeue.
    pub lock: Spinlock,

    /// Run-queue load counter (the linked threads, the idle thread included while linked);
    /// read via current_load() by the load balancer and select_target_cpu.
    load: AtomicU32,

    /// The idle pull's confirmation sample: the CPU this CPU found backlogged at its
    /// previous idle tick (§ Load Balancing).
    idle_pull_candidate: AtomicUsize,

    /// The backlog episode of that CPU the sample read (§ Load Balancing).
    idle_pull_episode: AtomicU32,

    /// This CPU's backlog episode under `lock`: made odd by `dequeue_highest` when it
    /// runs the queues dry of threads other than the idle thread, even again by the
    /// `link` that refills them (§ Load Balancing).
    backlog_episode: AtomicU32,

    /// Whether the previous idle tick held the candidate one tick more, a sibling of
    /// this CPU being busy (§ SMT Awareness).
    idle_pull_held: AtomicBool,

    /// Where the idle pull's scan starts: past the last candidate on which a pull
    /// found nothing it could take (§ Load Balancing).
    idle_pull_cursor: AtomicUsize,
}

struct RunQueue
{
    head: Option<*mut ThreadControlBlock>,
    tail: Option<*mut ThreadControlBlock>,
}
```

The queue index of a level (`queue_index`) is monotone in the level, so the highest non-empty
queue is the highest RT level with a ready thread, else the fair queue. The `non_empty` bitmask
enables O(1) selection of it: `31 - non_empty.leading_zeros()`
(`PerCpuScheduler::dequeue_highest`), the same expression on both architectures. Enqueue sets
the queue's bit; dequeue clears it if the queue becomes empty. A queue found by the load
balancer's scan (`find_runnable`) is reported as a level of that queue, the lowest fair level
for the fair queue, so the balancer's unlink and relink resolve to the same queue.

### Time Slice Policy

Each thread receives a time slice in ticks of the preemption timer; each timer interrupt
decrements a per-thread slice counter, and when the counter reaches zero the thread is
preempted and its counter refilled. The slice of an RT thread is `TIME_SLICE_TICKS` (10); that of
a fair thread is its level (§ Scheduling Classes), so the longest slice is 20 ticks, at fair level
20. With the 1 ms tick, an RT slice is 10 ms. The slice lengths and the timer period are
implementation constants, not part of the ABI.

`timer_tick` measures the slice by the level the running thread was dispatched at, which the
CPU records at each dispatch (`PerCpuScheduler::current_level`): it may not read the running
thread's `priority` without that thread's `sched_lock`. Each tick first cuts the remaining slice
to that level's quantum, then takes the tick, and an expired slice is refilled with the quantum
(`PerCpuScheduler::tick_outcome`). A priority change of a running thread marks the recorded level
stale, and the CPU records the new one at its first return to user mode with a thread queued
(§ Wake Preemption) or at the thread's next dispatch, whichever comes first; the thread's class,
the rank a wake preemption compares, and its slice from the first tick after follow that record:
until then the thread runs out the slice it holds, and from then on a thread lowered from fair 20
to 2 runs at most 2 ticks per slice, and one raised from the fair class into the RT class at most
`TIME_SLICE_TICKS`. A new thread's first slice is its creation level's.

Slice expiry never hands the CPU to a lower RT level, nor from an RT thread to a fair one: the
expiring thread is requeued at its run queue's tail and the highest non-empty queue runs next.
Within an RT level, and within the fair queue, threads share the CPU in round-robin order (FIFO
queue drained cyclically). A thread preempted by an outranking one is requeued at its queue's
head instead, so the preemption costs it no turn (§ Wake Preemption).

### Selection

```
pick_next(cpu):
    // non_empty is a bitmask over the run queues; find highest set bit
    if non_empty == 0: return idle_tcb
    q = highest_set_bit(non_empty)       // highest RT level, else the fair queue
    tcb = queues[q].dequeue()
    if queues[q].is_empty():
        non_empty &= ~(1 << q)
    return tcb
```

---

## Thread Control Block

The TCB is the kernel's per-thread state. A thread's TCB lives in its Thread slab, which
`SYS_CAP_CREATE_THREAD` retypes from the caller's Memory capability (boot code carves init's
thread from the SEED reserve): a guard page, the kernel stack, then the page holding the
`ThreadObject` and TCB, then the extended-state area and, when the kernel runs on shadow stacks,
the shadow-stack page (see
[memory-internals.md § Kernel Stack Allocation](memory-internals.md#kernel-stack-allocation)).
Idle threads' TCBs live in a per-CPU array allocated at boot. The excerpt below is abridged to
the fields this document discusses; `core/kernel/src/sched/thread.rs` holds the full definition.

```rust
pub struct ThreadControlBlock
{
    // === Scheduling state ===

    /// Current state of this thread.
    state: ThreadState,

    /// Scheduling priority (0–31).
    priority: u8,

    /// Remaining time slice ticks before preemption.
    slice_remaining: u32,

    /// Which CPU this thread is assigned to (or AFFINITY_ANY).
    cpu_affinity: u32,

    /// Soft affinity: preferred CPU (hint only; overridden by load balancing).
    preferred_cpu: u32,

    /// How wakes and the load balancer placed this thread (§ Placement Counters).
    placement: PlacementCounts,

    /// Intrusive run-queue link (next TCB in the same run queue).
    run_queue_next: Option<*mut ThreadControlBlock>,

    // === IPC state ===

    /// Inline message buffer for in-flight IPC data (the staged message).
    ipc_msg: Message,

    /// Caller bound at the call/recv rendezvous (consumed by the reply, released
    /// at the next receive, or cleared by a cancel, dealloc, or rollback claim).
    reply_tcb: AtomicPtr<ThreadControlBlock>,

    /// Wakeup value (notification bits, event payload, or wait-set member badge).
    wakeup_value: u64,

    /// Intrusive IPC wait queue links (endpoints link `ipc_wait_next` only;
    /// notifications, event queues and wait sets link both ways through
    /// `ipc::WaitQueue` and tag the queue in `ipc_wait_queue`).
    ipc_wait_next: Option<*mut ThreadControlBlock>,
    ipc_wait_prev: *mut ThreadControlBlock,
    ipc_wait_queue: AtomicPtr<WaitQueue>,

    // === Context ===

    /// Architecture-specific saved register state.
    saved_state: arch::current::context::SavedState,

    /// Kernel stack top (used to restore RSP0/kernel SP on context switch).
    kernel_stack_top: u64,

    /// Address space this thread runs in.
    address_space: *mut AddressSpace,

    // === Capability reference ===

    /// CSpace bound to this thread (set at SYS_CAP_CREATE_THREAD).
    cspace: *mut CSpace,

    // === Identity ===

    /// Unique thread identifier.
    thread_id: u32,
}
```

### Thread States

```
Created ──(SYS_THREAD_START)──► Ready ──(scheduled)──► Running
                                  ▲                       │
                                  │    (preempted or      │
                                  │     yield)            │
                                  │◄──────────────────────┘
                                  │
                          (IPC block, notification wait, etc.)
                                  │
                                Blocked
                                  │
                          (wakeup / IPC reply)
                                  │
                                  ▼
                                Ready

Running / Ready / Blocked ──(SYS_THREAD_STOP)──► Stopped
Created ──(SYS_THREAD_START, THREAD_START_SUSPENDED)──► Stopped
Stopped ──(SYS_THREAD_START)──► Ready
Running ──(SYS_THREAD_EXIT / SYS_ASPACE_EXIT)──► Exited (TCB freed at its last cap delete)
any state ──(object teardown / terminal fault)──► Exited
```

Every `Exited` transition, and the rule for each, is listed in
[thread-lifecycle-and-sleep.md](thread-lifecycle-and-sleep.md#lifecycle-state-machine)
§ Lifecycle State Machine; the stop is specified in its
[§ `sys_thread_stop` Cross-CPU Stop Protocol](thread-lifecycle-and-sleep.md#sys_thread_stop-cross-cpu-stop-protocol).

State transitions are governed by the per-field-group ownership rules in
[scheduling-internals.md](scheduling-internals.md). Cross-CPU writes to TCB
fields are subject to the lock hierarchy specified in that document.

---

## Context Switch Mechanism

### What Gets Saved and Restored

On each context switch, the arch `context::switch` function (see
[arch-interface.md](arch-interface.md) § `context`) saves and restores the minimal register
set needed for correct execution:

**x86-64 (callee-saved registers):**
- `rbx`, `rbp`, `r12`, `r13`, `r14`, `r15`
- `rip` (return address, via the call to `context::switch`)
- `rsp` (stack pointer)
- The `fs_base` MSR (TLS base pointer)
- `rflags`
- With shadow stacks on, `ssp` (the restore-token address the switch restores the thread's
  shadow stack from) and `ssp_token` (the thread's supervisor shadow-stack token, loaded into
  `IA32_PL0_SSP`)
- The kernel stack pointer is stored separately in the TSS `RSP0` field

Caller-saved registers (`rax`, `rcx`, `rdx`, `rsi`, `rdi`, `r8`–`r11`) are not saved
— by calling convention the caller has already saved them if needed.

**RISC-V (callee-saved registers):**
- `s0`–`s11` (saved registers)
- `ra` (return address — `context::switch` returns here)
- `sp` (stack pointer)
- `a0` (argument delivered on a new kernel thread's first entry; meaningful only at
  thread creation)

`tp` is not in `SavedState`: it is a per-hart kernel register that is never
thread-switched, and the user-mode TLS pointer lives in the trap frame's `tp`.

The full user register file (all 31 general-purpose registers on RISC-V, plus `sepc`
and `sstatus`) is saved in the thread's trap frame, not in `SavedState`. `SavedState`
holds only the kernel-mode callee-saved state. Floating-point, SIMD, and vector state
is in neither: it lives in the TCB's extended-state area, saved eagerly by the arch
`fpu::switch_out_save` on switch-out of a user thread and restored lazily on the
thread's first FP/SIMD/vector instruction after it is switched back in (`#NM` on
x86-64, the illegal-instruction trap with `sstatus.FS`/`VS` Off on RISC-V).

### Switch Sequence

```
context_switch(current_tcb, next_tcb):
    // 1. Update the kernel trap stack pointer so the next privilege-level
    //    transition (syscall, interrupt, or exception) lands on next_tcb's stack.
    //    x86-64: writes TSS.RSP0 and PerCpuData::kernel_rsp (the SYSCALL entry stack).
    //    RISC-V: writes PerCpuData::kernel_rsp (read by trap_entry to switch from the
    //    user stack). A kernel/idle thread passes 0.
    arch::current::cpu::set_kernel_trap_stack(next_tcb.kernel_stack_top)

    // 1b. Flush this CPU's whole TLB when next_tcb's kernel-stack guard was
    //     holed after this CPU's last guard flush, so no stale translation of
    //     the guard page outlives the switch, nor a stale not-present entry
    //     of a page filled before the hole, such as next_tcb's own kernel
    //     stack (memory-internals.md § Kernel Stack Guards).
    mm::stack_guard::flush_before_run(next_tcb.guard_epoch)

    // 2. Switch address space if different.
    if current_tcb.address_space != next_tcb.address_space:
        arch::current::paging::activate(next_tcb.address_space.root_phys)
        // Update active_cpus on both address spaces (for TLB shootdown tracking)

    // 3. Perform the register-level switch.
    //    Saves current callee-saved registers, publishes context_saved = 1 once the
    //    save is committed, restores next's, returns into next_tcb.
    arch::current::context::switch(
        &mut current_tcb.saved_state,
        &next_tcb.saved_state,
        &current_tcb.context_saved,
    )
    // Execution continues in next_tcb from here.
```

---

## SMP Scheduling

### Per-CPU Run Queues

Each CPU maintains its own `PerCpuScheduler`. Threads are assigned to CPUs. A thread
on CPU N's run queue runs only on CPU N unless migrated (see Load Balancing). This
design eliminates the need for a global run queue lock on the common path and is
cache-friendly — a thread's TCB is typically hot in CPU N's caches.

### Thread Assignment

`SYS_CAP_CREATE_THREAD` takes no affinity argument: every thread is created with
`cpu_affinity = AFFINITY_ANY` and `preferred_cpu = 0`. `SYS_THREAD_START` places it via
`select_target_cpu`. A hard affinity set by `SYS_THREAD_SET_AFFINITY` before the start wins
unconditionally. Otherwise the thread stays on `preferred_cpu` if that CPU's load
(`current_load()`) is within `LOAD_BALANCE_IMBALANCE_THRESHOLD` of the least-loaded CPU's,
and goes to the least-loaded CPU if not, a tie going to the CPU with the fewest busy SMT
siblings (§ SMT Awareness). The placement is recorded in `tcb.preferred_cpu` and used for
subsequent wakeups.

### Load Balancing

A pull-based balancer runs on every CPU's `timer_tick`: `sched::try_pull_idle` on a CPU
running its idle thread, `sched::try_pull_balance` on any other. The timer keeps firing
whatever the CPU runs, so a halted idle CPU keeps ticking: riscv64 re-arms `stimecmp` in its
interrupt handler, and x86_64 re-arms the TSC deadline there or, in periodic APIC mode,
reloads in hardware. The balancer consumes each CPU's run-queue load counter
(`PerCpuScheduler::current_load()`, maintained by `enqueue` / `dequeue_highest` /
`remove_from_queue`) and migrates at most one `Ready` thread per tick per CPU. The load is
the number of threads linked on the CPU's run queues. The running thread is not counted,
and the CPU's idle thread is counted while it is linked: the idle loop leaves the idle
thread through `schedule(Requeue::Always)`, which links it on the idle queue, where it stays
until the CPU next runs it. A CPU that left its idle thread for another so reads one more
than the threads queued behind its running one.

The balancer counts queued threads without weighing them by class or level (§ Scheduling
Classes): it evens out the number of queued threads per CPU, and `find_runnable` scans the
victim's queues from the highest, so an RT thread is pulled before a fair one.

Victim selection is mode-dependent:

- **Busy CPU, `my_load > 0`** — pick a pseudo-random victim
  (splitmix-style hash of the global `LOAD_BALANCE_TICK` counter and the
  local CPU id). Skip if the victim is not significantly busier than us
  (`their_load <= my_load + LOAD_BALANCE_IMBALANCE_THRESHOLD`).
- **Busy CPU, `my_load == 0`** — scan all other CPUs and pull from
  the heaviest, when its load exceeds `LOAD_BALANCE_IMBALANCE_THRESHOLD`. Scanning is
  cheap (one Relaxed atomic load per CPU) and guarantees the CPU finds work on the first
  tick that sees an imbalance. Pure random victim selection converges only
  probabilistically and on small topologies sometimes wastes many ticks
  before picking the busy CPU.
- **Idle CPU** (running its idle thread, its own queue empty) — a scan of the other CPUs
  in index order from its cursor (`PerCpuScheduler::idle_pull_cursor`), wrapping, and a
  pull whatever the victim's load. The heaviest CPU's load above
  `LOAD_BALANCE_IMBALANCE_THRESHOLD` is pulled at once. A smaller backlog, a thread other
  than the idle thread queued on a CPU (a bit of the run-queue mask above the idle queue's),
  is pulled once it has stood for a tick without a break: the idle CPU records the first
  such CPU in its scan's order as its candidate (`PerCpuScheduler::idle_pull_candidate`),
  with that CPU's backlog episode (`PerCpuScheduler::backlog`), and, at its next idle tick,
  pulls from that CPU if its backlog is still the same episode, else moves its cursor to the CPU
  after that one and records afresh, another CPU's backlog first when there is one. A CPU's
  backlog episode is a wrapping count, advanced under the CPU's run-queue lock, that ends a
  backlog only when the CPU's own dispatch (`dequeue_highest`) takes the last thread other than
  the idle thread: the dispatch makes the count odd, and the link that next queues such a
  thread makes it even again, so the same episode at both ticks is one backlog that the CPU
  did not run dry between them. A removal from the queues (`remove_from_queue`) ends no
  episode: a thread unlinked and linked again without running, as a priority change relocates
  it (`relocate_ready_priority`), keeps its episode, and a backlog that a pull, a migration or a
  stop empties and a link refills reads as the one before, which can cost one pull of a
  backlog that did not stand a tick, a pull the bound below allows. Threads
  time-slicing behind one another on a CPU stay one episode, since `schedule()` requeues
  the outgoing thread before it dequeues the next. An idle CPU with a busy SMT sibling holds a
  confirmed candidate one tick more before it pulls (§ SMT Awareness). A CPU whose queue
  holds only its idle thread is no backlog. The candidate is cleared after every attempt,
  when no CPU has a backlog, and on every tick the CPU runs another thread. A pull from the
  candidate that finds no thread it can take (`sched::PullOutcome::NothingPullable`: the
  backlog is pinned, or still mid-handoff) moves the cursor to the CPU after the candidate,
  so the next backlog recorded is another CPU's, and so does one whose re-check under the
  candidate's lock finds its backlog in a later episode (below). So neither a CPU whose
  backlog no pull can take nor one whose backlog keeps breaking within a tick, which would be
  recorded afresh at every tick, hides a backlog behind it. The scan is `sched::idle_scan`, the
  decision `sched::idle_pull_step`, and the tick `sched::idle_pull_tick`.

The idle CPU's pull below the threshold is what keeps a thread from starving while a CPU
idles. A thread queued behind a running thread that never blocks or yields to its level
(an RT thread spinning on a lock the queued thread holds, under § Scheduling Classes'
strict priority) stays queued for as long as that thread runs. The threshold does not see
one queued thread as an imbalance (a load of 2 with the linked idle thread), and
`select_target_cpu` keeps a woken thread on its preferred CPU at that load. An idle CPU
therefore pulls it, or another queued thread, within 2 + 2k + 2d + 2r idle ticks: one tick to
record it and one to pull it, plus what each other outcome of an idle tick costs. An idle CPU
with a busy SMT sibling holds each confirmed candidate one tick before it pulls (§ SMT
Awareness), so each two-tick cost below is three for it, and its bound is 3 + 3k + 3d + 3r;
the outcomes that cost no tick still cost none, since a pull above the threshold is not held.

- Recording a CPU ahead of it in the cursor's order whose queued threads no pull can take
  (pinned, or mid-handoff) costs two ticks: one to record that CPU and one to find nothing
  on it, after which the cursor passes it. k counts these CPUs.
- A deferred pull (`sched::PullOutcome::Deferred`) costs at most two ticks. A pull is
  deferred when a try-lock is contended, or when the revalidation under the thread's
  `sched_lock` refuses a thread that `sys_thread_set_affinity` pinned after the pick (below).
  A deferred pull from the candidate costs the tick it defers and one more to record a
  candidate again, since every attempt clears the candidate. A deferred pull above the
  threshold costs at most the tick in which the rule keeps its victim as the candidate, or
  records it in the backlog's place. d counts these pulls.
- Recording a candidate whose backlog clears before the pull from it, the thread running on
  its own CPU, costs at most two ticks: the one that recorded it, and the pull's when the
  pull, rather than the next tick's check, finds it cleared or in a later episode. r counts
  these candidates, a backlog that clears and forms again among them; each moves the cursor
  past its CPU, where the next scan starts, so the cursor only moves forward and r counts at
  most the CPUs ahead of the thread's in the cursor's order. The
  queued thread the bound is for cannot be one: its CPU's queues hold it, so no dispatch runs
  them dry and its backlog stays one episode until it runs, whatever unlinks and re-links it
  on that CPU meanwhile.
- A pull above the threshold that the re-check of its rule refuses
  (`sched::PullOutcome::RuleFailed`) or that finds nothing pullable
  (`sched::PullOutcome::NothingPullable`) costs no tick, since the confirmation rule decides
  the same tick (below). So the heaviest CPU, when its load is past the threshold with
  nothing pullable on it, costs nothing; any other CPU past the threshold with nothing
  pullable on it is recorded, and counts in k.

The rule stays bounded: only an idle CPU pulls below the threshold, and a pull leaves it busy, so
two busy CPUs never trade threads (the steady state the threshold protects); a busy CPU with nothing
queued but its idle thread draws no attempt; a backlog its CPU's dispatch runs dry between two idle
ticks, even one that forms again, stays with the CPU whose caches hold it (one that a removal
empties and a link refills reads as the one before, above); and a backlog of pinned threads, which
no pull can take, draws at most one try-lock attempt per idle CPU every two ticks (three for an
idle CPU with a busy SMT sibling) while its load reads at or below the threshold (above it, one per
idle CPU every tick, and two in a tick whose pull above the threshold moves nothing while a
candidate is confirmed).

A backlog that drains within a tick is not the pull's to spread: where its threads run is wake
placement's ([scheduling-internals.md](scheduling-internals.md) § Target CPU selection
(`select_target_cpu`)). The episode leaves such a backlog on its CPU even when its threads
could run in parallel. Two threads that hand work to one another in turns, each queued behind
the other for far less than a tick, so stay on one CPU, and their round trips wake no halted
CPU; an asynchronous producer and consumer whose every handoff drains within a tick stay
there too, since the pull does not spread them either. Two unpinned threads that each wait on a
thread of another CPU, such as the clients of two servers, can likewise come to share one CPU
while another idles, and stay there while each wake keeps them there (the sticky preferred CPU of
`select_target_cpu` stays within the threshold of the least-loaded CPU). What the episode leaves
is bounded by the threshold: a load above it is pulled at once, so a backlog the pull leaves to
break and re-form is one at a load of at most `LOAD_BALANCE_IMBALANCE_THRESHOLD` (2), the
running thread and one queued behind it. Whether a wake should place any of these by its waker,
or away from it, is open (#1560).

The loads that choose a pull are read without the CPUs' locks, and a CPU's `schedule()`
raises its own load for a moment under its lock: it counts every requeue of the running
thread on its own queues (such as a slice expiry, a yield, a wake preemption, the idle loop
leaving its idle thread, or a park a wake overtook, which `Requeue::IfRunnable` requeues)
before the dequeue that follows (a requeue its affinity routes to another CPU raises that
CPU's load instead, as a wake there would). A reading taken while the load is raised can pass the
threshold at a load that, settled, fails it, and a load can also change between the reading
and the pull. The pull therefore decides its rule again under the two run-queue locks, where
every load change has completed, and moves nothing when it no longer holds
(`sched::PullRule`): a pull above the threshold, a busy CPU's or an idle CPU's, re-checks that
the victim's load exceeds the puller's by more than `LOAD_BALANCE_IMBALANCE_THRESHOLD`; an idle
CPU's pull from its confirmed candidate re-checks no load but that the victim's backlog is
still the episode it confirmed, which under the victim's lock is exact, and the locked pick of
a queued unpinned thread takes from that backlog. An idle CPU whose pull above the threshold
moves nothing applies the confirmation rule in the same tick: it records or pulls its
candidate as if the scan had seen no load past the threshold. When the victim had no thread a
pull can take, the rule reads a second scan that leaves that victim out, and a candidate other
than it. When the re-check refused the pull, the load it read was a transient, and a deferred
pull (most often a contended try-lock, the outcome of a read taken while the victim's
`schedule()` holds its lock) says nothing of what the victim holds; in both cases the victim
may hold a backlog of its own, so the rule reads the same scan and candidate. After a deferred
pull, a pull the rule would make from the victim itself waits for the next tick, which keeps
the victim as the candidate, rather than try its locks a second time. So neither a scan that
keeps reading a transient nor a CPU whose pinned threads keep its load past the threshold
hides a backlog beyond the ticks the bound above counts for deferred pulls.

Migration goes through `pull_unpinned_ready(src_cpu, dst_cpu, rule)`, which shares the
validate-then-move core `relocate_ready_thread` with `migrate_ready_thread`:

```
pull_unpinned_ready(src, dst, rule):
    if !try_lock(min(src, dst).scheduler.lock): return   // ascending-CPU order
    if !try_lock(max(src, dst).scheduler.lock):
        unlock(min); return
    if !rule.passes(src.current_load(), src.backlog(), dst.current_load()):
        unlock both; return RuleFailed                   // the caller's reading no longer holds
    (tcb, prio) = src.find_runnable(|t| t.cpu_affinity == AFFINITY_ANY
                                        && t.context_saved.load(Acquire) == 1)
    if tcb is None: unlock both; return NothingPullable  // pinned or mid-handoff only
    if !try_lock(tcb.sched_lock): unlock both; return  // taken after run-queue locks
    // relocate_ready_thread: revalidate under sched_lock, then move.
    moved = false
    if tcb.state == Ready && tcb.context_saved == 1
       && (tcb.cpu_affinity == AFFINITY_ANY || tcb.cpu_affinity == dst):
        src.remove_from_queue(tcb, prio)       // decrements src's load counter
        dst.enqueue(tcb, prio)                 // increments dst's load counter
        tcb.preferred_cpu = dst
        moved = true
    unlock tcb.sched_lock; unlock both
    if moved: wake_idle_cpu(dst)               // always-IPI
```

The `context_saved == 1` predicate is the load-balancer liveness gate of
[scheduling-internals.md](scheduling-internals.md) § Cross-CPU TCB Ownership step 11: a
`Ready` thread with `context_saved == 0` is mid-handoff, still `current` on `src`, and
relocating it would dispatch it on two CPUs at once (#314/#293). The candidate's
`sched_lock` is try-acquired because it is taken after the run-queue locks, the reverse of
the canonical order; a failed try defers the pull. `relocate_ready_thread` re-checks
`Ready`, `context_saved == 1`, and affinity under that `sched_lock`. This closes the race
with `sys_thread_set_affinity` between the `find_runnable` predicate and the move: that
syscall writes `cpu_affinity` under the same `sched_lock`, so a pin committed before the
re-check refuses the move, and one committed after it finds the thread already on `dst`
and migrates it (or, once dispatched there, moves it at its next `schedule()`
cross-affinity requeue).

Lock order follows [scheduling-internals.md](scheduling-internals.md) § Lock Hierarchy rule 4
(ascending CPU id), and both acquisitions are **try-locks**: the pull runs
from every CPU's timer tick with interrupts disabled, and under a
pinned-heavy imbalance every idle CPU converges on the same victim every
tick. Queuing there forms a FIFO ticket convoy of interrupts-off spinners
that silences ticks, IPIs, and serial output system-wide and livelocks the
guest under host vCPU oversubscription (#375). A contended pull is simply
deferred to a later tick. Pinned threads (`cpu_affinity != AFFINITY_ANY`)
are invisible to the `find_runnable` predicate and are never migrated.

Hot-path cost per CPU per tick:
- Idle CPU: one Relaxed load of its own load, one Relaxed load of the load per remote CPU to find
  the heaviest victim, one Acquire load of the run-queue mask per remote CPU whose load is non-zero
  up to the first with a queued thread and one Relaxed load of that CPU's backlog episode, one
  Relaxed load each of its own candidate, its episode and its cursor, one Acquire load of the
  candidate's run-queue mask and one Relaxed load of its backlog episode, and a Relaxed store of its
  own candidate and episode (and of its cursor when a pull from the candidate found nothing
  pullable), fields only this CPU writes. A pull above the threshold that finds nothing pullable
  adds a second scan of the same cost. Each idle tick also loads its own `idle_pull_held` (Relaxed)
  and stores it with its candidate, and a confirmed candidate not held the tick before adds a
  `has_no_work` read of each of the idle CPU's SMT siblings (§ SMT Awareness).
- Busy CPU: one Relaxed load of its own candidate (a store only on the first busy tick
  after an idle one) and one of its own load, plus, with an empty queue, one Relaxed load
  per remote CPU, or, with queued threads, one Relaxed increment + one Relaxed load for the
  victim.
- Scheduler locks are try-acquired: by a busy CPU only when an imbalance above
  `LOAD_BALANCE_IMBALANCE_THRESHOLD` is observed, and by an idle CPU when the idle rule
  above decides a pull (a second time in the tick when a pull above the threshold moves
  nothing and the confirmation rule pulls the candidate). Under both locks the pull
  makes one Relaxed load of each CPU's load, and one load of the victim's run-queue mask and
  backlog episode, for the re-check.
- `link`, under the run-queue lock it already holds: one Relaxed load of the run-queue mask
  and, when the queues hold no thread but the idle thread, one Relaxed load of the episode and,
  when it starts a backlog episode, a Relaxed store of it. `dequeue_highest`, under the same
  lock: when its dequeue leaves no thread but the idle thread queued, one Relaxed load and
  store of the episode.

### Placement Counters

Each thread carries four counters of how its wakes and the load balancer placed it
(`thread::PlacementCounts`, the TCB's `placement`), which `SYS_CAP_INFO`'s
`CAP_INFO_THREAD_PLACEMENT` reads with the thread's CPU
([syscalls.md](syscalls.md#sys_cap_info-36) § `SYS_CAP_INFO` (36)). They are diagnostics: no
kernel path reads them to decide. ktest's round-trip benchmarks report them for the two threads of
each round trip, so a result line names whether the round trips stayed on one CPU or paid a wake
of another ([core/ktest/README.md](../../ktest/README.md)).

| Counter | Counts |
|---|---|
| `remote_wakes` | Wakes (`enqueue_and_wake`) that linked the thread on a CPU other than the waker's, each of which sent that CPU a wake IPI ([scheduling-internals.md](scheduling-internals.md#wake-protocol-invariants) § Wake Protocol Invariants) |
| `idle_wakes` | Of those, the wakes whose CPU ran its idle thread at the link, which halts while it has no work, so that the thread waited for the CPU to leave its halt |
| `wake_moves` | Wakes that linked the thread on a CPU other than its `preferred_cpu` |
| `pulls` | Load-balancer pulls that moved the thread (`pull_unpinned_ready`, § Load Balancing) |

A wake counts only when it links the thread: a wake that finds it running, already linked, stopped
or exited counts nothing. A thread's start, an affinity migration and a requeue of the running
thread are not wakes. Every increment holds the thread's `sched_lock`, so each counter has one
writer at a time and a load and a store make the increment; a reader takes no lock and reads each
counter `Relaxed`, a snapshot. Each counter is a free-running 32-bit count that wraps, so a reader
takes the wrapping difference of two reads. The CPU the selector reports is `preferred_cpu`, read
under the thread's `sched_lock`: the CPU the thread was last linked on or dispatched on.

---

## SMT Awareness

On systems with Simultaneous Multi-Threading (Hyper-Threading on Intel, SMT on AMD),
multiple logical CPUs share physical execution resources on the same core. The kernel records
which CPUs share a core and, among CPUs of equal load, places work on a CPU whose siblings are
idle, so threads spread across cores before they share one.

SMT siblings are not an isolation boundary. The scheduler places threads of different processes
on the siblings of one core at once, and contention for the resources the siblings share is a
channel between them; the scheduler does no core scheduling by trust, and core scheduling keyed
on a security domain is not implemented ([#1086](https://github.com/kottlerg/seraph/issues/1086)).
The system's posture is [docs/capability-model.md](../../../docs/capability-model.md)
§ Microarchitectural Isolation.

### Topology Detection

Each CPU records its core key, a value equal for exactly the logical CPUs that share one core
(`arch::current::cpu::core_key`, [arch-interface.md](arch-interface.md) § cpu), in its
slot of the per-CPU `CORE_SLOTS` slab (`topology::record_this_cpu`): the boot CPU in
Phase 8 before it starts the APs, each AP in `kernel_entry_ap` before it reports itself
online.

- **x86-64**: the x2APIC ID with the SMT level's bits shifted out. The topology leaf is
  `CPUID` 1FH where the CPU enumerates it, else 0BH; the shift is the `EAX[4:0]` of its SMT
  level (level type 1). A CPU with no SMT level shifts by 0, each logical CPU a core of its own,
  and a CPU whose leaf enumerates no level keys by its CPU index, with the same result.
- **riscv64**: each hart is a core of its own, keyed by its CPU index. The ISA defines no
  register that names a hart's core; the platform describes the grouping in the device tree
  (`cpu-map`) or ACPI (PPTT), which the bootloader does not parse. That parsing waits until a
  platform Seraph supports has multithreaded harts.

Once every AP is online, the boot CPU links each core's CPUs into a ring
(`topology::build_sibling_rings`): the per-CPU `SIBLING_RING` slab holds, for each CPU, the
next CPU of its core in ascending index order, wrapping, and a CPU alone on its core links to
itself. The boot CPU halts by name when a CPU recorded no key, and logs
`topology: N core(s), at most M thread(s) per core`. It publishes the ring with a Release
store; it is read-only from then on, and a reader before the publication sees no siblings. A
ring holds one entry per CPU, where a CPU set per core would cost a CPU-count-wide mask per core
([docs/coding-standards.md](../../../docs/coding-standards.md) § CPU-Count Width), and a reader
walks only the CPUs of one core. `SYS_SYSTEM_INFO(SmtSibling)` reports it
([syscalls.md](syscalls.md) § SYS_SYSTEM_INFO).

### Scheduling Preference

A sibling is busy when `PerCpuScheduler::has_no_work` fails for it: it runs a thread other
than its idle thread, or queues one. The read is lockless and Relaxed, and a sibling that
changes state under it costs one placement its tie-break, never correctness.

- **Placement** (`select_target_cpu`, § Thread Assignment): a tie on the least load goes to
  the CPU with the fewest busy siblings, then to the lowest index. The rings are walked only for
  the CPUs that tie on the least load seen so far, and no more once a CPU of an idle core holds
  it. The sticky preferred CPU is still taken first when its load is within the threshold, since
  the caches it holds outweigh the spread, and a hard affinity still wins.
- **Idle pull** (`try_pull_idle`, § Load Balancing): idle CPUs decide independently, each at
  its own tick, so the preference is a delay. An idle CPU that would pull from its confirmed
  candidate while one of its siblings is busy holds the candidate for one tick, once
  (`sched::IdlePullStep::Hold`, recorded in `PerCpuScheduler::idle_pull_held`); an idle CPU
  of an idle core that confirms the same backlog in that tick pulls it first. A pull above the
  threshold is not held, since a load past it is an imbalance rather than a tie. The hold raises
  that CPU's bound to 3 + 3k + 3d + 3r ticks (§ Load Balancing).
- A busy CPU's pull (`try_pull_balance`) takes no account of siblings: its own core is busy
  already.

The preference is soft: when every core has a busy CPU, threads go to siblings as the loads
direct, and affinity is unchanged. On a machine without SMT every CPU is alone on its core, no
CPU has a busy sibling, and placement and the idle pull behave as they would without the
preference.

---

## Preemption

### Timer-Driven Preemption

The preemption timer (started on the BSP in
[Phase 5](initialization.md#phase-5-architecture-hardware-initialisation) and on each AP
during its [Phase 8](initialization.md#phase-8-scheduler-and-smp-bringup) startup) fires at
the configured periodic interval on each CPU. The tick handler, `timer_tick`, runs:

```
timer_tick():
    if cpu == 0:                              // BSP only
        sleep_check_wakeups(); watchdog_tick_and_check()
    match tick_outcome(current.slice_remaining):   // PerCpuScheduler::tick_outcome
        Idle:                                 // zero slice: the idle thread
            try_pull_idle(cpu); return
        Continue(remaining):
            current.slice_remaining = remaining; reschedule = false
        Expired:
            current.slice_remaining = quantum_ticks(current_level); reschedule = true
    try_pull_balance(cpu)
    if !reschedule: return
    if preemption_disabled(): return          // see § Kernel-Mode Preemption Points
    schedule(Requeue::Always)                 // requeue at its queue's tail, then dequeue_highest
```

Only CPU 0's tick services the sleep list (`sleep_check_wakeups`) and runs the softlockup
watchdog (`watchdog_tick_and_check`), so no other CPU's tick wakes a timed-out sleeper (see
[thread-lifecycle-and-sleep.md § Sleep List Invariants](thread-lifecycle-and-sleep.md#sleep-list-invariants)).

On slice expiry the current thread goes back to the tail of its run queue (its RT level's, or
the fair queue), and `dequeue_highest` picks the next thread. If no other thread is queued in
its run queue or a higher one, the current thread is reselected and keeps running with no
context switch, even though its slice expired.

This ensures that a thread alone at the highest non-empty queue is never preempted needlessly
— only when a peer or superior competitor exists.

The tick does not decide a preemption by a queued thread that outranks the running one: that is
decided at the interrupt's return to user mode, as at every other (§ Wake Preemption).

### Wake Preemption

A thread queued on a CPU outranks the CPU's running thread when the highest non-empty run queue
other than the idle queue is above the queue of the running thread's level
(`PerCpuScheduler::outranked`): any RT level outranks a fair level and the idle level, and a
higher RT level a lower one. No level outranks its own, so one fair level never outranks another,
all of them sharing the fair queue, and threads of one RT level share it round-robin. The running
level is the one the CPU recorded at the thread's dispatch, or re-recorded after a change of its
priority (`current_level`, § Time Slice Policy).

The test each return makes is one AND: `PerCpuScheduler::set_current_level` stores, beside the
level, the `non_empty` bits of every queue above the level's queue (`outranking`), so a queued
thread outranks the running one exactly when `non_empty & outranking` is not zero. A return
reaches its CPU's scheduler through `PerCpuData::scheduler`, a pointer to the CPU's own entry of
the scheduler slab that `percpu::init_storage` sets once: on x86-64 at `gs:[88]`
(`PERCPU_SCHEDULER_OFFSET`), on riscv64 at `88(tp)`. The test is inlined at each return as one
load of that pointer, the loads of `non_empty` and `outranking`, an AND and a branch
(`sched::preempt_if_outranked`); only a hit calls the rest of the decision
(`sched::preempt_outranked`). Counted under icount at one CPU, the test adds 6 instructions to
a syscall on x86-64 and 5 on riscv64 in the release profile, 10 and 8 in the debug profile, whose
checks of the pointer's alignment and nullness the release profile drops. Both words are read
Relaxed: a link the CPU made itself precedes the test in program order, and a link from another
CPU is followed by its wake IPI, whose own return tests again
([scheduling-internals.md](scheduling-internals.md#wake-protocol-invariants) § Wake Protocol
Invariants).

A change of a running thread's priority reaches its CPU through that mask.
`sys_thread_set_priority` writes `priority` and reads `state` under the thread's `sched_lock`,
and every site that records a level from a thread's `priority` holds the same lock and makes the
thread `Running` in the same critical section: `schedule()`'s dispatch flip, under the incoming
thread's lock, and its same-thread re-mark and the decision's re-record below, under the running
thread's. The other records read no thread's priority: the idle level, and `sched::enter`'s boot
dispatch of init, before any other thread exists. So a record after the change reads the new
priority, and a change after a record finds the thread `Running`. The change then marks the
level of the CPU its `preferred_cpu` names (the CPU running it, written with the flip under the
same lock) stale before it releases the lock: `PerCpuScheduler::mark_level_stale` stores every
bit in `outranking`, which no level's mask has. It then prods the CPU, a no-op for the caller's
own. The next return to user mode there with any thread queued hits. The decision re-records the
level from `priority` under the thread's `sched_lock` and decides again, so a thread lowered
below a queued one yields at that return. A later dispatch overwrites the mark with the incoming
thread's level, read under that thread's lock.

A CPU decides at every return to user mode that can follow a link with no wake IPI pending
(`sched::preempt_if_outranked`), and when a queued thread outranks the running one it calls
`schedule(Requeue::Preempted)`:

- the end of every syscall (`syscall::finish_syscall`), after the syscall delivery point of
  upcalls ([fault-handling.md](../../../docs/fault-handling.md#asynchronous-upcalls) § Asynchronous
  Upcalls): a self-wake the syscall made, or a wake IPI a preemption-disabled window absorbed;
- the end of every interrupt taken from user mode (x86-64 `irq_dispatch`, riscv64
  `trap_dispatch`), after the handler's acknowledgement, the sole-reference drain pass
  ([capability-internals.md](capability-internals.md#sole-reference-observers) § Sole-Reference
  Observers) and the interrupt delivery point of upcalls: the wake IPI of a cross-CPU wake, the
  timer, device and TLB-shootdown interrupts, whose handlers can wake a thread on the CPU
  themselves, and the drain's posts, which can too;
- the end of every exception taken from user mode that resumes the thread (x86-64
  `exception_handler` and `page_fault_handler`, riscv64 `trap_dispatch`): fault delivery can
  link a thread on the CPU and absorb a wake IPI in a preemption-disabled window.

Where the return is an upcall delivery point, the delivery comes first and the decision after it,
and a thread the decision preempted passes the delivery point again, then the decision, when it is
dispatched again (`sched::deliver_and_preempt`). An upcall posted while it waited on the run
queue, for which no CPU is prodded since the thread runs nowhere, is so delivered at this return,
and a thread a delivery linked on the CPU, or whose wake IPI a delivery absorbed, is decided before
the thread returns. An exception's return is no delivery point, but a thread preempted there
passes the interrupt delivery point when it is dispatched again, as a thread an interrupt preempted
does (`sched::preempt_at_exception_return`;
[fault-handling.md](../../../docs/fault-handling.md#delivery-points) § Delivery points).

Two returns to user mode make no decision. The x86-64 `#NM` lazy FPU restore runs with interrupts
masked and preemption disabled throughout and links nothing, so an IPI raised meanwhile is taken
in user mode as it returns. A new thread's first entry to user mode follows the dispatch that
chose it as its CPU's highest, with interrupts masked until it reaches user mode, where a later
link's IPI is taken. The decision is skipped during the BSP boot transient, while preemption is
disabled, and for the idle thread, whose loop takes queued work itself (§ Idle Thread). Syscall
context stays non-preemptible (§ Kernel-Mode Preemption Points): a wake made or absorbed inside a
syscall takes effect at its exit.

`Requeue::Preempted` links the preempted thread at the head of its own queue, keeping its
remaining slice, in both classes: it has not finished its turn, and at the tail every peer of its
level would overtake it, costing it a turn per outranking wake and, for a fair thread, breaking
the one-turn bound of § Scheduling Classes. Slice expiry and a yield requeue at the tail
(`Requeue::Always`). A preempted thread whose hard affinity now names another CPU is linked at
that CPU's tail, as any requeue its affinity routes there (§ Active migration on affinity change).

**Latency bound.** A cross-CPU wake of an RT thread onto a CPU whose running thread it outranks
runs within the waker's release of the thread's `sched_lock` and of the target's run-queue lock,
the wake IPI's delivery, the target's longest interval with interrupts masked or preemption
disabled (bounded by
[scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) and by the
length of the syscall the target is in), and `schedule()` with its switch; there is no tick term.
A self-wake runs at the waker's syscall or interrupt exit. A timed wake adds the rounding of its
deadline to CPU 0's next tick (at most one tick), CPU 0's own interval with interrupts masked,
and the sleep batch's claims ahead of it
([thread-lifecycle-and-sleep.md](thread-lifecycle-and-sleep.md#sleep-list-invariants) § Sleep List
Invariants, invariant 6). The bound holds for the CPU the wake's placement chose. Placement does not
weigh levels (§ Soft Affinity), so an RT wake can be placed behind a running thread of its own or a
higher level and wait for it to block, yield or expire. Two wakes placed on one CPU at once can
likewise leave the lower waiting until the higher blocks or expires; closing that residual needs an
RT pull (a CPU running a lower level taking a waiting RT thread at its tick), which is not
implemented.

**Timed wakes** stay on CPU 0's tick (§ Timer-Driven Preemption): every ABI timeout is in
milliseconds and the tick is 1 ms, so a one-shot timer buys no resolution the ABI can ask for, and
one sleep list serviced by one CPU keeps its batch and quiesce invariants
([thread-lifecycle-and-sleep.md](thread-lifecycle-and-sleep.md#sleep-list-invariants) § Sleep List
Invariants). The wake that CPU 0's tick makes preempts wherever it is placed, as any other wake.

### Kernel-Mode Preemption Points

Syscall context is not preemptible. Syscall entry masks interrupts, and they stay masked
for the whole syscall except in bounded preempt-disabled, interrupt-enabled windows. When
`timer_tick` reaches a slice expiry while `percpu::preemption_disabled()` holds, it resets
the slice and skips the switch, and the thread is rescheduled at its next slice expiry, or at its
next return to user mode when a queued thread outranks it (§ Wake Preemption), which is decided
only there. Kernel-mode preemption therefore happens only at a slice-expiry tick with preemption
enabled.
The model, the spinlock hold-time bound, and lock ordering are specified in
[scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) (its
numbered ordering rules and the "Lock primitive" and "Bare spin locks" paragraphs).

---

## Idle Thread

Each CPU has one idle thread (priority 0) that runs when no other thread is ready.

Each iteration of `idle_thread_entry` first drains this CPU's deferred-reclaim queue
(`cap::object::drain_deferred_reclaim`) with interrupts enabled. While its run queues are empty
and the sole-reference table still has work, it runs further drain passes
(`cap::sole_reference::drain`), each bounded by `POST_BUDGET`
([capability-internals.md](capability-internals.md#sole-reference-observers) § Sole-Reference
Observers). It then masks interrupts
and checks `has_runnable`. If the run queues hold work, it re-enables interrupts and calls
`schedule(Requeue::Always)`, then loops. Otherwise it halts through the atomic enable-and-halt
`arch::current::cpu::halt_until_interrupt`.
Masking before the check means a wake IPI that lands between the check and the halt stays
pending and ends the halt. The protocol is specified in
[scheduling-internals.md](scheduling-internals.md#wake-protocol-invariants) § Wake Protocol
Invariants.

The idle thread makes no wake-preemption decision of its own (§ Wake Preemption): for the idle
level every queued thread outranks the running one, so the loop's `has_runnable` check is that
decision.

The timer never preempts the idle thread. Its `slice_remaining` is fixed at 0, and
`timer_tick` returns before the decrement for a zero slice; the check keys on the zero
slice, not on priority 0. Because its time slice is permanently zero, the timer never
deschedules it inside a teardown wait. The idle thread yields voluntarily via
`schedule(Requeue::Always)` when its run queue has work.

---

## Priority Inversion Mitigation

The kernel does not implement priority inheritance. The rationale: priority inheritance
adds significant complexity for a benefit that only applies to mutex-based shared
state, which Seraph avoids by design (message passing preferred over shared memory).

The primary locking primitive in the kernel is a spinlock, not a blocking mutex.
Spinlocks do not cause priority inversion: no context that holds one can be descheduled, so
a waiter spins only for the holder's bounded hold time, never behind a preempted holder.
Spinlock-hold intervals are bounded by policy
([scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy),
"Lock primitive").

If priority inversion is observed in practice at the userspace IPC level (a
high-priority thread blocked waiting for a low-priority server), the correct fix is
to place the server in the RT class, at a level above its clients (within the fair class a higher
level grants no precedence), not to add kernel priority inheritance.

---

## Affinity

### Hard Affinity

`tcb.cpu_affinity != AFFINITY_ANY` specifies a single CPU the thread must run on.
Wakeups always enqueue the thread on the specified CPU's run queue. If the
specified CPU id is not below `CPU_COUNT`, `SYS_THREAD_SET_AFFINITY` fails with
`InvalidArgument`. `SYS_CAP_CREATE_THREAD` takes no affinity and creates every thread with
`cpu_affinity = AFFINITY_ANY`.

Hard affinity is intended for:
- Interrupt-handling threads that must run on specific CPUs (NUMA, IRQ affinity)
- Real-time threads that must not suffer migration latency

### Active migration on affinity change

`SYS_THREAD_SET_AFFINITY` starts the migration during the call rather than leaving it to the
next enqueue ([syscalls.md](syscalls.md) § `SYS_THREAD_SET_AFFINITY`). Clearing to
`AFFINITY_ANY`, or naming the CPU in the thread's `preferred_cpu`, does no migration work.
Otherwise, by target state:

- **Ready** thread queued on the old CPU: the syscall, holding the target's `sched_lock`,
  calls `migrate_ready_thread`. It takes both scheduler locks (lower-numbered CPU first; see
  [scheduling-internals.md](scheduling-internals.md) § Lock Hierarchy rule 4) and revalidates
  `Ready`, `context_saved == 1`, and the affinity under them (`relocate_ready_thread`). It
  then moves the TCB from the source CPU's run queue to the destination's; on a committed
  move the syscall sends a wakeup IPI to the destination once it has released
  `sched_lock`. A lost race leaves the thread where it is.
- **Running** thread on a different CPU: the syscall sends a wakeup IPI to
  the **source** CPU (where the thread is currently running). The IPI itself
  does not call `schedule()`; the running thread observes the new
  affinity at its next entry to `schedule()` — preempt-on-slice-expiry,
  a preemption by an outranking thread (§ Wake Preemption), voluntary
  yield, or IPC block. The re-enqueue site in `schedule()`
  checks `cpu_affinity != current_cpu` and routes the requeue cross-CPU —
  linking the thread directly on the destination's run queue and IPIing
  it — instead of doing a local enqueue
  (see [scheduling-internals.md](scheduling-internals.md) § ThreadState Transitions).
  Worst-case latency is therefore one time slice of the thread (its slice
  length × tick period: `TIME_SLICE_TICKS` for a thread dispatched at an
  RT level, its level, at most 20, for one dispatched at a fair level; see
  § Time Slice Policy), not one tick.
- **Blocked / Stopped / Created**: the new affinity takes effect on the
  next enqueue (a wake, or `SYS_THREAD_START` on start or resume) via
  `select_target_cpu`; no migration work is needed.

The syscall writes `cpu_affinity`, reads `preferred_cpu` and `state`, and performs the
migration under the target's `sched_lock`, and prods the acting CPU after releasing it.
`lookup_cap` pins the target Thread for the call (see
[capability-internals.md](capability-internals.md) § Storage: Hybrid Radix Directory), so a
concurrent delete of its last capability frees it only after the call returns.

### Soft Affinity

`tcb.preferred_cpu` records the CPU the thread was last assigned to. The
wake-side placement (`select_target_cpu`) honours it as a sticky cache-
warmth hint: it scans all CPUs for `min_load`, and if `preferred_cpu`'s
load is within `LOAD_BALANCE_IMBALANCE_THRESHOLD` of `min_load`, the
thread is re-placed on its preferred CPU. Beyond that threshold the
thread is migrated to the least-loaded CPU. The threshold is the same
hysteresis a busy CPU's pull uses to decide an imbalance is real, so
soft affinity, wake placement, and the busy-CPU pull share one knob; an
idle CPU pulls below it (§ Load Balancing).

Hard affinity (`cpu_affinity != AFFINITY_ANY`) and save-window pinning
(`context_saved == 0`) both short-circuit ahead of the soft-affinity
check; see `select_target_cpu` in `core/kernel/src/sched/mod.rs` for
the full policy.

The scheduler does not expose soft affinity as a syscall parameter — it is an internal
optimisation.

---

## Summarized By

[core/kernel/README.md](../README.md), [Kernel Initialization Sequence](initialization.md),
[IPC Subsystem Internals](ipc-internals.md),
[SMP Scheduling and Locking Invariants](scheduling-internals.md),
[Syscall Interface Specification](syscalls.md),
[Architecture Overview](../../../docs/architecture.md),
[runtime/ruststd/README.md](../../../runtime/ruststd/README.md)
