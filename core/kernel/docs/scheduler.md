# Scheduler Internals

The Seraph kernel scheduler is preemptive, priority-based, and SMP-aware, with two scheduling
classes (§ Scheduling Classes): the top levels are scheduled by strict fixed priority (RT), the
lower ones fairly, by weight. Whenever a CPU schedules (block, yield, slice expiry, or idle
wake), it selects the highest-level runnable RT thread, else the next thread of its fair queue. A
wake does not preempt a running thread, with one exception: a running fair thread is preempted at
the next timer tick while an RT thread is queued on its CPU. Otherwise a newly runnable thread
waits until the running thread blocks or yields or its slice expires. Using SMT topology to
spread threads across physical cores rather than packing them onto one is design intent, not
yet implemented ([#267](https://github.com/kottlerg/seraph/issues/267)).

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
any fair one. A fair thread that is running when an RT thread is queued on its CPU is preempted
at the next timer tick (§ Timer-Driven Preemption), and goes back to the tail of the fair queue
with the rest of its slice. A wake itself does not preempt: an RT thread woken onto a CPU that
runs a fair thread waits for the next tick, or, when that tick finds preemption disabled
(§ Kernel-Mode Preemption Points), for the first later tick that finds it enabled. Immediate
preemption at the wake is not implemented.

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
    /// bound and refill and the RT-over-fair preemption.
    current_level: AtomicU8,

    /// Lock protecting the run queues. Held briefly during enqueue/dequeue.
    pub lock: Spinlock,

    /// Run-queue load counter; read via current_load() by the load balancer and select_target_cpu.
    load: AtomicU32,
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
(`PerCpuScheduler::tick_outcome`). A priority change of a running thread therefore reaches its
class at its next dispatch, and its slice at the first tick after that dispatch: until then the
thread runs out the slice it holds, and from then on a thread lowered from fair 20 to 2 runs at
most 2 ticks per slice, and one raised from the fair class into the RT class at most
`TIME_SLICE_TICKS`. A new thread's first slice is its creation level's.

Slice expiry never hands the CPU to a lower RT level, nor from an RT thread to a fair one: the
expiring thread is requeued at its run queue's tail and the highest non-empty queue runs next.
Within an RT level, and within the fair queue, threads share the CPU in round-robin order (FIFO
queue drained cyclically).

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
`ThreadObject` and TCB, then the extended-state area (see
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
Running ──(SYS_THREAD_EXIT / SYS_PROCESS_EXIT)──► Exited (TCB freed at its last cap delete)
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
and goes to the least-loaded CPU if not. The placement is recorded in `tcb.preferred_cpu`
and used for subsequent wakeups.

### Load Balancing

A pull-based balancer runs on every CPU's `timer_tick`: `sched::try_pull_idle` on a CPU
running its idle thread, `sched::try_pull_balance` on any other. Both architectures re-arm
the timer in its interrupt handler whatever the CPU runs, so a halted idle CPU keeps
ticking. The balancer consumes each CPU's run-queue load counter
(`PerCpuScheduler::current_load()`, the threads linked on its run queues, the running
thread not counted; maintained by `enqueue` / `dequeue_highest` / `remove_from_queue`) and
migrates at most one `Ready` thread per tick per CPU.

The balancer counts queued threads without weighing them by class or level (§ Scheduling
Classes): it evens out the number of queued threads per CPU, and `find_runnable` scans the
victim's queues from the highest, so an RT thread is pulled before a fair one.

Victim selection is mode-dependent:

- **Busy CPU with queued threads (`my_load > 0`)** — pick a pseudo-random victim
  (splitmix-style hash of the global `LOAD_BALANCE_TICK` counter and the
  local CPU id). Skip if the victim is not significantly busier than us
  (`their_load <= my_load + LOAD_BALANCE_IMBALANCE_THRESHOLD`).
- **Busy CPU with an empty queue (`my_load == 0`)** — scan all other CPUs and pull from
  the heaviest, when its load exceeds `LOAD_BALANCE_IMBALANCE_THRESHOLD`. Scanning is
  cheap (one Relaxed atomic load per CPU) and guarantees the CPU finds work on the first
  tick that sees an imbalance. Pure random victim selection converges only
  probabilistically and on small topologies sometimes wastes many ticks
  before picking the busy CPU.
- **Idle CPU** (running its idle thread, its own queue empty) — the same scan, and a pull
  whatever the victim's load. A load above `LOAD_BALANCE_IMBALANCE_THRESHOLD` is pulled
  at once. A smaller backlog is pulled once it has outlived one tick: the idle CPU
  records the heaviest CPU with a queued thread as its candidate
  (`PerCpuScheduler::idle_pull_candidate`) and, at its next idle tick, pulls from that
  CPU if its queue is still non-empty, else records the heaviest afresh. The candidate is
  cleared after every attempt, when no CPU has a queued thread, and on every tick the CPU
  runs another thread. The decision is `sched::idle_pull_step`.

The idle CPU's pull below the threshold is what keeps a thread from starving while a CPU
idles. A thread queued behind a running thread that never blocks or yields to its level
(an RT thread spinning on a lock the queued thread holds, under § Scheduling Classes'
strict priority) stays queued for as long as that thread runs; the threshold, which
counts only queued threads, never sees one queued thread as an imbalance, and
`select_target_cpu` keeps a woken thread on its preferred CPU at that load. An idle CPU
therefore pulls it within about two ticks. The rule stays bounded: only an idle CPU pulls
below the threshold, and a pull leaves it busy, so two busy CPUs never trade threads (the
steady state the threshold protects); a backlog that clears between two idle ticks stays
with the CPU whose caches hold it; and a backlog of pinned threads, which no pull can take, draws
at most one try-lock attempt per idle CPU every two ticks.

Migration goes through `pull_unpinned_ready(src_cpu, dst_cpu)`, which shares the
validate-then-move core `relocate_ready_thread` with `migrate_ready_thread`:

```
pull_unpinned_ready(src, dst):
    if !try_lock(min(src, dst).scheduler.lock): return   // ascending-CPU order
    if !try_lock(max(src, dst).scheduler.lock):
        unlock(min); return
    (tcb, prio) = src.find_runnable(|t| t.cpu_affinity == AFFINITY_ANY
                                        && t.context_saved.load(Acquire) == 1)
    if tcb is None: unlock both; return
    if !try_lock(tcb.sched_lock): unlock both; return  // taken after run-queue locks
    // relocate_ready_thread: revalidate under sched_lock, then move.
    moved = false
    if tcb.state == Ready && tcb.context_saved == 1
       && (tcb.cpu_affinity == AFFINITY_ANY || tcb.cpu_affinity == dst):
        src.remove_from_queue(tcb, prio)       // decrements src's load counter
        dst.enqueue(tcb, prio)                 // increments dst's load counter
        tcb.preferred_cpu = dst
        set_reschedule_pending_for(dst)
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
- Idle CPU: one Relaxed load per remote CPU to find the heaviest victim, one Relaxed load
  of its own candidate and one of the candidate's load, and a Relaxed store of the
  candidate when it changes.
- Busy CPU: one Relaxed load of its own candidate (a store only on the first busy tick
  after an idle one), plus, with an empty queue, one Relaxed load per remote CPU, or, with
  queued threads, one Relaxed increment + one Relaxed load for the victim.
- Scheduler locks are try-acquired: by a busy CPU only when an imbalance above
  `LOAD_BALANCE_IMBALANCE_THRESHOLD` is observed, and by an idle CPU when the idle rule
  above decides a pull.

---

## SMT Awareness

On systems with Simultaneous Multi-Threading (Hyper-Threading on Intel, SMT on AMD),
multiple logical CPUs share physical execution resources on the same core.

SMT topology awareness is design intent, not yet implemented
([#267](https://github.com/kottlerg/seraph/issues/267)). The kernel records no physical-core
or sibling topology, and `try_pull_balance` and `select_target_cpu` place threads by per-CPU
`current_load()` alone. The subsections below describe the intended design.

### Topology Detection

Physical core membership would be detected at boot via CPUID (x86-64 extended topology
leaf) or the device tree (RISC-V). Each `PerCpuData` would record:

```rust
struct PerCpuData
{
    cpu_id: u32,
    physical_core_id: u32,
    smt_sibling_mask: u64,  // bitmask of logical CPUs sharing this physical core
}
```

### Scheduling Preference

The load balancer would prefer to spread threads across distinct physical cores rather
than filling one core's SMT siblings:

```
when assigning a new thread to a CPU:
    prefer a CPU whose physical_core is not already occupied by another thread
    over a CPU that is a SMT sibling of a running thread
```

This preference would be soft — if all physical cores are occupied, threads would be
distributed across SMT siblings. The preference would be implemented as a tie-break in the
load metric rather than as a hard constraint.

SMT awareness would have no effect on the scheduler's correctness — it is a performance
optimisation to avoid resource sharing between threads that could otherwise run
independently.

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
            try_pull_balance(cpu); return
        Continue(remaining):
            current.slice_remaining = remaining; reschedule = false
        PreemptForRt(remaining):              // fair current, RT thread queued here
            current.slice_remaining = remaining; reschedule = true
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

A fair thread is also preempted before its slice expires, at any tick that finds an RT thread
queued on its CPU (`PreemptForRt`). It goes back to the fair queue's tail keeping the rest of its
slice, and the RT thread runs. RT threads are not preempted mid-slice: among them a newly
runnable higher level waits for the running thread to block, yield or expire, as above.

### Kernel-Mode Preemption Points

Syscall context is not preemptible. Syscall entry masks interrupts, and they stay masked
for the whole syscall except in bounded preempt-disabled, interrupt-enabled windows. When
`timer_tick` reaches a slice expiry while `percpu::preemption_disabled()` holds, it resets
the slice and skips the switch, and the thread is rescheduled at its next slice expiry (a fair
thread with an RT thread queued, at the next tick that finds preemption enabled). Kernel-mode
preemption therefore happens only at a tick that decides a reschedule, a slice expiry or a fair
thread's preemption for RT, with preemption enabled.
The model, the spinlock hold-time bound, and lock ordering are specified in
[scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy) (its
numbered ordering rules and the "Lock primitive" and "Bare spin locks" paragraphs).

---

## Idle Thread

Each CPU has one idle thread (priority 0) that runs when no other thread is ready.

Each iteration of `idle_thread_entry` first drains this CPU's deferred-reclaim queue
(`cap::object::drain_deferred_reclaim`) with interrupts enabled. It then masks interrupts
and checks `take_reschedule_pending` and `has_runnable` together. If either is set, it
re-enables interrupts and calls `schedule(Requeue::Always)` when the run queue has work, then loops.
Otherwise it halts through the atomic enable-and-halt `arch::current::cpu::halt_until_interrupt`.
Masking before the check means a wake IPI that lands between the check and the halt stays
pending and ends the halt. The protocol is specified in
[scheduling-internals.md](scheduling-internals.md#wake-protocol-invariants) § Wake Protocol
Invariants.

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
- **Running** thread on a different CPU: the syscall sets the
  **source** CPU's reschedule-pending flag and sends a wakeup IPI to the
  **source** CPU (where the thread is currently running). The IPI itself
  does not call `schedule()`; the running thread observes the new
  affinity at its next entry to `schedule()` — preempt-on-slice-expiry,
  a fair-dispatched thread's preemption for RT, voluntary yield, or IPC
  block. The re-enqueue site in `schedule()`
  checks `cpu_affinity != current_cpu` and routes the requeue cross-CPU —
  linking the thread directly on the destination's run queue, setting its
  reschedule-pending flag, and IPIing it — instead of doing a local enqueue
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
[Architecture Overview](../../../docs/architecture.md)
