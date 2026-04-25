# Scheduler Internals

The Seraph kernel scheduler is preemptive, priority-based, and SMP-aware. Scheduling
policy is minimal: the highest-priority runnable thread runs. SMT topology is used
to prefer spreading threads across physical cores rather than packing them onto one.

The scheduler interacts with two subsystems:

- **IPC** — IPC operations may block threads, wake threads, and trigger direct context
  switches (see [ipc-internals.md](ipc-internals.md))
- **Architecture layer** — context save/restore and the preemption timer are implemented
  by the arch traits defined in [arch-interface.md](arch-interface.md)

---

## Scheduling Algorithm

### Priority Levels

There are `NUM_PRIORITY_LEVELS` = 32 priority levels, numbered 0 (lowest) through
31 (highest):

- **Priority 0** — reserved for idle threads (one per CPU; never preempted).
- **Priorities 1–30** — available to userspace. `PRIORITY_MAX` = 30.
- **Priority 31** — reserved; cannot be requested by userspace.

Userspace threads specify a priority in [1, `PRIORITY_MAX`] at creation time
(`SYS_CAP_CREATE_THREAD`) or via `SYS_THREAD_SET_PRIORITY`. The kernel does not
implement dynamic priority adjustment or aging.

### Priority Authority

The usable priority range is split into two tiers, controlling who may assign a
given priority:

| Range | Name | Authority required |
|---|---|---|
| 1–20 | Normal | Thread Control capability only |
| 21–30 | Elevated | Thread Control + SchedControl (Elevate rights) |

`PRIORITY_DEFAULT = 10` is the baseline for newly created threads. Processes may
freely adjust their own threads within the normal range (1–20) — lowering priority
is always permitted, and raising within the normal range requires only the thread's
Control capability.

`SCHED_ELEVATED_MIN = 21` is the first priority that requires a SchedControl
capability. The SchedControl capability is created at boot (one for the entire
system) and held by init, which delegates derived copies to services that need
real-time-ish scheduling — audio servers, device managers, high-priority drivers.
Services without a SchedControl capability cannot assign elevated priorities
regardless of what other capabilities they hold.

This replaces the earlier ungated model in which any Control-capability holder
could set any priority in the 1–30 range.

### Run Queue Structure

Each CPU has a set of 32 run queues, one per priority level:

```rust
pub struct PerCpuScheduler
{
    /// Per-priority run queues. Each is an intrusive FIFO of ready TCBs.
    queues: [RunQueue; NUM_PRIORITY_LEVELS],

    /// Bitmask with one bit set per non-empty priority level.
    /// Allows O(1) selection of the highest non-empty priority.
    non_empty: u32,

    /// Currently running TCB on this CPU.
    current: *mut ThreadControlBlock,

    /// The idle TCB for this CPU.
    idle: *mut ThreadControlBlock,

    /// Lock protecting this struct. Held briefly during enqueue/dequeue.
    lock: Spinlock,
}

struct RunQueue
{
    head: Option<*mut ThreadControlBlock>,
    tail: Option<*mut ThreadControlBlock>,
}
```

The `non_empty` bitmask enables O(1) selection of the highest-priority non-empty
queue: `31 - non_empty.leading_zeros()` on x86-64 (using `BSR`), or
`31 - non_empty.leading_zeros()` on RISC-V. Enqueue sets the corresponding bit;
dequeue clears it if the queue becomes empty.

### Time Slice Policy

Each thread receives a configurable time slice. The preemption timer fires
periodically at a configurable interval; each timer interrupt decrements a per-thread
slice counter. When the counter reaches zero, the thread is preempted. The time
slice duration and timer period are implementation constants, not part of the ABI.

Time slices are equal across all priority levels. Priority determines which thread
runs next, not how much time each thread gets relative to others. A high-priority
thread that runs continuously will consume its full time slice before yielding to a
lower-priority thread (unless blocked).

Within a priority level, threads share the CPU in round-robin order (FIFO queue
drained cyclically).

### Selection

```
pick_next(cpu):
    // non_empty is a bitmask; find highest set bit
    if non_empty == 0: return idle_tcb
    priority = highest_set_bit(non_empty)
    tcb = queues[priority].dequeue()
    if queues[priority].is_empty():
        non_empty &= ~(1 << priority)
    return tcb
```

---

## Thread Control Block

The TCB is the kernel's per-thread state. It is allocated from the `tcb_cache` slab.

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

    /// Intrusive run-queue link (next TCB in the same priority queue).
    run_queue_next: Option<*mut ThreadControlBlock>,

    // === IPC state ===

    /// Single-use reply capability for the pending IPC call (if any).
    reply_cap_slot: Option<ReplyCapability>,

    /// Pending send message buffer (used while BlockedOnSend).
    pending_send: PendingSendBuffer,

    /// Wakeup value (payload for signal/event wakeup).
    wakeup_value: u64,

    /// Token from a wait set wakeup.
    wakeup_token: u64,

    /// Intrusive IPC wait queue link.
    ipc_wait_next: Option<*mut ThreadControlBlock>,

    // === Context ===

    /// Architecture-specific saved register state.
    saved_state: arch::current::Context::SavedState,

    /// Kernel stack top (used to restore RSP0/kernel SP on context switch).
    kernel_stack_top: VirtAddr,

    /// Address space this thread runs in.
    address_space: *mut AddressSpace,

    // === Capability reference ===

    /// CSpace bound to this thread (set via sys_thread_configure).
    cspace: *mut CSpace,

    // === Identity ===

    /// Unique thread identifier.
    thread_id: ThreadId,
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
                          (IPC block, signal wait, etc.)
                                  │
                                Blocked
                                  │
                          (wakeup / IPC reply)
                                  │
                                  ▼
                                Ready

Running ──(SYS_THREAD_STOP)──► Stopped
Running ──(SYS_THREAD_EXIT)──► Exited (TCB freed)
```

State transitions are protected by the TCB's implicit lock (the scheduler lock on
the CPU that owns the TCB) combined with the IPC object lock where relevant.

---

## Context Switch Mechanism

### What Gets Saved and Restored

On each context switch, the arch `Context::switch` function saves and restores the
minimal register set needed for correct execution:

**x86-64 (callee-saved registers):**
- `rbx`, `rbp`, `r12`, `r13`, `r14`, `r15`
- `rip` (return address, via the call to `Context::switch`)
- `rsp` (stack pointer)
- The `fs_base` MSR (TLS base pointer)
- The kernel stack pointer is stored separately in the TSS `RSP0` field

Caller-saved registers (`rax`, `rcx`, `rdx`, `rsi`, `rdi`, `r8`–`r11`) are not saved
— by calling convention the caller has already saved them if needed.

**RISC-V (callee-saved registers):**
- `s0`–`s11` (saved registers)
- `ra` (return address — `Context::switch` returns here)
- `sp` (stack pointer)
- `tp` (thread pointer, used for TLS)

The full user register file (all 31 general-purpose registers plus `sepc`, `sstatus`,
and the floating-point state) is saved in the thread's trap frame, not in
`SavedState`. `SavedState` holds only the kernel-mode callee-saved state.

### Switch Sequence

```
context_switch(current_tcb, next_tcb):
    // 1. Update the kernel trap stack pointer so the next privilege-level
    //    transition (syscall, interrupt, or exception) lands on next_tcb's stack.
    //    x86-64: writes TSS.RSP0 and SYSCALL_KERNEL_RSP.
    //    RISC-V: writes sscratch (read by trap_entry to switch from user stack).
    arch::current::cpu::set_kernel_trap_stack(next_tcb.kernel_stack_top)

    // 2. Switch address space if different.
    if current_tcb.address_space != next_tcb.address_space:
        pcid = tlb::pcid_for(next_tcb.address_space)
        arch::current::Paging::activate(next_tcb.address_space.root_table, pcid)
        // Update active_cpu_mask on both address spaces (for TLB shootdown tracking)

    // 3. Perform the register-level switch.
    //    Saves current callee-saved registers, restores next's, returns into next_tcb.
    arch::current::Context::switch(
        &mut current_tcb.saved_state,
        &next_tcb.saved_state,
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

When a new thread is created (`SYS_CAP_CREATE_THREAD`):

- If `cpu_affinity` is `AFFINITY_ANY`, the kernel assigns it to the CPU with the
  lowest total thread count (a simple load metric)
- If `cpu_affinity` specifies a CPU, the thread is assigned there unconditionally

The assignment is recorded in `tcb.preferred_cpu` and used for subsequent wakeups.

### Load Balancing

Load balancing runs periodically (at a configurable interval) and when a CPU becomes
idle:

```
balance(cpu):
    Find the most-loaded CPU: max_cpu
    if max_cpu == cpu or load difference is below a configurable threshold:
        return  // not worth migrating
    // Acquire scheduler locks in CPU ID order to prevent deadlock.
    Acquire both max_cpu.scheduler.lock and cpu.scheduler.lock
    // Always acquire the lower CPU ID's lock first.
    // Steal half the excess threads from max_cpu
    // Prefer migrating lower-priority threads to preserve latency for high-priority
    for thread in threads_to_migrate:
        max_cpu.dequeue(thread)
        thread.preferred_cpu = cpu
        cpu.enqueue(thread)
    Release both locks
```

Threads with hard CPU affinity (`cpu_affinity != AFFINITY_ANY`) are never migrated.

Migration requires no IPI — the migrated thread is simply enqueued on the new CPU's
run queue. The target CPU will pick it up on its next scheduler invocation (or
immediately if an IPI is sent to wake an idle CPU).

---

## SMT Awareness

On systems with Simultaneous Multi-Threading (Hyper-Threading on Intel, SMT on AMD),
multiple logical CPUs share physical execution resources on the same core. The
scheduler is aware of this topology.

### Topology Detection

Physical core membership is detected at boot via CPUID (x86-64 extended topology leaf)
or the device tree (RISC-V). Each `PerCpuData` records:

```rust
struct PerCpuData
{
    cpu_id: u32,
    physical_core_id: u32,
    smt_sibling_mask: u64,  // bitmask of logical CPUs sharing this physical core
}
```

### Scheduling Preference

The load balancer prefers to spread threads across distinct physical cores rather than
filling one core's SMT siblings:

```
when assigning a new thread to a CPU:
    prefer a CPU whose physical_core is not already occupied by another thread
    over a CPU that is a SMT sibling of a running thread
```

This preference is soft — if all physical cores are occupied, threads are distributed
across SMT siblings. The preference is implemented as a tie-break in the load metric
rather than as a hard constraint.

SMT awareness has no effect on the scheduler's correctness — it is a performance
optimisation to avoid resource sharing between threads that could otherwise run
independently.

---

## Preemption

### Timer-Driven Preemption

The preemption timer (configured in Phase 5 of initialization) fires at the
configured periodic interval on each CPU. The timer interrupt handler:

```
timer_interrupt_handler():
    current_tcb.slice_remaining -= 1
    if current_tcb.slice_remaining == 0:
        current_tcb.slice_remaining = TIME_SLICE_TICKS
        // Check if a higher or equal-priority thread is waiting
        if any_runnable_at_or_above(current_tcb.priority):
            enqueue(current_tcb, current_tcb.priority)
            next = pick_next(current_cpu)
            context_switch(current_tcb, next)
    // else: continue current thread
```

The preemption check is: "is there anyone else ready to run at this priority or
higher?" If yes, the current thread is re-enqueued and another is picked. If not,
the thread continues without preemption even if its time slice expired.

This ensures that a thread at a unique highest priority is never preempted needlessly
— only when a peer or superior competitor exists.

### Kernel-Mode Preemption Points

The kernel is preemptible in most kernel-mode execution paths. A thread executing a
syscall may be preempted while the timer fires if:

- No spinlock is held
- No interrupt-disabled section is active

Spinlock-hold intervals must be short (< ~10 µs) by policy. Code that holds a
spinlock must not call anything that blocks or takes another lock (except in defined
lock-ordering sequences).

The scheduler does not preempt the kernel while a spinlock is held. Instead, a
`preemption_pending` flag is set per-CPU; preemption occurs when the last spinlock
is released.

---

## Idle Thread

Each CPU has one idle thread (priority 0) that runs when no other thread is ready.

```rust
fn idle_thread_entry(cpu_id: u64) -> !
{
    loop
    {
        // Check for pending work before halting, to avoid a race where
        // a wakeup IPI arrives between the check and the halt instruction.
        if has_runnable_threads(cpu_id)
        {
            schedule();
        }
        // Halt until the next interrupt (timer or IPI).
        arch::current::Cpu::halt_until_interrupt();
    }
}
```

The idle thread is the only thread that cannot be preempted by the timer (its time
slice counter is not decremented — priority 0 is handled specially). It yields
voluntarily via the `schedule()` call when work becomes available.

---

## Priority Inversion Mitigation

The kernel does not implement priority inheritance. The rationale: priority inheritance
adds significant complexity for a benefit that only applies to mutex-based shared
state, which Seraph avoids by design (message passing preferred over shared memory).

The primary locking primitive in the kernel is a spinlock, not a blocking mutex.
Spinlocks do not cause priority inversion — the waiting thread spins rather than
blocking. Spinlock-hold intervals are bounded by policy.

If priority inversion is observed in practice at the userspace IPC level (a
high-priority thread blocked waiting for a low-priority server), the correct fix is
to use a higher-priority server thread, not to add kernel priority inheritance.

---

## Affinity

### Hard Affinity

`tcb.cpu_affinity != AFFINITY_ANY` specifies a single CPU the thread must run on.
The thread is never migrated. Wakeups always enqueue the thread on the specified CPU's
run queue. If the specified CPU is offline, `SYS_CAP_CREATE_THREAD` fails with
`InvalidArgument`.

Hard affinity is intended for:
- Interrupt-handling threads that must run on specific CPUs (NUMA, IRQ affinity)
- Real-time threads that must not suffer migration latency

### Soft Affinity

`tcb.preferred_cpu` records the CPU the thread was last assigned to. The load
balancer uses this as a hint to avoid unnecessary migration (cache warmth). A thread
may be migrated away from its preferred CPU when load balancing requires it.

The scheduler does not expose soft affinity as a syscall parameter — it is an internal
optimisation.

---

## Summarized By

None
