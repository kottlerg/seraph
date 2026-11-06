# Fault Handling

Redirection of kernel-unresolvable userspace thread faults to a userspace handler,
the mechanism on which demand paging, swap, mmap, and similar policies are built, and its
asynchronous dual, the capability-triggered upcall.

---

## Scope

This document is authoritative for the **fault-handler protocol**: how the kernel
delivers a userspace thread fault it cannot itself resolve to a userspace handler
("handler", or for the page-fault case a "pager"), and how the faulting thread is
suspended and later resumed.

In scope:

- The per-thread fault-handler binding and the syscall that sets it.
- The fault taxonomy and the fault-message contract delivered to the handler.
- The suspend / deliver / resume / kill state machine.
- The faults a syscall's copy of a caller-supplied buffer takes, and the restart of
  that syscall.
- Liveness, recursion, and security rules.
- The asynchronous upcall: its post, delivery points, mask, interaction with blocking syscalls,
  and nesting ([Asynchronous Upcalls](#asynchronous-upcalls)).
- How a userspace debugger uses both: breakpoints, single-step, register and memory access, and
  asynchronous break ([Debugging](#debugging)).

Out of scope (the kernel never does these):

- Walking filesystem metadata, or any notion of file-backed mappings, in the kernel.
- Page-replacement, swap, compression, or copy-on-write *policy*. The kernel provides
  the fault-redirection mechanism only; all paging policy is userspace.
- Kernel-internal page-CoW. CoW, if built, is a userspace handler policy expressed over
  explicit capability operations.

The handler installs mappings with the ordinary `SYS_MEM_MAP` authority; the kernel adds
no fault-specific mapping path. Mapping validation (W^X, rights subsetting, address-range
checks) is owned by the [memory model](memory-model.md) and the
[capability model](capability-model.md), unchanged.

---

## Implementation Status

The fault-redirection mechanism is implemented on both x86-64 and RISC-V for **both**
fault kinds: `SYS_THREAD_SET_FAULT_HANDLER`, the per-thread, per-class fault-handler binding
and its query and copy (`SYS_THREAD_GET_FAULT_HANDLER`, `SYS_THREAD_INHERIT_FAULT_HANDLER`), the
[fault message](#fault-message) for `FAULT_KIND_VM` (page faults) and `FAULT_KIND_EXCEPTION`
(every other kernel-unresolvable ring-3 exception — illegal instruction, breakpoint,
alignment, divide, …), and the [resume and kill](#delivery-resume-and-kill) state machine —
including register inspection and modification of a fault-blocked thread via
[`SYS_THREAD_READ_REGS`/`SYS_THREAD_WRITE_REGS`](capability-model.md#thread) — and the
restart of a syscall whose copy of a user buffer faults ([Kernel Copies](#kernel-copies)). A
thread with no handler bound is still terminated on a fault of its own access, the behavior for
all faults absent this mechanism (a kernel copy's fault fails its syscall instead). One x86-64
kernel check is terminal even with a handler bound: a syscall return RIP that is not
canonical, which no user action can produce (the top user page is unmappable) and which the
exit path kills as a user `#GP` without delivery, since no handler edit could make that return
valid (see
[syscalls.md § Syscall Entry and Exit](../core/kernel/docs/syscalls.md#syscall-entry-and-exit)).
The x86-64 abort vectors (`#DF`, `#MC`) and a hardware NMI that finds no watchdog backtrace request
pending (see
[scheduling-internals.md § `ipi_nmi_backtrace_stub` / `ipi_nmi_backtrace_handler`](../core/kernel/docs/scheduling-internals.md#ipi_nmi_backtrace_stub--ipi_nmi_backtrace_handler))
are the exception: they are never delivered to a handler and never terminate a thread; they halt
the CPU they arrive on, whatever ring they interrupt. The interrupted thread stays `current` on the
halted CPU and no death event is posted for it; a teardown of it does not complete (see
[thread-lifecycle-and-sleep.md § `dealloc_object(Thread)` Drain Protocol](../core/kernel/docs/thread-lifecycle-and-sleep.md#dealloc_objectthread-drain-protocol),
invariant 3), a stop of it does not return through its drain until a teardown commits `Exited`
over it (see
[§ `sys_thread_stop` Cross-CPU Stop Protocol](../core/kernel/docs/thread-lifecycle-and-sleep.md#sys_thread_stop-cross-cpu-stop-protocol),
invariant 3), and the other CPUs run on until one needs the halted CPU. A halt of the boot CPU
also ends sleep-list servicing and the BSP-hosted watchdog detectors, which run only there (see
[§ Sleep List Invariants](../core/kernel/docs/thread-lifecycle-and-sleep.md#sleep-list-invariants),
invariant 5), so no timeout wakes on any CPU; on a multi-CPU system an AP's BSP-heartbeat check
then reports the halted boot CPU once its grace window elapses, unless a TLB shootdown is
pending, which the check defers to (a shootdown naming the halted boot CPU ends in the IPI
watchdog's `fatal` instead; see
[§ Softlockup Watchdog](../core/kernel/docs/scheduling-internals.md#softlockup-watchdog)).

The demand-paging consumer is implemented: memmgr acts as the pager, procmgr binds it for
every ordinary process it creates (demand paging is the default; a process opts out with the
`CREATE_PINNED` flag) and delegates the child address space, the runtime copies the spawning
thread's bindings onto each thread it spawns (`SYS_THREAD_INHERIT_FAULT_HANDLER`), and the
`ProcessInfo` pager field (`pager_endpoint_cap` / `pager_badge`) tells the runtime that the
process is demand-paged. See
[services/procmgr/docs/ipc-interface.md](../services/procmgr/docs/ipc-interface.md).
Userspace reserves unbacked VA and registers it via `std::os::seraph::register_demand_paged`;
first touch faults, memmgr maps a frame and resumes. See
[services/memmgr/docs/ipc-interface.md](../services/memmgr/docs/ipc-interface.md)
(`REGISTER_REGION`, `DELEGATE_ASPACE`, and the fault arm).

A change of the binding of an in-flight fault's class cancels that delivery and delivers the
fault again under the binding current then ([Rebind](#delivery-resume-and-kill)), on both
architectures.

The asynchronous upcall ([Asynchronous Upcalls](#asynchronous-upcalls)) is implemented on both
architectures: `SYS_THREAD_POST_UPCALL`, the third class `FAULT_CLASS_UPCALL`, delivery at a
syscall's return and, for an `UPCALL_ANY_INSTRUCTION` post, at an interrupt's return to user mode,
the cancel of a blocking syscall, and `SYS_THREAD_SET_UPCALL_MASK`. Its end-to-end consumer is the
`deadline` fixture's supervisor, which cancels a spinning worker at a deadline
([programs/deadline/README.md](../programs/deadline/README.md)).

---

## Mechanism Overview

When a userspace thread takes a synchronous fault that the kernel cannot resolve on its
own (e.g. an access to an unmapped page that is not a stale-TLB artifact), the kernel:

1. Suspends the faulting thread.
2. Marshals a **fault message** describing the fault and delivers it as a synchronous,
   kernel-originated IPC to the thread's bound **fault-handler endpoint**.
3. Awaits the handler's reply. The handler resolves the fault by its own policy — for a
   page fault, it maps a frame into the faulting address space and replies to resume.
4. On reply, resumes the faulting thread, which re-executes the faulting instruction (or
   continues from a handler-modified instruction pointer).

If the thread has **no** fault handler bound, the fault is terminal: the thread is killed with exit
reason `EXIT_FAULT_BASE + <fault code>`, the behavior for all faults absent this mechanism. A fault
of a restartable syscall's copy of a user buffer is the exception: it fails that syscall with
`InvalidAddress` instead (see [Kernel Copies](#kernel-copies)). On x86-64, `#DF`, `#MC`, and a
hardware NMI that finds no watchdog backtrace request pending are not the thread's faults: they
are never delivered to a handler, record no exit reason, and halt the CPU they arrive on whatever
ring they interrupt, leaving the interrupted thread `current` there with no death event posted.
Voluntary exit codes occupy the disjoint range `[1, EXIT_FAULT_BASE)` below it (see
[Process Lifecycle](process-lifecycle.md#exit-reason)), so a fault reason and a voluntary exit code
can never alias; `ExitStatus::success()`/`code()` distinguish them without ambiguity.

Fault delivery reuses the synchronous IPC machinery of [IPC Design](ipc-design.md): the
suspended thread occupies the same role as a caller blocked awaiting a reply, and the
handler services it with the ordinary receive / reply cycle. Delivery is iterative
(suspend then reschedule), never kernel-stack recursion, so a chain of handlers cannot
exhaust the kernel stack.

---

## Fault-Handler Binding

The fault handler is bound **per thread and per fault class**. The handler is an ordinary
[`Endpoint`](capability-model.md#ipc-endpoint); there is no distinct fault-endpoint
capability type. The binding is per-thread kernel state, one per class: the bound endpoint and
its badge. The classes are `FAULT_CLASS_VM`, the virtual-memory faults (`FAULT_KIND_VM`, the
faults of a restartable syscall's user copy among them), `FAULT_CLASS_EXCEPTION`, every
other kernel-unresolvable user exception (`FAULT_KIND_EXCEPTION`), and `FAULT_CLASS_UPCALL`, the
asynchronous upcalls (`FAULT_KIND_UPCALL`; [Asynchronous Upcalls](#asynchronous-upcalls)). A fault
is delivered through its class's binding alone, so distinct services can own a thread's classes (a
pager its virtual-memory faults, a debugger its exceptions, a supervisor its upcalls); with no
handler bound for its class, a fault takes the outcome it has with no handler bound at all.

`SYS_THREAD_SET_FAULT_HANDLER(thread_cap, endpoint_cap, reserved, fault_class_mask)`:

- `thread_cap` MUST carry `CONTROL`. It selects the thread whose handler is set.
- `endpoint_cap` MUST refer to an `Endpoint`, or be the null index `0` to **unbind**. Each selected
  class's binding takes its own reference on the endpoint object for the lifetime of that binding
  (see [Liveness](#liveness)); unbinding releases it. Both lookups pin their object for the call, so
  neither the thread nor the endpoint can be freed while the binding is written (see
  [capability-internals.md § Storage: Hybrid Radix Directory](../core/kernel/docs/capability-internals.md#storage-hybrid-radix-directory)).
  The binding's badge is the derivation badge of `endpoint_cap`
  ([Capability Model § Badges](capability-model.md#badges)), `0` for an unbadged cap: the binder
  chooses which of its caps to bind, never the badge value; see [Security](#security).
- `reserved` MUST be `0`; any other value fails with `InvalidArgument`.
- `fault_class_mask` selects the classes the call binds or unbinds: `FAULT_CLASS_ALL`, every class,
  or any nonzero combination of `FAULT_CLASS_VM`, `FAULT_CLASS_EXCEPTION`, and `FAULT_CLASS_UPCALL`.
  The classes it leaves out keep their bindings. A mask of zero or with a bit no class defines fails
  with `InvalidArgument`.

A class's endpoint and badge are published as one unit: the binder writes both under the target
thread's scheduler lock, and fault delivery reads both once under the same lock and pins the
endpoint for the delivery (it takes its own reference there, while the binding's reference still
holds the endpoint, and releases it before the faulting thread parks; see
[capability-internals.md § Kernel Object Reference Counting](../core/kernel/docs/capability-internals.md#kernel-object-reference-counting)).
A delivery therefore carries the badge bound with the endpoint it reaches, and a rebind or
unbind concurrent with a fault never frees the endpoint mid-delivery. A fault whose delivery
finds its class's binding already cleared is unhandled (see [Reply](#reply)). A change of a
class's binding while a delivery of that class made under the old one is in flight cancels that
delivery, and the fault is delivered again under the new binding (see
[Delivery, Resume, and Kill](#delivery-resume-and-kill), Rebind); a change of another class's
binding leaves it alone.

A handler bound for several classes (`FAULT_CLASS_VM | FAULT_CLASS_EXCEPTION`, the binding procmgr
makes) dispatches on the fault kind (see [Fault Message](#fault-message)) and replies
[`FAULT_REPLY_KILL`](#reply) for kinds it does not handle, recovering for those kinds the outcome
they have with no handler bound.

`SYS_THREAD_GET_FAULT_HANDLER(thread_cap, class)` reads one class's binding: `thread_cap` MUST
carry `CONTROL`, and `class` MUST be exactly one class bit (`InvalidArgument` otherwise). It
returns whether the class is bound and, when it is, the badge bound with it, read once under the
same lock as one unit; it discloses no endpoint and creates no capability.

`SYS_THREAD_INHERIT_FAULT_HANDLER(dst_thread_cap, src_thread_cap, fault_class_mask)` copies, for
each class the mask selects, the source thread's binding onto the destination: both caps MUST
carry `CONTROL`, and the mask follows `SYS_THREAD_SET_FAULT_HANDLER`'s rules. The destination's
class is bound to the source's endpoint with the source's badge, its binding taking its own
reference on the endpoint, or unbound where the source has none. The source's bindings are read
once under its lock, and the destination's are published as `SYS_THREAD_SET_FAULT_HANDLER`
publishes them, with the same cancellation of a delivery in flight under a changed binding. The
binder needs no capability to the endpoint, and the badge is copied, never chosen.

### Inheritance is userspace policy

The kernel does not propagate a fault handler to new threads. Because binding requires
only `CONTROL` on the target thread, propagation is expressed by whoever holds that
authority:

- A process creator (procmgr) MAY bind a handler on each process's initial thread.
- A process runtime MAY bind a handler onto each thread it spawns. The Seraph runtime copies
  the spawning thread's bindings, every class, onto the new thread before starting it
  (`SYS_THREAD_INHERIT_FAULT_HANDLER`), so the pager procmgr binds on the initial thread
  reaches every thread of the process, and so does any other handler bound on a spawning
  thread. The process's page-fault pager is also advertised to the runtime through
  [`ProcessInfo`](process-lifecycle.md#processinfo--initinfo-handover-discipline), which tells
  it that the process is demand-paged.

This makes a system-wide default pager (see [Default System Pager](#default-system-pager))
a policy decision, not a kernel change.

---

## Fault Message

The fault message is delivered to the handler endpoint by the kernel on the faulting
thread's behalf. Its format is a stable cross-boundary contract.

- **Label** — the reserved `FAULT_LABEL`. It proves kernel origin only on an endpoint whose
  handler hands out no `SEND`. A handler that multiplexes client traffic on the same endpoint
  (memmgr) attributes the message by its badge, not by the label; see [Security](#security).
- **Badge** — the derivation badge of the bound Endpoint cap.
- **Data word 0** — the fault **kind**:
  - `FAULT_KIND_VM` — a virtual-memory (page) fault.
  - `FAULT_KIND_EXCEPTION` — a CPU exception with no kernel resolution (illegal
    instruction, alignment, divide error, and similar).
  - `FAULT_KIND_UPCALL` — an asynchronous upcall, not a fault
    ([Asynchronous Upcalls](#asynchronous-upcalls)).
  - Remaining values are reserved for future kinds (e.g. capability faults).
- **Data words 1–3** — kind-specific:
  - `FAULT_KIND_VM`: faulting virtual address; access flags (bit 0 read, bit 1 write,
    bit 2 instruction fetch, bit 3 present-vs-not-present); faulting instruction pointer.
    Bit 3 is set only on x86-64, and only for a user-half faulting address (for a
    kernel-half address it would disclose which kernel pages are mapped). On RISC-V it is
    always clear, because `scause` does not encode presence, so a handler there MUST NOT
    read a clear bit 3 as not-present; it inspects its own mappings instead.
  - `FAULT_KIND_EXCEPTION`: a **normalized exception code** (an architecture-neutral class —
    illegal instruction, breakpoint, alignment, divide, protection, … — so a handler
    dispatches without architecture knowledge; an unrecognized code is treated as the
    unknown class); the **architecture auxiliary code** (x86-64 the hardware error code,
    `0` where the vector has none; RISC-V `stval`); the faulting instruction pointer. The
    kernel maps each architecture's raw vector/cause to a normalized class
    (`normalize_x86_exception` in `core/kernel/src/arch/x86_64/idt.rs`,
    `normalize_riscv_exception` in `core/kernel/src/arch/riscv64/interrupts.rs`).
  - `FAULT_KIND_UPCALL`: the poster's cookie; the delivery point (`UPCALL_POINT_SYSCALL` or
    `UPCALL_POINT_INTERRUPT`); the thread's instruction pointer.

The faulting thread's full register state is not embedded; a handler that needs it reads
it with [`SYS_THREAD_READ_REGS`](capability-model.md#thread) on the faulting thread.

---

## Delivery, Resume, and Kill

A faulting thread with a bound handler enters a dedicated **fault-blocked** state distinct
from the call-reply blocked state, so its resume semantics differ from a syscall return:
it resumes at its reported instruction pointer, not by returning a value. For a fault that
is the faulting instruction, which re-executes; for a trap-type exception (x86-64 `#BP` and
`#DB`) it is the instruction after the trapping one ([Debugging](#debugging)). An upcall, which
is no fault, resumes as [Asynchronous Upcalls](#asynchronous-upcalls) states: on RISC-V at the
syscall point, past the `ecall` its reported pointer names.

- **Resume (genuine reply).** The handler replies (default disposition
  [`FAULT_REPLY_RESUME`](#reply)). The kernel resumes the faulting thread with its register
  state preserved (or as modified by the handler; see below) at its reported instruction
  pointer: it re-executes the faulting instruction, or, after a trap-type exception, continues
  after the trapping one. For a page fault whose handler has installed a satisfying mapping, the
  instruction now succeeds.
- **Kill (cancellation).** If the binding is severed before a reply — the handler thread is
  destroyed (its last Thread capability deleted), the handler thread receives again while the fault
  reply is still pending, with a receive that passes its capability and headroom checks
  ([Liveness](#liveness) rule 2), or the handler endpoint is destroyed while the fault is still
  queued on it ([Liveness](#liveness) rule 3) — the fault is unhandled ([Reply](#reply)): the
  faulting thread is killed, or, for a kernel copy's fault, its syscall fails
  ([Kernel Copies](#kernel-copies)). A stop of the faulting thread before any reply claims the
  fault also cancels the episode, but acts on nothing at once: it gives the episode a kill outcome
  and leaves the thread `Stopped`; when next started, the fault is unhandled. A stop after the
  handler's reply claimed the fault leaves that reply's disposition: when next started, the thread
  resumes on a `FAULT_REPLY_RESUME` reply, and the fault is unhandled on a `FAULT_REPLY_KILL`
  reply. Destroying it while stopped ends it as for any stopped thread. A cancelled fault-blocked
  thread is never resumed at its faulting instruction: a thread whose own access faulted is killed
  (a stopped one when next started), and one whose kernel copy faulted has that syscall fail.
- **Rebind (redelivery).** A change of the binding of the fault's class, by
  `SYS_THREAD_SET_FAULT_HANDLER` or `SYS_THREAD_INHERIT_FAULT_HANDLER` (an unbind, or a bind to
  another endpoint or with another badge), while a fault is in flight, before any reply or other
  cancellation claims it, cancels that delivery; a change of another class's binding leaves it
  alone. The cancellation: the queued fault message is withdrawn, or a handler that received it
  finds no pending reply (its `SYS_IPC_REPLY` fails with `InvalidCapability`). The fault is then
  delivered again, by the kernel, under the binding current when the faulting thread next runs, as a
  new delivery: the handler bound then receives the fault message with the badge of the cap bound
  then. With no handler bound then, the fault is unhandled, as a fault whose delivery finds the
  binding cleared ([Reply](#reply)): clearing the binding mid-fault kills the thread, or fails its
  kernel copy's syscall. A bind to the same endpoint with the same badge cancels nothing. A fault in
  flight is one whose delivery read the binding before the change; one that reads the binding after
  it is delivered under the new binding at once. A delivery made under the new binding can, in a
  narrow race, be cancelled and made again under that same binding, which the handler sees as one
  more fault message for the fault; the outcome is unchanged. A stop after the change claimed the
  fault leaves the redelivery: when next started, the thread delivers the fault again. Redelivery
  runs in the kernel, not by resuming the thread at its faulting instruction, so it holds for a
  trap-type exception whose instruction pointer is already past the trapping instruction.

### Modifying the faulting thread

A handler MAY alter the faulting thread's registers with
[`SYS_THREAD_WRITE_REGS`](capability-model.md#thread) before replying — for example to
advance the instruction pointer past an emulated instruction. The reply carries no register
payload; register changes are applied through the explicit thread-register authority and
take effect on resume. A handler that cannot make progress replies
[`FAULT_REPLY_KILL`](#reply) (or stops/destroys the thread via the thread capability).

---

## Reply

The reply **label** conveys disposition:

- `FAULT_REPLY_RESUME` — resume the faulting thread (the default).
- `FAULT_REPLY_KILL` — the handler declines.

The kernel ignores reply capabilities, and every data word but one: data word 0 of a
`FAULT_REPLY_KILL` reply, when the reply carries data words, is the handler's decline reason. The
kernel does not interpret it. When the decline kills a thread whose user-mode access faulted, the
kernel prints it on its serial console, on a `fault unhandled` line ahead of the `USERSPACE FAULT`
diagnostic; that line also names the kernel's own unhandled causes (the binding of the fault's class
found cleared at delivery, or the delivery cancelled before a reply), and its absence before a
`USERSPACE FAULT` line means no handler was bound for the fault's class. A decline with no data
words prints no reason. memmgr's reasons are tabled in
[services/memmgr/docs/ipc-interface.md](../services/memmgr/docs/ipc-interface.md#kernel-origin-fault-message-fault_label).

A declined fault, like every other unhandled one (the binding of its class cleared before delivery,
or the delivery cancelled; [Delivery, Resume, and Kill](#delivery-resume-and-kill)), takes the
outcome it has with no handler bound: a fault of a user-mode access kills the thread, and a fault of
a kernel copy fails its syscall with `InvalidAddress` ([Kernel Copies](#kernel-copies)). The reply
has this one meaning whatever raised the fault. The message is the same for both, and the handler
never chooses between the outcomes; binding a handler never changes the outcome of a fault it
declines. A handler that wants a thread ended whose kernel-copy fault it declines stops or destroys
it through its Thread capability. An upcall has no fault to leave unhandled: with no handler bound
it is not delivered, so a declined upcall is dropped and the thread continues
([Asynchronous Upcalls](#asynchronous-upcalls)).

---

## Kernel Copies

A syscall that copies to or from a caller-supplied user buffer can fault on that buffer inside the
kernel: the buffer lies on a page the pager has not backed (a demand region no access has reached,
or a page the pager has since reclaimed), or on a page whose mapping forbids the access. The
restartable syscalls, `SYS_GETRANDOM`, `SYS_THREAD_READ_REGS`, and `SYS_THREAD_WRITE_REGS`
([syscalls.md § Restartable Syscalls](../core/kernel/docs/syscalls.md#restartable-syscalls)), take
the fault path for such a fault:

- **Delivery.** With a handler bound, the kernel delivers `FAULT_KIND_VM` as for a user-mode access
  to the same address from the syscall instruction: the faulting address, the access (write for a
  copy to the buffer, read for a copy from it; bit 3 under the rules of
  [Fault Message](#fault-message)), and the syscall instruction as the faulting instruction
  pointer. The thread is fault-blocked with its register frame at that instruction, and the handler
  reads and edits it as for any fault.
- **Restart.** On `FAULT_REPLY_RESUME` the thread re-executes the syscall instruction: the syscall
  runs again from its start, with the frame's argument registers (as the handler left them), or the
  thread continues from an instruction pointer the handler wrote. A restartable syscall changes
  nothing visible outside the call before its copy and writes no register of the caller's frame,
  so its re-execution is a first call; a syscall MUST meet that rule to copy through this path.
- **No progress.** A handler that resumes without making the access satisfiable takes the same
  fault again on the re-execution, as a user-mode access would: each round is a full delivery to
  the handler, never a kernel retry, and ending the loop is the handler's policy.
- **Unhandled.** A fault the handler declines, or that is otherwise unhandled ([Reply](#reply)),
  fails the syscall with `InvalidAddress`; the thread continues past the syscall instruction, or
  from an instruction pointer the handler wrote. With no handler bound the syscall fails with
  `InvalidAddress` at once.
- **Stale entries.** A copy fault the live page tables already satisfy (a stale TLB entry, which a
  mapping the handler just installed can leave on another CPU) is retried in the kernel, as a
  user-mode fault is, and reaches neither the handler nor the caller.

The kernel cannot tell an address the pager registered from one it did not; the handler's reply
decides, as for a user-mode access. The registered IPC buffer page
([syscalls.md § `SYS_IPC_BUFFER_SET`](../core/kernel/docs/syscalls.md#sys_ipc_buffer_set-42)) is
not a caller-supplied buffer here: the kernel reads and writes it during IPC, around effects the
operation has committed, so it MUST stay mapped while IPC uses it, and a fault on it never reaches
the handler.

---

## Liveness

1. Each class's binding holds its own reference on the handler endpoint object, so a fault-blocked
   thread — which is queued on neither the endpoint's send nor receive queue — cannot be stranded by
   the endpoint being destroyed while it is bound. The reference is released on that class's unbind
   or rebind, or on thread destruction. The binder pins both the thread and the endpoint while it
   writes the binding, and a delivery pins the endpoint it read until it parks (see
   [Fault-Handler Binding](#fault-handler-binding)), so a release that drops the endpoint's last
   reference while a fault is queued on it destroys the endpoint under rule 3.
2. Destruction of the handler thread (deletion of the last capability to its Thread object)
   releases any fault-blocked thread awaiting that handler, leaving its fault unhandled (the
   [Kill](#delivery-resume-and-kill) path: the thread is killed, or its kernel copy's syscall
   fails), as does a later receive on the handler thread while the fault-blocked thread's reply
   is still pending (a receive that passes its capability and headroom checks; see
   [IPC Design](ipc-design.md#the-callreply-model)). A handler thread that only exits, or is
   stopped `Exited` by an object teardown, keeps its pending fault reply until it is destroyed.
3. A faulting thread blocked on a handler endpoint that has not yet received is released if
   that endpoint is destroyed.
4. Handler death is a system-level failure. Clients block on their next fault until a
   receiver reappears or a supervisor (procmgr, as a death observer) tears them down. The
   kernel does not special-case this beyond the rules above.

---

## Recursion and Escalation

Fault delivery for a thread is itself an operation that may fault — a handler thread can
take a fault while servicing one. Resolution is per-thread chaining: a handler's own faults
go to *its* handler, and a fault of a thread with no handler is unhandled ([Reply](#reply)),
which terminates the chain. A handler-bearing subsystem (e.g. a pager) MUST be reachable without
itself depending on the fault path — its own threads have no handler bound, or are eager-mapped —
so the chain is finite.

A thread MUST NOT be bound to a fault-handler endpoint that only it receives on; such a
thread would block on its own fault endpoint indefinitely.

---

## Asynchronous Upcalls

An upcall is the asynchronous, capability-triggered dual of fault delivery: a holder of a thread's
capability transfers the thread's control to the handler bound for its upcall class, at the
thread's next delivery point, and the thread then resumes. The upcall is delivered through the
fault machinery above, as a fault delivery of `FAULT_KIND_UPCALL` through the
`FAULT_CLASS_UPCALL` binding. The kernel adds no policy: no global upcall numbers, no default
action, and no ambient authority. A thread whose upcall class is unbound cannot be posted to.

### Posting

`SYS_THREAD_POST_UPCALL(thread_cap, cookie, flags)`:

- `thread_cap` MUST carry `UPCALL`, and also `CONTROL` when `flags` holds `UPCALL_ANY_INSTRUCTION`.
- `cookie` is the poster's word. The kernel delivers it uninterpreted and gives it no meaning.
- `flags` is `0` or `UPCALL_ANY_INSTRUCTION`. Any other bit fails with `InvalidArgument`.
- The post fails with `InvalidState` when the thread is `Created` or `Exited`, or has no handler
  bound for `FAULT_CLASS_UPCALL`. A right with no handler bound is inert.
- One upcall is pending on a thread at a time. A post while one is pending fails with `QueueFull`,
  and the pending upcall keeps its cookie.

### Delivery points

A pending upcall is delivered at the first delivery point the thread reaches after the post:

- **Syscall point** (`UPCALL_POINT_SYSCALL`): the return of any syscall of the thread, with the
  syscall's result already in its registers. A restartable syscall that re-executes after a fault
  of its user copy ([Kernel Copies](#kernel-copies)) has no return to deliver at until its
  re-execution returns.
- **Interrupt point** (`UPCALL_POINT_INTERRUPT`): only for an `UPCALL_ANY_INSTRUCTION` post. This
  is the return to user mode of an interrupt that preempted the thread, so it reaches a thread
  that makes no syscall. The post prods a CPU running the thread, so the thread takes an
  interrupt.

A thread at neither point keeps the upcall pending. Such a thread spins without syscalls, or was
posted to without `UPCALL_ANY_INSTRUCTION`.

Delivery suspends the thread fault-blocked and sends the [fault message](#fault-message) to the
receiver of the upcall class's endpoint. The message carries `FAULT_LABEL` and the binding's badge,
and its data words are `FAULT_KIND_UPCALL`, the cookie, the delivery point, and the thread's
instruction pointer as `SYS_THREAD_READ_REGS` reads it. On RISC-V at the syscall point, that
pointer names the `ecall`; the kernel steps past it on resume unless the handler wrote another
`pc`. The handler reads and edits the thread's registers as for a fault
([Modifying the faulting thread](#modifying-the-faulting-thread)).

Every disposition resumes the thread at its registers:

- A `FAULT_REPLY_RESUME` reply.
- A `FAULT_REPLY_KILL` reply. This declines the upcall, which drops it.
- A cancellation that drops the upcall. The cancellations are those of a fault
  ([Delivery, Resume, and Kill](#delivery-resume-and-kill)):
  - a stop of the thread before a reply (the thread resumes when next started);
  - the handler thread's destruction;
  - the handler thread receiving again;
  - the handler endpoint's destruction while the message is queued;
  - a binding found cleared at delivery.

A change of the upcall class's binding during a delivery delivers the upcall again under the new
binding, as for a fault. The [Liveness](#liveness) rules hold unchanged.

### Blocking syscalls

A post to a thread blocked in a syscall that can block cancels the block as a stop cancels it, and
wakes the thread. Those syscalls are listed in
[syscalls.md § Atomicity and Preemption Guarantees](../core/kernel/docs/syscalls.md#atomicity-and-preemption-guarantees)
(Blocking syscalls are interruptible).
The syscall returns `Interrupted`, unless a genuine wake or a sleep's elapsed deadline claimed it
first, and the upcall is delivered at that return. A blocking syscall that the thread enters with an
upcall pending returns `Interrupted` at once instead of blocking. The kernel restarts nothing;
whether to retry is the program's choice. For `SYS_IPC_CALL`, `Interrupted` does not mean that the
request went undelivered: a server that already received the message finds no reply pending, so a
program that retries a call may repeat its request, as after a stop.

A fault-blocked thread's fault, or an upcall delivery in progress, is never cancelled for an upcall:
the upcall waits for it to resolve. The protocol that keeps a post from missing a thread that is
about to block is
[thread-lifecycle-and-sleep.md § Upcall Cancel-and-Wake Protocol](../core/kernel/docs/thread-lifecycle-and-sleep.md#upcall-cancel-and-wake-protocol).

### Mask

`SYS_THREAD_SET_UPCALL_MASK(masked)` sets (`1`) or clears (`0`) the calling thread's upcall mask and
returns the previous one. A thread starts unmasked. While the mask is set:

- a post is accepted, and its upcall stays pending;
- no upcall is delivered;
- no block of the thread is cancelled.

Clearing the mask delivers a pending upcall at that syscall's own return. The mask is local to the
thread and takes no lock beyond the thread's own scheduler lock, so it brackets a critical section
without disturbing other threads.

### Nesting

- **Upcall during a fault.** An upcall posted to a fault-blocked thread stays pending and is
  delivered at the first delivery point after the fault resolves.
- **Upcall during an upcall.** Delivery takes the pending upcall, so a post during a delivery is
  accepted. It is delivered after the current one resolves, at the same delivery point when that
  point delivers it: a post without `UPCALL_ANY_INSTRUCTION` made during a delivery at the
  interrupt point waits for the thread's next syscall return.
- **The handler's own upcalls.** These go to the handler thread's own upcall binding, and its faults
  to its own fault handlers: per-thread chaining, as for faults
  ([Recursion and Escalation](#recursion-and-escalation)). A thread MUST NOT bind its upcall class
  to an endpoint that only it receives on.
- **A stopped thread** keeps a pending upcall, which is delivered at a delivery point after the
  thread is started. That includes one whose stop has committed while it still runs: it takes no
  upcall at the delivery points it passes before it leaves its CPU.
- **After a resume**, a fault the thread then takes (at an instruction pointer the handler wrote,
  for example) is an ordinary fault of its own class.

### Upcall security

A post needs `UPCALL` on the thread, a right a holder can keep while giving up `CONTROL` and
`OBSERVE`. Such a poster chooses only when the upcall happens and what its cookie is. What the
thread then does is decided by the handler that the holder of `CONTROL` bound, and only that
handler can edit the thread's registers, which `SYS_THREAD_WRITE_REGS` gates on `CONTROL`. A post
that may stop the thread at any instruction also needs `CONTROL`, which already lets its holder stop
the thread anywhere (`SYS_THREAD_STOP`).

The message's badge attributes the binding, not the poster. The cookie is the poster's own word, so
a handler that serves several posters cannot attribute an upcall to one of them by the message
alone.

---

## Debugging

A debugger is a userspace handler of a thread's exception class. It holds a Thread cap with
`OBSERVE`, to read the thread's registers, and `CONTROL`, to write them and to bind its handlers.
An asynchronous break also needs the upcall binding, and `UPCALL` beside `CONTROL` on the cap. The
kernel adds no debugging interface of its own. The pieces are:

- **Breakpoints.** A software breakpoint is `int3` on x86-64 and `ebreak` on RISC-V. It reaches
  the exception handler as `FAULT_KIND_EXCEPTION` with `FAULT_EXC_BREAKPOINT`. The reported
  instruction pointer is the hardware's:
  - x86-64 `#BP` is a trap, so the pointer is the instruction after `int3`, and resuming continues
    there;
  - RISC-V reports the `ebreak` itself, so a handler that resumes the thread steps the pointer past
    it: 2 bytes for `c.ebreak`, 4 for `ebreak`.

  The x86-64 `#BP` gate has DPL 3 so that a user `int3` raises `#BP` rather than `#GP`.
- **Single-step (x86-64).** A handler sets the trap flag (`X86_64_RFLAGS_TF`) in the stopped
  thread's `rflags` (`REGS_X86_64_FLAGS_OFFSET` of the register file) with
  `SYS_THREAD_WRITE_REGS`, and resumes it. The thread then takes `#DB` after each instruction,
  delivered as `FAULT_EXC_DEBUG` with the next instruction's pointer, until a handler clears the
  flag. Syscall entry clears the flag for the kernel, and the thread's return to user mode
  restores it. When the first `#DB` comes depends on that return's path:
  - **Through `sysretq`** (the return of a syscall), the restored flag traps at once, before any
    user instruction runs. So a stepped `syscall` steps past as one instruction, its `#DB` naming
    the instruction after it. Every other resume at a syscall return takes its first `#DB` at the
    pointer it stopped at, with no instruction run, and steps from there:
    - an upcall at the syscall point;
    - a stop while the thread was blocked in a syscall;
    - a syscall restarted after a fault of its user copy ([Kernel Copies](#kernel-copies)), whose
      `#DB` names the `syscall` instruction itself.
  - **Through `iretq`** (the return from a user-mode fault or exception, or from an interrupt,
    and a thread's first entry to user mode), one instruction runs before the first `#DB`. That
    covers a resume from a fault, a breakpoint or a step, from an upcall at the interrupt point,
    and from a stop of a thread an interrupt preempted; and the first start of a thread created
    stopped (`THREAD_START_SUSPENDED`) whose trap flag was set before that start, where the entry
    instruction runs first.
- **No single-step on RISC-V.** RISC-V has no user-mode single-step without a debug trigger. The
  kernel programs none: an instruction-count trigger is not available through the SBI Debug
  Triggers extension on the reference platform.
- **Registers and memory.** A handler reads and writes a stopped thread's registers with
  `SYS_THREAD_READ_REGS` and `SYS_THREAD_WRITE_REGS` ([Modifying the faulting
  thread](#modifying-the-faulting-thread)). A debugger thread of the debuggee's own process reaches
  the debuggee's memory directly while it is stopped. No syscall reads or writes another address
  space's memory.
- **Asynchronous break.** A debugger stops a running thread with an `UPCALL_ANY_INSTRUCTION`
  upcall ([Asynchronous Upcalls](#asynchronous-upcalls)). The thread is then fault-blocked, with
  its registers readable, at the delivery point the message's data word 2 names: the instruction
  an interrupt preempted, or a syscall's return.
- **Trap and emulate.** A handler that emulates a faulting instruction (an illegal instruction,
  say) writes the emulated result and the next instruction's pointer into the thread's registers
  and resumes it.

The `debugger` fixture drives the breakpoint, the x86-64 single-step, register and same-process
memory access, and the asynchronous break end to end
([programs/debugger/README.md](../programs/debugger/README.md)). ktest
`integration::fault_exception_redirect` drives a resume at a handler-written instruction pointer
after an illegal instruction, and `integration::single_step` steps a `syscall`.

---

## Security

The kernel synthesizes the fault delivery on the faulting thread's behalf using the bound
endpoint; it needs no send capability to the fault endpoint to deliver a fault. A handler
that hands out no `SEND` to its fault endpoint receives `FAULT_LABEL` only from the kernel.
The default pager's endpoint is not such an endpoint: it is memmgr's badged client endpoint,
and [`ProcessInfo`](process-lifecycle.md#processinfo--initinfo-handover-discipline)
distributes it as `SEND` to every demand-paged process (`pager_endpoint_cap`). A handler that
also serves ordinary clients on the same endpoint therefore cannot rely on the label alone: a
client holding `SEND` can send a message bearing `FAULT_LABEL`, carrying the badge of that
client's cap.

The badge is what attributes a fault there. The fault message badge is the derivation badge
of the Endpoint cap the binder bound, exactly the badge an ordinary send through that cap
carries, so it has the guarantees of [Capability Model § Badges](capability-model.md#badges):
set once by `SYS_CAP_DERIVE_BADGE`, inherited unchanged by every derived cap, and never chosen
by a binder (`SYS_THREAD_SET_FAULT_HANDLER`'s third argument is reserved). Binding requires
only `CONTROL` on the target thread and any `Endpoint` cap, a `SEND`-only one included, so a
client can bind its own threads to a shared endpoint, but its faults carry the badge of a cap
it holds, the same badge its own sends carry. memmgr mints one badged cap per process and
hands each process only its own, so a process that faults through `pager_endpoint_cap`
identifies itself, and its faults can back only its own registered regions; attributing a
fault to another process would need a cap bearing that process's badge, which memmgr never
gives it, or a copy of the binding of one of that process's threads
(`SYS_THREAD_INHERIT_FAULT_HANDLER`), which needs `CONTROL` on that thread. `CONTROL` on a
thread already lets its holder rewrite the thread's registers and so make it fault at any
address under its own binding, so the copy adds no authority over the faults attributed to that
process. `SYS_THREAD_GET_FAULT_HANDLER` discloses a binding's badge to a holder of `CONTROL`,
not a capability to its endpoint. Whether a badge value is guessable plays no part.

---

## Demand Paging and the Default System Pager

The page-fault case (`FAULT_KIND_VM`) is the basis for demand paging: a process reserves
virtual address space in the [page-reservation surface](userspace-memory-model.md#page-reservations)
without backing it, and on first access the pager allocates a frame and maps it. The pager
holds the faulting [address-space](capability-model.md#address-space) capability (attenuated
to the mapping rights it needs) and a frame source, and reclaims frames through the existing
process-death path of [Process Lifecycle](process-lifecycle.md#process-death).

Stack growth is built on it: the runtime registers each spawned thread's stack, and, for an
`ET_DYN` image, the part of the main thread's stack below the pages the loader commits, as demand
regions above an unregistered guard page, so a stack costs frames only as it grows and an overflow
faults on an address the pager declines (see
[Userspace Memory Model § Bootstrap Cross-Boundary VAs](userspace-memory-model.md#bootstrap-cross-boundary-vas)
and [ruststd § Spawned-thread stacks](../runtime/ruststd/README.md#spawned-thread-stacks)).

A kernel copy into or out of a caller-supplied buffer on a page of a demand region the pager has
not yet backed takes the same path through the restartable syscalls: the pager backs the page and
the syscall re-executes ([Kernel Copies](#kernel-copies)), so a caller need not touch its buffer
first.

### Default System Pager

The broadly useful memory policies — lazy and guard-page stack growth, zero-fill-on-demand
anonymous memory, copy-on-write sharing, swap and overcommit, working-set tracking,
snapshotting — exist only if a manager sits on the fault path of most processes. Binding a
default pager to all ordinary processes is a userspace policy decision (a creator default
plus the runtime's copy of the spawning thread's bindings onto each thread it spawns), not a
kernel one.

Demand paging is the **system-wide default**: procmgr binds memmgr (the pager) as the
fault handler on every process it creates and advertises it in
[`ProcessInfo`](process-lifecycle.md#processinfo--initinfo-handover-discipline)
(`pager_endpoint_cap` / `pager_badge`), and the runtime copies it onto spawned threads with the
spawning thread's bindings.
It is not a per-tier or per-service decision; a process is demand-paged simply because it is
a process.

The default MUST exempt only the narrow set that cannot depend on the fault path:

- **init, memmgr (the frame manager and pager), and procmgr** — these are pre-pager and are never
  routed through procmgr's pager-binding path (init is created by the kernel; it creates
  memmgr and procmgr via raw syscalls), so they are pinned by construction. A demand-paged
  pager would recurse on its own faults.
- **Drivers requiring pinned memory (DMA)** — a device may write a process's memory before a
  demand fault could back it, so DMA-capable drivers must be eager-mapped. The creator opts a
  process out with `procmgr_labels::CREATE_PINNED` (see
  [services/procmgr/docs/ipc-interface.md](../services/procmgr/docs/ipc-interface.md));
  devmgr sets it for the DMA-capable driver class (PCI devices with BAR + IRQ). The exemption
  is a creation-request flag, never a badge-range test.

A userspace fault round-trip is costlier than a kernel-internal fill; this cost is accepted
to keep paging policy out of the kernel.

svcmgr service definitions carry no paging key; see
[services/svcmgr/docs/service-definitions.md](../services/svcmgr/docs/service-definitions.md).

---

## Summarized By

[abi/process-abi/README.md](../abi/process-abi/README.md),
[Kernel Cross-Boundary Disclosure Inventory](../core/kernel/docs/cross-boundary-disclosure.md),
[SMP Scheduling and Locking Invariants](../core/kernel/docs/scheduling-internals.md),
[Syscall Interface Specification](../core/kernel/docs/syscalls.md),
[core/ktest/README.md](../core/ktest/README.md),
[Capability Model](capability-model.md), [IPC Design](ipc-design.md),
[Process Lifecycle](process-lifecycle.md), [Userspace Memory Model](userspace-memory-model.md),
[programs/deadline/README.md](../programs/deadline/README.md),
[programs/debugger/README.md](../programs/debugger/README.md),
[programs/demandpaged/README.md](../programs/demandpaged/README.md),
[programs/stackoverflow/README.md](../programs/stackoverflow/README.md),
[programs/threadstack/README.md](../programs/threadstack/README.md),
[runtime/ruststd/README.md](../runtime/ruststd/README.md),
[services/memmgr/README.md](../services/memmgr/README.md),
[memmgr IPC Interface](../services/memmgr/docs/ipc-interface.md),
[procmgr IPC Interface](../services/procmgr/docs/ipc-interface.md),
[`.svc` Service Definitions](../services/svcmgr/docs/service-definitions.md)
