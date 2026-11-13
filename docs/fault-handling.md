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
- How the crash service uses the exception class to report a faulting process
  ([Crash Reports](#crash-reports)).

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

The crash-report consumer of the exception class is implemented on both architectures: procmgr's
crash endpoint, the forward of a declined page fault (`FAULT_REPLY_FORWARD`), the crash service, and
procmgr's registry of the threads the runtime spawns, through which a fault of any registered thread
is reported with its registers ([Crash Reports](#crash-reports)).

A change of the binding of an in-flight fault's class cancels that delivery and delivers the
fault again under the binding current then ([Rebind](#delivery-resume-and-kill)), on both
architectures.

The asynchronous upcall ([Asynchronous Upcalls](#asynchronous-upcalls)) is implemented on both
architectures: `SYS_THREAD_POST_UPCALL`, the third class `FAULT_CLASS_UPCALL`, delivery at a
syscall's return and, for an `UPCALL_ANY_INSTRUCTION` post, at an interrupt's return to user mode,
the cancel of a blocking syscall, and `SYS_THREAD_SET_UPCALL_MASK`. Its end-to-end consumer is the
`deadline` fixture's supervisor, which cancels a spinning worker at a deadline
([programs/deadline/README.md](../programs/deadline/README.md)).

A debugger's access to the memory of the address space a thread executes in
(`SYS_THREAD_READ_MEM`, `SYS_THREAD_WRITE_MEM`, [Debugging](#debugging)) is implemented on both
architectures, the instruction-fetch synchronisation of a text write included. Its end-to-end
consumer is the `debugger` fixture, which debugs a child process
([programs/debugger/README.md](../programs/debugger/README.md)). The GDB stub, which debugs a
process of a running system from a host GDB over the debug port, is implemented on both
architectures ([services/gdbstub/README.md](../services/gdbstub/README.md)).

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
is delivered through its class's binding, so distinct services can own a thread's classes (a
pager its virtual-memory faults, a debugger its exceptions, a supervisor its upcalls); with no
handler bound for its class, a fault takes the outcome it has with no handler bound at all. The one
fault that crosses classes is a virtual-memory fault its handler forwards
([`FAULT_REPLY_FORWARD`](#reply)), delivered again through the exception class; an exception
handler therefore dispatches on the message's kind, as [Fault Message](#fault-message) gives it, and
may receive `FAULT_KIND_VM` with a fifth data word.

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

A handler bound for several classes (`FAULT_CLASS_VM | FAULT_CLASS_EXCEPTION`) dispatches on the
fault kind (see [Fault Message](#fault-message)) and replies [`FAULT_REPLY_KILL`](#reply) for kinds
it does not handle, recovering for those kinds the outcome they have with no handler bound. procmgr
binds the two classes to distinct services: the virtual-memory class to memmgr, the pager, and the
exception class to its crash endpoint, which the crash service receives on
([Crash Reports](#crash-reports)).

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
- **Data word 4** — only on a fault a virtual-memory handler forwarded
  ([`FAULT_REPLY_FORWARD`](#reply)): the forwarder's reason word (`0` when its reply carried
  none), at `FAULT_FORWARD_REASON_WORD`. A delivery no handler forwarded carries four data words.

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
  resumes on a `FAULT_REPLY_RESUME` reply, the fault is unhandled on a `FAULT_REPLY_KILL` reply,
  and a `FAULT_REPLY_FORWARD` reply is acted on as at any forward ([Reply](#reply)): the fault is
  delivered through the exception class when the reply answered the `FAULT_CLASS_VM` delivery of
  a fault other than a kernel copy's and an exception handler is bound, and is otherwise
  unhandled. Destroying it while stopped ends it as for any stopped thread. A cancelled
  fault-blocked thread is never resumed at its faulting instruction: a thread whose own access
  faulted is killed (a stopped one when next started), and one whose kernel copy faulted has that
  syscall fail.
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
- `FAULT_REPLY_FORWARD` — the handler of a `FAULT_CLASS_VM` delivery declines and forwards the fault
  to the thread's `FAULT_CLASS_EXCEPTION` handler. The kernel delivers the same fault message
  there, data words 0–3 unchanged and the forwarder's data word 0 as data word 4
  ([Fault Message](#fault-message)), and that handler's reply decides, as for any delivery of its
  class: the thread stays fault-blocked meanwhile, with its registers readable, and every later
  delivery of the fault (after a change of the exception class's binding) is made through the
  exception class. With no exception handler bound, the forward is a `FAULT_REPLY_KILL` reply
  carrying the forwarder's data word 0 as its reason, so the outcome and the kernel's diagnostic
  are those of the decline. On a delivery of any other class, and on the fault of a restartable
  syscall's user copy ([Kernel Copies](#kernel-copies)), a forward is a `FAULT_REPLY_KILL` reply.
  The forwarder never waits on the handler it forwards to; memmgr, the pager, forwards every fault
  it cannot back, so a crash service sees them ([Crash Reports](#crash-reports)).

The kernel ignores reply capabilities, and every data word but one: data word 0 of a
`FAULT_REPLY_KILL` or `FAULT_REPLY_FORWARD` reply, when the reply carries data words, is the
handler's decline reason. The kernel does not interpret it. When the decline kills a thread whose
user-mode access faulted, the kernel prints it on its serial console, on a `fault unhandled` line
ahead of the `USERSPACE FAULT` diagnostic, which names the fault's kind, its address, and the
instruction pointer, and dumps the registers. The `fault unhandled` line also names the kernel's own
unhandled causes: the binding of the fault's class found cleared at delivery, the delivery cancelled
before a reply, and no handler bound for the fault's class at all, so every killed user fault that
the fault path considered has one. The kills the fault path never considers print none: an x86-64
user `#PF` with a reserved bit set, which no user action causes, and a syscall return whose
instruction pointer is not canonical ([Implementation Status](#implementation-status)). A decline
with no data words prints no reason. memmgr's reasons are tabled in
[services/memmgr/docs/ipc-interface.md](../services/memmgr/docs/ipc-interface.md#kernel-origin-fault-message-fault_label),
and the crash service's reason is its report's id
([services/crashd/docs/operation.md](../services/crashd/docs/operation.md) § Per Fault).

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
restartable syscalls, `SYS_GETRANDOM`, `SYS_THREAD_READ_REGS`, `SYS_THREAD_WRITE_REGS`,
`SYS_THREAD_READ_MEM`, and `SYS_THREAD_WRITE_MEM`
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
- **Unhandled.** A fault the handler declines or forwards (a forward of a kernel copy's fault is a
  decline, so no exception handler sees a fault the thread survives), or that is otherwise
  unhandled ([Reply](#reply)), fails the syscall with `InvalidAddress`; the thread continues past
  the syscall instruction, or from an instruction pointer the handler wrote. With no handler bound
  the syscall fails with `InvalidAddress` at once.
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
The syscall returns `Interrupted`, unless a genuine wake or the elapsed deadline of a sleep or a
timed wait claimed it first, and the upcall is delivered at that return. A blocking syscall that
the thread enters with an upcall pending returns `Interrupted` at once instead of blocking: the
pending upcall refuses the park, so a try-once (`WAIT_TRY_ONCE`), which never parks, and a call
whose result is already available return their own result. The kernel restarts nothing; whether
to retry is the program's choice. For `SYS_IPC_CALL`,
`Interrupted` does not mean that the request went undelivered: a server that already received the
message finds no reply pending, so a program that retries a call may repeat its request, as after
a stop.

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
`OBSERVE`, to read the thread's registers, and `CONTROL`, to write them, to read and write the
memory of the address space the thread executes in, and to bind its handlers. An asynchronous
break also needs the upcall binding, and `UPCALL` beside `CONTROL` on the cap. Beyond the memory
copies, the kernel adds no debugging interface of its own. A debugger in another process takes
those caps from procmgr's attach request, which a holder of the debug authority sends and which
returns the process's main thread and every thread its runtime registered
([procmgr IPC Interface](../services/procmgr/docs/ipc-interface.md) § Label 20: `ATTACH_PROCESS`);
a thread the process spawns after an attach is listed by the next one. Such a debugger MUST bind a
listed thread's exception or upcall class under a badge carrying
`procmgr_labels::DEBUGGER_BADGE_TAG` (bit 62) with bit 63 clear, the debugger tag, by which
procmgr tells a debugger's binding from its own crash binding and from a handler the target bound
itself (§ Label 20: `ATTACH_PROCESS` there). The pieces are:

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
- **Single-step (RISC-V).** RISC-V has no user-mode single-step without a debug trigger, and the
  kernel programs none: an instruction-count trigger is not available through the SBI Debug
  Triggers extension on the reference platform, so the extension is unused
  ([platform-requirements.md](platform-requirements.md) § riscv64 Classification). A debugger steps
  a stopped thread with breakpoints instead, with no kernel interface beyond the memory copies:
  - it reads the thread's registers and the instruction at its pointer, and computes the address
    the thread runs next from them (`shared/riscv-step`,
    [shared/riscv-step/README.md](../shared/riscv-step/README.md)): the fall-through, a
    conditional branch's taken or not-taken target, or a jump's target;
  - it saves the two bytes there and plants the 2-byte `c.ebreak` with `SYS_THREAD_WRITE_MEM` and
    `THREAD_MEM_TEXT`, so the write takes the kernel's text route described under Text writes
    below: the frame written through the kernel's own mapping, a frame mapped more than once
    refused, and instruction fetch synchronised on every hart before the call returns;
  - it resumes the thread, which runs the one instruction and traps at the `c.ebreak`, delivered as
    `FAULT_EXC_BREAKPOINT` at the successor's address (RISC-V reports the `ebreak` itself, so no
    pointer moves back); it writes the two bytes back before the next step or resume.

  One fault arrives per instruction, as `FAULT_EXC_BREAKPOINT`, not `FAULT_EXC_DEBUG`. The
  `c.ebreak` is two bytes, so it never reaches past the successor's first parcel; the C extension
  that encodes it is in the riscv64 floor. The route has hazards a hardware step has not:
  - another thread of the space that runs the stepped code while the breakpoint is planted traps
    at it too, so the debugger stops the space's other threads while it steps;
  - a step between `lr` and `sc` loses the reservation, so the `sc` fails each time it is stepped
    to and a stepped retry loop never ends;
  - an instruction whose successor lies within its own bytes (a jump to itself, or a 4-byte jump
    or taken branch to its own second parcel) cannot be stepped, since the breakpoint planted there
    overwrites it before it runs, and a breakpoint instruction cannot be stepped, since it traps at
    itself; the decoder refuses both.
- **Registers.** A handler reads and writes a stopped thread's registers with
  `SYS_THREAD_READ_REGS` and `SYS_THREAD_WRITE_REGS` ([Modifying the faulting
  thread](#modifying-the-faulting-thread)).
- **Memory.** A debugger reads and writes the memory of the address space a thread executes in
  with `SYS_THREAD_READ_MEM` and `SYS_THREAD_WRITE_MEM`, at most `MAX_THREAD_MEM_COPY` bytes a
  call, all or nothing, under `CONTROL` on the thread's cap
  ([syscalls.md](../core/kernel/docs/syscalls.md) § `SYS_THREAD_READ_MEM` (60)). Only pages
  present in the space are reached: the kernel does not fault a page in for the copy, so a
  demand-paged page the debuggee has not touched is refused until it has. The calls do not need
  the thread stopped, since they act on the space and not the thread, but the space's other
  threads keep running and storing; a debugger stops every thread of the space for a coherent
  view. A debugger thread of the debuggee's own process can also reach the memory directly.
- **Text writes.** A software breakpoint is planted by writing `int3` or `ebreak` over an
  instruction, and removed by writing the instruction back. Text is mapped read-only, so the write
  takes `THREAD_MEM_TEXT`: the kernel writes the frame through its own mapping and leaves the
  thread's mapping read-only and executable, so W^X holds for every user mapping. It refuses the
  write with `InsufficientRights` when the page was mapped through a capability carrying neither
  Write nor Execute (firmware tables, a page lent read-only, a loaded process's read-only data),
  and when the page's frame is mapped more than once, since the frame would then be text or data
  of another mapping, possibly another process's; procmgr's loader gives each process its own image
  frames ([services/procmgr/README.md](../services/procmgr/README.md) § Responsibilities), so a
  process's text takes it. Every write synchronises instruction fetch on every CPU before it
  returns
  ([memory-model.md § Instruction-Fetch Coherence](memory-model.md#instruction-fetch-coherence)),
  so the thread's next fetch of the page sees the new bytes. A thread of the space running while the
  write lands can execute old or new bytes, or on x86-64 an instruction it fetched before; so the
  debugger stops the space's other threads around a text write, and resumes the thread it stopped
  at a breakpoint only after restoring the instruction and moving the pointer back to it.
- **Asynchronous break.** A debugger stops a running thread with an `UPCALL_ANY_INSTRUCTION`
  upcall ([Asynchronous Upcalls](#asynchronous-upcalls)). The thread is then fault-blocked, with
  its registers readable, at the delivery point the message's data word 2 names: the instruction
  an interrupt preempted, or a syscall's return.
- **Trap and emulate.** A handler that emulates a faulting instruction (an illegal instruction,
  say) writes the emulated result and the next instruction's pointer into the thread's registers
  and resumes it.

A debugger that rebinds a process's exception class takes the process's crash reports away for as
long as it holds it, and holds no SEND on procmgr's crash endpoint to bind it back. procmgr does
that for it: the debugger sends `DETACH_PROCESS` when it lets go, and procmgr restores the bindings
unasked once the debugger's thread that the attach named as its watch has exited
([procmgr IPC Interface](../services/procmgr/docs/ipc-interface.md) § Label 20: `ATTACH_PROCESS`,
§ Label 24: `DETACH_PROCESS`). A debugger finds a process by the name its creator gave it
(§ Label 23: `LIST_PROCESSES` there).

The GDB stub ([services/gdbstub/README.md](../services/gdbstub/README.md)) puts these pieces behind
a host GDB: it attaches to the process its host names, binds each listed thread's exception and
upcall classes to its own endpoint, stops every thread with an `UPCALL_ANY_INSTRUCTION` upcall
whenever one stops (all-stop), and serves the GDB remote serial protocol on the debug port
([device-management.md](device-management.md)). `cargo xtask test-gdb` drives it from a batch GDB
session on both architectures ([testing.md](testing.md) § GDB stub (`test-gdb`)).

The `debugger` fixture drives the breakpoint, the single-step on both architectures, register and
same-process memory access, and the asynchronous break end to end, then reads and writes a debuggee
process's memory and plants, takes, and removes a breakpoint in its text
([programs/debugger/README.md](../programs/debugger/README.md)). ktest
`integration::fault_exception_redirect` drives a resume at a handler-written instruction pointer
after an illegal instruction; `integration::single_step` steps a `syscall` on x86-64 and, on
riscv64, steps a thread through taken and not-taken branches and jumps, compressed ones among them;
and `integration::thread_memory` drives the memory calls' copies, text writes, and refusals.

---

## Crash Reports

The crash service is a userspace handler of the exception class that reports a process dying on a
fault to the system log, then ends the faulting thread as the kernel would have: it declines the
fault (`FAULT_REPLY_KILL`), so the thread dies with the same exit reason and the same death flow
([Process Lifecycle § Process Death](process-lifecycle.md#process-death)). The service, its report,
and its limits are in [services/crashd/README.md](../services/crashd/README.md) and
[crashd Operation](../services/crashd/docs/operation.md); the report's
format, the contract the host-side symbolizer reads, in
[services/crashd/docs/block-format.md](../services/crashd/docs/block-format.md).

- **Binding.** procmgr creates one crash endpoint and binds each process's exception class to it at
  creation, badged with the process's badge; the runtime copies the binding onto every thread it
  spawns ([Inheritance is userspace policy](#inheritance-is-userspace-policy)). The virtual-memory
  class stays memmgr's, and memmgr forwards each fault it cannot back
  ([`FAULT_REPLY_FORWARD`](#reply)), so a page fault reaches the crash service too.
- **Threads.** Each thread the runtime spawns registers itself with procmgr before it runs its
  code, handing procmgr a cap of itself, and procmgr binds its exception class again under a crash
  badge of the thread's own. The badge of a fault message therefore names the faulting thread, and
  procmgr's attach request, given that badge, returns the thread's process, every live thread of
  it, and the named thread's place among them, so the crash service reads the registers and stack
  of the thread that faulted ([procmgr IPC Interface](../services/procmgr/docs/ipc-interface.md)
  § Label 22: `REGISTER_THREAD`, § Label 20: `ATTACH_PROCESS`). A thread that never registered keeps
  its spawner's badge, or the process badge when its registration was refused at the registry's
  bound or for procmgr's heap while it carried a debugger's binding, and is reported without
  registers.
- **Receiver.** While no crash service is registered, a procmgr thread receives on the endpoint and
  declines every fault, so an image that stages no crash service kills a faulting thread as with no
  handler bound. A crash service registers with procmgr's debug authority and receives on the
  endpoint until it dies, when procmgr's thread receives again
  ([procmgr IPC Interface](../services/procmgr/docs/ipc-interface.md)).
- **Uncovered processes.** A process whose stop would deadlock the crash service, since the service
  waits on it, declares itself undebuggable, which unbinds its exception class: logd and the serial
  and framebuffer drivers, which carry the service's log output, the debug port's virtio-console
  driver, which the GDB stub waits on, and the crash service itself; in a boot that stages them,
  svctest and the GDB stub, debug-authority holders, declare too. init,
  memmgr, and procmgr are not created by procmgr and are never bound. A fault of any of these
  takes the outcome it has with no handler bound, and the kernel's `fault unhandled` and
  `USERSPACE FAULT` lines are its only report. Any process may declare itself so; the declaration
  affects the declarer alone and is one-way. Before logd or either driver declares, at its startup,
  a fault of it reaches the crash service, which declines it once its bound passes. A process
  created `CREATE_PINNED`, or whose pager binding failed, has no virtual-memory handler: its page
  faults, which no pager forwards, kill it unreported.
- **Debuggers.** A debugger binds a thread's exception class over the crash endpoint
  ([Debugging](#debugging)); the crash service then sees none of that thread's faults. An unbind
  leaves the class unbound, not bound to the crash endpoint again; procmgr binds it back on the
  debugger's `DETACH_PROCESS`, and when the debugger dies attached.

Writing reports to disk is not the crash service's: the report persists through logd's disk and
network sinks, so the filesystem stays off the crash path (design intent; not yet implemented). A
core dump of the dead process, after the log report and skipped for a process on the storage path,
and a policy that holds a crashed process stopped for a debugger to rebind, are design intent; not
yet implemented.

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
regions above an unregistered guard, so a stack costs frames only as it grows and an overflow
faults on an address the pager declines (see
[Userspace Memory Model § Bootstrap Cross-Boundary VAs](userspace-memory-model.md#bootstrap-cross-boundary-vas)
and [ruststd § Spawned-thread stacks](../runtime/ruststd/README.md#spawned-thread-stacks)). A
process with no pager maps each spawned thread's stack at spawn instead, above a guard it leaves
unmapped, and an overflow into that guard is a page fault no pager forwards, which kills the
process ([Crash Reports](#crash-reports)).

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
  devmgr sets it for every PCI-bound driver whose declaration declares DMA
  ([driver-binding.md](driver-binding.md#driver-declarations) § Driver Declarations), and for
  the IOMMU driver, whose units walk its table pages. The exemption
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
[Platform Requirements](platform-requirements.md), [Process Lifecycle](process-lifecycle.md),
[Testing](testing.md), [Userspace Memory Model](userspace-memory-model.md),
[programs/deadline/README.md](../programs/deadline/README.md),
[programs/debugger/README.md](../programs/debugger/README.md),
[programs/demandpaged/README.md](../programs/demandpaged/README.md),
[programs/stackoverflow/README.md](../programs/stackoverflow/README.md),
[programs/threadstack/README.md](../programs/threadstack/README.md),
[runtime/ruststd/README.md](../runtime/ruststd/README.md),
[services/crashd/README.md](../services/crashd/README.md),
[crashd Operation](../services/crashd/docs/operation.md),
[services/gdbstub/README.md](../services/gdbstub/README.md),
[services/memmgr/README.md](../services/memmgr/README.md),
[memmgr IPC Interface](../services/memmgr/docs/ipc-interface.md),
[procmgr IPC Interface](../services/procmgr/docs/ipc-interface.md),
[`.svc` Service Definitions](../services/svcmgr/docs/service-definitions.md),
[shared/riscv-step/README.md](../shared/riscv-step/README.md)
