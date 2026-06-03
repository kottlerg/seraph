# Fault Handling

Redirection of kernel-unresolvable userspace thread faults to a userspace handler,
the mechanism on which demand paging, swap, mmap, and similar policies are built.

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
- Liveness, recursion, and security rules.

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
fault kinds: `SYS_THREAD_SET_FAULT_HANDLER`, the per-thread fault-handler binding, the
[fault message](#fault-message) for `FAULT_KIND_VM` (page faults) and `FAULT_KIND_EXCEPTION`
(every other kernel-unresolvable ring-3 exception — illegal instruction, breakpoint,
alignment, divide, …), and the [resume and kill](#delivery-resume-and-kill) state machine —
including register inspection and modification of a fault-blocked thread via
[`SYS_THREAD_READ_REGS`/`SYS_THREAD_WRITE_REGS`](capability-model.md#thread). A thread with
no handler bound is still terminated, the behavior for all faults absent this mechanism.

Not yet implemented (this section is narrowed as each part lands):

- **The demand-paging consumer.** The `ProcessInfo` pager field referenced under
  [Demand Paging](#demand-paging-and-the-default-system-pager) and the demand-paged-memory
  consumer are not present yet.
- **Active unbind/rebind cancellation.** Clearing or rebinding a handler governs *future*
  faults; it does not yet actively cancel a fault already in flight on the affected thread.
  An in-flight fault is still resolved by the handler's reply, handler-thread death, the
  faulting thread being stopped or destroyed, or the handler endpoint being destroyed (all
  implemented). The remaining trigger — the binding being cleared mid-fault — is the only
  [Kill](#delivery-resume-and-kill) path not yet wired.

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

If the thread has **no** fault handler bound, the fault is terminal: the thread is killed
with exit reason `EXIT_FAULT_BASE + <fault code>`, the behavior for all faults absent this
mechanism.

Fault delivery reuses the synchronous IPC machinery of [IPC Design](ipc-design.md): the
suspended thread occupies the same role as a caller blocked awaiting a reply, and the
handler services it with the ordinary receive / reply cycle. Delivery is iterative
(suspend then reschedule), never kernel-stack recursion, so a chain of handlers cannot
exhaust the kernel stack.

---

## Fault-Handler Binding

The fault handler is bound **per thread**. The handler is an ordinary
[`Endpoint`](capability-model.md#ipc-endpoint); there is no distinct fault-endpoint
capability type. The binding is the new state.

`SYS_THREAD_SET_FAULT_HANDLER(thread_cap, endpoint_cap, badge, fault_class_mask)`:

- `thread_cap` MUST carry `CONTROL`. It selects the thread whose handler is set.
- `endpoint_cap` MUST refer to an `Endpoint`, or be the null index `0` to **unbind**.
  Binding takes a reference on the endpoint object for the lifetime of the binding (see
  [Liveness](#liveness)); unbinding releases it.
- `badge` is a caller-chosen value delivered as the fault message badge, identifying the
  faulting thread (or its process) to the handler. It is opaque to the kernel, mirroring
  the death-observer correlator of [Process Lifecycle](process-lifecycle.md#process-death).
- `fault_class_mask` selects which fault classes this handler covers. The defined value
  is the all-classes mask; it reserves the encoding for future per-class handlers without
  a new syscall.

A thread has a single fault handler covering all fault classes it is bound for. The
handler dispatches on the fault kind (see [Fault Message](#fault-message)) and replies
[`FAULT_REPLY_KILL`](#reply) for kinds it does not handle, recovering the default
terminal behavior for those kinds.

### Inheritance is userspace policy

The kernel does not propagate a fault handler to new threads. Because binding requires
only `CONTROL` on the target thread, propagation is expressed by whoever holds that
authority:

- A process creator (procmgr) MAY bind a handler on each process's initial thread.
- A process runtime MAY bind its own handler onto each thread it spawns. The process's
  page-fault pager is advertised to the runtime through
  [`ProcessInfo`](process-lifecycle.md#processinfo--initinfo-handover-discipline) for this
  purpose.

This makes a system-wide default pager (see [Default System Pager](#default-system-pager))
a policy decision, not a kernel change.

---

## Fault Message

The fault message is delivered to the handler endpoint by the kernel on the faulting
thread's behalf. Its format is a stable cross-boundary contract.

- **Label** — the reserved `FAULT_LABEL`. It marks the message as kernel-originated so a
  handler that multiplexes other traffic can distinguish faults. Userspace MUST NOT be
  able to forge it; see [Security](#security).
- **Badge** — the bound `badge`.
- **Data word 0** — the fault **kind**:
  - `FAULT_KIND_VM` — a virtual-memory (page) fault.
  - `FAULT_KIND_EXCEPTION` — a CPU exception with no kernel resolution (illegal
    instruction, alignment, divide error, and similar).
  - Remaining values are reserved for future kinds (e.g. capability faults).
- **Data words 1–3** — kind-specific:
  - `FAULT_KIND_VM`: faulting virtual address; access flags (bit 0 read, bit 1 write,
    bit 2 instruction fetch, bit 3 present-vs-not-present); faulting instruction pointer.
  - `FAULT_KIND_EXCEPTION`: a **normalized exception code** (an architecture-neutral class —
    illegal instruction, breakpoint, alignment, divide, protection, … — so a handler
    dispatches without architecture knowledge; an unrecognized code is treated as the
    unknown class); the **architecture auxiliary code** (x86-64 the hardware error code,
    `0` where the vector has none; RISC-V `stval`); the faulting instruction pointer. The
    kernel maps each architecture's raw vector/cause to a normalized class
    (`arch/x86_64/idt.rs`, `arch/riscv64/interrupts.rs`).

The faulting thread's full register state is not embedded; a handler that needs it reads
it with [`SYS_THREAD_READ_REGS`](capability-model.md#thread) on the faulting thread.

---

## Delivery, Resume, and Kill

A faulting thread with a bound handler enters a dedicated **fault-blocked** state distinct
from the call-reply blocked state, so its resume semantics differ from a syscall return:
it resumes by re-executing its faulting instruction, not by returning a value.

- **Resume (genuine reply).** The handler replies (default disposition
  [`FAULT_REPLY_RESUME`](#reply)). The kernel resumes the faulting thread with its register
  state preserved (or as modified by the handler; see below) and re-executes the faulting
  instruction. For a page fault whose handler has installed a satisfying mapping, the
  instruction now succeeds.
- **Kill (cancellation).** If the binding is severed before a reply — the handler thread
  dies, the binding is cleared, or the thread is stopped — the faulting thread is killed,
  exactly as an unhandled fault. It is never resumed with a spurious value.

### Modifying the faulting thread

A handler MAY alter the faulting thread's registers with
[`SYS_THREAD_WRITE_REGS`](capability-model.md#thread) before replying — for example to
advance the instruction pointer past an emulated instruction. The reply carries no register
payload; register changes are applied through the explicit thread-register authority and
take effect on resume. A handler that cannot make progress replies
[`FAULT_REPLY_KILL`](#reply) (or stops/destroys the thread via the thread capability).

---

## Reply

The kernel ignores reply data words. The reply **label** conveys disposition:

- `FAULT_REPLY_RESUME` — resume the faulting thread (the default).
- `FAULT_REPLY_KILL` — the handler declines; the kernel kills the faulting thread as an
  unhandled fault.

---

## Liveness

1. The binding holds a reference on the handler endpoint object, so a fault-blocked thread
   — which is queued on neither the endpoint's send nor receive queue — cannot be stranded
   by the endpoint being destroyed while it is bound. The reference is released on unbind,
   rebind, or thread destruction.
2. Handler-thread death releases any fault-blocked thread awaiting that handler, killing it
   (the [Kill](#delivery-resume-and-kill) path).
3. A faulting thread blocked on a handler endpoint that has not yet received is released if
   that endpoint is destroyed.
4. Handler death is a system-level failure. Clients block on their next fault until a
   receiver reappears or a supervisor (procmgr, as a death observer) tears them down. The
   kernel does not special-case this beyond the rules above.

---

## Recursion and Escalation

Fault delivery for a thread is itself an operation that may fault — a handler thread can
take a fault while servicing one. Resolution is per-thread chaining: a handler's own faults
go to *its* handler, and a thread with no handler is killed, terminating the chain. A
handler-bearing subsystem (e.g. a pager) MUST be reachable without itself depending on the
fault path — its own threads have no handler bound, or are eager-mapped — so the chain is
finite.

A thread MUST NOT be bound to a fault-handler endpoint that only it receives on; such a
thread would block on its own fault endpoint indefinitely.

---

## Security

The kernel synthesizes the fault delivery on the faulting thread's behalf using the bound
endpoint; it does not require, and the protocol does not distribute, a send capability to
the fault endpoint. A handler keeps `RECEIVE` and does not hand out `SEND`, so no other
party can deliver a forged fault message bearing `FAULT_LABEL`. The `badge` identifying the
faulting thread is fixed by the binder, not by the message sender.

---

## Demand Paging and the Default System Pager

The page-fault case (`FAULT_KIND_VM`) is the basis for demand paging: a process reserves
virtual address space in the [page-reservation surface](userspace-memory-model.md#page-reservations)
without backing it, and on first access the pager allocates a frame and maps it. The pager
holds the faulting [address-space](capability-model.md#address-space) capability (attenuated
to the mapping rights it needs) and a frame source, and reclaims frames through the existing
process-death path of [Process Lifecycle](process-lifecycle.md#process-death).

### Default System Pager

The broadly useful memory policies — lazy and guard-page stack growth, zero-fill-on-demand
anonymous memory, copy-on-write sharing, swap and overcommit, working-set tracking,
snapshotting — exist only if a manager sits on the fault path of most processes. The
mechanism is designed so binding a default pager to all ordinary processes is a userspace
policy decision (a creator default plus runtime propagation via `ProcessInfo`).

Such a default MUST exempt infrastructure that cannot depend on the fault path — init, the
frame manager, the pager itself, and drivers requiring pinned memory — by leaving them
without a pager (eager-mapped). A demand-paged pager would otherwise recurse on its own
faults. A userspace fault round-trip is costlier than a kernel-internal fill; this cost is
accepted to keep paging policy out of the kernel.

---

## Summarized By

[README.md](../README.md),
[IPC Design](ipc-design.md),
[Capability Model](capability-model.md),
[Process Lifecycle](process-lifecycle.md),
[Userspace Memory Model](userspace-memory-model.md)
