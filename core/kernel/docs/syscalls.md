# Syscall Interface Specification

This document defines the complete syscall ABI for Seraph: calling convention,
entry/exit mechanism, the full syscall table, per-call argument and return
specifications, error codes, and atomicity guarantees.

**Code counterparts:**
- [`abi/syscall/`](../../../abi/syscall/README.md) — `SYS_*` constants, `SyscallError`
  enum, scheduling and message constants. This is the binary contract: explicit stable
  reprs (`#[repr(C)]` structs, integer-repr enums), `no_std`, no deps outside `core`. Both
  the kernel and userspace depend on it. Changes here are ABI breaks.
- [`shared/syscall/`](../../../shared/syscall/README.md) — Rust wrapper functions for
  userspace. Thin inline-asm wrappers around the abi constants. No stability
  obligation; internal code reuse only.

---

## Calling Convention

### x86-64

Seraph uses the `SYSCALL`/`SYSRET` instructions on x86-64.

| Register | Role |
|---|---|
| `rax` | Syscall number (in); return value (out) |
| `rdi` | Argument 0 |
| `rsi` | Argument 1 |
| `rdx` | Argument 2 |
| `r10` | Argument 3 (not `rcx` — `SYSCALL` clobbers `rcx` with the return address) |
| `r8` | Argument 4 |
| `r9` | Argument 5 |
| `rcx` | Clobbered by `SYSCALL` (holds return address); not an argument register |
| `r11` | Clobbered by `SYSCALL` (holds saved rflags); not an argument register |

All other registers are preserved across a syscall, except the extra return registers
the IPC calls name (`r9` for `SYS_IPC_CALL`; `rsi` and `r8` for `SYS_IPC_RECV`; `rsi` for
`SYS_EVENT_RECV`). The callee-saved set matches the System V AMD64 ABI (`rbx`, `rbp`,
`r12`–`r15`).

**Return values:**

- `rax`: primary return value. On error, `rax` holds a negative `SyscallError` code.
  On success, `rax` holds the non-negative result (or zero if the call has no result).
- `rdx`: secondary return value (e.g. the label from `ipc_recv`, the acquired bits from
  `notification_wait`). A call with no secondary result leaves `rdx` unchanged. The IPC
  calls also return values in `rsi`, `r8` and `r9`: see § `SYS_IPC_CALL` (0),
  § `SYS_IPC_RECV` (2), and § `SYS_EVENT_RECV` (6).

**Errno convention:** The kernel returns the error code directly in `rax` as a
negative `i64`. There is no `errno` global — callers check the sign of `rax`.

### RISC-V

Seraph uses the `ECALL` instruction on RISC-V. The trap handler in `stvec` dispatches
`ecall` from U-mode to the syscall path.

| Register | Role |
|---|---|
| `a7` | Syscall number (in) |
| `a0` | Argument 0; primary return value (out) |
| `a1` | Argument 1; secondary return value (out) |
| `a2` | Argument 2 |
| `a3` | Argument 3 |
| `a4` | Argument 4 |
| `a5` | Argument 5 |

All other registers are preserved, except the extra return registers the IPC calls name
(`a2` for `SYS_IPC_CALL`; `a2` and `a3` for `SYS_IPC_RECV`; `a2` for `SYS_EVENT_RECV`).
Callee-saved registers are `s0`–`s11` and `sp` (matching the RISC-V calling convention); the
kernel also restores `ra`.

**Return values:** `a0` is the primary return value (negative on error). `a1` is the
secondary return value where applicable.

---

## Syscall Entry and Exit

### x86-64

On `SYSCALL`:
1. `rcx` ← `rip` (return address); `r11` ← `rflags`; the `rflags` bits in `SFMASK`
   are cleared
2. Transition to CPL 0 with kernel code segment
3. The entry stub's first instruction is `swapgs`: the kernel per-CPU GS base becomes
   active and the user GS base moves to `IA32_KERNEL_GS_BASE`
4. The stub saves the user `rsp` to `PerCpuData::user_rsp` and loads `rsp` from the
   per-CPU kernel stack pointer (`PerCpuData::kernel_rsp`, read through GS); `SYSCALL`
   itself does not change `rsp`, and TSS `RSP0` serves only interrupt and exception entry
5. Kernel saves the user register file (including `rcx` and `r11`) onto the kernel stack
6. Kernel calls `syscall::dispatch(tf)` with a pointer to the saved `TrapFrame`;
   `dispatch` reads the number from `rax` and arguments 0–5 from `rdi`, `rsi`, `rdx`,
   `r10`, `r8`, `r9`
7. Kernel writes return values into the saved register frame, except for a
   restarted syscall (§ Restartable Syscalls), whose frame `rip` it rewinds to the
   `SYSCALL` instruction
8. Kernel restores the user register file and switches to the user `rsp`
9. `cli; swapgs`: the user GS base is back in place, with interrupts off until `SYSRET`
   restores the user's `IF`
10. `SYSRET` restores `rip` from `rcx`, `rflags` from `r11`, transitions to CPL 3

No non-canonical return `rip` (at or above the boot paging depth's lower-half limit,
`1 << 47`, or `1 << 56` under `CR4.LA57`) can reach `SYSRET`, which would fault in
ring 0 on the user stack: the top user page is unmappable (`user_va_top`, see
[arch-interface.md](arch-interface.md) § `paging`), so the address after a `SYSCALL`
instruction is canonical, and `SYS_THREAD_CONFIGURE` and `SYS_THREAD_WRITE_REGS` reject
a non-canonical `rip`. The exit path still checks: a frame failing the check would
indicate a kernel defect, and the thread is terminated as for an unhandled user `#GP`
(vector 13) without the fault being offered to a bound fault handler, since no handler
action can make that frame's return valid. The GS-base exchange on every ring-3 entry
and exit follows [arch-interface.md](arch-interface.md) § `cpu`.

`SFMASK` clears `IF`, `TF`, `DF`, `AC`, `NT` and `IOPL` on `SYSCALL` entry, whatever
the user set: interrupts stay off until the kernel enables them, `DF` clear is the
string-instruction direction `copy_user` relies on, and `AC` clear keeps SMAP
enforced. Interrupts stay masked for the whole syscall, except in bounded
preempt-disabled, interrupt-enabled windows (see § Atomicity and Preemption Guarantees
and [scheduling-internals.md](scheduling-internals.md) § Lock Hierarchy).

### RISC-V

On `ECALL` from U-mode:
1. `sepc` ← `pc` (address of the `ecall` instruction)
2. `sstatus.SPP` ← 0 (was U-mode); `sstatus.SPIE` ← `sstatus.SIE`; `sstatus.SIE` ← 0
3. Execution jumps to `stvec` (the kernel trap handler)
4. Trap handler saves the full user register file to the per-thread trap frame
5. Trap handler checks `scause` — if it is an ecall from U-mode, routes to syscall path
6. Kernel calls `syscall::dispatch(tf)` with a pointer to the saved `TrapFrame`;
   `dispatch` reads the number from `a7` and arguments 0–5 from `a0`–`a5`
7. `dispatch` writes return values into the saved register frame (`a0`, `a1`, and for
   the IPC calls `a2`/`a3`), except for a restarted syscall (§ Restartable Syscalls)
8. After `dispatch` returns, the trap handler advances the saved `sepc` by 4, past the
   `ecall`, unless the syscall is restarted or dispatch rewrote `sepc`
   (`SYS_THREAD_WRITE_REGS`)
9. Kernel restores the user register file
10. `SRET` restores `pc` from `sepc`, restores `sstatus.SIE` from `sstatus.SPIE`,
    returns to U-mode (`sstatus.SPP` = 0)

### Restartable Syscalls

`SYS_GETRANDOM`, `SYS_THREAD_READ_REGS`, `SYS_THREAD_WRITE_REGS`, `SYS_THREAD_READ_MEM`, and
`SYS_THREAD_WRITE_MEM` are restartable: a fault
of the kernel's copy to or from the caller's buffer is handled as
[docs/fault-handling.md § Kernel Copies](../../../docs/fault-handling.md#kernel-copies)
specifies. With a fault handler bound to the caller, the fault is delivered as `FAULT_KIND_VM`
from the syscall instruction, and on `FAULT_REPLY_RESUME` the syscall re-executes from its start:
`dispatch` writes no return value, and the frame's instruction pointer names the syscall
instruction (x86-64 rewinds `rip` by the two bytes of `SYSCALL`; RISC-V leaves `sepc` at the
`ecall`). An unhandled fault, and every fault with no handler bound, fails the syscall with
`InvalidAddress`. A restartable syscall changes nothing visible outside the call before its copy
and writes no register of the caller's frame, so the re-execution sees its argument registers as
the first call did (on x86-64, the `rcx` and `r11` that `SYSCALL` overwrites carry no argument);
a syscall made restartable MUST meet the same rule. A copy fault the live tables already satisfy
(a stale TLB entry) is retried in the kernel and reaches neither the handler nor the caller. The
IPC buffer copies are not restartable: their faults fail or lose the transfer as
§ `SYS_IPC_BUFFER_SET` states.

---

## Syscall Numbers

**Authoritative source:** `abi/syscall/src/lib.rs` — the constants defined there
are the single source of truth. This table must match that file exactly.

Syscall numbers are ABI. A new syscall takes the next free number. While
the ABI is pre-1.0 (unstable), a number left vacant by a removed syscall may be
reclaimed for a new one, but a number in active use is never reassigned.

```
 0  SYS_IPC_CALL                 26  SYS_WAIT_SET_ADD
 1  SYS_IPC_REPLY                27  SYS_WAIT_SET_REMOVE
 2  SYS_IPC_RECV                 28  SYS_WAIT_SET_WAIT
 3  SYS_NOTIFICATION_SEND        29  SYS_IRQ_ACK
 4  SYS_NOTIFICATION_WAIT        30  SYS_IRQ_REGISTER
 5  SYS_EVENT_POST               31  SYS_CAP_DELETE
 6  SYS_EVENT_RECV               32  SYS_THREAD_SET_FAULT_HANDLER
 7  SYS_CAP_CREATE_ENDPOINT      33  SYS_MEMORY_SPLIT
 8  SYS_CAP_CREATE_NOTIFICATION  34  SYS_MMIO_MAP
 9  SYS_CAP_CREATE_EVENT_Q       35  SYS_IOPORT_BIND
10  SYS_CAP_CREATE_THREAD        36  SYS_CAP_INFO
11  SYS_CAP_CREATE_ASPACE        37  SYS_THREAD_SET_PRIORITY
12  SYS_CAP_CREATE_CSPACE        38  SYS_THREAD_SET_AFFINITY
13  SYS_CAP_CREATE_WAIT_SET      39  SYS_THREAD_READ_REGS
14  SYS_CAP_DERIVE               40  SYS_THREAD_WRITE_REGS
15  SYS_CAP_REVOKE               41  SYS_ASPACE_QUERY
16  SYS_MEM_MAP                  42  SYS_IPC_BUFFER_SET
17  SYS_MEM_UNMAP                43  SYS_SYSTEM_INFO
18  SYS_MEM_PROTECT              44  SYS_SBI_CALL
19  SYS_THREAD_START             45  SYS_MMIO_SPLIT
20  SYS_THREAD_STOP              46  SYS_THREAD_SLEEP
21  SYS_THREAD_YIELD             47  SYS_THREAD_BIND_NOTIFICATION
22  SYS_THREAD_EXIT              48  SYS_CAP_DERIVE_BADGE
23  SYS_THREAD_CONFIGURE         49  SYS_IRQ_SPLIT
24  SYS_CAP_COPY                 50  SYS_MEMORY_MERGE
25  SYS_CAP_MOVE                 51  SYS_IOPORT_SPLIT
                                 52  SYS_SCHED_SPLIT
                                 53  SYS_ASPACE_BIND_NOTIFICATION
                                 54  SYS_PROCESS_EXIT
                                 55  SYS_GETRANDOM
                                 56  SYS_THREAD_GET_FAULT_HANDLER
                                 57  SYS_THREAD_INHERIT_FAULT_HANDLER
                                 58  SYS_THREAD_POST_UPCALL
                                 59  SYS_THREAD_SET_UPCALL_MASK
                                 60  SYS_THREAD_READ_MEM
                                 61  SYS_THREAD_WRITE_MEM
                                 62  SYS_IRQ_MSG_ALLOC
```

**Implementation status.** Every number 0–62 has a handler; unallocated numbers
return `UnknownSyscall`.

---

## Error Codes

A syscall that inserts a capability into a CSpace (every `SYS_CAP_CREATE_*`, `SYS_CAP_COPY`,
`SYS_CAP_DERIVE`, `SYS_CAP_DERIVE_BADGE`, `SYS_CAP_MOVE`, and the split syscalls) leaves the
destination's IPC receive reserve (`CSPACE_IPC_RECV_RESERVE` free slots) untouched. Its
"slot-page pool exhausted" `OutOfMemory`, and its structural-ceiling `QuotaExceeded`, therefore
arise while that many slots are still free; only IPC capability transfer takes them
([capability-internals.md](capability-internals.md) § IPC Receive Reserve).

All syscalls return one of these error codes on failure. The value is negative in
`rax`/`a0`. Zero and positive values are success.

**Authoritative source:** `abi/syscall/src/lib.rs` — the `SyscallError` enum there
is the single source of truth. This block must match it exactly.

```rust
/// Syscall error codes returned in `rax` / `a0` as negative `i64` values.
///
/// On success the return value is `>= 0`. On error it is one of these
/// negative values. Userspace wrappers check `rax < 0` to detect errors.
#[repr(i64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallError
{
    /// Syscall number is not valid.
    UnknownSyscall = -1,
    /// Capability slot index is out of range, the slot is null, or the
    /// handle's generation is stale.
    InvalidCapability = -2,
    /// Caller does not hold sufficient rights for this operation.
    InsufficientRights = -3,
    /// A pointer argument does not satisfy alignment or range requirements.
    InvalidAddress = -4,
    /// An integer argument is out of the valid range for this call.
    InvalidArgument = -5,
    /// The operation would block but the caller requested non-blocking mode.
    WouldBlock = -6,
    /// Reserved; not returned by the current kernel.
    ObjectGone = -7,
    /// No memory available to satisfy the request.
    OutOfMemory = -8,
    /// The operation is not supported: on this object type, on this
    /// architecture, or (for a diagnostic query) in this boot; or the firmware
    /// returned an error (`SYS_SBI_CALL`).
    NotSupported = -9,
    /// The capability rights bitmask violates the W^X constraint.
    WxViolation = -10,
    /// Reserved; not returned by the current kernel.
    MsgTooLarge = -11,
    /// Reserved; not returned by the current kernel.
    Deadlock = -12,
    /// Event queue is full; post would be lost.
    QueueFull = -13,
    // -14 retired (`DmaUnsafe`, removed with `SYS_DMA_GRANT`); never reuse.
    /// The target object is not in the required state for this operation
    /// (e.g. thread not `Stopped` for `read_regs`/`write_regs`, or a wait set
    /// another thread already waits on).
    InvalidState = -15,
    /// A blocking operation was cancelled: the thread was stopped or
    /// interrupted by an upcall, the object it was blocked on was destroyed,
    /// or, for a call, the server received again, or was destroyed, before
    /// replying. The thread sees this as the return value of its blocked
    /// syscall. `SYS_THREAD_START` also returns it when its caller is stopped
    /// while the start waits for the target to settle (nothing is started).
    /// Batched capability operations (revoke, delete, move, a range split)
    /// also return it at their liveness backstop; each syscall's entry in
    /// core/kernel/docs/syscalls.md gives the state the backstop leaves.
    Interrupted = -16,
    /// A structural per-object ceiling was reached (e.g. a `CSpace`'s
    /// directory is full, or the object a new capability or a retype would
    /// reference already holds 2^31 references). Unlike `OutOfMemory`,
    /// donating memory (augment mode) cannot satisfy the request.
    QuotaExceeded = -17,
}
```

---

## IPC Syscalls

### `SYS_IPC_CALL` (0)

Send a message to an endpoint and block until a reply is received, or until an optional
timeout elapses.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `endpoint_cap` | Send capability to an IPC endpoint |
| 1 | `label` | Message label (opaque word; passed to server as-is) |
| 2 | `data_count`, `timeout_ms` | Bits 0–31: number of data words (0–MSG_DATA_WORDS_MAX). Bits 32–63: `timeout_ms`, `0` = no timeout (`syscall_abi::ipc_call_count_arg` packs both) |
| 3 | `cap_count` | Number of capabilities to transfer (0–MSG_CAP_SLOTS_MAX) |
| 4, 5 | (unused) | Ignored |

**Timeout:** A non-zero `timeout_ms` bounds the whole call, its wait for a receiver and its
wait for the reply, at timer-tick granularity. On expiry the call returns `WouldBlock`: a
caller still queued leaves the endpoint's send queue, and a caller already received loses its
reply binding, so the server's later `SYS_IPC_REPLY` finds no pending caller and returns
`InvalidCapability`. The request may therefore have been received, and acted on, when the call
times out. The field has no try-once value: every non-zero value is a bound in milliseconds.

**Capability handles:** When `cap_count` > 0, the kernel reads the `cap_count`
**full** cap handles (slot index plus per-slot generation, one `u64` per word) from
the caller's registered IPC buffer page, handle `i` at word
`MSG_CAP_HANDLES_WORD + i` (`MSG_DATA_WORDS_MAX + 1`), and copies them once before
validating them. The kernel generation-validates the sender's named slots: a stale
handle to a recycled slot is rejected (`InvalidCapability`) instead of transmitting
the slot's current occupant (see [capability-model.md](../../../docs/capability-model.md)
§ Capability Handle Format). The delivered destination handles are reported through
the result block in the receiver's IPC buffer page, at the same word offsets (see
[ipc-design.md](../../../docs/ipc-design.md) § Message Format).

**Data words:** When `data_count` > 0, the kernel reads the data words from
the caller's registered IPC buffer page (`SYS_IPC_BUFFER_SET`); the syscall
fails with `InvalidArgument` if none is registered. Reply data words are
written back to the same page when the server replies. No arbitrary user
pointer is dereferenced (see [ipc-design.md](../../../docs/ipc-design.md) § Message Format).

**Return:**

- `rax`/`a0`: 0 on success; `SyscallError` on failure
- `rdx`/`a1`: reply label (valid on success)
- `r9`/`a2`: reply data-word count

**Capability requirement:** `endpoint_cap` must have Send rights, plus Grant
when the message carries capabilities.

**Errors:** `InvalidCapability` (also: a cap slot is stale or Null),
`InsufficientRights`, `InvalidArgument` (a cap slot repeated in one message, or
`data_count` > 0 or `cap_count` > 0 with no IPC buffer page registered; a `data_count`
or `cap_count` above its maximum is clamped, not refused),
`InvalidAddress` (registered IPC buffer page unmapped), `InvalidState` (a cap
slot is pinned by an in-flight `SYS_CAP_REVOKE`, `SYS_CAP_MOVE`, or IPC capability
transfer), `QuotaExceeded` (a cap's object has its reference count at its 2^31 ceiling),
`Interrupted` (the call was cancelled while blocked, including by the receiving thread
receiving again before it replied; see `SYS_IPC_RECV`), `WouldBlock` (the timeout elapsed
before the reply). Cap-slot
problems are rejected before the caller blocks; a refusal that arises only
afterwards degrades to delivery with zero caps (the caller keeps its
capabilities; see [ipc-design.md](../../../docs/ipc-design.md) § Message Format).
A capability whose derived children take more than one lock
hold to migrate is moved in batches after the message commits (see
[capability-internals.md](capability-internals.md) § Move); if an ancestor's
revoke frees it meanwhile it arrives as handle 0 (the permanently null
slot), as it does when the receiver's CSpace is torn down meanwhile — the
sender then keeps it; if a concurrent deriver keeps its child list growing
past the batch backstop it arrives live while the sender's slot survives as
its derivation parent.

---

### `SYS_IPC_REPLY` (1)

Send a reply to the caller bound to this thread by its most recent `SYS_IPC_RECV`.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `label` | Reply label |
| 1 | `data_count` | Number of data words (0–MSG_DATA_WORDS_MAX) |
| 2 | `cap_count` | Number of capabilities to transfer (0–MSG_CAP_SLOTS_MAX) |
| 3, 4 | (unused) | Ignored |

The reply's cap handles travel as for `SYS_IPC_CALL`: full handles in the server's
IPC buffer page from word `MSG_CAP_HANDLES_WORD`, so a stale reply slot is rejected
rather than resolved to its current occupant (see
[capability-model.md](../../../docs/capability-model.md) § Capability Handle Format).

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The reply capability is implicit — it is the caller binding held in the calling
thread (`reply_tcb`, a per-thread field outside the CSpace, set at `SYS_IPC_RECV`
time; see [capability-internals.md](capability-internals.md) § Capability Transfer
in IPC). It is consumed by this syscall whether it succeeds or fails. If no reply
capability is present (this thread holds no pending caller: it received none, or the
caller was cancelled), the syscall returns `InvalidCapability`, unless a payload or cap
check fails first: `data_count` > 0 or `cap_count` > 0 with no IPC buffer page
registered returns `InvalidArgument`, an unmapped IPC buffer page `InvalidAddress`, and
an invalid reply cap slot its own error.

Data words follow the same rules as `SYS_IPC_CALL`: when `data_count` > 0
they are read from this thread's registered IPC buffer page and written to
the original caller's IPC buffer page; when `cap_count` > 0 the handles are read
from the same page's cap block.

**Capability requirement:** Implicit reply capability bound in the calling thread
(`reply_tcb`).

**Errors:** `InvalidCapability` (no pending reply, or a reply cap slot went
stale), `InvalidArgument` (a cap slot repeated in one reply, or
`data_count` > 0 or `cap_count` > 0 with no IPC buffer page registered), `InvalidAddress`
(registered IPC buffer page unmapped), `InvalidState` (a reply cap slot is
pinned by an in-flight `SYS_CAP_REVOKE`, `SYS_CAP_MOVE`, or IPC capability transfer),
`QuotaExceeded` (caller's CSpace
directory structurally full for reply cap transfer, or a transferred cap's object has its
reference count at its 2^31 ceiling), `OutOfMemory`
(slot-page pool exhausted); a `data_count` or `cap_count` above its maximum is clamped, not
refused, and the call never blocks, so it never returns `Interrupted`. Every payload or cap
failure while
a caller is pending — the data-path errors above included — consumes the
pending reply and wakes the caller with the `IPC_REPLY_TRANSFER_FAILED` label
and zero caps while the server receives the error (see
[ipc-design.md](../../../docs/ipc-design.md) § Message Format). A fault reply skips
cap processing entirely, and the label alone carries the disposition; a `FAULT_REPLY_KILL`
or `FAULT_REPLY_FORWARD` reply's data word 0, when sent, is read as the handler's decline reason
for the kernel's kill diagnostic or the forwarded message, and an unreadable word is dropped
rather than failing the reply (see
[fault-handling.md § Reply](../../../docs/fault-handling.md#reply)).

---

### `SYS_IPC_RECV` (2)

Wait for a call on an endpoint, with an optional bounded wait.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `endpoint_cap` | Receive capability to an IPC endpoint |
| 1 | `timeout_ms` | Wait policy: the sentinels of `SYS_EVENT_RECV` (below) |

| Value | Behaviour |
|---|---|
| `0` | Block until a caller arrives |
| `u64::MAX` (`WAIT_TRY_ONCE`) | Non-blocking try-once: take a queued caller, or return `WouldBlock` at once |
| `1 ..= MAX-1` | Block until a caller arrives or `timeout_ms` ms elapse, then return `WouldBlock` (at timer-tick granularity) |

**Return:**

- `rax`/`a0`: 0 on success; `SyscallError` on failure
- `rdx`/`a1`: label from the incoming message
- `rsi`/`a2`: badge of the incoming message (0 if unbadged)
- `r8`/`a3`: data-word count of the delivered message

The message's data words are written to the receiver's registered IPC buffer page, followed by the
cap-transfer result block (count, then the delivered destination handles) at word offset
`MSG_DATA_WORDS_MAX`. The kernel binds the caller to the receiving thread as its reply capability
(the per-thread `reply_tcb` field); `SYS_IPC_REPLY` consumes this binding implicitly. A receive
that passes its capability check and cap-slot pre-allocation while a reply is still pending first
releases the pending caller (a receive refused before then leaves the binding, and so does a
try-once that finds no caller, which therefore leaves the reply owed; a try-once that finds one
releases the pending caller as it binds the new one, and a bounded receive releases it before it
waits, whether or not the wait then times out): its
`SYS_IPC_CALL` returns `Interrupted`, a fault-blocked caller is killed as for any cancelled
fault episode (for the fault of a restartable syscall's user copy, that syscall fails with
`InvalidAddress`), and a caller blocked in an upcall delivery has its upcall dropped and resumes
([fault-handling.md](../../../docs/fault-handling.md#asynchronous-upcalls) § Asynchronous
Upcalls). The binding is therefore never overwritten
([ipc-design.md](../../../docs/ipc-design.md) § The Call/Reply Model).

For a call, the badge is the value attached to the sender's endpoint capability via
`SYS_CAP_DERIVE_BADGE`; it identifies the caller without a forgeable PID. For a
kernel-synthesized fault message (`FAULT_LABEL`), the badge is the one attached to the
Endpoint capability bound by `SYS_THREAD_SET_FAULT_HANDLER` (see
§ `SYS_THREAD_SET_FAULT_HANDLER` and [fault-handling.md](../../../docs/fault-handling.md)
§ Security).

**Capability requirement:** `endpoint_cap` must have Receive rights.

**Errors:** `InvalidCapability`, `InsufficientRights`, `QuotaExceeded` (server's CSpace
directory cannot supply `MSG_CAP_SLOTS_MAX` free slots), `OutOfMemory` (fewer than
`MSG_CAP_SLOTS_MAX` slots free and the slot-page pool exhausted) — both checked before the
receive parks, whether or not a message carries caps. The free slots counted include the IPC
receive reserve that general allocations leave free
([capability-internals.md](capability-internals.md) § IPC Receive Reserve), so only received
caps that have spent the reserve fail a receive
(see [ipc-design.md](../../../docs/ipc-design.md) § Receive-Failure Policy),
`Interrupted`, `WouldBlock` (a try-once found no caller, or a bounded wait elapsed). If an
already-queued sender's cap transfer is refused (a source slot went stale
or is pinned by an in-flight `SYS_CAP_REVOKE`, `SYS_CAP_MOVE`, or IPC capability transfer, a
cap's object has its reference count at its 2^31 ceiling, or the server's CSpace cannot supply the
destination slots, which the pre-park grow makes unlikely but does not reserve), the message is
still delivered — with zero caps; the sender keeps its
capabilities (see [ipc-design.md](../../../docs/ipc-design.md) § Message Format and
§ Receive-Failure Policy).

---

### `SYS_NOTIFICATION_SEND` (3)

OR bits into a notification object. Non-blocking; if threads are waiting and pending bits
remain when the send claims them, wakes the longest-waiting one with every pending bit. A send
whose bits an arriving wait or a concurrent send already took wakes no waiter (see
`SYS_NOTIFICATION_WAIT` and [ipc-design.md](../../../docs/ipc-design.md) § Notifications).

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `notification_cap` | Notification capability with Notify rights |
| 1 | `bits` | Bitmask to OR into the notification word |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

**Capability requirement:** `notification_cap` must have Notify rights.

**Errors:** `InvalidCapability`, `InsufficientRights`, `InvalidArgument` (bits == 0).

---

### `SYS_NOTIFICATION_WAIT` (4)

Block until at least one bit is set in the notification object, or until the
optional millisecond timeout elapses. Returns and atomically clears the
entire bitmask (see [ipc-design.md](../../../docs/ipc-design.md) § Notifications).

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `notification_cap` | Notification capability with Wait rights |
| 1 | `timeout_ms` | Wait policy: see sentinels below |

| Value | Behaviour |
|---|---|
| `0` | Block until a bit is set |
| `u64::MAX` (`WAIT_TRY_ONCE`) | Non-blocking try-once: return the pending bits, clearing them, or `WouldBlock` at once when none are set; the caller joins neither the notification's wait queue nor the sleep list |
| `1 ..= MAX-1` | Block until a bit is set, or return a zero bitmask once `timeout_ms` ms have elapsed (at timer-tick granularity; the kernel's sleep list has no capacity to refuse the wait, [thread-lifecycle-and-sleep.md § Sleep List Invariants](thread-lifecycle-and-sleep.md#sleep-list-invariants), invariant 4) |

**Return:**

- `rax`/`a0`: 0 on success; `SyscallError` on failure
- `rdx`/`a1`: acquired bitmask on success (non-zero on notification wake,
  because `SYS_NOTIFICATION_SEND` rejects zero-bit sends; `0` when the wait's
  timeout elapsed)

Same register layout as `SYS_EVENT_RECV`. The split avoids aliasing
bit-63-set bitmasks with the dispatcher's negative-Err encoding, so the
full 64-bit bitmask range is usable.

**Capability requirement:** `notification_cap` must have Wait rights.

**Errors:** `InvalidCapability`, `InsufficientRights`, `Interrupted` (the caller was stopped or
interrupted by an upcall, or the notification was destroyed while the caller waited),
`WouldBlock` (a try-once found no bit set; an elapsed bounded wait returns a zero bitmask
instead).

Several threads may wait on one notification. They queue in arrival order, and each delivery wakes
the longest-waiting one with every pending bit. A wait that enters while bits are pending takes
them at once, ahead of any queued waiter.

---

### `SYS_EVENT_POST` (5)

Append one entry to an event queue. Non-blocking; returns `QueueFull` if at capacity
(see [ipc-design.md](../../../docs/ipc-design.md) § Event Queues). An entry is two words, a
payload word and a tag word; any value of either, 0 included, is valid.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `queue_cap` | Event queue capability with Post rights |
| 1 | `payload` | Payload word of the entry |
| 2 | `tag` | Tag word of the entry |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

**Capability requirement:** `queue_cap` must have Post rights.

**Errors:** `InvalidCapability`, `InsufficientRights`, `QueueFull`.

---

### `SYS_EVENT_RECV` (6)

Dequeue the next entry from an event queue with optional bounded wait.

**Arguments:**

| # | Name         | Description                                             |
|---|--------------|---------------------------------------------------------|
| 0 | `queue_cap`  | Event queue capability with Recv rights                 |
| 1 | `timeout_ms` | Wait policy: see sentinels below                        |

`timeout_ms` sentinels, shared by `SYS_IPC_RECV`, `SYS_NOTIFICATION_WAIT`, and
`SYS_WAIT_SET_WAIT` (`u64::MAX` is `syscall_abi::WAIT_TRY_ONCE`; an elapsed
`SYS_NOTIFICATION_WAIT` returns a zero bitmask rather than `WouldBlock`):

| Value             | Behaviour                                                       |
|-------------------|-----------------------------------------------------------------|
| `0`               | Block forever until a post arrives                              |
| `u64::MAX`        | Non-blocking try-once; return `WouldBlock` if empty             |
| `1 ..= MAX-1`     | Block until post arrives or `timeout_ms` ms elapse |

**Return:**

- `rax`/`a0`: 0 on success; `SyscallError` on failure
- `rdx`/`a1`: payload word of the dequeued entry (valid on success)
- `rsi`/`a2`: tag word of the dequeued entry (valid on success)

**Capability requirement:** `queue_cap` must have Recv rights.

**Errors:** `InvalidCapability`, `InsufficientRights`, `WouldBlock`, `Interrupted` (the caller was
stopped or interrupted by an upcall, or the queue was destroyed while the caller was parked).

Blocked receivers queue in arrival order; each post wakes the longest-waiting one.

`WouldBlock` covers both the try-once-empty case and the timer-fired case;
the caller already knows which mode it asked for. The kernel uses an
out-of-band marker (`tcb.timed_out`) rather than an in-band
`wakeup_value` sentinel because event-queue payloads may be any `u64`
(0 included; see [ipc-internals.md](ipc-internals.md) § Event Queue, Recv Path)
— contrast `SYS_NOTIFICATION_WAIT`, where a notification wake never carries
0 bits because `SYS_NOTIFICATION_SEND` rejects zero-bit sends, so a `0` result
means the wait's timeout elapsed.

---

## Capability Handles

A capability handle — the `u64` value passed in and returned through the cap
argument and return registers, the full width of each — packs a per-slot
generation with the slot index: `handle = (generation << 32) | index`. The low 32
bits are the `CSpace` slot index; bits 32 to 62 are the slot's generation, which
the kernel bumps each time the slot is freed and recycled, wrapping at 2^31, so
bit 63 is always clear and a handle in the primary return register never reads as
a negative error code. Every cap-bearing syscall checks the handle's generation
against the slot's current generation and returns `InvalidCapability` on mismatch
(a handle with bit 63 set never matches) — a handle held across a free/reallocate
of its slot fails closed rather than aliasing the unrelated capability now at that
index (#349), unless it is held across exactly a multiple of 2^31 recycles of the
index. A never-recycled slot has generation 0, so its handle equals the bare index,
and a `0` handle means "no capability". An explicit destination index
(`SYS_CAP_COPY` and `SYS_CAP_MOVE`) is a bare slot index, not a handle: a value that
does not fit 32 bits returns `InvalidArgument`. Range-split syscalls return their two
child handles in the primary and secondary return registers. See
[capability-model.md](../../../docs/capability-model.md) § Capability Handle
Format.

---

## Capability Syscalls

Every `SYS_CAP_CREATE_*` call below, in create-mode and in augment-mode, carves the new object's
bytes from `memory_cap`'s region, and never from a page that some address space maps: a carve
whose bytes would advance the region's retype bump cursor over a page any user mapping still
names fails with `OutOfMemory` and changes nothing (the region's available bytes, retype cursor,
and free lists are as before the call). The page becomes retypable once every mapping of it is
gone, by `SYS_MEM_UNMAP` or by the destruction of the address space that maps it (see
[docs/capability-model.md § Typed Memory](../../../docs/capability-model.md#typed-memory)). Each
call's `OutOfMemory` for its Memory cap region covers this refusal.

### `SYS_CAP_CREATE_ENDPOINT` (7)

Retype a Memory capability into a new IPC endpoint. Returns a capability with
Send + Receive + Grant rights.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `memory_cap` | Memory capability (Retype rights) the endpoint object is carved from |

**Return:**

- `rax`/`a0`: new capability descriptor on success (positive); `SyscallError` on failure

**Capability requirement:** `memory_cap` must have Retype rights.

**Errors:** `InvalidCapability`, `InsufficientRights` (source Memory cap lacks Retype),
`OutOfMemory` (Memory cap region or slot-page pool exhausted), `QuotaExceeded`
(caller's CSpace directory structurally full, or the Memory object's reference count is at
its 2^31 ceiling).

---

### `SYS_CAP_CREATE_NOTIFICATION` (8)

Retype a Memory capability into a new notification object. Returns a capability with
Notify + Wait rights.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `memory_cap` | Memory capability (Retype rights) the notification object is carved from |

**Return:** `rax`/`a0`: new capability descriptor on success; `SyscallError` on failure.

**Capability requirement:** `memory_cap` must have Retype rights.

**Errors:** `InvalidCapability`, `InsufficientRights` (source Memory cap lacks Retype),
`OutOfMemory` (Memory cap region or slot-page pool exhausted), `QuotaExceeded`
(caller's CSpace directory structurally full, or the Memory object's reference count is at
its 2^31 ceiling).

---

### `SYS_CAP_CREATE_EVENT_Q` (9)

Retype a Memory capability into a new event queue with a fixed capacity and a fixed pool of
death-observer nodes.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `memory_cap` | Memory capability (Retype rights) the event queue is carved from |
| 1 | `capacity` | Ring buffer capacity in entries (1–EVENT_QUEUE_MAX_CAPACITY) |
| 2 | `observers` | Death-observer nodes in the queue's pool (0–EVENT_QUEUE_MAX_CAPACITY) |

The retype debit is `event_queue_retype_bytes(capacity, observers)`: the ring, and one node per
observer, live inline in the queue's retype slot. Each `SYS_THREAD_BIND_NOTIFICATION` or
`SYS_ASPACE_BIND_NOTIFICATION` onto the queue holds one node while its binding lives; a queue that
receives no death posts takes `observers = 0`.

**Return:** `rax`/`a0`: new capability descriptor (Post + Recv rights) on success;
`SyscallError` on failure.

**Capability requirement:** `memory_cap` must have Retype rights.

**Errors:** `InvalidArgument` (`capacity`, the full register, is 0 or exceeds
`EVENT_QUEUE_MAX_CAPACITY`, or `observers` exceeds it), `InvalidCapability`,
`InsufficientRights` (source Memory cap lacks Retype), `OutOfMemory` (Memory cap region
or slot-page pool exhausted), `QuotaExceeded` (caller's CSpace directory structurally full,
or the Memory object's reference count is at its 2^31 ceiling).

---

### `SYS_CAP_CREATE_THREAD` (10)

Retype a Memory capability into a new thread bound to an existing address space and
CSpace.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `memory_cap` | Memory capability (Retype rights); supplies the thread's kernel stack, its guard page, TCB, and FPU save area: `SystemInfoType::ThreadRetypeBytes` bytes |
| 1 | `aspace_cap` | Address space capability (Map rights) the thread executes in |
| 2 | `cspace_cap` | CSpace capability (Insert rights) the thread is bound to |
| 3 | `sched_cap` | `SchedControl` capability governing the creation priority, or 0 |
| 4 | `priority` | Initial priority, or 0 |

**Return:** `rax`/`a0`: new thread capability (Control + Observe + Upcall rights) on success;
`SyscallError` on failure.

The thread is created in the `Created` state; it does not begin execution until
`SYS_THREAD_START` is called. The entry point, stack pointer, argument register, and
TLS base are not set here — they are supplied by `SYS_THREAD_CONFIGURE` before start.
The creation priority is stated at creation: with `sched_cap` = 0, `priority` must
also be 0 and the thread is created at the floor (`PRIORITY_MIN`) — floor-only
creation needs no scheduling authority. With a `SchedControl` cap, `priority` = 0
selects the cap's band floor (`min`), and a nonzero `priority` must lie within the
cap's `[min, max]` band. Later changes go through `SYS_THREAD_SET_PRIORITY`.

**Capability requirements:** `memory_cap` (Retype), `aspace_cap` (Map), `cspace_cap`
(Insert), and — only to create above the floor — `sched_cap` (presence, band covering
`priority`). Map is intentionally reused for `aspace_cap`: a process that can modify an
address space's mappings is inherently trusted to create threads that execute within it.

**Errors:** `InvalidCapability`, `InsufficientRights` (a source cap lacks Retype/Map/Insert
respectively, or `priority` is outside `sched_cap`'s band), `InvalidArgument` (nonzero
`priority` without a `SchedControl` cap, or `priority` > `PRIORITY_MAX`), `OutOfMemory`
(Memory cap region or slot-page pool exhausted, or the kernel's guard-table reserve, which its
sizing makes unreachable; [memory-internals.md](memory-internals.md) § Kernel Stack Guards),
`QuotaExceeded` (caller's CSpace
directory structurally full, or the Memory object's reference count is at its 2^31 ceiling).

---

### `SYS_CAP_CREATE_ASPACE` (11)

Retype a Memory capability into a new, empty address space (create-mode), or donate
carved pages to an existing address space's page-table growth pool (augment-mode). The
kernel's higher-half mapping is shared into a newly created address space automatically.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `memory_cap` | Memory capability (Retype rights) the address space slab is carved from |
| 1 | `augment_cap` | `0` for create-mode; otherwise an AddressSpace cap (Map rights) whose PT growth pool receives the carved pages |
| 2 | `init_pages` | Pages to carve (create-mode requires `>= 2`: wrapper + root PT, remainder seed the PT growth pool) |

**Return:** `rax`/`a0`: create-mode — new address space capability (Map + Control rights,
plus Read when `memory_cap` carries the Memory `Phys` right); augment-mode — `0`.
`SyscallError` on failure.

Read gates only `SYS_ASPACE_QUERY`, which returns physical addresses, so it is minted only
from a source that already lets its holder read its frames' physical base
(`CAP_INFO_MEMORY_PHYS_BASE`): an address space a process creates from memory without the
`Phys` right cannot translate the pages it maps into it
([cross-boundary-disclosure.md](cross-boundary-disclosure.md) § Physical-address surfaces).

Augment-mode donations are unbounded in count. Once the target's inline donation
records are full, the kernel keeps its bookkeeping in the donations themselves: once per
record page (see [capability-internals.md](capability-internals.md) § Page Pools)
a donation's first page becomes that bookkeeping and only `init_pages − 1` pages reach
the pool, so a one-page donation can leave the budget unchanged. Read the budget back via
`SYS_CAP_INFO` rather than assuming `init_pages` were added.

`Control` lets the creator register terminal-fault death observers via
`SYS_ASPACE_BIND_NOTIFICATION`; copies handed to other components drop it via the
`SYS_CAP_DERIVE` rights mask (see
[capability-model.md](../../../docs/capability-model.md) § Address Space).

**Capability requirements:** `memory_cap` (Retype); in augment-mode, `augment_cap` (Map).

**Errors:** `InvalidArgument` (`init_pages` 0, overflow, or create-mode `init_pages < 2`),
`InvalidCapability`, `InsufficientRights` (source Memory cap lacks Retype, or augment
target lacks Map), `OutOfMemory` (Memory cap region or slot-page pool exhausted),
`QuotaExceeded` (caller's CSpace directory structurally full, or the Memory object's reference
count is at its 2^31 ceiling).

---

### `SYS_CAP_CREATE_CSPACE` (12)

Retype a Memory capability into a new, empty CSpace (create-mode), or donate carved
pages to an existing CSpace's slot-page pool (augment-mode).

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `memory_cap` | Memory capability (Retype rights) the CSpace slab is carved from |
| 1 | `augment_cap` | `0` for create-mode; otherwise a CSpace cap (Insert rights) whose slot-page pool receives the carved pages |
| 2 | `init_pages` | Pages to carve (create-mode: page 0 is the wrapper and pages `1..init_pages` seed the slot-page pool; augment-mode: every page goes to the target's pool, less a record page where one is opened) |
| 3 | — | Reserved (formerly `max_slots`); MUST be `0` in both modes, else `InvalidArgument` |

**Return:** `rax`/`a0`: create-mode — new CSpace capability (Insert + Delete + Derive
rights); augment-mode — `0`. `SyscallError` on failure.

Augment-mode donations are unbounded in count, with the same bookkeeping as
`SYS_CAP_CREATE_ASPACE`: once per record page a donation's first page is kept by
the kernel and only `init_pages − 1` pages reach the pool (see
[capability-internals.md](capability-internals.md) § Donation Records).

**Capability requirements:** `memory_cap` (Retype); in augment-mode, `augment_cap` (Insert).

**Errors:** `InvalidArgument` (`init_pages` 0 or overflow, or arg 3 non-zero),
`InvalidCapability`, `InsufficientRights` (source Memory cap lacks Retype, or augment
target lacks Insert), `OutOfMemory` (Memory cap region or slot-page pool exhausted, or,
in create-mode, every id of the kernel's `CSpace` registry live, which the registry's
one id per DRAM page puts past the memory that pays for the `CSpace`s; see
[capability-internals.md](capability-internals.md) § CSpace Registry),
`QuotaExceeded` (caller's CSpace directory structurally full, or the Memory object's reference
count is at its 2^31 ceiling).

---

### `SYS_CAP_CREATE_WAIT_SET` (13)

Retype a Memory capability into a new wait set of a fixed member capacity.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `memory_cap` | Memory capability (Retype rights) the wait set is carved from |
| 1 | `capacity` | Member capacity (1–`WAIT_SET_MAX_MEMBERS`, 1024) |

The retype debit is `wait_set_retype_bytes(capacity)`: the member slots and the ready ring live
inline in the set's retype slot. `SYS_WAIT_SET_ADD` past `capacity` members is refused.

**Return:** `rax`/`a0`: new wait set capability (Modify + Wait rights) on success;
`SyscallError` on failure.

**Capability requirement:** `memory_cap` must have Retype rights.

**Errors:** `InvalidArgument` (`capacity`, the full register, is 0 or exceeds
`WAIT_SET_MAX_MEMBERS`), `InvalidCapability`, `InsufficientRights` (source Memory cap lacks
Retype), `OutOfMemory` (Memory cap region or slot-page pool exhausted), `QuotaExceeded`
(caller's CSpace directory structurally full, or the Memory object's reference count is at
its 2^31 ceiling).

---

### `SYS_CAP_DERIVE` (14)

Derive a new capability from an existing one, with equal or fewer rights.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `source_cap` | Source capability descriptor |
| 1 | `rights_mask` | Rights bitmask for the derived capability |

**Return:** `rax`/`a0`: new capability descriptor on success; `SyscallError` on failure.

The derived capability references the same kernel object, except that a derived `Mmio`,
`IoPort`, or `Interrupt` capability references a fresh object over the same range, so the
mappings, port bindings, and interrupt binding made through it are withdrawn when it goes (see
[capability-model.md](../../../docs/capability-model.md) § Interrupt, § Mmio, and § IoPort
(x86-64 only)); a fresh `Interrupt` object starts unbound. The
effective rights are `rights_mask & source_rights` — bits requested beyond what the source holds
are silently masked off rather than rejected, so derivation can only attenuate. The derivation is
recorded in the global derivation tree for revocation tracking.

The source is revalidated under the derivation lock before the new slot is
linked beneath it (see [capability-internals.md](capability-internals.md)
§ Global Derivation Lock): a source a concurrent delete, move, or revoke freed
meanwhile fails with `InvalidCapability`, and one with a `SYS_CAP_REVOKE`,
`SYS_CAP_MOVE`, or IPC capability transfer in flight with `InvalidState`, rather than
leaving the new capability an unlinked derivation root.

**Errors:** `InvalidCapability` (source invalid, null, or freed meanwhile),
`InvalidState` (a `SYS_CAP_REVOKE`, a `SYS_CAP_MOVE`, or an IPC capability transfer is in flight
on the source), `OutOfMemory` (slot-page pool exhausted, or, for an `Mmio`, `IoPort`, or
`Interrupt` source, the caller's `CSpace` pool cannot back the fresh object; see
[capability-internals.md](capability-internals.md) § Body Arena), `QuotaExceeded` (caller's CSpace
directory structurally full; for an `Mmio`, `IoPort`, or `Interrupt` source, its range already has
`RANGE_COPY_LIMIT` (2^31 - 1) live copies; for any other source, the object's reference count is
at its 2^31 ceiling).

If the source capability has a non-zero badge, the derived capability inherits it.

---

### `SYS_CAP_DERIVE_BADGE` (48)

Derive a new capability with an attached badge value.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `source_cap` | Source capability descriptor |
| 1 | `rights_mask` | Rights bitmask for the derived capability (ANDed with the source's rights, as for `SYS_CAP_DERIVE`) |
| 2 | `badge` | Badge value to attach (must be non-zero) |

**Return:** `rax`/`a0`: new capability descriptor on success; `SyscallError` on failure.

The badge is an immutable `u64` value stored in the capability slot. When the
badged capability is used for IPC (via `SYS_IPC_CALL`), the kernel delivers
the badge to the receiver as the third return value of `SYS_IPC_RECV`.

Badges are generic — any capability type can carry a badge, not just endpoints.
For non-endpoint types, the badge is stored but not delivered via any kernel
mechanism; userspace can use it for bookkeeping (see
[capability-model.md](../../../docs/capability-model.md) § Badges).

The source capability must have `badge == 0`. Re-badging (setting a new badge
on an already-badged cap) returns `InvalidArgument`. Derivation via
`SYS_CAP_DERIVE` inherits the source's badge (see
[capability-model.md](../../../docs/capability-model.md) § Badges). Source revalidation
under the derivation lock, and the fresh object of an `Mmio`, `IoPort`, or `Interrupt`
derivation: as for `SYS_CAP_DERIVE`.

**Errors:** `InvalidArgument` (badge is zero or source already badged),
`InvalidCapability` (source invalid, null, or freed meanwhile), `InvalidState` (a
`SYS_CAP_REVOKE`, a `SYS_CAP_MOVE`, or an IPC capability transfer is in flight on the source),
`OutOfMemory` and `QuotaExceeded` (as for `SYS_CAP_DERIVE`).

---

### `SYS_CAP_REVOKE` (15)

Revoke all capabilities derived from a capability, across all processes.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `cap` | Capability whose descendants to revoke |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

Every descendant in the derivation tree is invalidated; the target capability itself
is preserved. Mappings established through a revoked Mmio descendant are unmapped,
with TLB shootdown, and IoPort bindings made through a revoked IoPort descendant
withdrawn, before the call returns; while a concurrent syscall holds the descendant's
object (any syscall naming it, which pins it), all of that object's mappings and
bindings are withdrawn when that syscall releases it instead; mappings established
through a revoked Memory descendant are not withdrawn; a server verifies their withdrawal
with `SYS_CAP_INFO`'s `CAP_INFO_MEMORY_MAPPINGS` (see
[capability-model.md](../../../docs/capability-model.md) § Memory).
Underlying kernel objects are not freed unless a revoked capability was the last
reference (see [capability-model.md](../../../docs/capability-model.md) § Revocation);
such a teardown can fail to complete as `SYS_CAP_DELETE` describes for a thread left
on a halted CPU. While the revoke is in flight, `SYS_CAP_DELETE`, `SYS_CAP_MOVE`,
`SYS_CAP_COPY`, `SYS_CAP_DERIVE`, `SYS_CAP_DERIVE_BADGE`, `SYS_MEMORY_SPLIT`,
`SYS_MEMORY_MERGE`, and the range splits on the target slot (and IPC transfer of it)
are refused with `InvalidState`. A `SYS_CAP_MOVE` or IPC transfer in flight pins its
source and destination slots the same way (see
[capability-internals.md](capability-internals.md) § Revocation Algorithm).

**Errors:** `InvalidCapability`; `InvalidState` (another revoke, a move, or an IPC
capability transfer is already in flight on this slot, or a corrupted derivation link
was found — the revoke is incomplete and the dangling chain was cut); `Interrupted`
(liveness backstop, after `MAX_REVOKE_BATCHES` batches: the subtree was larger than they cover, or
concurrent derivation kept extending it — everything revoked so far stays revoked; retry to
continue).

---

### `SYS_CAP_DELETE` (31)

Delete a single capability from the caller's CSpace. Does not affect derived capabilities.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `cap` | Capability descriptor to delete |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

If this is the last reference to the underlying object, the object is freed. Every `Mmio` and
`IoPort` capability references an object of its own, so deleting one frees it, which unmaps the
mappings and withdraws the port bindings made through it (see § `SYS_MMIO_MAP` and §
`SYS_IOPORT_BIND`). Freeing a `CSpace` or an `AddressSpace` first stops every thread bound to it
(each becomes `Exited` with retained exit reason `EXIT_KILLED`; its Thread object is freed when its
own last capability goes), so a process's threads never outlive either object (see
[scheduling-internals.md](scheduling-internals.md) § Thread Registry). **The stop includes the
caller**: a thread deleting the last capability to its own `CSpace` or `AddressSpace` — directly, or
because the deleted object's teardown cascades into it — is stopped by that delete and the call does
not return; the object is reclaimed once the thread is off its CPU. When another thread's syscall
holds a pin on the object at the delete (see below), the delete is not the last release: it returns
0, and the stop and the free happen when that syscall drops its pin, through the deferred reclaim of
the dropping thread's CPU. An `AddressSpace` an Mmio capability's object has recorded a mapping into
(§ `SYS_MMIO_MAP`) is likewise not released by the delete of its last capability: the delete returns
0, and the stop and the free happen when that Mmio object is freed and its record releases the
space. A teardown of a Thread left `current` on a CPU that `fatal` halted never completes (see
[thread-lifecycle-and-sleep.md](thread-lifecycle-and-sleep.md#dealloc_objectthread-drain-protocol) §
`dealloc_object(Thread)` Drain Protocol, invariant 3), nor does one of a `CSpace` or `AddressSpace`
with such a thread bound (see [scheduling-internals.md](scheduling-internals.md) § Thread Registry):
the call does not return, or, when the deleter is itself stopped and the teardown is deferred, the
deferred drain on its CPU never completes. An object another thread's syscall is still using is not
freed under it: the syscall holds a pin on it until it drops it (see
[capability-internals.md](capability-internals.md#storage-hybrid-radix-directory) § Storage: Hybrid
Radix Directory), and a stopped thread's teardown reaches the IPC source it was parked on only
through a binding that proves the source live (see
[thread-lifecycle-and-sleep.md](thread-lifecycle-and-sleep.md#dealloc_objectthread-drain-protocol) §
`dealloc_object(Thread)` Drain Protocol, step 11); a waker that claimed the thread holds the source
live until its wake completes (device IRQ delivery through the reference its binding holds on the
Notification, fault delivery through its pin on the endpoint, the death post through the observer
binding's reference; see
[capability-internals.md](capability-internals.md#kernel-object-reference-counting) § Kernel Object
Reference Counting). The caller's own `Thread` object is treated differently, as below.

Refused for two cases, both returning `InvalidState` with the capability left in
place: a thread may not delete any capability to its **own running**
`Thread` object, last reference or not (always an aliased/stale-cap bug — deleting
the last one would tear the calling thread down mid-syscall; the object is reclaimed
normally when a different thread later releases it), and a slot with a
`SYS_CAP_REVOKE`, `SYS_CAP_MOVE`, or IPC capability transfer
in flight may not be deleted until that operation completes.

Capabilities derived from the deleted slot are re-linked under its own derivation parent, so
they stay revocable from above (see
[capability-internals.md](capability-internals.md) § Revocation Algorithm). That re-linking runs
in batches with the derivation lock released between them (a slot can have arbitrarily many
children); between batches the slot stays live with its remaining children still under it. A
`SYS_CAP_REVOKE` that starts on the slot between batches stops the delete with `InvalidState`
(children already moved stay under the parent — still inside every ancestor's subtree); a
concurrent delete or move of the same slot that frees it first makes this call return 0 (the
generation no longer matches; nothing is released). A concurrent deriver extending the child
list faster than one batch per hold returns `Interrupted`; a retry continues from the remaining
children.

**Errors:** `InvalidCapability`; `InvalidState` (per above); `Interrupted`
(concurrent re-derivation backstop).

---

### `SYS_CAP_INFO` (36)

Read a single scalar field of a capability (or a system-wide diagnostic counter),
selected by a field code. Read-only inquiry.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `cap` | Capability handle to inspect |
| 1 | `field` | Field selector (`CAP_INFO_*` constant) |
| 2 | `first_page` / `credential` | `CAP_INFO_MEMORY_MAPPINGS`: first page of the window, from the region's base. `CAP_INFO_MEMORY_PHYS_BASE`: a Memory cap of the caller's carrying the `Phys` right, presented for a `cap` that lacks it, or `0` for none |
| 3 | `pages` | `CAP_INFO_MEMORY_MAPPINGS` only: window length in pages (1–`CAP_INFO_MEMORY_MAPPINGS_MAX_PAGES`) |

**Return:** `rax`/`a0`: the requested field value on success; `SyscallError` on failure.
Some fields pack two values into the word — e.g. `TAG_RIGHTS` returns `(tag << 32) |
rights`, and `THREAD_STATE` returns `(state << 32) | (exit_reason & 0xFFFFFFFF)`.

`CAP_INFO_MEMORY_MAPPINGS` (12) returns, for a Memory cap, the number of user page-table
leaves in every address space that name a frame of the queried window of its region, summed over
the window's frames (the frame map table's counts; see
[memory-internals.md § Frame Map Table](memory-internals.md#frame-map-table)). A frame's
count falls only once every CPU has dropped the leaf, so a value equal to the mappings the
caller itself holds means no other address space can reach the region; the value is a
snapshot, which stays current only while no one else holds a capability that can map the
region. The kernel answers only through a Memory cap the caller holds, and counts only the
window arguments 2 and 3 name, at most `CAP_INFO_MEMORY_MAPPINGS_MAX_PAGES` (512) pages, so the
walk stays bounded; a larger region is read window by window.

`CAP_INFO_MEMORY_PHYS_BASE` (8) returns, for a Memory cap, the physical address of its region's
first byte, and answers only a holder of the Memory `Phys` right
([capability-model.md](../../../docs/capability-model.md#memory) § Memory): the queried cap carries
it, or argument 2 names a Memory cap in the caller's `CSpace` that does, the credential, pinned for
the check alone. A holder of any `Phys` cap therefore reads the base of every Memory cap it holds,
those other processes send it included; memmgr grants `Phys` only to devmgr and the IOMMU drivers,
which need the physical addresses of the frames they map for devices
([cross-boundary-disclosure.md](cross-boundary-disclosure.md) § Physical-address surfaces).
A queried cap without the right and no credential (`0`), or a credential without it, is refused
`InsufficientRights`; a credential that is not a live Memory cap, `InvalidCapability`.

`CAP_INFO_SOLE_REFERENCE` (13) returns, for a capability of any type, `1` when the queried slot is
the only reference to the object it names and `0` otherwise. It reads the object's reference count,
which holds every capability slot naming the object in every `CSpace` and every kernel-internal
reference to it (a retype lease, a page-pool donation, a wait-set membership, a fault-handler or
death-observer binding, a syscall in flight; see [capability-internals.md § Kernel Object Reference
Counting](capability-internals.md#kernel-object-reference-counting)), and answers `1` when the count
is the queried slot's reference plus the inquiry's own pin. The count is read under the caller's
`CSpace` lock with the slot re-checked, so a delete or revoke of the queried slot racing the inquiry
answers `InvalidCapability`, never a false `1`. The derivations of a Memory capability name one
object, so a Memory cap is sole only when no derivation of it, no object retyped from it, and no
donation of it remains; a split child or a range-capability copy is an object of its own. Once `1`,
the answer stays `1` until the caller itself takes a further reference through the slot (a
derivation, copy, retype, donation, binding, wait-set add, or a syscall of its own in flight), since
no other process holds a capability through which to add one. A user mapping is not a reference
(`CAP_INFO_MEMORY_MAPPINGS` counts those). memmgr reads it before it returns a reclaimed frame to
its pool ([memory-pool.md § Reclamation](../../../services/memmgr/docs/memory-pool.md#reclamation)).

`CAP_INFO_ASPACE_TERMINAL_FAULT` (14) returns, for an AddressSpace cap, `0` while no thread of the
address space has taken a terminal fault, and otherwise the retained reason of the first one
(`EXIT_FAULT_BASE` plus the fault vector or cause; never `0`), which later faults do not overwrite.
It is the reason a `SYS_ASPACE_BIND_NOTIFICATION` observer of the space receives, read under the
same lock that serialises the fault's record and the bind, so a holder that missed the post reads
the outcome back here. The kernel records the reason before it commits the faulting thread's
`Exited` state, and posts it to the observers after, so a holder that has read a thread of the space
`Exited` by a terminal fault (`CAP_INFO_THREAD_STATE`) reads a non-zero reason here.

`CAP_INFO_IRQ_MSG_ADDRESS` (15) and `CAP_INFO_IRQ_MSG_DATA` (16) return, for an Interrupt cap
naming a message-signaled target (§ `SYS_IRQ_MSG_ALLOC`), the message a device writes to raise it:
the physical address and the 32-bit data word devmgr programs into the device's MSI capability or
MSI-X table entry before it delivers the driver a copy of the cap, which the driver only binds
([docs/device-management.md](../../../docs/device-management.md#message-signaled-interrupts)
§ Message-Signaled Interrupts). On x86-64 the address is the target CPU's compatibility-format local
APIC address (`0xFEE0_0000 | apic_id << 12`, physical destination, no redirection hint) and the data
its vector (fixed delivery, edge-triggered); on RISC-V the address is the target hart's
supervisor-level IMSIC interrupt file and the data the interrupt identity, written to the file's
`seteipnum_le` register. The address is an interrupt controller's, never RAM
([cross-boundary-disclosure.md](cross-boundary-disclosure.md)), so holding the cap answers it. An
Interrupt cap naming a wired line, or a range, answers `InvalidArgument`.

**Capability requirement:** None for every selector but `CAP_INFO_MEMORY_PHYS_BASE`, which
needs the Memory `Phys` right on the queried cap or the credential; `cap_info` otherwise reads
the slot without a rights check.

**Errors:** `InvalidCapability` (null/stale handle, empty slot, a referenced target
object is gone, or a `CAP_INFO_MEMORY_PHYS_BASE` credential that is not a live Memory cap),
`InsufficientRights` (`CAP_INFO_MEMORY_PHYS_BASE` with neither the queried cap nor the
credential carrying `Phys`), `InvalidArgument` (field requires a different capability type, the
selector is unknown, a `CAP_INFO_MEMORY_MAPPINGS` window is empty, longer than
`CAP_INFO_MEMORY_MAPPINGS_MAX_PAGES` pages, or runs past the region, or a
`CAP_INFO_IRQ_MSG_ADDRESS` or `CAP_INFO_IRQ_MSG_DATA` cap names no message-signaled target).

---

## Memory Syscalls

### `SYS_MEM_MAP` (16)

Map pages from a physical memory capability into an address space.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `memory_cap` | Memory capability (Map rights) |
| 1 | `aspace_cap` | Address space capability (Map rights) |
| 2 | `virt` | Virtual address to map at (page-aligned, user range) |
| 3 | `offset_pages` | Page offset into the frame |
| 4 | `page_count` | Number of pages to map (nonzero) |
| 5 | `prot_bits` | Protection bits: bit 0 = READ, bit 1 = WRITE, bit 2 = EXECUTE. If zero, derived from memory cap rights |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

If `prot_bits` is nonzero, the requested permissions must be a subset of the memory
cap's rights. W^X is enforced: WRITE and EXECUTE may not both be set. Bit 0 (READ)
carries no permission of its own; it makes an otherwise-empty read-only request
nonzero so the explicit path is taken instead of deriving from the cap's rights.

If `prot_bits` is zero, permissions are derived from the memory cap's rights directly.
This fails with `WxViolation` if the memory cap has both WRITE and EXECUTE rights.

Each page records the memory cap's WRITE and EXECUTE rights, whatever `prot_bits` asks for: the
most a later `SYS_MEM_PROTECT` may make of the page, and what a `THREAD_MEM_TEXT` write of
`SYS_THREAD_WRITE_MEM` needs of it when it is read-only (see
[memory-internals.md § Leaf Grant](memory-internals.md#leaf-grant)). A page mapped through a
Map-only cap stays read-only and never executable.

An executable mapping synchronises instruction fetch on every CPU before its first leaf is
installed, so bytes written to its frames before the call run as written (see
[docs/memory-model.md § Instruction-Fetch Coherence](../../../docs/memory-model.md#instruction-fetch-coherence)).

The mapping may not reach bytes the memory cap has retyped into kernel objects: the range must
start at or above the cap's retype bump cursor rounded up to a page, the bound `SYS_MEMORY_SPLIT`
applies to its split offset (see
[docs/capability-model.md § Typed Memory](../../../docs/capability-model.md#typed-memory)). While
the mapping lives, no retype carves its pages (see [Capability Syscalls](#capability-syscalls)).
A call that races a retype advancing the cursor over the requested range may fail with
`InvalidArgument` even when that retype is itself refused. Once the range's frames are counted,
the call resolves `memory_cap` a second time, and it fails with `InvalidCapability` if the
capability was revoked or deleted in between. A revoke therefore either stops the map or is
followed by a mappings count that includes it (see
[memory-internals.md § Frame Map Table](memory-internals.md#frame-map-table)).

**Capability requirements:** `memory_cap` (Map), `aspace_cap` (Map).

**Errors:** `InvalidAddress` (unaligned `virt`, non-canonical address, or mapping
range leaves the user half), `InvalidArgument` (zero page count, size/offset overflow,
`offset_pages` + `page_count` past the end of the memory cap's region, or `offset_pages`
below the page-rounded retype bump cursor),
`InvalidCapability` (also: `memory_cap` revoked or deleted while the call runs),
`InsufficientRights` (requested prot exceeds cap rights), `WxViolation` (both WRITE and
EXECUTE requested), `OutOfMemory`
(page table allocation failure, or a frame already named by `u32::MAX` user mappings).

---

### `SYS_MEM_UNMAP` (17)

Remove a mapping from an address space.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `aspace_cap` | Address space capability (Map rights) |
| 1 | `virt` | Virtual address to unmap (page-aligned, user range) |
| 2 | `page_count` | Number of pages to unmap (nonzero) |
| 3 | `flags` | Bit `MEM_UNMAP_RECLAIM_PTS`: tear down the whole span and reclaim now-empty intermediate page tables with a single coarse shootdown, plus one span invalidation each time the cleared frames overflow the frame-map release batch |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The physical frame is not freed — only the virtual mapping is removed. The memory
capability continues to exist. TLB shootdowns are performed on all CPUs running
threads in `aspace_cap` (see [memory-internals.md](memory-internals.md) § SMP TLB Shootdown).

**Capability requirement:** `aspace_cap` must have Map rights.

**Errors:** `InvalidAddress` (unaligned `virt`, or range leaves the user half),
`InvalidArgument` (zero page count or size/range overflow), `InvalidCapability`,
`InsufficientRights` (cap lacks Map).

---

### `SYS_MEM_PROTECT` (18)

Change the permission flags on an existing range of mappings without altering the
physical addresses.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `memory_cap` | Memory capability (Map rights) authorising the requested permission level |
| 1 | `aspace_cap` | Address space capability (Map rights) |
| 2 | `virt` | Virtual address of the mapping (page-aligned, user range) |
| 3 | `page_count` | Number of pages to reprotect (nonzero) |
| 4 | `prot_bits` | New protection bits: bit 1 = WRITE, bit 2 = EXECUTE |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

W^X is enforced on the new flags. The requested permissions must be a subset of the
`memory_cap`'s rights, which are re-checked here. `memory_cap` authorises the call; it need not
cover the frames under the range. Each page is bounded besides by the rights of the capability
that mapped it, which `SYS_MEM_MAP` and `SYS_MMIO_MAP` record in the page (see
[memory-internals.md § Leaf Grant](memory-internals.md#leaf-grant)): a page becomes writable only
if that capability carried WRITE, and executable only if it carried EXECUTE, so a `SYS_MMIO_MAP`
page never becomes executable, and one mapped through a Map-only cap stays read-only. Pages are
changed in order, and a page that refuses ends the call with the pages before it already
changed. Only the permissions change: each page keeps its memory type, so an uncacheable
`SYS_MMIO_MAP` page stays uncacheable.

A protect to executable synchronises instruction fetch on every CPU before the first leaf turns
executable, also when the pages are executable already: a process that wrote code through a
writable alias of an executable frame makes the code visible this way (see
[docs/memory-model.md § Instruction-Fetch Coherence](../../../docs/memory-model.md#instruction-fetch-coherence)).

**Capability requirements:** `memory_cap` (Map), `aspace_cap` (Map).

**Errors:** `InvalidAddress` (unaligned `virt`, range leaves the user half, or a page
in the range is not mapped), `InvalidArgument` (zero page count, size/range overflow,
or no free frame during the page-table walk), `WxViolation` (both WRITE and EXECUTE
requested), `InvalidCapability`, `InsufficientRights` (requested perms exceed
`memory_cap` rights, or a page's mapping capability lacks WRITE or EXECUTE the request asks for).

---

### `SYS_MEMORY_SPLIT` (33)

Carve a virgin tail off a Memory capability at a page boundary. The parent
capability stays in its slot and shrinks; a new capability covering the tail is
inserted in the caller's CSpace.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `memory_cap` | Memory capability to split (Map rights) |
| 1 | `split_offset` | Byte offset of the split: page-aligned, `> 0`, `< size`, and at or above the cap's retype bump offset rounded up to a page boundary |
| 2 | — | Reserved |

**Return:** `rax`/`a0`: capability descriptor for the tail
(`[base + split_offset, base + size)`) on success; `SyscallError` on failure.

The parent's `size` shrinks to `split_offset`; when it carries `RETYPE`, its
`available_bytes` debits by the carved length. The tail inherits the parent's
rights and ownership flag and is linked as a derivation sibling of the parent
(a child of the parent's derivation parent; a root when the parent is one).
Live retypes against the parent always sit below its bump offset, so the tail
is virgin.

A Memory object is split only through the one capability slot that names it. A derivation or
copy of a Memory cap names the source's object, so shrinking that object in place would shrink
what every other slot naming it reaches; the call refuses `memory_cap` while any other slot, in
any `CSpace`, names its object: a derivation parent, a sibling, a child, or a slot that still
shares the object once the derivation edge between them is gone (deleting a parentless root
leaves its children as unlinked roots). The kernel counts the slots that name each Memory object
(`MemoryObject::slot_count`, exact under the derivation lock the call holds). Retype leases,
donations, and other syscalls' pins are not slots and do not refuse the split.

The parent is revalidated under the derivation lock before its object is
touched and the tail is linked beside it (see
[capability-internals.md](capability-internals.md) § Global Derivation Lock): a
parent a concurrent delete freed meanwhile fails with `InvalidCapability`, and
one with a `SYS_CAP_REVOKE`, `SYS_CAP_MOVE`, or IPC capability transfer in flight
with `InvalidState`.

**Capability requirement:** `memory_cap` must have Map rights.

**Errors:** `InvalidArgument` (`split_offset` not page-aligned, zero, `>= size`,
leaving fewer than one page on the upper side, below the bump boundary, or another
slot names the parent's object), `InvalidCapability`, `InvalidState` (per
above), `InsufficientRights` (cap lacks Map), `OutOfMemory` (the caller's
`CSpace` pool cannot back the tail's body or its slot; see
[capability-internals.md](capability-internals.md) § Body Arena), `QuotaExceeded` (caller's CSpace
directory structurally full).

---

### `SYS_MMIO_MAP` (34)

Map an MMIO region capability into an address space. MMIO mappings use uncacheable
page attributes (PCD|PWT strong-uncacheable on x86-64; Svpbmt PBMT=IO on RISC-V)
rather than the default writeback caching (see
[arch-interface.md](arch-interface.md) § `paging`).

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `aspace_cap` | Address space capability (Map rights) |
| 1 | `mmio_cap` | MMIO region capability (Map rights) |
| 2 | `virt` | Virtual address to map at (page-aligned) |
| 3 | `flags` | Reserved (cache-mode overrides, etc.); ignored today |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

MMIO mappings are never executable, and mapping writability is derived from the
`mmio_cap`'s Write right, not from `flags`. The kernel forces the uncacheable
attribute unconditionally. Each page records the same rights as its most, so no
`SYS_MEM_PROTECT` makes it executable, or writable when `mmio_cap` lacks Write (see
[memory-internals.md § Leaf Grant](memory-internals.md#leaf-grant)).

The `mmio_cap`'s object records the mapping, holding a reference on the address space, before any
page is mapped. When the object is freed, because `mmio_cap` (or the copy it is) was deleted,
consumed by a split, or revoked through an ancestor, every recorded mapping is unmapped with TLB
shootdown, except a page the address space has since remapped to other memory (see
[capability-model.md](../../../docs/capability-model.md) § Mmio). One object records
`MMIO_INLINE_MAPPINGS` (4) mappings inline and each further one in a spill chunk funded by the
caller's `CSpace` (see [capability-internals.md](capability-internals.md) § Mmio Mappings); mapping
it again at the same `virt` of the same address space reuses its record. A call that fails with
`OutOfMemory` after the record is taken keeps the record and the pages it mapped (both go when the
object is freed); a retry at the same `virt` reuses the record.

**Capability requirements:** `aspace_cap` (Map), `mmio_cap` (Map).

**Errors:** `InvalidAddress` (unaligned or non-canonical `virt`, or range leaves the
user half), `InvalidCapability`, `InsufficientRights` (a cap lacks Map), `InvalidArgument`
(MMIO region size zero or not page-aligned, or size overflow), `OutOfMemory` (page table
allocation failure, or the caller's `CSpace` pool cannot fund a spill chunk for a mapping past the
inline records).

---

### `SYS_MMIO_SPLIT` (45)

Split an MMIO region capability into two non-overlapping child capabilities at a
page-aligned byte offset. The original capability is consumed, which frees its object and
unmaps every mapping made through it as § `SYS_MMIO_MAP` describes.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `mmio_cap` | MMIO region capability to split (Map rights) |
| 1 | `split_offset` | Page-aligned byte offset to split at; `0 < split_offset < size`, with at least one page on each side |

**Return:**

- `rax`/`a0`: capability descriptor for the lower region `[base, base+split_offset)` on
  success; `SyscallError` on failure
- `rdx`/`a1`: capability descriptor for the upper region `[base+split_offset, end)` on
  success

Both children inherit the original's rights and flags and are reparented to the
original's derivation parent. The original `mmio_cap` is consumed: its object is freed, so every
`SYS_MMIO_MAP` mapping made through it is unmapped, with TLB shootdown, before the call returns
(unless a concurrent syscall pins the object, then when that syscall releases it). A caller that
needs the region mapped maps it again through a child.

**Capability requirement:** `mmio_cap` must have Map rights.

The original is revalidated under the derivation lock before it is consumed
(see [capability-internals.md](capability-internals.md) § Revocation Algorithm):
if a concurrent delete removed it, or a `SYS_CAP_REVOKE`, a `SYS_CAP_MOVE`, or an IPC capability
transfer is in flight on it, the split fails with `InvalidState` and both children are rolled
back. Its children are re-linked under its derivation parent in batches (lock released between
them); a concurrent deriver extending that list faster than it is moved returns
`Interrupted`. Both children are inserted and linked under the original's
derivation parent in the first derivation-lock hold, so a concurrent move
cannot carry one out of the grantor's revoke reach before it is linked; a
child a concurrent delete removed before the split finished stays deleted,
and its returned handle carries the generation minted at insert, so it no
longer resolves even if the slot has since been refilled. A split that fails
after at least one batch leaves the children already moved under the
original's derivation parent, where they stay: the surviving original no
longer holds revoke authority over them, as after a `SYS_CAP_DELETE` of an
intermediate.
The three other range splits (`SYS_IRQ_SPLIT`, `SYS_IOPORT_SPLIT`,
`SYS_SCHED_SPLIT`) share this tail and these two errors.

**Errors:** `InvalidState`, `Interrupted` (per above), `InvalidArgument` (`split_offset` not
page-aligned, zero, `>= size`, or fewer than one page on the upper side), `InvalidCapability`,
`InsufficientRights` (cap lacks Map), `OutOfMemory` (the caller's `CSpace` pool cannot back the
children's bodies or slots), `QuotaExceeded` (caller's CSpace directory structurally full).

---

### `SYS_MEMORY_MERGE` (50)

Absorb a virgin, physically-adjacent tail Memory capability back into its parent — the
inverse of `SYS_MEMORY_SPLIT`. The parent's size grows to cover both ranges; the tail
capability is consumed and its slot freed.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `parent_cap` | Parent (physically-lower) Memory capability (Map rights); remains valid with grown size |
| 1 | `tail_cap` | Tail (physically-upper) Memory capability (Map rights); consumed |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The two capabilities must be derivation siblings with identical rights, be physically
contiguous (`parent.base + parent.size == tail.base`), and the tail must be virgin
(no live retypes: its retype bump cursor is at its base and its `available_bytes` equals
its size when it carries `RETYPE`, zero otherwise; a tail whose retyped objects have all
been freed qualifies). Both must carry the same memory-ownership flag, and each object must be
named by its own slot alone, under the rule of § `SYS_MEMORY_SPLIT`: growing the parent would
grow what another slot naming it reaches, and consuming the tail would leave another slot
naming it over a range the parent then owns.

**Capability requirements:** `parent_cap` (Map), `tail_cap` (Map); rights must match.

Both capabilities are revalidated under the derivation lock before either
object is touched and the tail is unlinked and freed (see
[capability-internals.md](capability-internals.md) § Global Derivation Lock): a
cap a concurrent delete freed meanwhile fails with `InvalidCapability`, and one
with a `SYS_CAP_REVOKE`, `SYS_CAP_MOVE`, or IPC capability transfer in flight with
`InvalidState`.

**Errors:** `InvalidArgument` (same slot/object, rights mismatch, ownership-flag
mismatch, not contiguous, tail not virgin, not siblings, or another slot names either
object),
`InvalidCapability`,
`InvalidState` (per above), `InsufficientRights` (either cap lacks Map).

---

## Thread and Process Syscalls

### `SYS_THREAD_START` (19)

Transition a thread from `Created` or `Stopped` state to `Ready` and enqueue it for scheduling,
or, with `THREAD_START_SUSPENDED`, a configured `Created` thread to `Stopped`.
Starting a thread whose fault episode a stop cancelled (before any reply claimed it), or whose
handler's claiming reply was `FAULT_REPLY_KILL` (or a `FAULT_REPLY_FORWARD` of a delivery other
than a virtual-memory one, of one with no exception handler bound, or of the fault of a
restartable syscall's user copy), kills it as an unhandled
fault, which posts its death and address-space observers, or, for the fault of a restartable
syscall's user copy, fails that syscall with `InvalidAddress` (see
[docs/fault-handling.md](../../../docs/fault-handling.md#delivery-resume-and-kill) § Delivery,
Resume, and Kill). An upcall delivery (`FAULT_KIND_UPCALL`) is no fault: one a stop cancelled,
or that the claiming reply declined (`FAULT_REPLY_KILL`, or `FAULT_REPLY_FORWARD`, which is a
decline for an upcall), drops the upcall, and the start resumes the thread at its registers
([docs/fault-handling.md](../../../docs/fault-handling.md#asynchronous-upcalls) § Asynchronous
Upcalls).
A stopped thread whose blocked syscall a waker claimed before the stop is restarted only once that
waker's wake has landed, so the resumed syscall returns the delivered result (see
[thread-lifecycle-and-sleep.md](thread-lifecycle-and-sleep.md) § `sys_thread_stop` Cross-CPU Stop
Protocol, invariant 4).

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Control rights) |
| 1 | `flags` | `THREAD_START_SUSPENDED`, or `0`; every other bit is reserved and MUST be clear |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

**Suspended start.** With `THREAD_START_SUSPENDED`, a configured `Created` thread becomes `Stopped`
instead of `Ready`: it is linked on no run queue and executes no user instruction. Its register
file is the one `SYS_THREAD_CONFIGURE` built (the entry as its instruction pointer), which
`SYS_THREAD_READ_REGS` and `SYS_THREAD_WRITE_REGS` read and write as for any `Stopped` thread, and
a later `SYS_THREAD_START` without the flag resumes it; `SYS_THREAD_STOP` of it returns
`InvalidState`, as for any `Stopped` thread. The flag is valid only for a `Created` target: the
state and the configured frame are decided under the target's `sched_lock`, which
`SYS_THREAD_CONFIGURE` and every start and teardown commit also take, so a start or teardown that
lands first leaves the target other than `Created` and the suspended start is refused (see
[thread-lifecycle-and-sleep.md](thread-lifecycle-and-sleep.md) § Lifecycle State Machine).

**Capability requirement:** `thread_cap` must have Control rights.

**Errors:** `InvalidArgument` (`flags` sets a reserved bit; checked before the capability),
`InvalidCapability`, `InsufficientRights` (cap lacks Control),
`InvalidArgument` (the target is the caller, is not yet configured, or is not in Created/Stopped
state under the locked commit — including one a concurrent start already resumed, or one that
exited or was killed by an object teardown after the first check — or, for a suspended start, is
not `Created` when it commits), `Interrupted` (the caller was itself stopped while the start waited
for the target to leave its CPU or for an owed wake; never for a suspended start, which waits for
nothing). Each
stop admits at most one start commit: absent an intervening stop, exactly one of several
concurrent starts of one stopped thread succeeds. A start that a concurrent `SYS_THREAD_STOP`
overtakes after its commit succeeds and leaves the thread `Stopped`, and a later start can then
commit again.

---

### `SYS_THREAD_STOP` (20)

Stop a running or runnable thread. The thread transitions to `Stopped` state. A stop that
lands while the target is inside its own exit (`SYS_THREAD_EXIT`, `SYS_PROCESS_EXIT`, or a
terminal fault) still returns 0, but the exit then commits `Exited` over the `Stopped` mark, so
the target never runs again and a later `SYS_THREAD_START` returns `InvalidArgument`.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Control rights) |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

A fault-blocked target's fault episode, unless the handler's reply claimed it first, is cancelled
with a kill outcome (no syscall returns) and the thread is left `Stopped`; the next
`SYS_THREAD_START` then kills it as an unhandled fault (for the fault of a restartable syscall's
user copy, fails that syscall with `InvalidAddress`). A thread whose handler's reply claimed the
fault first keeps that reply's outcome: when next started it resumes its faulting instruction on
`FAULT_REPLY_RESUME`, takes the unhandled outcome on `FAULT_REPLY_KILL`, and on
`FAULT_REPLY_FORWARD` delivers the fault through its exception class when the reply answered the
virtual-memory class's delivery of a fault other than a kernel copy's and an exception handler is
bound, and otherwise takes the unhandled outcome (see
[docs/fault-handling.md](../../../docs/fault-handling.md#delivery-resume-and-kill) § Delivery,
Resume, and Kill). A target blocked in an upcall delivery (`FAULT_KIND_UPCALL`) is killed in
neither case: a stop that cancels the delivery drops the upcall, any reply that claimed it first
settles it, and the thread resumes at its registers when next started (for a delivery at the
syscall point, its syscall returns its own result;
[docs/fault-handling.md](../../../docs/fault-handling.md#asynchronous-upcalls) § Asynchronous
Upcalls). If the thread is blocked (on IPC or in `SYS_THREAD_SLEEP`), the block is
cancelled (the blocked syscall on the target thread returns `Interrupted`, unless a genuine waker
or the elapsed deadline of a sleep or a timed wait claimed it first).
A target that blocks while the stop is in progress is cancelled the same way, never left registered
as a waiter (see [thread-lifecycle-and-sleep.md](thread-lifecycle-and-sleep.md) § `sys_thread_stop`
Cross-CPU Stop Protocol). A target waiting on an endpoint (queued to send or receive), a
notification, an event queue, or a wait set whose last capability is deleted concurrently is
claimed either by the stop or by the object's teardown, and both stamp the same cancellation: on
restart its syscall returns `Interrupted`, or a queued fault sender is killed (a restartable
syscall's copy fault fails that syscall with `InvalidAddress`, and a queued upcall delivery has its
upcall dropped and resumes;
[docs/fault-handling.md](../../../docs/fault-handling.md#asynchronous-upcalls) § Asynchronous
Upcalls). A thread running on
another CPU is marked `Stopped` under every CPU's scheduler lock, and the call returns once that
CPU has descheduled it and published its register save, at its next slice expiry, at a tick
that preempts it for an RT thread (a target dispatched at a fair level), or at the thread's own
park or yield, or once an object teardown has committed `Exited` over it; the
inter-processor interrupt sent to that CPU only forces a trap. A thread left `current` on a CPU that
`fatal` halted is never descheduled: a stop of it does not return through the drain until a
teardown commits `Exited` over it, and that teardown never completes (see
[thread-lifecycle-and-sleep.md](thread-lifecycle-and-sleep.md#dealloc_objectthread-drain-protocol)
§ `dealloc_object(Thread)` Drain Protocol, invariant 3). A caller that is itself stopped while
it waits deschedules in place; once restarted it re-resolves `thread_cap`, and its call completes
when the target has left its CPU and published its register save, or at once when that slot no
longer names the target with Control rights — the target may then still be executing, and
`SYS_THREAD_READ_REGS` and `SYS_THREAD_WRITE_REGS` refuse it with `InvalidState` until it has left
its CPU with its save published (see [thread-lifecycle-and-sleep.md](thread-lifecycle-and-sleep.md)
§ `sys_thread_stop` Cross-CPU Stop Protocol).

**Latency contract:** a stop of a thread running on another CPU completes at the target's next
slice-expiry `schedule()`, a tick that preempts it for an RT thread queued on its CPU (a target
dispatched at a fair level), or its own park or yield, not within the inter-processor-interrupt
latency: no interrupt-return path deschedules a `Stopped` current thread. That is within the
target's remaining time slice (at most the longest slice, 20 timer ticks, that of fair level 20;
`TIME_SLICE_TICKS`, 10, for a target dispatched at an RT level; see
[scheduler.md § Time Slice Policy](scheduler.md#time-slice-policy)), except when the
slice expires while the target runs a preemption-disabled kernel section with interrupts
enabled (a TLB-shootdown or drain spin, or a page-pool seeding or teardown window between
batches, `interrupt_window`): `timer_tick` then refills the slice without rescheduling,
and `preempt_enable` does not reschedule, so the stop completes at the first later tick that
decides a reschedule with preemption enabled: a slice expiry, a further slice later at the least,
or, for a target dispatched at a fair level, a tick that finds an RT thread queued, which can be
the next tick. Callers that need a bounded stop latency MUST budget a slice for each slice expiry
the target can spend in such a section; a tick that decides a preemption for RT and finds
preemption disabled leaves the slice running and adds nothing to that budget.

**Capability requirement:** `thread_cap` must have Control rights.

**Errors:** `InvalidCapability`, `InsufficientRights` (cap lacks Control),
`InvalidState` (thread not yet started, already stopped, or exited when the call reads it,
including one killed by an object teardown concurrently with the call; two concurrent stops of one
running thread can both succeed).

---

### `SYS_THREAD_YIELD` (21)

Voluntarily yield the remainder of the current thread's time slice.

**Arguments:** None.

**Return:** `rax`/`a0`: always 0.

The calling thread moves from `Running` to `Ready` and is re-enqueued at its current
priority. No
capability is required — this syscall acts on the calling thread implicitly.

**Errors:** None (this syscall cannot fail).

---

### `SYS_THREAD_EXIT` (22)

Exit the calling thread. The thread is marked `Exited` and another thread is
scheduled; it is never re-enqueued. This is the correct way for an individual
thread (e.g. a `std::thread`) to terminate itself. To exit the whole process
with a code, use `SYS_PROCESS_EXIT`.

**Arguments:** None.

**Return:** Does not return.

**Errors:** None (this syscall cannot fail).

---

### `SYS_PROCESS_EXIT` (54)

Exit the calling process with a voluntary exit code (the `std::process::exit` /
`main`-return path). The kernel encodes `code` via `syscall_abi::encode_exit_code`
into the exit-reason space (`0` clean, `1..=0x0FFF` verbatim with larger codes saturating
to `0x0FFF`; disjoint from the fault range `0x1000..=0x1FFF`; see
[process-lifecycle.md](../../../docs/process-lifecycle.md) § Exit reason), records it as
the calling thread's exit reason, and posts
it to that thread's death observers — a parent that bound the main thread (so
`ExitStatus::code()` carries it) and procmgr's per-thread observer (which reaps
the process). Structurally identical to `SYS_THREAD_EXIT` but with the encoded
caller-supplied reason (zero for a `code` of `0`); it does not post to the
address-space death surface (reserved for terminal faults). Sibling threads are reaped
by procmgr's cap-revoke teardown;
the kernel does not enumerate or stop them here (see
[process-lifecycle.md](../../../docs/process-lifecycle.md) § Process Death).

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `code` | Voluntary exit code (`u32`); `0` = success |

**Return:** Does not return.

**Errors:** None (this syscall cannot fail).

---

### `SYS_THREAD_SET_PRIORITY` (37)

Change a thread's scheduling priority after creation.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Control rights): selects *which* thread |
| 1 | `priority` | New priority (1–`PRIORITY_MAX`); a register value above 255 is out of range |
| 2 | `sched_cap` | `SchedControl` capability whose `[min, max]` band covers `priority`: governs *which level*. Always required |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

Assigning a priority is capability-gated with no ambient authority. `thread_cap`
(Control) authorises mutating the target thread; `sched_cap` must be a
`SchedControl` whose band includes `priority`. A process holding no `SchedControl`
(or one whose band excludes the requested level) cannot set any priority — there
is no free "normal" range. The kernel defines no normal/elevated boundary; that
partition is userspace policy expressed through `SchedControl` band distribution
(see [scheduler.md § Priority Authority](scheduler.md#priority-authority)).

Priority 0 (idle) and priority 31 (reserved) cannot be requested. Levels 21–`PRIORITY_MAX`
are scheduled by strict priority and levels 1–20 fairly, at a weight of the level
([scheduler.md § Scheduling Classes](scheduler.md#scheduling-classes)); that split is the
kernel's scheduling discipline, not an authority boundary. The change takes effect at the next
scheduler invocation: a `Ready` thread is re-linked at the new level at once, and a running
thread's class follows the new level from its next dispatch and its slice length from the first
timer tick after it ([scheduler.md § Time Slice Policy](scheduler.md#time-slice-policy)).

**Capability requirements:** `thread_cap` (Control rights); `sched_cap` (a
`SchedControl` whose band covers `priority`).

**Errors:** `InvalidCapability` (bad `thread_cap`, or no valid `SchedControl` at
`sched_cap`), `InsufficientRights` (`thread_cap` lacks Control, or band does not cover
`priority`), `InvalidArgument` (priority 0, priority 31, or out of range).

---

### `SYS_SCHED_SPLIT` (52)

Split a `SchedControl` capability into two children covering disjoint priority
bands. Mirrors the range-split shape of `SYS_IRQ_SPLIT` / `SYS_MMIO_SPLIT` /
`SYS_IOPORT_SPLIT`.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `sched_cap` | `SchedControl` capability to split |
| 1 | `split_at` | Lowest priority level of the upper child; must satisfy `min < split_at <= max` on the cap being split (a register value above 255 is outside it) |

**Return:**

- `rax`/`a0`: lower-child capability descriptor on success; `SyscallError` on failure
- `rdx`/`a1`: upper-child capability descriptor on success

The lower child covers `[min, split_at - 1]`, the upper child `[split_at, max]`.
The original cap is consumed; both children are reparented to the original's
derivation parent and carry the same (absent) rights. This is the only way to
narrow a band — `SYS_CAP_DERIVE` attenuates rights and cannot shrink a range (see
[capability-model.md](../../../docs/capability-model.md) § SchedControl).

**Capability requirements:** `sched_cap` must be a `SchedControl` (presence-only;
no rights bit).

Original revalidation, batched re-linking, `InvalidState`, and `Interrupted`: as for
`SYS_MMIO_SPLIT`.

**Errors:** `InvalidState`, `Interrupted` (per above),
`InvalidCapability` (not a `SchedControl`), `InvalidArgument`
(`split_at` outside `(min, max]`), `OutOfMemory` (the caller's `CSpace` pool cannot back the
children's bodies or slots), `QuotaExceeded` (caller's CSpace directory structurally full).

---

### `SYS_THREAD_SET_AFFINITY` (38)

Set or change a thread's CPU affinity.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Control rights) |
| 1 | `cpu_id` | Target CPU ID, or `AFFINITY_ANY` (u32::MAX) to clear affinity; a register value above `u32::MAX` is rejected |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

Setting a hard affinity prevents future migration by the load balancer and
takes effect immediately:

- A **Ready** thread queued on a different CPU is migrated to the new
  target CPU's run queue (`sched::migrate_ready_thread`).
- A **Running** thread on a different CPU is notified via a reschedule IPI
  and routed cross-CPU on its next `schedule()` entry. The IPI does not
  itself call `schedule()`; the running thread observes the new affinity
  at its next slice-expiry, voluntary yield, or IPC block (or, for a fair
  thread, at the next tick that finds an RT thread queued on its CPU).
  Worst-case latency is one time slice of the thread (see
  [scheduler.md](scheduler.md) § Active migration on affinity change).
- A **Blocked / Stopped / Created** thread observes the new affinity on
  its next enqueue (a wake, or `SYS_THREAD_START` on start or resume).

If `cpu_id` names an offline CPU, the call fails with `InvalidArgument`.

The call writes `cpu_affinity`, reads the target's `preferred_cpu` and `state`, and performs the
migration under the target's `sched_lock`, so the decision cannot race another CPU's scheduler
path. The target Thread is pinned for the call
([capability-internals.md](capability-internals.md#storage-hybrid-radix-directory) § Storage:
Hybrid Radix Directory), so a concurrent delete of its last capability frees it only after the call
returns.

**Capability requirement:** `thread_cap` MUST have Control rights.

**Errors:** `InvalidCapability`, `InsufficientRights` (cap lacks Control),
`InvalidArgument` (CPU offline or out of range).

---

### `SYS_THREAD_READ_REGS` (39)

Read the full register state of a stopped thread into a caller-supplied buffer.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Observe rights) |
| 1 | `buf_ptr` | Pointer to buffer in caller's address space |
| 2 | `buf_size` | Size of the buffer in bytes |

**Return:** `rax`/`a0`: number of bytes written on success; `SyscallError` on failure.

The thread MUST be in `Stopped` state, or fault-blocked awaiting a fault-handler
reply (`BlockedOnFault`) — the latter lets a bound fault handler inspect the
faulting registers (see [`docs/fault-handling.md`](../../../docs/fault-handling.md)).
The buffer receives the kernel's architecture-specific `TrapFrame`
(`core/kernel/src/arch/x86_64/trap_frame.rs`, `core/kernel/src/arch/riscv64/trap_frame.rs`);
`abi/syscall` publishes its size and its instruction- and stack-pointer offsets per architecture,
on x86-64 its `rflags` offset, and on riscv64 its `x1` offset, the base of the integer registers
(`REGS_X86_64_*`, `REGS_RISCV64_*`), and the kernel asserts its `TrapFrame` against them at compile
time. If `buf_size` is smaller than the required size, the call
fails with `InvalidArgument`.

A thread stopped while it runs on another CPU is `Stopped` from the stop's commit, but it executes
until that CPU deschedules it, so the call refuses it with `InvalidState` until it is `current` on
no CPU with its last register save published; the access then runs under the target's scheduling
lock, which every dispatch, start, and stop takes. The stop call that stopped the thread returns
only once it has left its CPU with its save published (see
[`SYS_THREAD_STOP`](#sys_thread_stop-20)), except a restarted
stopper's call whose slot no longer names the target, so a caller that issues this after its own
stop returns is not refused for this reason. A fault-blocked thread is accessed once it is
`current` on no CPU with its save published; a call that finds it still switching out waits for
that switch to finish.

**Capability requirement:** `thread_cap` MUST have Observe rights.

**Errors:** `InvalidCapability`, `InsufficientRights` (cap lacks Observe), `InvalidState`
(thread neither stopped and descheduled nor fault-blocked), `InvalidArgument` (buffer too small,
null pointer, or no register frame), `InvalidAddress` (buffer outside the user half, or a fault on
it that is unhandled; restartable, § Restartable Syscalls).

---

### `SYS_THREAD_WRITE_REGS` (40)

Write register state into a stopped thread from a caller-supplied buffer.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Control rights) |
| 1 | `buf_ptr` | Pointer to register file buffer in caller's address space |
| 2 | `buf_size` | Size of the buffer in bytes |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The thread MUST be in `Stopped` state, or fault-blocked awaiting a fault-handler
reply (`BlockedOnFault`) — the latter lets a bound fault handler advance the PC
or otherwise edit the faulting thread before replying (see
[`docs/fault-handling.md`](../../../docs/fault-handling.md)). The kernel sanitizes
the frame per architecture ([arch-interface.md](arch-interface.md) § `trap_frame` —
`arch::current::trap_frame`): a non-user instruction pointer (on x86-64, also a non-user
stack pointer) is rejected with `InvalidArgument`; x86-64 forces ring-3 selectors and
clears privileged RFLAGS bits; RISC-V discards the supplied `sstatus` and resumes the thread
with the value a first entry gets (SPIE set; SPP, SIE, SUM, and MXR clear; FS and VS Off, so
the thread's saved F/V state is restored lazily on first use).

A thread stopped while it runs on another CPU is `Stopped` from the stop's commit, but it executes
until that CPU deschedules it, so the call refuses it with `InvalidState` until it is `current` on
no CPU with its last register save published; the access then runs under the target's scheduling
lock, which every dispatch, start, and stop takes. The stop call that stopped the thread returns
only once it has left its CPU with its save published (see
[`SYS_THREAD_STOP`](#sys_thread_stop-20)), except a restarted
stopper's call whose slot no longer names the target, so a caller that issues this after its own
stop returns is not refused for this reason. A fault-blocked thread is accessed once it is
`current` on no CPU with its save published; a call that finds it still switching out waits for
that switch to finish.

**Capability requirement:** `thread_cap` MUST have Control rights.

**Errors:** `InvalidCapability`, `InsufficientRights` (cap lacks Control), `InvalidState`
(thread neither stopped and descheduled nor fault-blocked), `InvalidArgument` (buffer too small,
null pointer, no register frame, or illegal register values), `InvalidAddress` (buffer outside
the user half, or a fault on it that is unhandled; restartable, § Restartable Syscalls).

---

### `SYS_THREAD_READ_MEM` (60)

Copy bytes from the address space a thread executes in into a caller-supplied buffer.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Control rights) |
| 1 | `va` | Source address in the thread's address space |
| 2 | `buf_ptr` | Destination buffer in the caller's address space |
| 3 | `len` | Byte count, `1..=MAX_THREAD_MEM_COPY` (4096) |

**Return:** `rax`/`a0`: `len` on success; `SyscallError` on failure.

The thread need not be stopped: the copy reads the thread's address space, not the thread, so a
debugger stops the thread (and the space's other threads) for a view no store of theirs changes
mid-copy ([docs/fault-handling.md § Debugging](../../../docs/fault-handling.md#debugging)). The
kernel pins the address space while the thread is not `Exited`, then, under the space's page-table
lock, checks that every page of `[va, va + len)` is mapped by a 4 KiB user leaf of normal memory and
copies the range into a buffer on its own stack, all of it or none; the lock keeps an unmap from
running between the check and the copy. It then copies the buffer to `buf_ptr`. Pages are read
through the kernel's mapping of their frames, so the thread's own read permission does not gate the
read (an execute-only page reads). A page that is not present fails the call: the kernel does not
fault a page in, and the target's pager is not asked. Device memory (an uncacheable mapping, such as
an `SYS_MMIO_MAP` one, which `SYS_MEM_PROTECT` leaves uncacheable) is refused, since its frame need
not be RAM the kernel's mapping covers, and so is a page whose frame lies at or above the top of
RAM, which that mapping does not cover. On an error the buffer's contents are unspecified.

**Capability requirement:** `thread_cap` MUST have Control rights. Read access needs `CONTROL`, not
`OBSERVE`, because the space's memory holds whatever the process keeps, which register state does
not ([docs/capability-model.md § Thread](../../../docs/capability-model.md#thread)).

**Errors:** `InvalidCapability`, `InsufficientRights` (cap lacks Control), `InvalidState` (the
thread has exited, has no address space, or its address space's teardown has begun),
`InvalidArgument` (`len` 0 or above `MAX_THREAD_MEM_COPY`), `InvalidAddress` (`[va, va + len)` or
the buffer not wholly in the user half, a null buffer, a page of the range not present, mapped by
no 4 KiB leaf, device memory, or above the top of RAM, or a fault on the buffer that is unhandled;
restartable,
§ Restartable Syscalls).

---

### `SYS_THREAD_WRITE_MEM` (61)

Copy bytes from a caller-supplied buffer into the address space a thread executes in.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Control rights) |
| 1 | `va` | Destination address in the thread's address space |
| 2 | `buf_ptr` | Source buffer in the caller's address space |
| 3 | `len` | Byte count, `1..=MAX_THREAD_MEM_COPY` (4096) |
| 4 | `flags` | `THREAD_MEM_TEXT` (bit 0), or 0; every other bit is refused |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The kernel copies the buffer onto its own stack first, then pins the address space as
`SYS_THREAD_READ_MEM` does and, under the space's page-table lock, checks every page of
`[va, va + len)` before it writes any: each MUST be mapped by a 4 KiB user leaf of normal memory
whose frame lies below the top of RAM, and either writable by the thread, or read-only with
`THREAD_MEM_TEXT` set, mapped through a capability that carried WRITE or EXECUTE, and the page's
frame mapped exactly once across every address space. The write is all or nothing. A read-only
page needs the flag so that a write to text, such as a software breakpoint, is asked for; a
mapping capability with WRITE or EXECUTE, since one with neither (a firmware table, a page lent
read-only) gave its holder no right to change or run what the page holds (see
[memory-internals.md § Leaf Grant](memory-internals.md#leaf-grant)); and its frame mapped once,
since a frame mapped elsewhere too may be another process's text or data, which the write would
change through this thread's capability. procmgr's ELF loader gives each process its own image
frames and maps text through an Execute-bearing capability
([services/procmgr/README.md](../../../services/procmgr/README.md) § Responsibilities), so the text
of a process it loads takes the write; its read-only data segments, mapped through Map-only
capabilities, do not. The frame is written through the kernel's mapping of it; the
thread's mapping is not changed, so W^X holds for every user mapping. Every write synchronises
instruction fetch on every CPU before the call returns, whatever the target's leaves grant, since a
writable page's frame may be mapped executable elsewhere ([memory-model.md § Instruction-Fetch
Coherence](../../../docs/memory-model.md#instruction-fetch-coherence)).

A thread of the space that runs during the write may run or read old or new bytes, and on x86-64 a
thread running on another CPU may run an instruction it had fetched before the write; a debugger
stops the space's threads around a text write
([docs/fault-handling.md § Debugging](../../../docs/fault-handling.md#debugging)).

**Capability requirement:** `thread_cap` MUST have Control rights.

**Errors:** `InvalidCapability`, `InsufficientRights` (cap lacks Control, or a page is read-only
and `THREAD_MEM_TEXT` is clear or its mapping capability carried neither WRITE nor EXECUTE),
`InvalidState` (the thread has exited, has no address space, or
its address space's teardown has begun, or a read-only page's frame is mapped more than once),
`InvalidArgument` (`len` 0 or above `MAX_THREAD_MEM_COPY`, or an undefined `flags` bit),
`InvalidAddress` (as for `SYS_THREAD_READ_MEM`; a fault on the buffer is restartable,
§ Restartable Syscalls).

---

### `SYS_THREAD_SET_FAULT_HANDLER` (32)

Bind (or clear) the per-thread fault-handler endpoint for the fault classes a mask selects. A
kernel-unresolvable fault on the target thread is delivered as a synchronous, kernel-originated
IPC to the receiver of its class's endpoint, suspending the thread until the handler replies; with
no handler bound for its class the fault takes its unhandled outcome: the thread is killed, or a
restartable syscall's copy fails with `InvalidAddress`
([Restartable Syscalls](#restartable-syscalls)), and an upcall is not posted or is dropped. See
[`docs/fault-handling.md`](../../../docs/fault-handling.md).

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Control rights) — the thread whose handler is set |
| 1 | `endpoint_cap` | `Endpoint` capability, or `0` to unbind |
| 2 | `reserved` | MUST be `0` |
| 3 | `fault_class_mask` | Fault classes bound or unbound: `FAULT_CLASS_ALL`, or a nonzero combination of `FAULT_CLASS_VM`, `FAULT_CLASS_EXCEPTION`, and `FAULT_CLASS_UPCALL`; the classes left out keep their bindings |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

Each selected class's binding takes its own reference on the endpoint object for the binding's
lifetime; that class's rebinding or unbinding, or thread destruction, releases it (see
[fault-handling.md](../../../docs/fault-handling.md) § Liveness). The target Thread and the endpoint
are pinned for the call
([capability-internals.md](capability-internals.md#storage-hybrid-radix-directory) § Storage: Hybrid
Radix Directory), so a concurrent delete of either one's last capability frees it only after the
binding is published. A class's endpoint and badge are published as one unit under the target
thread's `sched_lock`; fault delivery reads them once under the same lock and pins the endpoint
until the faulting thread parks, so a concurrent rebind or unbind neither pairs one binding's
endpoint with another's badge nor frees the endpoint mid-delivery, and a delivery that finds the
binding cleared leaves the fault unhandled (the thread is killed, or a restartable syscall's copy
fault fails the syscall with `InvalidAddress`, § Restartable Syscalls, or, for the upcall class,
the upcall is dropped and the thread continues)
([capability-internals.md](capability-internals.md#kernel-object-reference-counting) § Kernel Object
Reference Counting). A change of a class's binding (an unbind, or a bind to another
endpoint or with another badge) cancels the fault delivery of that class in flight through the
binding it replaces, unless a
reply or another cancellation claimed it first: a queued fault message is withdrawn, a handler that
received it finds no pending reply (`SYS_IPC_REPLY` fails with `InvalidCapability`), and the
faulting thread delivers the fault again under the binding current when it next runs, the fault
being unhandled when none is bound. The call returns once the delivery is cancelled, waiting, with
interrupts enabled, for a faulting thread that read the old binding to commit its park. A bind to
the same endpoint with the same badge cancels nothing (see
[fault-handling.md](../../../docs/fault-handling.md) § Delivery, Resume, and Kill). Binding requires
only a valid `Endpoint` cap — `Control` on the thread is the authority; the endpoint cap names where
the thread's faults are delivered and, by its derivation badge (`0` for an unbadged cap), how they
are attributed: the fault message carries that badge, which the binder cannot choose. The kernel
synthesizes fault delivery via the binding and distributes no send capability to the endpoint, so a
handler that hands out no `SEND` to it receives `FAULT_LABEL` only from the kernel; a handler that
also serves clients on that
endpoint attributes the message by badge, with the guarantees of an ordinary send's badge (see
[fault-handling.md](../../../docs/fault-handling.md) § Security).

Page faults (`FAULT_KIND_VM`), the faults of a restartable syscall's user copy among them
(§ Restartable Syscalls), are routed to the handler of `FAULT_CLASS_VM`, and other
kernel-unresolvable ring-3 exceptions (`FAULT_KIND_EXCEPTION`) to the handler of
`FAULT_CLASS_EXCEPTION`, and posted upcalls (`FAULT_KIND_UPCALL`) to the handler of
`FAULT_CLASS_UPCALL` (§ `SYS_THREAD_POST_UPCALL`); a handler bound for several classes dispatches on
the fault kind and replies `FAULT_REPLY_KILL` for kinds it does not handle (see
[fault-handling.md](../../../docs/fault-handling.md) § Fault-Handler Binding and
§ Implementation Status).

**Capability requirement:** `thread_cap` MUST have Control rights; `endpoint_cap`
(when non-zero) MUST refer to an `Endpoint`.

**Errors:** `InvalidArgument` (`reserved` nonzero, or `fault_class_mask` zero or with a bit no
class defines; checked first), `InvalidCapability` (bad thread or endpoint cap),
`InsufficientRights` (thread lacks Control).

---

### `SYS_THREAD_GET_FAULT_HANDLER` (56)

Read a thread's fault-handler binding for one fault class (see
[fault-handling.md](../../../docs/fault-handling.md) § Fault-Handler Binding).

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Control rights) |
| 1 | `class` | Exactly one class bit: `FAULT_CLASS_VM`, `FAULT_CLASS_EXCEPTION`, or `FAULT_CLASS_UPCALL` |

**Return:** `rax`/`a0`: `1` when the class is bound, `0` when it is not, or a `SyscallError`;
on success `rdx`/`a1` carries the bound badge (`0` when unbound).

The class's endpoint and badge are read once under the target thread's `sched_lock`, where the
binders publish them, so the badge is the one bound with the endpoint the flag reports. The call
creates no capability and returns no endpoint or kernel address; the badge is the derivation badge
of the cap a binder bound or the copy of one (see
[cross-boundary-disclosure.md](cross-boundary-disclosure.md)).

**Capability requirement:** `thread_cap` MUST have Control rights.

**Errors:** `InvalidArgument` (`class` is not exactly one class bit; checked first),
`InvalidCapability` (bad thread cap), `InsufficientRights` (the cap lacks Control).

---

### `SYS_THREAD_INHERIT_FAULT_HANDLER` (57)

Copy one thread's fault-handler bindings, per class, onto another (see
[fault-handling.md](../../../docs/fault-handling.md) § Fault-Handler Binding and § Inheritance is
userspace policy).

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `dst_thread_cap` | Thread capability (Control rights), the thread bound |
| 1 | `src_thread_cap` | Thread capability (Control rights), the thread whose bindings are copied |
| 2 | `fault_class_mask` | Classes copied, as for `SYS_THREAD_SET_FAULT_HANDLER` |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

For each selected class the destination is bound to the source's endpoint with the source's badge,
or unbound where the source has none. The source's bindings are read once under its `sched_lock`,
each endpoint pinned there by a reference that becomes the destination binding's own, and the
destination's are published under its `sched_lock` as `SYS_THREAD_SET_FAULT_HANDLER` publishes
them, with the same cancellation of a delivery in flight under a changed binding. A copy from a
thread onto itself changes nothing. The binder needs no capability to the endpoint.

**Capability requirement:** both thread caps MUST have Control rights.

**Errors:** `InvalidArgument` (refused `fault_class_mask`; checked first), `InvalidCapability`
(a bad thread cap), `InsufficientRights` (a thread cap lacks Control).

---

### `SYS_THREAD_POST_UPCALL` (58)

Post an asynchronous upcall to a thread, delivered to the receiver of its `FAULT_CLASS_UPCALL`
binding at the thread's next delivery point (see
[fault-handling.md](../../../docs/fault-handling.md) § Asynchronous Upcalls).

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Upcall rights; Control rights too for `UPCALL_ANY_INSTRUCTION`) |
| 1 | `cookie` | Delivered uninterpreted as the upcall message's data word 1 |
| 2 | `flags` | `0`, or `UPCALL_ANY_INSTRUCTION` to deliver at an interrupt's return to user mode as well as at a syscall's return |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The post makes the upcall pending on the thread, written under the thread's `sched_lock` with its
cookie and flag. Unless the thread masks upcalls (§ `SYS_THREAD_SET_UPCALL_MASK`), a block of the
thread in a blocking syscall is cancelled as `SYS_THREAD_STOP` cancels it, and the thread is woken:
the syscall returns `Interrupted` and the upcall is delivered at its return. A park the thread
commits after the post is refused the same way, and a fault or upcall delivery in progress is left
to resolve (see [thread-lifecycle-and-sleep.md](thread-lifecycle-and-sleep.md) § Upcall
Cancel-and-Wake Protocol). Otherwise an `UPCALL_ANY_INSTRUCTION` post prods a CPU that runs the
thread, so the thread reaches an interrupt's return. The delivery is a fault delivery of
`FAULT_KIND_UPCALL`, data words `[kind, cookie, point, ip]`, with `point` `UPCALL_POINT_SYSCALL` or
`UPCALL_POINT_INTERRUPT`; any reply resumes the thread, and a decline or a cancellation drops the
upcall.

**Capability requirement:** `thread_cap` MUST have Upcall rights, and Control rights as well for
`UPCALL_ANY_INSTRUCTION`.

**Errors:** `InvalidArgument` (a `flags` bit other than `UPCALL_ANY_INSTRUCTION`; checked first),
`InvalidCapability` (bad thread cap), `InsufficientRights` (a right above is missing),
`InvalidState` (the thread is `Created` or `Exited`, or has no handler bound for
`FAULT_CLASS_UPCALL`), `QueueFull` (an upcall is already pending on the thread).

---

### `SYS_THREAD_SET_UPCALL_MASK` (59)

Set or clear the calling thread's upcall mask (see
[fault-handling.md](../../../docs/fault-handling.md) § Asynchronous Upcalls).

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `masked` | `1` to mask upcalls, `0` to unmask them |

**Return:** `rax`/`a0`: the previous mask (`0` or `1`); `SyscallError` on failure.

While the mask is set a posted upcall stays pending, is not delivered, and cancels no block of the
thread. Clearing the mask delivers a pending upcall at this syscall's return. The mask is written
under the thread's own `sched_lock`, where a post and a park commit read it.

No capability is required — this syscall acts on the calling thread implicitly.

**Errors:** `InvalidArgument` (`masked` is neither `0` nor `1`).

---

### `SYS_THREAD_SLEEP` (46)

Block the calling thread for a bounded duration. The timer wakes it at the deadline.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `ms` | Sleep duration in milliseconds; `0` returns immediately |

**Return:** `rax`/`a0`: 0 on wake, and also 0 at once, without sleeping, when a
pending coalesced wake refuses the park (see
[thread-lifecycle-and-sleep.md](thread-lifecycle-and-sleep.md) § `sys_thread_sleep` and the
Plain-Sleep Path), so a caller that needs the full duration re-checks elapsed time;
`SyscallError` on failure.

No capability is required — this syscall acts on the calling thread implicitly.

**Errors:** `InvalidCapability` (no current thread), `Interrupted` (the thread was stopped, or
interrupted by an upcall, before or during the sleep, unless the timer had already claimed its
elapsed deadline). The kernel's sleep list has no capacity to exhaust, so a sleep never fails for
room ([thread-lifecycle-and-sleep.md §
Sleep List Invariants](thread-lifecycle-and-sleep.md#sleep-list-invariants), invariant 4).

---

### `SYS_THREAD_BIND_NOTIFICATION` (47)

Register a death observer on a thread. When the target exits or faults terminally, the
kernel posts the two-word entry `(exit_reason, correlator)` to the bound event queue: the full
`u64` exit reason as the payload word and the full `u64` correlator as the tag word
(§ `SYS_EVENT_POST` (5)).

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Control rights) to observe |
| 1 | `eventq_cap` | Event queue capability (Post rights) the death notification is posted to |
| 2 | `correlator` | Caller-chosen `u64` routing tag, delivered unchanged as the tag word |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure. If the target has
already exited, the retained reason is delivered immediately and the call still returns 0.

**Lifetime:** a binding holds a reference on the event queue object from the bind until the
target thread is destroyed (its Thread object freed), so deleting every capability to the queue
leaves it live: the death post still reaches it, and the queue is freed after the post, when the
thread's teardown releases the binding's reference. A bind onto an already-exited thread posts at
once and holds no reference
([capability-internals.md](capability-internals.md#kernel-object-reference-counting) § Kernel
Object Reference Counting).

**Capability requirements:** `thread_cap` (Control), `eventq_cap` (Post).

**Observer nodes:** each live binding holds one death-observer node of `eventq_cap`'s pool
(§ `SYS_CAP_CREATE_EVENT_Q` (9), argument 2) until the target thread is destroyed; a bind onto an
already-exited thread takes none.

**Errors:** `InvalidCapability`, `InsufficientRights` (thread lacks Control or event
queue lacks Post), `OutOfMemory` (the event queue has no free observer node), `QuotaExceeded`
(the event queue's reference count is at its 2^31 ceiling).

---

## Wait Set Syscalls

### `SYS_WAIT_SET_ADD` (26)

Add an IPC primitive to a wait set.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `wait_set_cap` | Wait set capability (Modify rights) |
| 1 | `source_cap` | Capability to an endpoint, notification, or event queue |
| 2 | `badge` | Opaque u64 returned to the caller when this source is ready |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The `badge` is chosen by the caller to identify the source in a subsequent
`SYS_WAIT_SET_WAIT` result. The kernel does not interpret it.

**Capability requirements:** `wait_set_cap` (Modify), `source_cap` (the receive-side
right matching its type: Receive on an Endpoint, Wait on a Notification, Recv on an
EventQueue).

**Errors:** `InvalidCapability`, `InsufficientRights` (wait set lacks Modify, or source
lacks Receive/Wait/Recv), `InvalidArgument` (every member slot of the wait set's capacity is
occupied, or source already in a wait set).

---

### `SYS_WAIT_SET_REMOVE` (27)

Remove a previously added source from a wait set.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `wait_set_cap` | Wait set capability (Modify rights) |
| 1 | `source_cap` | Capability identifying the source to remove |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

**Capability requirements:** `wait_set_cap` (Modify).

**Errors:** `InvalidCapability` (bad cap, or source not in this wait set),
`InsufficientRights` (wait set lacks Modify).

---

### `SYS_WAIT_SET_WAIT` (28)

Block until any member of the wait set becomes ready, with an optional bounded wait.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `wait_set_cap` | Wait set capability (Wait rights) |
| 1 | `timeout_ms` | Wait policy: the sentinels of `SYS_EVENT_RECV` |

| Value | Behaviour |
|---|---|
| `0` | Block until a member is ready |
| `u64::MAX` (`WAIT_TRY_ONCE`) | Non-blocking try-once: return a ready member's badge, or `WouldBlock` at once |
| `1 ..= MAX-1` | Block until a member is ready or `timeout_ms` ms elapse, then return `WouldBlock` (at timer-tick granularity; a badge is any `u64`, so no in-band value marks the expiry) |

**Return:**

- `rax`/`a0`: 0 on success; `SyscallError` on failure
- `rdx`/`a1`: badge of the ready source (valid on success)

Only one ready source is returned per call (wake-one semantics). If multiple sources
are ready simultaneously, subsequent calls return them in turn without blocking, a
source that stays ready again after the others (see
[ipc-internals.md](ipc-internals.md) § Multiple Ready Sources).

Any number of threads may wait on one wait set. They queue in arrival order, and each
arrival of work on a member (a call queued on an endpoint, an entry posted to an event queue,
a send to a notification that wakes no direct waiter) wakes the longest-waiting one with that
member's badge; the others stay parked. A wake hands that one arrival to that one thread, and
no other thread is woken for it: if the woken thread does not take the work (it is stopped or
destroyed after the wake, or receives from another source first), the work stays ready on
the set, and the next thread to enter the wait, or the thread the next arrival on any member
wakes, is returned it. A pool whose other threads are all parked leaves that work untaken
until one of those happens (see [ipc-internals.md](ipc-internals.md) § Wait Set Readiness
Model, P1).

The badge names a source that was ready when the wait returned, or when its readiness
woke the caller; a source whose readiness lapsed before the call (an endpoint whose
queued sender was stopped or destroyed, a notification a direct wait drained) is not
returned for it. Readiness can still lapse between the return and the caller's receive
on the source, so that receive can find nothing: the badge reserves nothing, and another
thread waiting on the same set can take what made the source ready. A source stays queued on
the set while it is ready, so a wait by another thread before the first one receives returns
the same source (see [ipc-internals.md](ipc-internals.md) § Wait Path and § Wait Set
Readiness Model, P2).

**Capability requirement:** `wait_set_cap` must have Wait rights.

**Errors:** `InvalidCapability`, `InsufficientRights` (cap lacks Wait), `Interrupted` (the
caller was stopped or interrupted by an upcall, or the wait set was destroyed while the caller
waited), `WouldBlock` (a try-once found no member ready, or a bounded wait elapsed).

---

## Interrupt Syscalls

### `SYS_IRQ_ACK` (29)

Acknowledge a hardware interrupt line after handling, through the capability's own binding.
Re-enables the line at the interrupt controller once no binding on it owes an acknowledgement.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `irq_cap` | Interrupt capability for the line to acknowledge |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The kernel masks the interrupt line before delivering to the bindings on it, and marks every
binding as owing an acknowledgement (see [docs/architecture.md](../../../docs/architecture.md)
— Driver Model, and § `SYS_IRQ_REGISTER`). The driver must call `SYS_IRQ_ACK` to re-enable the
line. `SYS_IRQ_ACK` clears the acknowledgement owed by the binding of `irq_cap`'s own object (each
copy of an Interrupt capability is an object of its own), and unmasks the line only when no
binding on it owes one, so a shared line is re-enabled once every receiver signalled since the
last unmask has acknowledged. A new binding owes from the start, so the driver's first
`SYS_IRQ_ACK` after registering is what lets the line deliver. An acknowledgement is
idempotent: a repeated one, or one with no delivery since the last (a driver's timeout-wake
acknowledgement), clears nothing and unmasks only when no binding owes; with a single binding
on the line it unmasks whether or not an interrupt has been delivered since. Through an object
with no binding (never registered) the call changes nothing and returns 0: deleting a bound
Notification's capabilities leaves the binding, which still owes its acknowledgements
(§ `SYS_IRQ_REGISTER`, Unbind). A message-signaled target (§ `SYS_IRQ_MSG_ALLOC`) is never masked,
so through its capability the call changes nothing and returns 0.

**Capability requirement:** `irq_cap` MUST be a valid interrupt capability for the
specific line.

**Errors:** `InvalidCapability`, `InsufficientRights` (cap lacks Notify),
`InvalidArgument` (cap covers more than one line).

---

### `SYS_IRQ_REGISTER` (30)

Bind a notification to a hardware interrupt line through an Interrupt capability. When the
interrupt fires, the kernel delivers it by ORing a notification bit into every notification
bound to the line.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `irq_cap` | Interrupt capability for the line to register |
| 1 | `notification_cap` | Notification capability (Notify rights) to notify on interrupt |
| 2 | `mode` | The line's trigger and polarity: `IRQ_MODE_LEVEL` (bit 0, level-triggered; clear, edge) and `IRQ_MODE_ACTIVE_LOW` (bit 1, asserts low; clear, high), from `abi/syscall`; 0 is edge-triggered, active-high |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The binding lives in `irq_cap`'s own object: a copy or derivation of an Interrupt capability
references a fresh object over the same line (see
[capability-model.md](../../../docs/capability-model.md) § Interrupt), so a line holds one binding
per bound object, up to `MAX_IRQ_BINDINGS` (64), and receivers sharing a wired line each bind
through their own capability.

- **Bind.** Through an object with no binding the call adds one. The line's first binding records
  `mode` and routes the line at its controller in it, to one CPU, the next in turn
  ([arch-interface.md](arch-interface.md) § `interrupts`), and leaves it masked; the routing and the
  mode are kept while any binding remains, so every receiver on the line is signalled from that CPU.
  The binding holds a counted reference on the notification's object, which keeps the Notification
  from being freed while the binding names it. The call returns once the delivery running on the
  line's CPU, if any, has finished, so its mask cannot land after the receiver's first
  `SYS_IRQ_ACK`. A later binding must pass the recorded mode, and masks the line. Every new binding
  owes an acknowledgement, so the line stays masked until its receiver's first `SYS_IRQ_ACK`.
- **Rebind.** Through an object already bound, the call, which must pass the line's recorded mode,
  rebinds that binding to `notification_cap`'s notification, keeping whether it owes an
  acknowledgement and leaving the line's mask as it is. The binding's reference moves to the new
  notification's object and the replaced notification's is given up, once no delivery can still
  hold it: the call returns once the delivery running on the line's CPU, if any, has finished.
- **Deliver.** Each interrupt masks the line, marks every binding on it as owing an
  acknowledgement, ORs bit 0 into each bound notification, and completes at the controller. An
  interrupt the controller forwarded before the mask took effect is delivered too, so a receiver
  can be signalled again before it acknowledges. A receiver whose device did not raise the
  interrupt finds nothing in its device's status and acknowledges. The driver MUST call
  `SYS_IRQ_ACK` (see [architecture.md](../../../docs/architecture.md) § Driver Model); the line is
  unmasked once no binding owes.
- **Unbind.** A binding is removed when its Interrupt object is freed (its last capability deleted,
  consumed by a split, revoked through an ancestor, or torn down with its holder's CSpace); the
  removal gives up the binding's reference on its notification's object and waits out the delivery
  running on the line's CPU. Deleting a Notification's capabilities removes no binding: the bindings
  stay, and keep the Notification, until their Interrupt objects rebind or are freed. The line
  is then unmasked if bindings remain and none owes, so a receiver that goes cannot hold a shared
  line masked, and released at its controller when no binding remains; the release forgets the mode,
  so the line's next first binding records its own.

A message-signaled target (§ `SYS_IRQ_MSG_ALLOC`) binds through the same call with three
differences. Its CPU and slot were taken at its mint, so its first binding routes nothing. It
takes one binding, in mode 0 (a device's message is an edge). It is never masked: each message
ORs bit 0 into the bound notification and completes at the local APIC (x86-64) or needs no
completion (the IMSIC claim, RISC-V), and its `SYS_IRQ_ACK` changes nothing; a driver that must
hold its device's messages off does so at the device, through the device's own interrupt controls,
since devmgr alone writes the MSI-X table and its per-vector masks
([docs/device-management.md](../../../docs/device-management.md#message-signaled-interrupts)
§ Message-Signaled Interrupts). Removing
its binding frees no slot: the target stays the capability's until the capability is gone.

On x86-64 the line's I/O APIC redirection entry is programmed with the recorded mode: bit 15 set
for level-triggered, bit 13 for active-low. A level-triggered entry whose device still asserts at
the unmask delivers again, so an assertion while the line is masked is not lost (see
[docs/device-management.md](../../../docs/device-management.md) § Interrupt Delivery for what an
edge-triggered entry loses on a shared level-triggered line). On RISC-V the line's APLIC
source mode is programmed with it: Edge1 (rising edge), Edge0 (falling edge), Level1
(active-high) or Level0 (active-low). The APLIC in MSI delivery mode clears a source's pending
bit when it forwards it, so the unmask of a level-sensitive source pends it again through
`setipnum_le`, which takes only while the source is still asserted: an assertion held across
the acknowledgements is delivered again, as on x86-64.

**Capability requirements:** `irq_cap` (Notify rights; single-line), `notification_cap`
(Notify rights).

**Errors:** `InvalidCapability`, `InsufficientRights` (a cap lacks Notify),
`InvalidArgument` (IRQ cap covers more than one line, or names an id no discovered
interrupt controller implements: on x86-64 a GSI no I/O APIC reports, where the root
Interrupt cap spans 32768 GSIs; on RISC-V a source outside the APLIC's reported
`1..=riscv,num-sources`, where the root Interrupt cap spans the APLIC's 1024-id space; see
[arch-interface.md](arch-interface.md) § Module-level constants and free functions; or `mode`
sets a bit outside `IRQ_MODE_MASK`, differs from the mode the line's bindings recorded, or is
not 0 for a message-signaled target),
`QuotaExceeded` (the notification's object holds as many references as it may
(`REF_COUNT_LIMIT`); the line already holds `MAX_IRQ_BINDINGS` bindings, through other objects; a
message-signaled target already holds its one binding, through another object; or, for the
line's first binding on x86-64, no CPU whose APIC id an I/O APIC can name has a free device IDT
vector, each CPU having 217, shared with the message-signaled targets on it; a vector is freed
when its line's last binding is removed; or, for the line's first binding on RISC-V, no CPU's
IMSIC file has a free interrupt identity; an identity is freed when its line's last binding is
removed). Nothing changes on an error.

---

### `SYS_IOPORT_BIND` (35)

Bind an IoPort capability to a thread, granting that thread permission to
execute `in`/`out` instructions for the capability's port range via the TSS I/O
Permission Bitmap (IOPB).

**x86-64 only.** On RISC-V this syscall returns `NotSupported`.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Control rights) |
| 1 | `ioport_cap` | IoPort capability (Use rights) |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

Multiple bindings may be made to the same thread, each authorising a different port range; a
thread records at most `MAX_IOPORT_BINDINGS` (252) bindings, and binding the same
`ioport_cap` object again reuses its record. A bind takes effect at the target's next port
access even when the target is running on another CPU (every CPU's TSS IOPB is invalidated
and reloaded lazily). The thread records each binding against the `ioport_cap`'s object.
When that object is freed, because `ioport_cap` (or the copy it is) was deleted, consumed by
a split, or revoked through an ancestor, the binding is withdrawn from the thread, whose
bitmap is rebuilt from its remaining bindings, and every CPU reloads its TSS IOPB before its
next port access, a CPU running the thread included (see
[capability-model.md](../../../docs/capability-model.md) § IoPort (x86-64 only)).

**Capability requirements:** `thread_cap` (Control rights), `ioport_cap` (Use rights).

**Errors:** `NotSupported` (RISC-V — no I/O ports), `InvalidCapability` (also for a thread
already `Exited`),
`InsufficientRights` (a cap lacks Control/Use), `QuotaExceeded` (the thread already records
`MAX_IOPORT_BINDINGS` bindings through other objects), `OutOfMemory` (the first bind's
binding table, three pages, cannot be taken from the target thread's `CSpace` pool; see
[capability-internals.md](capability-internals.md) § IoPort Bindings).

---

### `SYS_IRQ_SPLIT` (49)

Split an interrupt range capability into two non-overlapping child capabilities at an
IRQ id. The original capability is consumed.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `irq_cap` | Interrupt range capability to split (Notify rights) |
| 1 | `split_at` | IRQ id to split at; `start < split_at < start + count` |

**Return:**

- `rax`/`a0`: capability descriptor for the lower range `[start, split_at)` on success;
  `SyscallError` on failure
- `rdx`/`a1`: capability descriptor for the upper range `[split_at, start+count)` on
  success

Both children inherit the original's rights and are reparented to the original's
derivation parent. The original `irq_cap` is consumed.

**Capability requirement:** `irq_cap` must have Notify rights.

Original revalidation, batched re-linking, `InvalidState`, and `Interrupted`: as for
`SYS_MMIO_SPLIT`.

**Errors:** `InvalidState`, `Interrupted` (per above), `InvalidArgument` (`split_at` outside
`(start, start+count)`), `InvalidCapability`, `InsufficientRights` (cap lacks Notify), `OutOfMemory`
(the caller's `CSpace` pool cannot back the children's bodies or slots), `QuotaExceeded` (caller's
CSpace directory structurally full).

---

### `SYS_IOPORT_SPLIT` (51)

Split an IoPort capability into two non-overlapping child capabilities at a port number.
The original capability is consumed, which withdraws every binding made through it as
§ `SYS_IOPORT_BIND` describes.

**x86-64 only.** On RISC-V this syscall returns `NotSupported`.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `ioport_cap` | IoPort capability to split (Use rights) |
| 1 | `split_at` | Port number to split at; `1 <= split_at <= 0xFFFF` and `base < split_at < base + size` |

**Return:**

- `rax`/`a0`: capability descriptor for the lower range `[base, split_at)` on success;
  `SyscallError` on failure
- `rdx`/`a1`: capability descriptor for the upper range `[split_at, base+size)` on
  success

Both children inherit the original's rights and are reparented to the original's
derivation parent. The original `ioport_cap` is consumed: every binding made through it is
withdrawn from every bound thread (the caller included), its bitmap rebuilt and every CPU's TSS
IOPB invalidated, before the call returns (unless a concurrent syscall pins the object, then when
that syscall releases it). A caller that needs the ports binds a child afterwards.

**Capability requirement:** `ioport_cap` must have Use rights.

Original revalidation, batched re-linking, `InvalidState`, and `Interrupted`: as for
`SYS_MMIO_SPLIT`.

**Errors:** `InvalidState`, `Interrupted` (per above), `NotSupported` (RISC-V — no I/O ports),
`InvalidArgument` (`split_at` 0, `> 0xFFFF`, or outside `(base, base+size)`), `InvalidCapability`,
`InsufficientRights` (cap lacks Use), `OutOfMemory` (the caller's `CSpace` pool cannot back the
children's bodies or slots), `QuotaExceeded` (caller's CSpace directory structurally full).

---

### `SYS_IRQ_MSG_ALLOC` (62)

Mint one message-signaled Interrupt capability: a delivery target a device raises by writing a
message (MSI or MSI-X) rather than by asserting a wired line.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `authority_cap` | Interrupt capability carrying `RIGHTS_IRQ_MINT` |

**Return:** `rax`/`a0`: the new capability's handle on success; `SyscallError` on failure.

The kernel takes a free slot of the next CPU in turn that has one
([arch-interface.md](arch-interface.md) § `interrupts`); the target's id, past every wired line, is
computed from its CPU and slot.
On x86-64 the slot is a device IDT vector of a CPU whose APIC id is below `0xFF`, the widest a
compatibility-format message address names (interrupt remapping is not implemented); on RISC-V it
is an interrupt identity in the hart's supervisor-level IMSIC file. Wired lines take their slots
from the same spaces. The call inserts into the caller's `CSpace` an Interrupt capability over
that one id, unbound, carrying `RIGHTS_IRQ_NOTIFY` only, as a derivation child of
`authority_cap`, so revoking the authority deletes it.

The holder reads the message through `SYS_CAP_INFO` (`CAP_INFO_IRQ_MSG_ADDRESS`,
`CAP_INFO_IRQ_MSG_DATA`), programs it into its device, and binds the capability with
`SYS_IRQ_REGISTER` in mode 0 (§ `SYS_IRQ_REGISTER` for how a message-signaled target delivers).
A copy of the capability names the same target. The target is held from the mint until neither
the capability nor any copy of it remains, whether or not it is bound, and is then free for a
later mint.

One call mints one target; a caller needing K targets (a device with K MSI-X vectors) calls K
times. The target's state is the lineage root of the capability the call creates, funded from the
caller's `CSpace` pool and returned there when the last capability to the target is gone; the
kernel reserves nothing per target at boot beyond the CPUs' slot rows
([docs/limits.md](../../../docs/limits.md)), so targets run out only with the CPUs' slots.

The kernel mints the root Interrupt capability with `RIGHTS_IRQ_MINT`
([capability-model.md](../../../docs/capability-model.md) § Interrupt); a minted capability does
not carry it.

**Capability requirement:** `authority_cap` must be an Interrupt capability with Mint rights.

**Errors:** `InvalidCapability` (`authority_cap` names no Interrupt capability),
`InsufficientRights` (it lacks Mint), `QuotaExceeded` (no CPU a message can reach has a free slot;
or the caller's `CSpace` directory is structurally full), `OutOfMemory` (the caller's `CSpace` pool
cannot fund the capability's body or slot; a refill cures it), `InvalidState` (the authority's slot
is held by an in-flight revoke, move, or transfer). Nothing changes on an error.

---

## Thread Configuration Syscalls

### `SYS_THREAD_CONFIGURE` (23)

Set the entry point, initial stack pointer, first-argument register, and TLS base for
a thread in the `Created` state. Must be called after `SYS_CAP_CREATE_THREAD` (which
binds the thread's address space and CSpace) and before `SYS_THREAD_START`.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Control rights) |
| 1 | `entry` | Virtual address of the thread entry point |
| 2 | `stack_top` | Initial stack pointer (rounded to the entry ABI's stack alignment) |
| 3 | `arg` | Value passed in the first argument register |
| 4 | `tls_base` | Initial TLS base (`fs_base` on x86-64; `tp` on RISC-V) |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The thread must be in the `Created` state; calling on a thread in any other state
returns `InvalidArgument`. The initial trap frame is built on the thread's kernel
stack so the first scheduler switch enters user mode at `entry`.

**Capability requirement:** `thread_cap` must have Control rights.

**Errors:** `InvalidCapability`, `InsufficientRights` (cap lacks Control),
`InvalidArgument` (thread not in the Created state, `entry` or `tls_base` at or above the
user VA top, or `stack_top`, as passed or after rounding to the entry ABI's alignment, above
it; on x86-64 the rounding is `(stack_top & !0xF) - 8`, so a `stack_top` below 16 wraps
above it).

---

## Cross-CSpace Syscalls

### `SYS_CAP_COPY` (24)

Copy a capability from the caller's CSpace into another CSpace, creating a new
derivation tree node (child of the source slot).

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `src_cap` | Capability to copy (source slot in caller's CSpace) |
| 1 | `dst_cspace_cap` | Target CSpace capability (Insert rights) |
| 2 | `dst_slot` | Destination slot index in the target CSpace, or `0` to let the kernel allocate a free slot (slot 0 is permanently null, so it is a safe "kernel picks" sentinel) |
| 3 | `rights_mask` | Rights for the copy; the effective rights are `rights_mask & source_rights` (bits the source lacks are silently masked off, not rejected) |

**Return:** `rax`/`a0`: the destination capability handle (slot index plus generation) on
success; `SyscallError` on failure.

The copy is a derivation (child of `src_cap` in the tree). Both the original and
the copy remain valid. The copy of an `Mmio`, `IoPort`, or `Interrupt` capability references a
fresh object, as for `SYS_CAP_DERIVE`. With `dst_slot == 0` the kernel auto-allocates a free
slot (and returns it); with a non-zero `dst_slot` the cap is placed at that
caller-chosen index — the path init uses to populate well-known slots in new
service CSpaces before starting their threads. This caller-chosen-slot mode
absorbed the former `SYS_CAP_INSERT`, whose number 32 `SYS_THREAD_SET_FAULT_HANDLER` now
reuses.

A high explicit `dst_slot` materialises every intermediate leaf page up to
its own, drawn from the destination's slot-page pool (donor-funded, in
bounded batches outside the heavyweight locks). When the pool cannot cover
the required growth the call fails with `OutOfMemory` before consuming any
pool page. Leaves grown for a placement that then fails — the target slot
turns out to be occupied, or a concurrent pool consumer starves the final
grow — stay behind as ordinary free capacity, and the pool pages they
consumed stay spent (see [capability-internals.md](capability-internals.md) § Storage:
Hybrid Radix Directory).

**Capability requirements:** `src_cap` (any non-null capability; no right is checked),
`dst_cspace_cap` (Insert).

The source is revalidated under the derivation lock before the copy is linked
beneath it (see [capability-internals.md](capability-internals.md) § Global
Derivation Lock): a source a concurrent delete, move, or revoke freed meanwhile
fails with `InvalidCapability`, and one with a `SYS_CAP_REVOKE`, a `SYS_CAP_MOVE`, or an IPC
capability transfer in flight with `InvalidState`. With a non-zero `dst_slot`, if
every other reference to the
destination CSpace goes while the call is backing the leaves up to that index,
the call reclaims that CSpace and fails with `InvalidCapability`; a caller bound
to it is stopped and the call never returns (see
[capability-model.md](../../../docs/capability-model.md) § "Kill process" pattern).

**Errors:** `InvalidCapability`, `InvalidState` (a `SYS_CAP_REVOKE`, a `SYS_CAP_MOVE`, or an IPC
capability transfer is in flight on the source), `InsufficientRights` (dst CSpace lacks Insert),
`InvalidArgument` (dst_slot occupied or out of range), `OutOfMemory` (slot-page pool exhausted,
or the dst CSpace pool cannot back an `Mmio`, `IoPort`, or `Interrupt` copy's object),
`QuotaExceeded` (dst CSpace directory structurally full, an `Mmio`, `IoPort`, or `Interrupt`
source's range already has `RANGE_COPY_LIMIT` (2^31 - 1) live copies, or any other source's object
has its reference count at its 2^31 ceiling).

---

### `SYS_CAP_MOVE` (25)

Move a capability from the caller's CSpace into another CSpace (or within its
own). Transfer semantics: the source slot is cleared; the destination inherits
the source's derivation position, including every capability derived from it.
An explicit high `dst_slot` follows `SYS_CAP_COPY`'s growth contract (every
intermediate leaf materialised from the destination's pool; `OutOfMemory`
without consumption when the pool cannot cover it).

The derived children are re-linked under the destination in batches with the
derivation lock released between them (a slot can have arbitrarily many
children; see [capability-internals.md](capability-internals.md) § Move).
Between batches both slots are pinned exactly as a `SYS_CAP_REVOKE` root is,
so the operations listed under `SYS_CAP_REVOKE` refuse them with
`InvalidState`; a `SYS_CAP_REVOKE` on an ancestor still reaches every node.
A concurrent deriver extending the child list faster than it is moved returns
`Interrupted`, leaving the capability live in both slots with the destination
a derived child of the source — a `SYS_CAP_REVOKE` on the source reclaims
it, so nothing is left outside the caller's reach even when the destination
index was auto-allocated. A CSpace torn down while the move is in flight
releases the children hanging under its dying slots as derivation roots, as
for any other slot.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `src_cap` | Capability to move (source slot in caller's CSpace) |
| 1 | `dst_cspace_cap` | Target CSpace capability (Insert rights) |
| 2 | `dst_slot` | Destination slot index in the target CSpace, or `0` to let the kernel allocate a free slot |

**Return:** `rax`/`a0`: the destination capability handle on success;
`SyscallError` on failure.

**Capability requirements:** `src_cap` (any), `dst_cspace_cap` (Insert).

With a non-zero `dst_slot`, if every other reference to the destination CSpace
goes while the call is backing the leaves up to that index, the call reclaims
that CSpace and fails with `InvalidCapability`; a caller bound to it is stopped
and the call never returns (see
[capability-model.md](../../../docs/capability-model.md) § "Kill process" pattern).

**Errors:** `InvalidCapability` (also: an ancestor's revoke freed the
capability while the move was in flight), `InsufficientRights` (dst CSpace
lacks Insert), `InvalidArgument` (dst_slot occupied or out of range),
`OutOfMemory` (slot-page pool exhausted), `QuotaExceeded` (dst CSpace directory
structurally full, or the object's reference count is at its 2^31 ceiling: the destination takes
its reference before the source releases its own), `InvalidState` (a `SYS_CAP_REVOKE`, another
`SYS_CAP_MOVE`, or an IPC
capability transfer is in flight on the source slot; or the destination slot was
freed while the move was in flight — the source keeps the capability),
`Interrupted` (liveness backstop, per above).

---

## Address Space Syscalls

### `SYS_ASPACE_QUERY` (41)

Translate a user virtual address to its mapped physical address.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `aspace_cap` | AddressSpace cap slot (must have `READ` right) |
| 1 | `virt` | Page-aligned virtual address to translate (user half only) |

**Return:** `rax`/`a0`: the mapped physical address on success; negative
`SyscallError` on failure.

**Capability requirement:** `READ` right on the AddressSpace cap, which
`SYS_CAP_CREATE_ASPACE` mints only from a source Memory cap carrying the `Phys`
right, so only a process that may read physical addresses translates its pages.

**Errors:**
- `InvalidAddress` — `virt` is not page-aligned, outside the user half
  (at or above `user_va_top`: `(1 << 47) - 4096` on x86-64, `(1 << 56) - 4096` under
  5-level paging; on riscv64 the active paging mode's boundary, `1 << 38` / `1 << 47` /
  `1 << 56`), or not currently mapped.
- `InvalidCapability` — cap slot is null, wrong type, or the object is gone.
- `InsufficientRights` — cap does not have the `READ` right.

---

### `SYS_ASPACE_BIND_NOTIFICATION` (53)

Bind a terminal-fault death observer to an address space. When any thread in the space faults
terminally (see [capability-model.md](../../../docs/capability-model.md) § "Kill process" pattern
for the triggers), the kernel posts the two-word entry `(fault reason, correlator)` to the bound
event queue, as § `SYS_THREAD_BIND_NOTIFICATION` (47) lays it out. Voluntary
`SYS_THREAD_EXIT` does not fire these observers (see
[capability-model.md](../../../docs/capability-model.md) § "Kill process" pattern).

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `aspace_cap` | AddressSpace capability (Control rights) to observe |
| 1 | `eventq_cap` | Event queue capability (Post rights) the fault notification is posted to |
| 2 | `correlator` | Caller-chosen `u64` routing tag, delivered unchanged as the tag word |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure. If the space has
already terminal-faulted, the retained reason is delivered immediately and the call
still returns 0.

**Lifetime:** a binding holds a reference on the event queue object from the bind until the
address space is destroyed, so deleting every capability to the queue leaves it live for the
terminal-fault post; the address space's teardown releases the reference. A bind onto an
already-faulted space posts at once and holds no reference
([capability-internals.md](capability-internals.md#kernel-object-reference-counting) § Kernel
Object Reference Counting).

**Capability requirements:** `aspace_cap` (Control), `eventq_cap` (Post).

**Observer nodes:** each live binding holds one death-observer node of `eventq_cap`'s pool
(§ `SYS_CAP_CREATE_EVENT_Q` (9), argument 2) until the address space is destroyed; a bind onto an
already-faulted space takes none.

**Errors:** `InvalidCapability`, `InsufficientRights` (address space lacks Control or
event queue lacks Post), `OutOfMemory` (the event queue has no free observer node),
`QuotaExceeded` (the event queue's reference count is at its 2^31 ceiling).

---

## IPC Buffer Syscall

### `SYS_IPC_BUFFER_SET` (42)

Register the per-thread IPC buffer page. This is the page the kernel uses for
IPC data words (`SYS_IPC_CALL`, `SYS_IPC_REPLY`, and `SYS_IPC_RECV` delivery,
whenever `data_count` > 0), for the cap handles a `SYS_IPC_CALL` or
`SYS_IPC_REPLY` transfers (whenever `cap_count` > 0), and for the cap-transfer
result block.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `virt` | Page-aligned virtual address of the IPC buffer page |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The page at `virt` must already be mapped in the calling thread's address space with
at least read+write permissions. The kernel records the address in the calling
thread's TCB. The page must remain mapped for the duration of any IPC that uses it.
The error surface is read-side only: a *sending* IPC that carries data words or
caps fails with `InvalidArgument` when no page is registered and `InvalidAddress`
when the registered page is unmapped, while delivery-side writes are best-effort — a
receiver with no usable page silently misses the data words and the
cap-result block. Transferred capabilities are still moved into that receiver's
CSpace; without the result block it cannot learn their handles, so the slots
stay consumed until the CSpace is torn down.

Calling `SYS_IPC_BUFFER_SET` again replaces the previous registration. Passing 0
deregisters the IPC buffer page (sending IPC that carries data words or caps then
fails with `InvalidArgument`).

**Capability requirement:** None — acts on the calling thread implicitly.

**Errors:** `InvalidAddress` (non-zero `virt` not page-aligned, or outside the user
half), `InvalidCapability` (no current thread).

---

## System Info Syscalls

### `SYS_SYSTEM_INFO` (43)

Query a scalar system value. Returns a single `u64` in `rax`/`a0` — no buffer required.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `info_type` | Which value to query (see `SystemInfoType` below) |
| 1 | `class` | `StackHighWater` only: the stack class (`STACK_CLASS_IDLE` 0, `STACK_CLASS_THREAD` 1, `STACK_CLASS_HANDOFF` 2); ignored by every other `info_type`, for which the `shared/syscall` wrapper passes 0 |

**Return:** `rax`/`a0`: the queried value on success; negative `SyscallError` on failure.

**Capability requirement:** None.

**Errors:** `InvalidArgument` (unknown `info_type`, or unknown `class` for `StackHighWater`);
`NotSupported` (`StackHighWater` handoff class, when the kernel could not locate the handoff
stack).

### `SystemInfoType`

```rust
#[repr(u64)]
pub enum SystemInfoType
{
    /// Kernel version packed as `(major as u64) << 32 | (minor as u64) << 16 | patch`.
    ///
    /// Equals the Seraph project version (the workspace `version`), parsed from
    /// `CARGO_PKG_VERSION` at build time; see `docs/conventions.md` for its
    /// semantics. It does not gate syscall-ABI compatibility.
    ///
    /// Userspace extracts components with:
    ///   major = version >> 32
    ///   minor = (version >> 16) & 0xFFFF
    ///   patch = version & 0xFFFF
    KernelVersion       = 0,

    /// Number of logical CPUs initialised at boot.
    CpuCount            = 1,

    // Discriminants 2 and 3 are reserved and MUST NOT be reused; these values
    // are a stable wire contract.

    /// Size of a physical page in bytes (always 4096 on supported platforms).
    PageSize            = 4,

    /// Boot protocol version used by the bootloader (see `abi/boot-protocol`).
    /// Userspace can use this to interpret fields in the boot info struct.
    BootProtocolVersion = 5,

    /// Microseconds elapsed since kernel timer initialisation. Returns 0 if
    /// the timer has not been initialised yet.
    ElapsedUs           = 6,

    /// Index of the CPU on which the calling thread is currently executing.
    /// Useful for diagnostics and for verifying affinity / migration
    /// behaviour from userspace.
    CurrentCpu          = 7,

    /// Exclusive top of the user half: the first virtual address a mapping
    /// syscall refuses (`user_va_top`). Fixed per architecture and boot paging
    /// mode: `(1 << 47) - 4096` or `(1 << 56) - 4096` on x86-64 at 4- or
    /// 5-level paging, whose top user page is unmappable; `1 << 38`, `1 << 47`,
    /// or `1 << 56` under riscv64 Sv39, Sv48, or Sv57.
    /// ruststd sizes a process's heap and reservation-arena zones from it.
    UserVaTop           = 8,

    /// Deepest use, in bytes, of the kernel stack class in arg1, measured from
    /// the paint the stack was filled with at allocation
    /// ([memory-internals.md](memory-internals.md) § Kernel Stack Depth):
    /// `STACK_CLASS_IDLE` — the deepest idle stack, scanned at the call;
    /// `STACK_CLASS_THREAD` — the deepest of every freed thread's kernel stack
    /// and the caller's own, scanned at the call; `STACK_CLASS_HANDOFF` — the
    /// bootloader's handoff stack, recorded when the BSP left it, or the error
    /// `NotSupported` when its base mark was not found. A diagnostic, read by
    /// ktest.
    StackHighWater      = 9,

    /// Raw retype debit of one `Thread`, in bytes, and so the size of the
    /// Memory capability `SYS_CAP_CREATE_THREAD` needs: one guard page, the
    /// kernel stack, one page holding the object wrapper and the TCB, and the
    /// extended-state (FPU, SIMD, vector) save area, all whole pages. The guard
    /// page is the caller's memory, debited with the rest, and unusable while
    /// the thread exists: the kernel unmaps it below the stack so an overflow
    /// faults. The save area is the boot CPU's, sized once at Phase 5: on
    /// x86-64 the XSAVE size of the components XCR0 enables (CPUID leaf 0xD),
    /// on riscv64 `304 + 32 * vlenb`, each rounded up to pages, at least one.
    /// Fixed for a boot, not across machines; ruststd, procmgr and init size
    /// every Thread slab from it.
    ThreadRetypeBytes   = 10,

    /// Number of `CSpace` ids in use system-wide: ids of the kernel's `CSpace`
    /// registry allocated at a `CSpace`'s creation and not yet returned by its
    /// teardown (`free_cspace_id`), the root `CSpace`'s included
    /// ([capability-internals.md](capability-internals.md) § CSpace Registry).
    /// A diagnostic count, read by ktest to check that a teardown returns its
    /// id; it counts every process's `CSpace`s.
    LiveCSpaceCount     = 11,

    /// Number of instruction-fetch synchronisations the kernel has issued
    /// since boot, one per call, not per page: one at boot for init's image,
    /// one for each `SYS_MEM_MAP` that asks for an executable mapping and each
    /// `SYS_MEM_PROTECT` to executable (counted once the call reaches the
    /// synchronisation, before it maps or protects, so a call that then fails
    /// is counted too), and one for each `SYS_THREAD_WRITE_MEM` that writes
    /// ([docs/memory-model.md](../../../docs/memory-model.md) § Instruction-Fetch
    /// Coherence). Each is a local `fence.i` and then an SBI `remote_fence_i`
    /// on every hart on RISC-V, and is counted and does nothing on x86-64. A
    /// diagnostic count, read by ktest to check that each such path
    /// synchronises, since emulation does not fail when one does not.
    InstructionCacheSyncs = 12,
}
```

### `SYS_SBI_CALL` (44)

Forward a sanctioned SBI firmware call to M-mode on RISC-V, gated by a per-extension
`SbiControl` capability right.

**RISC-V only.** On x86-64 this syscall returns `NotSupported`.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `sbi_cap` | `SbiControl` capability carrying the extension's required right |
| 1 | `extension` | SBI extension ID |
| 2 | `function` | SBI function ID |
| 3 | `arg_a0` | SBI call argument `a0` |
| 4 | `arg_a1` | SBI call argument `a1` |
| 5 | `arg_a2` | SBI call argument `a2` |

**Return:** `rax`/`a0`: the SBI call's return value on success; `SyscallError` on
failure. A nonzero SBI firmware error collapses to `NotSupported`.

Only a fixed set of six extensions is forwardable (SRST, SUSP, CPPC, BASE, DBCN, PMU);
each maps to a distinct `SbiControl` right. Extensions outside that set are rejected
(see [capability-model.md](../../../docs/capability-model.md) § SbiControl (RISC-V only)).

**Capability requirement:** `sbi_cap` must be an `SbiControl` cap holding the right that
`extension` maps to.

**Errors:** `NotSupported` (x86-64, or firmware returned an error), `InvalidArgument`
(extension not in the sanctioned set), `InvalidCapability`, `InsufficientRights`
(`SbiControl` cap lacks the extension's required right).

---

### `SYS_GETRANDOM` (55)

Fill a user buffer with CSPRNG-quality random bytes drawn from the kernel
entropy pool (see [entropy.md](entropy.md)). Each call draws fresh from the
kernel's per-CPU forward-secure generator; userspace holds no generator state.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `buf` | Destination buffer VA (must lie wholly in the user half) |
| 1 | `len` | Bytes to write (`1..=MAX_GETRANDOM_LEN`; `0` is a no-op) |

**Return:** `rax`/`a0`: the number of bytes written (always `len` on success —
the kernel never blocks for entropy once the pool is seeded, which happens
before any userspace process runs — see [entropy.md](entropy.md) § Boot-time entropy);
negative `SyscallError` on failure.

**Capability requirement:** None (ambient, like `SYS_SYSTEM_INFO`). Random bytes
name no object and confer no authority; the call is draw-only and injects no
entropy.

**Errors:** `InvalidArgument` (`len > MAX_GETRANDOM_LEN`); `InvalidAddress`
(null buffer, a span not wholly within the user half, or a fault on the span that is
unhandled; restartable, § Restartable Syscalls); `WouldBlock` (pool not yet seeded —
unreachable in practice).

Callers fill larger buffers by looping in `MAX_GETRANDOM_LEN`-byte chunks; the per-call
cap bounds the per-call interrupt-off window of the kernel draw (see
[entropy.md](entropy.md) § Draw API and consumers).

---

## Revocation Notes

### `SYS_CAP_REVOKE` targets the caller's own CSpace

`SYS_CAP_REVOKE` takes a capability in the caller's own CSpace and invalidates
all capabilities derived from it, across all processes; the target slot itself is
preserved. It cannot target a capability in a remote process's CSpace directly —
to revoke authority delegated to another process, revoke the intermediary
capability held in the caller's own CSpace.

### Delegating with the "derive twice" pattern

To delegate authority that can later be revoked without losing your own access:

```
1. Hold capability C (the original)
2. Derive C1 from C — you retain C1 as an intermediary
3. Derive C2 from C1 — C2 is the delegated capability
4. Transfer C2 to the child process via SYS_CAP_COPY or IPC
5. To revoke: call SYS_CAP_REVOKE(C1) — destroys every descendant of C1,
   including C2. You still hold C and C1, ready to re-delegate.
```

This pattern works because revocation is subtree-local: revoking C1 removes C1's
descendants (including C2) but leaves C1 itself, C, and any other children of C
intact (see [capability-internals.md](capability-internals.md) § Safe Delegation: the
"Derive Twice" Pattern).

---

## Atomicity and Preemption Guarantees

- **Capability transfer is all-or-nothing at commit.** Either every capability's
  move begins with the message or none does. A refusal that arises after the sender
  blocked delivers the message with zero capabilities, and the sender keeps them (see
  [ipc-design.md](../../../docs/ipc-design.md) § Message Format). The per-capability
  outcomes of a move batched after commit are specified in
  [capability-internals.md](capability-internals.md) § Move.

- **Capability operations complete before a successful return.** Derivation, deletion, and
  revocation each complete fully before the syscall returns success; the `Interrupted` and
  `InvalidState` returns of `SYS_CAP_DELETE` and `SYS_CAP_REVOKE` leave the work partially
  done (see those sections). A revocation that affects capabilities in other processes
  completes before `SYS_CAP_REVOKE` returns success; a large revocation proceeds in bounded
  batches, so other CPUs can observe not-yet-revoked descendants (still usable) mid-syscall —
  the fully revoked state is guaranteed only at a successful return (see
  [capability-internals.md](capability-internals.md) § Revocation Algorithm).

- **Memory mapping operations are atomic with respect to the address space.** After
  `SYS_MEM_MAP`, `SYS_MEM_UNMAP`, or `SYS_MEM_PROTECT` returns, every CPU observes the
  updated mapping on its next access. Rewrites that could leave a dangerous stale entry (unmap,
  permission narrowing, frame replacement) complete a synchronous cross-CPU TLB
  shootdown before returning; fresh maps and permission widenings instead rely on the
  page-fault handler's spurious-fault retry, which re-walks the live page table on
  first remote access (see [memory-internals.md](memory-internals.md) § SMP TLB Shootdown).
  Either way the end state is coherent before the access completes.

- **Syscalls are not preempted.** Syscall context runs with interrupts masked.
  Long-running operations (revocation traversal, SMP TLB shootdown waits) proceed in
  bounded batches or in preempt-disabled, interrupt-enabled windows, and re-check
  state between batches (see [scheduling-internals.md](scheduling-internals.md)
  § Lock Hierarchy).

- **Blocking syscalls are interruptible.** Any syscall that can block (`SYS_IPC_CALL`,
  `SYS_IPC_RECV`, `SYS_NOTIFICATION_WAIT`, `SYS_EVENT_RECV`, `SYS_WAIT_SET_WAIT`,
  `SYS_THREAD_SLEEP`) returns `Interrupted` if the calling thread is stopped via `SYS_THREAD_STOP`,
  or is posted an upcall it does not mask (`SYS_THREAD_POST_UPCALL`), unless its wake (a delivery,
  or the elapsed deadline of a sleep or a timed wait) was claimed first. `SYS_IPC_CALL` and
  `SYS_IPC_RECV` queued on an endpoint, `SYS_NOTIFICATION_WAIT`, `SYS_EVENT_RECV`, and
  `SYS_WAIT_SET_WAIT` also return `Interrupted` when the object waited on is destroyed under the
  caller, and `SYS_IPC_CALL` returns it when the receiving thread receives again before replying or
  is destroyed before replying. `SYS_THREAD_START` returns `Interrupted` when its caller is stopped
  while the start waits for the target to settle; nothing is started.

---

## Constants

| Constant | Value | Meaning |
|---|---|---|
| `MSG_DATA_WORDS_MAX` | 64 | Maximum data words per message |
| `MSG_CAP_SLOTS_MAX` | 4 | Maximum capabilities per message |
| `WAIT_TRY_ONCE` | `u64::MAX` | The `timeout_ms` that makes `SYS_IPC_RECV`, `SYS_NOTIFICATION_WAIT`, `SYS_EVENT_RECV`, or `SYS_WAIT_SET_WAIT` a non-blocking try-once |
| `IPC_CALL_TIMEOUT_SHIFT` | 32 | Bit position of `SYS_IPC_CALL`'s `timeout_ms` in its arg 2, above `data_count` |
| `CSPACE_IPC_RECV_RESERVE` | 4 | Free slots every CSpace keeps back from general allocations for IPC capability transfer (§ Error Codes) |
| `CSPACE_SLOTS_PER_PAGE` | 56 | Capability slots one donated CSpace slot page backs |
| `CSPACE_BODIES_PER_PAGE` | 31 | Capability bodies one page of a CSpace's body arena holds |
| `IOPORT_BINDING_TABLE_PAGES` | 3 | Most CSpace growth-budget pages a thread's first `ioport_bind` takes for its port-binding table |
| `PRIORITY_MIN` | 1 | Lowest priority a userspace thread may be assigned (0 is the idle band) |
| `PRIORITY_MAX` | 30 | Maximum priority for userspace threads |
| `EVENT_QUEUE_MAX_CAPACITY` | 2^20 | Maximum entries, and maximum death-observer nodes, in an event queue |
| `MAX_THREAD_MEM_COPY` | 4096 | Most bytes one `SYS_THREAD_READ_MEM` or `SYS_THREAD_WRITE_MEM` copies |
| `BOOT_PROTOCOL_VERSION` | 21 | Expected version in `BootInfo.version` |

The values are those of the [`abi/syscall`](../../../abi/syscall/src/lib.rs) and
[`abi/boot-protocol`](../../../abi/boot-protocol/src/lib.rs) crates, which are the
source of truth.

---

## Summarized By

[Kernel Handoff Contract](../../boot/docs/kernel-handoff.md), [core/kernel/README.md](../README.md),
[Architecture Abstraction Layer](arch-interface.md),
[Capability Subsystem Internals](capability-internals.md),
[Kernel Cross-Boundary Disclosure Inventory](cross-boundary-disclosure.md),
[Kernel Entropy Subsystem](entropy.md), [IPC Subsystem Internals](ipc-internals.md),
[Memory Subsystem Internals](memory-internals.md), [Scheduler Internals](scheduler.md),
[SMP Scheduling and Locking Invariants](scheduling-internals.md),
[Thread Lifecycle and Sleep List Invariants](thread-lifecycle-and-sleep.md),
[core/ktest/README.md](../../ktest/README.md),
[Capability Model](../../../docs/capability-model.md),
[Device Management](../../../docs/device-management.md), [IPC Design](../../../docs/ipc-design.md),
[Process Lifecycle](../../../docs/process-lifecycle.md),
[Testing](../../../docs/testing.md),
[runtime/ruststd/README.md](../../../runtime/ruststd/README.md),
[services/drivers/serial/README.md](../../../services/drivers/serial/README.md),
[memmgr Memory Pool](../../../services/memmgr/docs/memory-pool.md),
[Restart Protocol](../../../services/svcmgr/docs/restart-protocol.md),
[shared/syscall/README.md](../../../shared/syscall/README.md)
