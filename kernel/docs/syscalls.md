# Syscall Interface Specification

This document defines the complete syscall ABI for Seraph: calling convention,
entry/exit mechanism, the full syscall table, per-call argument and return
specifications, error codes, and atomicity guarantees.

**Code counterparts:**
- `abi/syscall/` — `SYS_*` constants, `SyscallError` enum, scheduling and message
  constants. This is the binary contract: `#[repr(C)]`, `no_std`, no deps outside
  `core`. Both the kernel and userspace depend on it. Changes here are ABI breaks.
- `shared/syscall/` — Rust wrapper functions for userspace. Thin inline-asm wrappers
  around the abi constants. No stability obligation; internal code reuse only.

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

All other registers are preserved across a syscall. The callee-saved set matches the
System V AMD64 ABI (`rbx`, `rbp`, `r12`–`r15`).

**Return values:**

- `rax`: primary return value. On error, `rax` holds a negative `SyscallError` code.
  On success, `rax` holds the non-negative result (or zero if the call has no result).
- `rdx`: secondary return value, used by calls that return two values (e.g. `ipc_recv`
  returns both a label and a word count). Zero if unused.

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

All other registers are preserved. Callee-saved registers are `s0`–`s11`, `sp`, `ra`
(matching the RISC-V calling convention).

**Return values:** `a0` is the primary return value (negative on error). `a1` is the
secondary return value where applicable.

---

## Syscall Entry and Exit

### x86-64

On `SYSCALL`:
1. `rcx` ← `rip` (return address); `r11` ← `rflags`
2. Transition to CPL 0 with kernel code segment
3. `rsp` ← kernel stack pointer from `RSP0` in the TSS (per-CPU)
4. Kernel saves the user register file (including `rcx` and `r11`) onto the kernel stack
5. Kernel calls `syscall::dispatch(nr=rax, args=[rdi, rsi, rdx, r10, r8, r9])`
6. Kernel writes return values into the saved register frame
7. Kernel restores the user register file
8. `SYSRET` restores `rip` from `rcx`, `rflags` from `r11`, transitions to CPL 3

Interrupts are disabled by `SFMASK` on `SYSCALL` entry (the `IF` bit is cleared).
The kernel re-enables them after saving state and switching to the kernel stack.

### RISC-V

On `ECALL` from U-mode:
1. `sepc` ← `pc` + 4 (return address past the ecall instruction)
2. `sstatus.SPP` ← 0 (was U-mode); `sstatus.SPIE` ← `sstatus.SIE`; `sstatus.SIE` ← 0
3. Execution jumps to `stvec` (the kernel trap handler)
4. Trap handler saves the full user register file to the per-thread trap frame
5. Trap handler checks `scause` — if it is an ecall from U-mode, routes to syscall path
6. Kernel calls `syscall::dispatch(nr=a7, args=[a0..a5])`
7. Kernel writes return values into the saved register frame (`a0`, `a1`)
8. Kernel restores the user register file
9. `SRET` restores `pc` from `sepc`, restores `sstatus.SIE` from `sstatus.SPIE`,
   returns to U-mode (`sstatus.SPP` = 0)

---

## Syscall Numbers

**Authoritative source:** `abi/syscall/src/lib.rs` — the constants defined there
are the single source of truth. This table must match that file exactly.

Syscall numbers are stable ABI. New syscalls are added at the end; existing numbers
are never reassigned or reused.

```
 0  SYS_IPC_CALL              22  SYS_THREAD_EXIT
 1  SYS_IPC_REPLY             23  SYS_THREAD_CONFIGURE
 2  SYS_IPC_RECV              24  SYS_CAP_COPY
 3  SYS_SIGNAL_SEND           25  SYS_CAP_MOVE
 4  SYS_SIGNAL_WAIT           26  SYS_WAIT_SET_ADD
 5  SYS_EVENT_POST            27  SYS_WAIT_SET_REMOVE
 6  SYS_EVENT_RECV            28  SYS_WAIT_SET_WAIT
 7  SYS_CAP_CREATE_ENDPOINT   29  SYS_IRQ_ACK
 8  SYS_CAP_CREATE_SIGNAL     30  SYS_IRQ_REGISTER
 9  SYS_CAP_CREATE_EVENT_Q    31  SYS_CAP_DELETE
10  SYS_CAP_CREATE_THREAD     32  SYS_CAP_INSERT
11  SYS_CAP_CREATE_ASPACE     33  SYS_FRAME_SPLIT
12  SYS_CAP_CREATE_CSPACE     34  SYS_MMIO_MAP
13  SYS_CAP_CREATE_WAIT_SET   35  SYS_IOPORT_BIND
14  SYS_CAP_DERIVE            36  SYS_DMA_GRANT
15  SYS_CAP_REVOKE            37  SYS_THREAD_SET_PRIORITY
16  SYS_MEM_MAP               38  SYS_THREAD_SET_AFFINITY
17  SYS_MEM_UNMAP             39  SYS_THREAD_READ_REGS
18  SYS_MEM_PROTECT           40  SYS_THREAD_WRITE_REGS
19  SYS_THREAD_START          41  SYS_ASPACE_QUERY
20  SYS_THREAD_STOP           42  SYS_IPC_BUFFER_SET
21  SYS_THREAD_YIELD          43  SYS_SYSTEM_INFO
                                44  SYS_SBI_CALL
                                45  SYS_MMIO_SPLIT
                                46  SYS_THREAD_SLEEP
                                47  SYS_THREAD_BIND_NOTIFICATION
                                48  SYS_CAP_DERIVE_TOKEN
```

**Implementation status.** Handlers implemented: 0–9 (IPC, signal, event
queue creation and I/O), 7–8 (endpoint/signal creation), 10–13 (thread,
aspace, cspace, wait set creation), 14–18 (cap management and memory),
21–28 (thread lifecycle, wait set operations), 29–30 (IRQ ACK and
register), 31–36 (cap delete/insert, frame split, MMIO map, ioport bind,
DMA grant), 41–43 (aspace query, ipc buffer set, system info). All other
numbers return `UnknownSyscall`.

---

## Error Codes

All syscalls return one of these error codes on failure. The value is negative in
`rax`/`a0`. Zero and positive values are success.

```rust
#[repr(i64)]
pub enum SyscallError
{
    /// Capability descriptor does not refer to a valid capability.
    InvalidCapability  = -1,
    /// The capability does not have the required rights for this operation.
    AccessDenied       = -2,
    /// An argument value is out of range or otherwise invalid.
    InvalidArgument    = -3,
    /// A required memory allocation failed.
    OutOfMemory        = -4,
    /// The target endpoint has no receiver waiting (non-blocking variant only).
    WouldBlock         = -5,
    /// The event queue is full; the post was rejected.
    QueueFull          = -13,
    /// The referenced object is in a state that does not permit this operation.
    InvalidState       = -7,
    /// The syscall number is not recognised.
    UnknownSyscall     = -8,
    /// The operation was interrupted (e.g. thread stopped while blocked).
    Interrupted        = -9,
    /// A physical address or virtual address argument is not aligned or canonical.
    AlignmentError     = -10,
    /// The requested mapping would exceed the address space's limit.
    AddressSpaceFull   = -11,
    /// DMA was requested on a platform without IOMMU protection, and the caller
    /// did not pass FLAG_DMA_UNSAFE to acknowledge unprotected DMA.
    DmaUnsafe          = -12,
}
```

---

## IPC Syscalls

### `SYS_IPC_CALL` (0)

Send a message to an endpoint and block until a reply is received.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `endpoint_cap` | Send capability to an IPC endpoint |
| 1 | `label` | Message label (opaque word; passed to server as-is) |
| 2 | `data_count` | Number of data words (0–MSG_DATA_WORDS_MAX) |
| 3 | `cap_slots` | Packed descriptor: up to MSG_CAP_SLOTS_MAX caps to transfer |
| 4 | `flags` | Bit 0: extended payload in IPC buffer page (see below) |

`cap_slots` encodes up to `MSG_CAP_SLOTS_MAX` capability descriptors packed into one
word (implementation constant; expected value 4, requiring 16 bits each in a 64-bit
word for up to 4 caps).

**Small messages (fast path):** When `data_count` ≤ `MSG_REGS_DATA_MAX` and
`flags` bit 0 is clear, all data words pass in registers. No memory access occurs
after argument validation.

**Extended payload:** When `flags` bit 0 is set, data words beyond the register
capacity are read from the caller's IPC buffer page (registered via
`SYS_IPC_BUFFER_SET`). The kernel reads directly from that page; no arbitrary pointer
dereference occurs. Reply data beyond register capacity is written to the caller's
IPC buffer page after the server replies.

**Return:**

- `rax`/`a0`: 0 on success; `SyscallError` on failure
- `rdx`/`a1`: reply label (valid on success)

**Capability requirement:** `endpoint_cap` must have Send rights.

**Errors:** `InvalidCapability`, `AccessDenied`, `InvalidArgument` (bad count,
or extended payload requested but IPC buffer page not registered or unmapped),
`Interrupted`.

---

### `SYS_IPC_REPLY` (1)

Send a reply to the caller that issued the most recent `SYS_IPC_RECV` on this thread.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `label` | Reply label |
| 1 | `data_count` | Number of data words (0–MSG_DATA_WORDS_MAX) |
| 2 | `cap_slots` | Capabilities to transfer in the reply (packed descriptors) |
| 3 | `flags` | Bit 0: extended payload in IPC buffer page |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The reply capability is implicit — it is retrieved from the calling thread's
`reply_cap_slot` (a per-thread field outside the CSpace, set at `SYS_IPC_RECV`
time). It is consumed by this syscall whether it succeeds or fails. If no reply
capability is present (i.e. this thread did not receive a call), the syscall
returns `InvalidCapability`.

Extended payload follows the same rules as `SYS_IPC_CALL`: when `flags` bit 0 is
set, data beyond register capacity is read from this thread's IPC buffer page and
written to the original caller's IPC buffer page.

**Capability requirement:** Implicit reply capability from `current_tcb.reply_cap_slot`.

**Errors:** `InvalidCapability` (no pending reply), `InvalidArgument`, `Interrupted`.

---

### `SYS_IPC_RECV` (2)

Wait for a call on an endpoint. Blocks until a caller arrives.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `endpoint_cap` | Receive capability to an IPC endpoint |

**Return:**

- `rax`/`a0`: 0 on success; `SyscallError` on failure
- `rdx`/`a1`: label from the incoming message
- `rsi`/`a2`: token from the sender's endpoint capability (0 if untokened)

Data words up to `MSG_REGS_DATA_MAX` are returned in registers. Extended payload
(when the sender set `flags` bit 0) is written to the receiver's IPC buffer page.
The kernel places a reply capability into a per-thread slot (`reply_cap_slot`);
this capability is retrieved implicitly by `SYS_IPC_REPLY`.

The token is the value attached to the sender's endpoint capability via
`SYS_CAP_DERIVE_TOKEN`. It identifies the caller without a forgeable PID.

**Capability requirement:** `endpoint_cap` must have Receive rights.

**Errors:** `InvalidCapability`, `AccessDenied`, `Interrupted`.

---

### `SYS_SIGNAL_SEND` (3)

OR bits into a signal object. Non-blocking; wakes the waiter if one is present.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `signal_cap` | Signal capability with Signal rights |
| 1 | `bits` | Bitmask to OR into the signal word |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

**Capability requirement:** `signal_cap` must have Signal rights.

**Errors:** `InvalidCapability`, `AccessDenied`, `InvalidArgument` (bits == 0).

---

### `SYS_SIGNAL_WAIT` (4)

Block until at least one bit is set in the signal object, or until the
optional millisecond timeout elapses. Returns and atomically clears the
entire bitmask.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `signal_cap` | Signal capability with Wait rights |
| 1 | `timeout_ms` | `0` = block indefinitely; `>0` = wake after at most `timeout_ms` ms |

**Return:**

- `rax`/`a0`: the bitmask that was set (positive, non-zero) on signal wake;
  `0` on timeout (unambiguous: `signal_send` rejects zero-bit sends, so a
  real wake always carries a non-zero mask). `SyscallError` on failure.

**Capability requirement:** `signal_cap` must have Wait rights.

**Errors:** `InvalidCapability`, `AccessDenied`, `Interrupted`.

---

### `SYS_EVENT_POST` (5)

Append one entry to an event queue. Non-blocking; returns `QueueFull` if at capacity.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `queue_cap` | Event queue capability with Post rights |
| 1 | `payload` | Word-sized payload to append |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

**Capability requirement:** `queue_cap` must have Post rights.

**Errors:** `InvalidCapability`, `AccessDenied`, `QueueFull`.

---

### `SYS_EVENT_RECV` (6)

Wait for and dequeue the next entry from an event queue.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `queue_cap` | Event queue capability with Recv rights |

**Return:**

- `rax`/`a0`: 0 on success; `SyscallError` on failure
- `rdx`/`a1`: dequeued payload word (valid on success)

**Capability requirement:** `queue_cap` must have Recv rights.

**Errors:** `InvalidCapability`, `AccessDenied`, `Interrupted`.

---

## Capability Syscalls

### `SYS_CAP_CREATE_ENDPOINT` (7)

Create a new IPC endpoint. Returns a capability with Send + Receive + Grant rights.

**Arguments:** None (no arguments required).

**Return:**

- `rax`/`a0`: new capability descriptor on success (positive); `SyscallError` on failure

**Errors:** `OutOfMemory` (cannot allocate endpoint object or CSpace slot).

---

### `SYS_CAP_CREATE_SIGNAL` (8)

Create a new signal object. Returns a capability with Signal + Wait rights.

**Arguments:** None.

**Return:** `rax`/`a0`: new capability descriptor on success; `SyscallError` on failure.

**Errors:** `OutOfMemory`.

---

### `SYS_CAP_CREATE_EVENT_QUEUE` (9)

Create a new event queue with a fixed capacity.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `capacity` | Ring buffer capacity in entries (1–EVENT_QUEUE_MAX_CAPACITY) |

**Return:** `rax`/`a0`: new capability descriptor (Post + Recv rights) on success;
`SyscallError` on failure.

**Errors:** `OutOfMemory`, `InvalidArgument` (capacity 0 or exceeds maximum).

---

### `SYS_CAP_CREATE_THREAD` (10)

Create a new thread in an existing address space.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `aspace_cap` | Address space capability (Map rights) for the new thread |
| 1 | `entry` | Virtual address of the thread entry point |
| 2 | `stack_top` | Initial stack pointer |
| 3 | `arg` | Value passed in first argument register |
| 4 | `priority` | Scheduling priority (1–`PRIORITY_MAX`); priorities ≥ `SCHED_ELEVATED_MIN` require a SchedControl capability held by the creating process |

**Return:** `rax`/`a0`: new thread capability (Control rights) on success;
`SyscallError` on failure.

The thread is created in the `Created` state; it does not begin execution until
`SYS_THREAD_START` is called.

**Capability requirement:** `aspace_cap` must have Map rights. Map is intentionally
reused here: a process that can modify an address space's mappings is inherently
trusted to create threads that execute within it.

**Errors:** `InvalidCapability`, `AccessDenied`, `InvalidArgument` (bad entry, stack,
or priority), `OutOfMemory`.

---

### `SYS_CAP_CREATE_ADDRESS_SPACE` (11)

Create a new, empty address space. The kernel's higher-half mapping is shared into
the new address space automatically.

**Arguments:** None.

**Return:** `rax`/`a0`: new address space capability (Map + Read rights) on success;
`SyscallError` on failure.

**Errors:** `OutOfMemory`.

---

### `SYS_CAP_CREATE_WAIT_SET` (13)

Create a new wait set.

**Arguments:** None.

**Return:** `rax`/`a0`: new wait set capability (Modify + Wait rights) on success;
`SyscallError` on failure.

**Errors:** `OutOfMemory`.

---

### `SYS_CAP_DERIVE` (13)

Derive a new capability from an existing one, with equal or fewer rights.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `source_cap` | Source capability descriptor |
| 1 | `rights_mask` | Rights bitmask for the derived capability (subset of source) |

**Return:** `rax`/`a0`: new capability descriptor on success; `SyscallError` on failure.

The derived capability references the same kernel object. The derivation is recorded
in the global derivation tree for revocation tracking.

**Errors:** `InvalidCapability` (source invalid or null), `AccessDenied` (requested
rights exceed those held in source), `OutOfMemory` (no free CSpace slot).

If the source capability has a non-zero token, the derived capability inherits it.

---

### `SYS_CAP_DERIVE_TOKEN` (48)

Derive a new capability with an attached token value.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `source_cap` | Source capability descriptor |
| 1 | `rights_mask` | Rights bitmask for the derived capability (subset of source) |
| 2 | `token` | Token value to attach (must be non-zero) |

**Return:** `rax`/`a0`: new capability descriptor on success; `SyscallError` on failure.

The token is an immutable `u64` value stored in the capability slot. When the
tokened capability is used for IPC (via `SYS_IPC_CALL`), the kernel delivers
the token to the receiver as the third return value of `SYS_IPC_RECV`.

Tokens are generic — any capability type can carry a token, not just endpoints.
For non-endpoint types, the token is stored but not delivered via any kernel
mechanism; userspace can use it for bookkeeping.

The source capability must have `token == 0`. Re-tokening (setting a new token
on an already-tokened cap) returns `InvalidArgument`. Derivation via
`SYS_CAP_DERIVE` inherits the source's token.

**Errors:** `InvalidCapability`, `InvalidArgument` (token is zero or source
already tokened), `OutOfMemory`.

---

### `SYS_CAP_REVOKE` (14)

Revoke a capability and all capabilities derived from it, across all processes.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `cap` | Capability to revoke |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The capability itself is invalidated, as are all descendants in the derivation tree.
The underlying kernel object is not freed unless this was the last reference to it.

**Errors:** `InvalidCapability`.

---

### `SYS_CAP_DELETE` (15)

Delete a single capability from the caller's CSpace. Does not affect derived capabilities.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `cap` | Capability descriptor to delete |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

If this is the last reference to the underlying object, the object is freed.

**Errors:** `InvalidCapability`.

---

## Memory Syscalls

### `SYS_MEM_MAP` (16)

Map pages from a physical frame capability into an address space.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `frame_cap` | Frame capability (Map rights) |
| 1 | `aspace_cap` | Address space capability (Map rights) |
| 2 | `virt` | Virtual address to map at (page-aligned, user range) |
| 3 | `offset_pages` | Page offset into the frame |
| 4 | `page_count` | Number of pages to map (nonzero) |
| 5 | `prot_bits` | Protection bits: bit 1 = WRITE, bit 2 = EXECUTE. If zero, derived from frame cap rights |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

If `prot_bits` is nonzero, the requested permissions must be a subset of the frame
cap's rights. W^X is enforced: WRITE and EXECUTE may not both be set.

If `prot_bits` is zero, permissions are derived from the frame cap's rights directly.
This fails with `WxViolation` if the frame cap has both WRITE and EXECUTE rights.

**Capability requirements:** `frame_cap` (Map), `aspace_cap` (Map).

**Errors:** `InvalidCapability`, `InsufficientRights` (requested prot exceeds cap
rights), `WxViolation` (both WRITE and EXECUTE requested), `InvalidArgument`
(unaligned `virt`, non-canonical address, zero page count, or offset beyond frame),
`OutOfMemory` (page table allocation failure).

---

### `SYS_MEM_UNMAP` (17)

Remove a mapping from an address space.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `aspace_cap` | Address space capability (Map rights) |
| 1 | `virt` | Virtual address to unmap (page-aligned) |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The physical frame is not freed — only the virtual mapping is removed. The frame
capability continues to exist. TLB shootdowns are performed on all CPUs running
threads in `aspace_cap`.

**Capability requirement:** `aspace_cap` must have Map rights.

**Errors:** `InvalidCapability`, `AccessDenied`, `InvalidArgument` (address not
mapped or unaligned).

---

### `SYS_MEM_PROTECT` (18)

Change the permission flags on an existing mapping without altering the physical address.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `aspace_cap` | Address space capability (Map rights) |
| 1 | `virt` | Virtual address of the mapping (page-aligned) |
| 2 | `flags` | New permission flags |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

W^X is enforced on the new flags. The caller cannot grant rights beyond what the
frame capability allows (but the frame capability is not re-checked here — the kernel
records the maximum rights at map time).

**Capability requirement:** `aspace_cap` must have Map rights.

**Errors:** `InvalidCapability`, `AccessDenied` (W^X violation or rights exceed
initial mapping rights), `InvalidArgument` (address not mapped).

---

### `SYS_FRAME_SPLIT` (33)

Split a frame capability at a page boundary, producing two frame capabilities that
together cover the same physical range as the original. The original capability is
consumed.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `frame_cap` | Frame capability to split |
| 1 | `offset_pages` | Page offset within the frame at which to split |

**Return:**

- `rax`/`a0`: capability descriptor for the lower portion (pages 0..offset_pages)
  on success; `SyscallError` on failure
- `rdx`/`a1`: capability descriptor for the upper portion (pages offset_pages..end)
  on success

The original `frame_cap` is consumed by this call. Both halves inherit the same
rights as the original. The derivation tree treats both halves as children of the
original's position.

`offset_pages` MUST be in the range [1, frame_size_pages − 1].

**Errors:** `InvalidCapability`, `InvalidArgument` (offset out of range or frame
is already a single page), `OutOfMemory` (no free CSpace slot for second cap).

---

### `SYS_MMIO_MAP` (34)

Map an MMIO region capability into an address space. MMIO mappings use uncacheable
page attributes (`PAT` write-combine or uncacheable on x86-64; device-ordered on
RISC-V) rather than the default writeback caching.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `aspace_cap` | Address space capability (Map rights) |
| 1 | `mmio_cap` | MMIO region capability (Map rights) |
| 2 | `virt` | Virtual address to map at (page-aligned) |
| 3 | `flags` | Mapping flags: readable, writable (not executable; MMIO is never XP) |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

MMIO mappings are never executable. The kernel forces the uncacheable attribute
regardless of the flags value; callers MUST NOT set both writable and executable.

**Capability requirements:** `aspace_cap` (Map), `mmio_cap` (Map).

**Errors:** `InvalidCapability`, `AccessDenied`, `InvalidArgument` (unaligned
`virt`, W^X violation, or non-canonical address), `AlignmentError`,
`AddressSpaceFull`.

---

### `SYS_DMA_GRANT` (36)

Return the physical address of a frame for use as a DMA buffer. Currently implements
the no-IOMMU fallback path only; full IOMMU support is deferred.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `frame_cap` | Frame capability (Map rights) to grant DMA access to |
| 1 | `device_id` | Reserved; pass 0. |
| 2 | `flags` | MUST include `FLAG_DMA_UNSAFE` (bit 2) to acknowledge no hardware isolation. |

**Return:** `rax`/`a0`: physical base address of the frame on success;
`SyscallError` on failure.

Without an IOMMU the granting device can access the entire physical frame without
hardware-enforced isolation. The caller MUST set `FLAG_DMA_UNSAFE` (bit 2 of
`flags`) to acknowledge this; if absent, `DmaUnsafe` is returned.

**Capability requirements:** `frame_cap` (Map rights).

**Errors:** `InvalidCapability`, `DmaUnsafe` (FLAG_DMA_UNSAFE not set).

---

## Thread and Process Syscalls

### `SYS_THREAD_START` (19)

Transition a thread from `Created` state to `Ready` and enqueue it for scheduling.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Control rights) |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

**Capability requirement:** `thread_cap` must have Control rights.

**Errors:** `InvalidCapability`, `AccessDenied`, `InvalidState` (thread not in
Created state).

---

### `SYS_THREAD_STOP` (20)

Stop a running or runnable thread. The thread transitions to `Stopped` state.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Control rights) |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

If the thread is blocked on IPC, the block is cancelled (the blocked syscall on the
target thread returns `Interrupted`). If the thread is running on another CPU, an
inter-processor interrupt is sent to force it out of userspace.

**Capability requirement:** `thread_cap` must have Control rights.

**Errors:** `InvalidCapability`, `AccessDenied`, `InvalidState` (thread already stopped
or exited).

---

### `SYS_THREAD_YIELD` (21)

Voluntarily yield the remainder of the current thread's time slice.

**Arguments:** None.

**Return:** `rax`/`a0`: always 0.

The calling thread remains `Ready` and is re-enqueued at its current priority. No
capability is required — this syscall acts on the calling thread implicitly.

---

### `SYS_THREAD_EXIT` (23)

Exit the calling thread. The thread's TCB is freed and another thread is scheduled.
This is the correct way for any thread to terminate itself, including init.

**Arguments:** None.

**Return:** Does not return.

**Errors:** None (this syscall cannot fail).

---

### `SYS_THREAD_SET_PRIORITY` (37)

Change a thread's scheduling priority after creation.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Control rights) |
| 1 | `priority` | New priority (1–`PRIORITY_MAX`) |
| 2 | `sched_cap` | SchedControl capability (Elevate rights); use 0 if not needed |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The priority range is divided into two tiers:

- **Normal range (1–20):** `sched_cap` is ignored. Any holder of the thread's
  Control capability may set priorities freely in this range.
- **Elevated range (21–30):** `sched_cap` MUST be a valid SchedControl capability
  with Elevate rights. Without it, the call returns `AccessDenied`.

Priority 0 (idle) and priority 31 (reserved) cannot be requested. The change takes
effect at the next scheduler invocation.

**Capability requirements:** `thread_cap` (Control rights); `sched_cap` (Elevate
rights) when `priority` ≥ `SCHED_ELEVATED_MIN`.

**Errors:** `InvalidCapability`, `AccessDenied` (insufficient rights for the
requested priority tier), `InvalidArgument` (priority 0, priority 31, or out
of range).

---

### `SYS_THREAD_SET_AFFINITY` (38)

Set or change a thread's CPU affinity.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Control rights) |
| 1 | `cpu_id` | Target CPU ID, or `AFFINITY_ANY` (u32::MAX) to clear affinity |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

Setting a hard affinity prevents future migration by the load balancer. The thread
is migrated to the target CPU at the next scheduler invocation if not already there.
If `cpu_id` names an offline CPU, the call fails with `InvalidArgument`.

**Capability requirement:** `thread_cap` MUST have Control rights.

**Errors:** `InvalidCapability`, `AccessDenied`, `InvalidArgument` (CPU offline or
out of range).

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

The thread MUST be in `Stopped` state. The buffer receives an architecture-defined
register file structure (layout published in the kernel ABI headers). If `buf_size`
is smaller than the required size, the call fails with `InvalidArgument`.

**Capability requirement:** `thread_cap` MUST have Observe rights.

**Errors:** `InvalidCapability`, `AccessDenied`, `InvalidState` (thread not stopped),
`InvalidArgument` (buffer too small or invalid pointer).

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

The thread MUST be in `Stopped` state. The kernel validates that the register values
are safe (e.g. the instruction pointer is in a canonical range; privilege bits cannot
be set).

**Capability requirement:** `thread_cap` MUST have Control rights.

**Errors:** `InvalidCapability`, `AccessDenied`, `InvalidState` (thread not stopped),
`InvalidArgument` (buffer wrong size, invalid pointer, or illegal register values).

---

## Wait Set Syscalls

### `SYS_WAIT_SET_ADD` (26)

Add an IPC primitive to a wait set.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `wait_set_cap` | Wait set capability (Modify rights) |
| 1 | `source_cap` | Capability to an endpoint, signal, or event queue |
| 2 | `token` | Opaque u64 returned to the caller when this source is ready |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The `token` is chosen by the caller to identify the source in a subsequent
`SYS_WAIT_SET_WAIT` result. The kernel does not interpret it.

**Capability requirements:** `wait_set_cap` (Modify), `source_cap` (at least one of
Receive/Wait/Recv rights on the source).

**Errors:** `InvalidCapability`, `AccessDenied`, `OutOfMemory`.

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

**Errors:** `InvalidCapability`, `AccessDenied`, `InvalidArgument` (source not in
this wait set).

---

### `SYS_WAIT_SET_WAIT` (28)

Block until any member of the wait set becomes ready.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `wait_set_cap` | Wait set capability (Wait rights) |

**Return:**

- `rax`/`a0`: 0 on success; `SyscallError` on failure
- `rdx`/`a1`: token of the ready source (valid on success)

Only one ready source is returned per call (wake-one semantics). If multiple sources
are ready simultaneously, subsequent calls return them without blocking.

**Capability requirement:** `wait_set_cap` must have Wait rights.

**Errors:** `InvalidCapability`, `AccessDenied`, `Interrupted`.

---

## Interrupt Syscalls

### `SYS_IRQ_ACK` (29)

Acknowledge a hardware interrupt line after handling. Re-enables the line at the
interrupt controller.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `irq_cap` | Interrupt capability for the line to acknowledge |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The kernel masks the interrupt line before delivering the notification to the driver
(see [docs/architecture.md](../../docs/architecture.md) — Driver Model). The driver
must call `SYS_IRQ_ACK` to re-enable the line. Calling `SYS_IRQ_ACK` without a
prior interrupt delivery has no effect.

**Capability requirement:** `irq_cap` MUST be a valid interrupt capability for the
specific line.

**Errors:** `InvalidCapability`, `AccessDenied`.

---

### `SYS_IRQ_REGISTER` (30)

Register a signal to receive interrupt notifications for a hardware interrupt line.
When the interrupt fires, the kernel delivers it by ORing a notification bit into
the registered signal.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `irq_cap` | Interrupt capability for the line to register |
| 1 | `signal_cap` | Signal capability (Signal rights) to notify on interrupt |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

Only one signal may be registered per interrupt line at a time. A second call
replaces the previous registration. The kernel masks the interrupt line before
delivering the notification; the driver MUST call `SYS_IRQ_ACK` to re-enable it.

**Capability requirements:** `irq_cap` (valid interrupt capability), `signal_cap`
(Signal rights).

**Errors:** `InvalidCapability`, `AccessDenied`.

---

### `SYS_IOPORT_BIND` (35)

Bind an IoPortRange capability to a thread, granting that thread permission to
execute `in`/`out` instructions for the capability's port range via the TSS I/O
Permission Bitmap (IOPB).

**x86-64 only.** On RISC-V this syscall returns `NotSupported`.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Control rights) |
| 1 | `ioport_cap` | IoPortRange capability (Use rights) |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

Multiple bindings may be made to the same thread, each authorising a different port
range. When `ioport_cap` is revoked, port access is removed from all threads it has
been bound to; access is always revocable.

**Capability requirements:** `thread_cap` (Control rights), `ioport_cap` (Use rights).

**Errors:** `InvalidCapability`, `AccessDenied`, `UnknownSyscall` (RISC-V).

---

## Thread Configuration Syscalls

### `SYS_THREAD_CONFIGURE` (23)

Bind a thread to an AddressSpace, CSpace, and IPC buffer. Must be called before
`SYS_THREAD_START`. Replaces the previous bindings if called on a stopped thread.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `thread_cap` | Thread capability (Control rights) |
| 1 | `aspace_cap` | AddressSpace capability (Map rights) to bind |
| 2 | `cspace_cap` | CSpace capability (Insert + Delete rights) to bind |
| 3 | `ipc_buf_vaddr` | Virtual address of the IPC buffer page in the thread's address space (0 to clear) |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

All three bindings are updated atomically. The thread must be in the Stopped or
Created state; calling on a Running or Blocked thread returns `InvalidState`.

**Capability requirements:** `thread_cap` (Control), `aspace_cap` (Map),
`cspace_cap` (Insert + Delete).

**Errors:** `InvalidCapability`, `AccessDenied`, `InvalidState` (thread not stopped),
`InvalidArgument` (ipc_buf_vaddr not page-aligned).

---

### `SYS_CAP_CREATE_CSPACE` (12)

Create a new, empty CSpace.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `max_slots` | Maximum number of capability slots (ceiling; 0 means system default) |

**Return:** `rax`/`a0`: new CSpace capability (Insert + Delete + Derive + Revoke rights)
on success; `SyscallError` on failure.

**Errors:** `InvalidArgument` (max_slots exceeds system maximum), `OutOfMemory`.

---

## Cross-CSpace Syscalls

### `SYS_CAP_COPY` (25)

Copy a capability from the caller's CSpace into another CSpace, creating a new
derivation tree node (child of the source slot).

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `src_cap` | Capability to copy (source slot in caller's CSpace) |
| 1 | `dst_cspace_cap` | Target CSpace capability (Insert rights) |
| 2 | `dst_slot` | Destination slot index in the target CSpace |
| 3 | `rights_mask` | Rights for the copy (must be subset of source rights) |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The copy is a derivation (child of `src_cap` in the tree). Both the original and
the copy remain valid. Used by init to delegate capabilities to services.

**Capability requirements:** `src_cap` (at least one right), `dst_cspace_cap` (Insert).

**Errors:** `InvalidCapability`, `AccessDenied`, `InvalidArgument` (dst_slot occupied
or out of range), `OutOfMemory`.

---

### `SYS_CAP_MOVE` (26)

Move a capability from the caller's CSpace into another CSpace. Transfer semantics:
the source slot is cleared; the destination inherits the source's derivation position.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `src_cap` | Capability to move (source slot in caller's CSpace) |
| 1 | `dst_cspace_cap` | Target CSpace capability (Insert rights) |
| 2 | `dst_slot` | Destination slot index in the target CSpace |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

**Capability requirements:** `src_cap` (any), `dst_cspace_cap` (Insert).

**Errors:** `InvalidCapability`, `AccessDenied`, `InvalidArgument` (dst_slot occupied
or out of range).

---

### `SYS_CAP_INSERT` (31)

Insert a derived copy of a capability from the caller's CSpace into another CSpace.
Like `SYS_CAP_COPY` but uses a CSpace capability directly for the destination.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `cspace_cap` | CSpace capability (Insert rights) for the target CSpace |
| 1 | `source_cap` | Capability to copy |
| 2 | `dest_slot` | Slot index in the target CSpace |
| 3 | `rights_mask` | Rights for the inserted capability (subset of source rights) |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

Used by init to populate new service CSpaces before starting their threads.

**Capability requirements:** `cspace_cap` (Insert), `source_cap` (at least one right).

**Errors:** `InvalidCapability`, `AccessDenied` (requested rights exceed source rights,
or dest_slot is already occupied), `InvalidArgument` (dest_slot out of range or
exceeds CSpace ceiling), `OutOfMemory`.

---

## Address Space Syscall

### `SYS_ASPACE_QUERY` (41)

Query the mapping at a virtual address in an address space.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `aspace_cap` | Address space capability (Read rights) |
| 1 | `virt` | Virtual address to query (page-aligned) |
| 2 | `buf_ptr` | Pointer to a buffer to receive mapping info |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The buffer receives an architecture-neutral mapping descriptor: physical address,
page size, and permission flags. If `virt` is not mapped, the call fails with
`InvalidArgument`. Layout is defined in the kernel ABI headers.

**Capability requirement:** `aspace_cap` must have Read rights.

**Errors:** `InvalidCapability`, `AccessDenied`, `InvalidArgument` (address not
mapped, unaligned, or non-canonical).

---

## IPC Buffer Syscall

### `SYS_IPC_BUFFER_SET` (41)

Register the per-thread IPC buffer page. This is the page the kernel uses for
extended IPC payloads (when `flags` bit 0 is set in `SYS_IPC_CALL` or
`SYS_IPC_REPLY`).

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `virt` | Page-aligned virtual address of the IPC buffer page |

**Return:** `rax`/`a0`: 0 on success; `SyscallError` on failure.

The page at `virt` must already be mapped in the calling thread's address space with
at least read+write permissions. The kernel records the address in the calling
thread's TCB. The page must remain mapped for the duration of any IPC that uses it;
if the page is unmapped when an extended IPC is attempted, the IPC syscall returns
`InvalidArgument`.

Calling `SYS_IPC_BUFFER_SET` again replaces the previous registration. Passing 0
deregisters the IPC buffer page (extended payloads will fail with `InvalidArgument`).

**Capability requirement:** None — acts on the calling thread implicitly.

**Errors:** `AlignmentError` (virt not page-aligned), `InvalidArgument` (page not
mapped or not writable; checked at registration time).

---

## System Info Syscalls

### `SYS_SYSTEM_INFO` (43)

Query a scalar system value. Returns a single `u64` in `rax`/`a0` — no buffer required.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `info_type` | Which value to query (see `SystemInfoType` below) |
| 1 | _(unused)_ | Must be 0 |

**Return:** `rax`/`a0`: the queried value on success; negative `SyscallError` on failure.

**Capability requirement:** None.

**Errors:** `InvalidArgument` (unknown `info_type`).

### `SystemInfoType`

```rust
#[repr(u64)]
pub enum SystemInfoType
{
    /// Kernel version packed as `(major as u64) << 32 | (minor as u64) << 16 | patch`.
    ///
    /// Semver semantics: major=breaking ABI change, minor=new syscalls added,
    /// patch=bug fix. Major is 0 while the kernel ABI is pre-stable and
    /// may change freely between any releases.
    ///
    /// Userspace extracts components with:
    ///   major = version >> 32
    ///   minor = (version >> 16) & 0xFFFF
    ///   patch = version & 0xFFFF
    KernelVersion       = 0,

    /// Number of logical CPUs initialised at boot.
    CpuCount            = 1,

    /// Number of free 4 KiB physical frames at the time of the call.
    FreeFrames          = 2,

    /// Total number of 4 KiB physical frames detected at boot (fixed after boot).
    /// `FreeFrames / TotalFrames` gives current memory pressure.
    TotalFrames         = 3,

    /// Size of a physical page in bytes (always 4096 on supported platforms).
    PageSize            = 4,

    /// Boot protocol version used by the bootloader (see `abi/boot-protocol`).
    /// Userspace can use this to interpret fields in the boot info struct.
    BootProtocolVersion = 5,
}
```

---

### `SYS_ASPACE_QUERY` (41)

Translate a user virtual address to its mapped physical address.

**Arguments:**

| # | Name | Description |
|---|---|---|
| 0 | `aspace_cap` | AddressSpace cap slot (must have `READ` right) |
| 1 | `virt` | Page-aligned virtual address to translate (user half only) |

**Return:** `rax`/`a0`: the mapped physical address on success; negative `SyscallError` on failure.

**Capability requirement:** `READ` right on the AddressSpace cap.

**Errors:**
- `InvalidAddress` — `virt` is not page-aligned, outside the user half (`>= 0x0000_8000_0000_0000`), or not currently mapped.
- `InvalidCapability` — cap slot is null, wrong type, or object is gone.
- `InsufficientRights` — cap does not have `READ` right.

---

## Revocation Notes

### `SYS_CAP_REVOKE` targets the caller's own CSpace

`SYS_CAP_REVOKE` invalidates the capability in the caller's own CSpace slot and
all capabilities derived from it, across all processes. It cannot target a
capability in a remote process's CSpace directly — to revoke authority delegated to
another process, revoke the intermediary capability held in the caller's own CSpace.

### Delegating with the "derive twice" pattern

To delegate authority that can later be revoked without losing your own access:

```
1. Hold capability C (the original)
2. Derive C1 from C — you retain C1 as an intermediary
3. Derive C2 from C1 — C2 is the delegated capability
4. Transfer C2 to the child process via SYS_CAP_INSERT or IPC
5. To revoke: call SYS_CAP_REVOKE(C1) — destroys C1 and C2
   You still hold C with full rights.
```

This pattern works because revocation is subtree-local: revoking C1 removes C1 and
all its descendants (including C2) but leaves C and any other children of C intact.

---

## Atomicity and Preemption Guarantees

- **IPC message delivery is atomic.** A message either fully transfers (including all
  capability slots) or does not transfer at all. There is no partial delivery.

- **Capability operations are atomic.** Derivation, deletion, and revocation each
  complete fully before the syscall returns. A revocation that affects capabilities
  in other processes completes before `SYS_CAP_REVOKE` returns.

- **Memory mapping operations are atomic with respect to the address space.** After
  `SYS_MEM_MAP` or `SYS_MEM_UNMAP` returns, all CPUs see the updated mapping (TLB
  shootdowns complete before return).

- **Syscalls may be preempted.** Long-running operations (revocation traversal, SMP
  TLB shootdowns) may be interrupted by a higher-priority runnable thread. The kernel
  uses appropriate locks and re-checks state on resumption to ensure correctness.

- **Blocking syscalls are interruptible.** Any syscall that can block (`SYS_IPC_CALL`,
  `SYS_IPC_RECV`, `SYS_SIGNAL_WAIT`, `SYS_EVENT_RECV`, `SYS_WAIT_SET_WAIT`) returns
  `Interrupted` if the calling thread is stopped via `SYS_THREAD_STOP`.

---

## Constants

| Constant | Value | Meaning |
|---|---|---|
| `MSG_DATA_WORDS_MAX` | TBD (≥4) | Maximum data words per message |
| `MSG_CAP_SLOTS_MAX` | 4 | Maximum capabilities per message |
| `PRIORITY_DEFAULT` | 10 | Default priority for newly created threads |
| `SCHED_ELEVATED_MIN` | 21 | First priority level requiring SchedControl capability |
| `PRIORITY_MAX` | 30 | Maximum priority for userspace threads |
| `FLAG_DMA_UNSAFE` | bit 2 | `SYS_DMA_GRANT` flag acknowledging unprotected DMA |
| `EVENT_QUEUE_MAX_CAPACITY` | 4096 | Maximum entries in an event queue |
| `BOOT_PROTOCOL_VERSION` | 2 | Expected version in `BootInfo.version` |

`MSG_DATA_WORDS_MAX` is fixed at implementation time. A value of 4–8 words balances
message capacity against syscall overhead. The exact value becomes stable ABI.

---

## Summarized By

None
