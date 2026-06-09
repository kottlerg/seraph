# Capability Model

Capabilities are the sole access control mechanism in Seraph.

- Every kernel-managed resource is represented by a capability.
- A process MUST NOT operate on a resource without a valid capability authorising
  that operation.
- The kernel MUST enforce capability checks on every resource operation.
- The system MUST NOT provide ambient authority or identity-based privilege.
- A resource MUST NOT be accessible by naming or guessing an identifier without
  holding the corresponding capability.

---

## Capability Spaces

Each process has a **capability space** (CSpace): a collection of capability slots.
Slots are referenced by integer index — a capability descriptor. A slot is either
empty (the null capability) or holds one capability referencing a kernel object and
its associated rights.

The CSpace has the following properties:
- **Grows on demand** — starts small and expands as slots are needed
- **Stable indices** — a capability descriptor remains valid for the lifetime of
  the capability; the kernel never moves or renumbers existing slots
- **O(1) lookup** — descriptor-to-capability resolution MUST be O(1)
- **Per-process ceiling** — each process has a maximum CSpace size enforced by the
  kernel

Slot 0 is permanently null and cannot be written — using index 0 always means "no
capability".

---

## Capability Handle Format

A capability handle — the value userspace passes to and receives from the kernel —
packs a per-slot **generation** with the slot index:

```
handle = (generation << CAP_INDEX_BITS) | index      // CAP_INDEX_BITS = 24
```

The low 24 bits are the slot index; the high 8 bits are the slot's generation
counter, which the kernel increments each time the slot is freed and recycled. On
every operation the kernel checks the handle's generation against the slot's
current generation and returns `InvalidCapability` on mismatch. This closes the
stale-slot alias class (#349): a handle held across a free/reallocate of its slot
fails closed instead of silently operating on whatever unrelated capability now
occupies the index.

A never-recycled slot has generation 0, so its handle is numerically identical to
the bare slot index. Long-lived capabilities minted once at boot or process spawn
(the `ProcessInfo`/`InitInfo`/`CapDescriptor` handover caps) therefore keep their
historical handle values, and the `handle == 0` "no capability" sentinel still
holds (a live cap always has index ≥ 1 in the low bits).

The handle is `u32`-wide and travels in the low half of a 64-bit syscall register.
Capabilities transferred over IPC, and the second child of a range split, are
delivered with their generation intact (the split delivers its two children in the
two return registers rather than packing them into one). The handle's generation
is **not** carried on the IPC *send* path (the packed send slots are index-only):
a cap named for transfer is identified by index alone, so a sender naming a stale,
recycled handle transmits the slot's current occupant rather than failing closed —
the one resolution path the generation check does not cover (#349), no worse than
the pre-generation behaviour and tightenable by widening the send pack. The cap the
recipient *receives* is generation-correct: the kernel re-derives it from the
freshly inserted destination slot.

---

## Capability Types

Each capability type represents a distinct kind of kernel object. The rights attached
to a capability are type-specific.

### Memory

A capability to one or more contiguous physical frames. Rights:
- **Map** — may map these frames into an address space
- **Write** — authority to create writable mappings
- **Execute** — authority to create executable mappings
- **Retype** — authority to consume bytes of this Memory's region as the
  backing storage for a newly created kernel object (see
  [Typed Memory](#typed-memory))

A capability may carry both Write and Execute rights, representing independent
authorities over the same physical memory. W^X is enforced at mapping time: the
kernel rejects any `mem_map` or `mem_protect` call that would make a page
simultaneously writable and executable.

The kernel mints Memory caps for all usable RAM at boot with `Map | Write |
Execute | Retype` and places them in init's CSpace. Memory caps minted for
firmware tables (ACPI regions, RSDP, DTB), boot modules, and init's own
ELF segments mint without `Retype` — they are mappable read-only references
to fixed-purpose memory and cannot be consumed for kernel-object creation.

Init transfers RAM Memory caps (via the derive-twice pattern) to memmgr, which
thereafter owns userspace RAM frame allocation and answers `REQUEST_MEMORY_CAPS`
for every std-built service. See
[`userspace-memory-model.md`](userspace-memory-model.md) and
[`services/memmgr/README.md`](../services/memmgr/README.md). MMIO Memory caps
follow a separate flow through devmgr; see
[`device-management.md`](device-management.md).

### Address Space

A capability to a process's virtual address space. Rights:
- **Map** — may install and remove mappings in this address space
- **Read** — may inspect current mappings

The kernel holds implicit authority over all address spaces; this capability is
what allows userspace memory managers to manage mappings on behalf of a process.

### IPC Endpoint

A capability to an IPC endpoint. Rights:
- **Send** — may call this endpoint (synchronous IPC, caller blocks for reply)
- **Receive** — may accept calls on this endpoint (held only by the server)
- **Grant** — may include capabilities in the message's capability slots

A send capability without grant right cannot pass capabilities to the server.
A server that should not receive unexpected resources from clients holds a receive
capability without grant on its own endpoint.

An endpoint may additionally be designated a thread's **fault handler** — a protocol
specified in [Fault Handling](fault-handling.md) (not yet implemented), with no distinct
fault-endpoint capability type: the kernel delivers that thread's unresolvable faults to
the bound endpoint.

### Notification

A capability to a notification object (bitmask-based async notification). Rights:
- **Notification** — may OR bits into the notification word (deliver notifications)
- **Wait** — may wait on this notification object and read the bitmask

### Event Queue

A capability to an event queue (ordered ring buffer). Rights:
- **Post** — may append an entry to the queue
- **Recv** — may wait on and read entries from the queue

### Interrupt

A capability granting the right to handle a specific hardware interrupt line.
The holder registers an endpoint to receive interrupt notifications on that line.
Interrupt capabilities are created by the kernel at boot and initially granted to
init, which delegates them to appropriate drivers.

### Mmio

A capability to a specific physical address range (an MMIO aperture) used for
memory-mapped I/O. Holding this capability allows mapping the region into an
address space (with Map right). Without this capability a process cannot map
physical addresses — it cannot name hardware it has not been granted access to.

### Thread

A capability to a thread. Rights:
- **Control** — may start, stop, and configure the thread
- **Observe** — may read the thread's register state (for debugging)

### CSpace

A capability to a capability space. Rights:
- **Insert** — may place a new capability into a slot
- **Delete** — may clear a slot
- **Derive** — may derive a new capability from an existing slot
- **Revoke** — may revoke a capability and all its descendants

CSpace capabilities are used when configuring a new thread (binding a CSpace to
the thread) and when cross-CSpace capability operations are needed (e.g. init
populating a new process's CSpace before handing it off).

### Wait Set

A capability to a wait set (see IPC design). Rights:
- **Modify** — may add or remove members
- **Wait** — may block on the wait set

### IoPort (x86-64 only)

A capability to a contiguous range of x86 I/O port numbers. Rights:
- **Use** — may bind this port range to a thread, allowing that thread to execute
  `in`/`out` instructions for those ports without a syscall

IoPort capabilities are created at boot from `IoPort` entries in the
boot-provided `platform_resources`. They are not creatable at runtime. A driver
that needs port I/O access receives a derived IoPort capability from init
(via devmgr), covering only its assigned port range.

Revoking an IoPort capability removes port access from all threads it has
been bound to. The kernel tracks bindings and updates each affected thread's IOPB
in the TSS on revocation.

### SbiControl (RISC-V only)

A capability authorising the holder to forward a *sanctioned* Supervisor Binary
Interface (SBI) extension to M-mode firmware via `SYS_SBI_CALL`. RISC-V only; it
does not exist on x86-64 (no SBI concept).

Authority is **per extension**, expressed as rights rather than a numeric range —
SBI extension IDs are sparse and non-numeric, so the cap does not join the
range-authority family and has no split/merge. Each sanctioned extension has its
own right:
- **Reset** — forward System Reset (SRST).
- **Suspend** — forward System Suspend (SUSP).
- **Cppc** — forward processor performance control (CPPC).
- **Base** — forward the read-only Base extension (version / extension probe).
- **Dbcn** — forward the Debug Console extension.
- **Pmu** — forward the Performance Monitoring Unit extension.

`SYS_SBI_CALL` maps the requested extension ID to the right it requires and
rejects the call with `InsufficientRights` unless the cap carries that right.

**Kernel floor.** The kernel hard-denies exactly one class, regardless of cap
(`InvalidArgument`): the extensions it manages internally — TIME (scheduler
timer), IPI (TLB shootdown / wakeups), RFENCE (remote fences), HSM (hart
lifecycle). These have no right and are absent from the vocabulary; forwarding
them from userspace would break a kernel invariant — halt a hart, corrupt TLB
coherence, or derail scheduling. The kernel draws the line at *soundness* only;
it does not encode preference about which otherwise-harmless extensions
userspace "should" use.

**Distribution is policy, not kernel enforcement.** Every non-reserved extension
is sanctioned with a right, but a holder can only forward an extension whose
right its cap actually carries — so what userspace may do is set by which caps
are handed out, by ordinary minimum-privilege distribution (`cap_derive`, which
only narrows rights, never widens; there is no dedicated SBI split operation).

The kernel mints the root cap once at boot, carrying every sanctioned right, into
init's cspace. **init is reaped after bootstrap, so any right not transferred to a
surviving service before the reap is dropped — unforwardable until the next boot.
This, not a kernel wall, is what bounds the live extension set.** init transfers a
cap narrowed to **Reset** + **Suspend** to devmgr, the steady-state holder of
platform firmware authority (it sits alongside the ACPI / MMIO / IRQ resources
devmgr already brokers). The remaining sanctioned rights are carried into no
surviving cap and die at init's reap: **Dbcn** is thrown away by design (the
userspace serial driver owns the console; forwarding the firmware console would
bypass the console-ownership model), and **Cppc** / **Base** / **Pmu** are simply
not needed by any current service. devmgr serves pwrmgr a copy further narrowed to
**Reset** only (system reset / reboot); **Suspend** is retained against a future
power-management path but delegated to no one today.

**Gating-granularity decision.** Per-cap authority is encoded as rights bits, not
an EID set carried by `SbiControlObject`, because the extension set is small and
non-numeric and only one actuating consumer exists (pwrmgr, SRST-only).
`SbiControlObject` stays bare and the init descriptor is unchanged
(`aux0 = aux1 = 0`), so `INIT_PROTOCOL_VERSION` is not bumped. The shared 32-bit
`Rights` budget bounds how many extensions can be sanctioned this way; revisiting
that budget (per-type rights) is tracked separately.

### SchedControl

A capability granting authority to assign thread priorities within a bounded
band. Like `Interrupt`/`Mmio`/`IoPort`, it is a **range authority**: the object
carries a `[min, max]` priority band, and holding the cap authorises setting any
priority in that band via `SYS_THREAD_SET_PRIORITY`. It carries **no rights bit** —
presence of the cap plus its band *is* the authority (a band-less or right-less
`SchedControl` would be inert, so there is nothing to gate). Narrow a band into
two disjoint children with `SYS_SCHED_SPLIT`; `cap_derive` cannot shrink a band
(it attenuates rights only).

There is no ambient priority authority: a process holding no `SchedControl`
cannot set *any* thread priority. The kernel does not define a normal/elevated
boundary — that partition is userspace policy expressed through cap
distribution. The root cap spans the full userspace range `[1, PRIORITY_MAX]`
and is created at boot. Init splits it into a baseline band (`[1, 20]` by
default) and an elevated remainder (`[21, PRIORITY_MAX]`); every spawned process
receives a baseline copy via `ProcessInfo.sched_control_cap` (procmgr fans it out
at `CREATE_PROCESS`), and services needing elevated scheduling receive an
explicit grant from the remainder. For priority levels, ranges, and constants,
see [core/kernel/docs/scheduler.md § Priority Levels](../core/kernel/docs/scheduler.md#priority-levels).

---

## Rights and Attenuation

Rights are a bitmask attached to each capability slot. When deriving a capability,
the derived copy may have equal or fewer rights than the source — rights can only
be removed, never added. This is called **attenuation**.

A process cannot grant another process more authority than it holds itself. If a
process holds a send-only endpoint capability, it can derive another send-only
capability (or a weaker one with no grant right), but it cannot produce a receive
capability it does not hold.

The kernel enforces this at derivation time. Any attempt to derive a capability
with rights not present in the source is rejected.

---

## Derivation and the Derivation Tree

Capabilities may be derived: a new capability slot is created referencing the same
underlying object, with equal or fewer rights. The original is retained. Both slots
now reference the object independently.

The kernel maintains a **derivation tree** tracking parent/child relationships between
capability slots across all processes, enabling correct revocation.

---

## Badges

A capability may carry an immutable **badge** — a `u64` value attached at derivation
time via `SYS_CAP_DERIVE_BADGE`. When a badged endpoint capability is used for IPC,
the kernel delivers the badge to the receiver alongside the message label.

Badges are generic: any capability type may carry one. For endpoints, the kernel
delivers the badge on `ipc_recv`. For other types, the badge is stored but not
automatically delivered — userspace may use it for bookkeeping.

### Kernel guarantees

`SYS_CAP_DERIVE_BADGE` enforces two invariants:

1. **Badges are set-once.** A non-zero badge may be attached only to a source
   capability that does NOT already carry one (`src_badge != 0` is rejected).
   Deriving from an already-badged cap propagates the parent's badge unchanged;
   the parent's badge cannot be replaced or shadowed.
2. **Badges propagate through the derivation tree.** Every derived child inherits
   the parent's badge (when non-zero). Once a cap is badged, every cap reachable
   from it through `cap_derive` / `cap_copy` carries the same badge.

These guarantees give the **receiver** of an IPC message a kernel-delivered badge
field it can trust: the value cannot be lied about on the receive path, cannot be
changed after the fact, and is locked to whichever derivation chain the cap belongs
to.

### What the kernel does NOT guarantee

The kernel does NOT restrict which badge *value* a caller chooses when attaching a
badge to an un-badged source. Any holder of an un-badged cap on an endpoint may
mint a badged child cap with any non-zero u64 value, including values that the
endpoint's server uses as authority markers (e.g.,
`procmgr_labels::DEATH_EQ_AUTHORITY`, `pwrmgr_labels::SHUTDOWN_AUTHORITY`).

This is the correct kernel semantics — minting un-badged sources is the
mechanism by which servers distribute badged identities. The implication for
servers is structural, not cryptographic.

### Server-side rule for authority-bearing endpoints

**Never distribute an un-badged SEND cap on an authority-bearing endpoint to a
holder that should not be able to mint arbitrary identities on it.** The
un-badged cap is a blank cheque — it is, by design, the source from which any
badged child can be derived.

In practice this means: the un-badged source cap on a server's endpoint lives
exclusively in the server's own CSpace (used internally to mint per-client
badged copies) and in the CSpaces of trusted bootstrap-time minters (today: init,
which dies and is fully reclaimed at the end of Phase 3). Every other client
receives a badged cap whose badge value is chosen by the trusted minter — the
client cannot subsequently re-badgeize it because of the set-once rule above.

Trying to harden a public authority-bearing badge value by making it "hard to
guess" (long random sentinel, etc.) is obscurity, not security: the same cap_derive
chain that would produce the well-known constant can produce any other u64.
Security comes from controlling *who holds an un-badged cap*, not from secrecy
of the badge bits.

### Verb-bit authority pattern

Endpoints that serve a mix of unprivileged and privileged labels gate
the privileged labels on a verb-bit in the caller's badge, rather than
splitting across separate endpoints. By convention the high bit
(`1u64 << 63`) is the first verb-bit. The set-once badge rules above
mean only the server and its trusted bootstrap-time minters can set
the verb-bit; a holder of an unprivileged cap cannot re-derive an
authority cap. The server's dispatcher checks
`msg.badge & VERB_BIT != 0` before servicing the privileged label and
replies `UNAUTHORIZED` otherwise.

---

## Capabilities as Namespaces

The capability and badge primitives above compose into Seraph's
filesystem namespace mechanism (node capabilities, attenuation through
rights bits, sandboxing by cap distribution) without any kernel support
beyond what this document specifies. The full model is in
[`namespace-model.md`](namespace-model.md); the wire format and
dispatch crate are in
[`shared/namespace-protocol/README.md`](../shared/namespace-protocol/README.md).

---

## Transfer

A capability may be transferred via IPC (see [ipc-design.md](ipc-design.md)) or moved
with `SYS_CAP_MOVE`. Transfer moves the capability from the source CSpace to the
destination CSpace — the source slot becomes null. This is not derivation; no new
entry appears in the derivation tree — the existing node is restamped onto the
destination slot.

Because the cap keeps its derivation position, a move transfers ownership of the
slot but not revocation authority over the lineage: the mover, having nulled its own
slot, no longer holds the cap, yet a `cap_revoke` on one of the cap's ancestors
still reaches it — even across a CSpace boundary. Such a revoke frees the recipient's
slot in the recipient's own CSpace; per-slot generation handles make the recipient's
now-stale handle fail closed rather than alias a recycled slot (#349). (A move within
the same CSpace likewise keeps the source's position.) To delegate a capability while
keeping your own copy, use `SYS_CAP_COPY` instead (see [Revocation](#revocation)).


---

## Revocation

Any process may revoke a capability it has derived. Revocation:

1. Invalidates the target capability slot
2. Recursively invalidates all capabilities derived from it, in all processes

After revocation, any process that held a derived capability can no longer use it.
The underlying kernel object is not destroyed — only the authority to access it is
withdrawn. If the revoker still holds the parent capability, it retains access.

A descendant delivered to another CSpace — by **IPC transfer**, `SYS_CAP_MOVE`, or
`SYS_CAP_COPY` — keeps its position in the derivation tree (see
[Transfer](#transfer)), so the revoke reaches it across the boundary and frees the
recipient's slot in the recipient's own CSpace. Per-slot generation handles ensure
the recipient's now-stale handle then fails with `InvalidCapability` rather than
aliasing a recycled slot index — the cross-CSpace stale-slot alias that was the #349
hazard.


---

## Object Creation

New kernel objects are created via typed syscalls. Every creation call
consumes a Memory capability with the `Retype` right as its first
argument; the kernel constructs the new object inside that Memory's
backing region, debiting bytes from the Memory's available-bytes ledger.

```
create_endpoint(frame)             → endpoint_cap  (Send + Receive + Grant)
create_notification(frame)               → notification_cap    (Notification + Wait)
create_event_queue(frame, n)       → queue_cap     (Post + Recv)
create_thread(frame, aspace, cs)   → thread_cap    (Control)
create_address_space(frame, ...)   → aspace_cap    (Map)
create_cspace(frame, ...)          → cspace_cap    (Insert + Delete + Derive + Revoke)
create_wait_set(frame)             → wait_set_cap  (Modify + Wait)
```

The kernel rejects creation if the Memory cap lacks `Retype` rights or
if its available-bytes ledger has insufficient room for the requested
object. The returned capability is placed in a free slot in the caller's
CSpace. The caller holds all rights on a freshly created object.

The kernel does not track ownership beyond the derivation tree. If a process destroys
all capabilities in the derivation tree for an object — including its own — the kernel
reclaims the object's bytes (returning them to the Memory cap from which the object
was retyped) and frees the slot. Objects do not outlive all references to them.

---

## Typed Memory

Every kernel object's backing storage is accounted to a specific Memory
capability. There is no ambient kernel pool from which a process can
draw kernel-object memory; a process can only create kernel objects
against Memory caps it holds with `Retype` rights.

### Available-bytes ledger

Each retypable Memory capability carries an `available_bytes` counter.
Creating a kernel object against the cap debits the counter by the
object's byte cost (rounded up to a fixed size class). Destroying
the object credits the bytes back. The counter is observable via
[`SYS_CAP_INFO`](#cap-introspection).

The ledger gives userspace memory managers a single primitive for
budgeting both *mapped* memory (via `mem_map`) and *kernel-object*
memory (via the create syscalls above): one Memory cap, two consuming
operations, one budget. A misbehaving service cannot inflate kernel
memory through a back channel — every byte of kernel-object backing
is debited from a cap the service holds.

### Auto-reclaim

When a kernel object's reference count reaches zero (every cap referring
to it has been destroyed), the kernel reclaims its bytes back to the
Memory capability the object was retyped from. If the source Memory cap's
own reference count then reaches zero, the reclamation cascades upward
through the derivation chain. Process death is an instance of this
cascade: revoking a child's CSpace destroys all caps the child held,
which deallocates every kernel object the child created, which credits
all bytes back to memmgr's frame pool — closing the loop without
explicit cleanup.

### Address-space and CSpace growth budgets

Page tables and CSpace slot pages are kernel-half memory that grows
during normal operation as a process maps memory or accumulates caps.
Each `AddressSpace` and `CSpace` capability carries its own growth
budget — a pool of pages donated at creation time from a Retype-bearing
Memory cap — from which `mem_map` and `cap_insert` allocate. Exhausting
the budget returns `NoMemory`; the budget refills via *augment mode* on
the same create syscall (passing the existing AS/CS slot as the augment
target merges a new slab of pages into its growth budget).

An `AddressSpace`'s intermediate page tables are also returned to its
growth budget mid-life when a region is torn down: `SYS_MEM_UNMAP` with
`MEM_UNMAP_RECLAIM_PTS` (issued by memmgr at `UNREGISTER_REGION`) clears
the span's leaf entries and frees each now-empty intermediate page table
back to the pool, crediting the budget. Without the flag, intermediate
page tables persist until the `AddressSpace` is destroyed. The credited
budget is observable via `SYS_CAP_INFO`.

This means every kernel-half page-table and slot-page allocation is
gated by a Memory cap the owning process holds. There is no untracked
kernel growth path.

### Cap introspection

`SYS_CAP_INFO` is a read-only inquiry that returns runtime state for
a held capability: tag and rights for any cap; size, available-bytes,
and retype-rights flag for Memory caps; PT growth budget for AddressSpace
caps; slot capacity, slots used, and growth budget for CSpace caps.
The syscall enables defensive ledger checks (e.g. memmgr can verify a
returning cap's available-bytes), and lets receivers of a cap from a
less-trusted source validate its shape before relying on it.

---

## Initial Capability Distribution

At boot, the kernel creates init's Thread, AddressSpace, and CSpace and populates
the CSpace with an initial set of capabilities covering all available resources:

- Memory capabilities for all usable physical memory
- Mmio capabilities for all boot-provided platform resource regions
  (MmioRange and PciEcam entries from `BootInfo.platform_resources`)
- Interrupt capabilities for all boot-provided interrupt lines
- Read-only Memory capabilities for firmware table regions (PlatformTable entries),
  allowing userspace to parse ACPI or Device Tree data
- IoPort capabilities for all boot-provided I/O port ranges (x86-64 only)
- One SbiControl capability (RISC-V only) carrying every sanctioned SBI right
- One SchedControl capability spanning the full userspace priority range `[1, PRIORITY_MAX]`
- Thread, AddressSpace, and CSpace capabilities for init itself
- Memory capabilities for each boot module image (raw ELF images for early services)

Init is responsible for delegating appropriate subsets of this authority to each service it starts,
following the principle of least privilege. See [device-management.md](device-management.md#what-devmgr-receives-from-init)
for devmgr's specific initial capability set.

### "Kill process" pattern

Since there is no Process kernel object, terminating a process is a userspace
(procmgr) policy, not a single kernel operation. procmgr revokes the capabilities
backing the process's threads; each revocation stops that thread and removes it
from the run queues. The kernel does not track which threads belong to an address
space and never bulk-terminates threads on its own. The process's resources are
reclaimed as their capability reference counts reach zero.

The kernel's only role in death is *notification*. An `AddressSpace` carries a
death-observer set (mirroring the per-thread death observers). On a terminal
fault by any thread in the address space — no fault handler bound, or the handler
replied `KILL` — the kernel posts the fault class (`EXIT_FAULT_BASE + vector`) to
each bound observer and exits the faulting thread. procmgr binds such an observer
at process creation, so a fatal fault on any thread — a worker, not just the main
thread — drives procmgr's teardown of the whole process. Normal thread exit does
not fire these observers.

---

## What the Kernel Does Not Do

The kernel does not provide:
- **Ambient authority** — there is no "root" or "superuser" at the kernel level.
  Init holds broad authority by virtue of its initial capabilities, not by identity.
- **Capability lookup by name** — there is no global namespace of capabilities.
  A process receives capabilities from its parent or via IPC; it cannot search for them.
- **Policy** — the kernel enforces that operations are authorised by capability.
  What the capabilities represent and how they should be distributed is entirely
  a userspace concern, managed by init and the services it supervises.

---

## Summarized By

[README.md](../README.md), [Architecture Overview](architecture.md), [storage.md](storage.md), [init](../services/init/README.md), [namespace-model.md](namespace-model.md)
