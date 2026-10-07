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
- **Pay-as-you-go** — capacity is whatever the owner-funded slot-page pool
  backs (see growth budgets below), bounded only by the directory's
  structural ceiling

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
two return registers rather than packing them into one). The IPC *send* path
carries the full handle as well — the packed transfer words hold one 32-bit
handle per field — so the kernel generation-validates the sender's named slots:
a stale, recycled handle fails closed with `InvalidCapability` instead of
transmitting the slot's current occupant. Every handle-resolution path is
covered by the generation check (#349). The cap the recipient *receives* is
generation-correct: the kernel re-derives it from the freshly inserted
destination slot.

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
Execute | Retype` and places them in init's CSpace. Boot-module, init-segment,
and reclaimed boot-scratch Memory caps carry the same full rights: cap rights
gate derivation, not existing mappings (init's segments are already mapped at
their true protection, and loaders map boot-module ELF sources read-only), and
full rights let the caps donate into memmgr's pool as general RAM at init's
reap. Only firmware-table Memory caps (ACPI regions, RSDP, DTB)
mint without `Retype` — mappable references to fixed-purpose memory that
cannot be consumed for kernel-object creation.

Init transfers RAM Memory caps (via the
[derive-twice pattern](../core/kernel/docs/capability-internals.md#safe-delegation-the-derive-twice-pattern))
to memmgr, which
thereafter owns userspace RAM frame allocation and answers `REQUEST_MEMORY_CAPS`
for every std-built service. See
[`userspace-memory-model.md`](userspace-memory-model.md) and
[`services/memmgr/README.md`](../services/memmgr/README.md). Mmio caps
follow a separate flow through devmgr; see
[`device-management.md`](device-management.md).

### Address Space

A capability to a process's virtual address space. Rights:
- **Map** — may install and remove mappings in this address space
- **Read** — may inspect current mappings
- **Control** — may register terminal-fault death observers
  (`aspace_bind_notification`); held by the space's creator and masked out of
  copies handed to components that only map into the space

The kernel holds implicit authority over all address spaces; this capability is
what allows userspace memory managers to manage mappings on behalf of a process.

### IPC Endpoint

A capability to an IPC endpoint. Rights:
- **Send** — may call this endpoint (synchronous IPC, caller blocks for reply)
- **Receive** — may accept calls on this endpoint (held only by the server)
- **Grant** — may include capabilities in the message's capability slots

A send capability without grant right cannot pass capabilities to the server.
A server that should not receive unexpected resources from clients distributes only
send capabilities without the grant right; the receive path does not consult the
receiver's Grant right.

An endpoint may additionally be designated a thread's **fault handler** — a protocol
specified in [Fault Handling](fault-handling.md), with no distinct
fault-endpoint capability type: the kernel delivers that thread's unresolvable faults to
the bound endpoint.

### Notification

A capability to a notification object (bitmask-based async notification). Rights:
- **Notify** — may OR bits into the notification word (deliver notifications)
- **Wait** — may wait on this notification object and read the bitmask

### Event Queue

A capability to an event queue (ordered ring buffer). Rights:
- **Post** — may append an entry to the queue
- **Recv** — may wait on and read entries from the queue

### Interrupt

A capability to a contiguous range of hardware interrupt lines (a range authority,
narrowed with `SYS_IRQ_SPLIT`). Rights:
- **Notify** — may register, acknowledge, and split (`SYS_IRQ_REGISTER`, `SYS_IRQ_ACK`,
  `SYS_IRQ_SPLIT`); register and acknowledge require a single-line cap

The holder binds a Notification to the line with `SYS_IRQ_REGISTER`; each interrupt
ORs bit 0 into that Notification, and the holder re-enables the line with
`SYS_IRQ_ACK`.

The kernel mints one root Interrupt range capability at boot that covers every IRQ
id on the architecture and places it in init's CSpace. Init hands it to devmgr,
which splits single-line children with `SYS_IRQ_SPLIT` and delegates one to each
driver.

### Mmio

A capability to a specific physical address range (an MMIO aperture) used for
memory-mapped I/O. Rights:
- **Map** — may map the region into an address space
- **Write** — may map the region writable (`sys_mmio_map` gates mapping
  writability on it; MMIO mappings are never executable)

Without this capability a process cannot map physical addresses — it cannot
name hardware it has not been granted access to.

Revoking an Mmio capability blocks new `SYS_MMIO_MAP` calls through its descendants but
does not unmap mappings already established through them; the kernel unmapping every
mapping made through those descendants on revocation is design intent (not yet
implemented — `SYS_MMIO_MAP` records no mapping, #457).

### Thread

A capability to a thread. Rights:
- **Control** — may start, stop, and configure the thread
- **Observe** — may read the thread's register state (for debugging)

### CSpace

A capability to a capability space. Rights:
- **Insert** — may place a new capability into a slot
- **Delete**, **Derive**, **Revoke** — defined but not checked by any syscall; slot
  deletion, derivation, and revocation act on the caller's own CSpace and need no
  CSpace capability

CSpace capabilities are used when configuring a new thread (binding a CSpace to
the thread) and when cross-CSpace capability operations are needed (e.g. init
populating a new process's CSpace before handing it off).

### Wait Set

A capability to a wait set (see
[IPC Design § Waiting on Multiple Sources](ipc-design.md#waiting-on-multiple-sources)). Rights:
- **Modify** — may add or remove members
- **Wait** — may block on the wait set

### IoPort (x86-64 only)

A capability to a contiguous range of x86 I/O port numbers. Rights:
- **Use** — may bind this port range to a thread, allowing that thread to execute
  `in`/`out` instructions for those ports without a syscall

The kernel mints one root IoPort capability over the full 64K port space at boot
(x86-64 only); IoPort capabilities are not creatable at runtime. Init hands devmgr a
copy, and devmgr narrows it with `SYS_IOPORT_SPLIT` and gives each driver only its
assigned port range (see
[services/devmgr/docs/responsibilities.md](../services/devmgr/docs/responsibilities.md)).

Revoking an IoPort capability removes port access from all threads it has
been bound to; the kernel tracks bindings and updates each affected thread's IOPB
in the TSS on revocation (design intent; not yet implemented — `SYS_IOPORT_BIND`
records no binding and revocation does not withdraw bound IOPB access, #457).

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

**Kernel floor.** The kernel forwards only the six sanctioned extensions above and
rejects every other extension ID regardless of cap (`InvalidArgument`). The rejected
set includes the extensions it manages internally — TIME (scheduler timer), IPI (TLB
shootdown / wakeups), RFENCE (remote fences), HSM (hart lifecycle) — whose forwarding
would break a kernel invariant. Sanctioning a further extension adds one entry to the
kernel's extension-to-right map and one `SbiControl` right.

**Distribution is policy, not kernel enforcement.** Each sanctioned extension has a
right, but a holder can only forward an extension whose
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
power-management path but delegated to no one today. See
[services/devmgr/docs/responsibilities.md](../services/devmgr/docs/responsibilities.md).

**Gating-granularity decision.** Per-cap authority is encoded as rights bits, not
an EID set carried by `SbiControlObject`, because the extension set is small and
non-numeric and only one actuating consumer exists (pwrmgr, SRST-only).
`SbiControlObject` carries no fields, and its init descriptor has `aux0 = aux1 = 0`.
Rights are scoped
per capability type, so `SbiControl` draws on its own full 32-bit space —
sanctioning further extensions does not compete with any other type's rights.

### SchedControl

A capability granting authority to assign thread priorities within a bounded
band. Like `Interrupt`/`Mmio`/`IoPort`, it is a **range authority**: the object
carries a `[min, max]` priority band, and holding the cap authorises setting any
priority in that band via `SYS_THREAD_SET_PRIORITY`, or placing a new thread at
it via `SYS_CAP_CREATE_THREAD`'s priority arguments (creation at the floor,
`PRIORITY_MIN`, needs no `SchedControl` at all). It carries **no rights bit** —
presence of the cap plus its band *is* the authority (a band-less or right-less
`SchedControl` would be inert, so there is nothing to gate). Narrow a band into
two disjoint children with `SYS_SCHED_SPLIT`; `cap_derive` cannot shrink a band
(it attenuates rights only).

There is no ambient priority authority: a process holding no `SchedControl`
cannot set *any* thread priority. The kernel does not define a normal/elevated
boundary — that partition is userspace policy expressed through cap
distribution. The root cap spans the full userspace range `[1, PRIORITY_MAX]`
and is created at boot. Init splits it into the baseline band
(`[1, sched_policy::BASELINE_PRIORITY_MAX]`, i.e. `[1, 28]`) and an elevated
remainder (`[29, PRIORITY_MAX]`) that never leaves init and dies at its reap.
Every spawned process receives a band via `ProcessInfo.sched_control_cap`:
procmgr fans its baseline out per child at create time — a plain `cap_copy`
for a full-width band, or copy-then-`SYS_SCHED_SPLIT` to mint a narrowed
`[1, band_max]` when the spawner requested one (the create label's
`CREATE_BAND_MAX` field, validated against the spawner's own band; see
[services/procmgr/docs/ipc-interface.md](../services/procmgr/docs/ipc-interface.md)). The
per-service level assignments live in `shared/ipc`'s `sched_policy` module
and the svcmgr `.svc` recipes. For priority levels, ranges, and constants, see
[core/kernel/docs/scheduler.md § Priority Levels](../core/kernel/docs/scheduler.md#priority-levels).

---

## Rights and Attenuation

Rights are a bitmask attached to each capability slot, scoped per capability type:
each type numbers its bits from 0 in its own space, and a rights mask is meaningful
only for the type it is named for. The all-ones mask (`RIGHTS_ALL`) is valid for
every type. Bit values are defined in [`abi/syscall`](../abi/syscall/README.md).
Storage and bit assignments are in
[core/kernel/docs/capability-internals.md § Rights Bitmask](../core/kernel/docs/capability-internals.md#rights-bitmask).

When deriving a capability, the derived copy may have equal or fewer rights than
the source — rights can only be removed, never added. This is called
**attenuation**. Attenuation is a bitwise AND against the source's rights word and
is uniform across types; the per-type scoping changes only how the bits are named
and numbered, not how they attenuate.

A process cannot grant another process more authority than it holds itself. If a
process holds a send-only endpoint capability, it can derive another send-only
capability (or one with no rights at all), but it cannot produce a grant or receive
capability it does not hold.

The kernel enforces this at derivation time: requested rights not present in the
source are dropped, never granted.

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

Kernel-synthesized fault messages are the exception. Their badge is the value the binder
passes to `SYS_THREAD_SET_FAULT_HANDLER`, not the derivation badge of any cap, and any holder
of a cap to the endpoint can bind its own thread with an arbitrary badge. Neither the
guarantee above nor the [verb-bit rule](#verb-bit-authority-pattern) below applies to a fault
message's badge; see [fault-handling.md § Security](fault-handling.md#security) and
[#459](https://github.com/kottlerg/seraph/issues/459).

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
only in the server's own CSpace (used internally to mint per-client badged
copies) and in the CSpaces of trusted minters. Today these are init, which
procmgr reaps once both its threads have exited after init's
[Handover stage](../services/init/docs/bootstrap.md#handover) (see
[process-lifecycle.md § Init reap](process-lifecycle.md#init-reap)), plus
procmgr, svcmgr, devmgr, and vfsd, which hold un-badged sources on other servers'
endpoints for the system's lifetime to mint per-client badges: devmgr on the
driver service endpoints it creates, from which it mints the verb-bit query caps,
and vfsd on the fs-driver endpoint it keeps for each terminal mount. Every other
client receives a badged cap whose badge value is chosen by the trusted minter —
the client cannot subsequently re-badgeize it because of the set-once rule above.

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
mean only the server and its trusted minters can set
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
destination CSpace — the source slot becomes null, except in the races
[capability-internals.md](../core/kernel/docs/capability-internals.md) § Move lists. This is
not derivation; no new entry appears in the derivation tree — the existing node is restamped
onto the destination slot.

Because the cap keeps its derivation position, a move transfers ownership of the
slot but not revocation authority over the lineage: the mover, having nulled its own
slot, no longer holds the cap, yet a `cap_revoke` on one of the cap's ancestors
still reaches it — even across a CSpace boundary. Such a revoke frees the recipient's
slot in the recipient's own CSpace; per-slot generation handles make the recipient's
now-stale handle fail closed rather than alias a recycled slot (#349). (A move within
the same CSpace likewise keeps the source's position.) To delegate a capability while
keeping your own copy, use `SYS_CAP_COPY` instead (see [Revocation](#revocation)).

The capabilities derived from a moved capability follow it: the move rewrites
every child's parent link, in batches with the derivation lock released between
them when the list is large. While a move is in flight both slots are pinned —
the same refusal an in-flight revocation imposes on its root — so no other
operation can tear the migration, and every descendant stays within its
ancestors' revocation reach throughout, with one exception the kernel shares
with every other slot: a CSpace torn down while the move is in flight releases
the children hanging under its dying slots as derivation roots. See
[capability-internals.md](../core/kernel/docs/capability-internals.md) § Move.


---

## Revocation

Any process may revoke the descendants of any capability it holds. Revocation recursively
invalidates all capabilities derived from the target, in all processes. The target
slot itself is preserved — the revoker keeps its own capability and only withdraws
delegated authority.

After revocation, any process that held a derived capability can no longer use it
(an established MMIO mapping or IoPort binding outlives it; see [Mmio](#mmio) and
[IoPort](#ioport-x86-64-only)). The target's kernel object is not destroyed, because the
preserved target slot still references it. A descendant that references a distinct
object, such as a range-split child, frees that object when its last reference goes.

A descendant delivered to another CSpace — by **IPC transfer**, `SYS_CAP_MOVE`, or
`SYS_CAP_COPY` — keeps its position in the derivation tree (see
[Transfer](#transfer)), so the revoke reaches it across the boundary and frees the
recipient's slot in the recipient's own CSpace. Per-slot generation handles ensure
the recipient's now-stale handle then fails with `InvalidCapability` rather than
aliasing a recycled slot index — the cross-CSpace stale-slot alias that was the #349
hazard. See [capability-internals.md](../core/kernel/docs/capability-internals.md)
§ Capability Transfer in IPC.


---

## Object Creation

New kernel objects are created via typed syscalls. Every creation call
consumes a Memory capability with the `Retype` right as its first
argument; the kernel constructs the new object inside that Memory's
backing region, debiting bytes from the Memory's available-bytes ledger.

```
SYS_CAP_CREATE_ENDPOINT(memory)               → endpoint_cap     (Send + Receive + Grant)
SYS_CAP_CREATE_NOTIFICATION(memory)           → notification_cap (Notify + Wait)
SYS_CAP_CREATE_EVENT_Q(memory, capacity)      → queue_cap        (Post + Recv)
SYS_CAP_CREATE_THREAD(memory, aspace, cspace, sched, priority) → thread_cap (Control + Observe)
SYS_CAP_CREATE_ASPACE(memory, augment, pages) → aspace_cap       (Map + Read + Control)
SYS_CAP_CREATE_CSPACE(memory, augment, pages) → cspace_cap       (Insert + Delete + Derive)
SYS_CAP_CREATE_WAIT_SET(memory)               → wait_set_cap     (Modify + Wait)
```

The kernel rejects creation if the Memory cap lacks `Retype` rights or
if its available-bytes ledger has insufficient room for the requested
object. The returned capability is placed in a free slot in the caller's
CSpace. The caller receives the rights listed above; a freshly created CSpace
capability carries no Revoke right.

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
each object's bytes back to the Memory cap it was retyped from; memmgr
returns the child's frames to its pool when procmgr sends `PROCESS_DIED`
(see [userspace-memory-model.md](userspace-memory-model.md)).

### Address-space and CSpace growth budgets

Page tables and CSpace slot pages are kernel-half memory that grows
during normal operation as a process maps memory or accumulates caps.
Each `AddressSpace` and `CSpace` capability carries its own growth
budget — a pool of pages donated at creation time from a Retype-bearing
Memory cap — from which `mem_map` and `cap_insert` allocate. Exhausting
the budget returns `OutOfMemory` (-8); the budget refills via *augment
mode* on the same create syscall (passing the existing AS/CS slot as the
augment target merges a new slab of pages into its growth budget).
Donations are unbounded in number: the kernel keeps its donation
bookkeeping inside the donated pages themselves, so once per record page
of bookkeeping a donation seeds one page fewer than it carried; the
budget reported by `SYS_CAP_INFO` is authoritative. See
[capability-internals.md](../core/kernel/docs/capability-internals.md)
§ Page Pools.

A `CSpace` has two independent growth bounds, distinguishable by error
code at the failure site:

- **Pool exhaustion** — the seeded slot-page pool is empty. Returns
  `OutOfMemory` (-8); refillable via augment mode. The kernel also logs
  the CSpace id, allocated count, and occurrence count on power-of-two
  occurrences.
- **Structural ceiling** — the slot directory is full. Returns
  `QuotaExceeded` (-17); a shape-derived bound (see
  [capability-internals.md](../core/kernel/docs/capability-internals.md)
  § Storage: Hybrid Two-Level Radix) that no memory donation can lift.

There is no per-CSpace slot quota: capacity below the structural
ceiling is exactly what the paid pool backs. Containing a child's cap
footprint is a memory-distribution decision — a supervisor that wants a
child bounded gives it less memory to fund growth with — not a kernel
knob.

Seeding policy: a CSpace creation site seeds the pool for the process's
expected startup population; a process that outgrows its seed self-funds
via augment-mode `cap_create_cspace` against its own `CSpace` cap. The
current backed capacity is observable via `SYS_CAP_INFO`
(`CAP_INFO_CSPACE_CAPACITY`); subtracting slots used yields headroom.

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
retype-rights flag, and physical base for Memory caps; lifecycle state and
exit reason for Thread caps; PT growth budget for AddressSpace caps; backed
slot capacity, slots used, and growth budget for CSpace caps; plus two
system-wide tagged-TLB diagnostic counters.
The syscall enables defensive ledger checks (e.g. memmgr can verify a
returning cap's available-bytes), and lets receivers of a cap from a
less-trusted source validate its shape before relying on it.

---

## Initial Capability Distribution

At boot, the kernel creates init's Thread, AddressSpace, and CSpace and populates
the CSpace with an initial set of capabilities covering all available resources.
The kernel mints these during Phases 7–9 of
[initialization.md](../core/kernel/docs/initialization.md#phase-7-capability-system)
(Phase 8 mints the late-reclaim cap over the AP trampoline page).

- Memory capabilities for all usable physical memory
- Mmio capabilities (Map | Write), one per `BootInfo.mmio_apertures` entry, plus one
  over the kernel console UART on RISC-V
- One root Interrupt range capability covering every valid IRQ id on the architecture
- Map-only Memory capabilities over each `AcpiReclaimable` memory-map region, the page
  holding `BootInfo.acpi_rsdp`, and the `BootInfo.device_tree` blob, allowing userspace
  to parse ACPI or Device Tree data
- One root IoPort capability covering the full 64K I/O port space (x86-64 only)
- One SbiControl capability (RISC-V only) carrying every sanctioned SBI right
- One SchedControl capability spanning the full userspace priority range `[1, PRIORITY_MAX]`
- Thread, AddressSpace, and CSpace capabilities for init itself
- Memory capabilities for each boot module image (raw ELF images for early services)
- Reclaimable Memory capabilities, one per `BootInfo.reclaim_ranges` entry (bootloader
  scratch pages and the bundle's non-module pages)
- Memory capabilities for init's own ELF segments, InitInfo pages, and stack pages,
  which init donates to memmgr at its reap

Init is responsible for delegating appropriate subsets of this authority to each service it starts,
following the principle of least privilege. See
[device-management.md](device-management.md#what-devmgr-receives-from-init)
for devmgr's specific initial capability set.

### "Kill process" pattern

Since there is no Process kernel object, terminating a process is a userspace (procmgr) policy, not
a single kernel operation. procmgr revokes and deletes the capabilities it holds to the process's
main thread, `CSpace`, and `AddressSpace`; a thread stops and leaves the run queues when the last
capability to it is deleted, and the process's other threads stop when the `CSpace` or
`AddressSpace` they are bound to is reclaimed. The kernel never terminates threads by policy of its
own; the one thing it enforces is that a thread cannot outlive the `CSpace` or `AddressSpace` it is
bound to: when the last capability to either object is deleted, every thread bound to it is stopped
before the object's storage is reclaimed, wherever those threads' own capabilities are held —
including the deleting thread itself, when it holds that last capability to its own `CSpace` or
`AddressSpace` (the delete then never returns to it). The process's resources are reclaimed as their
capability reference counts reach zero. For a thread displaced from a server's pending-reply binding
by a later receive, neither these stops nor the reap that deleting its last Thread capability starts
is memory-safe, and the reap can hang the kernel ([IPC Design](ipc-design.md#the-callreply-model),
[#443](https://github.com/kottlerg/seraph/issues/443)).

Beyond that stop, the kernel's role in death is *notification*. An
`AddressSpace` carries a death-observer set (mirroring the per-thread death
observers). On a terminal fault by any thread in the address space — no fault
handler bound, or the handler replied `KILL` — the kernel posts the fault class
(`EXIT_FAULT_BASE + vector`) to each bound observer and exits the faulting
thread. procmgr binds such an observer at process creation, so a fatal fault on
any thread — a worker, not just the main thread — drives procmgr's teardown of
the whole process. Normal thread exit does not fire these observers.

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

[abi/process-abi/README.md](../abi/process-abi/README.md),
[Capability Subsystem Internals](../core/kernel/docs/capability-internals.md),
[Kernel Initialization Sequence](../core/kernel/docs/initialization.md),
[Scheduler Internals](../core/kernel/docs/scheduler.md),
[Syscall Interface Specification](../core/kernel/docs/syscalls.md),
[Architecture Overview](architecture.md), [System Bootstrap](bootstrap.md),
[Device Management](device-management.md), [IPC Design](ipc-design.md),
[Memory Model](memory-model.md), [Namespace Model](namespace-model.md),
[Process Lifecycle](process-lifecycle.md), [Storage](storage.md),
[programs/capexhaust/README.md](../programs/capexhaust/README.md),
[programs/threadstack/README.md](../programs/threadstack/README.md),
[runtime/ruststd/README.md](../runtime/ruststd/README.md),
[services/devmgr/README.md](../services/devmgr/README.md),
[init Bootstrap Stages](../services/init/docs/bootstrap.md),
[services/memmgr/README.md](../services/memmgr/README.md),
[memmgr IPC Interface](../services/memmgr/docs/ipc-interface.md),
[memmgr Memory Pool](../services/memmgr/docs/memory-pool.md),
[procmgr IPC Interface](../services/procmgr/docs/ipc-interface.md),
[svcmgr IPC Interface](../services/svcmgr/docs/ipc-interface.md),
[Synthetic Root and Namespace Composition](../services/vfsd/docs/namespace-composition.md),
[shared/namespace-protocol/README.md](../shared/namespace-protocol/README.md)
