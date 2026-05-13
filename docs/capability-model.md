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

## Capability Types

Each capability type represents a distinct kind of kernel object. The rights attached
to a capability are type-specific.

### Memory Frame

A capability to one or more contiguous physical frames. Rights:
- **Map** — may map these frames into an address space
- **Write** — authority to create writable mappings
- **Execute** — authority to create executable mappings
- **Retype** — authority to consume bytes of this Frame's region as the
  backing storage for a newly created kernel object (see
  [Typed Memory](#typed-memory))

A capability may carry both Write and Execute rights, representing independent
authorities over the same physical memory. W^X is enforced at mapping time: the
kernel rejects any `mem_map` or `mem_protect` call that would make a page
simultaneously writable and executable.

The kernel mints Frame caps for all usable RAM at boot with `Map | Write |
Execute | Retype` and places them in init's CSpace. Frame caps minted for
firmware tables (ACPI regions, RSDP, DTB), boot modules, and init's own
ELF segments mint without `Retype` — they are mappable read-only references
to fixed-purpose memory and cannot be consumed for kernel-object creation.

Init transfers RAM Frame caps (via the derive-twice pattern) to memmgr, which
thereafter owns userspace RAM frame allocation and answers `REQUEST_FRAMES`
for every std-built service. See
[`userspace-memory-model.md`](userspace-memory-model.md) and
[`services/memmgr/README.md`](../services/memmgr/README.md). MMIO Frame caps
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

### Signal

A capability to a signal object (bitmask-based async notification). Rights:
- **Signal** — may OR bits into the signal word (deliver notifications)
- **Wait** — may wait on this signal object and read the bitmask

### Event Queue

A capability to an event queue (ordered ring buffer). Rights:
- **Post** — may append an entry to the queue
- **Recv** — may wait on and read entries from the queue

### Interrupt

A capability granting the right to handle a specific hardware interrupt line.
The holder registers an endpoint to receive interrupt notifications on that line.
Interrupt capabilities are created by the kernel at boot and initially granted to
init, which delegates them to appropriate drivers.

### MMIO Region

A capability to a specific physical address range used for memory-mapped I/O.
Holding this capability allows mapping the region into an address space (with Map
right). Without this capability a process cannot map physical addresses — it cannot
name hardware it has not been granted access to.

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

### IoPortRange (x86-64 only)

A capability to a contiguous range of x86 I/O port numbers. Rights:
- **Use** — may bind this port range to a thread, allowing that thread to execute
  `in`/`out` instructions for those ports without a syscall

IoPortRange capabilities are created at boot from `IoPortRange` entries in the
boot-provided `platform_resources`. They are not creatable at runtime. A driver
that needs port I/O access receives a derived IoPortRange capability from init
(via devmgr), covering only its assigned port range.

Revoking an IoPortRange capability removes port access from all threads it has
been bound to. The kernel tracks bindings and updates each affected thread's IOPB
in the TSS on revocation.

### SchedControl

A capability granting authority to assign elevated scheduling priorities. Rights:
- **Elevate** — may set thread priorities in the elevated range

There is one SchedControl capability, created at boot. Init holds it and delegates
derived copies to services that need real-time-ish scheduling (e.g. audio servers,
device managers). Without a SchedControl capability, a process can only set thread
priorities in the normal range. For priority levels, ranges, and constants, see
[core/kernel/docs/scheduler.md § Priority Levels](../core/kernel/docs/scheduler.md#priority-levels).

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

## Tokens

A capability may carry an immutable **token** — a `u64` value attached at derivation
time via `SYS_CAP_DERIVE_TOKEN`. Tokens serve as unforgeable caller identifiers:
when a tokened endpoint capability is used for IPC, the kernel delivers the token
to the receiver alongside the message label.

Tokens are generic: any capability type may carry one. For endpoints, the kernel
delivers the token on `ipc_recv`. For other types, the token is stored but not
automatically delivered — userspace may use it for bookkeeping.

A token is set once and cannot be changed. Deriving from a tokened capability
inherits the token. Attempting to set a new token on an already-tokened capability
returns an error.

---

## Capabilities as Namespaces

The capability mechanism above suffices to express filesystem
namespaces, sandbox views, and per-process roots without any kernel
support beyond what is already documented. A **node capability** in
Seraph is a tokened SEND on an IPC endpoint owned by a server
process; the token's bits encode a server-private node identifier
plus a per-cap rights mask, decoded by the server on every request.

This composition gives:

- **The capability is the namespace.** Holding a directory cap is
  the authority to walk that directory; no path string carries
  authority.
- **Sandboxing as cap distribution.** A child process whose initial
  bootstrap cap is a different node cap (or no cap at all) sees a
  different root, with no kernel mount table or chroot syscall
  involved.
- **Per-child distribution at spawn.** procmgr installs each child's
  `ProcessInfo.system_root_cap` from either the universal default
  (a tokened SEND on vfsd's namespace endpoint) or a spawner-supplied
  override. Spawners override via the `CONFIGURE_NAMESPACE` IPC
  between create and start, transferring an attenuated cap they
  obtained by walk-and-attenuate from a cap they already hold.
  procmgr never mints namespace caps itself.
- **Attenuation through rights bits.** The rights field in the token
  narrows on every walk under server enforcement, mirroring the
  derivation-tree attenuation the kernel enforces on the cap itself.

The system-scope authority for the namespace model is
[`namespace-model.md`](namespace-model.md); the wire format and
dispatch crate are
[`shared/namespace-protocol/README.md`](../shared/namespace-protocol/README.md).

---

## Transfer

A capability may be transferred via IPC (see [ipc-design.md](ipc-design.md)). Transfer
moves the capability from the sender's CSpace to the receiver's CSpace — the sender's
slot becomes null. This is not derivation; no new entry appears in the derivation tree.
The receiver inherits the sender's position in the existing tree.


---

## Revocation

Any process may revoke a capability it has derived. Revocation:

1. Invalidates the target capability slot
2. Recursively invalidates all capabilities derived from it, in all processes

After revocation, any process that held a derived capability can no longer use it.
The underlying kernel object is not destroyed — only the authority to access it is
withdrawn. If the revoker still holds the parent capability, it retains access.


---

## Object Creation

New kernel objects are created via typed syscalls. Every creation call
consumes a Frame capability with the `Retype` right as its first
argument; the kernel constructs the new object inside that Frame's
backing region, debiting bytes from the Frame's available-bytes ledger.

```
create_endpoint(frame)             → endpoint_cap  (Send + Receive + Grant)
create_signal(frame)               → signal_cap    (Signal + Wait)
create_event_queue(frame, n)       → queue_cap     (Post + Recv)
create_thread(frame, aspace, cs)   → thread_cap    (Control)
create_address_space(frame, ...)   → aspace_cap    (Map)
create_cspace(frame, ...)          → cspace_cap    (Insert + Delete + Derive + Revoke)
create_wait_set(frame)             → wait_set_cap  (Modify + Wait)
```

The kernel rejects creation if the Frame cap lacks `Retype` rights or
if its available-bytes ledger has insufficient room for the requested
object. The returned capability is placed in a free slot in the caller's
CSpace. The caller holds all rights on a freshly created object.

The kernel does not track ownership beyond the derivation tree. If a process destroys
all capabilities in the derivation tree for an object — including its own — the kernel
reclaims the object's bytes (returning them to the Frame cap from which the object
was retyped) and frees the slot. Objects do not outlive all references to them.

---

## Typed Memory

Every kernel object's backing storage is accounted to a specific Frame
capability. There is no ambient kernel pool from which a process can
draw kernel-object memory; a process can only create kernel objects
against Frame caps it holds with `Retype` rights.

### Available-bytes ledger

Each retypable Frame capability carries an `available_bytes` counter.
Creating a kernel object against the cap debits the counter by the
object's byte cost (rounded up to a fixed size class). Destroying
the object credits the bytes back. The counter is observable via
[`SYS_CAP_INFO`](#cap-introspection).

The ledger gives userspace memory managers a single primitive for
budgeting both *mapped* memory (via `mem_map`) and *kernel-object*
memory (via the create syscalls above): one Frame cap, two consuming
operations, one budget. A misbehaving service cannot inflate kernel
memory through a back channel — every byte of kernel-object backing
is debited from a cap the service holds.

### Auto-reclaim

When a kernel object's reference count reaches zero (every cap referring
to it has been destroyed), the kernel reclaims its bytes back to the
Frame capability the object was retyped from. If the source Frame cap's
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
Frame cap — from which `mem_map` and `cap_insert` allocate. Exhausting
the budget returns `NoMemory`; the budget refills via *augment mode* on
the same create syscall (passing the existing AS/CS slot as the augment
target merges a new slab of pages into its growth budget).

This means every kernel-half page-table and slot-page allocation is
gated by a Frame cap the owning process holds. There is no untracked
kernel growth path.

### Cap introspection

`SYS_CAP_INFO` is a read-only inquiry that returns runtime state for
a held capability: tag and rights for any cap; size, available-bytes,
and retype-rights flag for Frame caps; PT growth budget for AddressSpace
caps; slot capacity, slots used, and growth budget for CSpace caps.
The syscall enables defensive ledger checks (e.g. memmgr can verify a
returning cap's available-bytes), and lets receivers of a cap from a
less-trusted source validate its shape before relying on it.

---

## Initial Capability Distribution

At boot, the kernel creates init's Thread, AddressSpace, and CSpace and populates
the CSpace with an initial set of capabilities covering all available resources:

- Frame capabilities for all usable physical memory
- MMIO region capabilities for all boot-provided platform resource regions
  (MmioRange and PciEcam entries from `BootInfo.platform_resources`)
- Interrupt capabilities for all boot-provided interrupt lines
- Read-only Frame capabilities for firmware table regions (PlatformTable entries),
  allowing userspace to parse ACPI or Device Tree data
- IoPortRange capabilities for all boot-provided I/O port ranges (x86-64 only)
- One SchedControl capability (Elevate rights)
- Thread, AddressSpace, and CSpace capabilities for init itself
- Frame capabilities for each boot module image (raw ELF images for early services)

Init is responsible for delegating appropriate subsets of this authority to each service it starts,
following the principle of least privilege. See [device-management.md](device-management.md#what-devmgr-receives-from-init)
for devmgr's specific initial capability set.

### "Kill process" pattern

Since there is no Process kernel object, terminating a process is done by revoking
its AddressSpace capability. The kernel tracks which threads are bound to each
AddressSpace; on revocation, all bound threads are stopped and removed from run queues.
The process's resources are reclaimed as their capability reference counts reach zero.

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

[Architecture Overview](architecture.md), [init](../services/init/README.md)
