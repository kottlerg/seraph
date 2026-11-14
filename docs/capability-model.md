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
- **Bounded under speculation** — no user-supplied handle reaches a load that
  depends on it before the checks of its resolution (its index bound, the
  slot's occupancy and generation, and the type and the rights its lookup
  requires) are enforced as data, not by a conditional branch alone:
  a misspeculated resolution yields no object, never another slot's, an object
  of another type, or one whose slot lacks those rights. The same holds past
  resolution: a right a handler tests beyond those its lookup requires gates
  the object it backs as data, and a user-supplied value that selects a kernel
  array entry, a span of frames, a page-table walk, or a dispatch table entry
  is bounded as data before that load (mechanism:
  [core/kernel/docs/capability-internals.md](../core/kernel/docs/capability-internals.md)
  § Speculative-Execution Hardening)

Slot 0 is permanently null and cannot be written — using index 0 always means "no
capability".

---

## Microarchitectural Isolation

Capability isolation is architectural: capabilities decide which objects a process can name and
what it can do to them. They do not decide what a process can infer from the hardware state that
processes and the kernel share below the architecture: branch predictors, caches and internal
buffers, the execution resources of SMT siblings, timers and performance counters, frequency
scaling, and DRAM rows. The system draws the line as follows.

- **User-to-kernel boundary** — the kernel MUST defend it against every transient-execution class
  known on the floor silicon
  ([platform-requirements.md](platform-requirements.md) § Platform / silicon-era floor), always:
  every defence is on by default and has no off switch, and a defence that only some CPUs need
  is selected by enumerating the running CPU. The boundary protects every process at once and
  does not depend on whether the processes on a machine distrust each other. The defences in
  place are:
  - on both architectures, the data bounds of § Capability Spaces (**Bounded under
    speculation**): the checks between a user-supplied handle or value and the kernel load it
    selects hold on a mispredicted path
    ([core/kernel/docs/capability-internals.md](../core/kernel/docs/capability-internals.md)
    § Speculative-Execution Hardening);
  - on x86-64, an `lfence` after every entry-side `swapgs` decision (`entry_swapgs_asm`,
    `paranoid_entry_asm`), and the mitigations the floor silicon applies in silicon;
  - on riscv64, the data bounds alone: the RVA23 floor defines no speculation barrier and no
    speculation control for the kernel to enumerate or drive.

  On x86-64, enumerating the running CPU's vulnerabilities (`IA32_ARCH_CAPABILITIES` and CPUID)
  and applying the entry and exit mitigations a vulnerable CPU needs (buffer clearing,
  branch-predictor and return-prediction controls), for the classes the floor silicon does not
  mitigate in silicon, is design intent, not yet implemented
  ([#1085](https://github.com/kottlerg/seraph/issues/1085)). Until then the x86-64 boundary
  rests on the defences above.
- **User-to-user isolation** — not provided. The kernel issues no branch-predictor barrier on a
  context switch, does not schedule SMT siblings by trust, and partitions no cache. It grants
  every process one high-resolution counter, ungated: ring 3 reads the timestamp counter (the
  kernel does not set `CR4.TSD`), and U-mode reads the cycle counter (the kernel sets
  `scounteren.CY`). It grants user mode no other counter: it does not set `CR4.PCE`, and it sets
  no `scounteren` bit beyond `CY` (performance-counter access is design intent, not yet
  implemented, [#265](https://github.com/kottlerg/seraph/issues/265)). These controls, and the
  gating of that counter, need security domains
  ([#152](https://github.com/kottlerg/seraph/issues/152)): without a notion of domain the only policy treats every address space as its own domain, which in a
  microkernel puts a predictor barrier on most IPC switches, and one control applied alone (SMT
  sibling parking, for example) gives no guarantee that can be stated. Cross-domain isolation
  is design intent, not yet implemented
  ([#1086](https://github.com/kottlerg/seraph/issues/1086)).
- **SMT** — stays on. The kernel brings up and schedules every logical CPU, SMT siblings
  included, as an independent CPU. Siblings are not an isolation boundary: threads of different
  processes run on the siblings of one core at once, and contention for the resources the
  siblings share is a channel between them
  ([core/kernel/docs/scheduler.md](../core/kernel/docs/scheduler.md) § SMT Awareness).
- **Accepted and unmitigated** — cache-based side channels outside the transient-execution
  classes above, frequency-scaling (DVFS) channels of the Hertzbleed class, and Rowhammer, at
  both boundaries. The system applies no mitigation for them.

Capability isolation therefore does not keep a secret from a co-resident hostile process: until
security domains exist, a hostile process can attack a co-resident process through shared
microarchitectural state.

---

## Capability Handle Format

A capability handle — the value userspace passes to and receives from the kernel —
packs a per-slot **generation** with the slot index:

```
handle = (generation << CAP_INDEX_BITS) | index      // CAP_INDEX_BITS = 32
```

The handle is a `u64`. The low 32 bits are the slot index; bits 32 to 62 are the
slot's generation counter (`CAP_GEN_BITS = 31`), which the kernel increments each
time the slot is freed and recycled, wrapping at 2^31. Bit 63 is always clear: a
handle returned in the primary syscall return register never reads as a negative
error code. On every operation the kernel checks the handle's generation against
the slot's current generation and returns `InvalidCapability` on mismatch, a handle
with bit 63 set included. This closes the stale-slot alias class (#349): a handle
held across a free/reallocate of its slot fails closed instead of silently
operating on whatever unrelated capability now occupies the index. The check fails
open only for a handle held across exactly a multiple of 2^31 recycles of its one
index, when the wrapped generation matches again.

The index field sets the structural slot ceiling: the kernel's directory reaches the
field's whole leaves
([capability-internals.md](../core/kernel/docs/capability-internals.md) § Storage:
Hybrid Radix Directory), and the kernel asserts that its ceiling fits the field.

A never-recycled slot has generation 0, so its handle is numerically identical to
the bare slot index. Long-lived capabilities minted once at boot or process spawn
(the `ProcessInfo`/`InitInfo`/`CapDescriptor` handover caps) therefore keep their
historical handle values, and the `handle == 0` "no capability" sentinel still
holds (a live cap always has index ≥ 1 in the low bits).

The handle fills a 64-bit syscall register. Capabilities transferred over IPC, and
the second child of a range split, are delivered with their generation intact (the
split delivers its two children in the two return registers). The IPC *send* path
carries the full handle as well, one handle per word of the sender's IPC buffer cap
block ([ipc-design.md](ipc-design.md) § Message Format), so the kernel
generation-validates the sender's named slots: a stale, recycled handle fails closed
with `InvalidCapability` instead of transmitting the slot's current occupant. Every
handle-resolution path is covered by the generation check (#349). The cap the
recipient *receives* is generation-correct: the kernel re-derives it from the freshly
inserted destination slot.

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
- **Phys** — authority to read physical addresses: the physical base of this
  region, and of any other Memory cap its holder presents it beside
  (`CAP_INFO_MEMORY_PHYS_BASE`), and the Read right on an address space retyped
  from it (below)

A capability may carry both Write and Execute rights, representing independent
authorities over the same physical memory. W^X is enforced at mapping time: the
kernel rejects any `mem_map` or `mem_protect` call that would make a page
simultaneously writable and executable.

A page also stays within the rights of the capability that mapped it, which the kernel records
in the page (its leaf grant): `mem_protect` makes a page writable only if that capability carried
Write, and executable only if it carried Execute, whatever the rights of the Memory capability
the call names, so a page mapped through a Map-only capability stays read-only. A
`thread_write_mem` text write reaches a read-only page only when that capability carried Write
or Execute (§ Thread). See
[memory-internals.md § Leaf Grant](../core/kernel/docs/memory-internals.md#leaf-grant).

The kernel mints Memory caps for all usable RAM at boot with `Map | Write |
Execute | Retype | Phys` and places them in init's CSpace. Boot-module, init-segment,
and reclaimed boot-scratch Memory caps carry the same full rights: cap rights
gate derivation, not existing mappings (init's segments are already mapped at
their true protection, and loaders map boot-module ELF sources read-only), and
full rights let the caps donate into memmgr's pool as general RAM at init's
reap. Only firmware-table Memory caps (ACPI regions, RSDP, DTB)
mint with `Map` alone — mappable references to fixed-purpose memory that
cannot be consumed for kernel-object creation, whose physical bases init's
`InitInfo` descriptors already carry.

memmgr strips `Phys` from every grant except to devmgr and the IOMMU drivers, the
processes that program devices with physical addresses
([device-management.md](device-management.md#dma-authorisation) § DMA Authorisation),
so no other process reads where its frames lie
([services/memmgr/docs/ipc-interface.md](../services/memmgr/docs/ipc-interface.md)
§ Label 1; the remaining physical-address surfaces are classified in
[core/kernel/docs/cross-boundary-disclosure.md](../core/kernel/docs/cross-boundary-disclosure.md)
§ Physical-address surfaces).

Revoking a Memory capability invalidates its descendants but does not unmap the
pages they mapped: a mapping established through a revoked descendant stays in
place until its address space unmaps it or is torn down, so a server that hands
out a page and later revokes it cannot rely on the revoke to withdraw the
client's access. It can instead verify the withdrawal. After the revoke, no other
holder can map the page again: a `mem_map` already in flight through a revoked
capability either fails or is counted (see
[memory-internals.md § Frame Map Table](../core/kernel/docs/memory-internals.md#frame-map-table)).
`SYS_CAP_INFO`'s mappings count (see [Cap introspection](#cap-introspection)) falls
to the server's own mappings once the client's are gone, so the server reuses the
page only then.

Init moves its RAM Memory caps to memmgr, which holds each one alone and
thereafter owns userspace RAM frame allocation and answers `REQUEST_MEMORY_CAPS`
for every std-built service. See
[`userspace-memory-model.md`](userspace-memory-model.md) and
[`services/memmgr/README.md`](../services/memmgr/README.md). Mmio caps
follow a separate flow through devmgr; see
[`device-management.md`](device-management.md).

### Address Space

A capability to a process's virtual address space. Rights:
- **Map** — may install and remove mappings in this address space
- **Read** — may inspect current mappings (`SYS_ASPACE_QUERY`, which returns
  their physical addresses); minted on init's kernel-created address space and,
  for an address space retyped later, only when its Memory cap carries `Phys`
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
- **Mint** — may mint a message-signaled Interrupt capability (`SYS_IRQ_MSG_ALLOC`), route a
  wired line (`SYS_IRQ_ROUTE`; a single-line cap), and switch interrupt remapping
  (`SYS_IRQ_REMAP`)

The holder routes the line with `SYS_IRQ_ROUTE`, passing its trigger and polarity mode, which
the route records and every binding on the line shares, and which makes the capability's object a
holder of the route. It binds a Notification to the routed line with `SYS_IRQ_REGISTER`, a line
not routed being refused; each interrupt ORs bit 0 into that Notification, and the holder
re-enables the line with `SYS_IRQ_ACK`. The line is released once neither a route holder nor a
binding remains.

Every Interrupt capability references an object of its own, as for [Mmio](#mmio): a copy or
derivation references a fresh object over the same range, bounded the same way, and that object
carries the capability's binding of its line. Register and acknowledge act on the binding of the
capability's own object, so several capabilities to one line are each a binding: every interrupt
signals each bound Notification, and the line is re-enabled only once every binding has
acknowledged. A line holds at most 64 bindings, and a further registration returns `QuotaExceeded`.
When an Interrupt capability goes (deleted, consumed by a split, or revoked through an ancestor),
its object is freed and its binding removed, while the other capabilities' bindings to the line
stay; a binding holds a reference on its Notification, so a Notification whose capabilities are all
deleted lives on while a binding names it; a line whose remaining bindings owe no acknowledgement is
re-enabled then, so a receiver that goes cannot hold a shared line masked. The binding semantics are
specified in [core/kernel/docs/syscalls.md](../core/kernel/docs/syscalls.md) § `SYS_IRQ_REGISTER`
and § `SYS_IRQ_ACK`; the route, in § `SYS_IRQ_ROUTE`.

The kernel mints one root Interrupt range capability at boot that covers every IRQ id on the
architecture, with Notify and Mint rights, and places it in init's CSpace. Init keeps the root and
hands devmgr a full-rights derivation, from which devmgr splits single-line children with
`SYS_IRQ_SPLIT` for the drivers, routing each line through its split cap. devmgr attenuates the
capabilities it gives drivers to Notify only, so no driver holds Mint.

`SYS_IRQ_MSG_ALLOC` mints, through an Interrupt capability carrying Mint, one unbound
message-signaled Interrupt capability. It names one source id past every wired line and carries
Notify only, never Mint. It is a derivation child of the authority, so revoking the authority
deletes it. Its target is a delivery slot of one CPU: a device vector on x86-64, an interrupt
identity in a hart's IMSIC file on riscv64. The target's state is the lineage root of that
capability, funded from the minting CSpace's pool and returned there when the last capability to
the target is gone. The holder reads the message address and data with
`SYS_CAP_INFO` (`CAP_INFO_IRQ_MSG_ADDRESS`, `CAP_INFO_IRQ_MSG_DATA`), programs them into the
device's MSI or MSI-X entry, and binds with `SYS_IRQ_REGISTER` (mode 0, one binding only). The
kernel never masks a message target, and `SYS_IRQ_ACK` on it changes nothing: masking is the
device's. The target is freed for a later mint once neither the capability nor any copy of it
remains. The call's semantics are specified in
[core/kernel/docs/syscalls.md](../core/kernel/docs/syscalls.md) § `SYS_IRQ_MSG_ALLOC`.

### Mmio

A capability to a specific physical address range (an MMIO aperture) used for
memory-mapped I/O. Rights:
- **Map** — may map the region into an address space
- **Write** — may map the region writable (`sys_mmio_map` gates mapping
  writability on it, and `sys_mem_protect` never makes the page writable without it; MMIO
  mappings are never executable)

Without this capability a process cannot map physical addresses — it cannot
name hardware it has not been granted access to.

Every Mmio capability references an object of its own: a copy or derivation of one
(`SYS_CAP_COPY`, `SYS_CAP_DERIVE`, `SYS_CAP_DERIVE_BADGE`) references a fresh object over
the same range, and the object records each `SYS_MMIO_MAP` mapping made through the
capability. When the capability goes — deleted, consumed by a split, or revoked through an
ancestor — its object is freed and every mapping made through it is unmapped, with TLB
shootdown, before the deleting or revoking call returns, unless a concurrent syscall still
holds the object (any syscall naming the capability pins it), in which case all of its
mappings are unmapped when that syscall releases it. A page the address space has since
remapped to other memory is left alone. The revoked capability itself is preserved (see
[Revocation](#revocation)), so mappings made through it remain. Each recorded mapping holds
a reference on its address space, so an address space an Mmio capability's object has mapped
into outlives its own last capability until that Mmio object is freed. A copy's object is
funded by the `CSpace` that receives it, so a range's copies are bounded only by the memory their
holders donate (and the lineage count's encoding, 2^31 - 1 live copies, past which a copy returns
`QuotaExceeded`).

Any holder of an ancestor capability, in any process, can withdraw a mapping this way, so
the soundness obligation sits on the mapper: the userspace `mmio_map` wrapper is `unsafe`, and
its contract has the caller reach the mapping only through raw-pointer accesses,
never through a Rust reference, which is why the `cap_delete`, `cap_revoke`, and `mmio_split`
wrappers stay safe functions ([shared/syscall/README.md](../shared/syscall/README.md)).

### Thread

A capability to a thread. Rights:
- **Control** — may start, stop, and configure the thread, write its registers, and read and
  write the memory of the address space it executes in (`SYS_THREAD_READ_MEM`,
  `SYS_THREAD_WRITE_MEM`; [Fault Handling § Debugging](fault-handling.md#debugging))
- **Observe** — may read the thread's register state (for debugging)
- **Upcall** — may post an asynchronous upcall to the thread
  ([Fault Handling § Asynchronous Upcalls](fault-handling.md#asynchronous-upcalls)); a post that
  may be delivered at any instruction also needs Control

The memory access sits under Control, not Observe: a thread's registers show what the thread is
doing, but its address space holds whatever the process keeps, its secrets included, so reading
it is as much authority over the process as rewriting its registers, which already lets the holder
make the thread load and disclose any of that memory. The access reaches only the thread's own
address space, and needs no `AddressSpace` capability. A write to a page the thread's mapping makes
read-only (its text) is refused unless asked for; refused outright on a page mapped through a
capability with neither Write nor Execute (a firmware table, a page lent read-only), whose
contents no capability lets the holder change or run (§ Memory); and refused outright on a frame
mapped more than once, which could be another process's.

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

The kernel mints one root IoPort capability over the full 64K port space at boot (x86-64 only);
IoPort capabilities are not creatable at runtime. Init keeps the root and hands devmgr a full-rights
derivation, and devmgr narrows it with `SYS_IOPORT_SPLIT` and gives each driver only its assigned
port range (see
[services/devmgr/docs/responsibilities.md](../services/devmgr/docs/responsibilities.md)). devmgr's
`QUERY_SHUTDOWN_DEVICE` also serves the FADT's 2-port PM1a control window plus the 8042 reset
port, only to a caller whose badge carries `SHUTDOWN_DEVICE_AUTHORITY`: the seed-only
`devmgr.shutdown` cap, which pwrmgr alone seeds and svcmgr's `QUERY_ENDPOINT` refuses.

Every IoPort capability references an object of its own, as for [Mmio](#mmio): a copy or
derivation references a fresh object over the same range, funded the same way. Each thread
records its bindings against the objects they were made through. When an IoPort capability
goes — deleted, consumed by a split, or revoked through an ancestor — the kernel withdraws
every binding made through it from every bound thread, rebuilding each thread's I/O
permission bitmap from the bindings that remain, so a port another live binding grants stays
permitted. Before the deleting or revoking call returns, every CPU's TSS bitmap is
invalidated, so a bound thread running on another CPU reloads its current bitmap at its next
port access and a withdrawn port faults. As for Mmio, while a concurrent syscall holds the
object, its bindings are withdrawn when that syscall releases it. The revoked capability
itself is preserved (see [Revocation](#revocation)), so bindings made through it remain.

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

The kernel mints the root cap once at boot, carrying every sanctioned right, into init's cspace.
**init is reaped after bootstrap, so any right not transferred to a surviving service before the
reap is unforwardable until the next boot: the cap stays in init's CSpace and is released when the
reap frees that CSpace (see [process-lifecycle.md § Init reap](process-lifecycle.md#init-reap)).
This, not a kernel wall, is
what bounds the live extension set.** init transfers a cap narrowed to **Reset** + **Suspend** to
devmgr, the steady-state holder of platform firmware authority (it sits alongside the ACPI / MMIO /
IRQ resources devmgr already brokers). The remaining sanctioned rights are carried into no surviving
cap and are unreachable after init's reap: **Dbcn** is thrown away by design (the userspace serial
driver owns the console; forwarding the firmware console would bypass the console-ownership model),
and **Cppc** / **Base** / **Pmu** are simply not needed by any current service. devmgr serves pwrmgr
a derivation further narrowed to **Reset** only (system reset / reboot), gated on the
`SHUTDOWN_DEVICE_AUTHORITY` badge bit that only pwrmgr's seed-only `devmgr.shutdown` cap
carries; **Suspend** is retained against a future power-management path but delegated to no one
today. See
[services/devmgr/docs/responsibilities.md](../services/devmgr/docs/responsibilities.md).

**Gating-granularity decision.** Per-cap authority is encoded as rights bits, not
an EID set carried by `SbiControlObject`, because the extension set is small and
non-numeric and only one actuating consumer exists (pwrmgr, SRST-only).
`SbiControlObject` carries no fields, and its init descriptor has `aux0 = aux1 = 0`.
Rights are scoped
per capability type, so `SbiControl` draws on its own full 16-bit space —
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
remainder (`[29, PRIORITY_MAX]`) that never leaves init and is unreachable after its reap
(see § SbiControl above).
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
now reference the object independently. An Mmio, IoPort, or Interrupt capability is the
exception: its derivation or copy references a fresh object over the same range (see
[Mmio](#mmio)).

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

Kernel-synthesized fault messages carry the same guarantee: their badge is the derivation
badge of the Endpoint cap bound by `SYS_THREAD_SET_FAULT_HANDLER`, or a copy of another
thread's binding (`SYS_THREAD_INHERIT_FAULT_HANDLER`), so a binder can make the kernel stamp a
fault only with the badge of a cap it holds or of a binding of a thread it holds `CONTROL` on;
see [fault-handling.md § Security](fault-handling.md#security).

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
replies `UNAUTHORIZED` otherwise. The verb-bits in use are bits 58 through 63
(`ipc::VERB_BIT_MASK`). On an endpoint that gates labels this way, a
minter that hands out badges carrying other information keeps them clear:
procmgr's random per-process badge, stamped on every SEND procmgr mints
for a child (its procmgr, registry, and log SENDs) and on its process
handle, is redrawn until none of them is set; the handle alone also
carries a verb-bit procmgr sets itself,
`procmgr_labels::PROCESS_HANDLE_TAG`, which tells it from the child's own
procmgr SEND ([procmgr IPC Interface](../services/procmgr/docs/ipc-interface.md)
§ Messages). An un-badged SEND on such an endpoint stays with the server
and its trusted minters, since its holder could badge it with any
verb-bit. svcmgr's `QUERY_ENDPOINT` answers every
process, so a queryable verb-bit cap would be ambient: a verb-bit cap
svcmgr publishes itself (its well-known names and each provider's
`provides` names) is seed-only, reaching only the recipes that seed it,
and a name published through `PUBLISH_ENDPOINT` is always public, so an
external publisher MUST NOT publish a verb-bit cap there
([services/svcmgr/docs/ipc-interface.md](../services/svcmgr/docs/ipc-interface.md)
§ Label 3 and § Label 4).

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
now-stale handle fail closed rather than alias a recycled slot (#349); a syscall already
in flight on the object is not covered (see [Revocation](#revocation)). (A move within the
same CSpace likewise keeps the source's position.) To delegate a capability while
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

After revocation, any process that held a derived capability can no longer use it.
MMIO mappings and IoPort bindings made through a revoked descendant are withdrawn (see
[Mmio](#mmio) and [IoPort](#ioport-x86-64-only)); an established Memory mapping outlives
it (see [Memory](#memory)). The target's
kernel object is not destroyed, because the preserved target slot still references it.
A descendant that references a distinct object, such as a range-split child, frees that
object when its last reference goes.

A descendant delivered to another CSpace — by **IPC transfer**, `SYS_CAP_MOVE`, or
`SYS_CAP_COPY` — keeps its position in the derivation tree (see
[Transfer](#transfer)), so the revoke reaches it across the boundary and frees the
recipient's slot in the recipient's own CSpace. Per-slot generation handles ensure
the recipient's now-stale handle then fails with `InvalidCapability` rather than
aliasing a recycled slot index — the cross-CSpace stale-slot alias that was the #349
hazard. See [capability-internals.md](../core/kernel/docs/capability-internals.md)
§ Capability Transfer in IPC. A syscall already in flight on the object holds a reference on it
until the syscall stops using it, so the revoke frees the object only after that syscall is done
with it (see
[capability-internals.md](../core/kernel/docs/capability-internals.md#storage-hybrid-radix-directory)
§ Storage: Hybrid Radix Directory).

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
SYS_CAP_CREATE_THREAD(memory, aspace, cspace, sched, priority)
                                              → thread_cap       (Control + Observe + Upcall)
SYS_CAP_CREATE_ASPACE(memory, augment, pages) → aspace_cap       (Map + Control [+ Read])
SYS_CAP_CREATE_CSPACE(memory, augment, pages) → cspace_cap       (Insert + Delete + Derive)
SYS_CAP_CREATE_WAIT_SET(memory)               → wait_set_cap     (Modify + Wait)
```

The kernel rejects creation if the Memory cap lacks `Retype` rights or
if its available-bytes ledger has insufficient room for the requested
object. The returned capability is placed in a free slot in the caller's
CSpace. The caller receives the rights listed above: an address space carries
the bracketed Read only when the Memory cap it is retyped from carries `Phys`
(§ Address Space),
and a freshly created CSpace capability carries no Revoke right.

The kernel records capability lineage in the derivation tree and object lifetime in a
per-object reference count over capabilities and kernel-internal references (see
[capability-internals.md](../core/kernel/docs/capability-internals.md#kernel-object-reference-counting)
§ Kernel Object Reference Counting). When that count reaches zero, the kernel reclaims the
object's bytes, returning them to the Memory cap from which the object was retyped. Objects do
not outlive all references to them.

---

## Typed Memory

Every kernel object's backing storage is accounted to a specific Memory
capability. There is no ambient kernel pool from which a process can
draw kernel-object memory; a process can only create kernel objects
against Memory caps it holds with `Retype` rights. The exceptions are
the objects a syscall creates with no Memory cap to name: range-split
children, Mmio, IoPort, and Interrupt copies, spilled Mmio mapping records,
and per-thread port-binding tables. The `CSpace` the call inserts into or
resolves through, or a bound thread's own `CSpace` for its port-binding
table, funds them from the pages donated to it, as it funds its slots (see
[Address-space and CSpace growth budgets](#address-space-and-cspace-growth-budgets)).
The kernel's own SEED reserve backs only the objects the boot mints.

Kernel objects and user mappings never share a page, in either order. A Memory capability
cannot map bytes it has retyped into kernel objects: retype carves a cap's region upward from its
first byte, so every live kernel object retyped from it lies below its retype bump cursor, and
`mem_map` refuses any range that starts below that cursor, rounded up to a page (the same bound
`SYS_MEMORY_SPLIT` applies). Nor can a retype carve a page that is already mapped: the kernel
counts the user mappings of every frame of RAM, and a retype whose cursor would advance over a
page any address space maps, through any capability to it, fails with `OutOfMemory` and changes
nothing; the page is retypable again once its last mapping is unmapped or its address space is
destroyed. So kernel state carved from donated memory (slot pages, page tables, wrapper and
page-pool record pages) is never reachable through a user mapping, whichever came first, and
whatever splits and merges the region went through between them (see
[core/kernel/docs/memory-internals.md](../core/kernel/docs/memory-internals.md#frame-map-table)
§ Frame Map Table).

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

When a kernel object's reference count reaches zero (its capabilities and every
kernel-internal reference to it are released), the kernel reclaims its bytes back to the
Memory capability the object was retyped from. If the source Memory cap's
own reference count then reaches zero, the reclamation cascades upward
through the derivation chain. Process death is an instance of this
cascade: revoking a child's CSpace destroys all caps the child held,
which deallocates every kernel object only the child referenced, which
credits each object's bytes back to the Memory cap it was retyped from.
An object the child created that another process still references (a
capability to it, or a kernel-internal reference such as a wait-set
membership or an interrupt binding) is not destroyed: it lives on until its last reference goes,
its bytes stay debited from its source Memory object, and a capability to
it keeps working as before. memmgr returns the child's frames to its pool
when procmgr sends `PROCESS_DIED`, except a frame such an object still
occupies, another process still holds a capability to, or another address
space still maps, which memmgr holds out of the pool until none holds (see
[services/memmgr/docs/memory-pool.md](../services/memmgr/docs/memory-pool.md#reclamation)
§ Reclamation and [userspace-memory-model.md](userspace-memory-model.md)).

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

A `CSpace`'s budget also funds the kernel objects a syscall inserting into
or resolving through it creates without a Memory cap (split children,
range-capability copies, spilled mapping records, and the port-binding
tables of its threads), so such a call returns the refillable `OutOfMemory`
when the budget is spent; a funder therefore keeps a page of budget beyond
the slots it funds. A split child or copy can outlive the `CSpace` when its
capability moves elsewhere: a dead `CSpace` returns its donations at once
but for the pages such bodies sit on, each of which stays held to its
Memory cap until its last body goes, the analogue of a retyped object
pinning its Memory cap (see
[capability-internals.md](../core/kernel/docs/capability-internals.md)
§ Body Arena).

A `CSpace` has two independent growth bounds, distinguishable by error
code at the failure site:

- **Pool exhaustion** — the seeded slot-page pool is empty. Returns
  `OutOfMemory` (-8); refillable via augment mode. The kernel also logs
  the CSpace id, allocated count, and occurrence count on power-of-two
  occurrences.
- **Structural ceiling** — the slot directory is full. Returns
  `QuotaExceeded` (-17); the bound of the handle's index field, which the
  directory reaches (see
  [capability-internals.md](../core/kernel/docs/capability-internals.md)
  § Storage: Hybrid Radix Directory), and which no memory donation can lift.

Both bounds meet general allocations first: every `CSpace` keeps its
last `CSPACE_IPC_RECV_RESERVE` free slots (one message's
`MSG_CAP_SLOTS_MAX`) for IPC capability transfer. A `cap_create_*`,
`cap_copy`, `cap_derive`, split, or `cap_move` that would take one of
them fails as above while the reserved slots stay free, so a process
whose general slots are exhausted still receives a cap-bearing message
or reply. Received caps then spend the reserve, and only a receive into
a spent reserve fails before blocking (see
[capability-internals.md](../core/kernel/docs/capability-internals.md)
§ IPC Receive Reserve and [ipc-design.md](ipc-design.md)
§ Receive-Failure Policy).

There is no per-CSpace slot quota: capacity below the structural
ceiling is exactly what the paid pool backs. Containing a child's cap
footprint is a memory-distribution decision — a supervisor that wants a
child bounded gives it less memory to fund growth with — not a kernel
knob.

Seeding policy: a CSpace creation site seeds the pool for the process's
expected startup population; a process that outgrows its seed self-funds
via augment-mode `cap_create_cspace` against its own `CSpace` cap. The
current backed capacity is observable via `SYS_CAP_INFO`
(`CAP_INFO_CSPACE_CAPACITY`); subtracting slots used
(`CAP_INFO_CSPACE_USED`) and the IPC receive reserve yields the headroom
general allocations may still take; ruststd's `fund_cspace_slot_budget`
tops it up (see [runtime/ruststd/README.md](../runtime/ruststd/README.md)
§ CSpace slot headroom).

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
retype-rights flag, physical base (to a holder of the `Phys` right only, see
[Memory](#memory)), and the number of user mappings of its pages (for a
window of at most 512 pages per query) for Memory caps; lifecycle state and
exit reason for Thread caps; PT growth budget for AddressSpace caps; backed
slot capacity, slots used, and growth budget for CSpace caps; whether the
queried slot is the only reference to its object, for a cap of any type; plus
two system-wide tagged-TLB diagnostic counters.
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
- Mmio capabilities (Map | Write), one per `BootInfo.mmio_apertures` entry Phase 6 validates,
  plus one over the kernel console UART on RISC-V
- One root Interrupt range capability (Notify and Mint) covering every valid IRQ id on the
  architecture
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
`AddressSpace` (the delete then never returns to it, unless another thread's syscall still pins the
object, in which case the stop follows when that syscall releases it, or an Mmio capability's object
records a mapping into that `AddressSpace`, in which case the stop follows when that Mmio object is
freed; see [Mmio](#mmio)). The process's resources are
reclaimed as their capability reference counts reach zero; an object another thread's syscall is
still using is freed only once that syscall is done with it (see
[capability-internals.md](../core/kernel/docs/capability-internals.md#storage-hybrid-radix-directory)
§ Storage: Hybrid Radix Directory and
[thread-lifecycle-and-sleep.md](../core/kernel/docs/thread-lifecycle-and-sleep.md#dealloc_objectthread-drain-protocol)
§ `dealloc_object(Thread)` Drain Protocol, step 11).

Beyond that stop, the kernel's role in death is *notification*. An `AddressSpace` carries a
death-observer set (mirroring the per-thread death observers). A fault of a thread's own access is
terminal when:

- no fault handler is bound;
- the handler replies `KILL`;
- the fault episode is cancelled: by destruction of the handler thread (deletion of its last
  Thread capability), by destruction of the handler endpoint while the fault is still queued on it,
  or by a later receive on the handler thread that passes its capability and headroom checks while
  the fault reply is pending; or
- the faulting thread is stopped before any reply claims the fault, which cancels the episode.

On a terminal fault by any thread in the address space, the kernel posts the fault class
(`EXIT_FAULT_BASE + vector` on x86-64, `EXIT_FAULT_BASE + cause` on riscv64) to each bound observer
and exits the faulting thread. A stopped faulting thread is the exception in timing only: whether
the stop cancelled the episode or a `KILL` reply had already claimed it, the terminal fault takes
effect, and is posted, only if the thread is started again (see
[Fault Handling](fault-handling.md#delivery-resume-and-kill)). The fault of a restartable syscall's
copy of a user buffer is never terminal: in each of the cases above it fails that syscall with
`InvalidAddress`, the thread runs on, and nothing is posted (see
[Fault Handling § Kernel Copies](fault-handling.md#kernel-copies)).

procmgr binds such an observer at process creation, so a fatal fault on any thread — a worker, not
just the main thread — drives procmgr's teardown of the whole process. A worker's fault fails to
drive that teardown at once only when a full procmgr death queue drops its post, and then
procmgr's next drain recovers it: it reads the main-thread deaths it missed from the kernel's
thread states, and the terminal faults from each address space's retained terminal-fault reason
(`CAP_INFO_ASPACE_TERMINAL_FAULT`; see
[services/procmgr/README.md](../services/procmgr/README.md) § Process table and death queues).
Normal thread exit does not fire these observers.

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
[Firmware Parsing](../core/boot/docs/firmware-parsing.md),
[Capability Subsystem Internals](../core/kernel/docs/capability-internals.md),
[Kernel Cross-Boundary Disclosure Inventory](../core/kernel/docs/cross-boundary-disclosure.md),
[Kernel Initialization Sequence](../core/kernel/docs/initialization.md),
[Scheduler Internals](../core/kernel/docs/scheduler.md),
[Syscall Interface Specification](../core/kernel/docs/syscalls.md),
[Architecture Overview](architecture.md), [System Bootstrap](bootstrap.md),
[Device Management](device-management.md), [IPC Design](ipc-design.md),
[Memory Model](memory-model.md), [Namespace Model](namespace-model.md),
[Process Lifecycle](process-lifecycle.md), [Storage](storage.md),
[Supervision](supervision.md),
[programs/capexhaust/README.md](../programs/capexhaust/README.md),
[programs/threadstack/README.md](../programs/threadstack/README.md),
[runtime/ruststd/README.md](../runtime/ruststd/README.md),
[init Bootstrap Stages](../services/init/docs/bootstrap.md),
[services/memmgr/README.md](../services/memmgr/README.md),
[memmgr IPC Interface](../services/memmgr/docs/ipc-interface.md),
[memmgr Memory Pool](../services/memmgr/docs/memory-pool.md),
[services/procmgr/README.md](../services/procmgr/README.md),
[procmgr IPC Interface](../services/procmgr/docs/ipc-interface.md),
[svcmgr IPC Interface](../services/svcmgr/docs/ipc-interface.md),
[Synthetic Root and Namespace Composition](../services/vfsd/docs/namespace-composition.md),
[shared/namespace-protocol/README.md](../shared/namespace-protocol/README.md)
