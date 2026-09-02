# Capability Subsystem Internals

This document covers the implementation of the capability subsystem. The design —
capability types, rights, derivation, revocation, and transfer semantics — is
specified in [docs/capability-model.md](../../../docs/capability-model.md). This document
covers the data structures and algorithms that realise those semantics.

The capability subsystem comprises three components:

1. **CSpace** — per-process capability space (slot storage and lookup)
2. **Capability slot** — in-memory representation of one capability
3. **Derivation tree** — cross-process tree for revocation

---

## CSpace Implementation (`cap/cspace.rs`)

### Design Constraints

From the design document:

- O(1) lookup — descriptor-to-slot resolution on every IPC call
- Stable indices — a descriptor never changes after assignment
- Grows on demand — no upfront size prediction needed
- Pay-as-you-go — every slot page is drawn from a pool the owner funded
  with its own Memory caps, so per-process kernel memory is bounded by
  what the process paid for

### Storage: Hybrid Two-Level Radix

The CSpace is a hybrid radix: an inline root of leaf pointers plus
pool-allocated directory pages fanning out to further leaves (similar to a
page table with a large root):

```rust
pub struct CSpace
{
    /// Direct region: inline pointers to the first L1_DIRECT leaf pages.
    direct: [AtomicPtr<CSpacePage>; L1_DIRECT],
    /// Indirect region: inline pointers to pool-allocated directory pages,
    /// each fanning out to DIR_FANOUT further leaves.
    indirect: [AtomicPtr<CSpaceDirPage>; L1_INDIRECT],
    /// Grow cursor: leaves 0..next_leaf are allocated, contiguously.
    next_leaf: u32,
    /// Total number of slots currently allocated (not necessarily in use).
    allocated_slots: usize,
}

/// One page of CSpace slots (a leaf).
struct CSpacePage
{
    slots: [CapabilitySlot; L2_SIZE],
}

/// One pool-allocated directory page: DIR_FANOUT leaf pointers.
struct CSpaceDirPage
{
    entries: [AtomicPtr<CSpacePage>; DIR_FANOUT],
}
```

The concrete values of `L1_DIRECT`, `L1_INDIRECT`, `DIR_FANOUT`, and
`L2_SIZE` are implementation constants chosen so that one `CSpacePage` fits
a single pool page, one `CSpaceDirPage` is exactly one pool page, and every
slot index fits the cap handle's index field. They are established at
implementation time and are not part of the public ABI.
`(L1_DIRECT + L1_INDIRECT × DIR_FANOUT) × L2_SIZE` is the directory's
structural ceiling — the only slot bound a CSpace has; capacity below it is
whatever the owner-funded slot-page pool backs.

**Lookup is O(1):** A descriptor `d` selects leaf `d / L2_SIZE` and slot
`d % L2_SIZE`. Leaves below `L1_DIRECT` resolve through the inline root
(two dereferences); higher leaves resolve through one directory page
(three dereferences). No hash, no search.

**Growth is O(1) and strictly ordered:** leaves are materialised in index
order behind the `next_leaf` cursor, so allocated leaves are always the
contiguous range `0..next_leaf`. A grow into the indirect region first
materialises the covering directory page from the same owner-funded pool
(roughly one extra pool page per `DIR_FANOUT` leaves); a directory page
that outlives a failed leaf allocation stays published — already paid for,
it serves the next grow. Pages are never freed while the CSpace is live
(slot indices must remain stable).

**Memory ordering and lock domains:** directory and leaf pointers are
write-once while the CSpace is live, published with Release after full
initialisation, and read with Acquire by the lock-free lookup path
(`lookup_cap`, `cap_info`). Mutation is split across two lock domains:
slot occupancy, the free list, the directory, and the counters change
only under the CSpace spinlock, while the derivation linkage of occupied
slots changes only under the global derivation write lock (which reaches
any registered CSpace's slots via registry lookup without taking its
spinlock — see Derivation Tree below). Paths crossing the families hold
the derivation lock outermost, then the spinlock. Races on slot content
against the unlocked readers are narrowed — not closed — by the tag and
per-slot generation checks at the resolution sites; the residual is
confined to threads of the owning process racing each other.

**Slot 0** is always null. The leaf covering slot 0 exists once the CSpace
has grown, but the slot is permanently locked to the null capability,
enforced at the lookup level.

### Free Slot Tracking

A free list of available slot indices is maintained intrusively, with its head in
kernel memory:

```rust
pub struct CSpace
{
    // ... (above fields)
    free_head: Option<NonZeroU32>, // head of the intrusive free list (None = empty)
    free_count: usize,             // slots currently on the free list (O(1) queries)
}
```

A free slot is `CapTag::Null` and encodes its successor's index in the `deriv_parent`
field and its predecessor's in `deriv_first_child` (both derivation fields are
meaningless on an empty slot); `None` marks the list tail and the list head
respectively. The encoded `SlotId` carries `epoch == 0`, which a live derivation
link never does, so the two uses stay distinguishable. The predecessor link makes
`remove_from_free_list` — the explicit-placement path that unlinks an arbitrary
index — O(1); a list walk would run under the CSpace spinlock with interrupts
disabled. Allocation pops `free_head` and clears the slot; deallocation pushes onto
the head. When the list is empty and more slots are needed, the next leaf page is
allocated and all its usable slots are threaded onto the list.

A `Null` tag alone cannot tell a slot that is *linked on the free list* from one that
was just allocated and not yet populated, and the list tail is byte-identical to a
cleared slot. Each linked slot therefore also carries an on-free-list marker in
`CapabilitySlot.pad[0]`; `is_on_free_list()` reports membership in O(1) from
`tag == Null && pad[0] == marker`. `free_slot` consults it to reject a double-free of
any slot — re-pushing a slot already on the list would splice it in twice and cycle
the list, after which allocation could hand back an occupied slot. The marker is set
when a slot is linked (`set_next_free`) and cleared when it leaves the list (on
allocation, and when `remove_from_free_list` unlinks a specific index);
`allocate_slot` debug-asserts the popped slot was a genuine member.

This gives amortised O(1) allocation and O(1) deallocation.

---

## Capability Slot (`cap/slot.rs`)

### Representation

```rust
pub struct CapabilitySlot
{
    /// Discriminant identifying the kind of capability (or Null).
    tag: CapTag,

    /// Rights bitmask for this slot. Interpretation is tag-dependent.
    rights: Rights,

    /// Caller-identifying badge (0 = unbadged). Set via SYS_CAP_DERIVE_BADGE.
    /// Immutable once set; inherited by derivation and copy.
    badge: u64,

    /// Pointer to the kernel object this capability refers to.
    /// Null when tag == CapTag::Null.
    object: Option<NonNull<KernelObject>>,

    /// Derivation tree pointers (intrusive linked list).
    deriv_parent: Option<SlotId>,
    deriv_first_child: Option<SlotId>,
    deriv_next_sibling: Option<SlotId>,
    deriv_prev_sibling: Option<SlotId>,
}
```

The slot is 72 bytes (`#[repr(C)]`). 56 slots per CSpace page = 4032 bytes, fitting
in a 4096-byte slab bin with 64 B of tail slack.

`SlotId` is a global identifier combining a CSpace ID, an epoch generation
tag, and a slot index: `{cspace_id: u32, epoch: u32, index: NonZeroU32}`
(12 bytes; `Option<SlotId>` niche-optimises to the same size via the
`NonZeroU32` index). This allows derivation tree traversal across CSpace
boundaries without holding per-CSpace locks longer than necessary, and lets
`lookup_cspace(id, expected_epoch)` fail fast when a CSpace's id has been
recycled — a stale `SlotId` stamped with the pre-recycle epoch cannot
mis-target the new tenant. As of #248 the epoch is a random non-zero value
redrawn on each recycle (not a monotonic counter); the equality check is
unaffected, and the random redraw excludes the prior value so an
immediately-recycled `SlotId` always fails fast. See #137 for the recycling
allocator design.

### Per-Slot Generation

Each slot carries an 8-bit **generation** counter (in the spare `pad[1]` byte,
keeping the slot at 72 bytes). `CSpace::free_slot` increments it every time the
slot is recycled. The generation is encoded into the capability handle userspace
receives — `handle = (generation << CAP_INDEX_BITS) | index` (see
[capability-model.md](../../../docs/capability-model.md) § Capability Handle
Format) — and `lookup_cap`, together with the raw-resolution handlers in
`cap.rs` / `mem.rs` / `ipc.rs`, rejects a handle whose generation no longer
matches the slot's, returning `InvalidCapability`. This is the #349 fix: a stale
handle that reaches a recycled slot — including a slot a cross-`CSpace` revoke
freed out from under its holder — fails closed instead of aliasing the new
occupant. A never-recycled slot has generation 0, so its handle equals the bare
index — the backward-compatibility hinge that lets long-lived boot caps keep
their historical handle values.

The generation is distinct from `SlotId.epoch` (the per-`CSpace`-registry
counter) and from the `pad[0]` free-list marker. It must survive the
free→reallocate transition: `free_slot` bumps it *before* threading the slot onto
the free list, `set_next_free` preserves `pad[1]`, and `allocate_slot` clears the
slot with `clear_keep_generation` (which keeps `pad[1]`). The 8-bit counter wraps
after 256 recycles of one index — a bounded ABA window: on wrap a replayed handle
is no better protected than under the pre-generation scheme, and no worse. The
generation byte `pad[1]` plus the spare `pad[2]` leave a one-step widening to a
16-bit generation if churn ever makes 256 marginal.

### Capability Tags

```rust
#[repr(u8)]
pub enum CapTag
{
    Null          = 0,
    Memory        = 1,   // memory authority (Untyped/retype source)
    AddressSpace  = 2,
    Endpoint      = 3,
    Notification  = 4,   // bitmask-based async notification
    EventQueue    = 5,
    Interrupt     = 6,
    Mmio          = 7,   // memory-mapped I/O region
    Thread        = 8,
    CSpace        = 9,   // capability space; explicit kernel object
    WaitSet       = 10,
    IoPort        = 11,  // x86-64 only; created at boot from platform_resources
    SchedControl  = 12,  // priority-band authority; carries [min, max], no rights bit
    SbiControl    = 13,  // SBI forwarding authority (RISC-V only)
}
```

### Rights Bitmask

Rights are scoped per capability type: each slot stores one 32-bit erased rights
word (`Rights`), and the slot's `CapTag` selects which type's vocabulary
interprets it. Every type numbers its bits from 0 in its own full-width space.
The `u64` `RIGHTS_*` constants in `abi/syscall` are the single source of truth
for bit values; the kernel defines a `TypedRights<K: CapKind>` newtype per type
(`MemRights`, `EpRights`, `NtfRights`, ...) whose constants are derived from the
ABI values, so a rights constant of the wrong capability type cannot be passed
to a lookup at compile time.

Per-type vocabularies (bit positions within each type's own space):

```text
Memory        MAP=0  WRITE=1  EXECUTE=2  RETYPE=3
AddressSpace  MAP=0  READ=1   CONTROL=2
Endpoint      SEND=0 RECEIVE=1 GRANT=2
Notification  NOTIFY=0 WAIT=1
EventQueue    POST=0 RECV=1
Interrupt     NOTIFY=0
Mmio          MAP=0  WRITE=1
Thread        CONTROL=0 OBSERVE=1
CSpace        INSERT=0 DELETE=1 DERIVE=2 REVOKE=3
WaitSet       MODIFY=0 WAIT=1
IoPort        USE=0
SchedControl  (no rights bits: presence + [min, max] band is the authority)
SbiControl    RESET=0 SUSPEND=1 CPPC=2 BASE=3 DBCN=4 PMU=5
```

Rights are checked at every syscall that uses a capability. The check is a single
bitwise AND: `(slot.rights & required) == required`.

W^X enforcement at mapping time (`mem_map`, `mem_protect`):

```rust
fn check_wx(rights: Rights) -> Result<(), SyscallError>
{
    if rights.contains((MemRights::WRITE | MemRights::EXECUTE).erase())
    {
        Err(SyscallError::WxViolation)
    } else
    {
        Ok(())
    }
}
```

A capability may carry both Write and Execute rights (representing independent
authorities). W^X is enforced when those rights are exercised on a specific
mapping — no page may be simultaneously writable and executable.

### Kernel Object Reference Counting

Each kernel object (Endpoint, Notification, EventQueue, etc.) has an embedded reference
count representing the number of capability slots that point to it:

```rust
pub struct KernelObjectHeader
{
    ref_count: AtomicU32,
    kind: ObjectKind,
}
```

When a slot is cleared (deletion, revocation), the reference count is decremented.
When it reaches zero, the object is freed to its slab cache. This is the only
mechanism by which kernel objects are freed — there is no explicit "destroy" syscall.

The same refcount also tracks kernel-internal owners of an object. Wait-set
membership is one such owner: `sys_wait_set_add` `inc_ref`s the source's
header under the source's lock together with the back-pointer publication;
`sys_wait_set_remove` and `wait_set_drop` perform the matching `dec_ref`. The
source's state therefore outlives every wait-set member referencing it; the
Endpoint/Notification/EventQueue dealloc arms only `debug_assert` that
`state.wait_set` is null on entry (the invariant follows from the refcount).

---

## Derivation Tree (`cap/derivation.rs`)

### Structure

The derivation tree is a forest of trees — one tree per root capability (objects
created via `SYS_CAP_CREATE_*`). The tree is stored intrinsically in the capability
slots themselves (the `deriv_parent`, `deriv_first_child`, `deriv_next_sibling`,
`deriv_prev_sibling` fields), so no external tree allocation is needed.

This is an intrusive N-ary tree using child-sibling representation:

```
root_cap (no parent)
├── derived_A (first child of root)
│   ├── derived_A1 (first child of A)
│   └── derived_A2 (next sibling of A1)
└── derived_B (next sibling of A)
    └── derived_B1 (first child of B)
```

**Transfer** does not create a new derivation tree node — the transferred slot
inherits the donor's position in the tree. The donor's slot becomes null.

**Derivation** creates a new node as a child of the source slot in the tree.

### Global Derivation Lock

A single global reader-writer lock protects derivation tree modifications. Multiple
readers may hold it simultaneously for traversal (during `SYS_CAP_DERIVE`); writers
hold it exclusively during revocation.

This is a deliberate design choice: revocation is rare relative to capability use.
The global lock avoids deadlock from ordering multiple per-CSpace locks.

### Revocation Algorithm

`SYS_CAP_REVOKE` clears the subtree rooted at the target slot in batches of at most
`MAX_REVOKE_EDITS` constant-time tree edits (`revoke_subtree_batch`). Each batch
runs under the derivation tree write lock and repeatedly edits the head `H` of the
root's child list:

- `H` has a child: unlink that child and re-link it directly under the root (a
  *hoist* — it becomes the new list head, ahead of `H`).
- `H` is childless: unlink it, free its slot in its owning `CSpace` (under that
  `CSpace`'s lock), and collect its object for deallocation.

```
revoke(root_handle):
    loop:
        acquire derivation tree write lock
        revalidate root (non-Null, handle generation current); stop if not
        first batch: refuse if the root is already marked revoke-in-progress,
                     else set the marker
        objects, status = revoke_subtree_batch(root) // ≤ MAX_REVOKE_EDITS edits
        final batch (status ≠ MoreWork, or MAX_REVOKE_BATCHES reached):
            clear the marker
        release derivation tree write lock
        dec_ref / dealloc each collected object      // outside the lock
        Cleared → return success; DeadLink → return error;
        backstop reached → return Interrupted; MoreWork → loop

revoke_subtree_batch(root):
    repeat up to MAX_REVOKE_EDITS times:
        H = root.first_child; done if None (Cleared)
        if H has a first child G: unlink G; link G under root   (hoist)
        else: unlink H; free H's slot; collect its object       (free)
```

Every edit is O(1), so a batch holds the write lock for at most
`MAX_REVOKE_EDITS` constant-time steps regardless of the subtree's shape or
depth. Each node is hoisted at most once and freed exactly once, so clearing a
subtree of N nodes costs at most 2N edits across all batches — O(N) total, with
no per-batch re-traversal. Frees never exceed edits, so the same bound sizes the
dealloc output buffer.

Between batches the lock is dropped so collected objects can be deallocated
(`dealloc_object` may take other locks). The walk always operates on the root's
current child list, so children derived concurrently between batches are still
cleared, and the root is revalidated per batch so a root recycled mid-revoke
stops the loop. Every batch that reports more work performed a full budget of
edits, so the loop terminates against any fixed subtree; a concurrent deriver
can extend the work only by spending its own slots and syscalls. A liveness
backstop (`MAX_REVOKE_BATCHES`) bounds the loop unconditionally: it covers more
edits than any subtree plausibly-sized hardware can hold (every node costs its
creator a slot plus a kernel object), so tripping it indicates sustained
concurrent re-derivation and returns `Interrupted` — revoked nodes stay
revoked, and a retry continues from the surviving subtree.

Deletion and the range splits (`SYS_MMIO_SPLIT`, `SYS_IRQ_SPLIT`,
`SYS_IOPORT_SPLIT`, `SYS_SCHED_SPLIT`) consume a slot without revoking
under it: its children are re-linked under its derivation parent
(`reparent_children`) so they stay inside every ancestor's subtree. That
walk is batched on the same terms as revocation — `MAX_REPARENT_EDITS`
head pops per lock hold, each child detached into a clean root and
re-linked in O(1), the lock released between batches, and a
`MAX_REPARENT_BATCHES` backstop against a concurrent deriver — because a
slot can have been derived from up to the structural ceiling of every
CSpace. The consumed slot is revalidated under the lock before every batch
(tag and handle generation, no revoke in flight; the splits additionally
check it still holds the object that was looked up, since their lookup ran
without the lock): a concurrent revoke starting on it stops the delete with
`InvalidState` and children already moved stay under the parent, a
concurrent delete finishing it first turns the delete into a success and a
split into `InvalidState` with both children rolled back. The split's own
children are inserted and linked under the original's parent inside the
first hold, before any batch releases the lock, so they are never reachable
but unlinked — a sibling's `SYS_CAP_MOVE` carries whatever derivation
position it finds, and an unlinked child would leave the grantor's revoke
reach for good. Rolling a child back checks that its slot still holds it
under the generation minted at insert, so a sibling that deleted one (and
refilled its slot) never has an unrelated cap freed. The handles returned to
the caller are the ones minted under the insert's own `CSpace` lock hold, so
such a child's handle no longer resolves; re-reading the slot after the lock
is released would instead return a live handle to the refill.

Because hoisting destroys intermediate parent→child edges as the flattening
proceeds, the root is pinned for the whole multi-batch operation with a
**revoke-in-progress marker** (`CapabilitySlot::revoke_in_progress`, stored in
the slot's spare pad byte, read and written only under the derivation write
lock). `SYS_CAP_DELETE` and `SYS_CAP_MOVE` refuse a marked slot with
`InvalidState`; IPC capability transfer refuses to move one — the reply
direction surfaces `InvalidState` to the server (the caller resumes with
`IPC_REPLY_TRANSFER_FAILED`), the call direction rejects before blocking,
and a refusal detected only post-commit delivers the message with zero
caps (see [docs/ipc-design.md](../../../docs/ipc-design.md) § Message
Format). Deleting or moving the root between batches would promote the
temporarily hoisted survivors and permanently sever the intermediate
holders' revocation authority. The marker is cleared under the lock on
every syscall exit path — completion, dead-link error, and the
`Interrupted` backstop alike — so it cannot leak; a root freed by a
concurrent ancestor revoke sheds the marker with the slot (that ancestor's
revoke clears the hoisted survivors too, since they remain inside its
subtree).

A `CSpace` reaching refcount zero first stops every thread bound to it
(`sched::stop_threads_bound_to`, see
[scheduling-internals.md](scheduling-internals.md) § Thread Registry): each is
marked `Exited` and waited off every CPU before any slot page is freed, so no
thread can be mid-syscall against the dying directory, and none of the dying
process's own threads can touch the derivation forest during the drain below.
If the thread running the teardown is itself stopped — it deleted the last
capability to its own `CSpace`, or a concurrent teardown stopped it — nothing
below runs now: the object is queued for off-CPU reclaim and the whole arm
re-runs from the deferred drain once the thread has been scheduled away.
The same discipline applies to an `AddressSpace` reaching refcount zero.

Every derivation link reachable from a live slot resolves: before a `CSpace`
unregisters, its teardown drain (`drain_dying_cspace_batch`) unlinks every
dying slot from the forest — foreign children are orphaned into derivation
roots, and each slot is spliced out of its parent/sibling links with the
neighbours re-linked directly. Each unlink leaves the forest fully
consistent, so the drain runs in step-bounded batches (every slot visited and every link edit is one step) that release the
derivation write lock between holds (mirroring revocation's batching); a
foreign traversal in a window between batches sees ordinary consistent
nodes. The one remaining source of a dead link is a foreign sender whose
capability transfer into the dying CSpace had already committed to a
receiver there before that receiver was stopped, wiring a link into a slot
the drain cursor has passed. A link that fails to resolve — that race, or
genuine corruption — is contained wherever a walk meets it, always by
truncation: the revoke walk cuts the chain hanging from the dead link, logs
it, and the syscall returns `InvalidState` instead of reporting a clean
revoke; the reparent walk that deletion and the range splits run on the
consumed slot's children cuts and logs the same way and completes (the
abandoned children were already orphaned from a vanished CSpace); the
teardown drain, which has no caller to report to, detects the same condition
as a head pop that makes no progress, logs it, cuts the dying slot's child
list, and continues with the next slot. A drain truncation abandons the foreign children chained
behind the dead link without clearing their parent pointers: they keep
naming the dying CSpace, and only the registry epoch check keeps such a
pointer fail-closed (it resolves to nothing — the child behaves as a
derivation root) rather than aliasing onto a recycled CSpace id.

**Performance characteristics:** Revocation is O(N) in the number of descendants.
For well-behaved systems, derivation trees are shallow (a server derives a
capability for a client; the client rarely re-derives). Deep trees or large
revocations do not appear on latency-sensitive paths.

**Locking during revocation:** While the write lock is held, all other capability
operations on the affected slots are blocked. This is safe because revocation is
intentionally a strong operation — the revoker is asserting that no further access
to the capability is valid. A revocation larger than one batch is not atomic
against readers: between batches, unrevoked descendants remain usable until their
batch frees them, and hoisting is visible — surviving descendants may temporarily
appear as direct children of the root (still descendants of it and of every
ancestor above it, so ancestor revocation reach is preserved). When the syscall
returns successfully with the root still live, the root is childless.

**Deferred IPC cleanup:** The derivation tree write lock is ordered after IPC object
locks (see lock ordering in [ipc-internals.md](ipc-internals.md)). Therefore,
`SYS_CAP_REVOKE` must not acquire IPC object locks while holding the derivation tree
write lock. Revocation collects a set of IPC objects needing cleanup (e.g. endpoints
that have a revoked capability in their send queue), releases the write lock, then
acquires individual IPC object locks to perform cleanup.

### Safe Delegation: the "Derive Twice" Pattern

Revoking a capability via `SYS_CAP_REVOKE` invalidates all its descendants while
preserving the target slot itself. To delegate authority that can later be revoked
without losing your own access:

```
1. Hold capability C (the original).
2. Derive C1 from C — you retain C1 as an intermediary.
3. Derive C2 from C1 — C2 is the delegated capability.
4. Copy C2 into the child's CSpace with SYS_CAP_COPY.
5. To revoke: call SYS_CAP_REVOKE on your slot holding C1.
   This destroys every descendant of C1 — both your C2 and the child's copy.
   You still hold C and C1 with their rights intact, ready to re-delegate.
```

This pattern works because revocation is subtree-local: revoking C1 removes C1's
descendants but leaves C1 itself, C, and any siblings of C1 untouched. Delegation uses
`SYS_CAP_COPY` so you keep your own access to C2 while the child holds a revocable
copy. **IPC transfer** and `SYS_CAP_MOVE` instead hand the slot away — the sender's
slot is freed — but the moved cap keeps its position in the derivation tree (see
[Derivation Across Processes](#derivation-across-processes)), so it stays a
descendant of C1 and a `SYS_CAP_REVOKE` on C1 still reaches it across the `CSpace`
boundary. Revoking C1 frees the child's C2 slot in the child's own `CSpace`;
per-slot generation handles ensure the child's now-stale C2 handle then fails with
`InvalidCapability` instead of aliasing a recycled slot (#349).

### Derivation Across Processes

The hazard a cross-`CSpace` derivation edge creates (#349): `revoke_subtree_batch` walks
derivation edges and `free_slot`s each descendant in its own `CSpace`. If an edge
crosses a `CSpace` boundary, revoking a source's subtree frees a slot in a foreign
`CSpace` that the recipient still legitimately holds — and because cap handles
recycle slot indices, that freed index would then alias an unrelated live object.

Per-slot generation handles make cross-`CSpace` capability sharing safe. Both forms
of cross-`CSpace` sharing keep a derivation edge across the boundary:

- **IPC capability transfer / `SYS_CAP_MOVE`** hand the cap to the recipient and
  free the sender's slot, but the moved cap keeps its position in the derivation
  tree — it stays a descendant of whatever it was derived from, so an ancestor's
  `cap_revoke` reaches it across the boundary. (Same-`CSpace` moves likewise keep
  the source's position.)
- **`SYS_CAP_COPY`** keeps the new cap a derivation **child** of the source (the
  "Derive Twice" pattern above), so the source can revoke the delegated copy.

In both cases a `cap_revoke` can `free_slot` the recipient's slot in its own
`CSpace`. The handle the recipient holds carries the slot's **generation**
(`handle = (generation << CAP_INDEX_BITS) | index`); `free_slot` bumps the
generation, so the recipient's now-stale handle fails with `InvalidCapability`
rather than aliasing whatever later occupies the recycled index. See the per-slot
generation discussion under [Capability Slot](#capability-slot-capslotrs).

`SlotId` encodes `(cspace_id, epoch, slot_index)`. The derivation tree is resolved
by:

```
resolve(slot_id):
    cspace = cspace_table[slot_id.cspace_id]  // O(1) from global table
    return cspace.slot(slot_id.index)         // O(1) lookup (two or three levels)
```

Resolution does not require holding a lock on the target `CSpace` — the derivation
tree write lock is sufficient to prevent concurrent modification.

---

## Initial CSpace Population

During Phase 7 of initialization, the root CSpace is populated as follows.
Slot assignments are fixed by convention and communicated to init via the boot
protocol. Init must not assume specific slot numbers — the kernel passes the
layout via a well-known structure at the top of init's stack.

### Initial Slot Layout (Tentative)

| Slot | Capability |
|---|---|
| 0 | Null (permanent) |
| 1 | Init's own thread capability |
| 2 | Init's own address space capability |
| 3 | Init's own CSpace capability |
| 4 | SchedControl capability (band `[1, PRIORITY_MAX]`) |
| 5..N | Memory capabilities (one per usable physical region) |
| N+1..M | MMIO region capabilities (one per MmioRange / PciEcam entry) |
| M+1..K | Interrupt capabilities (one per IrqLine entry) |
| K+1..L | Read-only Memory capabilities (one per PlatformTable entry) |
| L+1..P | IoPort capabilities (one per IoPort entry; x86-64 only) |
| P+1..Q | Memory capabilities for boot module images (raw ELF for procmgr, devmgr, etc.) |
| Q+1..R | Reclaimable Memory capabilities for bootloader scratch pages (`BootInfo`, descriptor arrays, MMIO aperture array, reclaim-array page, transient page-table frames) and the bundle's non-module pages (header + entry table + pad, init ELF source body, inter-module and trailing slack — module bodies are excluded, covered by the boot-module Memory caps above) — one cap per `BootInfo.reclaim_ranges` entry |

The exact slot numbers are passed to init in the `KernelHandoff` structure placed
on init's user stack before it begins execution.

---

## Capability Transfer in IPC

IPC capability transfer (via `SYS_IPC_CALL` and `SYS_IPC_REPLY` capability slots)
moves all of a message's capabilities or none of them; a refused transfer does
not block message delivery (see
[docs/ipc-design.md](../../../docs/ipc-design.md) § Message Format). The
per-capability move is:

```
transfer_cap(sender, sender_slot_idx, receiver, receiver_slot_idx):
    acquire derivation tree write lock
    src_slot = sender.cspace.slot(sender_slot_idx)
    dst_slot = receiver.cspace.slot(receiver_slot_idx)
    // dst_slot must be null (verified before IPC delivery begins)
    dst_slot.{tag, rights, badge, object} = src_slot.{...}  // copy the cap
    // The moved cap takes the source's position in the derivation tree: its
    // parent, children, and siblings are repointed onto dst_slot, including
    // across the CSpace boundary. That cross-boundary edge is what lets an
    // ancestor's cap_revoke reach the moved cap; per-slot generation (#349)
    // makes the receiver's handle fail closed if such a revoke frees this slot.
    repoint_derivation_links(src_slot_id -> dst_slot_id)
    src_slot.tag = CapTag::Null                    // clear the sender's slot
    src_slot.object = None
    // Note: ref_count does not change (same number of slots reference the object)
    release derivation tree write lock
```

IPC capability transfer is always cross-`CSpace` (sender and receiver are distinct
processes). The transferred cap keeps its position in the derivation tree, so it
remains reachable by a `cap_revoke` on one of its ancestors; per-slot generation
handles make the receiver's handle fail closed if such a revoke frees the
receiver's slot (#349). The derivation write lock is held for the duration of the
transfer, so no revocation can run concurrently with a transfer, preventing torn
state.

Reply capabilities are not part of the derivation tree — they are single-use,
cannot be derived, and are not tracked for revocation. A reply capability is not
a `CapTag` variant; it is an implicit per-thread mechanism created by the kernel
at `SYS_IPC_RECV` time and stored in a per-thread slot, outside the process
CSpace. The kernel clears the per-thread reply slot after `SYS_IPC_REPLY`.

---

## Summarized By

[kernel/README.md](../README.md)
