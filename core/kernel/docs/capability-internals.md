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
- Per-process ceiling — bounded kernel memory per process

### Storage: Two-Level Array

The CSpace is implemented as a two-level array (similar to a small page table):

```rust
pub struct CSpace
{
    /// L1 directory: array of pointers to L2 pages.
    /// Statically sized; each entry covers L2_SIZE slots.
    directory: [Option<Box<CSpacePage>>; L1_SIZE],

    /// Total number of slots currently allocated (not necessarily in use).
    allocated_slots: usize,

    /// Maximum slots this CSpace may ever hold (enforced ceiling).
    max_slots: usize,
}

/// One page of CSpace slots (an L2 block).
/// Sized so that one CSpacePage is exactly one kernel heap allocation.
struct CSpacePage
{
    slots: [CapabilitySlot; L2_SIZE],
}
```

The concrete values of `L1_SIZE`, `L2_SIZE`, and the default `max_slots` are
implementation constants chosen so that one `CSpacePage` fits in a single slab
allocation and the maximum slot count per process is bounded. These values are
established at implementation time and are not part of the public ABI.

**Lookup is O(1):** A descriptor `d` maps to `directory[d / L2_SIZE].slots[d % L2_SIZE]`.
Two array dereferences, always. No hash, no tree traversal, no search.

**Growth is demand-driven:** Directory entries start as `None`. The first allocation
in a new L2 range triggers a `CSpacePage` allocation from the slab cache. L2 pages
are never freed while the CSpace is live (slot indices must remain stable).

**Slot 0** is always null. The directory entry for slot 0 exists but the slot is
permanently locked to the null capability, enforced at the lookup level.

### Free Slot Tracking

A free list of available slot indices is maintained separately:

```rust
pub struct CSpace
{
    // ... (above fields)
    free_head: Option<usize>,  // head of intrusive free list of slot indices
}
```

Free slots store their `next` index in their `CapabilitySlot.tag` field (repurposed
when the slot is empty). Allocation pops from the free list; deallocation pushes. If
the free list is empty and more slots are needed, the next L2 page is allocated and
all its slots are pushed onto the free list.

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

    /// Caller-identifying token (0 = untokened). Set via SYS_CAP_DERIVE_TOKEN.
    /// Immutable once set; inherited by derivation and copy.
    token: u64,

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

The slot is 56 bytes (`#[repr(C)]`). 64 slots per CSpace page = 3584 bytes, fitting
in a 4096-byte slab bin.

`SlotId` is a global identifier combining a CSpace ID and a slot index:
`(CSpaceId, usize)`. This allows derivation tree traversal across CSpace boundaries
without holding per-CSpace locks longer than necessary.

### Capability Tags

```rust
#[repr(u8)]
pub enum CapTag
{
    Null          = 0,
    Frame         = 1,
    AddressSpace  = 2,
    Endpoint      = 3,
    Signal        = 4,
    EventQueue    = 5,
    Thread        = 6,
    CSpace        = 7,   // capability space; explicit kernel object
    WaitSet       = 8,
    Interrupt     = 9,
    MmioRegion    = 10,
    Reply         = 11,  // single-use; not derivable
    IoPortRange   = 12,  // x86-64 only; created at boot from platform_resources
    SchedControl  = 13,  // authority to set elevated scheduling priorities
}
```

### Rights Bitmask

```rust
bitflags! {
    pub struct Rights: u32
    {
        // Frame rights
        const MAP        = 1 << 0;
        const WRITE      = 1 << 1;
        const EXECUTE    = 1 << 2;

        // Address space rights
        // MAP reused — same bit, tag-dependent: covers both "map frames into
        // this address space" and "create threads that run in this address space"
        const READ_ASPACE = 1 << 14;  // may inspect current mappings

        // Endpoint rights
        const SEND       = 1 << 3;
        const RECEIVE    = 1 << 4;
        const GRANT      = 1 << 5;

        // Signal rights
        const SIGNAL     = 1 << 6;
        const WAIT       = 1 << 7;

        // Event queue rights
        const POST       = 1 << 8;
        const RECV       = 1 << 9;

        // Thread rights
        const CONTROL    = 1 << 10;
        const OBSERVE    = 1 << 11;

        // CSpace rights
        const INSERT     = 1 << 12;  // may place a capability into a slot
        // (DELETE reuses a bit below)
        const DERIVE_CAP = 1 << 17;  // may derive a cap from an existing slot
        const REVOKE_CAP = 1 << 18;  // may revoke a cap and all its descendants

        // Wait set rights
        const MODIFY     = 1 << 13;
        // (WAIT reused for wait set wait right)

        // IoPortRange rights
        const USE        = 1 << 15;  // may bind port range to a thread

        // SchedControl rights
        const ELEVATE    = 1 << 16;  // may set thread priority in elevated range (21–30)
    }
}
```

Rights are checked at every syscall that uses a capability. The check is a single
bitwise AND: `(slot.rights & required) == required`.

W^X enforcement at mapping time (`mem_map`, `mem_protect`):

```rust
fn check_wx(rights: Rights) -> Result<(), SyscallError>
{
    if rights.contains(Rights::WRITE | Rights::EXECUTE)
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

Each kernel object (Endpoint, Signal, EventQueue, etc.) has an embedded reference
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
Endpoint/Signal/EventQueue dealloc arms only `debug_assert` that
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

`SYS_CAP_REVOKE` performs a post-order traversal of the subtree rooted at the target
slot, invalidating all descendants before the target itself:

```
revoke(slot_id):
    acquire derivation tree write lock
    post_order_revoke(slot_id)
    release derivation tree write lock

post_order_revoke(slot_id):
    slot = resolve(slot_id)  // look up slot across all CSpaces
    child = slot.deriv_first_child
    while child is not None:
        next = resolve(child).deriv_next_sibling
        post_order_revoke(child)
        child = next
    // All descendants now invalid; invalidate this slot
    slot.tag = CapTag::Null
    slot.object.map(|obj| obj.header.ref_count.fetch_sub(1, Ordering::Release))
    // Remove from parent's child list
    unlink_from_parent(slot_id)
    // Free the CSpace slot to the free list
    cspace_of(slot_id).free_slot(slot_id.index)
```

**Performance characteristics:** Revocation is O(N) in the number of descendants.
For well-behaved systems, derivation trees are shallow (a server derives a capability
for a client; the client rarely re-derives). Deep trees or large revocations are
theoretically O(N) but do not appear on latency-sensitive paths.

**Locking during revocation:** While the write lock is held, all other capability
operations on the affected slots are blocked. This is safe because revocation is
intentionally a strong operation — the revoker is asserting that no further access
to the capability is valid.

**Deferred IPC cleanup:** The derivation tree write lock is ordered after IPC object
locks (see lock ordering in [ipc-internals.md](ipc-internals.md)). Therefore,
`SYS_CAP_REVOKE` must not acquire IPC object locks while holding the derivation tree
write lock. Revocation collects a set of IPC objects needing cleanup (e.g. endpoints
that have a revoked capability in their send queue), releases the write lock, then
acquires individual IPC object locks to perform cleanup.

### Safe Delegation: the "Derive Twice" Pattern

Revoking a capability via `SYS_CAP_REVOKE` invalidates the target slot and all
its descendants. To delegate authority that can later be revoked without losing your
own access:

```
1. Hold capability C (the original).
2. Derive C1 from C — you retain C1 as an intermediary.
3. Derive C2 from C1 — C2 is the delegated capability.
4. Transfer C2 to the child process via SYS_CAP_INSERT or IPC capability slots.
5. To revoke: call SYS_CAP_REVOKE on your slot holding C1.
   This destroys C1 and C2 (all descendants of C1).
   You still hold C with its full rights intact.
```

This pattern works because revocation is subtree-local. Revoking C1 removes C1 and
all descendants but leaves C and any siblings of C1 untouched.

### Derivation Across Processes

`SlotId` encodes `(ProcessId, slot_index)`. Resolving a remote slot requires:

```
resolve(slot_id):
    cspace = cspace_table[slot_id.cspace_id]  // O(1) from global table
    return cspace.slot(slot_id.index)         // O(1) two-level lookup
```

Neither operation requires holding a lock on the target process's CSpace — the
derivation tree write lock is sufficient to prevent concurrent modification.

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
| 4 | SchedControl capability (Elevate rights) |
| 5..N | Frame capabilities (one per usable physical region) |
| N+1..M | MMIO region capabilities (one per MmioRange / PciEcam entry) |
| M+1..K | Interrupt capabilities (one per IrqLine entry) |
| K+1..L | Read-only Frame capabilities (one per PlatformTable entry) |
| L+1..P | IoPortRange capabilities (one per IoPortRange entry; x86-64 only) |
| P+1..Q | Frame capabilities for boot module images (raw ELF for procmgr, devmgr, etc.) |

The exact slot numbers are passed to init in the `KernelHandoff` structure placed
on init's user stack before it begins execution.

---

## Capability Transfer in IPC

IPC capability transfer (via `SYS_IPC_CALL` and `SYS_IPC_REPLY` capability slots)
is implemented atomically as part of message delivery:

```
transfer_cap(sender, sender_slot_idx, receiver, receiver_slot_idx):
    acquire derivation tree write lock
    src_slot = sender.cspace.slot(sender_slot_idx)
    dst_slot = receiver.cspace.slot(receiver_slot_idx)
    // dst_slot must be null (verified before IPC delivery begins)
    *dst_slot = *src_slot  // copy the entire slot structure
    // Update derivation tree: dst_slot takes src_slot's position
    relink_derivation_pointers(src_slot_id, dst_slot_id)
    // Clear the sender's slot
    src_slot.tag = CapTag::Null
    src_slot.object = None
    // Note: ref_count does not change (same number of slots reference the object)
    release derivation tree write lock
```

The derivation write lock is held for the duration of the transfer. This ensures
no revocation can run concurrently with a transfer, preventing torn state.

Reply capabilities (`CapTag::Reply`) are not part of the derivation tree — they are
single-use, cannot be derived, and are not tracked for revocation. They are created
by the kernel at `SYS_IPC_RECV` time and stored in a per-thread slot, outside the
process CSpace. The kernel clears the per-thread reply slot after `SYS_IPC_REPLY`.

---

## Summarized By

None
