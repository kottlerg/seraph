# Capability Subsystem Internals

This document covers the implementation of the capability subsystem. The design —
capability types, rights, derivation, revocation, and transfer semantics — is
specified in [docs/capability-model.md](../../../docs/capability-model.md). This document
covers the data structures and algorithms that realise those semantics.

The capability subsystem comprises six components:

1. **CSpace** — per-process capability space (slot storage and lookup)
2. **CSpace registry** — the RAM-sized arena mapping a `CSpaceId` to its live CSpace and epoch
3. **Page pools** — the donated pages behind a CSpace's slots and an address
   space's page tables, and the record of every donation
4. **Capability slot** — in-memory representation of one capability
5. **Range capability objects** — the Mmio, IoPort, and Interrupt objects, which record the
   mappings, port bindings, and interrupt binding made through them so revocation can withdraw
   them
6. **Derivation tree** — cross-process tree for revocation

---

## CSpace Implementation (`cap/cspace.rs`)

### Design Constraints

From [docs/capability-model.md](../../../docs/capability-model.md) § Capability Spaces:

- O(1) lookup — descriptor-to-slot resolution on every IPC call
- Stable indices — a descriptor never changes after assignment
- Grows on demand — no upfront size prediction needed
- Pay-as-you-go — every slot page is drawn from a pool the owner funded
  with its own Memory caps, so per-process kernel memory is bounded by
  what the process paid for

### Storage: Hybrid Radix Directory

The CSpace is a hybrid radix: an inline root of 256 pointers, split into four regions, plus
pool-allocated directory pages fanning out to further leaves (similar to a page table with a
large root). The direct region's root entries name leaves; each later region's entries name
directory pages one level deeper than the region before it:

```rust
pub struct CSpace
{
    /// Direct region: inline pointers to the first L1_DIRECT leaf pages.
    direct: [AtomicPtr<CSpacePage>; L1_DIRECT],
    /// Indirect region: inline pointers to level-1 directory pages.
    indirect: [AtomicPtr<DirPage<CSpacePage>>; L1_INDIRECT],
    /// Double-indirect region: inline pointers to level-2 directory pages.
    double: [AtomicPtr<DirPage<DirPage<CSpacePage>>>; L1_DOUBLE],
    /// Triple-indirect region: inline pointers to level-3 directory pages.
    triple: [AtomicPtr<DirPage<DirPage<DirPage<CSpacePage>>>>; L1_TRIPLE],
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

/// One pool-allocated directory page: DIR_FANOUT pointers to the level below.
struct DirPage<T>
{
    entries: [AtomicPtr<T>; DIR_FANOUT],
}
```

| Region | Root entries | Leaves per entry | Slots | Directory loads |
|---|---|---|---|---|
| direct | `L1_DIRECT` (128) | 1 | 0 to 7,167 | 0 |
| indirect | `L1_INDIRECT` (64) | `DIR_FANOUT` (512) | 7,168 to 1,842,175 | 1 |
| double-indirect | `L1_DOUBLE` (63) | 512² | 1,842,176 to 926,686,207 | 2 |
| triple-indirect | `L1_TRIPLE` (1) | 512³, used up to the ceiling | 926,686,208 to 4,294,967,263 | 3 |

The concrete values of `L1_DIRECT`, `L1_INDIRECT`, `L1_DOUBLE`, `L1_TRIPLE`, `DIR_FANOUT`, and
`L2_SIZE` are implementation constants chosen so that one `CSpacePage` fits a single pool page,
one `DirPage` of any level is exactly one pool page, the root keeps 256 entries (a const assert
holds the sum), and the regions reach the cap handle's index field. `L1_DIRECT`, `L1_INDIRECT`,
`L1_DOUBLE`, `L1_TRIPLE`, and `DIR_FANOUT` are not part of the public ABI, while `L2_SIZE` is
published as `CSPACE_SLOTS_PER_PAGE` (userspace funding arithmetic depends on it, and a const
assert pins the two together), so changing it is an ABI change. The directory's structural
ceiling, `MAX_SLOTS_STRUCTURAL`, is the whole leaves the 32-bit index field addresses:
`MAX_LEAVES`, 2^32 / `L2_SIZE` (76,695,844) leaves of `L2_SIZE` slots, 4,294,967,264 slots; the
last 32 indices of the field, which a whole leaf cannot hold, resolve nothing. It is the only slot
bound a CSpace has, set by the handle's ABI width rather than by the directory; capacity below it
is whatever the owner-funded slot-page pool backs (see
[docs/capability-model.md](../../../docs/capability-model.md) § Address-space and
CSpace growth budgets).

**Lookup is O(1):** A descriptor `d` selects leaf `d / L2_SIZE` and slot `d % L2_SIZE`. A leaf of
the direct region resolves through the inline root alone; a leaf of each later region through one
more directory page than the region before it, so a lookup makes at most three dependent
directory loads before the slot read, three only past slot 926,686,207. No hash, no search.

**Growth is O(1) and strictly ordered:** leaves are materialised in index
order behind the `next_leaf` cursor, so allocated leaves are always the
contiguous range `0..next_leaf`. A grow past the direct region first materialises every missing
directory page above the new leaf, top level first, from the same owner-funded pool (roughly one
extra pool page per `DIR_FANOUT` leaves, and one per `DIR_FANOUT` pages of the level below); a
directory page that outlives a failed lower-level or leaf allocation stays published — already
paid for, it serves the next grow. Pages are never freed while the CSpace is live (slot indices
must remain stable). Because growth is contiguous, over a span of leaves still to grow only the
directory pages above its first leaf can already exist, so `pages_to_cover`, the
explicit-placement path's fast-fail count, is arithmetic per level with one probe each.

An explicit placement (`SYS_CAP_COPY` or `SYS_CAP_MOVE` with a nonzero destination slot)
grows the destination before it takes the derivation lock and the `CSpace` lock pair
(`pre_grow_for_explicit_slot`): `MAX_GROW_LEAVES_PER_HOLD` leaves per hold of the destination's
spinlock, and the interrupts pending on its CPU taken between holds (`interrupt_window`, as
seeding does, [§ Donation Records](#donation-records)). The syscall therefore masks interrupts
for at most one batch of leaves at a time, whatever slot the caller chose; its total length still
grows with the slot.

**Memory ordering and lock domains:** directory and leaf pointers are write-once while the CSpace is
live, published with Release after full initialisation, and read with Acquire by the lock-free
readers. Mutation is split across two lock domains: slot occupancy, the free list, the directory,
and the counters change only under the CSpace spinlock, while the derivation linkage of occupied
slots changes only under the global derivation write lock (which reaches any registered CSpace's
slots via registry lookup without taking its spinlock — see Derivation Tree below). Paths crossing
the families hold the derivation lock outermost, then the spinlock.

A syscall that uses the object a handle names resolves the handle through `syscall::pin_slot` (or
`lookup_cap`, its single-type form): it reads the slot's tag, generation, rights, badge, and object
under the CSpace spinlock and takes a reference on the object inside that hold, the syscall pin of
[§ Kernel Object Reference Counting](#kernel-object-reference-counting). The pin keeps the object
live for as long as the handler uses it, whatever releases the slot's own reference meanwhile: a
sibling's delete of the last capability, or another holder's revoke of an ancestor. A split child (a
`SYS_MEMORY_SPLIT` tail, or a range-split MMIO, IoPort, IRQ, or SchedControl child) is a distinct
object linked under the original's derivation parent, and so is every copy or derivation of an Mmio,
IoPort, or Interrupt capability ([§ Range Capability Objects](#range-capability-objects)) and the
joined capability of a `SYS_MMIO_MERGE`, so
another holder's revoke of that ancestor can release it directly; for a same-object derivation, as
in the kill-process pattern, it is the delete following the revoke that releases it. Either way the
object is freed only when its count reaches zero, which a held pin defers until the syscall drops
it. Copy, derive, and derive-badge pin their source the same way, so the reference they take for the
new slot never lands on a freed object, and still revalidate the source slot under the derivation
write lock before they link the new one (see [§ Global Derivation Lock](#global-derivation-lock)).
The IPC transfer pre-validation (`prevalidate_sender_caps`) holds the sender's CSpace lock, under
which a slot stays occupied and its object live, so it also reads each object's reference count
against the ceiling. The remaining lock-free readers, the capability-tree syscalls' unlocked
pre-checks, read only the tag, generation, and in-flight pin of a slot and dereference no object.
Neither holds the derivation lock: their tag, generation, and pin checks only narrow the race they
act on, and the locked path re-decides.

**Slot 0** is always null. The leaf covering slot 0 exists once the CSpace
has grown, but the slot is permanently locked to the null capability,
enforced at the lookup level (see
[docs/capability-model.md](../../../docs/capability-model.md) § Capability Spaces).

### Speculative-Execution Hardening

The rule is [docs/capability-model.md](../../../docs/capability-model.md) § Capability Spaces:
resolving a handle, and the handler's use of it past resolution, hold under speculative execution.
A bound enforced only by a conditional branch does not hold on a mispredicted path, where the
loads behind the branch execute with the out-of-bound value, so every bound between a
user-supplied handle and the object it names is also enforced as data. The syscall handlers hold
the same line past resolution: a right a handler tests beyond those its lookup requires, and a
user-supplied value that selects a kernel array entry, a span of frames, a page-table walk, or a
dispatch table entry, are enforced as data as well (the table below). These bounds are the
kernel's defence of the user-to-kernel boundary against bounds-check bypass on both
architectures; the posture on the other transient-execution classes and on isolation between
processes is [docs/capability-model.md](../../../docs/capability-model.md)
§ Microarchitectural Isolation.

The primitives are `arch::current::speculation::index_mask` and
`arch::current::speculation::hide`. `index_mask(index, bound)` is all-ones when `index < bound`,
else zero, computed without a branch (x86-64 `cmp` then `sbb`; riscv64 `sltu` then `neg`, base
RV64I, since the RVA23 floor defines no speculation barrier). It is inline assembly so the
compiler cannot prove the mask redundant inside the arm of the guarding branch and delete it, and
it is not `pure`, so it is not moved into such an arm either. `hide` passes a value through an
empty, non-`pure` assembly block, giving a copy the compiler cannot relate to the original.
`arch::nospec` builds the arch-neutral forms on the two: `index_mask`, `mask_index`,
`mask_index_u64`, `mask_span_u64` (a byte span kept when it lies inside an object, else emptied),
`mask_if` (all-ones when a condition holds), `hide`, and `select_ptr` (one of two pointers chosen by
a mask).

A mask's output is opaque but its input is not. A condition that a dominating branch has already
tested is a constant inside that branch's arm, so a condition mask (`mask_if`) taken there on the
same condition is all-ones whatever the data. Every condition mask is therefore computed either
ahead of the branch it backs, or from a value `pin_checked` passed through `hide` at resolution,
which no later branch on it lets the compiler fold: inside an arm of a dispatch on a slot's tag,
from the hidden tag (`PinnedCap::tag_mask`), and for a right tested after resolution, from the
hidden rights (`PinnedCap::rights_mask`). An index mask (`index_mask`, or a `mask_index*` or
`mask_span_u64` form) taken inside the arm of the bounds branch it backs stays data, since its
input is the index or span, whose value the branch does not fix.

| Site | User-controlled value | Load it would steer | Hardening |
|---|---|---|---|
| `CSpace::leaf_ptr`, direct arm | handle index | `direct[leaf]` past the inline root | the leaf index is masked against `L1_DIRECT`; a failed bound selects `SENTINEL_LEAF` |
| `CSpace::leaf_ptr`, indirect, double-indirect, and triple-indirect arms | handle index | the region's root array past the inline root, then each directory entry | the region-relative index is masked against the region's span (`L1_INDIRECT × DIR_FANOUT`, `L1_DOUBLE × DIR_FANOUT²`, or, in the triple region, the leaves below `MAX_LEAVES`) before any load, and each directory index is reduced below `DIR_FANOUT`; a failed bound selects `SENTINEL_LEAF` |
| Leaf and directory pointers | handle index | a null leaf or directory dereferenced at an offset below one page | no pointer is null: unallocated entries name `SENTINEL_LEAF`, `SENTINEL_DIR`, `SENTINEL_DIR2`, or `SENTINEL_DIR3`, so the path has no null test |
| `syscall::pin_checked` (`pin_slot`, `lookup_cap`) | handle | the handler's typed accesses of a slot's object | occupancy, generation, type, and the rights the lookup requires are computed as values and folded into the object through `mask_if`, ahead of the branches that refuse them: on a path past a failed check, the object is null |
| `sys_cap_info`, `wait_set_source`, the `sys_wait_set_add` and `sys_wait_set_remove` source dispatch, `object_for_new_slot` | the slot's tag | a cast to the wrong object or state type | each tag arm casts the pointer selected by its own tag against the hidden tag (`PinnedCap::object_of`, `PinnedCap::tag_mask`, or `object_for_new_slot`'s `hidden_tag`) |
| `sys_wait_set_add` member right | the source's rights | the source's state and header, locked and written | the member right's mask (`PinnedCap::rights_mask`) selects the source pointers; past a failed test they are null |
| `sys_mem_map` and `sys_mem_protect` Write and Execute | the protection requested against the Memory cap's rights | the page-table walk of the map or protect loop | the requested rights' mask (`PinnedCap::rights_mask`) selects the address-space object the loop walks; past a failed test it is null |
| `sys_cap_info`, `CAP_INFO_MEMORY_PHYS_BASE` | the queried cap's rights, or the credential handle | the Memory object's `base`, read from a cap held without `PHYS` | the queried cap's `PHYS` mask (`PinnedCap::rights_mask`), or the credential's resolution, whose lookup folds `PHYS` into its object, selects the queried object; past a failed test it is null |
| `sys_mem_map` offset, and the `sys_cap_info` `CAP_INFO_MEMORY_MAPPINGS` window | page offset and count | the frame-map counters of frames past the Memory object (`FramePins::pin` and the mapping loop; `frame_map::mappings_in`) | the byte span is clamped to the object through `mask_span_u64`; a failed bound gives the empty span |
| `sys_aspace_query` | virtual address | the page-table walk into the kernel half of the root | the address is masked against `user_va_top` through `mask_index_u64`; a failed bound walks address 0 |
| `sys_mem_map`, `sys_mem_unmap`, `sys_mem_protect`, `sys_mmio_map` | virtual range | the page-table walk of the map, unmap, or protect loop into the kernel half of the root | `mm::user_page_range` returns the checked range clamped to `user_va_top` through `mask_span_u64`, and the loop walks the range it returns; a failed bound gives the empty range at 0 |
| `sys_aspace_harvest` | virtual range and page count | the page-table walk of the harvest's read and clear into the kernel half of the root, and the bitmap stores past the 512-byte kernel-stack bitmap | `mm::user_page_range` clamps the range as for `sys_mem_map`, and the walk takes its page count from the clamped range, masked below `MAX_HARVEST_PAGES + 1` through `mask_index`; a failed bound walks the empty range |
| `sys_thread_read_mem`, `sys_thread_write_mem` | target virtual address and length | the software walk of `copy_user_bytes` into the kernel half of the target's root | `thread_mem_args` clamps the span to `user_va_top` through `mask_span_u64`; a failed bound gives the empty span at 0 |
| `sys_thread_list_pages` | start address and run count | the software walk of `scan_user_leaves` into the kernel half of the target's root, and the run stores past the scratch buffer | the span from the start to `user_va_top` is clamped through `mask_span_u64`, and the run count is masked below `MAX_PAGE_RUNS + 1` through `mask_index_u64` before the runs are staged; a failed bound walks the empty span at 0 |
| `sys_thread_read_ext_regs` | image offset and length | the save-area loads past the area, and the copy's stores past the scratch buffer | the length is masked below `MAX_THREAD_MEM_COPY + 1` through `mask_index`, and `extended_span` clamps the span to the image through `mask_span_u64`; a failed bound gives the empty copy |
| `sys_entropy_contribute` | copy length | the copy's stores of caller-chosen bytes past the 256-byte kernel-stack stage | the length is masked below `MAX_ENTROPY_CONTRIBUTE_LEN + 1` through `mask_index` before the copy; a failed bound gives the empty copy |
| `sys_thread_set_affinity` | CPU index | the per-CPU scheduler entries `migrate_ready_thread` locks and links on | `set_affinity_locked` masks the CPU against `CPU_COUNT` through `mask_index`; a failed bound selects CPU 0 |
| `sys_thread_set_priority` | priority level | the run queue the relocate links the thread on | the level is masked below `PRIORITY_MAX + 1` through `mask_index`; a failed bound selects level 0 |
| `syscall::dispatch` | syscall number | a jump-table entry past the table | a number at or past `SYSCALL_NR_BOUND` (abi/syscall) is refused, and the table reads the number through `mask_index_u64` |
| `sys_system_info` and `sys_cap_info` dispatch | info kind, or field selector | a jump-table entry past the dispatch's table | a value at or past `SYSTEM_INFO_BOUND` or `CAP_INFO_FIELD_BOUND` is refused, and the dispatch reads it through `mask_index_u64` |

The sentinels are four statics in `cap/cspace.rs`. `SENTINEL_LEAF` is an all-`Null` `CSpacePage`
(4032 bytes) with no interior mutability, so it is placed in read-only data. `SENTINEL_DIR` is one
page of level-1 directory entries, each naming `SENTINEL_LEAF`; `SENTINEL_DIR2`'s entries name
`SENTINEL_DIR`, and `SENTINEL_DIR3`'s name `SENTINEL_DIR2`, so a walk through any unallocated
entry reaches `SENTINEL_LEAF`. A `CSpace` starts with every inline entry naming its region's
sentinel, and a grow fills a new directory page's entries with the sentinel of the level below
before publishing it. `slot` and `slot_mut` refuse the sentinel leaf after the loads, so
architecturally an unallocated index still resolves nothing, and `slot_mut` never hands out the
shared page. The masked fallback of every `leaf_ptr` arm is the sentinel, never leaf 0, so a
mispredicted bound reads only `Null` slots and never aliases a live slot of the caller's `CSpace`.
Every resolution of a handle passes through `slot` or `slot_mut`: `pin_slot`, `lookup_cap`, the
capability-tree handlers, the IPC transfer pre-validation, and explicit placement.

A misspeculated use of the null object that `pin_checked` folds a failed lookup into dereferences
null at a small offset. No address space maps a page below `USER_VA_FLOOR` (64 KiB), which every
capability object and the TCB fit under (`cap::object` asserts it at compile time), so that load
never reads memory a process chose, whether or not SMAP or a clear `SUM` stop it (see
[docs/memory-model.md § Userspace Layout](../../../docs/memory-model.md#userspace-layout)). A
right a handler tests after resolution, beyond those its lookup requires, is folded the same way:
`pin_checked` passes the slot's rights through `hide` into the `PinnedCap`, and the handler selects
through `PinnedCap::rights_mask` the object its accesses past the refusal go through, so a path
past a mispredicted refusal reaches null. The table lists every such right and every
user-supplied value outside the capability path that selects a kernel array entry, a span of
frames, a page-table walk, or a dispatch table entry.

### Free Slot Tracking

A free list of available slot indices is maintained intrusively, with its head in
kernel memory:

```rust
pub struct CSpace
{
    // ... (above fields)
    free_head: Option<NonZeroU32>, // head of the intrusive free list (None = empty)
    free_tail: Option<NonZeroU32>, // tail of the intrusive free list (None = empty)
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
the head. When more free slots are needed, the next leaf page is allocated and all its
usable slots are appended, in ascending order, at `free_tail`. Because a general
allocation grows while the slots of the IPC receive reserve (below) are still free,
appending hands those out before the new leaf's, so a run of consecutive inserts gets
consecutive indices across a leaf boundary: `InitInfo`'s contiguous Memory-cap ranges
depend on it, and the boot population checks every run it publishes (the RAM, hardware,
ACPI-region, init-segment, init-stack, and InitInfo-region caps), halting on the first slot out
of place (`cap::extend_slot_run_or_fatal`;
[initialization.md](initialization.md) § Phase 7 and § Phase 9).

A `Null` tag alone cannot tell a slot that is *linked on the free list* from one that
was just allocated and not yet populated, and the list tail is byte-identical to a
cleared slot. Each linked slot therefore also carries an on-free-list marker in
`CapabilitySlot.badge`, which carries no badge while the slot is `Null`;
`is_on_free_list()` reports membership in O(1) from `tag == Null && badge == marker`.
`free_slot` consults it to reject a double-free of
any slot — re-pushing a slot already on the list would splice it in twice and cycle
the list, after which allocation could hand back an occupied slot. The marker is set
when a slot is linked (`set_next_free`) and cleared when it leaves the list (on
allocation, and when `remove_from_free_list` unlinks a specific index);
`allocate_slot` debug-asserts the popped slot was a genuine member.

This gives amortised O(1) allocation and O(1) deallocation.

### IPC Receive Reserve

Every `CSpace` keeps its last `IPC_RECV_RESERVE` free slots (`CSPACE_IPC_RECV_RESERVE` in the
ABI, equal to `MSG_CAP_SLOTS_MAX`, one message's worth) for IPC capability transfer:

- **General allocations** (`allocate_slot` and the inserts built on it: every `cap_create_*`,
  `cap_copy`, `cap_derive`, split, kernel boot mint, and `cap_move`, including the
  explicit-placement `insert_cap_at`) grow the `CSpace` until more than `IPC_RECV_RESERVE`
  slots are free before they take one. When the pool cannot grow they fail with the grow's
  error (`PoolExhausted`, `OutOfMemory` to userspace; `OutOfSlots`, `QuotaExceeded`, at the
  structural ceiling) while the reserved slots stay free.
- **IPC transfer allocations** (`allocate_transfer_slot`, through `insert_cap_transfer` and
  `cap::transfer::Placement::IpcTransfer`, the placement `transfer_caps` uses for call, receive,
  and reply delivery) take any free slot, the reserved ones included, and grow only when none is
  free.

`pre_allocate(n)` grows until `n` slots are free, counting reserved ones. So the worst-case
`pre_allocate(MSG_CAP_SLOTS_MAX)` that `SYS_IPC_RECV` makes before parking succeeds without
growth on a `CSpace` whose general slots are exhausted, and the received caps land in the
reserve. The degradation is reserve-then-wedge:

1. General allocations fail first, visibly, with `OutOfMemory`.
2. Receives keep working, and received caps take reserved slots, until transfers have spent the
   reserve.
3. Only then does a receive fail before parking, the condition
   [docs/ipc-design.md](../../../docs/ipc-design.md) § Receive-Failure Policy handles.

Freeing a slot reopens general allocation once more than the reserve is free. The reserve is not
a lock: two threads sharing a `CSpace` can both receive into it, and a transfer that finds it
spent fails as any destination shortage does. A process keeps general headroom above the reserve
by funding its pool (`std::os::seraph::fund_cspace_slot_budget`).

---

## CSpace Registry (`cap/registry.rs`)

The registry maps a `CSpaceId` to its live `CSpace` and current epoch. It is an arena of 16-byte
entries (pointer, epoch, free-list link), one per 4 KiB page of DRAM
(`mm::init::system_ram_bytes`), so the id space never runs out before the memory that pays for
the `CSpace`s does: every `CSpace` costs its creator at least one wrapper page. Storage is
two-level: a chunk table sized from DRAM (`chunks_for_ram`) and allocated from the buddy, each
slot naming one 1 MiB buddy block of 65,536 entries (`REGISTRY_CHUNK_ORDER`), so no RAM size
exhausts it; the count stops only at `MAX_ID_CHUNKS`, past 16 TiB of DRAM, where the `u32`
`CSpaceId` width holds no more ids. `cap::init_cspace_registry` carves the table and the chunks
in Phase 4
([initialization.md](initialization.md) § Phase 4), after the Phase-2 exclusions and before the
Phase-7 drain; a short buddy is fatal.

`alloc_cspace_id` hands out the most recently retired id, else the next fresh one, under one
spinlock with O(1) holds. A vacant entry keeps its epoch and threads the free list through its
link word, so the epoch `free_cspace_id` redraws at retirement (§ Representation) persists across
the vacancy and is the one the next tenant's `register_cspace` returns. The same lock counts the
ids handed out and not yet retired (`live_cspace_count`), which
`SYS_SYSTEM_INFO(LiveCSpaceCount)` reports ([syscalls.md](syscalls.md) § `SYS_SYSTEM_INFO`):
ktest reads it to check that every `CSpace` teardown returns its id.

`lookup_cspace` takes no lock. It loads the chunk pointer (Acquire), then reads the entry's
epoch, its pointer, and its epoch again, each with Acquire, and resolves only when both epoch
reads equal the stamped epoch and the pointer is non-null. The second epoch read rejects a
concurrent unregister, retire, reuse, and register that would otherwise pair the new tenant's
pointer with the old epoch. An id no installed chunk backs resolves nothing.

---

## Page Pools (`cap/object.rs`)

The wrapper object that owns a `CSpace` (`CSpaceKernelObject`) keeps the
slot-page pool in a `PagePool`; the wrapper of an `AddressSpace` keeps its
intermediate page-table pool in the same type. A pool is an intrusive free
list of the donated pages (each free page's first word links the next) plus
a record of every donation — its source Memory object, byte offset, page
count, and, at a `CSpace`'s teardown, the list of its arena pages kept past
it — so teardown can return each donation to its source, whole or, for a
`CSpace`, with those pages cut out ([§ Body Arena](#body-arena)). A
`CSpace` pool's free page also carries, in its second word, the address of
its donation's record. The wrapper, not the pool, keeps the byte budget the
pool backs.

### Donation Records

Sixteen records live inline in the wrapper; the create-time slab, which
holds the wrapper itself, is record 0. When the inline records are full,
the next donation's first pool page becomes a *record page*: a chained
page (newest first) holding up to `RECORDS_PER_PAGE` further records,
whose record 0 is the donation the page came from. A donation is recorded
before any of its pages is published to the free list, so every free page
belongs to a reclaimable record, and the number of donations is bounded
only by the memory donated — one donated page of bookkeeping per record
page. A one-page donation that opens a record page seeds nothing; the
budget reported by `SYS_CAP_INFO` is authoritative.

Seeding pushes a donation's pool pages onto the free list in batches of
`SEED_BATCH_PAGES`, each under its own hold of the pool lock and credited
to the budget as it lands, and takes the interrupts pending on its CPU
between batches (`interrupt_window`: preemption disabled, interrupts
enabled for an instruction, then the caller's interrupt state restored).
The syscall that seeds a donation therefore masks interrupts for at most
one batch of pushes at a time, whatever its `init_pages`; its total length
still grows with `init_pages`.

A record page is kernel state kept in donated memory, like the wrapper page,
the slot pages, and the page tables themselves: the kernel trusts its
contents because the donating Memory capability cannot map what it has
retyped away, nor retype pages it already maps (the retype/map boundary of
[docs/capability-model.md § Typed Memory](../../../docs/capability-model.md#typed-memory)),
and [cross-boundary-disclosure.md](cross-boundary-disclosure.md) § Kernel state
in donated memory records that surface. The records are never scanned while
the owner is live: an address space's reclaiming unmap recognises pool-owned
page tables by a bit in the parent entry, not by the records; see
[memory-internals.md](memory-internals.md) § Page Table Node Ownership.

### Teardown

Teardown walks the record pages newest first, returning each page's other records before its
record 0 (whose donation holds the page), then the inline records, the create-time slab last. It
returns them in groups: a page's other records, and the inline records but record 0, are sorted in
place by Memory object and offset, and each run of them that shares a Memory object goes back as
one group, through one walk of that object's page free list (`retype_free_runs`); a record 0 is a
group of its own. A group's donations that end contiguously at their Memory object's bump frontier
roll it back over them all, as returning them one by one from the highest would. A donation's
Memory object that reaches zero there is queued on the dealloc cascade like every other object a
teardown orphans.

The cascade is one stack per `dealloc_object` call (`CascadeStack`), linked through the queued
objects' own headers: an object on it has a reference count of 0, so its `ref_count` and the
header's three padding bytes hold the link to the next, while the type and `ancestor` fields its
teardown reads stay intact, and the link is cleared when it is popped. An `AddressSpace` keeps its
link in its wrapper's `deferred_next` instead, the deferred-reclaim stack's link, which no other
stack uses while the cascade holds it: a thread still bound to a queued space reaches its count
through `pin_thread_aspace` ([§ Kernel Object Reference
Counting](#kernel-object-reference-counting), "Thread address-space pins"), and a link in the count
would read there as a live count, which the pin would take and corrupt. An object reaches zero once,
so only the call that took it there queues it, at most once at a time, and the stack holds any
number of objects without allocating. The one object queued twice is a `CSpace` wrapper: its arm's
first run, having popped it, pushes it back beneath the objects its slots held, so its second run,
which returns its pool, comes after their teardowns and every cascade they start ([§ Body
Arena](#body-arena)). Every release a teardown makes pushes the object it orphans: an ancestor
Memory object's retype lease, a donation's lease, the references a dying `CSpace`'s slots hold (a
nested `CSpace` among them), a caller-sized wait set's member references, a thread's fault-handler
binding and fault redirect, and the queue references of an owner's chain of death-observer nodes.
The call pops and tears down the most recent object until the stack is empty, and no teardown calls
`dealloc_object` itself, so a chain of `CSpace`s each holding the last reference to the next, or a
`CSpace` releasing thousands of objects, is torn down iteratively with constant stack use, and no
arm runs inside another's lock scope (a nested `CSpace`'s derivation drain takes the derivation
lock after the outer arm has released it; a wait set's sources are torn down after
`wait_set_drop` has released every source lock).

The call takes the interrupts pending on its CPU between every two teardowns (`interrupt_window`),
so a fan-out masks interrupts for one teardown at a time, and the teardowns whose own walks the
owner sizes take them between batches: a dying `CSpace`'s release pass after every
`RELEASE_BATCH_LEAVES` slot leaves (4 leaves, 224 slots), the sort of its kept arena pages, their
leases and the release of its holds on them ([§ Body Arena](#body-arena)), an owner's death-observer
chain after every `OBSERVER_BATCH_NODES` (64) nodes, an address space's frame release after every
page table ([memory-internals.md](memory-internals.md) § Frame Map Table), and an Mmio object's
mapping withdrawal after every mapping and every `SPILL_BATCH_CHUNKS` (64) spill chunks ([§ Mmio
Mappings](#mmio-mappings)). A registry walk (`thread_registry::for_each`) and an IPC source's
release of its waiters (`ipc::drain_in_batches`) take them between their batches, each batch one
hold of its lock. Every context that calls `dealloc_object` allows a window, holding no lock and
running where an interrupt may be taken with preemption disabled: a syscall and its epilogue, fault
delivery between its park commit and its `schedule()`
([scheduling-internals.md](scheduling-internals.md) § `ThreadState` Transitions, "Voluntary-block
window"), the end of an interrupt taken from user mode (§ Return Work there), and the idle thread's
drain. A window between two teardowns exposes no partial state: the popped object is torn down whole
before the window, the queued ones are reachable by nothing but their own links, a `CSpace`
wrapper's arena pages' `owner` back-pointers, which the windows of its arena-page pass expose
already, and a queued `AddressSpace`'s bound threads, whose pins its count of 0 refuses, and no
interrupt handler releases a reference, so no cascade runs nested inside another on its CPU.

The walk holds no lock across groups (each group's return takes only its Memory object's locks,
its read lock and its retype-allocator lock), and takes the interrupts pending on its CPU after
every group but the create-time slab's (`interrupt_window`, as seeding does, [§ Donation
Records](#donation-records)). Between two windows it therefore masks interrupts for one group: at
most `RECORDS_PER_PAGE` records of one Memory object, whose return costs one walk of that object's
page free list (at most one node per page of the object, [docs/limits.md](../../../docs/limits.md)),
an insertion per run, and the sort of the group. The kept arena pages are a dimension of their
own, bounded by the bodies that outlive the `CSpace`, one page per body at most, and their sort and
leases take windows of their own ([§ Body Arena](#body-arena)). Before taking the locks, the
return zeroes the group's runs
([memory-internals.md](memory-internals.md) § Kernel Object Memory), taking the pending interrupts
after every 16 pages it zeroes, so the zeroing adds at most one 16-page batch of stores to a window.
Neither the donation count nor any `init_pages` lengthens the window; the walk's
total length still grows with the donation count and, through the zeroing, with the pages donated,
the create-time slab's `init_pages` included. It runs to completion in whichever context drops
the last reference: the deleting syscall, with interrupts masked on that CPU except in the windows;
or, when the owner is handed to the per-CPU deferred-reclaim stack (a thread deleting an object it
is itself bound to, a syscall pin or a batched capability move dropping the last reference, or an
Mmio object's mapping record releasing the address space at that object's teardown; the producer
list is [thread-lifecycle-and-sleep.md](thread-lifecycle-and-sleep.md) § Self-teardown) — the next
syscall epilogue on that CPU, with interrupts masked except in the windows, or the idle thread's
drain, with interrupts enabled ([scheduling-internals.md](scheduling-internals.md) § Lock
Hierarchy, "Bare spin locks"). So an owner's teardown time scales with how much it donated, which
the zeroing visits once per page, and with how finely, and can land on an unrelated thread's
syscall, which is not preempted during it: the same memory donated as single pages costs one record
per page. The standard runtime's map retry donates one
page per page-table shortfall (its budget top-up donates the shortfall in one call), so a
process's count is of the order of its page-table page count, one per 2 MiB of mapped span.

### Body Arena

Some kernel objects a syscall creates have no Memory capability in the call to be retyped from:
the bodies of a range split (`SYS_MEMORY_SPLIT`'s tail, the two children of `SYS_MMIO_SPLIT`,
`SYS_IRQ_SPLIT`, `SYS_IOPORT_SPLIT`, and `SYS_SCHED_SPLIT`), the joined object of
`SYS_MMIO_MERGE`, the fresh object of an `Mmio`, `IoPort`, or `Interrupt` copy
([§ Copies and Lineages](#copies-and-lineages)), the mapping records
past an `Mmio` object's inline ones ([§ Mmio Mappings](#mmio-mappings)), and a thread's
port-binding table ([§ IoPort Bindings](#ioport-bindings)). A `CSpace` the call names funds them
from its pool, as it funds the slot:

| Body | Funded by |
|---|---|
| A split's children | the caller's `CSpace`, which receives them |
| An `Mmio`, `IoPort`, or `Interrupt` copy | the destination `CSpace` |
| An `Mmio` mapping-record spill chunk | the `CSpace` the map resolves through |
| A port-binding table | the bound thread's own `CSpace` |

The first three are 128-byte chunks of the `CSpace`'s body arena (`cap/arena.rs`). The arena
carves a pool page into 32 chunks: chunk 0 holds the page's header, an `ArenaPage`, and the other
31 go on the wrapper's free-chunk list, serialised by the pool's lock, from which
`CSpaceKernelObject::alloc_body` places a body. The header is a kernel object of its own:

| `ArenaPage` field | Content |
|---|---|
| `header` | a `KernelObjectHeader` whose reference count is the page's live chunks plus one hold, the owning `CSpace`'s while it lives and its teardown's while that runs; `ancestor` is null until the teardown keeps the page |
| `owner` | the funding `CSpaceKernelObject`, null once its teardown has passed the page |
| `next` | the owner's list of its arena pages, then its teardown's list of the pages it keeps |
| `kept_next` | the teardown's list of every page it keeps |
| `lock` | serialises `owner` against a chunk free, which pushes the chunk to the owner's list while the owner lives |
| `record` | the address of the record of the donation the page lies in, taken from the free pool page it was carved from |

A body's `header.ancestor` names its page, so its free returns the chunk there: to the owner's
list while the owner lives, releasing the page's reference either way. A page the arena takes
debits the growth budget like a slot page, so `CAP_INFO_CSPACE_CAPACITY` and
`CAP_INFO_CSPACE_BUDGET` count it, and an empty pool fails the call with the refillable
`OutOfMemory`, which an augment-mode `SYS_CAP_CREATE_CSPACE` lifts. Since a call may need a page
for its body when slot headroom is ample, a funder holds a page of budget beyond the slots it funds
(`syscall_abi::cspace_topup_pages`); a funder that knows its bodies in advance sizes its donation
with `CSPACE_BODIES_PER_PAGE` and `IOPORT_BINDING_TABLE_PAGES`, which the ABI publishes and the
kernel asserts, as init funds its own `CSpace`
([init Bootstrap Stages](../../../services/init/docs/bootstrap.md)). A port-binding table takes
three whole pool pages instead, and never outlives its pool: the thread's dealloc returns it, or,
when the thread's `CSpace` dies first, that teardown does, under the thread's `sched_lock` in both
cases, and a bind allocates and installs it under the same lock only while the thread is not
`Exited`. The kernel's SEED reserve
holds only the boot footprint (initialization.md § Phase 7); the one runtime body page it backs is
the root `CSpace`'s arena page for init's first split, before init funds its `CSpace` itself.

A chunk body can outlive its funder: a capability moved to another `CSpace` (`SYS_CAP_MOVE`, an IPC
transfer) keeps its body in the funder's arena. The teardown keeps only the pages such bodies sit
on. When the wrapper's reference count reaches zero, its dealloc arm runs twice. The first run
stops the `CSpace`'s threads, frees their port-binding tables, drains and drops the `CSpace`, and
queues the wrapper on the cascade stack beneath the objects its slots held, as [§
Teardown](#teardown) describes; those objects, and every cascade they start, are torn down first,
so the bodies the `CSpace`'s own slots held are freed to its arena before the second run. That run
makes one pass over its arena pages, clearing each one's `owner` under the page's lock and keeping,
with the owner's hold, every page whose count shows a live chunk, and takes the interrupts pending
on its CPU after every `ORPHAN_BATCH_PAGES` pages (`interrupt_window`), since the owner chose how
many pages there are; no chunk can be allocated any
more, so a count of one stays one, and a higher count never falls below the hold. Each kept page
goes onto its donation record's list (its `record` names it). Every donation then goes back at once
with its kept pages, sorted once (`cap::arena::sort_list`), cut out of its span
(`cap::arena::for_each_run`): each kept page takes a lease of its own on the Memory object its
donation came from and records it as its `ancestor`, and the runs between kept pages go back, with
the runs of the other donations of its group ([§ Teardown](#teardown)), through one walk of that
Memory object's page free list (`cap::retype::retype_free_runs`). The
teardown then releases its hold on each kept page. Since the owner chose how many bodies outlive
the `CSpace`, the sort takes the interrupts pending on its CPU after every `KEPT_SORT_BATCH_STEPS`
(256) steps, each step taking one page off a list or placing one in a merged run, and the leases
and the releases after every `KEPT_BATCH_PAGES` (64) pages (`interrupt_window`, with no lock
held). The release of a page's last reference, its
hold's or its last chunk's, returns the page to that Memory object (the `ArenaPage` arm of
`dealloc_object`). A dead `CSpace` therefore holds, past its death, only the pages its surviving
bodies sit on, each to its Memory object, the analogue of a retyped object pinning its Memory
capability; nothing it donated depends on its own bodies, so neither a donation of a tail the
`CSpace`'s own arena funded nor two `CSpace`s funding each other's donated tails can keep a pool
alive.

The cut sorts each donation's kept pages once and walks its span with them in order, so a teardown
with `r` donation records and `h` kept pages costs `O(r + h log h)`, allocating nothing and on a
fixed stack (the sort is a bottom-up merge through 64 sorted runs), plus one walk of each record's
Memory object's page free list and the zeroing of every page it returns, `O(p)` for `p` donated
pages, as the return of a donation without kept pages costs ([§ Teardown](#teardown)). `h` counts
only pages holding a body that outlives the `CSpace`: at most one per such body, and at most the
`CSpace`'s arena pages, one per 31 bodies it funded. Each of those
pages returns later, in the call that frees its last chunk, as a one-page `retype_free`.

---

## Capability Slot (`cap/slot.rs`)

### Representation

```rust
pub struct CapabilitySlot
{
    /// Discriminant identifying the kind of capability (or Null).
    tag: CapTag,

    /// In-flight pin (non-zero while pinned).
    pin: u8,

    /// Rights bitmask for this slot (16 bits). Interpretation is tag-dependent.
    rights: Rights,

    /// Per-slot generation, wrapping at 2^31.
    generation: u32,

    /// Caller-identifying badge (0 = unbadged). Set via SYS_CAP_DERIVE_BADGE.
    /// Immutable once set; inherited by derivation and copy. On a Null slot
    /// linked on the free list: the free-list marker.
    badge: u64,

    /// Pointer to the kernel object this capability refers to.
    /// Null when tag == CapTag::Null.
    object: Option<NonNull<KernelObjectHeader>>,

    /// Derivation tree pointers (intrusive linked list).
    deriv_parent: Option<SlotId>,
    deriv_first_child: Option<SlotId>,
    deriv_next_sibling: Option<SlotId>,
    deriv_prev_sibling: Option<SlotId>,
}
```

The slot is 72 bytes (`#[repr(C)]`): the tag, pin, rights, and generation fill its
first word with no implicit padding. 56 slots per CSpace page = 4032 bytes, fitting
one 4096-byte pool page with 64 B of tail slack.

`SlotId` is a global identifier combining a CSpace ID, an epoch generation
tag, and a slot index: `{cspace_id: u32, epoch: u32, index: NonZeroU32}`
(12 bytes; `Option<SlotId>` niche-optimises to the same size via the
`NonZeroU32` index). This allows derivation tree traversal across CSpace
boundaries without holding per-CSpace locks longer than necessary, and lets
`lookup_cspace(id, expected_epoch)` fail fast when a CSpace's id has been
recycled. As of #248 the epoch is a random non-zero value redrawn on each
recycle (not a monotonic counter); the equality check is unaffected, and the
random redraw excludes the prior value so an immediately-recycled `SlotId`
always fails fast. A `SlotId` stale across several recycles can match a later
random epoch with probability ~2⁻³² per recycle; this residual is accepted
because the capability, not the `SlotId`, is the authority. See #137 for the
recycling allocator design.

The registry that maps a `CSpaceId` to its live `CSpace` and epoch is described in
§ CSpace Registry above.

### Per-Slot Generation

Each slot carries a 32-bit **generation** field holding a counter that wraps at 2^31
(`CAP_GEN_BITS`), so it fits the handle's generation field and leaves the handle's bit 63 clear.
`CSpace::free_slot` increments it every time the slot is recycled. The generation is encoded into
the capability handle userspace receives — `handle = (generation << CAP_INDEX_BITS) | index` (see
[capability-model.md](../../../docs/capability-model.md) § Capability Handle Format) — and
`syscall::pin_slot` (and `lookup_cap` through it), together with the raw-resolution paths in
`syscall/cap.rs` (whose `revalidate_src_under_lock` `syscall/mem.rs` reuses), `syscall/ipc.rs`,
`cap/transfer.rs`, and `cap/split.rs`, rejects a handle whose generation no longer matches the
slot's, returning `InvalidCapability`. This is the #349 fix: a stale handle that reaches a recycled
slot — including a slot a cross-`CSpace` revoke freed out from under its holder — fails closed
instead of aliasing the new occupant. A never-recycled slot has generation 0, so its handle equals
the bare index — the backward-compatibility hinge that lets long-lived boot caps keep their
historical handle values.

The generation is distinct from `SlotId.epoch` (the `CSpace` registry epoch, a random value redrawn
each time the id is recycled) and from the free-list marker. It must survive the
free→reallocate transition: `free_slot` bumps it *before* threading the slot onto the free list,
`set_next_free` preserves it, and `allocate_slot` clears the slot with `clear_keep_generation`
(which keeps it). The counter wraps after 2^31 recycles of one index, a bounded ABA window: a
handle held across exactly a multiple of 2^31 recycles of its index matches the slot's generation
again and resolves to the occupant of the moment. The slot index stays in service at wrap rather
than being retired, since a retired index is a slot leaked for the `CSpace`'s life and a hot index
on the LIFO free list is recycled at the rate of its create/delete cycle.

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
    IoPort        = 11,  // x86-64 only; Phase 7 mints one root cap over the full 64K port space
    SchedControl  = 12,  // priority-band authority; carries [min, max], no rights bit
    SbiControl    = 13,  // SBI forwarding authority (RISC-V only)
    EntropyControl = 14, // authority to contribute bytes to the entropy pool
    KernelLog     = 15,  // authority to read the kernel log
}
```

### Rights Bitmask

Rights are scoped per capability type: each slot stores one 16-bit erased rights
word (`Rights`), and the slot's `CapTag` selects which type's vocabulary
interprets it. Every type numbers its bits from 0 in its own full-width space.
The `u64` `RIGHTS_*` constants in `abi/syscall` are the single source of truth
for bit values; the kernel defines a `TypedRights<K: CapKind>` newtype per type
(`MemRights`, `EpRights`, `NtfRights`, ...) whose constants are derived from the
ABI values, so a rights constant of the wrong capability type cannot be passed
to a lookup at compile time; deriving them const-asserts each ABI bit is below
bit 16, so a type with a seventeenth right fails the build until the word
widens. A `u64` rights mask a syscall takes keeps its low 16 bits
(`Rights::from_mask`): the bits above name no right of any type, so attenuation
is unchanged. Scoping and attenuation semantics are in
[docs/capability-model.md](../../../docs/capability-model.md) § Rights and Attenuation.

Per-type vocabularies (bit positions within each type's own space):

```text
Memory        MAP=0  WRITE=1  EXECUTE=2  RETYPE=3
AddressSpace  MAP=0  READ=1   CONTROL=2
Endpoint      SEND=0 RECEIVE=1 GRANT=2 IDENTIFY=3
Notification  NOTIFY=0 WAIT=1
EventQueue    POST=0 RECV=1
Interrupt     NOTIFY=0
Mmio          MAP=0  WRITE=1
Thread        CONTROL=0 OBSERVE=1
CSpace        INSERT=0 DELETE=1 DERIVE=2 REVOKE=3
WaitSet       MODIFY=0 WAIT=1
IoPort        USE=0
SchedControl  (no rights bits: presence + [min, max] band is the authority)
SbiControl    RESET=0 SUSPEND=1 CPPC=2 BASE=3 DBCN=4 (bit 5 reserved)
EntropyControl CONTRIBUTE=0
KernelLog     READ=0
```

Rights are checked at every syscall that uses a capability. The check is a single
bitwise AND: `(slot.rights & required) == required`.

W^X is enforced at mapping time. `sys_mem_map` takes the mapping's writable and executable
flags from the requested protection bits, each of which must be backed by the Memory cap's
Write or Execute right, or from those rights when no bits are given. `sys_mem_protect`
takes them from the new protection bits, each bounded also by the Write and Execute rights of
the cap that mapped the page ([memory-internals.md § Leaf Grant](memory-internals.md#leaf-grant)).
Either syscall returns `WxViolation` when both flags are set.

A capability may carry both Write and Execute rights (representing independent
authorities). W^X is enforced when those rights are exercised on a specific
mapping — no page may be simultaneously writable and executable (see
[docs/capability-model.md](../../../docs/capability-model.md) § Memory).

### Kernel Object Reference Counting

Each kernel object (Endpoint, Notification, EventQueue, etc.) has an embedded reference
count over the capability slots that point to it and the kernel-internal owners that
hold it (the principal ones are listed below):

```rust
pub struct KernelObjectHeader
{
    ref_count: AtomicU32,
    obj_type: ObjectType,
    /// The high 24 bits of the dealloc-cascade link while the object is
    /// queued on one (its low 32 bits sit in `ref_count`, then 0; an
    /// `AddressSpace` keeps its link in its wrapper instead); zero at every
    /// other time.
    cascade_link_hi: [u8; 3],
    /// The Memory object this object's bytes were retyped from.
    ancestor: AtomicPtr<KernelObjectHeader>,
}
```

When a slot is cleared (for example by deletion, revocation, or the teardown of the CSpace holding
it) or a kernel-internal owner releases its reference, the reference count is decremented. When it
reaches zero, the object's bytes are returned to the Memory object it was retyped from
(`retype_free`). Apart from a never-published body that a failed split, a failed `SYS_MMIO_MERGE`,
or a failed `SYS_CAP_CREATE_*` insert rolls back at its initial count, this is the only mechanism by
which kernel objects are freed — there is no explicit "destroy" syscall (see
[docs/capability-model.md](../../../docs/capability-model.md) § Auto-reclaim). A holder reads
whether the count holds anything beyond its own slot with `SYS_CAP_INFO`'s `CAP_INFO_SOLE_REFERENCE`
([syscalls.md](syscalls.md#sys_cap_info-36) § `SYS_CAP_INFO`).

A Memory object also counts, apart from its reference count, the capability slots that name it
(`MemoryObject::slot_count`): `CSpace::fill_slot`, the one fill every insert goes through, raises
it, and `CSpace::free_slot` and a dying `CSpace`'s object drop (§ Teardown) lower it. A slot that
names an existing object is filled, and an occupied slot freed, only under the derivation lock
(§ Global Derivation Lock), so the count is exact for a holder of that lock; the dying `CSpace`'s
drop runs outside it but only lowers the count. `SYS_MEMORY_SPLIT` and `SYS_MEMORY_MERGE` read it
to refuse an object another slot names
([syscalls.md](syscalls.md#sys_memory_split-33) § `SYS_MEMORY_SPLIT`).

An Endpoint counts the slots that name it with the Receive right
(`EndpointState::receivers`) through the same hooks: `CSpace::fill_slot` calls `note_slot_filled`,
and `CSpace::free_slot` and a dying `CSpace`'s object drop call `note_slot_released`, each of which
dispatches on the slot's tag and rights (a Memory slot to `slot_count`, an Endpoint slot with the
Receive right to `receivers`). A slot without the Receive right, a wait-set membership, and a
fault-handler binding are not counted. Where a release leaves the count at zero (`SYS_CAP_DELETE`,
a revoke's `dealloc_revoked`, `release_moved_object`, and a dying `CSpace`'s drop),
`release_if_unreceivable` releases the endpoint's queued callers and parked receivers before the
reference goes ([ipc-internals.md](ipc-internals.md) § Endpoint).

The count is the low 31 bits of the 32-bit word and cannot wrap; bit 31 is `REF_OBSERVED`, set while
a sole-reference observer is bound (§ Sole-Reference Observers), and every reader masks it
(`references_in`). The references userspace can multiply without a bound of their own, new
capability slots, retype leases, death-observer and sole-reference bindings, Mmio mapping records,
and interrupt bindings, are refused at `REF_COUNT_LIMIT` (2^30) with `QuotaExceeded`: a copy,
derivation, badged derivation, or move takes its new slot's reference through
`KernelObjectHeader::try_inc_ref`, the one checked increment (a move's destination counts because a
move its liveness backstop abandons leaves both slots live; an IPC transfer instead checks every cap
of its message before its first move, so it refuses all or none, and its moves take their
references unchecked), and `retype_allocate` refuses a retype from a Memory object whose count is
at the limit, before the new object takes its lease; an observer bind takes its reference on the
queue through `try_inc_ref` too, since the queue's creator funds any number of observer nodes,
`SYS_MMIO_MAP` takes a mapping record's reference on the address space the same way, since its
mappers fund any number of records, and `SYS_IRQ_REGISTER` takes a binding's reference on its
Notification the same way. The limit is correct as is, not one a workload meets: each such
reference costs a 72-byte slot, a retype child of at least 128 bytes, a 40-byte observer node, or a
16-byte mapping record beside the page-table entry its mapping holds, so 2^30 of them hold at least
16 GiB against one object, and reaching it refuses instead of carrying the count into the flag.
Every other reference is taken unchecked, in the 2^30 of headroom between the limit and the flag,
because each kind is bounded by an object count rather than by a request. Per thread: its syscall
pins (a few), its fault-handler binding (one), its fault redirect (one), the lease of a retype it
has in flight that passed `retype_allocate`'s check just before the count reached the limit (one),
and the destinations of an IPC transfer it has in flight that passed the message check (at most
`MSG_CAP_SLOTS_MAX`, four); fewer than 16 in all. Per other object: wait-set membership (one per
source), SEED leases (the boot mints, bounded by the SEED reserve), and the destinations IPC
transfers' abandoned moves leave live (a message check refuses once the count is at the limit and
transfers run one at a time under the derivation lock, so these keep an object's slot references
within `MSG_CAP_SLOTS_MAX - 1` of the limit). Exhausting the headroom would take some 2^26 threads,
each with its own kernel stack and TCB (at least 1 TiB of kernel stacks).

The principal kernel-internal owners:

- **Retype ancestry.** Each object retyped from a Memory object holds a reference on
  that ancestor (`header.ancestor`), released when the descendant is freed; the
  kernel's boot-minted objects hold the same reference on the SEED reserve.
- **Page-pool donations.** A Memory object donated to an AddressSpace's or CSpace's
  page pool is referenced by the donation record until that AddressSpace or CSpace is
  freed. The Memory object an AddressSpace or CSpace is created from is referenced
  once, by donation record 0, which serves as its retype ancestry too.
- **Arena pages.** A body a `CSpace`'s arena funded (a split's children, an `Mmio`,
  `IoPort`, or `Interrupt` copy, a mapping-record spill chunk) holds a reference on the arena
  page it sits on, and the page a hold of its owner's; a page kept past its owner's death holds
  a lease on the Memory object its donation came from until its last chunk goes
  ([§ Body Arena](#body-arena)).
- **Mmio mapping records.** Each `SYS_MMIO_MAP` mapping an Mmio object records holds a
  reference on the target `AddressSpace`, taken through `try_inc_ref`, released when the object is
  freed and the mapping withdrawn ([§ Mmio Mappings](#mmio-mappings)), so an address space outlives
  its last capability while an Mmio capability mapped into it lives.
- **Kernel-lifetime pins.** The SEED reserve holds a reference the kernel never releases
  (the SEED pin from `install_seed_memory`), so it is never freed. No other object is
  pinned: the root CSpace's creation reference, the kernel's hold on it through boot,
  passes to init's own CSpace capability in Phase 9
  ([§ Initial CSpace Population](#initial-cspace-population)).
- **Fault-handler binding.** `SYS_THREAD_SET_FAULT_HANDLER` and
  `SYS_THREAD_INHERIT_FAULT_HANDLER` take a reference on the bound Endpoint for each fault class
  they bind, released on that class's unbind or rebind, or on thread destruction. The binder
  publishes each class's endpoint and badge as one unit under the target thread's `sched_lock`
  and releases the replaced bindings' references only after it unlocks (`release_ref`); the
  inheritance takes the source's references under the source thread's `sched_lock`, while the
  source's bindings still hold the endpoints.
- **Fault delivery.** `ipc::fault::fault_dispatch` reads the faulting thread's binding once,
  under that thread's own `sched_lock`, and takes its own reference on the endpoint in the same
  hold, while the binding's reference still holds it. It releases that reference after the
  delivery and before its park (the pin-before-park rule), so a concurrent rebind or unbind
  cannot free the endpoint mid-delivery; a release that drops the last reference runs the
  endpoint's teardown, whose send-queue drain kills the faulter if it is still queued there; the
  drain also runs when no capability with the Receive right on the endpoint is left.
- **Fault redirect.** A `FAULT_REPLY_REDIRECT` reply takes a reference on the Endpoint it names
  into the faulting thread's `fault_redirect` field (one per thread), held until the thread's next
  delivery takes it (as a fault delivery does a binding's) or the thread's destruction releases
  it ([fault-handling.md § Reply](../../../docs/fault-handling.md#reply)).
- **Death-observer bindings.** `SYS_THREAD_BIND_NOTIFICATION` and
  `SYS_ASPACE_BIND_NOTIFICATION` take a reference on the bound EventQueue, under the owner's
  lock (the thread's `sched_lock`, the address space's `death_lock`), held for the binding's
  lifetime. The owner's teardown (the `dealloc_object` Thread and `AddressSpace` arms)
  returns each observer node to its queue's pool and then releases the reference, queueing a
  queue it drops to zero on the dealloc cascade (§ Teardown); a death walk runs on the dying
  thread or on a faulting thread of the live address space, so the owner, and with it every observer
  reference, outlives every post. A bind after the death posts at once under the binder's
  syscall pin and takes no reference.
- **Sole-reference bindings.** `SYS_CAP_BIND_SOLE_REFERENCE` takes a reference on the bound
  EventQueue through `try_inc_ref`, held until the binding posts: the drain returns the node to
  its queue's pool and then releases the reference (§ Sole-Reference Observers). The binding holds
  no reference on the object it observes.
- **Interrupt bindings.** A bound `Interrupt` binding holds a reference on its Notification's
  object, taken by `SYS_IRQ_REGISTER` through `try_inc_ref` and released only by the change that
  takes the notification from the binding (a rebind to another notification, or the binding's
  removal when its Interrupt object is freed, `irq::unregister`), once no delivery can still hold
  the notification. A Notification a binding names is therefore not freed
  ([§ Interrupt Bindings](#interrupt-bindings)).
- **Syscall pins.** Every syscall that resolves a handle to use the object it names
  holds a reference on that object for as long as it uses it: `syscall::pin_slot` (and
  `lookup_cap` through it) takes it under the slot's CSpace lock and returns it as a
  `syscall::PinnedCap`, whose drop releases it through `cap::object::release_ref`. A
  release that drops the last reference queues a `Thread`, `CSpace`, or `AddressSpace` for
  this CPU's deferred reclaim (it may be bound to the running thread) and frees any other
  type in place. A pin is dropped before its syscall parks (the pin-before-park rule of
  [scheduling-internals.md § Lock Hierarchy](scheduling-internals.md#lock-hierarchy)): a
  thread killed while parked never runs the destructor, and the park's binding, not the
  pin, keeps the parked thread reachable from the object's teardown.
- **Thread address-space pins.** `SYS_THREAD_READ_MEM`, `SYS_THREAD_WRITE_MEM` and
  `SYS_THREAD_LIST_PAGES` reach the address space a thread executes in, which no reference of
  the thread holds: the space's teardown instead marks every bound thread `Exited`, under the
  thread's `sched_lock`, before it frees anything. `sched::pin_thread_aspace` reads the thread's
  state and space under that lock and, while the thread is not `Exited`, takes a reference with
  `KernelObjectHeader::inc_ref_if_live`, which refuses a count of zero rather than revive an
  object whose teardown has begun. A space queued on a dealloc cascade reads zero too, since the
  cascade keeps its link outside the count ([§ Teardown](#teardown)). The reference is released
  through `release_ref` when the copy or the listing ends, before the syscall returns, as a
  syscall pin's is.
- **Wait-set membership.** `sys_wait_set_add` `inc_ref`s the source's header under the
  source's lock together with the back-pointer publication; `sys_wait_set_remove` and
  `wait_set_drop` perform the matching `dec_ref`. The source's state therefore outlives
  every wait-set member referencing it; the Endpoint/Notification/EventQueue dealloc arms
  only `debug_assert` that `state.wait_set` is null on entry (the invariant follows from
  the refcount). The membership protocol is in [ipc-internals.md](ipc-internals.md)
  § Wait Set Add/Remove.

**Pin invariant.** A syscall pin may be taken only on an object whose count is not zero, so
`pin_slot` takes it under the CSpace lock while the slot it reads is still occupied, and every path
that frees an occupied slot clears the slot under that CSpace's lock before it releases the
reference the slot held: `SYS_CAP_DELETE`, the revoke batch's `unlink_free_collect`, the range
splits' consume of the original (`install_split_children`) and their rollback of a child, the
`SYS_MEMORY_MERGE` tail, both caps a `SYS_MMIO_MERGE` consumes (`commit_mmio_merge`), and a move's
freed source (`free_source`, released through `release_moved_object`). A slot observed occupied
under the lock therefore still holds its reference, and the increment lands before any release can
reach zero. The one release that clears no slot, the dying CSpace's `for_each_object` drop in its
`dealloc_object` arm, runs only after every thread bound to the CSpace is stopped and off every CPU
and the CSpace is unregistered, so no `pin_slot` can be reading it.


### Sole-Reference Observers

`SYS_CAP_BIND_SOLE_REFERENCE` binds an observer node to the object a capability names, and the
kernel posts `(0, correlator)` through it once: the first time the drain finds the object at one
reference after the bind, or at the object's death
([syscalls.md](syscalls.md) § `SYS_CAP_BIND_SOLE_REFERENCE`). A server that lends a client a
derivation learns this way that the client's copies are gone, with no query of its own to prompt.
The mechanism is `cap/sole_reference.rs`.

- **The flag.** Bit 31 of the count word, `REF_OBSERVED`, marks an observed object. It rides in
  the word so that `dec_ref` learns it from the value its `fetch_sub` returns: one signed compare
  of that value passes every decrement that leaves two or more references and finds the flagged
  words, the last release and an underflow, so with no observer bound the decrement costs what it
  did before the flag, with no memory access and no lock. Increments never
  read it, and the limit and the headroom above keep the count below it (§ Kernel Object Reference
  Counting).
- **The table.** One leaf spinlock, 256 chains keyed by a hash of the object address, and a
  pending mask with a bit per chain. A chain holds one node per observed object, the object's
  other nodes hanging off it through `ObserverNode::group`, so the work under the lock grows with
  the observed objects of a chain, not with their observers. The node is a queue's observer-pool
  node (`ipc::event_queue::ObserverNode`, a `DeathObserver` with the object and group links),
  charged to the queue's retype debit. Nothing is acquired and no reference is released under the
  lock, and it serialises every change to the flag and the chains, so the flag is set exactly while
  the object's nodes are on its chain.
- **The bind.** Under the syscall's pin on the object, the bind takes a node from the queue's pool
  and a reference on the queue, then, under the table lock, links the node and sets the flag. Its
  pin release is an ordinary decrement: when the slot is the only other holder, that release is the
  fall to one reference, which the next drain posts.
- **The fall to one.** The decrement from `REF_OBSERVED | 2` sets the pending bit of the object's
  chain, computed from the address alone. It reads the object no further: that decrement may have
  released the decrementer's last hold on it, so another CPU may already have freed it.
- **The death.** The decrement from `REF_OBSERVED | 1` leaves no reference, so its caller owns the
  object. Under the table lock it moves the object's nodes from the chain to the fired list and
  clears the word, before the caller's dealloc cascade reuses it as a link. A flagged object
  reaches zero only this way, so no binding ends without a post.
- **The drain.** `drain_deferred_reclaim`, after its reclaim, on a syscall return whose CPU's
  `SOLE_REF` bit is set and in the idle loop, and `sched::interrupt_return_work` on an interrupt
  return from user mode whose CPU's `SOLE_REF` bit is set (scheduling-internals.md § Return Work),
  read one summary word when nothing is pending: `sole_reference::drain` is inline, a load and a
  branch, and its pass is out of line. That load is Relaxed. An ordering would not make it
  see a newer value, only order the accesses after it, and the pass orders its own through its
  Acquire load and AcqRel swap of the summary. A bit the CPU set itself, by a release or by a pass
  that left fired nodes, is seen by its own later load unless a pass that cleared the bit, on any
  CPU, took its work, so the release is claimed by this CPU's next pass or by that one; either
  pass may post after the call that made the release returns, and the budget may leave the post
  to a later pass, as The budget says. A bit set by another CPU that the load misses is drained
  by that CPU at its own next drain point (its syscall return, its next interrupt from user mode,
  or its idle loop), or by a CPU after its next timer tick, so the bound under The budget holds.
  Otherwise, under the table lock, it claims each object of a pending chain whose word is
  `REF_OBSERVED | 1` by a compare-and-swap to 1, moving its nodes to the fired list, and takes at
  most `POST_BUDGET` (64) nodes off the fired list. An object on a chain is live,
  since its death takes it off the chain under the same lock before its memory can be reused. A
  compare-and-swap that races an increment either fails, and the object stays bound, or wins, and
  the count was one. After the unlock the drain returns each node to its pool, posts through
  `sched::post_one_death_event`, and releases the binding's queue reference, so no post is made
  under `DERIVATION_LOCK` or a CSpace lock, and a binder that receives a post finds its node
  free.
- **The budget.** A death fires every node bound to the object, any number of them, each funded by
  its binder's queue. The budget bounds what one pass does for observers its thread did not bind.
  Nodes left on the fired list keep the summary's fired bit set for a later pass. A decrement that
  marks the table or fires observers posts its own CPU's `SOLE_REF` bit, a pass that leaves fired
  nodes posts it again, and each CPU's timer tick posts its own while the summary is nonzero
  (`sole_reference::work_pending`), so a pass runs at the next return to user mode of the CPU
  that made the mark or left the nodes, and of every CPU a tick reaches meanwhile, one pass per
  return (scheduling-internals.md § Return Work). An idle CPU whose run queues are empty drains
  too, a pass at a time, before its halt decision. The next pass therefore comes within a timer
  tick while any CPU runs user code or idles; when every CPU is in the kernel across a tick, it
  comes at the first return to user mode or idle-loop pass after it. Each pass posts up to the
  budget. The drain that claims a post may run on a CPU other than the one whose release made it,
  so a post can reach its queue just after the call that made the release returns.
- **What a post means.** Every arrival at `REF_OBSERVED | 1` is a decrement from
  `REF_OBSERVED | 2`, which marks the chain, so a count that rests at one is always found. A count
  that falls to one and rises again before the drain looks is not claimed, and is found at its next
  fall to one or at the object's death. A bind on an object already observed links a second node,
  and each node posts once. The remaining reference may be any holder's, the binder's or another
  kernel owner's; a move, the one an IPC transfer makes at rendezvous, takes its destination's
  reference before it frees its source, so a capability in transit never dips the count.

---

## Range Capability Objects

Mmio, IoPort, and Interrupt capabilities grant hardware access that outlives the syscall that
establishes it: a page mapping, a thread's I/O permission bitmap, or a Notification's binding
to an interrupt line. Revocation must withdraw that access
([docs/capability-model.md](../../../docs/capability-model.md) § Interrupt, § Mmio, § IoPort),
so the kernel ties each grant to the object of the capability it was made through, and
withdraws it when that object is freed.

### Copies and Lineages

`SYS_CAP_COPY`, `SYS_CAP_DERIVE`, and `SYS_CAP_DERIVE_BADGE` of an Mmio, IoPort, or Interrupt
capability do not share the source's object: `object_for_new_slot` places a fresh object over the
same range in the arena of the `CSpace` that receives the new slot ([§ Body Arena](#body-arena)), so
every slot owns its object, and deleting the slot, consuming it with a split (or, for an Mmio, a
merge), or revoking an ancestor of it frees it (a syscall pin defers the free to the pinning
syscall's end, as for any object). A boot mint, a range split, or an Mmio merge produces a lineage
*root*; a copy records its root (`RangeLineage`), and the root's lineage count holds a root share
while the root has references plus one per live copy. A copy past `RANGE_COPY_LIMIT` live copies of
one root returns `QuotaExceeded`, counting the copies alone whether or not the root is still
referenced. The limit is the count's encoding bound below the root share (2^31 - 1), not a capacity:
each copy costs its funder a slot and a chunk, so the limit's copies would hold more than 400 GiB of
pools. A split of a copy produces two fresh roots, each with a lineage of its own. A copy's body is
freed with its last reference; the root's body is freed when its last share goes, so a copy's root
pointer never dangles.

### Mmio Mappings

An `MmioObject` holds `MMIO_INLINE_MAPPINGS` (4) mapping records inline, each an `AddressSpace`
(with a reference) and the VA of the region's first page; mapping the object again at a place
already recorded reuses its record. A mapping past the inline records goes to a spill chunk of seven
records, taken from the arena of the `CSpace` the map resolves through ([§ Body Arena](#body-arena))
and chained from the object, newest first; a map whose arena cannot fund a chunk returns
`OutOfMemory`. The records are atomics: `sys_mmio_map` claims a free record by compare-exchange,
fills its VA, and publishes the address space last with Release, and pushes a new chunk, its first
record already claimed, onto the chain's head by compare-exchange, so concurrent maps through one
object need no lock. Two maps racing to record the same place may each take a record, and two
finding every record taken may each push a chunk, which costs a record or a chunk and is otherwise
harmless. `sys_mmio_map` records the mapping before it maps a page, and holds its pin on the object
across both, so the teardown finds every page a call maps, a partial map included, and never sees a
claimed record unfilled. The object's dealloc arm runs `withdraw_mappings`: for each record, inline
and spilled, `AddressSpace::unmap_region_if_phys` clears, under `pt_lock`, each leaf that still maps
the matching device page (a page the user has since remapped to other memory is left alone), then
issues one TLB invalidation for the span on every CPU that runs the space, after the lock is
released (plus one under the lock each time the span's cleared frames overflow the frame-map release
batch; see [memory-internals.md § Frame Map Table](memory-internals.md#frame-map-table)); the device
frames are never reallocated, so no frame reuse waits on the shootdown. The record's address-space
reference is then released through `release_ref`, so an address space it was the last reference to
goes to this CPU's deferred reclaim, as for a syscall pin: an Mmio object can be freed in place
inside IPC delivery, where an address-space teardown must not run. Each spill chunk then returns to
the arena that funded it. The records and chunks are as many as the owners' mappings, so the
withdrawal takes the interrupts pending on its CPU between two records and after every
`SPILL_BATCH_CHUNKS` (64) chunks it returns (`interrupt_window`, with no lock held; [§
Teardown](#teardown)).

### IoPort Bindings

A bound thread's `iopb` pointer names the bitmap at the head of its port-binding table
(`cap::ioport_bindings::IoPortBindings`): one page holding the bitmap's two page-sized parts
(`ThreadIopb`, ports 0 to 32767 and 32768 to 65535, each in a page of its own), the funder, and up
to `MAX_IOPORT_BINDINGS` (252) records of `(IoPort object, base, count)`, after the record cells
of its three pages. The three pages come from
the pool of the bound thread's own `CSpace` ([§ Body Arena](#body-arena)), taken and installed under
the thread's `sched_lock` while it is not `Exited`, and return there when the thread is destroyed
or, first, when that `CSpace` dies. `sys_ioport_bind` records the binding and permits its ports
under the thread's `sched_lock`; a bind through an object the thread already records changes
nothing, and a distinct object past the 252nd returns `QuotaExceeded`. Each binding is made through
a distinct `IoPort` object, so the bound is one thread's fan-out over separately held port ranges,
and its page is funded by the thread's `CSpace`. A bind of another thread also invalidates every
CPU's TSS bitmap (below), so a target already running elsewhere picks up the new ports at its next
port access. The bitmap is always the union of the recorded bindings.

The IoPort dealloc arm runs `withdraw_everywhere` before the object's bytes go. It walks
the thread registry and, under each thread's `sched_lock`, drops the records naming the
object (compared by address, never dereferenced) and rebuilds the bitmap from the rest; the walk
holds the registry lock a batch at a time, with an interrupt window between batches; a
bind through the object holds a pin on it, so none can record it once the teardown runs.
`dealloc_object(Thread)` detaches a dying thread's table under the same lock before
freeing it. If any bitmap changed, `gdt::invalidate_all_iopbs` stores an out-of-limit
`iopb_offset` into every CPU's TSS, with a trailing fence, so every ring-3 port access after
the revoke raises `#GP`. The `#GP` handler (`gdt::reload_invalidated_iopb`) sees the invalid
offset, reloads the running thread's current bitmap under its `sched_lock`, restores the
offset, and retries the instruction: a port the thread still holds succeeds, one it lost
faults again and is handled as a genuine `#GP`. A thread with no bindings runs with the
out-of-limit offset itself: a context switch to it stores that offset and writes no byte of
the bitmap, and its `#GP` is genuine at once, with nothing reloaded. A context switch to a
bound thread makes the TSS hold its bitmap and restores the offset, under that thread's
`sched_lock` in the hold that marks it running, so a remote bind's or withdrawal's
invalidation is never overwritten by a stale load. A switch to the idle thread, which runs no
ring-3 code, touches neither; the next thread's switch sets the offset for itself.

Each bitmap carries a generation (`ThreadIopb::generation`), drawn from one kernel-wide
64-bit counter by the table's initialisation, by every bind that records a binding, and by
every withdrawal that drops one, so it changes with the bitmap's bytes, under the same
`sched_lock`, and never repeats: no two states of any bitmap, a table freed and reallocated
at the same address or a TCB reused included, share one, and none is 0. Each CPU's TSS records
the generation of the bitmap it last copied (`TssWithIopb::held_generation`, 0 before any).
The context switch and the `#GP` reload copy a bound thread's parts only when that record
differs from the thread's generation, which they read under the thread's `sched_lock`; an
equal record means the TSS already holds exactly the bitmap's current bytes, so a thread
switched away from and back to on one CPU, with only unbound or idle threads between, costs
one offset store. A CPU's TSS is written only by that CPU, except for the offset, which
`TssWithIopb`'s alignment lets another CPU store atomically; any interleaving of a remote
invalidation with a local reload leaves the CPU either invalidated or running a bitmap loaded
under its thread's lock after the rebuild.

### Interrupt Bindings

An `InterruptObject` carries one binding (`irq::IrqBinding`): unbound until `SYS_IRQ_REGISTER`
through it, and then linked in its line's binding list in the IRQ routing table with one bit of the
line's bound and owing masks (`core/kernel/src/irq.rs`, module doc § Sharing). Since a copy is a
fresh object, each capability to a line is a binding of its own, and a line holds at most
`irq::MAX_IRQ_BINDINGS` (64). The object also carries a `route_held` flag: `SYS_IRQ_ROUTE` through
it (`irq::route`) stores it `true`, under the IRQ routing lock, and makes the object a holder of its
line's route, never a copy of it. The object's `dealloc_object` arm removes its binding
(`irq::unregister`) before the body goes: under the IRQ routing lock it unlinks the binding, clears
its bits, waits out the delivery running on the line's CPU (`irq::DeliveryGate`, one per CPU), and
unmasks or releases the line, so no delivery reaches the freed body and the other bindings on the
line stay. It then loads `route_held` (`Relaxed`: the object's last reference is gone) and, when
set, gives up the route (`irq::drop_route_holder`); the line is released once neither a holder nor a
binding remains. A bound binding holds a counted reference on its Notification's object, taken by
`SYS_IRQ_REGISTER` and given up only by the change that takes the notification from the binding (a
rebind to another notification, or this removal), so a Notification is freed only once no binding
names it: its teardown makes no IRQ change, and deleting a Notification's capabilities leaves its
bindings in place until their Interrupt objects rebind or are freed. A range capability (more
than one line) never binds, and its arm finds nothing to remove.

A message-signaled target's capability (`SYS_IRQ_MSG_ALLOC`) is the root of a lineage of its own
over its one id (`irq::is_message`), and every copy or derivation of it is a member of that
lineage. The root body, funded from the minting CSpace's pool, is the target's state: the slot's
entry on the target's CPU (`irq::SlotEntry`) anchors its binding, and the id is computed from the
CPU and slot (`irq::message_id`). The target outlives any one object: the `dealloc_object` arm
frees it (`irq::free_message`, which releases the CPU's slot) only when the release frees the
lineage's root body, once no object of the lineage is left, and the body's funding returns to the
minting CSpace's pool, so no capability can name an id a later mint reuses.

---

## Derivation Tree (`cap/derivation.rs`)

### Structure

The derivation tree is a forest of trees — one tree per root capability, a slot with no
derivation parent. `SYS_CAP_CREATE_*` and the boot population create roots, and a delete, a
split, or a `CSpace` teardown can leave a slot without a parent. The tree is stored
intrinsically in the capability slots themselves (the `deriv_parent`, `deriv_first_child`,
`deriv_next_sibling`, `deriv_prev_sibling` fields), so no external tree allocation is needed.

This is an intrusive N-ary tree using child-sibling representation:

```
root_cap (no parent)
├── derived_A (first child of root)
│   ├── derived_A1 (first child of A)
│   └── derived_A2 (next sibling of A1)
└── derived_B (next sibling of A)
    └── derived_B1 (first child of B)
```

**Transfer** (`SYS_CAP_MOVE`, IPC capability transfer) does not create a new
derivation tree node — the destination slot takes the donor's position in the
tree and the donor's slot becomes null (see
[docs/capability-model.md](../../../docs/capability-model.md) § Transfer for the
semantics and [Move](#move) for how a large child list is migrated).

**Derivation** creates a new node as a child of the source slot in the tree.

### Global Derivation Lock

A single global reader-writer lock protects the derivation tree. Every path that
links, moves, or frees an occupied slot holds it for writing: copy, derive, the
splits, the memory merge, the Mmio merge, move and IPC transfer, delete, revoke, and object
teardown. Inserts that create a derivation root (`SYS_CAP_CREATE_*`, the boot
population) take only the CSpace spinlock — a root has no linkage to edit.
Lock-free readers never traverse the tree; they resolve one slot by handle and
rely on the tag and generation checks described above.

The source of a copy or derive, the parent of a memory split, and both caps of
a memory merge or an Mmio merge are looked up unlocked, so each of those paths revalidates them
under the write lock — same tag-bearing occupancy, same generation, same
object, not pinned by an in-flight revoke, move, IPC capability transfer, or range split — before
touching the object or editing the tree. Every occupied→free transition holds the lock, so a slot
that revalidates stays live (and stays the link's parent) for the rest of the hold. A slot freed
meanwhile fails the call with `InvalidCapability` (a revoke, move, IPC capability transfer, or range
split in flight on it, `InvalidState`); the alternative — `link_child` dropping the link under a
freed parent — would leave the new capability a derivation root outside every ancestor's revoke
reach, and a merge would free a recycled tail index.

This is a deliberate design choice: a single lock avoids deadlock from ordering
multiple per-CSpace locks, and derivation-tree edits are rare relative to
capability use.

The lock is a bare CAS spin lock. Every context that takes it cannot be
descheduled — syscall context with interrupts masked, a preempt-disabled
window, or the idle thread's deferred reclaim, whose time slice is permanently
zero — and a holder never parks (see
[scheduling-internals.md](scheduling-internals.md) § Lock Hierarchy, "Bare spin
locks", for the contexts, the invariant each rests on, and the order in which these
locks nest). The lock records its write holder's CPU, thread, syscall, and call
site, and a CPU spinning for it records a lock-wait breadcrumb; the softlockup
watchdog dump prints both.

A loop whose number of holds a caller sizes (revocation, the reparent walk of deletion and the
range splits, a move's child walk, and a dying `CSpace`'s teardown drain, below) releases the lock
between two holds through `DerivationLock::write_unlock_between_batches`, which then takes the
interrupts pending on its CPU (`interrupt_window`, as the page-pool seeding does, [§ Donation
Records](#donation-records)). Such a syscall therefore masks interrupts for one batch of
constant-time edits at a time, whatever the size of the subtree, child list, or `CSpace` it works
through; its total length still grows with that size. The final hold and every early exit release
the lock alone, so a call that finishes in one hold opens no window. The window holds no lock and
keeps preemption disabled, so the thread neither switches nor migrates; it exposes nothing that the
release does not already expose to other CPUs, and every such loop revalidates what it works on
when it takes the lock again. The dealloc cascade's fan-out and a dying `CSpace`'s release passes
take no derivation lock; they take `interrupt_window` between their batches themselves ([§
Teardown](#teardown)).

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
        first batch: refuse if the root is already pinned, else pin it
        objects, status = revoke_subtree_batch(root) // ≤ MAX_REVOKE_EDITS edits
        final batch (status ≠ MoreWork, or MAX_REVOKE_BATCHES reached):
            unpin the root
        release derivation tree write lock; MoreWork: take pending interrupts
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
(`dealloc_object` may take other locks), and the interrupts pending on the CPU are taken ([§ Global
Derivation Lock](#global-derivation-lock)). The walk always operates on the root's
current child list, so children derived concurrently between batches are still
cleared, and the root is revalidated per batch so a root recycled mid-revoke
stops the loop. Every batch that reports more work performed a full budget of
edits, so the loop terminates against any fixed subtree; a concurrent deriver
can extend the work only by spending its own slots and syscalls. A liveness
backstop (`MAX_REVOKE_BATCHES`) bounds the loop unconditionally and returns
`Interrupted` once that many batches have run: about 2.7 × 10^8 edits, which a
fixed subtree of some 1.3 × 10^8 nodes (9 to 18 GiB of slots) also exceeds, as
does sustained concurrent re-derivation. Revoked nodes stay revoked, so a retry
continues from the surviving subtree, and a fixed subtree of any size is cleared
by finitely many retries.

Deletion and the range splits (`SYS_MMIO_SPLIT`, `SYS_IRQ_SPLIT`,
`SYS_IOPORT_SPLIT`, `SYS_SCHED_SPLIT`) consume a slot without revoking
under it: its children are re-linked under its derivation parent
(`reparent_children`) so they stay inside every ancestor's subtree. That
walk is batched on the same terms as revocation — `MAX_REPARENT_EDITS`
head pops per lock hold, each child detached into a clean root and
re-linked in O(1), the lock released between batches with the CPU's pending interrupts taken
there, and a `MAX_REPARENT_BATCHES` backstop against a concurrent deriver — because a
slot can have been derived from up to the structural ceiling of every
CSpace. The consumed slot is revalidated under the lock before every batch
(tag and handle generation, not pinned by an in-flight revoke, move, IPC capability
transfer, or range split; after its first batch the delete also checks that the slot still holds the
object it captured, and the splits check the looked-up object from the first hold, since their
lookup ran without the lock): a concurrent revoke starting on it stops the delete with
`InvalidState` and children already moved stay under the parent, a concurrent delete finishing it
first turns the delete into a success and a split into `InvalidState` with both children rolled
back. The split's own children are inserted and linked under the original's parent inside the first
hold, before any batch releases the lock, so they are never reachable but unlinked. From the first
release of the lock to the split's final hold both carry the in-flight pin below, so no sibling
derives from, copies, moves, deletes, or transfers either while the batches run: each stays
childless and where the first hold put it, inside the grantor's revoke reach, and rolling one back
is one constant-time step, never a walk of a child list a sibling sized. An ancestor's revoke still
frees a pinned child, as it frees a pinned revoke root. The final hold unpins a child, and a
rollback frees one, only while its slot still holds it under the generation minted at insert, so a
slot such a revoke freed, and any refill of it, is left as it is. The handles returned to the caller
are the ones minted under the insert's own `CSpace` lock hold, so a child a revoke freed before the
split returned has a handle that no longer resolves; re-reading the slot after the lock is released
would instead return a live handle to the refill.

Because hoisting destroys intermediate parent→child edges as the flattening
proceeds, the root is pinned for the whole multi-batch operation with the
**in-flight pin** (`CapabilitySlot::pinned`, stored in the slot's `pin` byte, written only under
the derivation write lock and read under it by every path that acts on it; the advisory
pre-checks of [§ Storage: Hybrid Radix Directory](#storage-hybrid-radix-directory) read it
without that lock, and their locked path re-decides; a move pins its source and destination
the same way — see [Move](#move) — and a range split its two children, above).
`SYS_CAP_DELETE`, `SYS_CAP_MOVE`, `SYS_CAP_COPY`, `SYS_CAP_DERIVE`, `SYS_CAP_DERIVE_BADGE`,
`SYS_MEMORY_SPLIT`, `SYS_MEMORY_MERGE`, the range splits, `SYS_MMIO_MERGE`, `SYS_IRQ_MSG_ALLOC`
on its authority, and a further `SYS_CAP_REVOKE` refuse a pinned slot with `InvalidState`; a
syscall that only uses the slot's object (a map, a bind, `SYS_CAP_INFO`) reads no pin and acts;
IPC capability transfer refuses to move one — the reply direction surfaces `InvalidState` to
the server (the caller resumes with `IPC_REPLY_TRANSFER_FAILED`), the call
direction rejects before blocking, and a refusal detected only post-commit
delivers the message with zero caps (see
[docs/ipc-design.md](../../../docs/ipc-design.md) § Message Format). Deleting
or moving the root between batches would promote the temporarily hoisted
survivors and permanently sever the intermediate holders' revocation
authority. The pin is cleared under the lock on every syscall exit path —
completion, dead-link error, and the `Interrupted` backstop alike — so it
cannot leak; a root freed by a concurrent ancestor revoke sheds the pin with
the slot (that ancestor's revoke clears the hoisted survivors too, since they
remain inside its subtree).

A `CSpace` reaching refcount zero first stops every thread bound to it
(`sched::stop_threads_bound_to`, see [scheduling-internals.md](scheduling-internals.md) § Thread
Registry): each is marked `Exited` and waited off every CPU before any slot page is freed, so no
thread can be mid-syscall against the dying directory, and none of the dying process's own threads
can touch the derivation forest during the drain below. If the thread running the teardown is itself
stopped — it deleted the last capability to its own `CSpace`, or a concurrent teardown stopped it —
nothing below runs now: the object is queued for off-CPU reclaim and the whole arm re-runs from the
deferred drain once the thread has been scheduled away. The same discipline applies to an
`AddressSpace` reaching refcount zero. A syscall on another thread that still uses a `Thread`,
`CSpace`, or `AddressSpace` it resolved holds a syscall pin on it, so the count cannot reach zero
under that syscall (see [§ Storage: Hybrid Radix Directory](#storage-hybrid-radix-directory)); and
the stops' cancellations, like a dying thread's own drain, reach the IPC source a stopped thread
was parked on only through its binding, re-read under the thread's `sched_lock`, which proves the
source not yet freed (see
[thread-lifecycle-and-sleep.md](thread-lifecycle-and-sleep.md#dealloc_objectthread-drain-protocol)
§ `dealloc_object(Thread)` Drain Protocol, step 11). A waker that claimed the thread holds the
source live until its wake nulls the binding: device IRQ delivery through the reference its
binding holds on the Notification, which a change gives up only after waiting out the CPU's
delivery gate (`irq::DeliveryGate`), fault delivery
through the reference it pins on the handler endpoint, and the death post through the observer
binding's reference on its `EventQueue` (§ Kernel Object Reference Counting).

Every derivation link reachable from a live slot resolves: before a `CSpace`
unregisters, its teardown drain takes every one of its slots out of the forest,
and from the drain's first hold no IPC capability transfer or in-flight move
wires a link into it ([Teardown Drain](#teardown-drain)). A link that fails to
resolve is therefore genuine corruption, contained wherever a walk meets it,
always by truncation: the revoke walk cuts the chain hanging from the dead
link, logs it, and the syscall returns `InvalidState` instead of reporting a
clean revoke; the reparent walk that deletion and the range splits run on the
consumed slot's children cuts and logs the same way and completes; the teardown
drain, which has no caller to report to, cuts and logs the same way and
continues, as it does for an unlink that makes no progress (a node whose own
links do not lead back to the list it heads), and it unlinks a dying node
abandoned behind such a cut from the parent that no longer lists it ([Teardown
Drain](#teardown-drain)). A truncation abandons the live
nodes chained behind the dead link without clearing their parent pointers:
they keep naming the vanished `CSpace`, and only the registry epoch check keeps
such a pointer fail-closed (it resolves to nothing — the node behaves as a
derivation root) rather than aliasing onto a recycled `CSpace` id.

**Performance characteristics:** Revocation is O(N) in the number of descendants.
For well-behaved systems, derivation trees are shallow (a server derives a
capability for a client; the client rarely re-derives). Deep trees or large
revocations do not appear on latency-sensitive paths.

**Locking during revocation:** While the write lock is held, every other operation that takes the
derivation lock (copy, derive, the splits, merge, move, IPC transfer, the reply path's destination
pre-allocation, delete, revoke, the teardown drain) waits. Lock-free capability use is not blocked;
once a slot is freed, the tag and generation checks fence it. This is safe because revocation is
intentionally a strong operation — the revoker is asserting that no further access to the capability
is valid. A revocation larger than one batch is not atomic against readers: between batches,
unrevoked descendants remain usable until their batch frees them, and hoisting is visible —
surviving descendants may temporarily appear as direct children of the root (still descendants of it
and of every ancestor above it, so ancestor revocation reach is preserved). When the syscall returns
successfully with the root still live, the root is childless.

**Deallocation outside the lock:** The derivation tree lock and the source IPC locks are
separate outer roots of the lock hierarchy (see
[scheduling-internals.md](scheduling-internals.md) § Lock Hierarchy). `SYS_CAP_REVOKE` acquires
no IPC object lock while it holds the derivation tree write lock. Each batch collects the
objects of the slots it freed and releases the write lock. It then `dec_ref`s each object and
deallocates any that reach zero (`dealloc_revoked`); `dealloc_object` takes whatever IPC object
locks that object's teardown needs.

### Teardown Drain

A `CSpace` reaching refcount zero takes every one of its slots out of the derivation forest before
it unregisters (`drain_dying_cspace_batch`, `core/kernel/src/cap/drain.rs`). The teardown keeps the
lineage as a delete does: a capability derived through a dying slot is re-linked under the nearest
ancestor outside the dying `CSpace`, so it stays inside every revoke above it, and becomes a
derivation root only when no such ancestor exists. A capability derived through a process that has
exited therefore stays revocable by whoever delegated to that process, and an intermediate holder
cannot take a lineage out of its ancestors' reach by exiting.

The dying slots of a derivation tree form *regions*, maximal connected groups of dying slots. A
region's *top* is the dying slot whose parent `P` is outside the dying `CSpace` or absent, and `P`
is where everything hanging under the region goes. The drain scans the slot indices, ascends from
each slot still in the forest to its region's top, and flattens the region from there with the
revoke walk's stackless hoist, one constant-time edit per step on the top's head `H`:

```
drain(dying CSpace):
    first hold: mark the CSpace draining
    for each slot index, in order:
        while the slot is in the forest (it has a parent, a child, or a sibling):
            x = the slot; while x's parent is a dying slot: x = that parent   (ascend)
            P = x's parent, re-read at every step
            no H              → unlink x                                     (drained)
            H outside         → unlink H; link it under P (a root if no P)
            H dying, child G  → unlink G; link it under x if dying, else under P
            H dying, no child → unlink H                                     (drained)
    final hold: unregister the CSpace
```

Each dying slot is examined at most twice by the scan, ascended over once, hoisted at most once and
unlinked once, and each capability outside the `CSpace` that hangs under a region is re-linked once,
directly under `P`. The drain's total work is therefore linear in the slots the `CSpace` spans and
the capabilities hanging under them, whatever the shape of its trees or the order of its indices.
Re-linking each dying slot's children under its own parent instead would move a child again for
every dying ancestor the scan reaches after it: quadratic for a chain of dying slots whose parents
sit at higher indices than their children, a shape any process can lay out with explicit-index
inserts or moves. Each slot scanned, ascent, and link edit is one step, at most `MAX_DRAIN_EDITS`
per derivation-lock hold, so a hold is bounded by a constant whatever the population; the drain's
position across holds is the scan's cursor and the slot it works from.

Every edit leaves the forest consistent, so the drain releases the derivation lock between holds,
as revocation does, taking the interrupts pending on its CPU there ([§ Global Derivation
Lock](#global-derivation-lock)), and a foreign traversal in a window between holds sees ordinary
nodes. A revoke
above a region hoists or frees dying slots like any others, and whatever the drain re-links goes
under `P`, inside that revoke's subtree; a dying slot a revoke freed is skipped as empty. The scan
passes a slot only once it is out of the forest, so a dying slot that foreign activity moves out of
its region between holds is examined again rather than left behind, and `P` is re-read at every
step, since a foreign delete can re-link a top. Work can still arrive between holds — a foreign
delete of a slot whose parent is dying re-links its children there, and the drain then re-links
them in turn — so the loop is bounded by contention rather than by a constant, and carries no batch
backstop: a teardown cannot fail, and a holder of capabilities derived from the dying `CSpace`
prolongs it only while it keeps deleting, which stalls the deleting thread, not the system.

The first hold marks the `CSpace` *draining*, a flag written and read under the derivation lock.
From then on IPC capability transfer resolves the `CSpace` as gone
([Capability Transfer in IPC](#capability-transfer-in-ipc)), and so does an in-flight move's
revalidation of either slot ([Move](#move)): no capability enters the `CSpace` behind the scan, and
none leaves a slot the drain has already taken out of the forest, where the destination would take
an empty position and become a root. The drain itself, delete, revoke, and the splits resolve a
draining `CSpace` as before, since they edit its slots.

At the end no live slot of a consistent forest names the dying `CSpace`, the invariant
`free_cspace_id` relies on to recycle the id. A link that fails to resolve is contained by
truncation, and the registry epoch check keeps fail-closed the parent pointers of the nodes it
abandons (see [Revocation Algorithm](#revocation-algorithm)). A dying slot abandoned that way still
names a parent whose list it is no longer on; the drain meets it as a parent that heads no list,
which in a consistent forest no slot's parent is, and unlinks the slot from that parent, logs it,
and drains it as a top, since an ascent would reach a region that never holds it and the scan would
examine the slot again without end. More ascents than the `CSpace` has slots can only be
a cycle of parent links, since no edit puts a slot under one of its own descendants; the drain
unlinks the slot it stands on from its parent, which breaks the cycle, and logs it.

### Move

`SYS_CAP_MOVE` and IPC capability transfer relocate an occupied slot to a
fresh slot — auto-allocated or, for the syscall, caller-chosen — in the same
or another `CSpace` (`core/kernel/src/cap/transfer.rs`). The destination takes the source's
exact position in the tree: its parent, its siblings, and every one of its
children are repointed onto the new slot, and the source is freed. The child
walk is the unbounded part — a slot can have been derived from up to the
structural ceiling of every `CSpace` — so it runs on the same terms as
deletion's reparent walk: `MAX_REPARENT_EDITS` head pops per lock hold
(`reparent_children`, each child detached and re-linked under the destination
in O(1)), the derivation lock released between batches with the CPU's pending interrupts taken
there ([§ Global Derivation Lock](#global-derivation-lock)), and a `MAX_REPARENT_BATCHES` backstop
against a concurrent deriver.

```
move(src, dst):
    first hold (derivation lock + both CSpace locks, pointer order):
        validate src: occupied, handle generation current, not pinned
        take dst's reference on the object (QuotaExceeded at REF_COUNT_LIMIT,
            unless an IPC transfer checked the whole message first)
        insert dst (releasing that reference if the insert fails); pin src and dst
        migrate up to MAX_REPARENT_EDITS children of src under dst
        all moved → finish; else link dst as src's first child
    every later hold (derivation lock; a finish also takes the source CSpace lock to free src):
        revalidate src and dst: occupied, same generation, same object
        (a slot whose CSpace is draining counts as gone)
        both live     → unlink dst, migrate another batch, finish or re-link
        src gone, dst live → unpin dst; done (whoever took src releases its reference)
        dst gone      → unpin src; InvalidState (src keeps the cap and its remaining children)
        both gone     → InvalidCapability
    finish: dst takes src's links and every neighbour that points at src;
            free src; unpin dst
    after the hold: dec_ref the object for the freed src slot
```

A capability with at most `MAX_REPARENT_EDITS` children completes inside the
first hold. Between holds the tree is consistent and revocation-complete: the
destination hangs under the still-live source, so it and the children already
moved beneath it remain descendants of every ancestor of the source, and the
children not yet moved remain under the source. An ancestor's revoke running
concurrently sees ordinary nodes — it may hoist the destination up to its own
root, and the next batch detaches the destination from wherever it hangs
before re-linking it. Two slots name the object while the move is in flight
and the destination holds its own reference, so a revoke that frees either
slot drops exactly that slot's reference.

Both slots carry the in-flight pin between batches. The pin refuses every
operation that would tear the migration — a delete, move, copy, derive,
split, merge, revoke, or IPC transfer of either slot returns `InvalidState`
until the move completes — and, because derivation from a pinned slot is
refused, the source's child list can grow only indirectly (deleting one of
its children promotes that child's children to it), which is what the
backstop covers. Tripping it leaves the destination where the last batch
re-linked it, a live derived child of the source with both pins cleared —
the shape `SYS_CAP_COPY` produces — and returns `Interrupted` from the
syscall; an IPC transfer delivers the destination handle.

Neither slot pins its `CSpace` against teardown. IPC transfer resolves both
`CSpace`s through the registry under the derivation lock, from the identity
each TCB carries (`cspace_id`, `cspace_epoch`): a parked sender or receiver
holds no reference on its `CSpace`, so a raw pointer read from its TCB could
name storage a teardown has unregistered and freed, whereas a `CSpace` that
resolves stays allocated for the hold — unregistration happens under the
same lock and the storage is released only after it. The later batches
resolve both slots the same way, and treat a slot whose `CSpace` is draining as
gone ([Teardown Drain](#teardown-drain)), so a `CSpace` torn down meanwhile is
observed as gone rather than dereferenced, no batch migrates into or out of a
`CSpace` whose drain has begun, and a source slot left in a dying `CSpace` is
left to that teardown's cascade, which releases the reference it holds. The
drain treats the in-flight slots like any other, re-linking what hangs under a
dying slot under the nearest ancestor outside its `CSpace`. When the source's
`CSpace` dies, the move completes where it stands: the drain re-links the
destination, carrying its migrated children, and the source's unmigrated
children under the source's parent, so all of them stay inside every revoke
above the source (the unmigrated children as the destination's siblings, not
its children). When the destination's `CSpace` dies, the move reports
`InvalidState` and the source keeps the capability: the drain re-links the
migrated children under the source, its parent, so the source keeps every
child. When the freed source
slot's reference was the last one to a `Thread`, `CSpace`, or
`AddressSpace`, the object goes to the CPU's deferred reclaim rather than
being torn down in place — a teardown stops bound threads and waits on
other CPUs' scheduling, which must not happen inside IPC delivery. Other
types are freed in place; a Notification or `EventQueue` may first wait for
the timer's in-flight wakeup batch (`sched::sleep_wakeups_quiesce`), a
bounded wait that needs only that no IPC, scheduler, or sleep-list lock is
held, as at every move's release. A capability whose
source and destination an ancestor's revoke both freed mid-transfer, or
whose destination went with the receiver's `CSpace` (the sender then keeps
it), is delivered as handle 0 (the permanently null slot); one that trips
the backstop is delivered live, the sender's slot surviving as its
derivation parent.

### Safe Delegation: the "Derive Twice" Pattern

Revoking a capability via `SYS_CAP_REVOKE` invalidates all its descendants while
preserving the target slot itself (see
[docs/capability-model.md](../../../docs/capability-model.md) § Revocation). To
delegate authority that can later be revoked without losing your own access:

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
[docs/capability-model.md](../../../docs/capability-model.md) § Transfer and
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

Per-slot generation handles keep a stale handle from aliasing a recycled slot after a
cross-`CSpace` revoke, and a syscall already in flight on the object holds a pin that keeps
the object live until the syscall drops it (see
[§ Storage: Hybrid Radix Directory](#storage-hybrid-radix-directory)). Both forms
of cross-`CSpace` sharing keep a derivation edge across the boundary:

- **IPC capability transfer / `SYS_CAP_MOVE`** hand the cap to the recipient and
  free the sender's slot, but the moved cap keeps its position in the derivation
  tree — it stays a descendant of whatever it was derived from, so an ancestor's
  `cap_revoke` reaches it across the boundary. (Same-`CSpace` moves likewise keep
  the source's position; see
  [docs/capability-model.md](../../../docs/capability-model.md) § Transfer.)
- **`SYS_CAP_COPY`** keeps the new cap a derivation **child** of the source (the
  "Derive Twice" pattern above), so the source can revoke the delegated copy.

In both cases a `cap_revoke` can `free_slot` the recipient's slot in its own
`CSpace`. The handle the recipient holds carries the slot's **generation**
(`handle = (generation << CAP_INDEX_BITS) | index`, per
[docs/capability-model.md](../../../docs/capability-model.md) § Capability Handle
Format); `free_slot` bumps the generation, so the recipient's now-stale handle fails
with `InvalidCapability` rather than aliasing whatever later occupies the recycled
index. See the per-slot generation discussion under
[Capability Slot](#capability-slot-capslotrs).

`SlotId` encodes `(cspace_id, epoch, index)`. The derivation tree is resolved
by:

```
resolve(slot_id):
    // O(1) registry lookup; none if unregistered or the epoch is stale
    cspace = lookup_cspace(slot_id.cspace_id, slot_id.epoch)
    slot = cspace.slot(slot_id.index)        // O(1) lookup (two or three levels)
    return none if slot is Null, else slot   // occupancy gate (resolve_slot_mut)
```

Resolution does not require holding a lock on the target `CSpace` — the derivation
tree write lock is sufficient to prevent concurrent modification.

---

## Initial CSpace Population

Phases 7, 8, and 9 of initialization, per [initialization.md](initialization.md)
([§ Phase 7](initialization.md#phase-7-capability-system),
[§ Phase 8](initialization.md#phase-8-scheduler-and-smp-bringup),
[§ Phase 9](initialization.md#phase-9-init-creation-and-scheduler-entry)), populate the
root CSpace, which becomes init's CSpace. Slots are assigned sequentially from slot 1 in
the order below; the counts in each group depend on the platform, so init must not assume
specific slot numbers.

### Initial Slot Layout

| Order | Phase | Capability |
|---|---|---|
| 0 | — | Null (permanent; always slot 0) |
| 1 | 7 | Memory capabilities (one per contiguous RAM extent drained from the buddy allocator; the seed extent contributes only its post-reserve tail) |
| 2 | 7 | Mmio capabilities, Map and Write rights (one over the kernel console UART on RISC-V, then one per validated `BootInfo.mmio_apertures` entry) |
| 3 | 7 | SchedControl capability (band `[1, PRIORITY_MAX]`) |
| 4 | 7 | One root Interrupt range capability (every valid IRQ id on the architecture; Notify and Mint rights) |
| 5 | 7 | Map-only Memory capabilities (one per `AcpiReclaimable` memory-map region, as many as the map reports, then the page holding `BootInfo.acpi_rsdp`, then the `BootInfo.device_tree` blob) |
| 6 | 7 | One root IoPort capability over the full 64K I/O port space (x86-64 only), or one SbiControl capability carrying every sanctioned SBI right (RISC-V only) |
| 7 | 7 | One EntropyControl capability carrying Contribute |
| 8 | 7 | One KernelLog capability carrying Read |
| 9 | 7 | Memory capabilities for boot module images (raw ELF for procmgr, devmgr, etc.) |
| 10 | 7 | Reclaimable Memory capabilities for bootloader scratch pages (`BootInfo`, descriptor arrays, MMIO aperture array, reclaim-array page, CPU-id pages, transient page-table frames) and the bundle's non-module pages (header + entry table + pad, init ELF source body, inter-module and trailing slack — module bodies are excluded, covered by the boot-module Memory caps above) — one cap per `BootInfo.reclaim_ranges` entry not flagged `RECLAIM_FLAG_LATE` |
| 11 | 8 | Late-reclaim Memory capabilities (one per `BootInfo.reclaim_ranges` entry flagged `RECLAIM_FLAG_LATE`: the AP trampoline page) |
| 12 | 9 | Init's own address space capability |
| 13 | 9 | Reclaimable Memory capabilities for init's ELF segments |
| 14 | 9 | Reclaimable Memory capabilities for the `InitInfo` pages |
| 15 | 9 | Reclaimable Memory capabilities for init's stack pages |
| 16 | 9 | Init's own thread capability |
| 17 | 9 | Init's own CSpace capability |

The kernel passes the slot numbers to init in the `InitInfo` block it maps into
init's address space (its VA is init's first argument; see
[abi/init-protocol/README.md](../../../abi/init-protocol/README.md)). The `CapDescriptor` array
lists each Phase 7 and Phase 8 slot with its type; header fields name the single
caps and the base and count of several groups, including every Phase 9 group.

The root CSpace is created with one reference, the kernel's hold on it while Phases 7 to 9
populate it. Init's own CSpace capability (order 16) takes over that reference rather than
adding one, and init's thread, like every thread, holds none on the CSpace it is bound to,
so from Phase 9 on the root CSpace is an ordinary CSpace whose count is its capabilities and
syscall pins: the deletion of its last capability, procmgr's at init's reap, frees it
through the CSpace teardown ([§ Teardown](#teardown)) and releases every capability it
still holds ([process-lifecycle.md § Init reap](../../../docs/process-lifecycle.md#init-reap)).
Its id, 0, is recycled then like any other.

---

## Capability Transfer in IPC

IPC capability transfer (via `SYS_IPC_CALL` and `SYS_IPC_REPLY` capability slots) begins the move of
all of a message's capabilities or of none of them — all-or-nothing at commit. The sender names the
caps by their full handles in its IPC buffer's cap block (word `MSG_CAP_HANDLES_WORD` on); the
syscall copies them once into the message it validates and queues, so a later write to the page
changes nothing the transfer acts on. A refusal detectable
before the caller blocks fails the `SYS_IPC_CALL`; one that arises after the caller blocked delivers
the message with zero capabilities, the sender keeping its own; a refused `SYS_IPC_REPLY` transfer
returns the error to the server and wakes the caller with the `IPC_REPLY_TRANSFER_FAILED` reply in
place of the server's (see [docs/ipc-design.md](../../../docs/ipc-design.md) § Message Format). Each
capability is relocated by the batched move described under [Move](#move):

```
transfer_caps(sender_cspace, handles, receiver_cspace):
    // Each identity (cspace_id, cspace_epoch) is copied out of its thread
    // while the thread is known to be live: the running thread, a sender
    // under the endpoint lock before its reply binding is published, or a
    // thread a won reply claim or a wake_in_flight pin keeps.
    one hold (derivation lock, then both CSpace locks in pointer order):
        resolve both CSpaces through the registry from the two identities;
            either gone or draining → refuse
        validate every handle: distinct, occupied, generation current,
            not pinned
        refuse (QuotaExceeded) if any handle's object is at REF_COUNT_LIMIT
        pre-allocate len(handles) slots in the receiver's CSpace,
            the IPC receive reserve included
        begin every move (insert dst, its reference unchecked, pin both,
            first batch)
    drive each move that did not finish, one batch per hold
    deliver the destination handles
    // The moved cap takes the source's position in the derivation tree: its
    // parent, children, and siblings are repointed onto the destination,
    // including across the CSpace boundary. That cross-boundary edge is what
    // lets an ancestor's cap_revoke reach the moved cap; per-slot generation
    // (#349) makes the receiver's handle fail closed if such a revoke frees
    // this slot.
```

IPC capability transfer is normally cross-`CSpace` (sender and receiver in
distinct processes); two threads sharing one `CSpace` can transfer between
themselves, the lock pair collapsing to a single acquisition. The transferred
cap keeps its position in the derivation tree, so it remains reachable by a
`cap_revoke` on one of its ancestors (see
[docs/capability-model.md](../../../docs/capability-model.md) § Revocation);
per-slot generation handles make the receiver's handle fail closed if such a revoke
frees the receiver's slot (#349). A move that finishes in the first hold is atomic
against revocation; one that needs further batches is protected by the in-flight
pins and stays revocation-complete between holds (see [Move](#move)).

A `CSpace` whose teardown drain has begun resolves as gone (`CSpaceIdentity::lookup`; see
[Teardown Drain](#teardown-drain)): a transfer into or out of it is refused as one whose `CSpace`
has unregistered is, no capability moving and the sender keeping its own (the refusals above: a
message delivered with zero capabilities, or a reply that wakes the caller with
`IPC_REPLY_TRANSFER_FAILED`). No capability enters a dying `CSpace` behind the drain's scan, and
none leaves a slot the drain has already taken out of the forest. The reply path's destination
pre-allocation resolves the caller's `CSpace` the same way.

Reply capabilities are not part of the derivation tree — they are single-use, cannot be derived, and
are not tracked for revocation (see [docs/ipc-design.md](../../../docs/ipc-design.md) § The
Call/Reply Model). A reply capability is not a `CapTag` variant; it is an implicit per-thread
binding outside the process CSpace: the receiving thread's `reply_tcb` field, which the kernel
points at the caller when a call and a receive rendezvous — in `SYS_IPC_CALL` when the server is
already waiting, in `SYS_IPC_RECV` or `SYS_IPC_REPLY_RECV` when the caller is, or in
kernel fault delivery (`core/kernel/src/ipc/fault.rs`), which takes the caller role. The kernel
clears the binding when `SYS_IPC_REPLY` or `SYS_IPC_REPLY_RECV` claims it by compare-exchange in
`endpoint_reply`, before it reads the caller, validates the payload, or moves a capability (a
failure after the claim wakes the caller with the transfer-failed reply), at the
thread's next `SYS_IPC_RECV` that passes its capability check and cap-slot pre-allocation and
either waits or finds a caller (a try-once that finds none leaves the binding), which releases the
unreplied caller, when a stop (`cancel_ipc_block`) or a teardown claims the bound caller, when a
timed call's timeout expires (`cancel_for_timeout`), when a change of a fault-blocked caller's
fault-handler binding claims it (`ipc::fault::claim_fault_park`), or when `endpoint_call` rolls the
rendezvous back because the caller's park commit was refused (`rollback_uncommitted_call`); a
refused receive rebind never publishes the binding (see
[ipc-internals.md](ipc-internals.md) § Call Path (Sender), § Receive Path (Server), and § Reply
Path, and
[thread-lifecycle-and-sleep.md § BlockedOnReply Edge — Symmetry Rules](thread-lifecycle-and-sleep.md#blockedonreply-edge--symmetry-rules)).

---

## Summarized By

[core/kernel/README.md](../README.md),
[Kernel Cross-Boundary Disclosure Inventory](cross-boundary-disclosure.md),
[IPC Subsystem Internals](ipc-internals.md), [Memory Subsystem Internals](memory-internals.md),
[Scheduler Internals](scheduler.md),
[SMP Scheduling and Locking Invariants](scheduling-internals.md),
[Syscall Interface Specification](syscalls.md),
[core/ktest/README.md](../../ktest/README.md),
[Capability Model](../../../docs/capability-model.md),
[Coding Standards](../../../docs/coding-standards.md),
[Fault Handling](../../../docs/fault-handling.md), [IPC Design](../../../docs/ipc-design.md),
[Process Lifecycle](../../../docs/process-lifecycle.md),
[init Bootstrap Stages](../../../services/init/docs/bootstrap.md)
