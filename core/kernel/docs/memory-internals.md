# Memory Subsystem Internals

This document covers the implementation of the kernel's memory subsystem. The design
goals (higher-half layout, buddy + slab allocation, W^X enforcement, TLB management) are
specified in [docs/memory-model.md](../../../docs/memory-model.md). This document
describes how those goals are realised in code.

The memory subsystem comprises five components:

1. **Buddy allocator** — physical frame allocation
2. **Slab allocator** — fixed-size kernel object allocation
3. **Size-class allocator** — general variable-size kernel heap
4. **Address space management** — per-process virtual address space objects
5. **TLB management** — local invalidation, tagged (PCID/ASID) no-flush context switch with a full-flush fallback, and SMP shootdown

---

## Buddy Allocator (`mm/buddy.rs`)

### Data Structures

The buddy allocator manages physical memory as a set of power-of-two-sized blocks.
The implementation supports orders 0 through `MAX_ORDER` (inclusive), where an
order-`n` block contains 2^n contiguous 4 KiB pages.

```rust
pub struct BuddyAllocator
{
    /// One free list per order. Each list is a singly-linked list of free
    /// block headers embedded in the first page of each free block.
    free_lists: [FreeListHead; MAX_ORDER + 1],

    /// Total number of free pages currently available across all orders.
    free_pages: usize,

    /// Physical base address of the region this allocator manages.
    /// Used to compute buddy addresses from block addresses.
    phys_base: PhysAddr,
}

/// A node in a free list. Stored in the first bytes of the free block itself —
/// no external metadata allocation required.
struct FreeBlock
{
    next: Option<PhysAddr>,
}
```

`MAX_ORDER` is an implementation constant chosen so the maximum single allocation
is large enough for any kernel use while keeping the free-list array small.
The exact value is established at implementation time.

### Zone Management

The allocator supports a single zone in the common case (all usable RAM). Where
hardware requires DMA-accessible memory below a physical address limit, a second
zone is added at init time. Zone selection is the caller's responsibility — the
allocator does not automatically prefer one zone. Zone boundaries are tracked as
`(phys_base, phys_end)` pairs; each zone has its own `BuddyAllocator` instance.

### Allocation and Deallocation Properties

**Allocation:** Serves the requested order from the free list of that order. If empty,
splits a larger block from the next available order, inserting the unused half into
the appropriate free list. This is O(MAX_ORDER) in the worst case and near-O(1) for
well-behaved workloads.

**Deallocation and coalescing:** On free, the buddy address is computed via XOR of
the block address with its size (buddy pairs differ in exactly one bit). If the buddy
is free, the two blocks are merged and the process repeats at the next order. This
is O(MAX_ORDER) in the worst case and eliminates long-term fragmentation.

### Thread Safety

The allocator is protected by a single spinlock. Allocation on the kernel hot path
should be infrequent enough that contention is not a concern. If profiling reveals
lock contention, per-CPU free lists (magazines) can be layered on top without
changing the core algorithm.

---

## Slab Allocator (`mm/slab.rs`)

### Purpose

The slab allocator provides O(1) allocation and deallocation for fixed-size kernel
objects. Each object type has a dedicated slab cache; objects of the same type are
co-located for cache efficiency.

### Cache Structure

```rust
pub struct SlabCache
{
    /// Size of each object in bytes.
    object_size: usize,

    /// Objects per slab (computed from object_size and slab page count).
    objects_per_slab: usize,

    /// Number of pages per slab (1–4, chosen so objects_per_slab >= SLAB_MIN_OBJECTS).
    pages_per_slab: usize,

    /// Slabs with at least one free slot.
    partial_slabs: SlabList,

    /// Slabs with no free slots (tracked for deallocation detection).
    full_slabs: SlabList,

    /// Slabs with all slots free (returned to buddy allocator when empty).
    empty_slabs: SlabList,

    /// Total allocation count (for diagnostics).
    alloc_count: u64,
}
```

### Slab Layout

A slab is a contiguous group of `pages_per_slab` physical pages. Its layout is:

```
[ SlabHeader | padding to object alignment ][ object 0 ][ object 1 ] ... [ object N ]
```

`SlabHeader` is stored at the start of the slab:

```rust
struct SlabHeader
{
    /// Intrusive list links (for partial/full/empty lists).
    list_next: Option<PhysAddr>,
    list_prev: Option<PhysAddr>,

    /// Head of the free slot list embedded in free objects.
    free_head: Option<*mut FreeSlot>,

    /// Number of currently allocated (in-use) objects in this slab.
    in_use: u32,

    /// Back-pointer to the cache this slab belongs to.
    cache: *mut SlabCache,
}
```

Free slots embed their next-pointer at offset 0 within the otherwise-unused object
memory:

```rust
struct FreeSlot
{
    next: Option<*mut FreeSlot>,
}
```

This avoids any external free-list allocation — the free list is intrusive into the
free object memory itself.

### Allocation

```
cache.alloc():
    slab = partial_slabs.head
    if slab is None:
        slab = cache.grow()  // allocate a new slab from buddy allocator
        if slab is None: return None (OOM)
    slot = slab.free_head
    slab.free_head = slot.next
    slab.in_use += 1
    if slab.free_head is None:
        move slab from partial_slabs to full_slabs
    return slot as *mut T (zeroed by grow() at slab creation)
```

### Deallocation

```
cache.free(ptr):
    slab = find_slab_for(ptr)  // round ptr down to slab base
    slot = ptr as *mut FreeSlot
    slot.next = slab.free_head
    slab.free_head = slot
    slab.in_use -= 1
    if slab.in_use == 0:
        move slab from partial_slabs (or full_slabs) to empty_slabs
        // optionally return to buddy allocator if empty_slabs grows large
    else if was in full_slabs:
        move slab from full_slabs to partial_slabs
```

Finding the slab from a pointer: since each slab is page-aligned and `pages_per_slab`
is known, masking the pointer to the slab's page-aligned base reaches `SlabHeader`.

### Registered Caches

The following slab caches are registered during Phase 4 of initialization:

| Cache | Object Type |
|---|---|
| `cap_slot_cache` | `CapabilitySlot` |
| `tcb_cache` | `ThreadControlBlock` |
| `endpoint_cache` | `Endpoint` |
| `signal_cache` | `Signal` |
| `event_queue_cache` | `EventQueueHeader` |
| `wait_set_cache` | `WaitSet` |
| `address_space_cache` | `AddressSpace` |

Object sizes are determined by the final struct layouts and are not part of the ABI.

---

## Size-Class Allocator (`mm/size_class.rs`)

### Purpose

For variable-size kernel allocations (dynamic arrays, temporary buffers, strings in
kernel paths), the size-class allocator provides O(1) allocation with bounded
fragmentation.

### Bin Sizes

Bins are at successive powers of two, starting from a small minimum and covering
up to a maximum bin size. The exact bin boundaries are implementation constants.
Allocations are rounded up to the next bin size. Each bin is backed by a dedicated
slab cache.

Allocations larger than the maximum bin size are served directly from the buddy
allocator (rounded up to a power-of-two page count).

### Implementation

```rust
pub struct SizeClassAllocator
{
    bins: [SlabCache; NUM_BINS],  // one per power-of-two size
}

impl SizeClassAllocator
{
    pub fn alloc(&mut self, size: usize, align: usize) -> Option<NonNull<u8>>
    {
        if size > MAX_BIN_SIZE
        {
            // Direct buddy allocation, rounded to page order
            let order = size.next_power_of_two().trailing_zeros() as usize
                - PAGE_SHIFT;
            BUDDY.lock().alloc(order).map(phys_to_virt)
        } else
        {
            let bin_idx = bin_for(size, align);
            self.bins[bin_idx].alloc()
        }
    }
}
```

This allocator is exposed as the kernel's `GlobalAlloc` implementation, enabling
`alloc::boxed::Box` and `alloc::vec::Vec` in kernel code.

---

## Address Space Objects (`mm/address_space.rs`)

### Structure

Each process virtual address space is represented by an `AddressSpace` object:

```rust
pub struct AddressSpace
{
    /// Physical address of the root page table frame (PML4 / Sv48 root).
    root_phys: u64,

    /// Virtual address of the root frame (via the direct physical map).
    root_virt: u64,

    /// Set of CPUs currently running threads in this address space (bit N = CPU
    /// N has this AS active). Queried by TLB shootdown to pick IPI targets.
    active_cpus: AtomicCpuMask,

    /// CAS spin lock serialising page-table modifications. Does NOT disable
    /// interrupts (shootdown needs IF=1 to deliver IPIs); preemption is held off
    /// by the caller.
    pt_lock: AtomicBool,
}
```

### Lifecycle

1. **Creation** (`SYS_CAP_CREATE_ADDRESS_SPACE`): allocate a root page table frame,
   zero it, map the kernel higher half (shared across all address spaces via a
   shared PML4/root entry), allocate an `AddressSpace` from the slab cache.

2. **Use**: threads reference the `AddressSpace` via their TCB. When scheduled, the
   scheduler calls `arch::current::paging::activate(root_phys)` to switch the hardware
   page table.

3. **Modification** (`SYS_MEM_MAP`, `SYS_MEM_UNMAP`, `SYS_MEM_PROTECT`): acquire
   `pt_lock`, call `arch::current::paging::map_user_page`/`unmap_user_page`/
   `protect_user_page`, then perform TLB management (see TLB Management section below).

4. **Destruction**: when the last capability to the address space is deleted, all
   page table frames are freed to the buddy allocator and the `AddressSpace` object is
   freed to the slab cache.

### Fork-Like Operations

Seraph does not provide a `fork()` equivalent. New address spaces are created empty
and populated by the process loader. Copy-on-write is not implemented. Shared memory
is established by mapping the same frame capability into multiple address spaces.

---

## TLB Management

Local invalidation primitives live in the per-architecture paging modules:
`arch::current::paging::flush_page` invalidates a single VA on the current CPU
(`invlpg` / `sfence.vma <va>`), and `flush_tlb_all` invalidates all non-global entries
(CR3 reload / `sfence.vma zero, zero`). When tagging is active, `flush_page_tagged` and
`flush_tag` invalidate a single VA or a whole tag for an arbitrary PCID/ASID (`invpcid` /
`sfence.vma <va>, <asid>` and `sfence.vma zero, <asid>`), independent of the tag currently
loaded. Cross-CPU invalidation is the shootdown protocol in `mm/tlb_shootdown.rs`. The tag
allocator and per-address-space tag state live in `mm/tag_allocator.rs`; see
[docs/memory-model.md](../../../docs/memory-model.md) for the model.

### Context Switch TLB Handling

When tagging is enabled, a switch to a different address space calls
`AddressSpace::activate`, which claims a hardware tag for the space (lazily, on first
activation) and loads the root under that tag **without** flushing
(`arch::current::paging::activate_tagged`): x86-64 writes CR3 with the PCID and bit 63 set
(`CR4.PCIDE` is on); RISC-V writes `satp` with the ASID and no `sfence.vma`. A per-CPU
generation check then flushes only that tag if it was reissued to a different space
(`tag_gen` mismatch) or accrued unmaps while this CPU was switched away (`tlb_gen` lag). A
`SeqCst` fence between the scheduler's `mark_active` and the generation reads is the
load-bearing barrier (paired with fences in the unmap and eviction paths) that closes the
switch-away races. Where tagging is unavailable — no hardware tags, or a tag field too
narrow to provide more usable tags than CPUs — `activate` uses the full-flush path
`arch::current::paging::activate(root_phys)` (CR3 write with `CR4.PCIDE` clear / `satp`
ASID 0 + `sfence.vma`) on every switch. When tagging is enabled the pool can never be
exhausted (the allocator keeps more usable tags than CPUs, and at most one space per CPU is
active), so a claim always succeeds and no user space ever runs untagged. Threads sharing an
address space require no TLB operation on switch. The per-CPU elided/performed flush counts are
summed by the `CAP_INFO_TLB_*` `cap_info` selectors.

### SMP TLB Shootdown

When a mapping is modified in an address space that has active threads on other CPUs,
stale TLB entries on those CPUs may need invalidation. The leaf PTE is edited under
the per-address-space `pt_lock`, which is then **released before** any cross-CPU
work: holding it across the IPI ack-wait would serialize every concurrent map/unmap
on the address space behind cross-CPU latency.

The shootdown itself is lock-free — there is no global shootdown lock and no IPI
payload. Each CPU owns a request slot. The initiator publishes `(root, virt, tag)` into
its own slot, sets the pending bit of each target CPU, then sends the IPI:

```
1. Edit the leaf PTE under pt_lock; release pt_lock.
2. Bump the space's tlb_gen and fence (so a switched-away CPU flushes on
   reactivation); read active_cpus; exclude the current CPU.
3. Publish (root, virt, tag) into this CPU's request slot and set each target's
   pending bit (the bit doubles as the per-target liveness/ack token).
4. Send the shootdown IPI to the targets and wait for every pending bit to clear.
```

A target services the slot only once it observes its own pending bit set, so it never
reads a half-published request; it invalidates the named VA for `tag` (so a CPU that has
since switched to another space still flushes the right translation) and clears its bit.
Preemption stays disabled across the whole edit-then-shootdown sequence.

The shootdown is **not** issued unconditionally. Each rewrite is classified as it
commits (`MapOutcome`):

- **Fresh** (no prior mapping) and **Widen** (same frame, strictly broader rights)
  skip the remote shootdown. No remote CPU can hold an entry granting more than the
  live PTE, so the worst case is a spurious fault the page-fault handler resolves by
  re-walking the live PTE and retrying.
- **Replace** (different frame, or a permission narrowing) issues the synchronous
  shootdown above: a stale entry would alias a freed/reused frame or cache revoked
  rights, which no retry can recover. `unmap` is always synchronous.

The shootdown targets only CPUs currently running the space (`active_cpus`). A CPU that
switched away still holds the space's tagged entries (the switch did not flush them), so it
is reached not by the IPI but by the per-CPU generation check on its next reactivation: step
2 bumped the space's `tlb_gen` before snapshotting `active_cpus`, and a `SeqCst` fence on
each side guarantees that for every CPU either the initiator sees it active (and IPIs it) or
it observes the bumped `tlb_gen` on reactivation (and flushes the tag). Never neither. On
the full-flush fallback (no tagging) the request carries `tag == 0` and the switch already
flushed the outgoing space's entries, so a switched-away CPU has nothing stale.

### Direct Physical Map Access

The direct physical map is set up during Phase 3 of initialization and covers all
usable physical memory. The kernel uses `phys_to_virt` and `virt_to_phys` helpers:

```rust
/// Convert a physical address to a kernel virtual address via the direct map.
/// The physical address must be within usable physical RAM.
pub fn phys_to_virt(phys: PhysAddr) -> VirtAddr
{
    // SAFETY: PHYSMAP_BASE + phys is within the direct physical map region,
    // which is mapped for all usable RAM during Phase 3 initialization.
    VirtAddr(PHYSMAP_BASE + phys.0)
}

/// Convert a kernel virtual address in the direct map to its physical address.
/// The virtual address must be within the direct physical map region.
pub fn virt_to_phys(virt: VirtAddr) -> PhysAddr
{
    debug_assert!(virt.0 >= PHYSMAP_BASE);
    PhysAddr(virt.0 - PHYSMAP_BASE)
}
```

These are the only valid paths for physical-to-virtual conversion. Arbitrary physical
addresses must not be accessed by computing offsets from kernel image addresses.

---

## Kernel Stack Allocation

Each kernel thread (the kernel-side execution context for syscall and interrupt
handling) has a dedicated kernel stack. Kernel stacks are allocated directly from the
buddy allocator:

- Size: `KERNEL_STACK_PAGES` pages (e.g. 8 pages = 32 KiB)
- Alignment: `KERNEL_STACK_PAGES`-page aligned (enables O(1) stack-base recovery
  from an arbitrary stack pointer by masking)
- Guard page: one unmapped page immediately below the stack (allocated but not mapped,
  so stack overflow faults immediately rather than silently corrupting adjacent memory)

Stack allocation happens in Phase 8 (scheduler initialization) for idle threads and
in `SYS_CAP_CREATE_THREAD` for user-created threads.

---

## Page Table Node Tracking

Intermediate page table nodes (PML3/PML2/PML1 on x86-64; levels 2/1/0 on RISC-V Sv48)
are allocated from the buddy allocator at order 0 (one 4 KiB page each). The kernel
must track these to free them when an address space is destroyed.

Each intermediate node page is tracked via a `PageTableNode` entry in a slab cache.
The entry records the physical address of the page and the level it occupies in the
table hierarchy. On address space destruction, the kernel walks the derivation of the
root table, freeing all tracked intermediate nodes before freeing the root.

No reference counting is needed for intermediate nodes — they are owned exclusively
by the address space that contains them.

---

## Summarized By

None
