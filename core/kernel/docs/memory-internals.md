# Memory Subsystem Internals

This document covers the implementation of the kernel's memory subsystem. The design
goals (higher-half layout, buddy + slab allocation, W^X enforcement, PCID/ASID
management) are specified in [docs/memory-model.md](../../docs/memory-model.md). This
document describes how those goals are realised in code.

The memory subsystem comprises five components:

1. **Buddy allocator** — physical frame allocation
2. **Slab allocator** — fixed-size kernel object allocation
3. **Size-class allocator** — general variable-size kernel heap
4. **Address space management** — per-process virtual address space objects
5. **TLB management** — PCID/ASID allocation, shootdown protocol

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
    /// Root page table frame (physical address of the PML4 / root Sv48 table).
    root_table: PhysAddr,

    /// Assigned PCID/ASID. None if not yet assigned or after recycling.
    pcid: Option<u16>,

    /// Reference count: number of threads currently running in this address space.
    /// Used to determine when a shootdown IPI is necessary.
    active_cpu_mask: AtomicU64,  // bitmask of CPUs running threads in this space

    /// Lock protecting page table modifications.
    table_lock: Spinlock,
}
```

### Lifecycle

1. **Creation** (`SYS_CAP_CREATE_ADDRESS_SPACE`): allocate a root page table frame,
   zero it, map the kernel higher half (shared across all address spaces via a
   shared PML4/root entry), allocate an `AddressSpace` from the slab cache.

2. **Use**: threads reference the `AddressSpace` via their TCB. When scheduled, the
   scheduler calls `Paging::activate(table, pcid)` to switch the hardware page table.

3. **Modification** (`SYS_MEM_MAP`, `SYS_MEM_UNMAP`, `SYS_MEM_PROTECT`): acquire
   `table_lock`, call `Paging::map`/`unmap`/`protect`, then perform TLB management
   (see TLB Management section below).

4. **Destruction**: when the last capability to the address space is deleted, all
   page table frames are freed to the buddy allocator, the `AddressSpace` object is
   freed to the slab cache, and the PCID/ASID is returned to the pool.

### Fork-Like Operations

Seraph does not provide a `fork()` equivalent. New address spaces are created empty
and populated by the process loader. Copy-on-write is not implemented. Shared memory
is established by mapping the same frame capability into multiple address spaces.

---

## TLB Management (`mm/tlb.rs`)

### PCID/ASID Allocation

The kernel maintains a global pool of PCID/ASID values (12 bits on x86-64; hardware-
defined width on RISC-V, typically 16 bits).

```rust
pub struct PcidAllocator
{
    /// Bitmask of currently-in-use PCID values.
    /// PCID 0 is reserved for kernel-only contexts (never assigned to a process).
    in_use: [u64; PCID_POOL_WORDS],

    /// Generation counter, incremented on each full cycle through the pool.
    /// Used to detect when a recycled PCID has been reassigned.
    generation: u32,
}
```

Allocation is a scan for the first zero bit in `in_use`. On deallocation, the bit
is cleared and a global TLB flush is issued to invalidate any cached translations
using that PCID before it is reissued to a new address space.

When the pool is exhausted (all PCIDs in use simultaneously — unusual in practice),
the oldest PCID is evicted: its address space loses its PCID, a full flush occurs,
and the PCID is reassigned to the new address space.

### Context Switch TLB Handling

On each context switch between threads in different address spaces:

```
1. Look up the target address space's PCID (or allocate one if absent)
2. Call Paging::activate(table, pcid)
   - If PCID is valid and not recycled: hardware retains TLB entries tagged with
     this PCID; no explicit flush needed (hardware TLB tagging handles this)
   - If PCID was just allocated (new or recycled): a full TLB flush occurs
```

Threads in the same address space switching on the same CPU require no TLB operation.

### SMP TLB Shootdown

When a mapping is modified in an address space that has active threads on other CPUs,
TLB entries on those CPUs must be invalidated. The protocol:

```
1. Acquire table_lock on the address space
2. Modify the page table (map/unmap/protect)
3. Read active_cpu_mask to determine which remote CPUs are affected
4. For each affected remote CPU: send an IPI (Inter-Processor Interrupt)
   with the address space pointer and virtual address to invalidate
5. Wait for all targeted CPUs to acknowledge (spin on a per-CPU counter)
6. Release table_lock
```

The IPI handler on each remote CPU:

```
1. Receive the (address_space, virt_addr) from the IPI payload
2. If the current address space matches: call Paging::flush_page(virt_addr)
3. Increment the acknowledgement counter
```

If a CPU switches away from the affected address space between step 3 and step 5, its
TLB entries for that space are irrelevant (a context switch performs the appropriate
flush). The kernel checks for this case and skips the IPI for CPUs that have switched.

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
