# Memory Subsystem Internals

This document covers the implementation of the kernel's memory subsystem. The design
goals (higher-half layout, buddy allocation, retype-backed kernel objects, W^X
enforcement, TLB management) are specified in
[docs/memory-model.md](../../../docs/memory-model.md). This document describes how
those goals are realised in code.

The memory subsystem comprises six components:

1. **Buddy allocator** — boot-time physical frame allocation
2. **Kernel object memory** — objects carved out of Memory capabilities by retype,
   and the page pools behind address spaces and CSpaces
3. **Address space management** — per-process virtual address space objects
4. **TLB management** — local invalidation, tagged (PCID/ASID) no-flush context
   switch with a full-flush fallback, and SMP shootdown
5. **Kernel stack allocation** — idle stacks from the buddy, every other stack from
   the thread's own slab
6. **Page table node ownership** — which page-table pages belong to an address
   space's pool and which the kernel lends

---

## Buddy Allocator (`mm/buddy.rs`)

### Data Structures

The buddy allocator manages physical memory as a set of power-of-two-sized blocks.
The implementation supports orders 0 through `MAX_ORDER` (inclusive), where an
order-`n` block contains 2^n contiguous 4 KiB pages.

Free-block metadata lives in fixed-size static arrays inside the allocator
struct, not in the free pages themselves: the bootloader identity-maps only
specific regions (`BootInfo`, modules, stack, memory map buffer; see
[core/boot/docs/page-tables.md](../../boot/docs/page-tables.md) § What Gets Mapped), so
free RAM is not generally writable when the allocator initialises in Phase 2.

```rust
pub struct BuddyAllocator
{
    /// Physical block address stored at each pool slot (slot 0 unused).
    addrs: [u64; POOL_SIZE + 1],
    /// Next slot index in the same list for each pool slot (0 = NONE).
    nexts: [u16; POOL_SIZE + 1],
    /// Head slot index for each order's free list (0 = empty list).
    free_lists: [u16; MAX_ORDER + 1],
    /// Head of the unused-slot pool chain.
    pool_head: u16,
    // ... the pool-init flag, page counters, and the Phase-7 seal flag
}
```

Each order's free list is a singly-linked list of pool slot indices; nodes are
recycled through a free-node chain. `POOL_SIZE` (4096) bounds the number of
simultaneously tracked free blocks across all orders — ~32 GiB of RAM when
blocks sit at `MAX_ORDER`. The struct is all-zero-constructible and lives in
BSS.

`MAX_ORDER` is 11 (largest single allocation: 2048 pages = 8 MiB). It is sized
so the largest per-CPU boot slab at `boot_protocol::MAX_CPUS` — `AP_IST_STACKS`,
512 × 16 KiB = 8 MiB — fits one block, since `alloc_zeroed_slab` rounds every
slab to a single power-of-two block. Compile-time asserts at the consumer sites
(`arch/x86_64/ap_trampoline.rs`, `arch/x86_64/gdt.rs`) enforce that envelope:
growing `MAX_CPUS` or a per-CPU slab element past it fails the build rather
than the boot.

### Zone Management

The allocator manages a single zone: one `BuddyAllocator` instance covering all
usable RAM. It has no zone concept. Physical-address-range constraints (e.g.
DMA reachability) are not a kernel concern; they belong to devmgr and the
userspace memory authority, per [docs/memory-model.md](../../../docs/memory-model.md) § Buddy
Allocator.

### Allocation and Deallocation Properties

**Allocation:** Serves the requested order from the free list of that order. If empty,
splits a larger block from the next available order, inserting the unused half into
the appropriate free list. This is O(MAX_ORDER) in the worst case and near-O(1) for
well-behaved workloads.

**Deallocation and coalescing:** On free, the buddy address is computed via XOR of
the block address with its size (buddy pairs differ in exactly one bit). If the buddy
is free, the two blocks are merged and the process repeats at the next order, at most
MAX_ORDER times. Each merge removes the buddy from its order's free list by a linear search
of that list (`remove_block`), so a free costs up to MAX_ORDER levels, each linear in that
order's free-list length. Coalescing eliminates long-term fragmentation.

### Thread Safety

The allocator is protected by a single spinlock (`FRAME_ALLOC_LOCK`, taken by
`mm::with_frame_allocator`). It serves boot only: the Phase 7 drain empties it, and `seal`
arms a debug tripwire on later frees, so no runtime path allocates from it and contention is
not a concern.

---

## Kernel Object Memory (`cap/retype.rs`)

The kernel runs no heap and no `GlobalAlloc`
([docs/memory-model.md](../../../docs/memory-model.md) § Kernel Object Memory). Every kernel object
— the slot pages of a CSpace, thread control blocks, endpoints, notifications, event
queues, wait sets, address spaces, CSpaces, and Memory objects themselves — is
carved out of a Memory capability by retype: the body is constructed in place
at the offset the retype allocator returns, its header records the source, and
the bytes go back to that source when the object's reference count reaches zero,
whether a capability (deleted, or removed by a revoke) or a kernel-internal owner
releases the last reference (see [capability-internals.md](capability-internals.md)
§ Kernel Object Reference Counting). The kernel's own objects are retyped from the SEED
reserve, pinned at the Phase 7 handoff from the front of the largest block
drained from the buddy allocator
([initialization.md](initialization.md) § Phase 7: Capability System); the wrapper bodies
of split-derived caps (the `sys_memory_split` tail and the MMIO, IRQ, I/O-port and
SchedControl split children) and per-thread IOPB leases are also carved from SEED at
runtime; every other userspace object comes from the capability a `cap_create_*` syscall
names. Address spaces and CSpaces
additionally own a page pool for their page tables and slot pages
([capability-internals.md](capability-internals.md) § Page Pools).

Retype and pool allocation are fallible and MUST be handled as fallible at every
call site; there is no allocation that cannot fail
([docs/memory-model.md](../../../docs/memory-model.md) § Kernel Allocation is Fallible).

---

## Address Space Objects (`mm/address_space.rs`)

### Structure

Each process virtual address space is represented by an `AddressSpace` object:

```rust
pub struct AddressSpace
{
    /// Physical address of the root page table frame (PML4 / RISC-V root).
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

    // ... hardware tag state (`tag`, `tag_gen`, `tlb_gen`) and the
    // terminal-fault observer state (`death_observers`, `death_lock`, ...)
}
```

### Lifecycle

1. **Creation** (`SYS_CAP_CREATE_ASPACE`): carve a slab from the source
   Memory cap; page 0 holds the wrapper object and the in-place `AddressSpace`,
   page 1 the zeroed root page table with the kernel higher half mapped (root
   entries 256–511 copied from the active root, so every address space shares the
   kernel's lower-level tables), and the remaining
   pages seed the page-table pool.

2. **Use**: threads reference the `AddressSpace` via their TCB. When scheduled, the
   scheduler calls `AddressSpace::activate` to switch the hardware page table (see
   Context Switch TLB Handling below).

3. **Modification** (`SYS_MEM_MAP`, `SYS_MEM_UNMAP`, `SYS_MEM_PROTECT`): acquire
   `pt_lock`, call `arch::current::paging::map_user_page_pooled` (`map_user_page` for
   a space with no recorded donation) / `unmap_user_page` (`unmap_user_region_pooled`
   for a `MEM_UNMAP_RECLAIM_PTS` unmap) / `protect_user_page`, then perform TLB
   management (see TLB Management section below).

4. **Destruction**: when the address space's reference count reaches zero (see
   [capability-internals.md](capability-internals.md) § Kernel Object Reference
   Counting), every
   donation to its page-table pool — the create-time slab included, with the root
   table and the `AddressSpace` itself — is returned to its source Memory cap
   wholesale (see Page Table Node Ownership below and
   [capability-internals.md](capability-internals.md) § Teardown).

### Fork-Like Operations

Seraph does not provide a `fork()` equivalent. New address spaces are created empty
and populated by the process loader. Copy-on-write is not implemented. Shared memory
is established by mapping the same memory capability into multiple address spaces.

---

## TLB Management

Local invalidation primitives live in the per-architecture paging modules:
`arch::current::paging::flush_page` invalidates a single VA on the current CPU
(`invlpg` / `sfence.vma <va>`), and `flush_tlb_all` drops the current CPU's cached
translations (a CR3 reload, which invalidates the non-global entries of the loaded PCID /
`sfence.vma zero, zero`, which invalidates every entry). When tagging is active,
`flush_page_tagged` and `flush_tag` invalidate a single VA or a whole tag for an arbitrary
PCID/ASID (`invpcid` / `sfence.vma <va>, <asid>` and `sfence.vma zero, <asid>`),
independent of the tag currently loaded. Cross-CPU invalidation is the shootdown protocol
in `mm/tlb_shootdown.rs`. The tag pool and the per-CPU tag state live in
`mm/tag_allocator.rs`; each address space's own tag state (`tag`, `tag_gen`, `tlb_gen`) is
in its `AddressSpace`; see
[docs/memory-model.md](../../../docs/memory-model.md) for the model.

Multi-page ranges use the batched-invalidation window (`inval_batch_begin`, per-page
`inval_page` / `inval_page_tagged`, `inval_batch_end`): on RISC-V the window is the Svinval
bracket (`sfence.w.inval` … `sinval.vma` per page … `sfence.inval.ir`), architecturally
equivalent to an `sfence.vma` per page but paying the fence cost once; on x86-64 the
brackets are no-ops and the per-page calls are `invlpg` / INVPCID. The single-VA
primitives stay `sfence.vma` — for one address a bracket is three instructions instead of
one. Region teardown (`unmap_region_pooled`) uses the window for spans up to
`RANGE_FLUSH_CEILING_PAGES` (32) and the coarse full flush above that, where one working-set
refill is cheaper than per-page walks.

### NAPOT Contiguity (RISC-V)

Uncacheable (PBMT=IO) user mappings are opportunistically coalesced into Svnapot 64 KiB
groups: when a leaf install completes an index-aligned run of 16 identically-attributed,
physically-contiguous 4 KiB leaves on a 64 KiB-aligned base, the arch layer rewrites the
group as one NAPOT translation (N bit set, `ppn[3:0]` carrying the size encoding), letting
hardware cache one TLB entry for the window. Only the MMIO map path produces eligible
runs, so eligibility is gated on PBMT=IO.

Two invariants keep the hint transparent:

- **Promotion and demotion need no flush of their own.** Both encodings translate every
  VA in the group identically, so a cached pre-rewrite entry is benignly stale; each slot
  rewrite is one aligned u64 store, so the lock-free spurious-fault walk sees a correct
  view mid-rewrite either way.
- **Writers demote before divergence.** Any unmap, permission change, or remap touching a
  NAPOT member first restores the 16 per-page PTEs, then modifies its slot — partially
  rewriting a live group would leave siblings whose cached 64 KiB entry still translates
  the modified VA. The writer's ordinary per-VA (or span-wide) invalidation then also
  kills any cached group entry, since an `sfence.vma`/`sinval.vma` naming any address
  inside a NAPOT range must invalidate a covering cached translation.

Readers decode both shapes: `translate_user_page` reconstructs a NAPOT member's PA bits
\[15:12\] from the VA; the fault classifier and teardown walks are N-agnostic (a NAPOT
member carries the same V/U/R/W/X bits, and leaf-vs-table discrimination is by R/W/X).

### Context Switch TLB Handling

When tagging is enabled, a switch to a different address space calls
`AddressSpace::activate`, which claims a hardware tag for the space (lazily, on first
activation) and loads the root under that tag **without** flushing
(`arch::current::paging::activate_tagged`): x86-64 writes CR3 with the PCID and bit 63 set
(`CR4.PCIDE` is on); RISC-V writes `satp` with the ASID and no `sfence.vma`. A per-CPU
generation check then flushes only that tag if it was reissued to a different space
(`tag_gen` mismatch) or accrued unmaps while this CPU was switched away (`tlb_gen` lag;
see [docs/memory-model.md](../../../docs/memory-model.md) § TLB Management). A
`SeqCst` fence between the scheduler's `mark_active` and the generation reads is the
load-bearing barrier (paired with fences in the unmap and eviction paths) that closes the
switch-away races. Where tagging is unavailable — no hardware tags, or a tag field too
narrow to provide more usable tags than CPUs — `activate` uses the full-flush path
`arch::current::paging::activate(root_phys)` (CR3 write with `CR4.PCIDE` clear / `satp`
ASID 0 + `sfence.vma`) on every switch. When tagging is enabled a claim always succeeds: a
full pool evicts the least-recently-claimed tag not active on any CPU, and because the
allocator keeps more usable tags than CPUs and at most one space per CPU is active, such a
tag always exists, so no user space ever runs untagged. Threads sharing an
address space require no TLB operation on switch
([docs/memory-model.md](../../../docs/memory-model.md) § TLB Management). The per-CPU
elided/performed flush counts are summed by the `CAP_INFO_TLB_*` `cap_info` selectors.

### SMP TLB Shootdown

When a mapping is modified in an address space that has active threads on other CPUs,
stale TLB entries on those CPUs may need invalidation. The leaf PTE is edited under
the per-address-space `pt_lock`, which is then **released before** any cross-CPU
work: holding it across the IPI ack-wait would serialize every concurrent map/unmap
on the address space behind cross-CPU latency. Region teardown (`unmap_region_pooled`) is
the exception: it holds `pt_lock` across its one coarse shootdown so that no CPU can reuse
a just-freed page-table frame before every TLB and paging-structure cache is clean; the
contended `pt_lock` path enables interrupts, so a waiting CPU still acks the IPI. Known
defect (#443): on RISC-V a ranged teardown (at most `RANGE_FLUSH_CEILING_PAGES`) invalidates
per VA with `sinval.vma va, zero`, which covers only leaf entries, so a hart can keep a cached
non-leaf entry naming a freed page-table frame.

The shootdown itself is lock-free — there is no global shootdown lock and no IPI
payload. Each CPU owns a request slot. The initiator publishes `(root, virt, pages, tag)`
into its own slot, sets the pending bit of each target CPU, then sends the IPI:

```
1. Edit the leaf PTE under pt_lock; release pt_lock.
2. Bump the space's tlb_gen and fence (so a switched-away CPU flushes on
   reactivation); read active_cpus; exclude the current CPU.
3. Publish (root, virt, pages, tag) into this CPU's request slot and set each
   target's pending bit (the bit doubles as the per-target liveness/ack badge).
4. Send the shootdown IPI to the targets and wait for every pending bit to clear.
```

A target services the slot only once it observes its own pending bit set, so it never
reads a half-published request; it invalidates the named VA — or, for a range request
(`pages > 1`), each page of the span inside one batched-invalidation window — for `tag`
when the request carries one (so a CPU that has since switched to another space still
flushes the right translation; region teardown's range and full-flush requests carry
`tag == 0` and rely on its `tlb_gen` bump for any CPU that switched away) and clears its
bit. Range flushes from every slot matched in one service pass share a
single window, and **every acknowledgement is deferred until the window closes**: a queued
`sinval.vma` is architecturally complete only when the closing `sfence.inval.ir` retires,
so acking earlier would let the initiator proceed against a translation the target can
still use. A full-flush or single-page slot serviced after the window opens executes its
`sfence.vma`-family instruction inside the open window — architecturally legal (the
closing fence still completes the queued `sinval.vma`s), just not part of the batch.
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

The direct physical map is set up during Phase 3 of initialization
([initialization.md](initialization.md) § Phase 3: Kernel Page Tables) and covers all
usable physical memory. The kernel uses `phys_to_virt` and `virt_to_phys` helpers:

```rust
/// Convert a physical address to its direct-map virtual address.
pub fn phys_to_virt(phys: u64) -> u64
{
    direct_map_base() + phys
}

/// Convert a direct-map virtual address back to a physical address.
pub fn virt_to_phys(virt: u64) -> u64
{
    virt - direct_map_base()
}
```

`direct_map_base()` is a runtime value, not a compile-time constant: the bootloader
randomizes the direct-map base per boot (KASLR) and the kernel publishes it once at
entry (`init_paging_mode`), after which the accessor is a single relaxed atomic load.
The Phase-3 builder guards the layout with the shared `boot_protocol::direct_map_ceiling`
(RAM plus any framebuffer / kernel MMIO above the RAM ceiling), which must end at or
below the kernel image base ([initialization.md](initialization.md) § Phase 3: Kernel Page
Tables). These are the only valid paths for physical-to-virtual
conversion. Arbitrary physical addresses must not be accessed by computing offsets from
kernel image addresses.

---

## Kernel Stack Allocation

Each kernel thread (the kernel-side execution context for syscall and interrupt
handling) has a dedicated kernel stack of `KERNEL_STACK_PAGES` pages. Two sources
exist:

- The idle threads' stacks come from the buddy allocator in Phase 4, one
  power-of-two block per CPU, while the buddy still holds large contiguous blocks
  (before the Phase 7 drain); they live for the kernel's lifetime
  ([initialization.md](initialization.md) § Phase 4: Typed-Memory Cap Surface).
- Every other thread's stack is the first `KERNEL_STACK_PAGES` pages of its
  Thread slab — stack, then the page holding the `ThreadObject` and TCB, then
  the per-thread FPU/SIMD save area — which `SYS_CAP_CREATE_THREAD` carves from
  the caller's Memory capability, and boot code carves from the SEED reserve
  for init's own thread; the slab returns to its source when the thread's
  reference count reaches zero (see [capability-internals.md](capability-internals.md)
  § Kernel Object Reference Counting).

---

## Page Table Node Ownership

Intermediate page table nodes (PML3/PML2/PML1 on x86-64; every level below
the root on RISC-V — two to four of them depending on the negotiated paging
mode) are one 4 KiB page each and are owned exclusively by the address space
that contains them; no reference counting is needed. Their source depends on
the mapping path:

- `SYS_MEM_MAP` and `SYS_MMIO_MAP` into a retype-backed address space (every
  user address space, including init's bootstrap space) draw them from the
  page pool of the space's wrapper object, seeded at creation and refilled by
  augment-mode donations from Memory caps; the map returns `OutOfMemory` when
  the pool is empty. The pooled map path marks each table it installs with a
  software bit in the parent entry (`POOLED_TABLE`); a reclaiming unmap
  (`MEM_UNMAP_RECLAIM_PTS`) returns a now-empty node to that pool only when
  its parent entry carries the bit.
- Kernel-direct mappings through `map_page` (the Phase 9 init image, InitInfo
  page, and stack) and any address space without a recorded donation draw
  them from the fixed kernel page-table pool (`mm::kernel_pt_pool`).

No per-node tracking structure exists. On address-space destruction the kernel
does not walk the tables: the wrapper returns every donation wholesale to its
source Memory cap, which reclaims the pool-drawn nodes with it, and the root
table goes with the create-time slab. Kernel-direct nodes are never returned
to the kernel page-table pool. Only init's bootstrap space holds any, and
procmgr destroys it at init's reap (see
[docs/process-lifecycle.md § Init reap](../../../docs/process-lifecycle.md#init-reap)),
so they stay consumed. This residue is an accepted cost, not a defect or
design intent to reclaim: it is bounded by the pool seed (`POOL_SEED_PAGES`,
64 pages), and the pool is a fixed kernel reserve accounted as
kernel-reserved at Phase 7, so returning the nodes would make no page
available to userspace.
See [capability-internals.md](capability-internals.md) § Page Pools for the
donation-record mechanism.

---

## Summarized By

[Page Tables](../../boot/docs/page-tables.md), [core/kernel/README.md](../README.md),
[Architecture Abstraction Layer](arch-interface.md),
[Capability Subsystem Internals](capability-internals.md),
[Kernel Initialization Sequence](initialization.md), [IPC Subsystem Internals](ipc-internals.md),
[SMP Scheduling and Locking Invariants](scheduling-internals.md),
[Syscall Interface Specification](syscalls.md), [Memory Model](../../../docs/memory-model.md),
[Process Lifecycle](../../../docs/process-lifecycle.md),
[init Bootstrap Stages](../../../services/init/docs/bootstrap.md),
[services/procmgr/README.md](../../../services/procmgr/README.md)
