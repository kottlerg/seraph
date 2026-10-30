# Kernel Cross-Boundary Disclosure Inventory

Enumerates every value the kernel emits across the user/kernel boundary and
classifies it toward the goal that no kernel virtual address or kernel pointer
escapes to userspace — a prerequisite for kernel address-space layout
randomization (KASLR). Accepted residual: the x86-64
descriptor-table registers on a CPU without UMIP (§ Surface inventory).

---

## Threat model

KASLR randomizes the kernel's virtual base. A single kernel virtual address (VA),
kernel pointer, or value derived from one that reaches userspace defeats base
randomization. This inventory audits the kernel's complete output surface and
records, per surface, why it carries no kernel VA or, for an accepted residual, what it
leaks. It is the
standing reference the coding-standards rule "Cross-Boundary Data Hygiene"
([docs/coding-standards.md](../../../docs/coding-standards.md)) requires every new
cross-boundary output to be added to.

Scope is the *kernel-virtual-address* leak. Physical-address disclosure is a
distinct, narrower concern handled in "Physical-address surfaces" below.

## Classification

Each surface is classified as one of:

- **(a) kernel VA / pointer** — a kernel virtual address, kernel pointer, or value
  derived from one. A leak. **None found** among emitted values; the one hardware surface
  of this class, the descriptor-table registers on an x86-64 CPU without UMIP, is listed
  below, and kernel state kept in donated memory is a separate surface, below.
- **(b) userspace VA** — an address in the caller's own (or a delegate's) address
  space. The caller already owns it; not a disclosure.
- **(c) opaque / randomized** — a kernel-minted identifier that is unguessable
  (drawn from the entropy root) or a non-pointer registry index. Reveals no kernel
  layout.
- **(d) fixed-by-contract** — an enum discriminant, constant, count, or
  firmware-originated value defined by the ABI.
- **(e) physical address** — a physical address exposed by ABI contract, gated by a
  capability the caller holds. Not a kernel VA. See "Physical-address surfaces".

## Surface inventory

Every syscall returns `Result<u64, SyscallError>` marshalled into a single return
register (`rax` on x86-64, `a0` on RISC-V) by `TrapFrame::set_return`; multi-value
returns (IPC, the notification / event-queue / wait-set waits, and the split handlers'
second cap handle) use the `set_ipc_*` family. No handler returns a raw pointer: the
return type is uniformly integer, and the only address-valued returns are physical
(class **e**). The dispatch table is `syscall::dispatch`; the full numbered table
is in [core/kernel/docs/syscalls.md](syscalls.md).

| Surface | Anchor (stable identifier) | Class |
|---|---|---|
| Syscall return convention; no raw-pointer return path | `syscall::dispatch`, `TrapFrame::set_return` | b/c/d |
| `SYS_CAP_INFO` tag/rights (rights half is type-scoped, interpreted via the tag in the high half), thread-state, TLB / cspace / memory / address-space page-table budget counts, memory has-retype flag | `cap::sys_cap_info` | c/d |
| `CAP_INFO_MEMORY_PHYS_BASE` → `MemoryObject::base` | `cap::sys_cap_info`, `cap::object::MemoryObject` | **e** |
| `CAP_INFO_MEMORY_MAPPINGS` → summed user-mapping counts of a Memory region's frames | `cap::sys_cap_info`, `mm::frame_map::mappings_in` | d |
| `SYS_SYSTEM_INFO` (kernel and boot-protocol versions, cpu count, page size, elapsed µs, current cpu) | `sysinfo::sys_system_info` | c/d |
| `SYS_ASPACE_QUERY` → leaf physical address of a user page | `sysinfo::sys_aspace_query`, `AddressSpace::query_page` | **e** |
| `SYS_THREAD_READ_REGS` / `WRITE_REGS` → target thread's user `TrapFrame` | `thread::sys_thread_read_regs`, `TrapFrame::sanitize_for_user_resume` | b/d |
| `SYS_GETRANDOM` → random bytes into a user buffer + byte count | `entropy::sys_getrandom` | d |
| `SYS_SBI_CALL` → firmware `sbiret.value` on success, `NotSupported` on any firmware error (RISC-V; args caller-supplied) | `sbi::sys_sbi_call` | d |
| `SYS_IPC_BUFFER_SET` → status only (validates user-half, page-aligned VA) | `syscall::sys_ipc_buffer_set` | (no output) |
| Cap split / create / derive handlers → opaque cap handles | `mem::sys_memory_split`, `hw::sys_mmio_split`, `cap::sys_cap_derive` | c |
| IPC `Message` label / badge / data[] / cap_slots[] | `ipc::message::Message`, `ipc::{read_ipc_buf, write_ipc_buf, write_cap_results}` | b/c |
| Fault message `kind` / `d1` / `d2` / `ip` (user VA or hardware code) + label / badge | `ipc::fault::FaultInfo`, `redirect_user_page_fault`, `redirect_user_exception`, `fault_info_for` | b/d |
| Exit / death reason encoding + death payload `(correlator << 32) \| reason` | `syscall::encode_exit_code`, `EXIT_*` constants, `sched::post_one_death_event` | c/d |
| Thread ID (random CSPRNG correlator for every thread but init, whose ID is the fixed value 1; no `tid → TCB` table; never returned as data) | `sched::alloc_thread_id` | c/d |
| `CSpaceId` (registry index, never returned to userspace); capability badges (caller-chosen) | `cap::alloc_cspace_id`, `cap::slot::CapabilitySlot::badge` | c |
| Boot-time `InitInfo` handover — kernel writes a read-only struct into init's mapped region | `init_protocol::InitInfo`, `init_protocol::CapDescriptor` | b/c/d/e |
| x86-64 descriptor-table registers read at CPL 3 (`SGDT`, `SIDT`, `SLDT`, `SMSW`, `STR`): `#GP` where `CR4.UMIP` is set; the IDTR and GDTR bases on a CPU without UMIP | `cpu::enable_smep_smap`, `idt::IDT`, `gdt::GDT`, `gdt::AP_GDT_PTR` | d / **a** without UMIP |

Notes on the non-obvious entries:

- **IPC `cap_slots[]`** carry cap *handles* (CSpace-local index + per-slot
  generation), never pointers: the sender's own full handles inbound
  (`syscall_abi::unpack_cap_handles`, generation-validated by
  `ipc::prevalidate_transfer_slots` before any move), and freshly
  re-derived destination handles outbound. Both directions expose only
  values the owning process already holds or is being granted; see
  [syscalls.md](syscalls.md) § Capability Handles.
- **Fault messages** carry, for `FAULT_KIND_VM`, the user faulting address in `d1`
  (`CR2` on x86-64, `stval` on RISC-V), access flags in `d2`, and the user instruction
  pointer from the `TrapFrame` in `ip`; for `FAULT_KIND_EXCEPTION`, a normalized
  exception code in `d1` and an architecture code (x86-64 error code, RISC-V `stval`)
  in `d2` ([docs/fault-handling.md](../../../docs/fault-handling.md) § Fault Message).
  On x86-64, `FAULT_ACCESS_PRESENT` in `d2` copies the hardware `#PF` P bit only when
  `CR2` is a user-half address (`page_fault_handler`): the kernel half is mapped
  supervisor-only in every user address space, so for a kernel-half `CR2` the bit would
  let a process bound as its own fault handler probe whether a kernel VA is mapped, and
  it is reported clear there. RISC-V never sets the bit. No other word carries a kernel
  VA or a value derived from one. The forwarded/readable `TrapFrame` holds only user-mode
  register state (no kernel stack pointer, kernel return address, or `CR3`/`satp`); the
  write path re-validates through `sanitize_for_user_resume`. `sys_thread_read_regs`
  pins the Thread it resolves through `lookup_cap` for the call, so a sibling's concurrent
  delete or revoke of the last Thread capability cannot free the thread slab while
  `sched::with_held_frame` snapshots its trap frame: the snapshot `copy_to_user` returns
  is the target's user register state.
- **Descriptor-table registers** are a hardware output, not a value the kernel emits:
  with `CR4.UMIP` clear, `SIDT` and `SGDT` execute at CPL 3 and return the IDTR and GDTR.
  The IDT and the BSP's GDT are statics in the kernel image, so on any CPU `SIDT`, and
  `SGDT` on the BSP, recover the KASLR image slide; an AP's GDT is a slot of the per-AP slab
  `gdt::init_ap_storage` allocates, a direct-map address, so `SGDT` on an AP recovers the
  randomized direct-map base. One unprivileged instruction reveals either. The kernel sets
  `CR4.UMIP` on every CPU whose CPUID reports it (`cpu::enable_smep_smap`, BSP and APs,
  before the first ring-3 entry), and the five reads then raise `#GP`, delivered or killed
  on as any user exception. UMIP is opportunistic
  ([docs/platform-requirements.md](../../../docs/platform-requirements.md) § x86-64
  Classification), so on a CPU without it the disclosure remains (class **a**): an accepted
  residual of the platform floor, not a defect of the kernel's outputs. `SLDT` and `STR`
  return selectors and `SMSW` the low CR0 bits, none of them an address. RISC-V has no
  user-readable descriptor-table register.
- **Thread IDs** are random per `sched::alloc_thread_id`, except init's, which is the
  fixed value 1 (class **d**) (issue #248;
  [scheduling-internals.md](scheduling-internals.md) § Cross-CPU TCB Ownership) — a
  monotonic id would leak thread creation counts/rates wherever logged. They are diagnostic
  correlators only and never cross the boundary as syscall data.
- **`SYS_SBI_CALL`** forwards caller-supplied arguments to M-mode firmware and
  returns the firmware result; neither the arguments the kernel forwards nor the
  value it returns is kernel-derived.
- **`InitInfo` handover** is the boot-time kernel→init struct written into a
  read-only region the kernel maps at a per-boot user VA (`InitLayout::init_info_va`,
  drawn by `mm::address_space::choose_init_layout` from `INIT_INFO_WINDOW`, with
  `DEFAULT_INIT_INFO_VA` as the unseeded fallback) and passes to init in its first
  argument register (class **b**, a userspace address; see
  [docs/userspace-memory-model.md](../../../docs/userspace-memory-model.md) § Bootstrap
  Cross-Boundary VAs). Its `*_cap` / `*_base`
  fields are CSpace slot indices (**c**); versions, counts, and byte-size
  accounting facts including `kernel_reserved_bytes` are quantities, not
  addresses (**d**); the only addresses it carries are physical — each
  `CapDescriptor::aux0` for a Memory/Mmio cap and `InitFramebufferInfo::physical_base`
  (**e**, see "Physical-address surfaces"). No field is a kernel VA.
- **`CAP_INFO_MEMORY_MAPPINGS`** returns a count (**d**). It is the number of user
  page-table leaves, in any address space, that name a frame of the queried Memory region.
  It carries no address, and the kernel answers only through a Memory capability the caller
  holds, for a region of at most 512 pages. What it discloses beyond the caller's own
  mappings is how many leaves other holders of the same frames map, a coarse activity signal
  about those holders. A server that hands pages out needs exactly that signal: it reuses a
  page only once a client's mapping of it is gone.

## Physical-address surfaces

Three surfaces emit real addresses. All are **physical**, not kernel virtual:

- `SYS_ASPACE_QUERY` (`sysinfo::sys_aspace_query`) returns the leaf physical address
  backing a *user* page, gated on an `AddressSpace` capability with the `READ` right
  ([syscalls.md](syscalls.md) § `SYS_ASPACE_QUERY` (41)). The intermediate page-table
  addresses traversed during the walk are not returned.
- `CAP_INFO_MEMORY_PHYS_BASE` (`cap::sys_cap_info`) returns `MemoryObject::base`, the
  physical base of a Memory object the caller holds a capability to. memmgr depends
  on it to track region contiguity.
- The `InitInfo` handover publishes physical bases for the resources it hands init:
  `CapDescriptor::aux0` (Memory / Mmio physical base) and
  `InitFramebufferInfo::physical_base`. Each describes a resource init receives a
  capability to.

A physical address does not reveal the kernel's randomized virtual base, and each is
gated behind a capability the caller already holds, so none defeats KASLR. They
are fixed-by-contract disclosures, not leaks.

**Resolved for the KASLR work ([#252](https://github.com/kottlerg/seraph/issues/252)):**
KASLR draws the direct-map base from the boot-entropy source at 1 GiB granularity
(≈17–26 bits on x86-64 / Sv48 / Sv57, ≈8 bits on a near-full Sv39 half; see
[docs/memory-model.md](../../../docs/memory-model.md) § Virtual Address Space Layout),
independently of any physical address. A leaked physical address therefore does **not**
reveal the phys→virt offset — recovering the direct-map base from a physical address
would require also knowing that page's virtual address, which these surfaces do not
disclose. So `SYS_ASPACE_QUERY` and `CAP_INFO_MEMORY_PHYS_BASE` remain fixed-by-contract
disclosures, not KASLR leaks. (`kernel_physical_base` is likewise a physical value and
unaffected; the kernel scrubs the *virtual* KASLR bases — `kernel_virtual_base`,
`direct_map_base` — from the donated `BootInfo` page after consuming them; see
[initialization.md](initialization.md) § Phase 5.)

## Kernel state in donated memory

The surfaces above are values the kernel emits. A distinct surface is kernel
state the kernel keeps in memory retyped from a user-held Memory capability:
every object the retype dispatch carves there — wrapper pages, capability slot
pages (each slot holds an object pointer) and the directory pages that index
them (each a page of leaf pointers), page tables, page-pool record pages (each
record holds a raw `KernelObjectHeader` pointer to its donation's ancestor;
see [capability-internals.md](capability-internals.md) § Page Pools), thread
slabs (the kernel stack with its saved kernel pointers and return addresses,
the TCB, and the extended-state save area), and the sub-page bodies of
endpoints, notifications, wait sets, and event queues (which hold TCB and
source-object pointers) — plus the retype allocator's free-list links (offsets
into the region, not addresses). The donating capability cannot map what it
has retyped away: `SYS_MEM_MAP` refuses a range below its retype bump cursor
([docs/capability-model.md § Typed Memory](../../../docs/capability-model.md#typed-memory)).
Nor can a retype carve a page any address space maps: the kernel counts the
user mappings of every frame of RAM and refuses a retype over a mapped page
([memory-internals.md](memory-internals.md) § Frame Map Table), so no kernel
object state in donated memory sits behind a live user mapping, whichever order
the map and the retype came in.

Memory the bootloader used is a related surface, whether it is donated
through `reclaim_ranges` or returned by the memory map as usable and drained
at Phase 7. The kernel zeroes both before init runs, so neither bootloader
scratch nor firmware leftovers reach userspace with their contents intact
(boot modules, firmware tables, and init's image reach it by design). Phase 7 zeroes every drained
extent it mints to userspace (`cap::drain_and_install_seed`). That covers the UEFI
stack the bootloader ran on, `EfiBootServicesData` holding the slid kernel image
addresses and the KASLR locals at handoff. Phase 9 zeroes every `reclaim_ranges`
entry right before init is enqueued (`cap::scrub_reclaim_ranges`). That covers the
transient page-table frames, whose populated entry indices encode the slid kernel
VA; the `BootInfo` page and the descriptor arrays; the bundle's non-module pages;
and the AP trampoline page, whose parameter block carried the AP entry point and
idle-stack VAs ([initialization.md](initialization.md) § Phase 7 and § Phase 9).
Two earlier scrubs remain as defence in depth: Phase 5 clears the seed and the
two KASLR bases from the `BootInfo` page once consumed, and the bootloader
clears its own copies of the entropy words. Init's segment allocations are
zeroed whole by the bootloader before the image is copied in
([core/boot/docs/elf-loading.md](../../boot/docs/elf-loading.md) § Init ELF
Loading).

From Phase 3 to the Phase 7 drain, the buddy allocator also keeps kernel state in
free RAM: the first 16 bytes of every free block hold its free-list header, the
physical address of the next free block and the block's order
([memory-internals.md](memory-internals.md) § Buddy Allocator). No header reaches
a user-visible page. Only free blocks carry a header (a merge clears the header
of every buddy it absorbs), `BuddyAllocator::alloc` zeroes the header bytes of
every block it hands out, and the pre-drain blocks that reach userspace, init's
`InitInfo` block and stack pages, are zeroed whole at Phase 9 before they are
mapped. The drain hands its extents out with their headers in place, and Phase 7
zeroes all of them, the seed reserve included, before minting any, as above, so
the Memory caps userspace retypes and maps start from zeroed RAM.

## Kernel console diagnostics

The kernel's `kprint!` / `kprintln!` macros (`core/kernel/src/console.rs`) and the
register-dump, watchdog, and `KERNEL EXCEPTION` paths do format kernel pointers (`{:p}`,
`{:#x}`). No IPC channel delivers kernel log output to a userspace process as data, but
`kprintln!` mirrors to the framebuffer, whose memory userspace can read back; only the
serial-only class ([docs/console-model.md](../../../docs/console-model.md) § Ownership
across the boot lifecycle) is not userspace-readable. The
always-on `USERSPACE FAULT` serial dumps print the faulting thread's *own* user
registers, not kernel addresses. Every kernel VA outside the low-VA identity mappings
(the boot-stack mapping and, until Phase 8, the AP trampoline page, whose VAs equal
their physical addresses) lies in one of the two regions KASLR randomizes (the image
or the direct map; see
[docs/memory-model.md](../../../docs/memory-model.md) § Virtual Address Space Layout), so
kernel-pointer console output is governed by the serial-only rule below; it must not be
routed to any userspace-reachable IPC or log channel.

**KASLR values are serial-only.** The randomized kernel image base, direct-map base, and slide, and
any kernel virtual address derived from them (an image VA or a direct-map VA), are secrets whose
disclosure defeats KASLR. `kprintln!` mirrors to the framebuffer, and although the kernel writes
that framebuffer directly (not as a driver client), the framebuffer *memory* is later handed to the
userspace framebuffer driver ([docs/console-model.md](../../../docs/console-model.md) § The
framebuffer driver as sole userspace framebuffer owner), which can read the pixels back — so a KASLR
value printed via `kprintln!` becomes userspace-recoverable. These values must be emitted **only**
via the serial-only sinks (`kprintln_serial!` / `console::serial_write_fmt`; on the panic and NMI
paths the lock-bypassing `console::panic_write_fmt` and `kprintln_nmi!` / `console::nmi_write_fmt`),
never `kprintln!`, and never through any IPC or log channel. The panic handler's backtrace and the
x86-64 NMI backtrace print their kernel addresses through those two sinks. The Phase-1 KASLR report
prints address-free status lines (one for the image, one for the direct map) via `kprintln!` and the
slide/bases only via `kprintln_serial!`; the Phase-9 init-thread report prints the thread id and
priority on one `kprintln!` line and init's kernel stack top (a direct-map VA) on a separate
`kprintln_serial!` line; the watchdog dump's lock-wait line prints the lock kind via `kprintln!` and
the lock word's address (an image VA for a static lock, revealing the slide, or a direct-map VA for
a slab-resident one) only via `kprintln_serial!`, and the rest of the watchdog dump (the per-CPU
snapshot, the sleep list, the registry walk and its blocking-object decode) names threads by id and
objects by kind, printing no pointer; the bootloader's console (which also mirrors to the
framebuffer) prints only the opaque `kaslr_flags`. Paths that end in `fatal`, which halts only the
faulting CPU (so on SMP the rest of the system, userspace included, keeps running), print an
address-free header via `kprintln!` and every value that can be a kernel VA via `kprintln_serial!`:
the x86-64 `KERNEL EXCEPTION` dump (`rip`, `cr2`, and the register file serial-only; the vector,
error code, `cs`, and `rflags` on the console), the riscv64 `KERNEL EXCEPTION` dump (`sepc`,
`stval`, `satp`, and the register file serial-only; `scause` and `sstatus` on the console), the
riscv64 unknown-interrupt path (`sepc` serial-only), and the riscv64 `BUG: ecall return sepc` path
(`sepc`, `ra`, `sp`, and `a7` serial-only). `free_seed_scratch`'s corrupt-lease report, which
returns rather than halting, prints the lease's size and the seed's physical range via `kprintln!`
and the lease pointer and its derived physical address, whose difference is the direct-map base,
only via `kprintln_serial!`.

## Maintaining this inventory

When a syscall, IPC field, fault message field, exit reason, or `cap_info` /
`system_info` selector is added or changed, classify its output here in the same
change, per the "Cross-Boundary Data Hygiene" rule in
[docs/coding-standards.md](../../../docs/coding-standards.md). A kernel-minted
identifier observed across the boundary is drawn from the entropy root
(`entropy::next_u32` / `entropy::fill_bytes`); see [entropy.md](entropy.md).

---

## Summarized By

[core/kernel/README.md](../README.md), [Capability Subsystem Internals](capability-internals.md),
[Kernel Initialization Sequence](initialization.md),
[SMP Scheduling and Locking Invariants](scheduling-internals.md),
[Console Model](../../../docs/console-model.md),
[Device Management](../../../docs/device-management.md), [Testing](../../../docs/testing.md)
