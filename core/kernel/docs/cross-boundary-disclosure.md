# Kernel Cross-Boundary Disclosure Inventory

Enumerates every value the kernel emits across the user/kernel boundary and
classifies it, establishing that no kernel virtual address or kernel pointer
escapes to userspace — a prerequisite for kernel address-space layout
randomization (KASLR).

---

## Threat model

KASLR randomizes the kernel's virtual base. A single kernel virtual address (VA),
kernel pointer, or value derived from one that reaches userspace defeats base
randomization. This inventory audits the kernel's complete output surface and
records, per surface, why it carries no kernel VA. It is the standing reference
the coding-standards rule "Cross-Boundary Data Hygiene"
([docs/coding-standards.md](../../../docs/coding-standards.md)) requires every new
cross-boundary output to be added to.

Scope is the *kernel-virtual-address* leak. Physical-address disclosure is a
distinct, narrower concern handled in "Physical-address surfaces" below.

## Classification

Each surface is classified as one of:

- **(a) kernel VA / pointer** — a kernel virtual address, kernel pointer, or value
  derived from one. A leak. **None found.**
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
IPC returns use the `set_ipc_*` family. No handler returns a raw pointer: the
return type is uniformly integer, and the only address-valued returns are physical
(class **e**). The dispatch table is `syscall::dispatch`; the full numbered table
is in [docs/syscalls.md](syscalls.md).

| Surface | Anchor (stable identifier) | Class |
|---|---|---|
| Syscall return convention; no raw-pointer return path | `syscall::dispatch`, `TrapFrame::set_return` | b/c/d |
| `SYS_CAP_INFO` tag/rights, thread-state, TLB / cspace / memory counts | `cap::sys_cap_info` | c/d |
| `CAP_INFO_MEMORY_PHYS_BASE` → `MemoryObject::base` | `cap::sys_cap_info`, `cap::object::MemoryObject` | **e** |
| `SYS_SYSTEM_INFO` (version, cpu count, page size, elapsed µs, current cpu) | `sysinfo::sys_system_info` | c/d |
| `SYS_ASPACE_QUERY` → leaf physical address of a user page | `sysinfo::sys_aspace_query`, `AddressSpace::query_page` | **e** |
| `SYS_THREAD_READ_REGS` / `WRITE_REGS` → target thread's user `TrapFrame` | `thread::sys_thread_read_regs`, `TrapFrame::sanitize_for_user_resume` | b/d |
| `SYS_GETRANDOM` → random bytes into a user buffer + byte count | `entropy::sys_getrandom` | d |
| `SYS_SBI_CALL` → firmware `sbiret.value` + error code (RISC-V; args caller-supplied) | `sbi::sys_sbi_call` | d |
| `SYS_IPC_BUFFER_SET` → status only (validates user-half, page-aligned VA) | `syscall::sys_ipc_buffer_set` | (no output) |
| Cap split / create / derive handlers → opaque cap handles | `mem::sys_memory_split`, `hw::sys_mmio_split`, `cap::sys_cap_derive` | c |
| IPC `Message` label / badge / data[] / cap_slots[] | `ipc::message::Message`, `ipc::{read_ipc_buf, write_ipc_buf, write_cap_results}` | b/c |
| Fault message `kind` / `d1` / `d2` / `ip` (user VA or hardware code) + label / badge | `ipc::fault::FaultInfo`, `redirect_user_page_fault`, `redirect_user_exception`, `fault_info_for` | b/d |
| Exit / death reason encoding + death payload `(correlator << 32) \| reason` | `syscall::encode_exit_code`, `EXIT_*` constants, `sched::post_one_death_event` | c/d |
| Thread ID (random CSPRNG correlator; no `tid → TCB` table; never returned as data) | `sched::alloc_thread_id` | c |
| `CSpaceId` (registry index, never returned to userspace); capability badges (caller-chosen) | `cap::alloc_cspace_id`, `cap::slot::CapabilitySlot::badge` | c |
| Boot-time `InitInfo` handover — kernel writes a read-only struct into init's mapped region | `init_protocol::InitInfo`, `init_protocol::CapDescriptor` | b/c/d/e |

Notes on the non-obvious entries:

- **IPC `cap_slots[]`** carry destination CSpace *indices* re-derived for the
  receiver, not pointers; the per-slot generation is stripped on the send path
  (`ipc::unpack_cap_slots`).
- **Fault messages** source `d1`/`ip` from the live user `TrapFrame` — the faulting
  user address and user instruction pointer. The forwarded/readable `TrapFrame`
  holds only user-mode register state (no kernel stack pointer, kernel return
  address, or `CR3`/`satp`); the write path re-validates through
  `sanitize_for_user_resume`.
- **Thread IDs** are random per `sched::alloc_thread_id` (issue #248) — a monotonic
  id would leak thread creation counts/rates wherever logged. They are diagnostic
  correlators only and never cross the boundary as syscall data.
- **`SYS_SBI_CALL`** forwards caller-supplied arguments to M-mode firmware and
  returns the firmware result; neither the arguments the kernel forwards nor the
  value it returns is kernel-derived.
- **`InitInfo` handover** is the boot-time kernel→init struct written into a
  read-only region the kernel maps at the fixed *user* VA `INIT_INFO_VADDR`
  (class **b** — a userspace address by ABI contract). Its `*_cap` / `*_base`
  fields are CSpace slot indices (**c**); versions, counts, and byte-size
  accounting facts including `kernel_reserved_bytes` are quantities, not
  addresses (**d**); the only addresses it carries are physical — each
  `CapDescriptor::aux0` for a Memory/Mmio cap and `InitFramebufferInfo::physical_base`
  (**e**, see "Physical-address surfaces"). No field is a kernel VA.

## Physical-address surfaces

Three surfaces emit real addresses. All are **physical**, not kernel virtual:

- `SYS_ASPACE_QUERY` (`sysinfo::sys_aspace_query`) returns the leaf physical address
  backing a *user* page, gated on an `AddressSpace` capability with the `READ` right.
  The intermediate page-table addresses traversed during the walk are not returned.
- `CAP_INFO_MEMORY_PHYS_BASE` (`cap::sys_cap_info`) returns `MemoryObject::base`, the
  physical base of a Memory object the caller holds a capability to. memmgr depends
  on it to track region contiguity.
- The `InitInfo` handover publishes physical bases for the resources it hands init:
  `CapDescriptor::aux0` (Memory / Mmio physical base) and
  `InitFramebufferInfo::physical_base`. Each describes a resource init receives a
  capability to.

A physical address does not reveal the kernel's randomized virtual base, and each is
gated behind a capability the caller already holds, so neither defeats KASLR. They
are fixed-by-contract disclosures, not leaks.

**Resolved for the KASLR work ([#252](https://github.com/kottlerg/seraph/issues/252)):**
KASLR draws the direct-map base from the boot-entropy source at 1 GiB granularity
(≈17–26 bits on x86-64 / Sv48 / Sv57, ≈8 bits on a near-full Sv39 half), independently
of any physical address. A leaked physical address therefore does **not** reveal the
phys→virt offset — recovering the direct-map base from a physical address would require
also knowing that page's virtual address, which these surfaces do not disclose. So
`SYS_ASPACE_QUERY` and `CAP_INFO_MEMORY_PHYS_BASE` remain fixed-by-contract disclosures,
not KASLR leaks. (`kernel_physical_base` is likewise a physical value and unaffected;
the kernel scrubs the *virtual* KASLR bases — `kernel_virtual_base`, `direct_map_base` —
from the donated `BootInfo` page after consuming them.)

## Kernel console diagnostics

The kernel's `kprint!` / `kprintln!` macros (`console.rs`) and the register-dump,
watchdog, and `KERNEL EXCEPTION` paths do format kernel pointers (`{:p}`, `{:#x}`).
These are **not** a userspace-readable data channel: per the console-model contract
([docs/console-model.md](../../../docs/console-model.md)), the kernel writes the UART
directly and never becomes a client of the userspace serial or framebuffer driver,
and no IPC channel delivers kernel log output to a userspace process as data. The
always-on `USERSPACE FAULT` serial dumps print the faulting thread's *own* user
registers, not kernel addresses. Kernel-pointer console output is therefore an
operator-console diagnostic outside the KASLR threat model; it must not be routed to
any userspace-reachable IPC or log channel.

**KASLR values are serial-only.** The randomized kernel image base, direct-map base,
and slide are secrets whose disclosure defeats KASLR, and they are subject to a
tighter rule than other kernel-pointer diagnostics. `kprintln!` mirrors to the
framebuffer, and although the kernel writes that framebuffer directly (not as a driver
client), the framebuffer *memory* is later handed to the userspace framebuffer driver,
which can read the pixels back — so a KASLR value printed via `kprintln!` becomes
userspace-recoverable. These values must be emitted **only** via the serial-only path
(`kprintln_serial!` / `console::serial_write_fmt`), never `kprintln!`, and never
through any IPC or log channel. The Phase-1 KASLR report prints an address-free status
line via `kprintln!` and the slide/bases only via `kprintln_serial!`; the bootloader's
console (which also mirrors to the framebuffer) prints only the opaque `kaslr_flags`.

## Maintaining this inventory

When a syscall, IPC field, fault message field, exit reason, or `cap_info` /
`system_info` selector is added or changed, classify its output here in the same
change, per the "Cross-Boundary Data Hygiene" rule in
[docs/coding-standards.md](../../../docs/coding-standards.md). A kernel-minted
identifier observed across the boundary is drawn from the entropy root
(`entropy::next_u32` / `entropy::fill_bytes`); see [entropy.md](entropy.md).

---

## Summarized By

[Kernel](../README.md)
