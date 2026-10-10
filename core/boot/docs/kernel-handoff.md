# Kernel Handoff Contract

CPU state, memory state, and register contents the bootloader guarantees
at the kernel entry point. This document is the **contract** — what the
kernel may assume at entry. The *flow* that establishes the contract
(the ten-step boot sequence) is in [boot-flow.md](boot-flow.md); the
*page-table state* at entry is in [page-tables.md](page-tables.md)
§"Contract at Kernel Entry".

The kernel MUST NOT assume anything about the environment beyond what
this document specifies. The bootloader MUST establish exactly this
state before jumping to the kernel entry point.

---

## Kernel Entry Point

The kernel exports a single entry-point symbol. The bootloader jumps to
this address after establishing the CPU state described below.

Signature:

```rust
#[unsafe(no_mangle)]
pub extern "C" fn kernel_entry(boot_info: *const BootInfo) -> !;
```

The entry point receives a single argument: a pointer to the
`BootInfo` structure. The pointer is valid and the structure is fully
populated before the jump. The entry point must not return; the
bootloader does not provide a return address in any meaningful context.

### Calling Convention

`extern "C"` on a Seraph kernel target resolves to:

- **x86-64**: System V AMD64 ABI (first integer argument in `rdi`).
- **RISC-V (RV64IMAC)**: LP64 (first integer argument in `a0`). The kernel
  target is soft-float; the bootloader-to-kernel boundary carries no
  FP/V state.

These are the LLVM defaults for the respective `extern "C"` ABI on the
Seraph custom targets; the bootloader places the `BootInfo` pointer in
`rdi` / `a0` accordingly. Any future change to the kernel entry's
calling convention is an ABI break and MUST accompany a
`BOOT_PROTOCOL_VERSION` bump (see
[`abi/boot-protocol/README.md`](../../../abi/boot-protocol/README.md)).

The `BootInfo` type and all its fields are defined in the
[`abi/boot-protocol`](../../../abi/boot-protocol/) crate. The kernel must
validate `BootInfo.version == BOOT_PROTOCOL_VERSION` on entry and halt
rather than proceed with a mismatched structure (see
[initialization.md](../../kernel/docs/initialization.md) § Phase 0: Entry Validation).

---

## CPU State at Entry

### x86-64

| Item | Guaranteed state |
|---|---|
| Mode | 64-bit long mode |
| Interrupts | Disabled (`IF` = 0) |
| Direction flag | Clear (`DF` = 0) |
| Paging | Enabled; kernel mapped at intended virtual addresses |
| Stack | Valid; at least 64 KiB available |
| `rdi` | Physical address of `BootInfo` structure |
| Floating point | Not initialised; kernel must not use SSE/AVX before enabling |
| GDT | UEFI firmware's (bootloader installs none); kernel replaces it in Phase 5 |
| IDT | Firmware's IDTR; not to be relied on; interrupts stay disabled until the kernel installs its own |

### RISC-V (RV64IMAC, soft-float)

| Item | Guaranteed state |
|---|---|
| Privilege level | Supervisor mode |
| Interrupts | Disabled (`sstatus.SIE` = 0) |
| MMU | Enabled under the negotiated paging mode (Sv39/Sv48/Sv57, recoverable from `satp.MODE`); kernel mapped at intended virtual addresses |
| Stack | Valid; at least 64 KiB available |
| `a0` | Physical address of `BootInfo` structure |
| `a1` | Hart ID of the booting hart (obtained via `EFI_RISCV_BOOT_PROTOCOL`; 0 when the protocol is absent or its call fails) |
| Floating point | Not initialised |

Secondary harts remain stopped under the SBI firmware's Hart State Management (HSM)
extension until the kernel starts them with SBI HSM `hart_start` during SMP bringup
([initialization.md](../../kernel/docs/initialization.md) §"Phase 8: Scheduler and SMP Bringup").

---

## Handoff Sequence

The reference bootloader's architecture-specific handoff implementation
lives in [`core/boot/src/arch/x86_64/handoff.rs`](../src/arch/x86_64/handoff.rs)
and [`core/boot/src/arch/riscv64/handoff.rs`](../src/arch/riscv64/handoff.rs).
The bootloader's page table is installed, the stack pointer is switched to the bootloader-allocated
handoff stack, the BootInfo pointer is loaded into the first-argument register, direction/interrupt
flags are established per the contract above, and control transfers to `kernel_entry` via an
unconditional jump that does not return.

The UEFI firmware's GDT (x86-64), which the bootloader leaves loaded because it installs none,
remains active at entry; the kernel replaces it in Phase 5 (see
[initialization.md](../../kernel/docs/initialization.md) § Phase 5). IDTR likewise still references
the firmware's IDT, which the kernel must not rely on; interrupts stay disabled until the kernel
installs its own. The kernel replaces the bootloader's root page table in Phase 3
([initialization.md](../../kernel/docs/initialization.md) § Phase 3); for ASID use after handoff see
[page-tables.md](page-tables.md) § Activation and
[memory-internals.md](../../kernel/docs/memory-internals.md) § Context Switch TLB Handling.

---

## What Lives Elsewhere

- `BootInfo` field layout, `BOOT_PROTOCOL_VERSION`, `MmioAperture`
  format, memory-map sort/overlap rules, and every other ABI-level
  invariant are owned by the
  [`abi/boot-protocol`](../../../abi/boot-protocol/) crate; see its
  [`abi/boot-protocol/src/lib.rs`](../../../abi/boot-protocol/src/lib.rs) and
  [`abi/boot-protocol/README.md`](../../../abi/boot-protocol/README.md).
- The ten-step boot sequence that leads up to handoff is owned by
  [boot-flow.md](boot-flow.md).
- The page-table state at entry (what pages are mapped, with which
  permissions) is owned by [page-tables.md](page-tables.md) §"Contract
  at Kernel Entry".

---

## Summarized By

[Boot Flow](boot-flow.md), [Page Tables](page-tables.md),
[core/kernel/README.md](../../kernel/README.md), [System Bootstrap](../../../docs/bootstrap.md)
