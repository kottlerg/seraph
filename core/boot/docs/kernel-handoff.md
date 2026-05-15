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
#[no_mangle]
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
`BOOT_PROTOCOL_VERSION` bump.

The `BootInfo` type and all its fields are defined in the
[`abi/boot-protocol`](../../../abi/boot-protocol/) crate. The kernel must
validate `BootInfo.version == BOOT_PROTOCOL_VERSION` on entry and halt
rather than proceed with a mismatched structure.

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
| GDT | Bootloader-provided; kernel replaces it during early initialisation |
| IDT | Not loaded; interrupts must remain disabled until the kernel installs its own |

### RISC-V (RV64IMAC, soft-float)

| Item | Guaranteed state |
|---|---|
| Privilege level | Supervisor mode |
| Interrupts | Disabled (`sstatus.SIE` = 0) |
| MMU | Enabled (Sv48); kernel mapped at intended virtual addresses |
| Stack | Valid; at least 64 KiB available |
| `a0` | Physical address of `BootInfo` structure |
| `a1` | Hart ID of the booting hart (obtained via `EFI_RISCV_BOOT_PROTOCOL`) |
| Floating point | Not initialised |

Secondary harts remain in the UEFI firmware's spin loop or halted state
until the kernel releases them via SBI HSM calls during SMP bringup.

---

## Handoff Sequence

The reference bootloader's architecture-specific handoff implementation
lives in [`boot/src/arch/x86_64/handoff.rs`](../src/arch/x86_64/handoff.rs)
and [`boot/src/arch/riscv64/handoff.rs`](../src/arch/riscv64/handoff.rs).
The bootloader's page table is installed, the BootInfo pointer is
loaded into the first-argument register, direction/interrupt flags are
established per the contract above, and control transfers to
`kernel_entry` via an unconditional jump that does not return.

The bootloader-provided GDT (x86-64) and ASID 0 (RISC-V) remain active
at entry; the kernel replaces them during its own initialisation.

---

## What Lives Elsewhere

- `BootInfo` field layout, `BOOT_PROTOCOL_VERSION`, `MmioAperture`
  format, memory-map sort/overlap rules, and every other ABI-level
  invariant are owned by the
  [`abi/boot-protocol`](../../../abi/boot-protocol/) crate; see its
  [`src/lib.rs`](../../../abi/boot-protocol/src/lib.rs) and
  [`README.md`](../../../abi/boot-protocol/README.md).
- The ten-step boot sequence that leads up to handoff is owned by
  [boot-flow.md](boot-flow.md).
- The page-table state at entry (what pages are mapped, with which
  permissions) is owned by [page-tables.md](page-tables.md) §"Contract
  at Kernel Entry".

---

## Summarized By

[docs/bootstrap.md](../../../docs/bootstrap.md), [boot/README.md](../README.md)
