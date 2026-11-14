# Return-Address Integrity

Specifies how the kernel protects its own return addresses on each architecture: the threat it
answers beside Rust's memory safety and the kernel-stack guard pages, the options evaluated, the
direction chosen per architecture, and the verified state of the toolchain, the firmware, and
the emulator that direction depends on.

---

## Scope

This document covers backward-edge control-flow integrity for kernel (supervisor) code: that a
kernel function returns only to the address its caller's call left. It is authoritative for the
per-architecture choice of mechanism and for the conditions under which each is built.

Out of scope:

- Forward-edge control-flow integrity (indirect calls and jumps): x86-64 IBT, RISC-V Zicfilp,
  and KCFI. They are evaluated in § Options for completeness and not pursued.
- Return-address integrity for userspace programs.
- The feature classification itself, which
  [docs/platform-requirements.md](../../../docs/platform-requirements.md) owns.

Implementation status: no mechanism of this document is implemented. Every statement of kernel
behaviour in § Direction, § riscv64 Mechanism, and § x86-64 Mechanism is design intent.

---

## Threat Model

The kernel is written in Rust, so safe code cannot write out of bounds or through a dangling
pointer. What remains is the `unsafe` code (the architecture layer, the page tables, the
assembly entry paths), a compiler or library defect, and hardware faults that corrupt memory. A
write from any of them that lands on a saved return address turns a memory error into control of
the kernel's execution.

The kernel-stack guard pages (`mm/stack_guard.rs`;
[memory-internals.md](memory-internals.md) § Kernel Stack Guards) stop one class of such writes:
a stack that grows past its bottom faults on the unmapped page below it instead of writing the
memory beneath. A guard catches a downward linear overflow. It does not catch a write inside the
stack's bounds, such as an overrun of a local buffer onto the return address of the same frame,
or a write through a stray pointer that lands on a stack.

A shadow stack catches both. Each call records the return address a second time, in memory that
ordinary stores cannot write, and each return compares the two copies and faults on a mismatch.
The guard pages and the shadow stack are complementary, and neither replaces the other. A shadow
stack does not stop a corruption of data, of a function pointer, or of an indirect-branch target,
and it does not stop an attacker who can write the shadow-stack memory itself, which is why that
memory has no ordinary writable mapping (§ riscv64 Mechanism).

---

## Options

Toolchain statements are for the pinned `nightly-2026-11-10` (rustc 1.102.0-nightly `ac8310ba6`,
LLVM 23.1.5) and were verified as § Verification Record states; QEMU statements are for the
QEMU versions named there.

| Option | Protects | Toolchain | Hardware | Under QEMU TCG |
|---|---|---|---|---|
| Stack canary (`-Zstack-protector`) | A linear overrun of a frame's local array onto its saved state | rustc offers only the strategy (`all`, `strong`, `basic`, `none`) and no option for the guard's location, so no per-CPU or per-thread guard exists | Any | Testable |
| rustc ShadowCallStack (`-Zsanitizer=shadow-call-stack`) | Return addresses, in a second stack addressed by `gp` | Supported by the built-in riscv64 targets; not by `x86_64-unknown-none` (which supports only `kcfi` and `kernel-address`) | Any riscv64 hart | Testable |
| x86-64 CET shadow stack (SHSTK) | Return addresses, in shadow-stack pages written only by `CALL` and the shadow-stack instructions | Needs no instrumentation: `CALL` pushes the return address to both stacks and `RET` compares the copies and raises a control-protection fault on a mismatch ([Linux x86 shadow stack documentation](https://docs.kernel.org/arch/x86/shstk.html)) | Present on the development host, a 12th-generation Intel Core (`user_shstk` in `/proc/cpuinfo`); its spread across the x86-64 platform floor was not verified | Not testable: TCG refuses `cet-ss` |
| x86-64 CET IBT | Indirect-branch targets (forward edge) | `-Zcf-protection=branch` | Not verified | Not testable: TCG refuses `cet-ibt` |
| RISC-V Zicfiss | Return addresses, in shadow-stack (SS) pages that only shadow-stack instructions can write | The compiler must emit `sspush` and `sspopchk`; no rustc flag of the pinned toolchain does (§ Verification Record, check 1) | An RVA23 expansion option, not mandatory (check 4); the instructions are Zimop and Zcmop encodings, mandatory in RVA23, and run as no-ops where Zicfiss is absent or not enabled | Testable: TCG enforces the return-address check and the SS-page protection (check 3) |
| RISC-V Zicfilp | Indirect-branch targets (forward edge) | Not evaluated; [rust-lang/rust#165215](https://github.com/rust-lang/rust/pull/165215) reports that `-Zcf-protection=branch` crashes rustc on RISC-V | An RVA23 expansion option | Not evaluated |

The software ShadowCallStack keeps its shadow stack in ordinary writable memory, at an address
held in a register every function can read: it raises the cost of an attack, and an arbitrary
write still defeats it. The canary detects only a linear overrun that crosses the canary, and
one value is shared by every thread and every CPU. The hardware shadow stacks are the
only options whose second copy ordinary stores cannot reach.

---

## Direction

The maintainer decided the direction per architecture, both mechanisms opportunistic: used where
the hardware has the feature, with the kernel running unprotected and otherwise unchanged where
it does not
([docs/platform-requirements.md](../../../docs/platform-requirements.md) § Feature Classes):

- **riscv64: Zicfiss supervisor shadow stacks.** The shadow-stack instructions are Zimop and
  Zcmop encodings, which RVA23 mandates, so one kernel image serves every RVA23 hart: with
  Zicfiss enabled they enforce, and without it they do nothing. The path is testable under the
  emulator CI uses.
- **x86-64: CET supervisor shadow stacks (SHSTK)**, tracked in
  [#1083](https://github.com/kottlerg/seraph/issues/1083). CI, which runs only under TCG, can
  validate only the path without CET; a local KVM boot on CET hardware validates the enabled
  path.
- **No software ShadowCallStack on either architecture.** On riscv64 it is a compile-time
  alternative to Zicfiss, not a complement: both instrument the same prologues and epilogues, and
  the software form protects less (§ Options). On x86-64 the toolchain does not offer it.

Forward-edge CFI (IBT, Zicfilp) is not pursued.

The riscv64 mechanism cannot be built yet: no rustc flag of the pinned toolchain emits the
Zicfiss instructions (check 1). The riscv64 implementation waits until the pinned toolchain's
`-Zcf-protection=return` marks each function with LLVM's `hw-shadow-stack` attribute on riscv64,
the change [rust-lang/rust#165215](https://github.com/rust-lang/rust/pull/165215) proposes (open
when this was verified). The x86-64 implementation does not depend on it, since CET SHSTK needs
no compiler instrumentation.

Downsides of the direction:

- A riscv64 machine on which any hart lacks Zicfiss gets no protection on any hart, and Zicfiss
  is optional in RVA23 (check 4).
- x86-64 hardware without CET gets no protection.
- The x86-64 enabled path lies outside the CI gate.
- The riscv64 path depends on an unstable rustc flag and on target features LLVM still names
  experimental (`experimental-zicfiss`).

---

## riscv64 Mechanism

Design intent; not yet implemented. The architectural facts are from the RISC-V privileged and
unprivileged specifications' CFI chapters and the SBI specification's Firmware Features (FWFT)
extension, as § Verification Record cites them.

- **Code generation.** The kernel target (`xtask/targets/riscv64imac-seraph-none.json`) gains
  `+zimop`, `+zcmop`, and `+experimental-zicfiss`, and every crate of the kernel image builds
  with `-Zcf-protection=return`. LLVM then emits `sspush ra` (compressed to `c.sspush ra` with
  Zcmop) in the prologue of each function that saves `ra`, and `sspopchk ra` before its return.
  The target's `features` change makes Zimop and Zcmop required on riscv64: a hart without them
  takes an illegal-instruction exception at the first such encoding. RVA23 mandates both, so the
  requirement excludes no hardware inside the floor.
- **Enable.** The kernel asks M-mode for supervisor shadow stacks with SBI FWFT `SET` of
  `SHADOW_STACK` (feature 2) to 1, with the `LOCK` flag so nothing can clear it before the hart
  resets; firmware sets `menvcfg.SSE`. `ssp` cannot be written before the enable (with
  `menvcfg.SSE` clear an access to it is an illegal instruction), and every `sspush` after it
  stores at `ssp`, so the `SET` and the write of `ssp` are one assembly sequence with no call
  between them, made with interrupts disabled, after the hart's first shadow stack has its SS
  leaf (below):
  - The boot hart enables after Phase 3 and the boot-stack rebase, inline in
    `kernel_entry_post_rebase` once Phase 4 has captured `KernelMmio`, not in a function it
    calls. Before Phase 3 no direct map, and so no SS leaf, exists. A function entered before the
    enable would check its return against a shadow stack it never pushed to;
    `kernel_entry_post_rebase` never returns, so no frame that began before the enable runs its
    `sspopchk`.
  - A secondary hart enables in its startup assembly, before its first call, on the shadow
    stack the boot hart prepared for its idle stack.
  - Shadow stacks are on for every hart or for none, since a thread migrates between harts with
    a live call chain, so the kernel decides before any hart enables. The bootloader gains a
    `HART_CAP_ZICFISS` bit in `KernelMmio::hart_caps`, which it sets only when every enabled
    hart's DTB node or ACPI RHCT ISA string advertises Zicfiss, as for the other `HART_CAP_*`
    bits. Without that bit no hart asks, and the kernel runs with the instructions as no-ops: a
    machine on which only some harts have Zicfiss boots unprotected. With it, the boot hart's
    reply decides: after an error reply (`SBI_ERR_NOT_SUPPORTED`, or the reply of a firmware
    without FWFT) no hart asks either. A secondary hart whose `SET` fails after the boot hart's
    succeeded contradicts its own hardware description, and halts the boot, as a secondary hart
    with a different vector length does
    ([docs/platform-requirements.md](../../../docs/platform-requirements.md) § riscv64
    Classification states both conditions).

  The kernel keeps `senvcfg.SSE` clear, so U-mode cannot access `ssp` and runs Zicfiss
  instructions as no-ops. `SYS_SBI_CALL` keeps refusing the FWFT extension (`syscall/sbi.rs`),
  since a forwarded FWFT call would reach this setting.
- **Shadow-stack memory.** Each kernel stack gets a shadow stack: one 4 KiB page per Thread,
  carved from the Thread retype slot (`sched/thread_slot.rs`), and one per idle stack and for the
  handoff stack. Its direct-map leaf becomes an SS page (`R=0`, `W=1`, `X=0`), so no ordinary
  writable alias of it exists; the split of the 2 MiB direct-map leaf reuses the guard-page
  reserve of `mm/stack_guard.rs`. With `menvcfg.SSE` clear that encoding is reserved, and any
  access to the page faults. The boot hart installs the handoff shadow stack's leaf just before
  its enable, when nothing accesses the page; on an error reply it restores the leaf as ordinary
  memory. Every other SS leaf is installed only once shadow stacks are on. Ordinary loads may
  read an SS page; ordinary stores, fetches, and cache-block operations fault.
- **`ssp`.** The trap entry (`arch/riscv64/interrupts.rs`) runs on the interrupted thread's
  shadow stack, as it runs on its kernel stack; the context switch (`arch/riscv64/context.rs`)
  saves the outgoing thread's `ssp` and loads the incoming one's.
- **Faults.** A mismatch at `sspopchk` raises the software-check exception (cause 18) with
  `stval` 3 (shadow-stack fault); a shadow-stack instruction whose `ssp` points outside an SS
  page raises a store/AMO access fault. Both are kernel faults and halt.
- **Emulation.** The xtask riscv64 `-cpu` string
  ([docs/build-system.md](../../../docs/build-system.md) § QEMU and Firmware) gains
  `zimop=on,zcmop=on,zicfiss=on`. QEMU names `zimop` and `zcmop` from 9.1 and `zicfiss` from
  9.2, so the QEMU minimum rises from 9.0 to 9.2.
- **Test.** A ktest cell corrupts a saved return address between `sspush` and `sspopchk` and
  expects the software-check exception. TCG does not fault a shadow-stack access outside an SS
  page (check 3), so CI cannot catch an `ssp` that points at ordinary memory, which halts the
  kernel on hardware: a ktest cell checks instead that the running thread's `ssp` lies within an
  SS leaf of its own shadow stack.

---

## x86-64 Mechanism

Design intent; not yet implemented. The implementation
([#1083](https://github.com/kottlerg/seraph/issues/1083)) specifies it here: `CR4.CET`,
`IA32_S_CET.SH_STK_EN`, the supervisor shadow-stack pointer, the interrupt shadow-stack table for
the vectors that switch stacks, shadow-stack leaves in the direct map, and the shadow-stack token
switch on context switch. Its protection does not depend on compiler instrumentation, since
`CALL` and `RET` maintain the shadow stack (§ Options).

---

## Verification Record

The four facts the riscv64 implementation depends on, each verified as stated. Probes were
throwaway and are not in the tree.

1. **The pinned toolchain does not emit Zicfiss instructions.** A two-function `no_core` crate
   and `core` were compiled for a copy of `xtask/targets/riscv64imac-seraph-none.json` with
   `+zimop,+zcmop,+experimental-zicfiss`, and the assembly was read:
   - With `supported-sanitizers: ["shadow-call-stack"]` and `-Zsanitizer=shadow-call-stack`,
     LLVM emits the software shadow call stack through `gp` (`addi gp, gp, 8` and
     `sd ra, -8(gp)` in the prologue), not `sspush`.
   - With `-Zcf-protection=return`, rustc sets the `cf-protection-return` module flag and LLVM
     emits nothing for it. LLVM 23 emits `sspush` and `sspopchk` only in a function carrying the
     `hw-shadow-stack` attribute: the toolchain's own `llc` emits them once that attribute is
     added to rustc's IR, and clang 23 adds it under `-fcf-protection=return`. The string
     `hw-shadow-stack` occurs in the toolchain's `libLLVM` and not in `librustc_driver`.
   - Upstream, [rust-lang/rust#165215](https://github.com/rust-lang/rust/pull/165215) makes
     `-Zcf-protection=return` add `hw-shadow-stack` on RISC-V (requiring the `zimop` target
     feature); it was open, so no nightly carries it.
2. **The OpenSBI in the boot path implements FWFT `SHADOW_STACK`.** QEMU's `-machine virt`
   runs its bundled OpenSBI below the EDK2 firmware. The CI boot log (the riscv64 ktest cells
   on `ubuntu-26.04`, QEMU 10.2) prints `OpenSBI v1.8`, `Runtime SBI Version : 3.0`, and `fwft`
   among the standard SBI extensions; QEMU 11.1.3 as packaged on the development host bundles
   OpenSBI v1.8.1. OpenSBI v1.8's `lib/sbi/sbi_fwft.c` implements `SHADOW_STACK` as
   `menvcfg.SSE`, reported as supported only on a hart with Zicfiss, and `lib/sbi/sbi_hart.c`
   delegates the software-check exception to S-mode on a platform with the `medeleg` feature,
   which the CI log reports. [docs/platform-requirements.md](../../../docs/platform-requirements.md)
   names no OpenSBI version; it requires SBI HSM and RFENCE only.
3. **QEMU TCG enforces S-mode shadow stacks, with one gap.** A bare S-mode program, entered by
   the OpenSBI v1.8.1 that QEMU 11.1.3 bundles, on `-machine virt` with
   `-cpu rv64,zimop=on,zcmop=on,zicfiss=on` under TCG (OpenSBI reported `zicfiss` among the
   hart's extensions), observed:
   - Before any FWFT call, with `satp` Bare, `c.sspush ra` and `sspopchk ra` ran as no-ops, and
     reading `ssp` raised an illegal-instruction exception.
   - FWFT `GET` of `SHADOW_STACK` returned 0, `SET` to 1 returned success, and a second `GET`
     returned 1.
   - Under Sv39, with `ssp` at the top of an SS page: a matching `sspush` and `sspopchk` (both
     the 32-bit and the compressed push) left `ssp` where it started; a return address changed
     between them raised the software-check exception (cause 18) with `stval` 3 and left `ssp`
     unincremented; an ordinary store to the SS page raised a store/AMO access fault (cause 7);
     an ordinary load from it succeeded; a jump into it raised an instruction access fault.
   - The gap: with `ssp` on an ordinary readable and writable page, `sspush` stored and
     decremented `ssp` without a fault, and `sspopchk` raised the software-check exception
     instead of the store/AMO access fault the privileged specification requires. QEMU's page
     walk (`get_physical_address` in `target/riscv/cpu_helper.c` at v10.2.0, the same code in
     `target/riscv/tcg/cpu_helper.c` on its development branch) refuses a shadow-stack access
     only to a read-only page. Under TCG a test can therefore rely on the mismatch fault and on
     the protection of SS pages from ordinary stores, and not on the fault of a shadow-stack
     access outside an SS page.

   The program was not run on the QEMU 10.2 and OpenSBI v1.8 of the CI image; their sources
   were read as checks 2 and 3 cite them. QEMU 11.1.3 under TCG also refuses the x86-64
   `cet-ss` and `cet-ibt` CPU properties ("TCG doesn't support requested feature").
4. **Zicfiss is optional in RVA23.** The RVA23 profile text lists Zicfiss under RVA23U64
   Optional Extensions, Expansion Options, and states that RVA23S64 has the same unprivileged
   options as RVA23U64. It lists Zimop and Zcmop among the RVA23U64 mandatory extensions, which
   RVA23S64 includes.

Sources read: the CFI chapters of the RISC-V ISA manual (`src/unpriv/cfi.adoc` and
`src/priv/cfi.adoc` of `riscv/riscv-isa-manual`), the Firmware Features extension of the SBI
specification (`src/ext-firmware-features.adoc` of `riscv-non-isa/riscv-sbi-doc`), the RVA23
profile (`src/rva23-profile.adoc` of `riscv/riscv-profiles`), OpenSBI at tag v1.8, and QEMU's
`target/riscv` at tags v9.0.0, v9.1.0, v9.2.0 and v10.2.0 and on its development branch, each as
published in November 2026.

---

## Summarized By

[core/kernel/README.md](../README.md),
[Platform Requirements](../../../docs/platform-requirements.md)
