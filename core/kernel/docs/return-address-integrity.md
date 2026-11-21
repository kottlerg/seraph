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

Implementation status: the x86-64 mechanism is implemented as § x86-64 Mechanism describes. The
riscv64 mechanism is not: every statement of riscv64 kernel behaviour in § Direction and § riscv64
Mechanism is design intent.

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
([docs/platform-requirements.md](../../../docs/platform-requirements.md) § Feature Classes). On
x86-64 a selected transient-execution control that rewrites a return takes precedence over the
feature (§ x86-64 Mechanism, Decision):

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
- x86-64 hardware with CET whose transient-execution selection rewrites a return gets none
  either. Among released parts that is AMD Zen 3, which reports `CET_SS` without Automatic IBRS
  (APM2 § 3.1.7) and so takes the retpoline sequence AMD recommends for it (AMD-SB-1036), and a
  guest whose hypervisor passes `CET_SS` but hides enhanced IBRS or Automatic IBRS. Intel's
  parts with `CET_SS` (Tiger Lake and later) enumerate enhanced IBRS, and AMD's from Zen 4
  Automatic IBRS, so they keep shadow stacks
  ([transient-execution.md](transient-execution.md) § Branch target injection). IBRS on entry,
  which an Intel part whose returns fall back to the branch target buffer takes in place of
  enhanced IBRS, and the IBPB on entry, which an AMD part takes for branch type confusion and
  speculative return stack overflow, rewrite no return and keep them.
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

  The kernel writes `senvcfg` whole with 0 on every hart
  (`cpu::disable_unswitched_user_state`), so `senvcfg.SSE` is clear: U-mode cannot access
  `ssp` and runs Zicfiss instructions as no-ops. `SYS_SBI_CALL` keeps refusing the FWFT
  extension (`syscall/sbi.rs`), since a forwarded FWFT call would reach this setting.
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

Implemented in `arch/x86_64/shadow_stack.rs`, with the context switch, the syscall path, and the
direct-map edits it relies on. The architectural facts are from the Intel SDM's CET chapter
(Volume 1, chapter 17) and its instruction pages for `RSTORSSP`, `SAVEPREVSSP`, `SETSSBSY`,
`CLRSSBSY`, `CALL`, `RET`, and `IRET`. The protection needs no compiler instrumentation, since
`CALL` and `RET` maintain the shadow stack (§ Options); the kernel image is the same with
shadow stacks on or off.

- **Decision.** In Phase 4 the boot CPU decides, once, that shadow stacks are on when it reports
  `CET_SS` (`CPUID.(EAX=7,ECX=0):ECX[7]`) and no transient-execution control the kernel selected
  in Phase 1 rewrites a return (`shadow_stack::decide`, `mitigation::Controls::rewrites_returns`),
  before any shadow-stack page is laid out. The maintainer decided that the mitigation of an
  enumerated vulnerability takes precedence over shadow stacks: a control whose code returns to
  an address the shadow stack does not hold would raise `#CP`, and the rule names such
  controls as a class, not one by one. The retpoline sequence is one: its `ret` goes to the
  branch target
  ([transient-execution.md](transient-execution.md) § Branch target injection). IBRS on entry
  is not: it writes `IA32_SPEC_CTRL` on entry and exit, and the entry routine's calls and
  returns pair up (transient-execution.md § Return predictions). The IBPB on entry is not
  either: the fill after it drops its calls' entries from both stacks together
  (transient-execution.md § IBPB on entry). Where the CPU
  reports `CET_SS` and the selection keeps shadow stacks off, `decide` logs it. They are on
  for every CPU or for none, since a thread migrates between CPUs with a
  live call chain: an AP that lacks `CET_SS` when the boot CPU has it halts the boot
  (`shadow_stack::prepare_ap`), and
  [docs/platform-requirements.md](../../../docs/platform-requirements.md) § x86-64
  Classification states the condition. The kernel does not read `CET_SSS`
  (`CPUID.(EAX=7,ECX=1):EDX[18]`), which says that the processor never marks a supervisor
  token busy before an event delivery completes. KVM does not report it to a guest, and the
  kernel enables shadow stacks without it, so under a hypervisor whose event delivery is
  interrupted midway a token can be left busy and the next delivery through it faults.
- **Shadow-stack memory.** Every shadow stack is one 4 KiB page, which holds 512 return
  addresses, and an event taken in ring 0 takes three words of it (below). A deeper chain runs
  into the page below, which faults for a Thread's and the idle thread's (an ordinary page there,
  to which no shadow-stack access is allowed).
  - Each Thread's is the last page of its retype slot (`sched/thread_slot.rs`), above its
    extended-state area, and the slot grows by one page while shadow stacks are on: the slot size
    a Thread retype debits, and `SystemInfoType::ThreadRetypeBytes`, include it.
  - Each CPU keeps three pages from the top of its idle-stack block's spare, directly below the
    guard page: the idle thread's shadow stack, lowest; the IST1 shadow stack (`#DF`, `#MC`),
    with the interrupt SSP table in the first eight words of its page; and the IST2 shadow
    stack (NMI). A shadow stack that outgrows its page runs on into the page below, where no
    fault stops it when that page is a shadow stack too; the idle thread's, which nests every
    interrupt taken while the CPU idles, is the lowest, so the page below it is never one of
    the three, and an IST stack holds one event.
  - The handoff stack's is one page the boot CPU takes from the buddy in Phase 5 and keeps.

  Each page's direct-map leaf has the shadow-stack encoding: present, not writable, dirty,
  supervisor, never executable (`PageTableEntry::new_shadow_stack_page`). Ordinary stores to it
  fault, and shadow-stack accesses succeed, since every table entry above the leaf is
  writable. The 2 MiB direct-map leaf is split first, from the guard-page reserve of
  `mm/stack_guard.rs` ([memory-internals.md](memory-internals.md) § Shadow-Stack Pages). A
  Thread's page gets the encoding in `stack_guard::hole`, under the same hold as its guard,
  and every online CPU drops its translation of the page before thread creation continues (a
  kernel-page shootdown), so no CPU keeps a writable alias of a live shadow stack. Thread
  destruction (`stack_guard::close`) maps the page read-write again and flushes only its own
  CPU: a CPU that kept the read-only translation and writes the page faults, and the page-fault
  handler's spurious-write retry (a supervisor write to a kernel-half page whose live leaf is
  present and writable) flushes the entry and re-executes the store. The per-CPU and handoff
  pages get the encoding while only the boot CPU runs, and keep it.
- **Tokens and the switch.** A fresh shadow stack whose top is `T` holds three words
  (`shadow_stack::fresh_words`): the supervisor token at `T - 8` (its own address, busy bit
  clear), the address the thread first runs at at `T - 16`, and a restore token at `T - 24`
  holding `(T - 16) | 1`. The thread's `SavedState` gains `ssp` (the address of the restore token
  its next switch-in restores from, `T - 24` for a fresh stack) and `ssp_token` (its supervisor
  token, `T - 8`). `context::switch` reads the outgoing shadow-stack pointer (`rdsspq`), stores
  the word below it in `current.ssp`, moves to the incoming stack through the restore token at
  `next.ssp` (`rstorssp`), leaves a restore token on the outgoing stack at that word
  (`saveprevssp`), and loads `IA32_PL0_SSP` with `next.ssp_token`, all before the outgoing
  thread's `context_saved = 1` publication, so a CPU that resumes it finds its restore token. It
  resumes the incoming thread with `ret`, so the shadow stack checks the resume address, where
  without shadow stacks it jumps. A switch whose outgoing and incoming states are the same thread
  (the scheduler's idle-to-idle fallback) leaves the shadow stack as it is: no restore token lies
  below the running SSP, so `rstorssp` would fault.
- **Enable.** `shadow_stack::enable` sets `IA32_S_CET.SH_STK_EN` and runs `setssbsy`, which
  takes the supervisor token `IA32_PL0_SSP` names, marks it busy, and starts an empty shadow
  stack below it; it returns by a jump, since that stack holds no copy of its return address.
  No frame that began before the enable may return after it, so it is called only from functions
  that never return:
  - The boot CPU enables in Phase 5, in `kernel_entry_post_rebase` after the tagged-TLB setup and
    before the SYSCALL MSRs and the timer, on the handoff shadow stack
    (`shadow_stack::prepare_boot_cpu` lays out its token, points `IA32_PL0_SSP` at it and
    `IA32_INTERRUPT_SSP_TABLE_ADDR` at the boot CPU's table, and sets `CR4.CET`). The GDT reload's
    far return precedes it. The kernel logs `shadow stacks: on`.
  - An AP enables in `kernel_entry_ap` before its SYSCALL MSRs, on its idle shadow stack, whose
    supervisor token `shadow_stack::prepare_ap` loads.
  - `sched::enter` loads `IA32_PL0_SSP` with init's token before init's first run, which is not
    a switch-in.
- **Kernel entry and exit.** An interrupt or exception from ring 3 loads the shadow-stack
  pointer from `IA32_PL0_SSP`, the running thread's supervisor token, and marks it busy, and the
  `IRET` back to ring 3 clears the busy bit. `SYSCALL` does neither: `syscall_entry` runs
  `setssbsy` once it is on the kernel stack, and the exit runs `clrssbsy` on the token at the
  shadow-stack pointer before `SYSRETQ`, with interrupts disabled from before the restores. An
  event taken in ring 0 pushes its `CS`, return address, and shadow-stack pointer to the shadow
  stack, and `IRET` checks them, so no handler may resume a ring-0 frame at a different address:
  a fault inside `copy_user` ends the copy in place (`rcx` 0, `rax` the bytes left) instead of
  moving `rip` to a fixup. `#DF`, `#MC` (IST1), and NMI (IST2) switch to the per-CPU IST shadow
  stack the interrupt SSP table names. User mode runs without shadow stacks: the kernel writes
  `IA32_U_CET` 0 on every CPU that has CET (`cpu::set_user_msr_controls`;
  [cross-boundary-disclosure.md](cross-boundary-disclosure.md) § User-mode hardware controls).
- **Faults.** A mismatch raises the control-protection fault (`#CP`, vector 21): error code 1
  for `RET`, 2 for `IRET`, 4 for `RSTORSSP`, 5 for `SETSSBSY`. It is a kernel fault and halts
  with the kernel exception report. Whenever `CR4.CET` is set, that report ends with the CPU's
  `IA32_S_CET`, interrupt SSP table address, and `IA32_PL0_SSP`, serial-only
  (`shadow_stack::report_registers`). The kernel writes a non-zero table address before it sets
  `CR4.CET`, and writes `IA32_S_CET` only in `shadow_stack::enable`, with `SH_STK_EN` set. A
  report with `CR4.CET` set, `SH_STK_EN` clear, and a zero table address therefore shows CET
  state lost outside the kernel, as on a host that is itself a guest of another hypervisor it
  can be lost at run time (§ Verification Record), while a kernel path that left `SH_STK_EN`
  clear on a CPU it armed shows a non-zero table address. Once `SH_STK_EN` is lost, the next
  `setssbsy` or `rstorssp` raises `#UD`.
- **Without CET.** `CR4.CET` stays clear and every shadow-stack instruction of the switch and
  the syscall path is skipped by a branch on `shadow_stack::ENABLED`. No page is kept or
  converted, and the Thread slot keeps its size.
- **Test.** `cargo xtask test cet` ([docs/testing.md](../../../docs/testing.md) § CET shadow
  stacks (`cet` case)) boots the kernel under KVM with `-cpu host,cet-ss=on,enforce`. ktest must
  pass with `shadow stacks: on`, and a return address of `syscall::dispatch` that the host
  overwrites through QEMU's gdbstub must raise `#CP` with error code 1. The kernel carries no test
  code for it. QEMU refuses to start where KVM cannot give the guest `CET_SS`, and the command then
  fails, naming the feature. A boot whose exception report shows the CET state lost outside the
  kernel, as the Faults item above describes, is inconclusive on a host that is itself a guest, by
  the CPUID hypervisor bit, and is run again, up to four runs, passing only on a run without it; on
  any other host it fails. The host tests of `shadow_stack.rs` model `RSTORSSP`, `SAVEPREVSSP`,
  `CALL`, and `RET` over the token layout.

---

## Verification Record

The four facts the riscv64 implementation depends on (checks 1 to 4), and the x86-64
mechanism on hardware (check 5), each verified as stated. Probes were
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
5. **KVM gives a guest supervisor shadow stacks, and the x86-64 mechanism enforces them.**
   `cargo xtask test cet` ([docs/testing.md](../../../docs/testing.md) § CET shadow stacks (`cet`
   case)) ran
   at 4 vCPUs under KVM with QEMU 11.1.3 on a CET-capable Intel part, on a host that is itself a
   guest of another hypervisor (nested virtualization). With `-cpu host,cet-ss=on,enforce` QEMU
   started, the kernel printed `shadow stacks: on`, and ktest passed. In a second boot, a return
   address of `syscall::dispatch` overwritten on the ordinary stack through QEMU's gdbstub raised
   `#CP` with error code 1 (`NEAR-RET`) at the first attempt.
6. **On a host that is itself a guest, a guest's CET state can be lost at run time.** On that
   host, 8 of 47 x86_64 ktest boots at 4 vCPUs on shadow stacks, the `cet` case's first boot among
   them, ended in a kernel `#UD` at `setssbsy` or `rstorssp`. Each report showed `CR4.CET` set,
   `SH_STK_EN` clear, and the interrupt SSP table address 0. The kernel writes `IA32_S_CET` and
   that address once per CPU and never with 0 (§ x86-64 Mechanism, Faults), so the state was
   lost outside the kernel, and the `cet` case counts such a boot as inconclusive on a host that is
   itself a guest (§ x86-64 Mechanism, Test). The kernel has not run on shadow stacks on a host
   that is not a guest ([#1160](https://github.com/kottlerg/seraph/issues/1160)).

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
