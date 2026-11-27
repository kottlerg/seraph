# Kernel Performance Counters

The kernel's side of the user performance counters a `PmuControl` capability governs
([docs/capability-model.md](../../../docs/capability-model.md) § `PmuControl`): each CPU
describes its counters at bring-up, `SYS_PMU_CONFIGURE` programs the calling CPU's user counters,
and `SYS_PMU_BIND` decides which threads read them directly from user mode. The calls' contracts
are in [syscalls.md](syscalls.md) § Performance Counter Syscalls; this document specifies the
mechanism behind them (`core/kernel/src/perfmon.rs`, the architecture halves
`arch/x86_64/pmu.rs` and `arch/riscv64/pmu.rs`, and the host-tested decode and encodings of
[shared/pmu](../../../shared/pmu/README.md)).

---

## Per-CPU state

Each CPU's `PerCpuData::pmu` (`perfmon::CpuPmu`) holds the word `armed`, 1 while the CPU has a
user configuration, what its counters offer (`pmu::Info`: the user counters, their width, the
events they count), the grant in effect on the CPU, and the architecture's state (which counters
the current configuration holds, and on x86-64 each event's encoding). Only the owning CPU reads
or writes it, with interrupts disabled: at bring-up, in a dispatch, at a return to user mode, and
in `SYS_PMU_CONFIGURE`. No lock guards it.

The description is taken on each CPU, by that CPU, at its bring-up (`perfmon::init_this_cpu`:
the boot CPU in Phase 5, each AP in its entry; [initialization.md](initialization.md)), because a
hybrid part's core types differ in what they count. Bring-up leaves every user counter stopped
at zero and no grant in effect. A riscv64 hart whose `hart_caps` lacks `HART_CAP_SSCOFPMF`
describes no counters. The boot CPU logs the description,
`pmu: counters=<n> width=<bits> events=<mask>`, or `pmu: no counters`.

---

## Counters

The user counters are the general-purpose counters a configuration takes, from the lowest up,
one per event. One counter of each CPU is the kernel's and no configuration takes it:

| Architecture | User counters | Kernel's counter | Read handle |
|---|---|---|---|
| x86-64, Intel (CPUID 0AH) | Every general-purpose counter, up to eight | Fixed counter 1 where the CPU has two fixed counters, else the highest general-purpose counter | The `RDPMC` index |
| x86-64, AMD family 17h and later | The core counters below the kernel's, at most six | The highest core counter | The `RDPMC` index |
| riscv64 (SBI PMU extension) | The programmable hardware counters (`hpmcounter3` and up) but the kernel's | The programmable counter of the highest CSR | The CSR's offset from `cycle` |

The layouts are `pmu::intel::Layout`, `pmu::amd::Perfmon::user` and `reserved`, and
`pmu::riscv::Layout`. The kernel's counter is the one a kernel-owned use (the NMI watchdog of
#1088) programs; this document's mechanism never touches it.

On x86-64 an event select names the event, its unit mask, the mode's `USR` and `OS` bits and `EN`,
never `INT`, `ANY`, `INV`, `EDGE` or a counter mask; the user counters' enables in the global
control (`IA32_PERF_GLOBAL_CTRL` on Intel version 2 and later, `PerfCntrGlobalCtl` on AMD with
PerfMonV2) are set at bring-up and left set. On riscv64 the firmware owns the selectors
(`mhpmevent`): a counter is claimed with `sbi_pmu_counter_config_matching`, over the free user
counters with the mode's inhibit flags alone, started at zero with `sbi_pmu_counter_start`, and
released with `sbi_pmu_counter_stop` and its reset flag. The events a hart counts are probed once at
bring-up, by claiming and releasing a counter for each. Counters are offered only when every hart
has Sscofpmf: without it the SBI PMU extension cannot filter a counter by privilege mode (OpenSBI
accepts and ignores the inhibit flags), so a user reader's counts would include the kernel's
execution, a disclosure channel, and the kernel reports no counters. Sscofpmf also gives the
overflow interrupt the kernel's reserved counter needs. On a hart with Smcntrpmf, OpenSBI answers
`Cycles` or `Instructions` with the fixed `cycle` or `instret` counter when no offered counter
counts it, after writing the request's inhibit flags into that counter's `mcyclecfg` or
`minstretcfg`. Such an answer is no claim (`pmu::riscv::claimed_index`): the claim flags never clear
or start a counter, so the fixed counter's value is untouched, and its filter is written back at
once to the one bring-up gives it, counting every mode but M-mode (`reset_fixed`).

A configuration replaces the CPU's previous one, whoever made it: its counters are stopped at
zero (released, on riscv64) before the new events are programmed. A configuration of no events
releases the CPU's user counters. A configuration that fails leaves the previous one in place on
x86-64, where every select is computed before any counter is touched; on riscv64 a counter that
no claim takes is found only while claiming, so the CPU is then left with no configuration.

---

## The grant

User mode reads the counters directly: `RDPMC` on x86-64, `csrr hpmcounterN` on riscv64. A
thread reads them only while it holds the grant, its `ThreadControlBlock::pmu_reader` flag, which
`SYS_PMU_BIND` sets and clears, and runs on a CPU with a user configuration: a CPU with none
grants no thread, so there a bound thread's read faults as an unbound one's. The grant is written
to the CPU as:

- x86-64: `CR4.PCE`, all-or-nothing, set for a reader and clear otherwise; a reader can `RDPMC`
  every counter `RDPMC` names, not only the configured ones. `cpu::enable_smep_smap` clears it
  with the other denied user controls on every CPU, so each starts from no grant.
- riscv64: `scounteren`, `interrupts::USER_COUNTERS` (`cycle` alone) for every thread, with the
  bits of the CPU's configured counters added for a reader.

An unbound read raises the CPU's fault (`#GP(0)` on x86-64, an illegal-instruction exception on
riscv64), which the kernel delivers as the thread's fault.

The grant in effect on a CPU follows the user thread that runs there. `CpuPmu` records which
grant is in effect, and a CPU writes the control only when the grant it applies differs:

- **Dispatch.** `sched::mark_dispatched`, which marks a thread `Running` on its CPU under the
  thread's `sched_lock`, tests the CPU's `armed` word (`perfmon::armed`, one GS- or
  `tp`-relative load). On a CPU with no user configuration, where no grant is in effect, the
  dispatch does nothing more: one per-CPU load and a not-taken branch. On a configured CPU it
  applies a user thread's flag (`perfmon::switch_in`, out of line), and a kernel thread leaves
  the grant as it is, since it never runs user code.
- **Bind.** `SYS_PMU_BIND` stores the flag under the target's `sched_lock`, and when the target
  is `Running` posts the return-work bit `PMU_GRANT` to its CPU in the same critical section,
  then prods that CPU (`sched::prod_remote_cpu`) after the unlock when it is not the caller's.
  The CPU's next return to user mode takes the bit and applies its running thread's flag
  (`perfmon::sync_grant`; [scheduling-internals.md](scheduling-internals.md) § Return Work).
  A dispatch before the store is followed by the post to its CPU, and one after it reads the new
  flag, so no interleaving leaves a running thread on a stale grant past that return.
  On a CPU with no user configuration the return applies no grant.
- **Configure.** `SYS_PMU_CONFIGURE` sets the `armed` word to whether the CPU holds a
  configuration after the call, and writes the caller's grant again, the flag applied only when it
  does, whether the call succeeded or not: on riscv64 the reader's bits are the configured
  counters', and a failed configuration there leaves none. A release therefore ends the grant in
  effect, and a configuration by a bound caller starts it.

A grant therefore holds, on a configured CPU, before the caller's next instruction when the
caller binds itself, from the target's first return to user mode after the prod reaches its CPU
when the target runs elsewhere, and from its next dispatch otherwise; and from the configuration
of the CPU a bound thread runs on. Revoking the `PmuControl` capability does not unbind: a binding
ends by `SYS_PMU_BIND` off or by the thread's exit.

---

## What a value means

A counter counts all work on its CPU in the configuration's mode, not one thread's: the kernel
neither saves nor restores counts across a switch. A value is valid while its reader stays on the
CPU that configured it, which is why `SYS_PMU_CONFIGURE` refuses a caller whose hard affinity
does not name the CPU it runs on. The cross-thread exposure this opens is classified in
[cross-boundary-disclosure.md](cross-boundary-disclosure.md): it is granted, by a capability,
to the measuring thread alone.

---

## Testing

- **Host tests** (`cargo xtask test`): `shared/pmu` decodes CPUID leaves 0AH, 1AH, 80000001H and
  80000022H, the SBI counter descriptions, the event tables per vendor and core type, the event
  selects and SBI flags per mode, the layouts, and the register packing; the kernel checks the
  `PerCpuData` layout.
- **ktest** `integration::pmu`: where the CPU has counters (riscv64 in CI, where QEMU's Sscofpmf
  gives the harts counters), the argument and capability refusals, every event the CPU reports and
  no other, an unbound read's fault, a bound thread's counted reads, a bound read's fault once the
  counters are released, and the revoke of a thread spinning alone on another CPU; where it has
  none (x86-64 in CI, under QEMU's TCG), the same refusals with `NotSupported` once a call reaches
  the counters, a configure, a release and a bind refused `NotSupported`, and an unbound read's
  fault.

---

## Summarized By

[core/kernel/README.md](../README.md), [Syscall Interface Specification](syscalls.md),
[Capability Model](../../../docs/capability-model.md),
[shared/pmu/README.md](../../../shared/pmu/README.md)
