# Transient Execution

Specifies the x86-64 vulnerability table, for the running CPU the exposure of each
transient-execution class at the user-to-kernel boundary, derived at boot from CPUID,
`IA32_ARCH_CAPABILITIES` and the vendors' published guidance, and the user-to-kernel controls the
kernel selects from it.

---

## Scope

The kernel defends the user-to-kernel boundary against every transient-execution class, always,
and selects each defence that only some CPUs need by enumerating the running CPU
([docs/capability-model.md](../../../docs/capability-model.md) § Microarchitectural Isolation).
The vulnerability table is that enumeration. It is computed once, on the boot CPU, in Phase 1
after the baseline check (`speculation::select_mitigations`), and written to the serial log
(§ Report).

The table states what each class asks of the kernel at the user-to-kernel boundary, and the
kernel applies the controls it selects there: buffer clearing on return to user mode, the
branch-predictor controls, IBRS on entry for `retbleed` on an Intel part without enhanced IBRS,
an IBPB on entry for `retbleed` on an AMD part (branch type confusion) and for
`spec_rstack_overflow`, and the return stack buffer fills (§ Controls). A class with kernel
action that the selection leaves open, for want of a control, of an IBPB, of an IBPB that flushes
branch types, or of STIBP while SMT is on, is reported as vulnerable on the serial log
(§ Report).

RISC-V has no counterpart. The RVA23 floor defines no enumeration of transient-execution
vulnerabilities and no speculation control, so `speculation::select_mitigations` does nothing
on riscv64.

The table's code is `arch/x86_64/vulnerability.rs`: `read` collects the inputs through a CPUID
and an MSR accessor, `derive` maps them to a `VulnerabilityTable` as a pure function of them,
and `report` logs both. `read` and `derive` are host-tested (§ Validation). The controls' code
is `arch/x86_64/mitigation.rs` (§ Controls).

---

## Exposure

Each class takes one of four exposures. They are ordered as listed: where two rules give a class
different exposures, the table keeps the greater, unless a rule below lowers it explicitly.

| Exposure | Log heading | Meaning |
|---|---|---|
| `NotAffected` | `not affected` | The vendor states the CPU is not affected, or the CPU enumerates that it is not |
| `OtherBoundary` | `affected, not at user-to-kernel` | Affected, but the vendor confines the class to other boundaries (VM entry and exit, an IBPB, one process to another), or prescribes no kernel action at user-to-kernel |
| `Firmware` | `affected, mitigated by firmware` | Affected at user-to-kernel; the vendor's mitigation is the silicon, its microcode or the platform firmware alone |
| `Kernel` | `affected, kernel action` | Affected at user-to-kernel, and the vendor's mitigation needs the kernel to act, or no rule establishes otherwise |

A class no rule speaks for is `Kernel`: the table never assumes a CPU safe without a vendor
statement or an enumerated bit.

---

## Classes

The table reports eighteen classes, each named as the Linux kernel's vulnerability report names
it, so that the serial log and a Linux host's `/sys/devices/system/cpu/vulnerabilities` can be
compared class by class. The Intel column is the CVE by which the derivation finds the class's
column in Intel's list (§ Intel).

| Class | Log name | Intel list column (CVE) | AMD source |
|---|---|---|---|
| Bounds check bypass (Spectre v1) | `spectre_v1` | CVE-2017-5753 | AMD's 2018 statements, STMS |
| `swapgs` variant | `swapgs` | CVE-2019-1125 | Not affected (AMD statement of 2019-08-06) |
| Branch target injection (Spectre v2) | `spectre_v2` | CVE-2017-5715 | AMD's 2018 statements, STMS |
| Branch history injection | `bhi` | CVE-2022-0001 | Not affected (AMD-SB-7018) |
| Speculative store bypass | `spec_store_bypass` | CVE-2018-3639 | Family 15h onward (AMD's 2018 SSB statement) |
| Rogue data cache load (Meltdown) | `meltdown` | CVE-2017-5754 | Not affected (AMD's 2018 statements) |
| L1 terminal fault | `l1tf` | CVE-2018-3620 | Not affected (AMD's 2018 statement) |
| Microarchitectural data sampling | `mds` | CVE-2018-12126, -12127, -12130 | Not affected (AMD's 2019 statement, SBAMA) |
| TSX asynchronous abort | `tsx_async_abort` | CVE-2019-11135 | Not affected: AMD64 defines no TSX |
| Processor MMIO stale data | `mmio_stale_data` | CVE-2022-21125, -21166 | Not affected (no AMD claim; inferred) |
| Special register buffer data sampling | `srbds` | CVE-2020-0543 | Not affected (no AMD claim; inferred) |
| Gather data sampling | `gather_data_sampling` | CVE-2022-40982 | Not affected (no AMD claim; inferred) |
| Register file data sampling | `reg_file_data_sampling` | CVE-2023-28746 | Not affected (no AMD claim; inferred) |
| RSB alternate behaviour (Intel), branch type confusion (AMD) | `retbleed` | CVE-2022-29901 | BTC-TG, AMD-SB-1037 |
| Post-barrier RSB predictions | `eibrs_pbrsb` | CVE-2022-26373 | Not affected (no AMD claim; inferred) |
| Indirect target selection | `indirect_target_selection` | CVE-2024-28956 | Not affected (inferred from AMD-SB-7034) |
| Speculative return stack overflow | `spec_rstack_overflow` | none: not affected | AMD-SB-7005, SRSO-WP |
| Transient scheduler attacks | `tsa` | none: not affected | AMD-SB-7029, AMD-SB-7073, TSA-TG |

"Inferred" marks an Intel-named class for which no AMD document makes a claim either way. The
table reads such a class as not affected on AMD parts because each is defined by an Intel
microarchitectural structure, enumeration bit or predictor mode that AMD64 does not define. This
is the one place the table relies on an inference instead of a vendor statement.

### Excluded classes

These are not in the table, for the reason given:

- **Classes with no user-to-kernel exposure.** `itlb_multihit` (a guest attacking a VMM),
  `vmscape` (a guest attacking the host's user space), `spectre_v2_user` (one process attacking
  another), and the SGX-only classes, including load value injection, which Intel states is not a
  practical exploit outside SGX.
- **Classes with no OS action and no enumeration.** Branch privilege injection (CVE-2024-45332,
  INTEL-SA-01247) is mitigated by microcode alone. Zero-at-ret (CVE-2026-20917, INTEL-SA-01423)
  needs a privileged adversary in ring 0 and is mitigated by firmware alone.
- **Linux report entries that are not classes.** `old_microcode`, `ghostwrite` (a RISC-V
  implementation defect), and `ibpb_no_ret`, an IBPB property that the table records as the
  `ibpb_leaves_rsb` behaviour (§ Predictor behaviours).
- **Classes subsumed by a reported one, or mitigated by microcode.** Spectre v3a (rogue system
  register read) is mitigated by microcode alone. Intra-mode branch target injection is part of
  `bhi`. Restricted RSB alternate behaviour (RRSBA) keeps alternate return predictions within
  the current predictor mode while enhanced IBRS is on (Intel's RSBU guidance), and the table
  records it as the `rsb_alternate` behaviour (§ Predictor behaviours).
- **Classes the kernel's design excludes.** Lazy FP state restore (CVE-2018-3665,
  INTEL-SA-00145) reads, under speculation, the FPU, SIMD and vector registers of another thread
  that a lazy switch left in place. No thread runs on registers that hold another thread's
  state: on x86-64 the switch-in of a thread loads its own state, and on RISC-V the switch-in of
  a thread that has not used F, D or V clears the registers before it runs with the units off
  ([scheduler.md](scheduler.md) § What Gets Saved and Restored).

---

## Inputs

`read` takes the inputs below, each zero where the CPU does not implement it. It reads no CPUID
leaf above the maximum basic or extended leaf, and no sub-leaf of leaf 07H above that leaf's
maximum, since such a leaf returns another leaf's data. It reads `IA32_ARCH_CAPABILITIES` (MSR
10AH) only when `CPUID.(EAX=07H,ECX=0):EDX[29]` enumerates it, since an absent MSR faults.

| Input | Read for |
|---|---|
| `CPUID.00H` EBX, EDX, ECX | Vendor string: `GenuineIntel`, `AuthenticAMD`, other |
| `CPUID.01H:EAX` | Family, model and stepping, with the extended fields as Intel SDM Vol. 2A and the AMD PPRs define them |
| `CPUID.(EAX=07H,ECX=0):EBX` | HLE (bit 4) and RTM (bit 11): TSX is present |
| `CPUID.(EAX=07H,ECX=0):EDX` | `MD_CLEAR` (bit 10); hybrid (bit 15); IBRS and IBPB (bit 26); STIBP (bit 27); `IA32_ARCH_CAPABILITIES` implemented (bit 29) |
| `CPUID.(EAX=0BH,ECX=0)` | A vendor other than AMD: SMT is on when the level type (`ECX[15:8]`) is SMT and the level counts more than one logical processor (`EBX[15:0]`) |
| `CPUID.(EAX=07H,ECX=2):EDX` | `BHI_CTRL` (bit 4) |
| `CPUID Fn8000_0001 ECX` | AMD: `TopologyExtensions` (bit 22), which enumerates `Fn8000_001E` |
| `CPUID Fn8000_0008 EBX` | IBPB (bit 12), STIBP (bit 15); AMD: `SsbdNotRequired` (bit 26), `BTC_NO` (bit 29), `IBPB_RET` (bit 30) |
| `CPUID Fn8000_001E EBX` | AMD: SMT is on when the threads per core, less one (bits 15:8), are not zero |
| `CPUID Fn8000_0021 EAX` | AMD: `LfenceAlwaysSerializing` (bit 2), `VERW_CLEAR` (bit 5), Automatic IBRS (bit 8), `SBPB` (bit 27), `IBPB_BRTYPE` (bit 28), `SRSO_NO` (bit 29), `SRSO_USER_KERNEL_NO` (bit 30) |
| `CPUID Fn8000_0021 ECX` | AMD: `TSA_SQ_NO` (bit 1), `TSA_L1_NO` (bit 2), `TSA_FILL_NO` (bit 7) |
| `IA32_ARCH_CAPABILITIES` | The `*_NO` bits, `RSBA`, `TSX_CTRL` and `RFDS_CLEAR` (§ Enumerated bits); `RRSBA` (§ Predictor behaviours); `IBRS_ALL` (bit 1) and `DOITM` (bit 12) (§ Controls) |

On an AMD Family 19h part that enumerates IBPB and neither `SBPB` nor `IBPB_BRTYPE`, `read` also
probes for the microcode of AMD-SB-7005, which makes an IBPB flush every branch type and adds
`SBPB` (bit 7 of `IA32_PRED_CMD`, MSR 49H) without enumerating either on every part (SRSO-WP). It
writes `SBPB` to `IA32_PRED_CMD`: the write completes where the microcode implements the bit, and
raises `#GP` where it does not, as a write of a reserved bit does. The write recovers from the
fault (`idt::msr_recovering`). For the one instruction, the CPU runs on a probe table built on the
stack, whose `#GP` gate resumes at a label after the `wrmsr` and whose other gates are the kernel's
where the kernel's table is the one loaded; the table loaded before is loaded again after. The
gate's delivery reads the kernel's code-segment descriptor, so the boot CPU loads the kernel's
segment descriptors first, in Phase 1 ([initialization.md](initialization.md) § Phase 1): the
firmware's GDT lies in memory the kernel's page tables do not map. The probe runs with interrupts
off and before shadow stacks are on, since the gate resumes at an address other than the one the
CPU saved, which a shadow stack would refuse. A completed write runs a branch predictor barrier,
which changes no architectural state. The result is the `sbpb_accepted` field of the first report
line (§ Report).

The table and the selection are made from the boot CPU's inputs. Intel states that the RFDS bits
enumerate identically on every logical processor of a hybrid part. No vendor document found
states the same for every bit the table reads, so each AP reads its own inputs before it sets
an MSR control and halts the boot when it does not enumerate one the boot CPU selected
(§ Controls).

---

## Derivation

`derive` applies five steps in order: the vendor's per-model table, the
`IA32_ARCH_CAPABILITIES` bits, AMD's CPUID bits (AMD parts only), the boundary rules, then the
predictor behaviours.

### Intel

The per-model table is Intel's machine-readable affected-processor list, the form Intel
publishes of its consolidated table "Affected Processors: Transient Execution Attacks & Related
Security Issues by CPU". It is vendored verbatim and compiled into the kernel
([vendor/intel-affected-processor-list](../vendor/intel-affected-processor-list/README.md)).

- **Rows.** A row lists the CPU when its family and model are the CPU's and its stepping column
  names the CPU's stepping or reads `All`. Where the list holds rows for both core-type
  compositions of one model and stepping (Alder Lake S stepping 5, hybrid, and Catlow, its
  P-core-only form), the rows whose `CPUID.07H.0:EDX[15]` condition the CPU contradicts are
  dropped, unless that drops every row: a hypervisor can hide the bit, and firmware that disables
  a hybrid part's E-cores clears it. Intel states that P-core-only parts may be unaffected by RFDS
  where the hybrid parts of the same signature are affected.
- **Columns.** A column belongs to a class when its header names that class's CVE (§ Classes).
  Indirect target selection has three columns with one CVE, told apart by the variant the header
  names. Only the cBPF variant reaches the kernel from user mode, through kernel direct branches
  in the same predictor mode. The IBPB variant crosses an IBPB between processes, and the
  guest-host variant is a VMM's. Their columns give at most `OtherBoundary`. The RRSBA column
  (CVE-2022-28693) is not a class: a CPU that a row lists with a status other than
  `Not Affected` in it has the `rsb_alternate` behaviour (§ Predictor behaviours).
- **Cells.** `Not Affected` is `NotAffected`. A status that names software (`Software`,
  `MCU+Software`, `Hardware+Software`, `MCU_BIOS+Software`) is `Kernel`. A status of microcode,
  hardware or BIOS alone (`MCU`, `Hardware+MCU`, `MCU_BIOS+BIOS`) is `Firmware`. Any other status
  (`No planned mitigation`) is `Kernel`.
- **Combination.** A class takes the greatest exposure of the rows that list the CPU.
- **Unlisted.** A model no row lists, and a class no column covers, is `Kernel`. Intel states
  that a processor past its End of Servicing Lifetime may not be listed.
- **AMD classes.** `spec_rstack_overflow` and `tsa` are `NotAffected`: both are AMD
  microarchitecture defects.

### AMD

AMD publishes no machine-readable list, so the per-family table is taken from AMD's bulletins and
technical guidance:

- `spectre_v1` and `spectre_v2`: `Kernel` on every family.
- `spec_store_bypass`: affected on Family 15h and later (AMD's 2018 SSB statement, AMD's SSBD
  white paper), then capped by the boundary rules.
- `retbleed` (branch type confusion): `Kernel` on every family but 19h. BTC-TG states that
  Family 19h is not affected and does not set `BTC_NO`. BTC-TG lists Families 15h and 17h as
  affected, and AMD gives no statement on older parts.
- `spec_rstack_overflow`: `Kernel` on every family. AMD-SB-7005 covers Zen to Zen 4, and later
  parts are judged by their bits.
- `tsa`: `Kernel` on Family 19h and later. TSA-TG states that older families are not affected
  and do not set the bits. Family 1Ah was added in TSA-TG Rev. 3.0.
- Every other class: `NotAffected`, per the AMD source column of § Classes.

### Other vendors

Every class is `Kernel`, then refined by the enumerated bits and the boundary rules.

### Enumerated bits

The `IA32_ARCH_CAPABILITIES` bits mean the same wherever the MSR is implemented, and a hypervisor
may implement it on any vendor, so they apply to every vendor. A `*_NO` bit sets its class to
`NotAffected`:

| Bit | Name | Class |
|---|---|---|
| 0 | `RDCL_NO` | `meltdown`, `l1tf` |
| 4 | `SSB_NO` | `spec_store_bypass` |
| 5 | `MDS_NO` | `mds` |
| 8 | `TAA_NO` | `tsx_async_abort` |
| 13, 14, 15 | `SBDR_SSDP_NO`, `FBSDP_NO`, `PSDP_NO`, all three | `mmio_stale_data` |
| 20 | `BHI_NO` | `bhi` |
| 24 | `PBRSB_NO` | `eibrs_pbrsb` |
| 26 | `GDS_NO` | `gather_data_sampling` |
| 27 | `RFDS_NO` | `reg_file_data_sampling` |
| 62 | `ITS_NO` | `indirect_target_selection` (set by a hypervisor only) |

Then:

- `RFDS_CLEAR` (bit 28) without `RFDS_NO` raises `reg_file_data_sampling` to `Kernel`.
- `RSBA` (bit 2) raises `retbleed` to `Kernel`. A hypervisor sets it for a guest that may run on
  an affected part.
- A CPU with neither RTM, HLE nor `TSX_CTRL` (bit 7) has no TSX, and `tsx_async_abort` is
  `NotAffected` (Intel's TAA guidance).
- `BHI_CTRL` sets `indirect_target_selection` to `NotAffected`. Intel states that parts from
  Alder Lake and Sapphire Rapids onward are not affected, and its check for a guest treats a CPU
  that enumerates `BHI_CTRL` as not affected.

On AMD parts:

- `SsbdNotRequired` sets `spec_store_bypass` to `NotAffected`.
- `BTC_NO` sets `retbleed` to `NotAffected`.
- `SRSO_NO` sets `spec_rstack_overflow` to `NotAffected`. Otherwise `SRSO_USER_KERNEL_NO` caps
  it at `OtherBoundary`: SRSO-WP states that such a part is not affected across the user/kernel
  boundary but may be across others.
- `TSA_SQ_NO` and `TSA_L1_NO` together set `tsa` to `NotAffected` on Family 19h. On later
  families `TSA_FILL_NO` is also needed. TSA-TG states that Family 19h is not affected by
  TSA-FILL and does not set `TSA_FILL_NO`.

### Boundary rules

The last step lowers each class to the boundary its vendor confines it to:

- **`spec_store_bypass`: at most `OtherBoundary`.** The kernel does not set SSBD while it runs.
  Intel does not recommend SSBD for operating systems, is not aware of a practical exploit
  against one, and asks the OS for a per-process opt-in instead (Intel's SSB guidance). AMD
  recommends the default setting, which keeps memory disambiguation, and states that the
  bypassed value is "within the context and privilege level of the current program" (AMD's SSBD
  white paper). A per-process opt-in defends one process against another, which
  [capability-model.md](../../../docs/capability-model.md) § Microarchitectural Isolation does
  not provide.
- **`eibrs_pbrsb`: at most `OtherBoundary`.** Intel defines post-barrier RSB predictions only
  across an RSB barrier, which is an IBPB or a VM exit with IBRS set (Intel's PBRSB guidance).
- **`srbds`: at most `Firmware`.** The microcode enables the mitigation by default. The only OS
  action Intel prescribes is to turn it off on parts where TSX is disabled.
- **`mmio_stale_data`: at most `OtherBoundary`, unless `mds` or `tsx_async_abort` is `Kernel`.**
  Intel's decision rule: a part also affected by MDS or TAA clears CPU buffers before returning to
  untrusted software, as for MDS. Any other part clears them only before a VM entry, for an
  attacker with MMIO access, which only a VMM gives.

### Predictor behaviours

Beside the classes, the table records three behaviours of the return predictions and the IBPB.
Each is a property of the predictors, not a class of its own. The first two select where the
kernel fills the return stack buffer (RSB), and the third whether an IBPB answers `retbleed` on
an AMD part and `spec_rstack_overflow` (§ Controls). A CPU of another vendor has all three.

| Behaviour | Log name | Meaning | Intel | AMD |
|---|---|---|---|---|
| `IbpbLeavesRsb` | `ibpb_leaves_rsb` | An IBPB does not keep a `RET` after it from being predicted by an RSB entry created before it | `eibrs_pbrsb` is not `NotAffected`: Intel defines post-barrier RSB predictions across an IBPB as well as a VM exit | No `IBPB_RET` (`CPUID Fn8000_0008 EBX[30]`): AMD-SB-1040 states that an IBPB may not prevent return predictions from pre-IBPB targets on Zen to Zen 3 |
| `RsbAlternate` | `rsb_alternate` | A `RET` that finds the RSB empty may be predicted by an alternate predictor, such as the branch target buffer | `retbleed` is not `NotAffected` (the list's RSBA column, or `RSBA`), the list's RRSBA column gives it (§ Intel), or `IA32_ARCH_CAPABILITIES.RRSBA` (bit 19) | No part: AMD states that its processors do not put `RET`-based predictions in BTB-type structures (STMS, mitigation V2-1) |
| `IbpbLeavesBranchType` | `ibpb_leaves_brtype` | An IBPB does not flush the branch type predictions that branch type confusion and speculative return stack overflow train | No part: both classes are AMD's | Every part but these: one that enumerates `SRSO_NO` or `IBPB_BRTYPE` (`CPUID Fn8000_0021 EAX[29]`, `EAX[28]`); Family 15h and 17h, whose IBPB flushes every branch type, so that SRSO-WP treats them as `IBPB_BRTYPE`; and Family 19h with the microcode of AMD-SB-7005, which enumerates `SBPB` (`EAX[27]`) or accepts the `SBPB` probe (§ Inputs) |

The behaviours select a fill after an IBPB the kernel issues and on a context switch in the
retpoline build. Neither selects a fill on entry from user mode. Intel states that an RSB
overwrite after a transition from user mode to supervisor mode is not necessary when SMEP is
enabled, which the kernel does, and that on parts with enhanced IBRS, SMEP prevents user-mode RSB
entries from being used in supervisor mode (Intel's mitigation overview). AMD names an RSB
stuffing sequence (STMS, mitigation V2-3) and SMEP as alternative ways to protect the return
address predictor (BTC-TG).

---

## Controls

The kernel selects the user-to-kernel controls from the table once, on the boot CPU in Phase 1
(`speculation::select_mitigations`), before any AP starts or any thread enters user mode. The
selection is `mitigation::select`, a pure function of the inputs below; `mitigation::install`
publishes it, and every CPU sets the per-CPU controls of it in its bring-up
(`speculation::apply_mitigations_this_cpu`: the boot CPU in Phase 1, each AP in
`kernel_entry_ap`). A CPU that does not enumerate an MSR control the selection holds
(`IBRS_ALL`, IBRS for IBRS on entry, Automatic IBRS, `BHI_CTRL`, `DOITM`, IBPB for the IBPB on
entry, or STIBP) halts with "CPU lacks the <control> the boot CPU selected"
(`mitigation::missing_msr_control`) before it touches the MSR, since the access would fault.
The code is `arch/x86_64/mitigation.rs`.

### Selection

The inputs are the classes the table gives `Kernel` exposure, the three predictor behaviours,
whether SMT is on (§ Inputs), and seven enumerated bits: `IBRS_ALL` (`IA32_ARCH_CAPABILITIES`
bit 1), IBRS (`CPUID.(EAX=07H,ECX=0):EDX[26]`, read on an Intel part only: another vendor's
`retbleed` may be branch type confusion, which IBRS does not answer), Automatic IBRS
(`CPUID Fn8000_0021 EAX[8]`, AMD), `BHI_CTRL`, `DOITM` (`IA32_ARCH_CAPABILITIES` bit 12), IBPB
(`CPUID Fn8000_0008 EBX[12]` or `CPUID.(EAX=07H,ECX=0):EDX[26]`), and STIBP (`EBX[15]` or
`EDX[27]` of the same leaves). A kernel built to force the return mitigations replaces some of
them (§ Forced return mitigations).

| Control | Log name | Selected when | Where it acts |
|---|---|---|---|
| Enhanced IBRS | `eibrs` | `spectre_v2` is `Kernel`, or `retbleed` is `Kernel` and the CPU has `rsb_alternate`; and the CPU enumerates `IBRS_ALL` | `IA32_SPEC_CTRL.IBRS` set once on every CPU |
| IBRS on entry | `ibrs_entry` | `retbleed` is `Kernel`, the CPU has `rsb_alternate`, no `IBRS_ALL`, and the CPU enumerates IBRS | `IA32_SPEC_CTRL.IBRS` set on every entry from user mode and cleared on every return to it |
| Automatic IBRS | `auto_ibrs` | `spectre_v2` is `Kernel`, neither of the two above, and the CPU enumerates Automatic IBRS | `EFER.AIBRSE` (bit 21) set on every CPU |
| Retpoline | `retpoline` | `spectre_v2` is `Kernel`, with none of the three | Every indirect call and jump of the kernel |
| `BHI_DIS_S` | `bhi_dis_s` | `bhi` is `Kernel` and the CPU enumerates `BHI_CTRL` | `IA32_SPEC_CTRL.BHI_DIS_S` (bit 10) set on every CPU |
| Branch history clearing | `bhb_clear` | `bhi` is `Kernel`, without `BHI_CTRL` | Every entry from user mode |
| `VERW` on exit | `verw_exit` | `mds`, `tsx_async_abort`, `mmio_stale_data`, `reg_file_data_sampling` or `tsa` is `Kernel` | Every return to user mode |
| `VERW` before idle | `verw_idle` | `mds` or `tsa` is `Kernel` | Before the idle loop's `hlt` |
| RSB fill on switch | `rsb_fill_switch` | Retpoline is selected and the CPU has `rsb_alternate` | Every context switch |
| RSB fill after IBPB | `rsb_fill_ibpb` | The CPU has `ibpb_leaves_rsb` | After every IBPB the kernel issues |
| `DOITM` | `doitm` | The CPU enumerates `DOITM` | `IA32_UARCH_MISC_CTL.DOITM` (MSR 1B01H, bit 0) set on every CPU |
| IBPB on entry | `ibpb_entry` | `retbleed` is `Kernel` without `rsb_alternate` (branch type confusion), or `spec_rstack_overflow` is `Kernel`; and the CPU enumerates IBPB and has no `ibpb_leaves_brtype` | `IA32_PRED_CMD.IBPB` (MSR 49H, bit 0) written on every entry from user mode |
| STIBP | `stibp` | IBPB on entry is selected and the CPU enumerates STIBP | `IA32_SPEC_CTRL.STIBP` (bit 1) set on every CPU |

The host tests in `mitigation.rs` cover each rule, and the selection for the parts of
§ Validation (§ Validation). `SYS_SYSTEM_INFO(SpeculationControls)` reports the inputs, the
selection and the controls in effect on the calling CPU
([syscalls.md](syscalls.md) § `SYS_SYSTEM_INFO`).

### Branch target injection

Enhanced IBRS keeps predictions trained in user mode from steering the kernel's indirect branches
while `IA32_SPEC_CTRL.IBRS` stays set, so the kernel sets it once per CPU and never clears it
(Intel's eIBRS guidance). Automatic IBRS is AMD's counterpart: with `EFER.AIBRSE` set, the CPU
applies IBRS protection to CPL 0 without a write on each entry (APM2 § 3.1.7). Otherwise the
kernel takes the retpoline sequence (Intel's retpoline white paper), which AMD recommends in
place of its earlier `lfence`/`jmp` sequence (AMD-SB-1036).

The kernel is built with every indirect branch through a thunk: `cargo xtask build` passes
`-Zretpoline-external-thunk` to the x86-64 kernel and its `-Z build-std` crates
([docs/build-system.md](../../../docs/build-system.md) § Custom Targets), which sends each
indirect call and jump the compiler emits to `__x86_indirect_thunk_r11` and lowers no `match` to
a jump table. The kernel's thunk tests a flag that `install` sets. With retpoline selected it
runs the sequence: a `call` whose return the RSB predicts into a `pause; lfence` loop, and a
`ret` to the target. Otherwise it runs `lfence; jmp r11`, where the `lfence` keeps a
mispredicted test of the flag from reaching the plain jump on a part that needs the sequence. The
assembly stubs have three indirect branches of their own. `switch`'s resume without shadow
stacks goes through the thunk. `shadow_stack::enable` ends in a plain `jmp r11` to its caller,
outside the thunk: it runs only where shadow stacks turn on, which `shadow_stack::decide` allows
only when retpoline is not selected (below), so the jump never needs the sequence. The AP
trampoline's long-mode relay (`ap_trampoline.rs`) ends in a plain `jmp rax` to the AP's entry
function, outside the thunk: it runs once per AP, in Phase 8, before any thread has entered user
mode on any CPU, so no prediction user mode trained can steer it.

The cost of the thunk where retpoline is not selected (a call, a compare and an `lfence` per
indirect branch) is not measured.

The retpoline sequence and CET supervisor shadow stacks exclude each other: the sequence's `ret`
goes to an address the shadow stack does not hold, which raises `#CP` (Intel SDM Vol. 1, CET
shadow stacks), and Intel states that retpoline is incompatible with CET shadow stacks (Intel's
BHI guidance). Intel's parts with `CET_SS` (Tiger Lake and later) also enumerate `IBRS_ALL`, and
AMD's parts from Zen 4 enumerate Automatic IBRS, so among released parts the conflict reaches AMD
Zen 3, which has `CET_SS` without Automatic IBRS, and a guest whose hypervisor hides `IBRS_ALL`
or Automatic IBRS but passes `CET_SS`. On such a CPU the kernel runs without shadow stacks: the
mitigation takes precedence, and `shadow_stack::decide` turns them on only when no selected
control rewrites a return
([return-address-integrity.md](return-address-integrity.md) § x86-64 Mechanism). No such part
is in the project's reach to boot ([#1123](https://github.com/kottlerg/seraph/issues/1123)); the
host tests of `mitigation.rs` cover the rule over the Zen 3, Zen 4 and development-host vectors.

### Return predictions

On an Intel part with `rsb_alternate` (Skylake-generation parts, the list's RSBA column), a `ret`
that finds the RSB empty may be predicted from the branch target buffer, which user mode can
train. Intel states that IBRS mitigates this behaviour and the retpoline sequence does not, and
that the operating system should set IBRS after the transition from a less privileged mode
(Intel's RSBU guidance). Where such a part has no enhanced IBRS but implements IBRS, the kernel
selects IBRS on entry. Enhanced IBRS covers the case where the part has it.

The entry routine, `seraph_enter_from_user`, runs on every entry from user mode before any
indirect branch and any `ret` its own `call` does not pair: in `syscall_entry` after the frame
is saved, in every exception and interrupt trampoline that builds a `TrapFrame`
(`enter_from_user_asm`, keyed on the saved CS). Each runs it after the
entry's `cld`, `clac` and swap to the kernel GS base, a paranoid stub after its
`paranoid_entry_asm`. With IBRS on entry selected it first writes
`IA32_SPEC_CTRL` with the kernel's value, `IBRS` set; with the IBPB on entry selected it then
issues the IBPB (§ IBPB on entry). It ends in `lfence`, so no later instruction runs before the
writes complete. Every return to user mode writes the user-mode
value, the same without `IBRS` (`mitigation::ibrs_exit_asm`), with interrupts off and after the
last kernel `call`, `ret` and indirect branch: in `syscall_entry` before `sysretq`, in
`tf_resume_asm` when the frame's CS is ring 3, and in `return_to_user` and
`switch_and_enter_user`. The paranoid stubs (NMI, `#DB`, `#DF`, `#MC`) can arrive between a
return's write and its `sysretq` or `iretq`, or before an entry's write, so they save the
interrupted value and write the kernel's on entry, and on exit write the user-mode value when
they return to ring 3 and the saved one otherwise. Under this control the kernel owns the whole
MSR: both values are the selection's `IA32_SPEC_CTRL` bits (`BHI_DIS_S` where selected, and
`IBRS` in the kernel's), and every CPU writes the kernel's value whole in its bring-up, so a bit
the firmware set is cleared.

IBRS set in the kernel also keeps predictions made in user mode from steering the kernel's
indirect branches, so it answers branch target injection as well, and the selection takes neither
the retpoline sequence nor the switch fill beside it (§ Return stack buffer). It rewrites no
return, so shadow stacks stay on
([return-address-integrity.md](return-address-integrity.md) § x86-64 Mechanism).

AMD parts have no `rsb_alternate` (§ Predictor behaviours), so the rule does not select IBRS on
entry for their `retbleed` (branch type confusion); the IBPB on entry answers it (§ IBPB on
entry). An Intel part without enhanced IBRS or IBRS stays on the retpoline sequence. A part of
another vendor, whose `retbleed` may be either form and whose IBRS is not read, takes enhanced
IBRS where it enumerates `IBRS_ALL` and the retpoline sequence otherwise. `mitigation::report`
logs each of these as vulnerable (§ Report): enhanced IBRS and IBRS on entry count as answering
`retbleed` only on an Intel part with `rsb_alternate` and the IBRS input.

No part that the project boots has `retbleed`; a kernel built to force the return mitigations
runs IBRS on entry, or the IBPB on entry, on the development host (§ Forced return mitigations).

### IBPB on entry

Branch type confusion (`retbleed` on Families 15h and 17h) lets user mode train the branch
target buffer so that a kernel instruction is predicted as a `ret` or another branch type to a
target user mode chose (BTC-TG). Speculative return stack overflow lets it train predictions that
overflow the return address predictor, so that a kernel `ret` is predicted to such a target
(SRSO-WP). For both at the user-to-kernel boundary AMD specifies an IBPB on every entry from user
mode, which flushes the predictions user mode trained before the kernel takes any (BTC-TG;
SRSO-WP), on a part whose IBPB flushes branch types; and STIBP where SMT is on, since an IBPB does
not keep a sibling thread running user mode from training the predictions both threads share.

The kernel builds no return thunk, the other mechanism AMD names: IBPB is the one AMD specifies
for every form of both classes, it rewrites no return and so leaves shadow stacks on
(§ Branch target injection), and its correctness rests on properties of the entry code that a
review can check without the hardware:

- **Before the first `ret`.** `seraph_enter_from_user` issues the IBPB (`mitigation::ibpb_asm`,
  a write of bit 0 to `IA32_PRED_CMD`) before its own `ret`, the first `ret` and indirect branch
  of every entry from user mode: `syscall_entry` calls it after the frame is saved,
  `enter_from_user_asm` after the frame of every exception and interrupt from ring 3, none
  with a `call` or `ret` before it (§ Return predictions).
- **NMI and machine check.** The paranoid stubs (NMI, `#DB`, `#DF`, `#MC`) run
  `enter_from_user_asm` after their `paranoid_entry_asm`, so from ring 3 they issue it there.
  From ring 0 they issue it in `paranoid_entry_asm`, after their `IA32_SPEC_CTRL` write: one can
  arrive in an entry from user mode before its IBPB, and its handler's returns would otherwise take
  the predictions user mode trained. The stubs are rare, so the repeated barrier costs little.
- **The fill.** Where the IBPB leaves the RSB (`ibpb_leaves_rsb`: no `IBPB_RET`, Zen to Zen 3,
  AMD-SB-1040), the fill after an IBPB follows it: 32 `call`s whose return addresses trap
  speculation (`int3`) and are dropped from the stack. Where a supervisor shadow stack is on, which
  `rdsspq` reports by a non-zero shadow stack pointer, `incsspq` drops the 32 entries from it too,
  so the two stacks match again and no return is rewritten.
- **Serialization.** The routine ends in `lfence`, so a mispredicted test of a flag runs no later
  instruction (§ `LFENCE` serialization).

STIBP is selected with the IBPB on entry wherever the CPU enumerates it, and set once in
`IA32_SPEC_CTRL` on every CPU (in both values the entry and exit code write under IBRS on entry).

The selection leaves a class vulnerable where the CPU has no IBPB; where its IBPB leaves branch
types (`ibpb_leaves_brtype`: Family 19h without the microcode of AMD-SB-7005, a later family that
enumerates no `IBPB_BRTYPE`, another vendor), where the IBPB on entry is not selected, since it
would answer neither class; and where SMT is on and the CPU has no STIBP (Zen and Zen+ without
it), where the IBPB on entry is selected but leaves the sibling thread open. `mitigation::report`
logs each such class with its reason (§ Report), and the host tests cover the selection and each
reason over Zen, Zen 2, Zen 3 with and without that microcode, and Zen 4 (§ Validation). Its cost
on an AMD part is not measured ([#1123](https://github.com/kottlerg/seraph/issues/1123)).

### `LFENCE` serialization

Every flag test of the entry routine and of the thunk's plain path ends in `lfence`, so that a
mispredicted test runs no later instruction. On AMD parts that holds where `LFENCE` is
dispatch-serializing, which `DE_CFG[1]` (MSR C001_1029H) makes it (STMS, mitigation G-2). Every
CPU sets the bit in its bring-up (`mitigation::apply_this_cpu`): a read, a write with bit 1 added
where it reads clear, and a read back, each recovering from `#GP` as the `SBPB` probe does
(§ Inputs). The boot CPU logs the outcome, and an AP only one other than set (§ Report). The kernel
does not write it:

- **On Intel and other vendors.** Intel defines `LFENCE` as not executing until every prior
  instruction completes locally (Intel SDM Vol. 2A, LFENCE), and `DE_CFG` is AMD's MSR.
- **On AMD Families before 10h, and 11h.** `LFENCE` is dispatch-serializing there without the
  bit (STMS, mitigation G-2).
- **Where `LfenceAlwaysSerializing` is enumerated** (`CPUID Fn8000_0021 EAX[2]`): `LFENCE` is
  dispatch-serializing whatever the bit holds (APM CPUID Fn8000_0021).
- **Where the access faults or the bit does not hold.** A hypervisor may not pass the MSR or may
  ignore the write. The log names the outcome, and the boot continues.

### Forced return mitigations

A kernel built with `SERAPH_FORCE_RETURN_MITIGATION` in the environment of `cargo xtask build`
selects from forced inputs (`mitigation::FORCED_RETURN`, read at compile time):

- `intel`: the CPU's inputs with `retbleed` and `rsb_alternate` added and `IBRS_ALL` removed,
  the inputs of an Intel part that needs IBRS on entry.
- `amd`: the CPU's inputs with `retbleed` and `spec_rstack_overflow` added and `rsb_alternate`
  removed, the inputs of an AMD part that needs the IBPB on entry (§ IBPB on entry). The boot CPU
  also makes the `SBPB` probe, and every CPU the `DE_CFG[1]` step (§ `LFENCE` serialization),
  whatever the vendor, so that their recovery from `#GP` runs where the MSR access faults.

Neither adds an enumerated bit, so a CPU without IBRS or IBPB still selects no control it cannot
run. The inputs view of `SYS_SYSTEM_INFO(SpeculationControls)` reports the forced inputs, and the
boot logs a line naming the override before the controls (§ Report). Unset or empty, the variable
forces nothing; any other value fails the build. Cargo rebuilds the kernel when the variable
changes.

On the development host the forced build selects IBRS on entry in place of enhanced IBRS, beside
`BHI_DIS_S`, `VERW` on exit and the fill after an IBPB, so the ktest boot runs the entry and exit
writes on every CPU. Its cost there was measured with the ktest bench: release builds with and
without the override, three boots of each, at 4 vCPUs in a KVM guest on the Alder Lake host, with
no other guest running. Each figure is a boot's minimum over 1000 iterations, given as the range
of the three boots' minima. Each syscall round trip costs about 575 cycles more:
`null_syscall_roundtrip` 184 to 186 cycles without the override and 757 to 759 with it, and
`cap_info_lookup` 265 to 269 and 842 to 844. `mem_map_unmap`, two calls, costs about 1150 more
(1935 to 2148, and 3212 to 3252). The IPC and notification round trips, which wait on another
thread, vary more between boots than the difference. The comparison is with enhanced IBRS, which
writes nothing on entry or exit, and on a part that is not one IBRS on entry is selected for; its
cost on such a part is not measured ([#1123](https://github.com/kottlerg/seraph/issues/1123)).

### Branch history injection

`BHI_DIS_S` keeps branch history from user mode from selecting the predicted targets of the
kernel's indirect branches (Intel's BHI guidance). A CPU without `BHI_CTRL` runs Intel's clearing
sequence in the entry routine, `seraph_enter_from_user` (§ Return predictions), after the
`IA32_SPEC_CTRL` write and the IBPB on entry (§ IBPB on entry). It is the long sequence (12 outer
and 7 inner iterations), which Intel states is effective on every part that does not enumerate
`BHI_NO`. Its calls and returns pair up, so it runs on a supervisor shadow stack. With none of
IBRS on entry, the IBPB on entry and the clearing selected, the routine runs `lfence` and
returns.

### Buffer clearing

`VERW` with a memory operand overwrites the CPU buffers that microarchitectural data sampling,
TSX asynchronous abort, MMIO stale data, register file data sampling and transient scheduler
attacks sample, on a CPU whose microcode implements the clearing (Intel's MDS, TAA, MMIO and
RFDS guidance; TSA-TG). The kernel runs it after the last kernel load of every return to user
mode: after the `swapgs` and before the `sysretq` of `syscall_entry`, before the `iretq` of
every trampoline that returns to ring 3 (`exit_swapgs_asm`), and in `return_to_user` and
`switch_and_enter_user`. The paranoid stubs (NMI, `#DB`, `#DF`, `#MC`) run it on every
return, to ring 0 as well: one can interrupt a return to user mode after its `VERW`, and its
handler's loads would otherwise reach user mode. The spurious-interrupt stub runs only `iretq`
and loads nothing but the frame the CPU pushed, so it runs none. The operand is the kernel's data
segment selector, a writable one as Intel's MDS guidance asks.

Where `mds` or `tsa` is `Kernel`, the idle loop also runs `VERW` before `hlt`
(`cpu::halt_until_interrupt`): the halted thread's buffers are repartitioned to the SMT sibling
(Intel's MDS guidance; TSA-TG). `report` logs a warning when `VERW` is selected on a CPU that
enumerates none of `MD_CLEAR` (`CPUID.(EAX=07H,ECX=0):EDX[10]`), `RFDS_CLEAR` or `VERW_CLEAR`
(`CPUID Fn8000_0021 EAX[5]`): its microcode clears nothing.

### Return stack buffer

On a part with `rsb_alternate`, a `ret` that finds the RSB empty may be predicted from the
branch target buffer, which the retpoline sequence leaves open. Where retpoline is selected on
such a part, `switch` fills the RSB with 32 entries that trap speculation (`int3`) once it is on
the next thread's stack, then runs `lfence` (Intel's retpoline white paper). Retpoline keeps
shadow stacks off (§ Branch target injection), so the fill runs only without them, and its return
addresses are dropped from the stack alone.

IBRS on entry, which replaces retpoline on a part with `retbleed`, keeps such a `ret` from
taking a prediction user mode trained (§ Return predictions), so the switch fill is not selected
beside it.

Where an IBPB does not clear the RSB (`ibpb_leaves_rsb`), the fill after an IBPB is selected.
The kernel issues an IBPB only on entry from user mode, where the IBPB on entry is selected, and
the fill follows it there (§ IBPB on entry); with the IBPB on entry not selected, the control is in
effect but nothing runs it.

The user-to-kernel boundary needs no other fill, since SMEP is enabled (§ Predictor behaviours).
SMEP is required: `cpu::verify_baseline` refuses a CPU without it, and `cpu::enable_smep_smap`
sets `CR4.SMEP` on every CPU
([docs/platform-requirements.md](../../../docs/platform-requirements.md) § x86-64
Classification).

### Speculative store bypass

The kernel does nothing for speculative store bypass at the user-to-kernel boundary and does not
set SSBD: neither vendor's guidance calls for it there (§ Boundary rules), and the class is
`OtherBoundary` on every part.

### Data-operand-independent timing

The kernel sets `IA32_UARCH_MISC_CTL.DOITM` on every CPU that enumerates it
(`IA32_ARCH_CAPABILITIES.DOITM`, bit 12), from boot, for every thread. Intel guarantees the
operand-independent timing of the instructions it lists (`MUL` among them) on such a part only
while `DOITM` is set; on Core parts before Ice Lake, which do not enumerate it, the listed
instructions behave as if it were set (Intel's DOIT guidance). The decision gives x86-64 the
guarantee the riscv64 floor gives through Zkt, which the constant-time claims of
[shared/crypto](../../../shared/crypto/README.md) rest on, with no off switch, as for every other
control. Its downsides: Intel does not recommend enabling the mode globally, because of its
performance cost, which it expects to grow on later parts, and suggests a per-thread or
per-process opt-in instead; the cost is not measured; and no boot the project runs enumerates
`DOITM` (the development host under KVM, QEMU's TCG), so the path is not exercised there.

AMD defines no counterpart. Its timing side-channel guidance asks software for constant-time
algorithms and names no instruction-timing mode or guarantee (AMD-TPSC).

---

## Report

`report` writes seven lines to the serial log after `baseline ok`. The first two give the CPU
and the inputs: the first ends with whether SMT is on and whether the `SBPB` probe was accepted
(§ Inputs), each 0 or 1. Each of the next four gives one exposure's classes in table order, or
`none`. The last gives the behaviours the CPU has, or `none`. `mitigation::report` then writes
the override line of a forced build (§ Forced return mitigations; the `amd` line ends with the
`SBPB` probe's outcome, `accepted` or `faulted`), the selected controls by their log names
(§ Selection), or `none`, one line for each of `retbleed` and `spec_rstack_overflow` that is
`Kernel` and that the selection leaves vulnerable, and the warning of § Buffer clearing where it
applies. The reason in a vulnerable line is `no control answers it` (§ Return predictions),
`no IBPB`, `IBPB does not flush branch types`, or `SMT on without STIBP` (§ IBPB on entry).
`mitigation::apply_this_cpu` writes the `DE_CFG[1]` line on the boot CPU, and on an AP only for
an outcome other than `set` (§ `LFENCE` serialization); `<n>` is the CPU's initial APIC ID and
the outcome is `set`, `not set: the MSR access raised #GP` or `not set: the write did not hold`.
The first two lines are one line each in the log; they are broken here for width, and each `<v>`
is a hexadecimal value:

```text
x86 cpu: GenuineIntel family 0x6 model 0x97 stepping 0x2 hybrid 0 doitm 0 smt 1 \
         sbpb_accepted 0
x86 cpu: arch_capabilities <v> cpuid 7.0 ebx <v> edx <v> 7.2 edx <v> 8000_0008 ebx <v> \
         8000_0021 eax <v> ecx <v>
x86 vulnerabilities, affected, kernel action: <classes>
x86 vulnerabilities, affected, mitigated by firmware: <classes>
x86 vulnerabilities, affected, not at user-to-kernel: <classes>
x86 vulnerabilities, not affected: <classes>
x86 predictor behaviours: <behaviours>
x86 mitigations: <controls>
x86 mitigations: vulnerable: <class> (<reason>)
x86 mitigations: cpu <n>: DE_CFG[1] (LFENCE dispatch-serializing) <outcome>
```

---

## Validation

The host tests in `vulnerability.rs` (`cargo xtask test`) derive the table of real parts from
their CPUID signatures and enumeration bits. Each test cites the advisory or list row its
expectation comes from:

- Alder Lake S (`06_97H`, stepping 2), with the development host's `IA32_ARCH_CAPABILITIES`.
- Ice Lake U/Y (`06_7EH`, stepping 5).
- Comet Lake (`06_A5H`, `06_A6H`).
- Jasper Lake and Alder Lake N, the Atom parts affected by RFDS.
- AMD EPYC 7002 "Rome" (Zen 2).
- AMD Family 19h (Zen 3) with and without `SBPB`, `IBPB_BRTYPE` or an accepted `SBPB` probe.
- AMD EPYC 9005 "Turin" (Zen 5), with the bits its PPR reports.
- An Intel part and an AMD part that report every `*_NO` bit their vendor defines.

Further tests cover each rule of § Derivation, the reading limits of § Inputs, and the shape of
the vendored list: every row has the header's column count, every cell a class reads has a
status § Intel maps, and every Intel class has a column.

On the development host (Alder Lake S, KVM, `-cpu host`), the classes the ktest boot logs as
affected (every exposure but `NotAffected`) are the classes the host's Linux kernel reports as
affected in its `bugs` line, less the entries § Excluded classes names. The boot logs the
`ibpb_leaves_rsb` behaviour, which the host's `bugs` line reports as `ibpb_no_ret`.

The host tests in `mitigation.rs` cover each rule of § Selection, and the controls selected for
the development host's part, the CPU QEMU's TCG presents, AMD Zen 2, Zen 3 and Zen 4, Ice Lake
and Comet Lake with and without `IBRS_ALL`, Skylake S and Coffee Lake H with IBRS (IBRS on
entry), the parts that report every `*_NO` bit, an Intel model the list does not name, and a CPU
of another vendor. For the IBPB on entry they cover Zen with SMT and no STIBP, Zen 2 with IBPB
and STIBP, Zen 3 without the microcode of AMD-SB-7005 and with it (probe, `SBPB` or
`IBPB_BRTYPE`), and Zen 4 with `IBPB_BRTYPE`, which keeps shadow stacks. They also cover the MSR
bits each control sets, the two `IA32_SPEC_CTRL` values of IBRS on entry, the flags `install`
leaves, both forced inputs and the refusal of an unknown override, each class and reason the log
names as vulnerable, where `DE_CFG[1]` is written, and the outcome its accesses give.

The ktest case `integration::speculation_controls` restates § Selection over the inputs the
kernel reports and requires the selection to match it, then requires the controls in effect on
every CPU to equal the selection, read through `SYS_SYSTEM_INFO(SpeculationControls)` with the
case pinned to each CPU in turn. On the development host the boot selects enhanced IBRS,
`BHI_DIS_S`, `VERW` on exit and the fill after an IBPB; under QEMU's TCG it selects retpoline
and the fill after an IBPB. The `intel` forced build (§ Forced return mitigations) selects IBRS
on entry in place of enhanced IBRS, and the `amd` one the IBPB on entry with its fill and STIBP
beside enhanced IBRS, with the `SBPB` probe and the `DE_CFG[1]` step faulting and recovering. No
boot the project runs selects the branch history clearing, the fill on switch, `VERW` before
idle, Automatic IBRS or `DOITM`; the host tests alone cover their selection.

Validation on other hardware is [#1123](https://github.com/kottlerg/seraph/issues/1123).

---

## Sources

Intel pages are under
`https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/`
(abbreviated `SSG/`).

| Short name | Document |
|---|---|
| Intel's list | [Intel affected-processor list](https://github.com/intel/Intel-affected-processor-list), vendored |
| CPUID page | `SSG/technical-documentation/cpuid-enumeration-and-architectural-msrs.html` |
| Intel's MDS, TAA, MMIO, SRBDS, GDS guidance | `SSG/technical-documentation/` `intel-analysis-microarchitectural-data-sampling.html`, `intel-tsx-asynchronous-abort.html`, `processor-mmio-stale-data-vulnerabilities.html`, `special-register-buffer-data-sampling.html`, `gather-data-sampling.html` |
| Intel's RFDS, PBRSB, RSBU, ITS, SSB guidance | `SSG/advisory-guidance/` `register-file-data-sampling.html`, `post-barrier-return-stack-buffer-predictions.html`, `return-stack-buffer-underflow.html`, `indirect-target-selection.html`, `speculative-store-bypass.html` |
| Intel's retpoline white paper | `SSG/technical-documentation/retpoline-branch-target-injection-mitigation.html` |
| Intel's DOIT guidance | `SSG/best-practices/data-operand-independent-timing-isa-guidance.html` |
| Intel SDM | Intel 64 and IA-32 Architectures Software Developer's Manual |
| Intel's BHI, eIBRS, mitigation overview | `SSG/technical-documentation/` `branch-history-injection.html`, `indirect-branch-restricted-speculation.html`, `speculative-execution-side-channel-mitigations.html` |
| APM2 | AMD64 Architecture Programmer's Manual Vol. 2, pub. 24593 |
| APM3 | AMD64 Architecture Programmer's Manual Vol. 3, pub. 24594 |
| STMS | AMD, "Software Techniques for Managing Speculation on AMD Processors" |
| SBAMA | AMD, "Speculation Behavior in AMD Micro-Architectures" |
| BTC-TG | AMD, "Technical Guidance for Mitigating Branch Type Confusion" |
| SRSO-WP | AMD, "Technical Update Regarding Speculative Return Stack Overflow" |
| TSA-TG | AMD, "Technical Guidance for Mitigating Transient Scheduler Attacks", Rev. 3.0 |
| AMD-TPSC | AMD, "AMD CPU Timing and Power Side-Channel Guidance", pub. 71030, Rev. 1.10 |
| AMD's SSBD white paper | AMD, "Speculative Store Bypass Disable" white paper (124441) |
| AMD-SB-*n* | `https://www.amd.com/en/resources/product-security/bulletin/amd-sb-<n>.html` |

---

## Summarized By

[core/kernel/README.md](../README.md), [Architecture Abstraction Layer](arch-interface.md),
[Kernel Initialization Sequence](initialization.md),
[Capability Model](../../../docs/capability-model.md),
[Platform Requirements](../../../docs/platform-requirements.md),
[Threat Model](../../../docs/threat-model.md),
[shared/crypto/README.md](../../../shared/crypto/README.md)
