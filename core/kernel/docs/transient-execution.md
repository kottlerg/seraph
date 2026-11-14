# Transient Execution

Specifies the x86-64 vulnerability table: for the running CPU, the exposure of each
transient-execution class at the user-to-kernel boundary, derived at boot from CPUID,
`IA32_ARCH_CAPABILITIES` and the vendors' published guidance.

---

## Scope

The kernel defends the user-to-kernel boundary against every transient-execution class, always,
and selects each defence that only some CPUs need by enumerating the running CPU
([docs/capability-model.md](../../../docs/capability-model.md) § Microarchitectural Isolation).
The vulnerability table is that enumeration. It is computed once, on the boot CPU, in Phase 1
after the baseline check (`speculation::enumerate_vulnerabilities`), and written to the serial
log (§ Report).

The table states what each class asks of the kernel at the user-to-kernel boundary. Applying the
defences it selects (buffer clearing on return to user mode, the branch-predictor controls, the
return-prediction controls) is design intent, not yet implemented
([#1085](https://github.com/kottlerg/seraph/issues/1085)).

RISC-V has no counterpart. The RVA23 floor defines no enumeration of transient-execution
vulnerabilities and no speculation control, so `speculation::enumerate_vulnerabilities` does
nothing on riscv64.

The code is `arch/x86_64/vulnerability.rs`: `read` collects the inputs through a CPUID and an
MSR accessor, `derive` maps them to a `VulnerabilityTable` as a pure function of them, and
`report` logs both. `read` and `derive` are host-tested (§ Validation).

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
  implementation defect), and `ibpb_no_ret`, which describes an IBPB behaviour.
- **Classes subsumed by a reported one, or mitigated by microcode.** Spectre v3a (rogue system
  register read) is mitigated by microcode alone. Intra-mode branch target injection is part of `bhi`. Restricted RSB alternate behaviour
  (RRSBA) is part of `retbleed` on the parts that have it.

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
| `CPUID.(EAX=07H,ECX=0):EDX` | Hybrid (bit 15); `IA32_ARCH_CAPABILITIES` implemented (bit 29) |
| `CPUID.(EAX=07H,ECX=2):EDX` | `BHI_CTRL` (bit 4) |
| `CPUID Fn8000_0008 EBX` | AMD: `SsbdNotRequired` (bit 26), `BTC_NO` (bit 29) |
| `CPUID Fn8000_0021 EAX` | AMD: `SRSO_NO` (bit 29), `SRSO_USER_KERNEL_NO` (bit 30) |
| `CPUID Fn8000_0021 ECX` | AMD: `TSA_SQ_NO` (bit 1), `TSA_L1_NO` (bit 2), `TSA_FILL_NO` (bit 7) |
| `IA32_ARCH_CAPABILITIES` | The `*_NO` bits, `RSBA`, `TSX_CTRL` and `RFDS_CLEAR` (§ Enumerated bits) |

The inputs are read on the boot CPU only. Intel states that the RFDS bits enumerate identically
on every logical processor of a hybrid part. No vendor document found states the same for every
bit the table reads.

---

## Derivation

`derive` applies four steps in order: the vendor's per-model table, the
`IA32_ARCH_CAPABILITIES` bits, AMD's CPUID bits (AMD parts only), then the boundary rules.

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
  guest-host variant is a VMM's. Their columns give at most `OtherBoundary`.
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
- `spec_store_bypass`: affected on every family, then capped by the boundary rules.
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

<!-- Predictor behaviours section: pending -->

---

## Report

`report` writes six lines to the serial log after `baseline ok`. The first two give the CPU and
the inputs. Each of the other four gives one exposure's classes in table order, or `none`:

```text
x86 cpu: GenuineIntel family 0x6 model 0x97 stepping 0x2 hybrid 0
x86 cpu: arch_capabilities 0x... cpuid 7.0 ebx 0x... edx 0x... 7.2 edx 0x... 8000_0008 ebx 0x... 8000_0021 eax 0x... ecx 0x...
x86 vulnerabilities, affected, kernel action: <classes>
x86 vulnerabilities, affected, mitigated by firmware: <classes>
x86 vulnerabilities, affected, not at user-to-kernel: <classes>
x86 vulnerabilities, not affected: <classes>
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
- AMD EPYC 9005 "Turin" (Zen 5), with the bits its PPR reports.
- An Intel part and an AMD part that report every `*_NO` bit their vendor defines.

Further tests cover each rule of § Derivation, the reading limits of § Inputs, and the shape of
the vendored list: every row has the header's column count, every cell a class reads has a
status § Intel maps, and every Intel class has a column.

On the development host (Alder Lake S, KVM, `-cpu host`), the classes the ktest boot logs as
affected (every exposure but `NotAffected`) are the classes the host's Linux kernel reports as
affected in its `bugs` line, less the entries § Excluded classes names. Validation on other
hardware is [#1123](https://github.com/kottlerg/seraph/issues/1123).

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
| Intel's BHI, eIBRS, mitigation overview | `SSG/technical-documentation/` `branch-history-injection.html`, `indirect-branch-restricted-speculation.html`, `speculative-execution-side-channel-mitigations.html` |
| APM3 | AMD64 Architecture Programmer's Manual Vol. 3, pub. 24594 |
| STMS | AMD, "Software Techniques for Managing Speculation on AMD Processors" |
| SBAMA | AMD, "Speculation Behavior in AMD Micro-Architectures" |
| BTC-TG | AMD, "Technical Guidance for Mitigating Branch Type Confusion" |
| SRSO-WP | AMD, "Technical Update Regarding Speculative Return Stack Overflow" |
| TSA-TG | AMD, "Technical Guidance for Mitigating Transient Scheduler Attacks", Rev. 3.0 |
| AMD's SSBD white paper | AMD, "Speculative Store Bypass Disable" white paper (124441) |
| AMD-SB-*n* | `https://www.amd.com/en/resources/product-security/bulletin/amd-sb-<n>.html` |

---

## Summarized By

[core/kernel/README.md](../README.md), [Architecture Abstraction Layer](arch-interface.md),
[Kernel Initialization Sequence](initialization.md),
[Capability Model](../../../docs/capability-model.md)
