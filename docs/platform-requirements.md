# Platform Requirements

System-scope classification of the CPU and platform features each supported architecture
requires, may use opportunistically, or does not support, and the boot-time gate that enforces
the required set.

---

## Scope

This document is authoritative for the **per-architecture hardware-support baseline**: which CPU,
firmware, and platform features are required for Seraph to run, which are used only when present,
and which are explicitly unsupported. It is also authoritative for the **boot-time feature-gate**
contract — the early-boot check that refuses unsupported hardware with a clear diagnostic.

In scope:

- The targeting envelope and the rule that decides required-vs-opportunistic.
- The two-layer floor: the instruction baseline and the platform/silicon-era floor.
- The required / opportunistic / unsupported classification of each feature, per architecture.
- The explicit IOMMU and in-silicon-mitigation policy.
- The boot-time feature-gate's responsibility and diagnostic contract.

Out of scope (owned elsewhere, referenced here):

- The psABI / toolchain feature level and target JSONs —
  [build-system.md](build-system.md#custom-targets).
- The mechanism of W^X, NX, SMEP/SMAP, the RISC-V U-bit/`SUM` isolation, and tagged-TLB tagging —
  [memory-model.md](memory-model.md).
- IOMMU discovery and the DMA safety model — [device-management.md](device-management.md).
- The microarchitectural isolation posture (transient execution, SMT, shared-state channels) —
  [capability-model.md](capability-model.md) § Microarchitectural Isolation.
- Console / serial ownership across boot — [console-model.md](console-model.md).
- The UEFI handoff, firmware tables, and `BootInfo` surface — [bootstrap.md](bootstrap.md) and
  [abi/boot-protocol/README.md](../abi/boot-protocol/README.md).

---

## Targeting Envelope

Seraph targets mainstream **workstation, laptop, and server** machines, plus future-facing
**handheld** devices with compatible silicon. Minimal and embedded platforms are not targeted.

The decision rule for every feature below:

> Require a feature if and only if it is present across that mainstream envelope at the floor
> generation. Never require a server-exclusive or bleeding-edge feature.

x86-64-v4 / AVX-512 is unsupported as a *requirement* precisely because it is essentially
server-class at this generation — the wrong target for the envelope above.

---

## Floor Definition

The floor has two layers. A platform MUST satisfy both.

### Instruction baseline

The psABI feature level the userspace toolchain emits, owned by the target JSONs
([build-system.md](build-system.md#custom-targets)):

- **x86-64**: x86-64-v3 (AVX, AVX2, BMI1/2, FMA, MOVBE, F16C, LZCNT, POPCNT, CMPXCHG16B, plus
  XSAVE) — Haswell-class instruction selection.
- **riscv64**: the RVA23U64 subset RV64GCV plus Zba/Zbb/Zbs.

### Platform / silicon-era floor

The instruction baseline alone does not pin a platform generation. The platform floor does:

- **x86-64**: approximately the **2019–2020** mainstream generation (Intel ~10th-generation
  Comet/Ice Lake, AMD Zen 2). This is the generation at which in-silicon transient-execution
  mitigations, an invariant TSC, `RDSEED`, and PCID/INVPCID are uniformly present. The x86-64-v3
  instruction floor (2013) is necessary but not sufficient; the platform floor is the binding
  requirement.
- **riscv64**: RVA23 silicon, which is inherently modern (post-2024). No separate era pin is
  needed; the RVA23 mandatory set defines the floor.

---

## Feature Classes

Each feature is classified per architecture as one of:

- **Required** — the kernel MUST have it; the boot-time feature-gate (or a subsystem's own boot
  assertion) refuses hardware that lacks it, except where
  [§ Boot-Time Feature Gate](#boot-time-feature-gate) names a feature as deliberately ungated or
  not CPU-detectable. W^X, isolation, and the floor depend on these.
- **Opportunistic** — used when present, not required. Absence degrades performance or a
  non-essential capability, never correctness.
- **Unsupported** — not used, and in some cases actively refused. Listed so absence is never
  mistaken for an oversight, and so a future requirement is a deliberate floor change.

---

## x86-64 Classification

### Required

- **Instruction baseline** — the x86-64-v3 set above (AVX, AVX2, BMI1/2, FMA, MOVBE, F16C,
  LZCNT, POPCNT, CMPXCHG16B) and `XSAVE`.
- **Long mode, `SYSCALL`/`SYSRET`, `NX` (`EFER.NXE`)** — the privilege and W^X substrate. The
  kernel sets bit 63 on non-executable PTEs; `NX` is mandatory.
- **`CR0.WP`** — supervisor write-protect. Without it, ring-0 writes bypass read-only page
  permissions and the kernel's own W^X is unenforced. The kernel sets and requires it on every CPU.
- **SMEP and SMAP** — supervisor execution and access prevention. See
  [memory-model.md](memory-model.md).
- **PCID and INVPCID** — address-space-tagged TLBs. The kernel assigns a tag per address space and
  elides the per-switch flush; see [memory-model.md](memory-model.md).
- **Invariant TSC** — a constant-rate timestamp counter, the basis of timekeeping.
- **8254 PIT** — required only where CPUID leaf 0x15 does not give the TSC rate (it enumerates
  no crystal frequency: AMD, older Intel, and QEMU's emulated CPUs). There the kernel measures the
  TSC over one 8254 window at boot; where an exact rate is enumerated it never touches the 8254.
  The local-APIC timer, which the periodic-fallback tick path uses, is measured against the TSC
  whatever the TSC rate's source
  ([core/kernel/src/arch/x86_64/timer_rate.rs](../core/kernel/src/arch/x86_64/timer_rate.rs)).
- **Local APIC and an I/O APIC** — interrupt delivery and routing.
- **CPUID extended-topology leaf 0x0B** — the source of the BSP's full 32-bit x2APIC ID (CPU
  topology itself comes from the ACPI MADT).
- **`RDRAND` and `RDSEED`** — hardware entropy sources seeded into the kernel CSPRNG.
- **In-silicon transient-execution mitigations** (MDS, L1TF, and the rest of the ~2019 set) — a
  consequence of the platform floor. Their per-vulnerability enforcement is a hardening concern and
  is vendor-specific (Intel enumerates via `IA32_ARCH_CAPABILITIES`; AMD differs), so it is not part
  of the cross-vendor boot-gate. What the kernel defends beyond them, and what it leaves
  unmitigated, is the posture of [capability-model.md](capability-model.md)
  § Microarchitectural Isolation; the controls it selects by enumeration (enhanced or automatic
  IBRS, IBRS on entry, the IBPB on entry and STIBP, `BHI_DIS_S`, `VERW`) are opportunistic in
  the same sense as the entries below, each with a software fallback or a stated gap
  ([core/kernel/docs/transient-execution.md](../core/kernel/docs/transient-execution.md)
  § Controls).
- **2 MiB large pages** — used for the kernel direct map.
- **UEFI firmware and ACPI 2.0+ (XSDT, MADT)** — the boot and hardware-discovery path. There is no
  BIOS or RSDT fallback.
- **COM1 16550 UART at I/O port `0x3F8`** — the boot/console serial device.

### Opportunistic

- **x2APIC mode** — used when present (and required to address more than 255 CPUs); the kernel
  falls back to xAPIC MMIO.
- **AES-NI and SHA-NI** — crypto acceleration (design intent; not yet enabled).
- **CET shadow stack (SHSTK)** — supervisor shadow stacks, return-address integrity for the
  kernel, enabled when the boot CPU reports `CET_SS` and the kernel's transient-execution
  selection uses no control that rewrites a return (the retpoline sequence, which a CPU without
  enhanced IBRS, Automatic IBRS or IBRS on entry takes, AMD Zen 3 among them; IBRS on entry and
  the IBPB on entry rewrite none): the mitigation takes precedence.
  Once enabled, every other CPU must report `CET_SS` too, or the boot halts. Without it the
  kernel runs unprotected and otherwise unchanged
  ([core/kernel/docs/return-address-integrity.md](../core/kernel/docs/return-address-integrity.md)
  § x86-64 Mechanism).
- **TSC-deadline timer mode** — drives the preemption tick when present; the periodic APIC
  timer is the fallback.
- **MONITOR/MWAIT** — the idle loop's wait, with the C1 hint, the state `HLT` enters, when
  CPUID.01H:ECX.MONITOR reports it: a wake of a thread onto an idle CPU then stores to that CPU's
  idle wake word instead of sending an IPI. Without it the idle loop halts in `HLT` and every
  remote wake sends the IPI
  ([core/kernel/docs/scheduler.md](../core/kernel/docs/scheduler.md) § Idle Thread).
- **UMIP** (`CR4.UMIP`) — set on every CPU when present, so ring-3 `SGDT`, `SIDT`, `SLDT`, `SMSW`,
  and `STR` raise `#GP`. It is not uniform at the platform floor (Intel's Skylake-derived 10th
  generation lacks it), so it is not required. Without it ring 3 can read the IDT and GDT bases,
  which disclose the KASLR image slide (the IDT and the BSP's GDT lie in the kernel image) or
  the direct-map base (an AP's GDT lies in the direct map); see
  [core/kernel/docs/cross-boundary-disclosure.md](../core/kernel/docs/cross-boundary-disclosure.md)
  § Surface inventory.
- **DOITM** (`IA32_UARCH_MISC_CTL` bit 0, enumerated by `IA32_ARCH_CAPABILITIES` bit 12) — set
  on every CPU that enumerates it, from boot, for every thread, so the instructions Intel lists
  as data-operand-independent (`MUL` among them) keep operand-independent timing, the guarantee
  the riscv64 floor gives through Zkt and the constant-time claims of
  [shared/crypto](../shared/crypto/README.md) rest on. Intel parts before Ice Lake do not
  enumerate it and time those instructions as if it were set; AMD defines no counterpart. The
  decision, its reason and its cost against Intel's advice are in
  [core/kernel/docs/transient-execution.md](../core/kernel/docs/transient-execution.md)
  § Data-operand-independent timing.
- **EFI_RNG_PROTOCOL** — an additional boot entropy seed.
- **TPM 2.0** — a hardware random number generator independent of RDSEED and RDRAND: when the
  firmware reports a TPM 2.0 in the ACPI `TPM2` table on the FIFO interface or on the CRB
  interface started through its start register (start methods 6 and 7), the TPM driver reads it
  with `TPM2_GetRandom` and `entropyd` mixes its bytes into the kernel pool
  ([services/drivers/docs/tpm.md](../services/drivers/docs/tpm.md)). It is not a boot dependency:
  without a TPM, or with one the driver does not start, the system runs unchanged. No other TPM
  function (measured boot, sealing, attestation) is used.
- **UEFI Secure Boot** — the firmware verifies the bootloader, Authenticode-signed with a key the
  deployer enrols in its db, before it runs it ([signing.md](signing.md) § Secure Boot). Used when
  the platform enables it, and never a default boot dependency: without it the system boots
  unchanged, and the bootloader logs on every boot whether it is on. A system's signed
  configuration may require it (design intent;
  [#1416](https://github.com/kottlerg/seraph/issues/1416)).
- **RTC (CMOS / MC146818)** — the wall clock: when firmware describes one, the `cmos-rtc` driver
  answers `timed`'s wall-time reads ([services/drivers/README.md](../services/drivers/README.md)
  § Existing Drivers). It is not a boot dependency: without one, wall-time reads fail and the
  system runs unchanged.
- **GOP framebuffer** — graphical console; a headless serial-only boot is valid.
- **PCIe ECAM (MCFG)** — discovered when firmware publishes it; not required by the kernel.
- **LA57 (5-level paging)** — a larger-VA expansion above 4-level paging, the x86-64 analogue of
  riscv64's Sv57: the bootloader enables it when CPUID reports it
  ([core/boot/docs/page-tables.md](../core/boot/docs/page-tables.md) § x86-64: Negotiated Paging
  Depth), and the kernel takes the paging depth from `CR4.LA57` at entry, as riscv64 takes its
  mode from `satp`. Its 64 PiB halves meet the 526 TB target of
  [#177](https://github.com/kottlerg/seraph/issues/177); without it the 4-level 128 TiB halves
  cap direct-mapped RAM and each process's virtual address space below that target.

### Unsupported

- **AVX-512 / x86-64-v4** — server-class; never required, never depended upon.
- **1 GiB huge pages, global pages (`PGE`), MTRR reprogramming, HPET, the legacy 8259 PIC** —
  not used. (The kernel relies on firmware's default PAT and leaves the 8259 masked.)
- **`FSGSBASE`** — kept disabled: the kernel clears `CR4.FSGSBASE` on every CPU, because its
  paranoid NMI / `#DB` / `#DF` / `#MC` entry depends on ring 3 being unable to set a
  kernel-half GS base; without `FSGSBASE` ring 3 can change it only by loading a GDT selector,
  whose base is 0 (see [arch-interface.md](../core/kernel/docs/arch-interface.md) § `cpu`).
- **CET indirect-branch tracking (IBT)** — not used: forward-edge control-flow integrity is not
  pursued
  ([core/kernel/docs/return-address-integrity.md](../core/kernel/docs/return-address-integrity.md)).
- **Legacy BIOS / multiboot** — boot is UEFI-only.

---

## riscv64 Classification

### Required

- **Instruction baseline** — RV64GCV plus Zba/Zbb/Zbs. The compressed (C) extension is part of it; a
  debugger's single-step plants the 2-byte `c.ebreak` it encodes
  ([fault-handling.md](fault-handling.md) § Debugging). The Vector extension is a hard requirement;
  the kernel reads `vlenb` on the boot hart and refuses `vlenb == 0`, a `vlenb` above 8192 (VLEN
  65536, the V specification's largest), or one that is not a power of two. Any other vector length
  is accepted: each thread's save area grows with it (`304 + 32 * vlenb` bytes, rounded up to pages;
  `core/kernel/src/arch/riscv64/fpu.rs`, `core/kernel/src/sched/thread_slot.rs`).
- **Uniform vector length** — every hart has the boot hart's `vlenb`. Each thread's save area is
  sized from the boot hart's, and the save and restore paths stride by the running hart's, so each
  secondary hart reads its own `vlenb` at bring-up and a different value halts the boot.
- **Supervisor isolation — the U bit and `sstatus.SUM`** — S-mode never executes from user
  (U=1) pages, and the kernel keeps `SUM` clear outside its user-copy routines so supervisor
  accesses to user pages fault. See [memory-model.md](memory-model.md).
- **PMP** — physical-memory protection established by M-mode firmware; it protects firmware
  memory, not user pages.
- **ASID-tagged TLBs** — the `satp` ASID field, the RISC-V counterpart of PCID; see
  [memory-model.md](memory-model.md).
- **AIA (Ssaia, APLIC, IMSIC)** — the only external-interrupt path the kernel drives: Ssaia on
  every hart, a supervisor-level APLIC domain that supports MSI delivery mode, and a
  supervisor-level IMSIC file per hart at the layout the firmware tables report (both from
  `BootInfo.kernel_mmio`). The kernel halts the boot without them (see
  [initialization.md](../core/kernel/docs/initialization.md) § Phase 5: Architecture Hardware
  Initialisation). Under Smstateen the M-mode firmware must also grant S-mode the AIA CSRs the
  kernel uses: `siselect` and `sireg` through `mstateen0.CSRIND`, and `stopei` and the IMSIC file
  behind `sireg` through `mstateen0.IMSIC`. Each hart's first access to them recovers from a trap
  and halts the boot with a message naming both bits (`aia::init_hart`); OpenSBI grants both on a
  hart with Smaia. Under emulation this needs QEMU ≥ 9.0, the first release whose `ssaia` and
  `smaia` CPU properties are not experimental, and `-machine virt,aia=aplic-imsic`
  ([build-system.md](build-system.md) § QEMU and Firmware).
- **Sstc — `stimecmp`** — the supervisor timer.
- **Svpbmt, Svinval, Svnapot** — page-based memory types, fine-grained fence invalidation, and
  NAPOT page encodings; asserted by `paging::verify_paging_extensions`, before the first
  userspace mapping, from the bootloader-confirmed hart capabilities. Svade is the baseline A/D-bit
  model. The kernel pre-sets A in every leaf and D in every writable leaf, and clears A only
  through `SYS_ASPACE_HARVEST`. Absent Svadu, it sets A (and D on a store) in its fault path when
  an access finds the bit clear
  ([memory-internals.md](../core/kernel/docs/memory-internals.md#accessed-bits) § Accessed Bits).
  Under emulation the CPU model enables Svade and disables Svadu (`svade=on,svadu=off`,
  [build-system.md](build-system.md) § QEMU and Firmware), so CI runs that fault path.
- **Ssstateen — `sstateen0`, granted to S-mode** — the state-enable CSR through which the kernel
  keeps U-mode from every state it does not save and restore on a context switch: state a process
  could reach and the kernel does not switch would persist into the next process on the hart, a
  leak or a covert channel below the capability boundary. Every hart writes `sstateen0` with no
  state enabled (the custom state of `C`, the Zfinx `fcsr` of `FCSR`, which is read-only zero on a
  hart with F, the Zcmt `jvt` of `JVT`, and every bit a later extension defines) and halts the
  boot when the write does not read back
  (`core/kernel/src/arch/riscv64/cpu.rs`, `disable_unswitched_user_state`), then writes `senvcfg`
  whole with 0 and halts the boot when that write does not read back either. `sstateen1` to
  `sstateen3` are not written: no ratified extension defines state in them. The M-mode firmware
  must grant S-mode both CSRs, `sstateen0` through `mstateen0.SE0` and `senvcfg` through
  `mstateen0.ENVCFG`, since Smstateen gates S-mode's `senvcfg` too; OpenSBI grants both on a hart
  with Smstateen, the M-mode part of the extension, which the firmware alone uses. The RVA23 floor
  mandates Ssstateen, so requiring it excludes no in-floor hardware. Under emulation the CPU model
  must enable Smstateen (`smstateen=on`, [build-system.md](build-system.md) § QEMU and Firmware).
- **`time` CSR (Zicntr)** — the timestamp source.
- **Address translation**: one of Sv39/Sv48/Sv57, negotiated at boot (DTB
  `mmu-type` claim, confirmed by a `satp` write-probe that falls back to the next-narrower mode;
  see [core/boot/docs/page-tables.md](../core/boot/docs/page-tables.md#mode-negotiation)). Sv39
  is the RVA23 mandatory minimum and the refusal floor; Sv48 is the standing
  default in CI and development.
- **UEFI firmware over an SBI (M-mode) implementation; a device tree or ACPI** — the boot and
  discovery path. SBI HSM is required to start secondary harts, and SBI RFENCE for its
  `remote_fence_i`, which makes instruction fetch on every hart see code written through a data
  path ([memory-model.md](memory-model.md) § Instruction-Fetch Coherence).
- **MMIO ns16550a UART** — the boot/console serial device (base discovered via firmware tables,
  with a platform fallback).

### Opportunistic

- **Svadu** — hardware A/D-bit updates, in effect when the firmware sets `menvcfg.ADUE`. The
  kernel does not enable them; without them its fault path sets the bits (Svade, above).
- **Sv57** — a larger-VA expansion above the Sv48 default; used when the
  platform advertises and the probe confirms it.
- **Zvk vector crypto** — crypto acceleration (design intent; not yet enabled).
- **Zawrs** — the idle loop's wait, `WRS.NTO` on an `lr.w` reservation of the hart's idle wake
  word, when the firmware tables advertise it for every hart (`HART_CAP_ZAWRS`); RVA23 mandates
  it. A wake of a thread onto an idle hart then stores to that word instead of sending an IPI.
  Without it the idle loop halts in `WFI` and every remote wake sends the IPI
  ([core/kernel/docs/scheduler.md](../core/kernel/docs/scheduler.md) § Idle Thread). The
  M-mode firmware must leave `mstatus.TW` clear, as `WFI` needs.
- **EFI_RNG_PROTOCOL** — the boot seed's only firmware source under the EDK2 firmware the
  default boot uses, exposed through the firmware's `VirtioRngDxe` binding `virtio-rng`;
  firmware that delivers a DTB may supply `/chosen/rng-seed` instead, and with neither the pool
  seeds from the Zkr `seed` CSR where the hart has it and the firmware grants it, and otherwise
  from jitter (see [core/kernel/docs/entropy.md](../core/kernel/docs/entropy.md)).
- **Zkr seed CSR** — the kernel's hardware RNG, a raw entropy source the pool mixes beside the
  boot seed; used where the hart implements `Zkr` and the M-mode firmware grants S-mode the CSR
  (`mseccfg.SSEED`, which OpenSBI sets on such a hart), which the kernel learns by probing the
  CSR (see [core/kernel/docs/entropy.md](../core/kernel/docs/entropy.md)).
- **Goldfish RTC** — the wall clock: when the platform describes one, the `goldfish-rtc` driver
  answers `timed`'s wall-time reads ([services/drivers/README.md](../services/drivers/README.md)
  § Existing Drivers). It is not a boot dependency: without one, wall-time reads fail and the
  system runs unchanged.
- **GOP framebuffer, PCIe ECAM** — as on x86-64.
- **UEFI Secure Boot** — as on x86-64. It needs an EDK2 build with Secure Boot, which not every
  distribution's RISC-V firmware is ([build-system.md](build-system.md) § QEMU and Firmware).
- **Zicfiss** — supervisor shadow stacks, return-address integrity for the kernel, enabled
  through the SBI Firmware Features extension; an RVA23 option, not mandatory. Used only when
  the firmware tables advertise it for every hart, so a machine on which only some harts have it
  runs unprotected; a secondary hart whose firmware then refuses the enable, after the boot
  hart's succeeded, halts the boot, since its description is wrong (design intent;
  not yet enabled, and not buildable until the toolchain emits the shadow-stack instructions;
  [core/kernel/docs/return-address-integrity.md](../core/kernel/docs/return-address-integrity.md)).

### Unsupported

- **PLIC** — not driven: the kernel has no PLIC path, and a platform that presents only a PLIC
  does not boot.
- **Legacy / embedded RISC-V profiles** — outside the RVA23 floor.
- **Port-mapped I/O** — RISC-V has no port I/O; all device access is MMIO.
- **Zicfilp landing pads** — not used: forward-edge control-flow integrity is not pursued
  ([core/kernel/docs/return-address-integrity.md](../core/kernel/docs/return-address-integrity.md)).
- **Cache-block-management instructions (Zicbom/Zicboz/Zicbop)** — not used; the kernel assumes
  cache-coherent DMA, and denies U-mode `cbo.zero`, `cbo.clean`, `cbo.flush` and `cbo.inval`
  (`senvcfg` written whole with 0). (Distinct from Svpbmt: the PBMT memory type governs how a
  hart's own accesses to a mapping behave, not DMA cache coherence.)
- **TPM** — not a boot dependency.
- **Sdtrig debug triggers (SBI Debug Triggers, DBTR)** — not used: the kernel programs no trigger.
  The reference platform (QEMU `-cpu max` under OpenSBI) offers two triggers through DBTR, of the
  address-match types, and no instruction-count (`icount`) trigger, which a single-step would
  need; a debugger steps a riscv64 thread with software breakpoints instead
  ([fault-handling.md](fault-handling.md) § Debugging).

---

## IOMMU and DMA Confinement

The IOMMU (Intel VT-d, the RISC-V IOMMU extension) is **opportunistic** on both architectures. It
is a platform/chipset feature whose presence and usability vary across the envelope — firmware may
disable it, fuse it off, or omit it on consumer boards and handhelds — so requiring it would exclude
in-envelope hardware.

The IOMMU is discovered by the userspace device manager and programmed by a userspace IOMMU
driver it directs, not by the kernel: VT-d on x86-64, the RISC-V IOMMU on riscv64. When an
IOMMU is present and configured, device DMA is confined to explicitly mapped frames; when it is
absent or unconfigured, DMA is unconfined (a degraded mode). A system's signed boot-time policy MAY
make confinement a requirement (`dma-confinement = required`): devmgr then starts no DMA-capable
driver for a device no IOMMU unit confines, and a machine whose boot device is left unconfined does
not boot until it is given a confining IOMMU or a policy that does not require one. The
authoritative DMA safety model, the setting, the refusal and the recovery included, is in
[device-management.md](device-management.md) (§ DMA Safety Model, § Required DMA Confinement).

---

## Boot-Time Feature Gate

The kernel verifies the required set during early boot — after the console is live so a diagnostic
can be printed, and before any subsystem that assumes a required feature initializes. On a missing
feature it halts with a message naming the specific feature, rather than failing obscurely later.

- **x86-64**: a single `cpu::verify_baseline()` checks the cross-vendor, CPUID-detectable required
  features (the v3 instruction set, long mode / `SYSCALL` / `NX`, SMEP/SMAP, `XSAVE`,
  extended-topology leaf 0x0B, `RDRAND`/`RDSEED`) and ensures `CR0.WP` is set. Three required
  features are deliberately not gated because the software emulator used for continuous integration
  (QEMU TCG) cannot provide them and the kernel degrades correctly: PCID/INVPCID tagged TLBs (the
  kernel retains a full-flush fallback), invariant TSC (a frequency-stability guarantee; the kernel
  takes the TSC rate from CPUID or measures it against the PIT), and the vendor-specific in-silicon
  mitigations.
- **riscv64**: required features are asserted where each is safely detectable from supervisor mode —
  the SBI HSM and RFENCE extensions at the gate, and the Vector extension and the ASID-tagged TLB at
  their initialization sites (every hart without V, a secondary hart with a `vlenb` other than the
  boot hart's, and every hart without ASIDs; emulated RISC-V provides ASID, so unlike x86-64 PCID
  this is gated). A hart without V, the boot hart or a secondary one, is stopped by the kernel's
  fatal illegal-instruction trap at its `vlenb` read rather than by a message naming V; the boot
  hart's named message covers a malformed `vlenb`. Ssstateen is asserted by access on every hart,
  the boot hart in Phase 5 and each secondary hart at its bring-up: a hart without it, or whose
  firmware keeps `sstateen0` from S-mode, traps at the write, and the trap's fixup halts the boot
  with a message naming Ssstateen, as does a write that does not read back; a hart whose firmware
  keeps `senvcfg` from S-mode (`mstateen0.ENVCFG` clear) halts the same way, with a message naming
  `senvcfg` and that bit. Extension requirements introduced by a subsystem (the timer, the paging
  extensions, AIA) are asserted by that subsystem during boot — the timer, for example, refuses to
  boot unless the bootloader confirmed Sstc (and a timebase frequency) for every hart from the
  firmware tables (ACPI RHCT, or the DTB `/cpus` nodes), and the interrupt initialisation unless it
  confirmed Ssaia for every hart and reported a supervisor-level APLIC domain and IMSIC layout.

Platform features that are not CPU-detectable (the PIT, UEFI, ACPI/DTB, the UART) are not probed by
the gate; their absence manifests as a boot failure on the discovery path they feed. Where the
8254 PIT is the TSC rate source, a missing or dead one counts as no working 8254 when its window
ends at once, gives an implausible rate, or outlives a poll budget in TSC ticks; the kernel then
takes the rate from CPUID leaf 0x16's base frequency, approximate, where leaf 0x15 enumerates the
TSC ratio, and otherwise halts the boot at timer calibration with a message naming the sources it
tried.

---

## Platform Limits

Independent of the feature classification, the kernel imposes fixed platform limits:

- **Page size** is 4 KiB ([memory-model.md](memory-model.md)).
- **Maximum RAM** is what the paging mode's kernel half can direct-map below the top-2 GiB kernel
  image window: the half less 2 GiB, so 128 TiB less 2 GiB under x86-64 4-level paging and riscv64
  Sv48, and 254 GiB under Sv39 ([memory-model.md](memory-model.md)); a platform whose RAM reaches
  past it is refused at boot. Within those halves no kernel table bounds RAM: the Phase 3 page
  tables come from a carve of RAM sized to the machine (`core/kernel/src/mm/paging.rs`), which
  the fixed stage-1 seed maps only the first chunks of, so the same holds under x86-64 5-level
  paging and Sv57, whose half is 64 PiB less 2 GiB (`BOOT_TABLE_POOL_SIZE`,
  [limits.md](limits.md)).
- **CPU count** is at most `boot_protocol::MAX_CPUS` (8192); CPUs beyond it are not brought up.

---

## Future Architectures

The classification is structured to extend to a third architecture (for example aarch64) without
reshaping the existing sections: the new architecture adds its own `## <arch> Classification`
section with the same Required / Opportunistic / Unsupported subsections, an entry in the floor
definition, and an arch-local `cpu::verify_baseline()`. The targeting envelope and the
required-vs-opportunistic rule are architecture-neutral and unchanged.

---

## Summarized By

[Page Tables](../core/boot/docs/page-tables.md),
[Architecture Abstraction Layer](../core/kernel/docs/arch-interface.md),
[Kernel Initialization Sequence](../core/kernel/docs/initialization.md),
[Return-Address Integrity](../core/kernel/docs/return-address-integrity.md),
[Architecture Overview](architecture.md), [Build System](build-system.md),
[Fault Handling](fault-handling.md), [Memory Model](memory-model.md),
[shared/riscv-step/README.md](../shared/riscv-step/README.md)
