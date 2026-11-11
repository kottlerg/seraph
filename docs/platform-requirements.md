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
- **8254 PIT** — used once at boot to calibrate the TSC (and the local-APIC timer for the
  periodic-fallback tick path).
- **Local APIC and an I/O APIC** — interrupt delivery and routing.
- **CPUID extended-topology leaf 0x0B** — the source of the BSP's full 32-bit x2APIC ID (CPU
  topology itself comes from the ACPI MADT).
- **`RDRAND` and `RDSEED`** — hardware entropy sources seeded into the kernel CSPRNG.
- **In-silicon transient-execution mitigations** (MDS, L1TF, and the rest of the ~2019 set) — a
  consequence of the platform floor. Their per-vulnerability enforcement is a hardening concern and
  is vendor-specific (Intel enumerates via `IA32_ARCH_CAPABILITIES`; AMD differs), so it is not part
  of the cross-vendor boot-gate.
- **2 MiB large pages** — used for the kernel direct map.
- **UEFI firmware and ACPI 2.0+ (XSDT, MADT)** — the boot and hardware-discovery path. There is no
  BIOS or RSDT fallback.
- **COM1 16550 UART at I/O port `0x3F8`** — the boot/console serial device.

### Opportunistic

- **x2APIC mode** — used when present (and required to address more than 255 CPUs); the kernel
  falls back to xAPIC MMIO.
- **AES-NI and SHA-NI** — crypto acceleration (design intent; not yet enabled).
- **CET (shadow stack / IBT)** — control-flow integrity (design intent; not yet enabled).
- **TSC-deadline timer mode** — drives the preemption tick when present; the periodic APIC
  timer is the fallback.
- **UMIP** (`CR4.UMIP`) — set on every CPU when present, so ring-3 `SGDT`, `SIDT`, `SLDT`, `SMSW`,
  and `STR` raise `#GP`. It is not uniform at the platform floor (Intel's Skylake-derived 10th
  generation lacks it), so it is not required. Without it ring 3 can read the IDT and GDT bases,
  which disclose the KASLR image slide (the IDT and the BSP's GDT lie in the kernel image) or
  the direct-map base (an AP's GDT lies in the direct map); see
  [core/kernel/docs/cross-boundary-disclosure.md](../core/kernel/docs/cross-boundary-disclosure.md)
  § Surface inventory.
- **EFI_RNG_PROTOCOL** — an additional boot entropy seed.
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
- **Legacy BIOS / multiboot** — boot is UEFI-only.
- **Secure Boot, TPM, RTC** — not boot dependencies.

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
  Initialisation).
- **Sstc — `stimecmp`** — the supervisor timer.
- **Svpbmt, Svinval, Svnapot** — page-based memory types, fine-grained fence invalidation, and
  NAPOT page encodings; asserted by `paging::verify_paging_extensions`, before the first
  userspace mapping, from the bootloader-confirmed hart capabilities. Svade is the baseline A/D-bit
  model.
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

- **Svadu** — hardware A/D-bit updates (design intent; not yet implemented: the kernel pre-sets
  A in every leaf PTE and D in every writable leaf; Svade is the required baseline).
- **Sv57** — a larger-VA expansion above the Sv48 default; used when the
  platform advertises and the probe confirms it.
- **Zvk vector crypto** — crypto acceleration (design intent; not yet enabled).
- **EFI_RNG_PROTOCOL** — the boot seed's only firmware source under the EDK2 firmware the
  default boot uses, exposed through the firmware's `VirtioRngDxe` binding `virtio-rng`;
  firmware that delivers a DTB may supply `/chosen/rng-seed` instead, and with neither the pool
  seeds from jitter (see [core/kernel/docs/entropy.md](../core/kernel/docs/entropy.md)).
- **GOP framebuffer, PCIe ECAM** — as on x86-64.

### Unsupported

- **PLIC** — not driven: the kernel has no PLIC path, and a platform that presents only a PLIC
  does not boot.
- **Ssstateen / Smstateen** — not used, although the RVA23 floor mandates Ssstateen: the kernel
  does not program the state-enable CSRs.
- **Legacy / embedded RISC-V profiles** — outside the RVA23 floor.
- **Port-mapped I/O** — RISC-V has no port I/O; all device access is MMIO.
- **Cache-block-management instructions (Zicbom/Zicboz/Zicbop)** — not used; the kernel assumes
  cache-coherent DMA. (Distinct from Svpbmt: the PBMT memory type governs how a hart's own
  accesses to a mapping behave, not DMA cache coherence.)
- **Secure Boot, TPM, RTC** — not boot dependencies.
- **Zkr seed CSR** — not used: M-mode-owned under default firmware, so it is not an S-mode
  entropy source; the kernel reports no riscv64 hardware RNG (see
  [core/kernel/docs/entropy.md](../core/kernel/docs/entropy.md)).
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
absent or unconfigured, DMA is unconfined (a degraded mode). The authoritative DMA safety model is
in [device-management.md](device-management.md).

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
  calibrates the TSC against the PIT), and the vendor-specific in-silicon mitigations.
- **riscv64**: required features are asserted where each is safely detectable from supervisor mode —
  the SBI HSM and RFENCE extensions at the gate, and the Vector extension and the ASID-tagged TLB at
  their initialization sites (every hart without V, a secondary hart with a `vlenb` other than the
  boot hart's, and every hart without ASIDs; emulated RISC-V provides ASID, so unlike x86-64 PCID
  this is gated). A hart without V, the boot hart or a secondary one, is stopped by the kernel's
  fatal illegal-instruction trap at its `vlenb` read rather than by a message naming V; the boot
  hart's named message covers a malformed `vlenb`. Extension requirements introduced by a subsystem
  (the timer, the paging extensions, AIA) are asserted by that subsystem during boot — the timer,
  for example, refuses to boot unless the bootloader confirmed Sstc (and a timebase frequency) for
  every hart from the firmware tables (ACPI RHCT, or the DTB `/cpus` nodes), and the interrupt
  initialisation unless it confirmed Ssaia for every hart and reported a supervisor-level APLIC
  domain and IMSIC layout.

Platform features that are not CPU-detectable (the PIT, UEFI, ACPI/DTB, the UART) are not probed by
the gate; their absence manifests as a boot failure on the discovery path they feed. A missing or
dead 8254 PIT halts the boot at timer calibration with a message naming the PIT, once a poll
budget in TSC ticks expires.

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
[Architecture Overview](architecture.md), [Build System](build-system.md),
[Fault Handling](fault-handling.md), [Memory Model](memory-model.md),
[shared/riscv-step/README.md](../shared/riscv-step/README.md)
