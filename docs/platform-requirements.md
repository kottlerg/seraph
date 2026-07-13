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

- The psABI / toolchain feature level and target JSONs — [build-system.md](build-system.md#custom-targets).
- The mechanism of W^X, NX, SMEP/SMAP, SUM/PMP, and tagged-TLB tagging — [memory-model.md](memory-model.md).
- IOMMU discovery and the DMA safety model — [device-management.md](device-management.md).
- Console / serial ownership across boot — [console-model.md](console-model.md).
- The UEFI handoff, firmware tables, and `BootInfo` surface — [bootstrap.md](bootstrap.md) and
  [`abi/boot-protocol/`](../abi/boot-protocol/).

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

- **x86-64**: x86-64-v3 (AVX2, BMI1/2, FMA, MOVBE, F16C, LZCNT, POPCNT, plus XSAVE) — Haswell-class
  instruction selection.
- **riscv64**: RVA23U64 (RV64GCV plus Zba/Zbb/Zbs).

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
  assertion) refuses hardware that lacks it. W^X, isolation, and the floor depend on these.
- **Opportunistic** — used when present, not required. Absence degrades performance or a
  non-essential capability, never correctness.
- **Unsupported** — not used, and in some cases actively refused. Listed so absence is never
  mistaken for an oversight, and so a future requirement is a deliberate floor change.

---

## x86-64 Classification

### Required

- **Instruction baseline** — the x86-64-v3 set above (AVX2, BMI1/2, FMA, MOVBE, F16C, LZCNT,
  POPCNT, CMPXCHG16B) and `XSAVE`.
- **Long mode, `SYSCALL`/`SYSRET`, `NX` (`EFER.NXE`)** — the privilege and W^X substrate. The
  kernel sets bit 63 on non-executable PTEs; `NX` is mandatory.
- **`CR0.WP`** — supervisor write-protect. Without it, ring-0 writes bypass read-only page
  permissions and the kernel's own W^X is unenforced. The kernel sets and requires it on every CPU.
- **SMEP and SMAP** — supervisor execution and access prevention. See [memory-model.md](memory-model.md).
- **PCID and INVPCID** — address-space-tagged TLBs. The kernel assigns a tag per address space and
  elides the per-switch flush; see [memory-model.md](memory-model.md).
- **Invariant TSC** — a constant-rate timestamp counter, the basis of timekeeping.
- **8254 PIT** — used once at boot to calibrate the TSC (and the local-APIC timer for the
  periodic-fallback tick path).
- **Local APIC and an I/O APIC** — interrupt delivery and routing.
- **CPUID extended-topology leaf 0x0B** — SMT/topology enumeration.
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
- **AES-NI and SHA-NI** — crypto acceleration.
- **CET (shadow stack / IBT)** — control-flow integrity, when enabled.
- **TSC-deadline timer mode** — drives the preemption tick when present; the periodic APIC
  timer is the fallback.
- **EFI_RNG_PROTOCOL** — an additional boot entropy seed.
- **GOP framebuffer** — graphical console; a headless serial-only boot is valid.
- **PCIe ECAM (MCFG)** — discovered when firmware publishes it; not required by the kernel.

### Unsupported

- **AVX-512 / x86-64-v4** — server-class; never required, never depended upon.
- **LA57 (5-level paging)** — the kernel uses 4-level paging.
- **1 GiB huge pages, global pages (`PGE`), `FSGSBASE`/`SWAPGS`, MTRR reprogramming, HPET, the legacy
  8259 PIC** — not used. (The kernel sets per-CPU GS through `IA32_GS_BASE` and never swaps; it
  relies on firmware's default PAT and leaves the 8259 masked.)
- **Legacy BIOS / multiboot** — boot is UEFI-only.
- **Secure Boot, TPM, RTC** — not boot dependencies.

---

## riscv64 Classification

### Required

- **Instruction baseline** — RV64GCV plus Zba/Zbb/Zbs. The Vector extension is a hard requirement;
  the kernel refuses a hart reporting `vlenb == 0`.
- **Supervisor isolation — `SUM` and PMP** — supervisor-user access control and physical-memory
  protection (PMP is established by M-mode firmware). See [memory-model.md](memory-model.md).
- **ASID-tagged TLBs** — the `satp` ASID field, the RISC-V counterpart of PCID; see
  [memory-model.md](memory-model.md).
- **AIA — Ssaia, with APLIC and IMSIC** — the interrupt controller. PLIC is unsupported.
- **Sstc — `stimecmp`** — the supervisor timer.
- **Svpbmt, Svinval, Svnapot** — page-based memory types, fine-grained fence invalidation, and
  NAPOT page encodings. Svade is the baseline A/D-bit model.
- **Ssstateen / Smstateen** — state-enable CSRs, required for the hardening posture.
- **Zkr seed CSR** — the supervisor-accessible hardware entropy source.
- **`time` CSR (Zicntr)** — the timestamp source.
- **Address translation**: one of Sv39/Sv48/Sv57, negotiated at boot (DTB
  `mmu-type` plus a `satp` write-probe; the widest confirmed mode wins). Sv39
  is the RVA23 mandatory minimum and the refusal floor; Sv48 is the standing
  default in CI and development.
- **UEFI firmware over an SBI (M-mode) implementation; a device tree or ACPI** — the boot and
  discovery path. SBI HSM is required to start secondary harts.
- **MMIO ns16550a UART** — the boot/console serial device (base discovered via firmware tables,
  with a platform fallback).

### Opportunistic

- **Svadu** — hardware A/D-bit updates (Svade is the required baseline).
- **Sv57** — a larger-VA expansion above the Sv48 default; used when the
  platform advertises and the probe confirms it.
- **Zvk vector crypto** — crypto acceleration.
- **EFI_RNG_PROTOCOL, GOP framebuffer, PCIe ECAM** — as on x86-64.

### Unsupported

- **PLIC** — replaced by AIA, no fallback.
- **Legacy / embedded RISC-V profiles** — outside the RVA23 floor.
- **Port-mapped I/O** — RISC-V has no port I/O; all device access is MMIO.
- **Cache-block-management instructions (Zicbom/Zicboz/Zicbop)** — not used; the kernel assumes
  cache-coherent DMA.
- **Secure Boot, TPM, RTC** — not boot dependencies.

---

## IOMMU and DMA Confinement

The IOMMU (Intel VT-d, the RISC-V IOMMU extension) is **opportunistic** on both architectures. It
is a platform/chipset feature whose presence and usability vary across the envelope — firmware may
disable it, fuse it off, or omit it on consumer boards and handhelds — so requiring it would exclude
in-envelope hardware.

The IOMMU is discovered and programmed by the userspace device manager, not the kernel. When an
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
  SBI presence at the gate, and the Vector extension and the ASID-tagged TLB at their initialization
  sites (a hart lacking either is refused; emulated RISC-V provides ASID, so unlike x86-64 PCID this
  is gated). Extension requirements introduced by a subsystem (the interrupt controller, the timer,
  the paging extensions) are asserted by that subsystem at its own initialization — the timer, for
  example, refuses to boot unless the bootloader confirmed Sstc (and a timebase frequency) for every
  hart from the firmware tables (ACPI RHCT, or the DTB `/cpus` nodes).

Platform features that are not CPU-detectable (the PIT, UEFI, ACPI/DTB, the UART) are not probed by
the gate; their absence manifests as a boot failure on the discovery path they feed.

---

## Platform Limits

Independent of the feature classification, the kernel imposes two fixed platform limits on both
architectures:

- **Page size** is 4 KiB.
- **Maximum RAM** is approximately 248 GiB. The kernel's boot-time direct-map pool is a fixed-size
  table sized for that ceiling; a platform with more RAM is refused at boot
  (`core/kernel/src/mm/paging.rs`).

---

## Future Architectures

The classification is structured to extend to a third architecture (for example aarch64) without
reshaping the existing sections: the new architecture adds its own `## <arch> Classification`
section with the same Required / Opportunistic / Unsupported subsections, an entry in the floor
definition, and an arch-local `cpu::verify_baseline()`. The targeting envelope and the
required-vs-opportunistic rule are architecture-neutral and unchanged.

---

## Summarized By

[README.md](../README.md), [Architecture Overview](architecture.md), [Memory Model](memory-model.md)
