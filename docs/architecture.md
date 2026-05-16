# Architecture Overview

This document describes Seraph's component structure and the boundaries between
kernel mechanisms and userspace policy.

---

## Project Goals

- Minimal, modular microkernel; most functionality in userspace
- Capability-based security model throughout
- Clear component boundaries with explicit IPC contracts
- Architecture-specific code isolated behind shared traits
- Self-hosting as a long-term goal

Seraph does not provide binary compatibility with other operating systems.
32-bit and legacy x86 are not targeted.

---

## Philosophy

Seraph is a microkernel‑based operating system. The kernel is a minimal, trusted
component that provides only core mechanisms: isolation, communication, scheduling,
memory management, and capability enforcement.

All policy and services live in userspace.

Expanding kernel scope increases the TCB and MUST be treated as an architectural
decision.

---

## Kernel Responsibilities

The kernel provides only the core mechanisms required to support the system.

The kernel is responsible for:

**IPC**
Message delivery between processes, including endpoint management and asynchronous
notifications. The kernel enforces that communication occurs only via authorised
capabilities and does not interpret message contents.

**Scheduling**
Preemptive, priority‑based scheduling across all CPUs. Userspace may freely alter
priority to some level; changes beyond a certain level require explicit authority
via capabilies.

**Memory management**
Physical frame allocation, virtual address space management, and page table
maintenance. The kernel enforces isolation between address spaces and explicit,
capability‑controlled sharing.

**Capabilities**
The sole access control mechanism. All resources—memory regions, IPC endpoints,
interrupt lines, and CPU time—are represented as capabilities and enforced
unconditionally by the kernel. See [capability-model.md](capability-model.md)
for the full model.

The kernel does not implement filesystems, device drivers, network stacks, user
management, or other policy. These components run in userspace.

---

## System Architecture

All inter-component communication crosses the kernel via IPC. There are no shared
memory shortcuts between services except where explicitly established as a
capability-granted shared mapping.

---

## Userspace Services

System functionality beyond core mechanisms is implemented in userspace as isolated
services and applications. All services communicate exclusively via IPC and operate
under explicit capability grants.

**init**
First userspace process. Starts memmgr and procmgr, requests early services
(devmgr, svcmgr, drivers, vfsd), delegates capabilities, then hands its own
`AddressSpace` / `CSpace` / `Thread` caps plus every reclaimable Frame cap
(segments, stack, `InitInfo` pages, IPC buffer) to procmgr via
`REGISTER_INIT_TEARDOWN` and exits. Procmgr's death-EQ observer fires on
the exit and reclaims every init resource — kernel objects torn down,
Frame caps donated to memmgr's pool. After reap, zero init residue
remains in the system. See [`abi/boot-protocol/`](../abi/boot-protocol/),
[`process-lifecycle.md`](process-lifecycle.md) §"Init reap", and
`services/procmgr/src/init_reap.rs`.

**memmgr**
Owns the userspace RAM frame pool. Receives all RAM Frame caps from init at
boot and serves frame allocation IPC to all std-built services. Tracks
per-process frame ownership and reclaims on process death. `no_std`. See
[`process-lifecycle.md`](process-lifecycle.md) and
[`userspace-memory-model.md`](userspace-memory-model.md).

**procmgr**
Process lifecycle manager. All post-boot process creation, ELF loading, and
teardown go through procmgr. Procmgr is itself a memmgr client and
bootstraps its heap by calling memmgr.

**svcmgr**
Service health monitor. Detects crashes and requests restarts via procmgr; holds
direct process-creation capabilities to restart procmgr itself.

**devmgr**
Device manager. Receives platform resource capabilities from init, enumerates devices,
spawns driver processes, and delegates per-device capabilities.
See [device-management.md](device-management.md).

**pwrmgr**
Power manager. Sole holder of the raw platform shutdown caps (ACPI
reclaimable Frame caps + `IoPortRange` on x86-64; `SbiControl` on
RISC-V). Exposes `SHUTDOWN` / `REBOOT` over IPC, gated by a
`SHUTDOWN_AUTHORITY` token bit. usertest invokes `SHUTDOWN` through a
tokened cap on the success path so naked `cargo xtask run` exits
cleanly. See [`services/pwrmgr/README.md`](../services/pwrmgr/README.md).

**drivers**
Isolated userspace processes. Access hardware only through capabilities granted by
devmgr.

**vfsd**
Unified filesystem namespace over separate fs driver processes. Delegates operations
to the appropriate driver.

**fs drivers**
Separate binaries in `fs/` (FAT, ext4, tmpfs, etc.), launched by vfsd. Communicate
with block drivers via IPC.

**netd**
Network stack. Manages interfaces via driver IPC and exposes socket-like endpoints
to applications.

**logd**
Post-mount owner of the master log endpoint. Every userspace
process holds a pre-installed tokened SEND cap on the same kernel
endpoint (seeded by procmgr at spawn time into
`ProcessInfo.log_send_cap`); logd drains the RECV side. Init runs an
interim `init-logd` thread until logd is launched at the end of init's
Phase 2, then hands over via `log_labels::HANDOVER_PULL` (the kernel
endpoint object is unchanged across the handover, so existing tokened
SEND caps survive without re-derivation). Subscribes to procmgr's
death-notification cascade for per-sender slot reclamation.

**base**
Unprivileged applications (shell, terminal, editor, core tools).

---

## Kernel Primitives vs. Userspace Abstractions

The kernel manages three primitive object types:

- **Thread** — a schedulable unit of execution with a saved register state, a priority,
  and bindings to an AddressSpace, a CSpace, and an IPC buffer.
- **AddressSpace** — a virtual address space with a page table root and a set of
  frame mappings. Revoking an AddressSpace capability stops all threads bound to it.
- **CSpace** — a capability space: a growable array of capability slots that a thread
  uses to name kernel objects.

The kernel has no "Process" object. A **process** is a userspace convention: a group
of threads sharing an AddressSpace and a CSpace, managed by procmgr. The kernel
enforces isolation via AddressSpace and CSpace boundaries, not via a process abstraction.

---

## Bootstrap Sequence

The end-to-end boot lifecycle — power-on through svcmgr handover — is
summarized in [`bootstrap.md`](bootstrap.md). Authoritative enumerations
live in the component scope:

- Bootloader steps 1–10 — [`core/boot/docs/boot-flow.md`](../core/boot/docs/boot-flow.md).
- Kernel phases 0–9 — [`core/kernel/docs/initialization.md`](../core/kernel/docs/initialization.md).
- Userspace boot order (init → memmgr → procmgr → svcmgr) and
  ProcessInfo/InitInfo handover — [`process-lifecycle.md`](process-lifecycle.md).
- init's userspace bootstrap — [`services/init/README.md`](../services/init/README.md) and
  [`services/init/docs/bootstrap.md`](../services/init/docs/bootstrap.md).

Boot modules (procmgr, devmgr, drivers, etc.) are configurable via `boot.conf`
per [`abi/boot-protocol/`](../abi/boot-protocol/); the minimum set is procmgr, devmgr,
one block driver, one FS driver, and vfsd.

---

## Driver Model

Device drivers run as unprivileged userspace processes. No driver code executes in
kernel space. Hardware access is granted explicitly via capabilities and is fully
revocable.

**MMIO**
Physical MMIO regions are mapped into a driver’s address space under capability
control. Once mapped, drivers access registers directly without kernel mediation.

**Port I/O (x86‑64 only)**
Drivers receive an IoPortRange capability for assigned port ranges. Binding this
capability enables direct execution of port I/O instructions for those ranges.
Access is revoked automatically when the capability is revoked. RISC‑V does not
support port I/O.

**DMA**
DMA isolation is exclusively a userspace concern. devmgr discovers IOMMU
hardware (via firmware-table passthrough), programs the translation tables
itself, and authorises DMA on a per-device basis. The kernel reads no
IOMMU registers, holds no per-device DMA state, and exposes no DMA-grant
syscall. Frame physical-base addresses (which DMA-issuing drivers program
into device transports) reach drivers through memmgr's `REQUEST_FRAMES`
reply. See `device-management.md`.

**Interrupts**
Hardware interrupts are received by the kernel and delivered to drivers as
asynchronous IPC notifications. Drivers re‑enable interrupt delivery explicitly
after handling.

---

## IPC (summary — [ipc-design.md](ipc-design.md))

All inter‑process communication occurs via the kernel’s IPC mechanism. Shared memory
is established only via explicit capability-granted mappings.

- **Synchronous calls** for structured request/reply between services.
- **Asynchronous notifications** for interrupts and completion signals.

---

## Memory Model (summary — [memory-model.md](memory-model.md))

Higher-half kernel layout on both architectures. Each process has an isolated address
space. The kernel enforces W^X at the page table level.

---

## Capability Model (summary — [capability-model.md](capability-model.md))

Capabilities are the sole access control mechanism. Every resource is represented by
a capability; threads MUST hold a valid capability to access any resource.

---

## Target Platforms

Seraph targets 64‑bit architectures with modern MMU and privilege support.

**x86‑64**
Uses APIC and PCIDs. IOMMU hardware, when present, is discovered and
programmed by devmgr in userspace; the kernel does not touch it. 32-bit
and legacy x86 are not supported. The kernel is soft-float (no SSE/AVX/MMX);
userspace targets the **x86-64-v3** psABI feature level (ratified 2020) —
SSE2/3/SSSE3/SSE4.1/4.2, AVX, AVX2, FMA, BMI1/2, LZCNT, MOVBE, F16C, POPCNT.

**RISC‑V**
The kernel is **RV64IMAC** soft-float (LP64 ABI); userspace targets the
**RVA23U64** profile (RVA23 v1.0, ratified 2024-10-21) — IMAFDCV plus the
Zba/Zbb/Zbs bitmanip set, hard-float LP64D ABI. Embedded or non-standard
configurations are not targeted. The kernel never touches F/D/V state
itself; userspace FP/V state is preserved across preemption by a lazy
save/restore discipline.

See [coding-standards.md#c-architecture-invariants](coding-standards.md#c-architecture-invariants)
for the architectural code isolation rules.

---

## Non-Goals

**POSIX API compatibility.**
Seraph defines its own native interfaces. Filesystem formats and network protocols
may be adopted as data formats, not as API commitments.

**Binary compatibility with other operating systems.**
Seraph does not aim to run Linux or other OS binaries.

---

## Summarized By

[README.md](../README.md), [init/README.md](../services/init/README.md), [memmgr/README.md](../services/memmgr/README.md), [procmgr/README.md](../services/procmgr/README.md)

