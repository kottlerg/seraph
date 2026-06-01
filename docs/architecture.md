# Architecture Overview

This document describes Seraph's component structure and the boundaries between
kernel mechanisms and userspace policy.

---

## Project Goals

- Minimal, modular microkernel; most functionality in userspace
- Capability-based security model throughout
- Clear component boundaries with explicit IPC contracts
- Architecture-specific code isolated behind a shared arch-dispatch surface
- Self-hosting as a long-term goal

Seraph defines its own native interfaces; POSIX API compatibility is not
a goal. Filesystem formats and network protocols may be adopted as data
formats, not as API commitments. Seraph does not provide binary
compatibility with other operating systems. 32-bit and legacy x86 are
not targeted. Userspace targets these native interfaces through standard
language runtimes (`ruststd`, `libc`), not through compatibility shims.

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
First userspace process. Bootstraps tier-1 services (memmgr, procmgr),
spawns the remaining early services, delegates per-service capabilities,
then exits. See [`process-lifecycle.md`](process-lifecycle.md) and
[`services/init/README.md`](../services/init/README.md).

**memmgr**
Owns the userspace RAM frame pool and serves frame-allocation IPC to
std-built services. `no_std`. See
[`userspace-memory-model.md`](userspace-memory-model.md) and
[`services/memmgr/README.md`](../services/memmgr/README.md).

**procmgr**
Process lifecycle manager. All post-boot process creation, ELF loading,
and teardown go through procmgr. See
[`process-lifecycle.md`](process-lifecycle.md) and
[`services/procmgr/README.md`](../services/procmgr/README.md).

**svcmgr**
Service health monitor. Detects crashes and requests restarts via
procmgr; holds the fallback capabilities needed to restart procmgr
itself. See [`services/svcmgr/README.md`](../services/svcmgr/README.md).

**devmgr**
Device manager. Enumerates platform hardware, spawns driver processes,
and delegates per-device capabilities. See
[device-management.md](device-management.md).

**pwrmgr**
Power manager. Owns the platform shutdown surface and serves
`SHUTDOWN` / `REBOOT` IPC. See
[`services/pwrmgr/README.md`](../services/pwrmgr/README.md).

**drivers**
Isolated userspace processes. Access hardware only through capabilities
granted by devmgr.

**vfsd**
Unified filesystem namespace over separate fs driver processes. The
system-scope composition (cap-delegation chain, GPT role-GUID
discovery, mount lifecycle) is specified in [storage.md](storage.md).

**fs drivers**
Separate binaries in `fs/` (FAT, ext4, tmpfs, etc.), launched by vfsd.

**netd**
Network stack. Manages interfaces via driver IPC and exposes socket-
like endpoints to applications.

**logd**
Owner of the master log endpoint; drains log messages from every
process holding a pre-installed log SEND cap. See
[`services/logd/README.md`](../services/logd/README.md).

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

Boot modules (procmgr, memmgr, devmgr, vfsd, virtio-blk, fatfs) are packed into
`\EFI\seraph\bootstrap.bundle` by `cargo xtask build` (see
[`xtask/README.md`](../xtask/README.md) for the producer side and
[`abi/boot-protocol/src/bundle.rs`](../abi/boot-protocol/src/bundle.rs) for the
wire format); the bootloader exposes each entry as a named `BootModule` and
init looks them up by `BootModule.name`.

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
Uses APIC. IOMMU hardware, when present, is discovered and
programmed by devmgr in userspace; the kernel does not touch it.

**RISC‑V**
Embedded or non-standard configurations are not targeted.

Per-arch kernel and userspace target specifications (soft-float / FP
profile, psABI feature floor, microarchitecture pins) are in
[`build-system.md`](build-system.md#custom-targets). Architectural code
isolation rules are in
[coding-standards.md#c-architecture-invariants](coding-standards.md#c-architecture-invariants).

---

## Summarized By

[README.md](../README.md),
[devmgr/README.md](../services/devmgr/README.md),
[init/README.md](../services/init/README.md),
[logd/README.md](../services/logd/README.md),
[memmgr/README.md](../services/memmgr/README.md),
[procmgr/README.md](../services/procmgr/README.md),
[pwrmgr/README.md](../services/pwrmgr/README.md),
[svcmgr/README.md](../services/svcmgr/README.md)

