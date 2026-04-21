# System Bootstrap

End-to-end summary of the boot lifecycle from power-on through handover to
svcmgr. This document is a routing summary; every stage below is authoritatively
owned by a component-scope document, and the full specification of any stage
is found by following the link.

---

## Power-on to kernel entry (bootloader)

UEFI firmware loads the bootloader from the EFI System Partition; the
bootloader reads `boot.conf`, loads the kernel and init ELFs plus any boot
modules, queries the UEFI memory map, builds initial page tables, calls
`ExitBootServices`, populates `BootInfo`, and jumps to the kernel entry point.
The sequence is specified in ten bootloader steps in
[`boot/docs/boot-flow.md`](../boot/docs/boot-flow.md).

---

## Kernel entry (ABI gate)

The bootloader hands control to the kernel at a single entry-point symbol
with `BootInfo` supplied by register. The CPU state, memory state, and
`BootInfo` layout established at this gate are specified in
[`boot-protocol.md`](boot-protocol.md).

---

## Kernel initialization phases

The kernel runs ten numbered phases (kernel phase 0 through kernel phase 9)
from entry-point validation to scheduler handoff. Authoritative enumeration
and per-phase failure behavior are in
[`kernel/docs/initialization.md`](../kernel/docs/initialization.md). Phase 7
is the capability-minting phase: the kernel synthesizes the initial
capability set from `BootInfo.platform_resources` and populates init's root
CSpace. Downstream documents
([`device-management.md`](device-management.md),
[`userspace-memory-model.md`](userspace-memory-model.md)) anchor their
timing claims to kernel phase 7.

---

## init spawn (ABI gate)

At the end of kernel phase 9, the kernel maps the init image — pre-parsed
by the bootloader and delivered via `BootInfo.init_image` — into a new
address space, creates init's initial thread, and enters userspace. The
init-image contract is specified in [`boot-protocol.md`](boot-protocol.md)
under "InitImage"; the kernel side of the handoff is the last phase in
[`kernel/docs/initialization.md`](../kernel/docs/initialization.md). The
kernel's only baked-in knowledge of userspace is this handoff — it has no
notion of `init`, `procmgr`, or any other userspace role beyond starting
whatever binary was staged in the init slot.

---

## Userspace bootstrap (init)

The init binary starts procmgr via raw syscalls (no IPC yet), requests
procmgr to start the remaining early services (devmgr, svcmgr, drivers,
vfsd, optionally netd), delegates the appropriate subsets of its initial
capability set to each service, registers services with svcmgr, and exits.
Role-level description is in [`init/README.md`](../init/README.md);
authoritative stage enumeration lives in
[`init/docs/bootstrap.md`](../init/docs/bootstrap.md). Alternative init
binaries (for example [`ktest/README.md`](../ktest/README.md)) may occupy
the init slot for specialized purposes and follow their own bootstrap
shape.

---

## Handover to svcmgr

Once init exits, svcmgr is the resident supervisor: it monitors registered
services, handles restarts, and holds the direct process-creation
capabilities needed to recover procmgr itself. See
[`svcmgr/README.md`](../svcmgr/README.md).

---

## Summarized By

None
