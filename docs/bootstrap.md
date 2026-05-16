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
[`core/boot/docs/boot-flow.md`](../core/boot/docs/boot-flow.md).

---

## Kernel entry (ABI gate)

The bootloader hands control to the kernel at a single entry-point symbol
with `BootInfo` supplied by register. The CPU state and register contents
at this gate are specified in
[`core/boot/docs/kernel-handoff.md`](../core/boot/docs/kernel-handoff.md); the
`BootInfo` layout and `BOOT_PROTOCOL_VERSION` contract are owned by the
[`abi/boot-protocol/`](../abi/boot-protocol/) crate.

---

## Kernel initialization phases

The kernel runs ten numbered phases (kernel phase 0 through kernel phase 9)
from entry-point validation to scheduler handoff. Authoritative enumeration
and per-phase failure behavior are in
[`core/kernel/docs/initialization.md`](../core/kernel/docs/initialization.md). Phase 7
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
init-image contract is specified by the `InitImage` type in the
[`abi/boot-protocol/`](../abi/boot-protocol/) crate; the kernel side of
the handoff is the last phase in
[`core/kernel/docs/initialization.md`](../core/kernel/docs/initialization.md). The
kernel's only baked-in knowledge of userspace is this handoff — it has no
notion of `init`, `procmgr`, or any other userspace role beyond starting
whatever binary was staged in the init slot.

---

## Userspace bootstrap (init)

The init binary starts memmgr and procmgr via raw syscalls (no IPC yet),
transferring the RAM frame pool to memmgr and minting procmgr's
`memmgr_endpoint_cap` so procmgr's std heap bootstrap finds memmgr on its
first call. Init then requests procmgr to start the remaining early services
(devmgr, svcmgr, drivers, vfsd, optionally netd), delegates the appropriate
subsets of its initial capability set to each service, registers services
with svcmgr, and exits.

At the end of init's Phase 2 — after the root mount completes but before
Phase 3 spawns any other service — init spawns real `logd` from
`/bin/logd` and hands it the receive side of the master log endpoint
via `log_labels::HANDOVER_PULL`. init-logd's receive loop terminates
on the final handover reply. The kernel endpoint object is unchanged
across the transition, so every pre-existing tokened SEND cap (held
by memmgr, procmgr, every tier-1 service) continues to work without
re-derivation; only the holder of the RECV cap changes. See
[`services/logd/README.md`](../services/logd/README.md) and
[`services/logd/docs/handover-protocol.md`](../services/logd/docs/handover-protocol.md). The system-scope userspace boot order lives in
[`process-lifecycle.md`](process-lifecycle.md); role-level description is in
[`services/init/README.md`](../services/init/README.md); authoritative stage
enumeration lives in
[`services/init/docs/bootstrap.md`](../services/init/docs/bootstrap.md).
Alternative init binaries (for example
[`core/ktest/README.md`](../core/ktest/README.md)) may occupy the init slot
for specialized purposes and follow their own bootstrap shape.

---

## Handover to svcmgr

Once init exits, svcmgr is the resident supervisor: it monitors registered
services, handles restarts, and holds the direct process-creation
capabilities needed to recover procmgr itself. See
[`services/svcmgr/README.md`](../services/svcmgr/README.md).

---

## Summarized By

None
