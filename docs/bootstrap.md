# System Bootstrap

End-to-end summary of the boot lifecycle from power-on through handover to svcmgr.

Every stage below is authoritatively owned by a component-scope
document; the full specification of any stage is found by following
the link.

---

## Power-on to kernel entry (bootloader)

UEFI firmware loads the bootloader from the EFI System Partition; the
bootloader reads `\EFI\seraph\bootstrap.bundle` (a Seraph-defined container
that packs init and every boot module into one file — see
[`abi/boot-protocol::bundle`](../abi/boot-protocol/src/bundle.rs)), loads
the kernel from `\EFI\seraph\kernel`, ELF-parses the bundle entry named
`init` into `BootInfo.init_image`, exposes every other bundle entry as a
named `BootModule`, builds initial page tables, queries the final UEFI
memory map, calls `ExitBootServices`, populates `BootInfo`, and jumps to the
kernel entry point. The sequence is specified in ten bootloader steps in
[`core/boot/docs/boot-flow.md`](../core/boot/docs/boot-flow.md).

Boot-time configuration on disk consists of only the two ESP files
named above, the optional presence-only `\EFI\seraph\nokaslr` KASLR
override knob
([boot-flow.md § Step 5d](../core/boot/docs/boot-flow.md#step-5d-apply-the-kaslr-slide),
[elf-loading.md § File Paths](../core/boot/docs/elf-loading.md#file-paths)),
and the bootloader binary itself, installed both at `\EFI\seraph\boot.efi`
and at the EFI fallback path
([build-system.md § Build Output: the Sysroot](build-system.md#build-output-the-sysroot)).
`BootInfo` carries no kernel command
line; root-partition identity comes from GPT type-GUID role discovery,
performed by vfsd
([storage.md § GPT Role-GUID Discovery](storage.md#gpt-role-guid-discovery)),
and ktest options are baked into ktest's compile-time defaults
([ktest README § Compile-time options](../core/ktest/README.md#compile-time-options)).

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
is the capability-minting phase: the kernel mints the initial capability
set from `BootInfo.memory_map` (via the drained buddy), `mmio_apertures`,
`kernel_mmio` (the RISC-V console UART), `acpi_rsdp`, `device_tree`,
`modules`, and the `reclaim_ranges` entries without `RECLAIM_FLAG_LATE`,
and populates the root CSpace that Phase 9 hands to init (see
[initialization.md § Phase 7](../core/kernel/docs/initialization.md#phase-7-capability-system);
the full initial set is enumerated in
[capability-model.md § Initial Capability Distribution](capability-model.md#initial-capability-distribution)).
Late reclaim ranges are minted into that CSpace in
[Phase 8](../core/kernel/docs/initialization.md#phase-8-scheduler-and-smp-bringup).
Downstream documents
([`device-management.md`](device-management.md),
[`userspace-memory-model.md`](userspace-memory-model.md)) anchor their
timing claims to kernel phase 7.

---

## init spawn (ABI gate)

In kernel phase 9, the kernel maps the init image — pre-parsed
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

The init binary creates memmgr and procmgr via raw syscalls (process
creation through procmgr IPC is not yet available), transferring the RAM
frame pool to memmgr and minting procmgr's
`memmgr_endpoint_cap` so procmgr's std heap bootstrap finds memmgr on its
first call. Init then requests procmgr to start devmgr and vfsd, and later svcmgr
from `/services/svcmgr` (devmgr spawns the drivers; svcmgr launches every
other service post-handover), delegates the appropriate
subsets of its initial capability set to each service, endows svcmgr with the
handover endowment, and exits.

Init runs a second thread, init-logd, that drains the master log endpoint and
writes lines to serial directly from early boot onward. svcmgr launches and
supervises the real [`logd`](../services/logd/README.md) post-handover, minting its
bootstrap caps from the reserved log-sink sources init endows; the real `logd` then takes the
receive side of the master log endpoint and pulls init-logd's captured history. The
kernel endpoint object is unchanged across the transition, so existing badged
SEND caps continue to work without re-derivation. See
[`services/logd/docs/handover-protocol.md`](../services/logd/docs/handover-protocol.md).

The system-scope userspace boot order lives in
[`process-lifecycle.md`](process-lifecycle.md); role-level description
is in [`services/init/README.md`](../services/init/README.md);
authoritative stage enumeration lives in
[`services/init/docs/bootstrap.md`](../services/init/docs/bootstrap.md).
Alternative init binaries (for example
[`core/ktest/README.md`](../core/ktest/README.md)) may occupy the init
slot for specialised purposes and follow their own bootstrap shape.

---

## Handover to svcmgr

At the end of init's Handover stage (logged as `phase 3`), init
transfers its kernel-object and reclaimable Memory capabilities to
procmgr via `REGISTER_INIT_TEARDOWN` and exits; once both init threads
have exited, procmgr tears down init's threads and AddressSpace, donates
the Memory caps to memmgr's pool, and drops its reference to init's
CSpace. The caps left in that kernel-pinned root CSpace stay alive but
unreachable; releasing them is design intent, not yet implemented
([#443](https://github.com/kottlerg/seraph/issues/443)). See
[`process-lifecycle.md`](process-lifecycle.md) §"Init reap".

Once init exits, svcmgr is the resident supervisor. See
[`services/svcmgr/README.md`](../services/svcmgr/README.md).

---

## Summarized By

None
