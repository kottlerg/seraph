# init

Bootstrap service and first userspace process. The kernel starts init at the end
of its initialization sequence. Init is a minimal bootstrapper — it starts early
services, delegates all capabilities, and exits. It is not a long-lived service
manager.

---

## Source Layout

```
init/
├── Cargo.toml                  # Workspace member; no_std binary
└── src/
    └── main.rs                 # _start() entry point, bootstrap sequence
```

Init depends on `shared/elf` for ELF parsing (to load procmgr from its boot
module) and `shared/syscall` for raw syscall wrappers (to create procmgr's
process without IPC).

---

## Role

Init's responsibilities are strictly bounded:

1. **Start procmgr** — init contains a minimal ELF parser (from `shared/elf`)
   and uses raw syscall wrappers (from `shared/syscall`) to create procmgr's
   process directly, without IPC. This is the only process init creates itself.

2. **Request early service startup** — init requests procmgr to start the
   remaining early services in order: devmgr, svcmgr, drivers, VFS, and
   optionally net.

3. **Delegate capabilities** — for each service, init derives and transfers the
   appropriate subset of its initial capabilities via IPC. Init retains derived
   intermediary copies (for potential revocation), not the roots.

4. **Register services with svcmgr** — before exiting, init registers all
   started services with svcmgr along with their restart policies and capability
   sets.

5. **Exit** — init calls `sys_thread_exit`. It holds no long-lived state, no
   supervision capability, and no restart authority. svcmgr takes over.

---

## What init does NOT do

- Does not supervise services or restart them on crash (svcmgr's responsibility)
- Does not hold raw process-creation fallback capabilities after delegating them
  to svcmgr
- Does not read a service dependency graph file at runtime (bootstrap order is
  compiled in)
- Does not remain resident after bootstrap completes

---

## Capability flow

At entry, init holds the full initial CSpace populated by the kernel:
- Thread, AddressSpace, and CSpace caps for itself
- Frame caps for all usable physical memory
- One MmioRegion cap per coarse MMIO aperture
- One root Interrupt range cap (narrowed per-device in userspace via `sys_irq_split`)
- IoPortRange cap covering the full 64K port space (x86-64)
- SbiControl cap (RISC-V)
- Read-only Frame caps covering the ACPI RSDP page, each `AcpiReclaimable` region, and the DTB blob — devmgr parses firmware tables from these
- SchedControl cap
- Frame caps for boot module images (procmgr, devmgr, drivers, etc.)

Init derives and transfers these to services using the "derive twice" pattern
(see `docs/capability-model.md`) so it can revoke if needed before svcmgr takes over.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../docs/architecture.md) | Bootstrap sequence, init/procmgr/svcmgr roles |
| [abi/boot-protocol/](../abi/boot-protocol/) | InitImage, boot modules, initial CSpace |
| [docs/capability-model.md](../docs/capability-model.md) | Initial capability distribution |
| [docs/coding-standards.md](../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

None
