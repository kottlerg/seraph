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

1. **Start memmgr** — init contains a minimal ELF parser (from
   `shared/elf`) and uses raw syscall wrappers (from `shared/syscall`)
   to create memmgr's process directly, without IPC. Init transfers the
   full RAM Frame cap pool from its own CSpace into memmgr's CSpace via
   the derive-twice pattern, then serves a single bootstrap-IPC round
   carrying the slot range so memmgr knows where its pool lives.

2. **Start procmgr** — init creates procmgr the same way (raw syscalls,
   no IPC). Before starting procmgr's thread, init calls
   `memmgr.REGISTER_PROCESS` to mint procmgr's `memmgr_endpoint_cap`
   and writes it into procmgr's `ProcessInfo` so procmgr's std heap
   bootstrap reaches memmgr on its first call.

3. **Request early service startup** — init requests procmgr to start
   the remaining early services in order: devmgr, svcmgr, drivers, VFS,
   and optionally net. Tier-1 services (devmgr, vfsd, drivers) are
   spawned via boot-module `CREATE_PROCESS` *before* init has a
   namespace cap, so they hold none — their `ProcessInfo.system_root_cap`
   is zero, which is correct for kernel-adjacent services that have no
   business reading the filesystem.

4. **Acquire the seed system-root cap** — after the cmdline-driven
   root mount completes, init issues
   `vfsd_labels::GET_SYSTEM_ROOT_CAP` to vfsd. The returned tokened
   SEND on vfsd's namespace endpoint at `NodeId::ROOT` with full
   rights is init's seed: every later Phase 3 child receives a
   `cap_copy` of it via `procmgr_labels::CONFIGURE_NAMESPACE`. Init
   is the cap-distribution authority for tier-3 services; there is no
   procmgr broadcast.

5. **Delegate capabilities** — for each service, init derives and
   transfers the appropriate subset of its initial capabilities via
   IPC. Init retains derived intermediary copies (for potential
   revocation), not the roots.

6. **Spawn Phase 3 services from VFS** — svcmgr, crasher, pwrmgr,
   usertest, hello, stdiotest are loaded by walking init's seed
   system-root cap to `/bin/<name>`, then issuing
   `procmgr_labels::CREATE_FROM_FILE` with the resolved file cap.
   Each child receives a `cap_copy` of init's root via
   `CONFIGURE_NAMESPACE` before start. See
   [`docs/namespace-model.md`](../../docs/namespace-model.md) for the
   namespace-cap distribution invariants.

   pwrmgr is spawned before usertest so init can derive two SEND
   caps on pwrmgr's service endpoint — one with the
   `SHUTDOWN_AUTHORITY` token, one without — and install both as
   seed caps in usertest's bootstrap round. usertest invokes
   `pwrmgr_labels::SHUTDOWN` through the authorised cap on the
   success path so naked `cargo xtask run` exits cleanly. The
   un-tokened twin drives `pwrmgr_cap_deny_phase`, which asserts the
   gate rejects un-tokened callers. See
   [`services/pwrmgr/README.md`](../pwrmgr/README.md).

7. **Register services with svcmgr** — before exiting, init registers
   all started services with svcmgr along with their restart policies
   and capability sets.

8. **Exit** — init calls `sys_thread_exit`. It holds no long-lived
   state, no supervision capability, and no restart authority. svcmgr
   takes over.

memmgr and procmgr are the only two processes init creates via raw
syscalls. Every later service is spawned via IPC to procmgr.

After the split, the only `no_std` userspace services in the running
system are init and memmgr; everything else is std-built.

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
| [docs/architecture.md](../../docs/architecture.md) | Bootstrap sequence, init/memmgr/procmgr/svcmgr roles |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Userspace boot order, ProcessInfo/InitInfo handover, authority transfer |
| [abi/boot-protocol/](../../abi/boot-protocol/) | InitImage, boot modules, initial CSpace |
| [abi/init-protocol/](../../abi/init-protocol/) | Kernel-to-init handover (`InitInfo`) |
| [docs/capability-model.md](../../docs/capability-model.md) | Initial capability distribution |
| [services/memmgr/README.md](../memmgr/README.md) | First service init creates; receives the RAM frame pool |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

None
