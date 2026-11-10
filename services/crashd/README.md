# crashd

The crash service: reports each process that dies on a fault to the system log, then ends the
faulting thread as the kernel would have.

---

## Role

A thread killed by a fault leaves only its exit reason; its registers are gone by then. crashd
receives the fault while the thread is still stopped, reads it, and logs one marked block with the
fault, the registers, the bytes at the instruction pointer, the image placement, and a stack walk,
in the format [docs/block-format.md](docs/block-format.md) defines. It then declines the fault
(`FAULT_REPLY_KILL`), so the thread dies with the exit reason and the death flow it would have had
with no handler ([docs/fault-handling.md](../../docs/fault-handling.md) § Crash Reports). crashd
never writes to the filesystem.

svcmgr starts crashd from `rootfs/config/svcmgr/services/crashd.svc`, which sets
`debug_authority = yes` ([`.svc` Service Definitions](../svcmgr/docs/service-definitions.md)).
Whether a system reports crashes is a staging decision: an image without the recipe has no crash
service, and a faulting process dies as it does with no handler bound.

How crashd registers with procmgr, handles each fault under a 2 s bound, and which processes and
threads it cannot report is in [docs/operation.md](docs/operation.md).

---

## Source Layout

```
crashd/
├── Cargo.toml
├── README.md
├── docs/
│   ├── block-format.md    # The block's lines and fields: the symbolizer's contract
│   └── operation.md       # Startup, per-fault handling, bounds, limits
└── src/
    ├── main.rs            # Registration, the fault loop, the reading, the watchdog
    └── arch/
        ├── mod.rs         # Architecture-dispatch surface
        ├── x86_64/
        │   └── mod.rs     # Register-file layout
        └── riscv64/
            └── mod.rs     # Register-file layout
```

The block's emitter and the stack scan are `shared/crash-report`
([shared/crash-report/README.md](../../shared/crash-report/README.md)), host-tested there.

---

## Testing

The `crashme` fixture faults on purpose in both kinds
([programs/crashme/README.md](../../programs/crashme/README.md)); the usertest boot runs it, and
`cargo xtask test-crash-report` checks the blocks in that boot's log
([docs/testing.md](../../docs/testing.md) § Crash reports). svctest's `crash_endpoint` phase drives
procmgr's side, registration, handover, and take-back, with svctest as the crash service.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/block-format.md](docs/block-format.md) | The block's lines and fields |
| [docs/operation.md](docs/operation.md) | Startup, per-fault handling, bounds, limits |
| [docs/fault-handling.md](../../docs/fault-handling.md) | § Crash Reports, § Reply (`FAULT_REPLY_FORWARD`), § Asynchronous Upcalls |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | § Process Death |
| [services/procmgr/docs/ipc-interface.md](../procmgr/docs/ipc-interface.md) | `REGISTER_CRASH_SERVICE`, `ATTACH_PROCESS`, `DECLARE_NO_DEBUG` |
| [services/svcmgr/docs/service-definitions.md](../svcmgr/docs/service-definitions.md) | `debug_authority` |
| [docs/testing.md](../../docs/testing.md) | § Crash reports |

---

## Summarized By

[Fault Handling](../../docs/fault-handling.md), [Testing](../../docs/testing.md)
