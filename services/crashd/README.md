# crashd

The crash service: reports each process that dies on a fault to the system log, writes an ELF
core of it when its policy names the process, then ends the faulting thread as the kernel would
have.

---

## Role

A thread killed by a fault leaves only its exit reason; its registers are gone by then. crashd
receives the fault while the thread is still stopped, reads it, and logs one marked block with the
fault, the registers, the bytes at the instruction pointer, the image placement, and a stack walk,
in the format [docs/block-format.md](docs/block-format.md) defines. It then declines the fault
(`FAULT_REPLY_KILL`), so the thread dies with the exit reason and the death flow it would have had
with no handler ([docs/fault-handling.md](../../docs/fault-handling.md) § Crash Reports).

A page fault memmgr declined for want of memory crashd may hold instead, when its recipe sets a
stall (`CRASHD_OOM_STALL_MS`; the shipped recipe sets 10 000 ms): the fault waits queued on one
of 16 endpoints crashd made at start, no thread of crashd waiting on it, until the memory it waits
for is there, memmgr's pressure level below `CRITICAL` or, for a commit overrun, memmgr's draw room
open, when crashd resumes it, or the stall passes, when crashd reports and declines it.

Before the decline, when the `CORE_DUMP` entry of its recipe's environment names the process,
crashd writes an ELF core of it to `/crash` on the root filesystem, which host `gdb` reads, under
a per-core and a directory byte budget; the recipe sets `CORE_DUMP=no`, so no core is written by
default. The core's directory, names and contents are in [docs/core-format.md](docs/core-format.md).
crashd writes no core of a process a dump waits on, which declares itself so to procmgr: vfsd, the
FAT driver, the block driver, devmgr and the IOMMU driver, through which the core is written, and
logd, which the dump's outcome line waits on. Its recipe grants it `/crash` alone, without the right
to read a core back.

svcmgr starts crashd from `rootfs/config/svcmgr/services/crashd.svc`, which sets
`debug_authority = yes`, and `reserve = yes`, which creates it inside memmgr's system reserve
([`.svc` Service Definitions](../svcmgr/docs/service-definitions.md)).
Whether a system reports crashes is a staging decision: an image without the recipe has no crash
service, and a faulting process dies as it does with no handler bound.

How crashd registers with procmgr, handles each fault under a 2 s bound, holds a fault declined
for want of memory, writes a core under a 60 s bound of its own, and which processes and threads it
cannot report is in
[docs/operation.md](docs/operation.md).

---

## Source Layout

```
crashd/
├── Cargo.toml
├── README.md
├── core-file/             # The core's notes and layout, the policy, the directory (host-tested)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── layout.rs      # ELF header, program headers, the budget's choice of page runs
│       ├── notes.rs       # PT_NOTE contents in the Linux layouts
│       ├── policy.rs      # CORE_DUMP parsing and name matching
│       └── store.rs       # Core names, sequence numbers, eviction
├── fault-bound/           # The per-fault bound's state, shared with the watchdog (host-tested)
│   ├── Cargo.toml
│   └── src/lib.rs
├── oom-hold/              # The hold's decisions: slots, deadlines, repeats (host-tested)
│   ├── Cargo.toml
│   └── src/lib.rs
├── docs/
│   ├── block-format.md    # The block's lines and fields: the symbolizer's contract
│   ├── core-format.md     # The core's directory, names, budgets, and ELF contents
│   └── operation.md       # Startup, per-fault handling, hold, core dump, bounds, limits
└── src/
    ├── main.rs            # Registration, the fault loop, the reading, the watchdog
    ├── dump.rs            # The core dump: stop, read, lay out, store
    ├── hold.rs            # The hold's loop: wait set, redirects, resumes, timeouts
    └── arch/
        ├── mod.rs         # Architecture-dispatch surface
        ├── x86_64/
        │   └── mod.rs     # Register-file layout
        └── riscv64/
            └── mod.rs     # Register-file layout
```

The block's emitter and the stack scan are `shared/crash-report`
([shared/crash-report/README.md](../../shared/crash-report/README.md)), host-tested there. The
state the fault loop and the watchdog share, which generation is being handled, its deadline, and
whether the watchdog has committed to cancel it, is `fault-bound/`, host-tested there
([docs/operation.md](docs/operation.md) § Bounds). Everything about a core that is computation on
what crashd read, its notes, its layout within the budget, the policy, and the directory's names
and eviction, is `core-file/`, host-tested there; `src/dump.rs` does the reading and writing.
Which fault the hold takes, its slot and deadline, and how each hold ends, the repeat rule
included, is `oom-hold/`, host-tested there; `src/hold.rs` makes the endpoints, waits and
replies ([docs/operation.md](docs/operation.md) § Hold).

---

## Testing

The `crashme` fixture faults on purpose in both kinds, on its main thread and on a spawned one
([programs/crashme/README.md](../../programs/crashme/README.md)); the usertest boot runs it, and
``cargo xtask test-crash-report` checks the blocks in that boot's log
([docs/testing.md](../../docs/testing.md) § Crash reports). That boot stages a crashd recipe whose
`CORE_DUMP` names crashme, and the fixture's tester checks the core each faulting mode leaves in
`/crash`. It also sets a stall of 3000 ms, and the tester has the fixture write a page while
memory is critical, once resumed after the hold and once declined when the stall passes.
svctest's `crash_endpoint` phase drives
procmgr's side, registration, handover, and take-back, and the thread list and crash badges an
attach returns, with svctest as the crash service.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/block-format.md](docs/block-format.md) | The block's lines and fields |
| [docs/core-format.md](docs/core-format.md) | The core's directory, names, budgets, and contents |
| [docs/operation.md](docs/operation.md) | Startup, per-fault handling, hold, core dump, bounds, limits |
| [docs/fault-handling.md](../../docs/fault-handling.md) | § Crash Reports, § Reply (`FAULT_REPLY_FORWARD`, `FAULT_REPLY_REDIRECT`), § Asynchronous Upcalls |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | § Process Death |
| [services/procmgr/docs/ipc-interface.md](../procmgr/docs/ipc-interface.md) | `REGISTER_CRASH_SERVICE`, `ATTACH_PROCESS`, `LIST_PROCESSES`, `DECLARE_NO_DEBUG`, `DECLARE_NO_CORE`, `REGISTER_THREAD` |
| [core/kernel/docs/syscalls.md](../../core/kernel/docs/syscalls.md) | `SYS_THREAD_STOP`, `SYS_THREAD_READ_REGS`, `SYS_THREAD_READ_EXT_REGS`, `SYS_THREAD_LIST_PAGES`, `SYS_THREAD_READ_MEM` |
| [services/svcmgr/docs/service-definitions.md](../svcmgr/docs/service-definitions.md) | `debug_authority`, `env`, `namespace` |
| [docs/testing.md](../../docs/testing.md) | § Crash reports |

---

## Summarized By

[Fault Handling](../../docs/fault-handling.md), [Testing](../../docs/testing.md)
