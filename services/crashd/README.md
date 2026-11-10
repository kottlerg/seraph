# crashd

The crash service: reports each process that dies on a fault to the system log, then ends the
faulting thread as the kernel would have.

---

## Role

A thread killed by a fault leaves only its exit reason; its registers are gone by then. crashd
receives the fault while the thread is still stopped, reads it, and logs one marked block with the
fault, the registers, the bytes at the instruction pointer, the image placement, and a stack walk
([docs/block-format.md](docs/block-format.md)). It then declines the fault (`FAULT_REPLY_KILL`),
so the thread dies with the exit reason and the death flow it would have had with no handler
([docs/fault-handling.md](../../docs/fault-handling.md) § Crash Reports). crashd never writes to
the filesystem.

svcmgr starts crashd from `rootfs/config/svcmgr/services/crashd.svc`, which sets
`debug_authority = yes` ([`.svc` Service Definitions](../svcmgr/docs/service-definitions.md)).
Whether a system reports crashes is a staging decision: an image without the recipe has no crash
service, and a faulting process dies as it does with no handler bound.

---

## Source Layout

```
crashd/
├── Cargo.toml
├── README.md
├── docs/
│   └── block-format.md    # The block's lines and fields: the symbolizer's contract
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

## Startup

1. crashd declares itself undebuggable to procmgr (`DECLARE_NO_DEBUG`), so no debug-authority
   holder stops it and its own threads are not bound to the endpoint it receives on.
2. Its bootstrap round delivers one cap, a `DEBUG_AUTHORITY`-badged `SEND|GRANT` on procmgr.
3. With it, crashd sends `REGISTER_CRASH_SERVICE` with a Thread cap of its main thread, and receives
   a `RECV` cap on procmgr's crash endpoint, which every process procmgr creates has its exception
   class bound to ([procmgr IPC Interface](../procmgr/docs/ipc-interface.md)
   § `REGISTER_CRASH_SERVICE`).
4. It starts its watchdog thread and receives faults.

When crashd dies, procmgr declines the faults on the endpoint until a respawned crashd registers.

---

## Per Fault

The fault message names the process by its badge, the fault's kind and words, and the instruction
pointer. crashd:

1. sends `ATTACH_PROCESS` for the badge, which returns the Thread caps procmgr holds for the
   process, today its main thread's, and the image's load bias and text bounds;
2. reads the main thread's registers. The read succeeds, and its instruction pointer matches the
   message's, only when the main thread is the one stopped on this fault; the block's `thread` is
   then `main`, and it carries the registers and the stack walk;
3. reads the bytes at the instruction pointer through the same cap, since every thread of the
   process shares its address space;
4. logs the block, then declines the fault with the block's id as the decline reason, which the
   kernel prints on its `fault unhandled` line.

The block is logged before the decline, so the kernel's diagnostic of the kill does not land among
its lines on the serial console.

---

## Bounds

Reading one fault and logging its block is bounded by a watchdog, 2 s per fault (`FAULT_BOUND`). The
attach request can wait on procmgr, and procmgr can be waiting on the faulting process (an fs driver
serving a `CREATE_FROM_FILE` read); a log write can wait on a driver logd writes through. When the
bound passes, the watchdog stops and starts the receiving thread, which cancels the request it
waits in; crashd declines the fault at once, marking the block `status=timeout` when the attach was
the request cancelled, and logs the rest of the block after the decline, when nothing waits on the
faulting thread any more. The stack scan reads at most 8 KiB (`STACK_SCAN_BYTES`).

---

## Limits

- **Threads other than the main one.** procmgr holds a Thread cap for a process's main thread only;
  the threads the runtime spawns are created in the process's own `CSpace`. For a fault of such a
  thread, crashd cannot read the registers, so its block carries `thread=unidentified`, the fault,
  the image placement, and the bytes at the instruction pointer, and no registers and no stack
  walk. A runtime registry of spawned threads, through which `ATTACH_PROCESS` returns every thread
  of a process, is design intent; not yet implemented
  ([#838](https://github.com/kottlerg/seraph/issues/838)).
- **Uncovered processes.** init, memmgr, and procmgr are not created by procmgr, and logd, the
  serial driver, and crashd declare themselves undebuggable, since crashd's log output waits on
  them. A fault of any of them takes the outcome it has with no handler bound; the kernel's
  `fault unhandled` and `USERSPACE FAULT` lines are its only report.
- **Debugged threads.** A debugger that binds a thread's exception class takes its faults; crashd
  sees none of them.

Persistence of the reports through logd's disk and network sinks, core dumps after the log report,
and holding a crashed process stopped for a debugger are design intent; not yet implemented
([docs/fault-handling.md](../../docs/fault-handling.md) § Crash Reports).

---

## Testing

The `crashme` fixture faults on purpose in both kinds
([programs/crashme/README.md](../../programs/crashme/README.md)); the usertest boot runs it, and
`cargo xtask test-crash-report` checks the blocks in that boot's log
([docs/testing.md](../../docs/testing.md) § Crash reports).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/block-format.md](docs/block-format.md) | The block's lines and fields |
| [docs/fault-handling.md](../../docs/fault-handling.md) | § Crash Reports, § Reply (`FAULT_REPLY_FORWARD`), § Debugging |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | § Process Death |
| [services/procmgr/docs/ipc-interface.md](../procmgr/docs/ipc-interface.md) | `REGISTER_CRASH_SERVICE`, `ATTACH_PROCESS`, `DECLARE_NO_DEBUG` |
| [services/svcmgr/docs/service-definitions.md](../svcmgr/docs/service-definitions.md) | `debug_authority` |
| [docs/testing.md](../../docs/testing.md) | § Crash reports |

---

## Summarized By

None
