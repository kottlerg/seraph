# gdbstub

The GDB stub: debugs one process of a running system from a host GDB over the debug port. It
finds the process by name, attaches to it through procmgr's debug authority, takes the fault and
upcall classes of its threads, and serves the GDB remote serial protocol on the debug port, so the
host's GDB stops, inspects, changes, and steps the process with its own symbols.

---

## Role

The stub is the debug port's consumer for per-process debugging
([docs/fault-handling.md](../../docs/fault-handling.md) § Debugging): a userspace handler of the
target's exception class that turns GDB's packets into the kernel's thread calls
(`SYS_THREAD_READ_REGS`, `SYS_THREAD_WRITE_REGS`, `SYS_THREAD_READ_MEM`, `SYS_THREAD_WRITE_MEM`,
`SYS_THREAD_POST_UPCALL`) and its fault replies. It debugs the one process its `argv[1]` names,
for the boot. QEMU's own gdbstub, which reads the whole machine, is the tool for the kernel and
for a guest that no longer runs userspace ([docs/testing.md](../../docs/testing.md)
§ Troubleshooting).

It runs only on a boot that stages it. Its recipe is a template,
`rootfs/config/svcmgr/debug/gdbstub.svc`, which svcmgr does not scan, so an image that does not
stage it has no attach path through it. `cargo xtask run --debug-port <PORT> --debug-target
<NAME>` writes the template into `/config/svcmgr/services/` with `<NAME>` appended to its `argv`,
repacks `disk.img`, prints the host GDB command line, and removes it again after QEMU exits;
`cargo xtask run-parallel --parallel 1 --debug-port <PORT> --debug-target <NAME>` does the same
around its runs, and `cargo xtask test-gdb` stages it the same way
([xtask/README.md](../../xtask/README.md)). The
recipe sets `debug_authority = yes` and seeds `devmgr.debug`
([`.svc` Service Definitions](../svcmgr/docs/service-definitions.md)).

---

## Source Layout

```
gdbstub/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs            # Startup, attach, fault receivers, all-stop, the packet loop, detach
    ├── lib.rs             # Host-tested: stop signals; module roots
    ├── regs.rs            # Host-tested: kernel register file <-> GDB register block
    ├── breakpoints.rs     # Host-tested: breakpoint instructions, the inserted-breakpoint table
    └── arch/
        ├── mod.rs         # Architecture-dispatch surface
        ├── x86_64/
        │   └── mod.rs     # Single-step by the trap flag
        └── riscv64/
            └── mod.rs     # Single-step by a planted c.ebreak at the decoded successor
```

Framing, command parsing, and the target descriptions are `shared/gdb-rsp`
([shared/gdb-rsp/README.md](../../shared/gdb-rsp/README.md)); the riscv64 successor decoder is
`shared/riscv-step` ([shared/riscv-step/README.md](../../shared/riscv-step/README.md)).

---

## Startup and Attach

1. The stub declares itself undebuggable (`DECLARE_NO_DEBUG`), as every debug-authority holder
   does before it spawns a thread, and takes its bootstrap round: `caps[0]` the `devmgr.debug`
   seed, `caps[1]` the `DEBUG_AUTHORITY` SEND on procmgr.
2. It takes the debug port from devmgr (`QUERY_DEBUG_PORT_DEVICE`), retrying while devmgr replies
   `NO_DEVICE`, since the port's driver loads with devmgr's on-disk batch, and registers an RX
   notification on it. A boot without `--debug-port`, a missing seed or authority, or a missing
   target name ends the stub, which logs why.
3. It walks procmgr's process list (`LIST_PROCESSES`) for the first process whose name is its
   `argv[1]`, retrying while there is none, since the target can start after the stub. A name is
   the `argv[0]` the target's creator passed; for a service, the first word of its recipe's
   `argv`.
4. It attaches (`ATTACH_PROCESS`), paging the thread list, with a cap of its own main thread as
   procmgr's watch ([Detach](#detach)), and binds each listed thread's exception and upcall classes
   to its fault endpoint under a badge of its own: bit 62 with the thread's list index plus one,
   bit 63 clear, so the binding is neither the target's process badge nor a crash badge, as
   procmgr requires of a debugger
   ([procmgr IPC Interface](../procmgr/docs/ipc-interface.md) § Label 22: `REGISTER_THREAD`).
5. It stops every thread ([Stop Model](#stop-model)) and logs
   `attached; serving the debug port (<name>)`.

When the walk or the attach fails, the stub serves the port detached: `?` reports the target
exited, and the next `qSupported`, a new GDB connection, tries the walk and the attach again.

---

## Stop Model

The stub is all-stop: while GDB holds the target, every thread of it is fault-blocked on the
stub's endpoint.

- **Receivers.** One receiver thread per target thread takes that thread's fault and upcall
  messages and holds the reply until the serve loop decides it, since a receive on the same
  thread would cancel the reply pending. The decision is a `FAULT_REPLY_RESUME`, or a
  `FAULT_REPLY_KILL` when GDB resumes a thread stopped on a fault with a signal, so the fault
  takes the outcome it has with no handler bound
  ([docs/fault-handling.md](../../docs/fault-handling.md) § Reply).
- **Stopping.** To stop the target (the attach, GDB's interrupt byte `0x03`, and the stop of every
  other thread when one stops) the stub posts each running thread an `UPCALL_ANY_INSTRUCTION`
  upcall and waits up to `STOP_WAIT` (2 s) for each to arrive. A thread whose upcall does not
  arrive in time runs on and is not reported held. An upcall that arrives while the target runs
  was posted to a thread that had stopped on a fault first; its stop is over, and the stub
  resumes it at once.
- **Stop replies.** A stop reports the stopping thread (`T<sig>thread:<id>;`) with the signal its
  fault maps to: `SIGTRAP` for a breakpoint or a step, `SIGILL`, `SIGBUS`, `SIGFPE` for those
  exceptions, `SIGSEGV` for any other fault and a page fault the pager forwarded, and `SIGINT` for
  an interrupt. GDB's thread ids are the attach list's indices plus one; thread 1 is the main
  thread.
- **Breakpoints.** `Z0` plants `int3` (kind 1) on x86-64, `c.ebreak` (kind 2) or `ebreak` (kind 4)
  on riscv64, through the kernel's text route (`THREAD_MEM_TEXT`) with every thread held, and keeps
  the bytes it replaced; `z0` writes them back. GDB itself sets the pointer back to the
  breakpoint after an x86-64 stop, and steps over a breakpoint it resumes from by removing it for
  the step, so the stub never moves a pointer or steps over a planted instruction.
- **Single-step.** `s`, or a `vCont` step action, runs one instruction of one thread, the others
  held: on x86-64 by the trap flag, on riscv64 by a `c.ebreak` planted at the successor the
  instruction's decode gives and removed at the step's stop, with the hazards
  [docs/fault-handling.md](../../docs/fault-handling.md) § Debugging lists for that route.
- **Memory.** `m`, `M`, and `X` read and write the target's address space through any held
  thread's cap; a write that a read-only page refuses goes through the text route. Only pages
  present in the space are reached, so a demand-paged page the target has not touched reads as an
  error.

---

## Protocol Coverage

| Packet | Answer |
|---|---|
| `qSupported` | `PacketSize`, `QStartNoAckMode+`, `qXfer:features:read+`, `vContSupported+`; attaches first when detached |
| `QStartNoAckMode` | `OK`, then no acknowledgements |
| `?` | `T05` for the current thread; `W00` when detached |
| `qAttached` | `1`: GDB detaches on quit rather than killing the target |
| `qOffsets` | the image's load bias, so GDB relocates the host binary's symbols |
| `qXfer:features:read:target.xml` | the architecture's target description |
| `qfThreadInfo`, `qsThreadInfo`, `qC`, `Hg`, `Hc`, `T` | the live threads, the current one, its selection |
| `g`, `G`, `p`, `P` | the current thread's registers, read and written through its register file |
| `m`, `M`, `X` | target memory |
| `Z0`, `z0` | software breakpoints |
| `c`, `C`, `s`, `S`, `vCont?`, `vCont` | resume and step, as above |
| `D` | detach ([Detach](#detach)), then `OK` |
| `k` | detach; the target is not killed |
| the interrupt byte `0x03` | stop every thread; `T02` |
| any other packet | an empty reply |

Hardware breakpoints and watchpoints (`Z1` to `Z4`), non-stop mode, and `vAttach` and `vRun` are
not served; GDB falls back or reports them unsupported.

---

## Detach

`D` (GDB's `detach`, and its quit while attached, since `qAttached` is `1`) and `k` restore the
target as the attach found it: the stub writes every breakpoint's bytes back, undoes a step in
flight, resumes every held thread, and sends procmgr `DETACH_PROCESS`, which binds the target's
main thread back to the crash endpoint under its process badge and each registered thread under
its crash badge, minting one for a thread that registered during the attach. The stub then
unbinds the upcall class and drops the thread caps, and logs
`detached from <name> (crash bindings restored: <bool>)`. The stub cannot restore the crash
bindings itself, since it holds no SEND on procmgr's crash endpoint.

When the stub dies attached, procmgr restores the crash bindings the same way: the attach left it
a cap of the stub's main thread, and procmgr restores the target once that thread has exited
([procmgr IPC Interface](../procmgr/docs/ipc-interface.md) § Label 24: `DETACH_PROCESS`). The
stub's death cannot undo its own changes to the target: a planted breakpoint stays planted, and a
thread it held is released as its handler's death releases it
([docs/fault-handling.md](../../docs/fault-handling.md) § Liveness): one held at a fault is
killed, and one held by an upcall resumes. A fault taken between the stub's death and procmgr's
restore waits on the stub's endpoint, which its binding keeps alive, and the restore delivers it
again to the crash endpoint (§ Delivery, Resume, and Kill there, Rebind).

The debug port is a byte stream with no connection state: the stub cannot observe a host GDB that
disconnects without `D`. The target then stays held until a GDB connects again, which finds it
still attached.

---

## Limits

| Bound | Value | Past it |
|---|---|---|
| `MAX_THREADS` | 32 threads per attach | listed threads past it are left bound to the crash endpoint and are not shown to GDB |
| `STOP_WAIT` | 2 s per all-stop | a thread whose upcall has not arrived runs on |
| `FIND_ATTEMPTS` × `FIND_INTERVAL` | 600 × 100 ms, for the port and for the target | the stub ends (no port) or serves detached (no target) |
| `POLL_MS` | 10 ms | the serve loop's wait for port bytes between looks at the threads' stops |

A thread the target spawns after the attach copies its spawner's bindings, the stub's badge
among them, so its stops arrive under its spawner's badge and are not its own thread in GDB: the
stub resumes a stop that arrives for a thread it already holds. A new attach, after a detach,
lists it. The stub's thread ids are list indices, not kernel thread identities.

Each bound's entry is in [docs/limits.md](../../docs/limits.md) § Other services.

---

## Testing

The host tests cover the register map, the breakpoint table and instructions, and the stop
signals. `cargo xtask test-gdb` boots the `gdb-target` fixture (`programs/debugger
--gdb-target`, [programs/debugger/README.md](../../programs/debugger/README.md)) with the stub and
runs a batch GDB session over the debug port: it lists two threads, breaks on the fixture's tick
function and continues to it, rewrites and reads back a variable, single-steps, selects the second
thread and reads its registers, and detaches ([docs/testing.md](../../docs/testing.md) § GDB stub
(`test-gdb`)). svctest's `debug_authority_refused` phase
checks that `LIST_PROCESSES` and `DETACH_PROCESS` refuse a caller without the authority.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/fault-handling.md](../../docs/fault-handling.md) | § Debugging, § Asynchronous Upcalls, § Liveness |
| [services/procmgr/docs/ipc-interface.md](../procmgr/docs/ipc-interface.md) | `LIST_PROCESSES`, `ATTACH_PROCESS`, `DETACH_PROCESS`, `DECLARE_NO_DEBUG`, `REGISTER_THREAD` |
| [services/drivers/virtio/console/README.md](../drivers/virtio/console/README.md) | The debug port's driver and the serial protocol it serves |
| [docs/device-management.md](../../docs/device-management.md) | The debug port and `QUERY_DEBUG_PORT_DEVICE` |

---

## Summarized By

[Fault Handling](../../docs/fault-handling.md), [Testing](../../docs/testing.md),
[services/README.md](../README.md),
[procmgr IPC Interface](../procmgr/docs/ipc-interface.md),
[xtask/README.md](../../xtask/README.md)
