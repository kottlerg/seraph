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
repacks the disk images in the layout they have, prints the host GDB command line, and removes it
again after QEMU exits;
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
    ├── main.rs            # Startup, attach, fault receivers, the session's syscalls, packet loop
    ├── lib.rs             # Host-tested: stop signals, step errors; module roots
    ├── session.rs         # Host-tested: the stop state machine of a session, and its invariants
    ├── control.rs         # Host-tested: badges, stop credit and settling, slots, rewind, resumes
    ├── regs.rs            # Host-tested: kernel register file <-> GDB register block
    ├── breakpoints.rs     # Host-tested: breakpoint instructions, the inserted-breakpoint table
    └── arch/
        ├── mod.rs         # Architecture-dispatch surface
        ├── x86_64/
        │   └── mod.rs     # Single-step by the trap flag
        └── riscv64/
            └── mod.rs     # Single-step by a planted c.ebreak at the decoded successor
```

`session.rs` holds every run-control decision and its order, the stop model below, over a
`Kernel` trait that `main.rs` implements with syscalls and the host tests with a simulated
kernel; its module documentation states the invariants the model keeps.

Framing, command parsing, and the target descriptions are `shared/gdb-rsp`
([shared/gdb-rsp/README.md](../../shared/gdb-rsp/README.md)); the riscv64 successor decoder is
`shared/riscv-step` ([shared/riscv-step/README.md](../../shared/riscv-step/README.md)).

---

## Startup and Attach

1. The stub declares itself undebuggable (`DECLARE_NO_DEBUG`), as every debug-authority holder
   does before it spawns a thread, and takes its bootstrap round: `caps[0]` the `devmgr.debug`
   seed, `caps[1]` the `DEBUG_AUTHORITY` SEND on procmgr. A declaration procmgr does not accept
   ends the stub, which logs why: the declaration is what makes procmgr refuse an attach to the
   stub, so no memory write of the stub's lands in its own address space.
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
   to its fault endpoint under a badge carrying the debugger tag (`DEBUGGER_BADGE_TAG`, bit 62,
   bit 63 clear) with the index of the stub's table the thread is stored at plus one, by which
   procmgr tells a debugger's binding
   ([procmgr IPC Interface](../procmgr/docs/ipc-interface.md) § Label 20: `ATTACH_PROCESS`). A
   thread whose bind fails keeps its place in the table, so the indices after it stay those of
   procmgr's list, and is not shown to GDB. A refused or failed page deletes the caps already
   taken and has procmgr drop the watch again (`DETACH_PROCESS`).
5. It stops every thread ([Stop Model](#stop-model)) and logs
   `attached; serving the debug port (<name>)`.

When the walk or the attach fails, the stub serves the port detached: `?` reports the target
exited, and the next `qSupported`, a new GDB connection, tries the walk and the attach again,
looking for the target `REATTACH_ATTEMPTS` times ([Limits](#limits)), well inside the 30 s
`remotetimeout` of the GDB command line xtask prints. Each attach first declines any stop left
over from an earlier session (below), so none is taken for one of its own, as the stub does with
every stop that arrives while it is detached.

---

## Stop Model

The stub is all-stop: while GDB holds the target, every thread of it is fault-blocked on the
stub's endpoint.

- **Receivers.** Receiver threads take the fault and upcall messages off the stub's endpoint,
  each holding one message's reply until the serve loop decides it, since a receive on the same
  thread would cancel the reply pending. The stub keeps one receiver per slot of its table, and
  one free beyond every stop it holds or keeps (below), up to `MAX_RECEIVERS`, so below that
  bound the next stop finds one; a receiver the stub cannot start is logged. The decision is a
  `FAULT_REPLY_RESUME`, or a `FAULT_REPLY_KILL` when GDB resumes a thread stopped on a fault with
  a signal, so the fault takes the outcome it has with no handler bound
  ([docs/fault-handling.md](../../docs/fault-handling.md) § Reply).
- **Stopping.** To stop the target (the attach, GDB's interrupt byte `0x03`, and the stop of every
  other thread when one stops) the stub posts each running thread an `UPCALL_ANY_INSTRUCTION`
  upcall and waits up to `STOP_WAIT` (2 s) for each to arrive. Once none is awaited, it refreshes
  its table once (below), posts an upcall to each thread the refresh adds, and restarts every held
  breakpoint hit or fault GDB has not been told of, since any of them can be a new thread's
  (below). A thread whose upcall does not arrive in time runs on and is not reported held. The
  all-stop's end makes every held stop one GDB has been told of. An upcall that arrives while the
  target runs was posted to a thread that had stopped on a fault first; its stop is over, and the
  stub resumes it at once. A thread the upcall
  finds blocked in an interruptible syscall returns from it with `Interrupted`
  ([docs/fault-handling.md](../../docs/fault-handling.md) § Asynchronous Upcalls, Blocking
  syscalls), so each all-stop can end a sleep, a wait, or an IPC call of the target early, as any
  stop can.
- **Crediting a stop.** A thread the target spawns after the attach copies its spawner's bindings,
  the stub's badge among them, so its stops arrive under its spawner's badge. The stub credits a
  stop to the thread its badge names only when that thread is not already held and its register
  file reads at the pointer the message carries. Any other stop makes it refresh its table: it
  pages procmgr's thread list (`ATTACH_PROCESS`) from the count of the table's threads still
  alive, since procmgr lists those first and in the same order, retaking the page when one of them
  exits meanwhile (`REFRESH_TRIES` times), and binds each new thread under its own badge, in the
  slot of an exited thread or after the last. A bind to a new badge delivers the new thread's stop
  again under it ([docs/fault-handling.md](../../docs/fault-handling.md) § Delivery, Resume, and
  Kill, Rebind), and cancels the first delivery, which ignores the stub's answer. A new thread
  stored in the slot of the exited spawner whose badge it copied keeps its binding, which cancels
  nothing, so the stub credits the stop to that thread when it is the one blocked at its pointer.
  When a refresh adds a thread, every held breakpoint hit or fault GDB has not been told of is
  restarted (below), since any of them can be a new thread's stop credited to its spawner. The
  stub then tells stops by origin: an upcall or a step's `#DB` only the thread it names makes, and
  a breakpoint hit or a fault any thread bound under the badge can. With the named thread held:
  - A stop of its own origin beside a held breakpoint hit or fault: the held one was a new
    thread's, credited to it. The new stop is held in its place, and the old one declined.
  - A stop of its own origin beside a held one of its own origin: the kernel delivered the held
    one again. The new delivery is held, and the old one, which the kernel cancelled, answered
    `FAULT_REPLY_RESUME`.
  - A breakpoint hit or a fault beside a held one that GDB has not been told of: one of two
    deliveries under one badge, the thread's own and a new thread's or one the kernel made again,
    and which is live is unknown. The stub restarts the thread: it sets its pointer back to the
    breakpoint it took, planted or built into the target, as for a hit it does not report
    (below), and resumes both, so the thread runs its breakpoint or faulting instruction again
    and stops anew. A restart is idempotent: an answer to a delivery the kernel cancelled is
    ignored.
  - A breakpoint hit or a fault that repeats a held one GDB has been told of (the same kind,
    class, and pointer): the kernel's second delivery of it, which a rebind's race can make
    ([docs/fault-handling.md](../../docs/fault-handling.md) § Delivery, Resume, and Kill,
    Rebind), or a stop of a thread the stub cannot bind at the same instruction. The stub keeps
    it beside the held one, answers neither now, and gives both the answer the held one takes.

  A held stop GDB has been told of is never restarted, nor is a held upcall or `#DB`. It is
  answered by a resume, a step, the detach, or the end of a session whose threads have all exited,
  or replaced by a stop of its thread's own origin, which a thread held on its own stop cannot
  make. Any other stop is declined: an upcall or a `#DB` resumes, and a breakpoint hit or a fault
  is answered `FAULT_REPLY_KILL`, so a thread the stub cannot bind (the table is full, or the
  thread never registered) takes the outcome its fault has with no handler bound, rather than
  resuming past a breakpoint or faulting again for ever.
- **Stop replies.** A stop reports the stopping thread (`T<sig>thread:<id>;`) with the signal its
  fault maps to: `SIGTRAP` for a breakpoint or a step, `SIGILL`, `SIGBUS`, `SIGFPE` for those
  exceptions, `SIGSEGV` for any other fault and a page fault the pager forwarded, and `SIGINT` for
  an interrupt. GDB's thread ids are the table's indices plus one; thread 1 is the main thread.
- **Breakpoints.** `Z0` plants `int3` (kind 1) on x86-64, `c.ebreak` (kind 2) or `ebreak` (kind 4)
  on riscv64, through the kernel's text route (`THREAD_MEM_TEXT`) with every thread held, and keeps
  the bytes it replaced; `z0` writes them back. GDB itself sets the pointer back to the
  breakpoint after an x86-64 stop it is told of, and steps over a breakpoint it resumes from by
  removing it for the step. A breakpoint another thread hits during an all-stop is held
  unreported; on x86-64, whose `int3` leaves the pointer past it, the stub sets that thread's
  pointer back to the breakpoint, so its resume runs the breakpoint again and the hit is reported
  then.
- **Single-step.** `s`, or a `vCont` step action, runs one instruction of one thread, the others
  held: on x86-64 by the trap flag, on riscv64 by a `c.ebreak` planted at the successor the
  instruction's decode gives and removed at the step's stop, with the hazards
  [docs/fault-handling.md](../../docs/fault-handling.md) § Debugging lists for that route. An
  all-stop that ends otherwise (GDB's interrupt, another thread's stop) undoes the step once its
  thread is held, and the planted `c.ebreak` is written back through any live thread once the
  stepped one has exited. A detach whose stepped thread an all-stop left running stops the target
  once more and writes the `c.ebreak` back whatever comes; a trap flag on an x86-64 thread that
  never stopped stays set, which the stub logs, and the thread's next instruction then traps to
  the crash endpoint.
- **Resuming.** `c`, `C`, `s`, `S`, and `vCont` act on the current thread or the one the action
  names; an address the packet gives becomes that thread's pointer first. A signal passed to a
  thread stopped on a fault declines the fault (`FAULT_REPLY_KILL`), so a step that passes one is a
  continue passing it. A `vCont` whose actions name no live thread is answered `E01`; a resume with
  no target, or after which every thread has exited, is answered `W00`.
- **Memory.** `m`, `M`, and `X` read and write the target's address space through any held
  thread's cap; a write that a read-only page refuses goes through the text route, which reaches
  text, mapped through a capability that carries Execute, but not read-only data such as `.rodata`
  or RELRO, mapped through a Map-only one, so such a write is answered `E01`. Only pages present in
  the space are reached, so a demand-paged page the target has not touched reads as an error.

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
target as the attach found it, as far as procmgr's crash bindings go: the stub undoes a step in
flight, refreshes its table, so a thread registered since the last all-stop has its stop come again
under its own badge, writes every breakpoint's bytes back through a live thread when one is left,
and resumes every held thread. It answers `FAULT_REPLY_RESUME` for `DRAIN_WAIT` ([Limits](#limits))
to each stop that reaches its endpoint meanwhile, first setting a hit of a breakpoint it wrote back
to the breakpoint's address, so the thread runs the restored bytes. It then sends procmgr
`DETACH_PROCESS`, which binds the target's main thread, and each listed thread procmgr recorded as
the target's own at its registration, back to the crash endpoint when its exception class is bound
under the debugger tag, is unbound, or is bound by procmgr under another badge. Any other listed
thread, one procmgr left under another process's badge among them, it never binds to the crash
endpoint, and it unbinds the debugger's binding on it. It leaves a thread bound to any other
handler, unbinds each upcall class bound under the debugger tag, and does so as well when every
thread has exited. The stub's own unbind of the upcall class after it changes nothing. The stub
drops the thread caps and logs `detached from <name> (crash bindings restored: <bool>)`. The stub
cannot restore the crash bindings itself, since it holds no SEND on procmgr's crash endpoint. A
handler the target had bound on a thread's exception or upcall class itself, which the attach's bind
replaced, is not bound back: procmgr restores its own bindings, not the target's
([procmgr IPC Interface](../procmgr/docs/ipc-interface.md) § Label 24: `DETACH_PROCESS`).

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
| `MAX_THREADS` | 32 live threads per attach, refreshes included; an exited thread's slot is taken again | listed threads past it are left bound to the crash endpoint and are not shown to GDB; a thread spawned after the attach past it runs under its spawner's binding, and its stops are settled as [Crediting a stop](#stop-model) says |
| `MAX_RECEIVERS` | 64 receiver threads, twice `MAX_THREADS` | a stop waits on the stub's endpoint until a held one is answered |
| `STOP_WAIT` | 2 s per all-stop | a thread whose upcall has not arrived runs on |
| `FIND_ATTEMPTS` × `FIND_INTERVAL` | 600 × 100 ms, for the port and for the target at startup | the stub ends (no port) or serves detached (no target) |
| `REATTACH_ATTEMPTS` × `FIND_INTERVAL` | 50 × 100 ms, for the target at a `qSupported` that finds the stub detached | the stub stays detached; `?` reports the target exited |
| `REFRESH_TRIES` | 3 pages per refresh | the stop is settled as no new thread's, and the next stop that is not its thread's own refreshes again |
| `DRAIN_WAIT`, `DRAIN_QUIET` | 500 ms, ended early by 50 ms with no stop, per detach | a stop that reaches the stub's endpoint after procmgr's rebind is a thread's procmgr did not rebind, and the stub declines it |
| `POLL_MS` | 10 ms | the serve loop's wait for port bytes between looks at the threads' stops |

A thread spawned after the attach that stops at the same pointer as its spawner while the
spawner's own stop is in flight can be credited with the spawner's stop until the spawner's stop
arrives; the restart above then runs the spawner's breakpoint or faulting instruction again. When
the second thread is one the stub cannot bind, both deliveries are live and both are resumed, so on
x86-64 that thread, at a breakpoint, resumes past it, as it does when it repeats a held stop GDB
already knows of and is resumed with it; one beside such a stop that does not repeat it is
declined, which kills it. The stub's thread ids are table indices, not kernel thread identities,
and the id of an exited thread names the thread that takes its slot.

Each bound's entry is in [docs/limits.md](../../docs/limits.md) § Other services.

---

## Testing

The host tests cover the register map, the breakpoint table and instructions, the stop signals,
the binding badges, the credit of a stop to its thread, the origin, settling, and decline of a stop
no thread claims, the slot a new thread takes, the rewind of an unreported breakpoint hit, and the
resume plans of `c`, `s`, and `vCont`. They drive the stop state machine against a simulated
kernel through the interleavings that can break it: a spawner and a thread it spawned after the
attach at one breakpoint, in either order and with the spawner's stop late; a fault of a thread
the stub cannot bind; a new thread in its exited spawner's slot; stops during a step; a repeat of
a stop GDB knows of, and the kernel's second delivery of one; a restart at a breakpoint built into
the target; a thread's own upcall beside a stop that was not its; stops racing a resume or an
all-stop, and an all-stop that holds no thread; a continue that ends every thread; and a detach
with a stop pending, with every thread exited, and with the step's thread exited or never
stopped. `cargo xtask test-gdb`
boots the `gdb-target`
fixture (`programs/debugger --gdb-target`,
[programs/debugger/README.md](../../programs/debugger/README.md)) with the stub and runs a batch
GDB session over the debug port: it lists two threads, breaks on the fixture's tick function and
continues to it, rewrites and reads back a variable and a register, single-steps, selects the
second thread and reads its registers, and detaches, and the stub's detach line reports the crash
bindings restored ([docs/testing.md](../../docs/testing.md) § GDB stub (`test-gdb`)). svctest's
`debug_authority_refused` phase checks that `LIST_PROCESSES` and `DETACH_PROCESS` refuse a caller
without the authority, and its `crash_endpoint` phase drives both for a holder of it, with the
restore after a watch thread's exit.

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
