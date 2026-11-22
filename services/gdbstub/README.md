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
`cargo xtask run --runs 1 --debug-port <PORT> --debug-target <NAME>` does the same
around its runs, and the `debug-port` case's second boot stages it the same way
([xtask/README.md](../../xtask/README.md)). The
recipe sets `debug_authority = yes` and seeds `devmgr.class.debug-port`
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
   does before it spawns a thread, and takes its bootstrap round: `caps[0]` the
   `devmgr.class.debug-port` seed, `caps[1]` the `DEBUG_AUTHORITY` SEND on procmgr. A declaration
   procmgr does not accept ends the stub, which logs why: the declaration is what makes procmgr
   refuse an attach to the stub, so no memory write of the stub's lands in its own address space.
2. It follows the debug port through a
   [`device_tracker::Device`](../../shared/device-tracker/README.md) on the class, waiting without
   a bound until devmgr serves the class's first live driver, since the port's driver loads with
   devmgr's on-disk batch. The device's tracker keeps the port across devmgr's restart of its
   driver (logged `debug port driver at ordinal <n>`), and before each read or write the stub
   registers its RX notification with a driver instance it has not registered with. Bytes the stub
   writes while the class serves no driver are dropped, as bytes written to a dead one are. A
   missing seed or authority, or a missing target name ends the stub, which logs why; a boot
   without `--debug-port` leaves it waiting.
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
   taken and has procmgr drop the watch again (`DETACH_PROCESS`). A list whose walk a thread's
   exit can have torn ([Stop Model](#stop-model), Crediting a stop) is taken again,
   `REFRESH_TRIES` walks in all; the attach keeps a list still torn then and refreshes its table
   no more.
5. It stops every thread ([Stop Model](#stop-model)) and logs
   `attached; serving the debug port (<name>)`. A target its creator had not started at that
   all-stop's last read of it, at most `START_POLL` before its end, holds no stop, and once
   started it would run while GDB took it for stopped. The stub detaches from such a target
   instead, logs
   `<name> not started within the attach's wait; detached (crash bindings restored: <bool>)`, and
   counts the attach as failed.

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
  upcall and waits up to `STOP_WAIT` (2 s) for each to arrive. The kernel refuses an upcall to a
  thread its creator has not started, as procmgr lists a process's main thread between its creation
  and its start, so the stub reads such a thread's state again every `START_POLL` (10 ms), posts
  its upcall once it has started, and waits up to `STOP_WAIT` from that post for it. A thread
  blocked in an IPC call, queued or awaiting its reply, takes its upcall only at the call's return,
  with the reply in its registers ([docs/fault-handling.md](../../docs/fault-handling.md)
  § Asynchronous Upcalls, Blocking syscalls), and runs no instruction before it. The stub reads
  each posted thread's upcall state (`CAP_INFO_THREAD_UPCALL`) as often, and counts a thread held
  in a call, its upcall pending and not masked, as stopped at once; its upcall, when it arrives
  while the target is still stopped, is held as any stop, so a register request of the thread
  waits up to `STOP_WAIT` for it once the call has returned. Once none is awaited, it
  refreshes its table once (below), posts an upcall to each thread the refresh adds,
  and restarts every held breakpoint hit or fault GDB has not been told of, since any of them can
  be a new thread's (below). A thread whose upcall does not arrive in time runs on and is not
  reported held. The all-stop's end makes every held stop one GDB has been told of. An upcall that
  arrives while the target runs, of a thread GDB resumed, was posted to it when it had stopped on a
  fault first, or while it was held in a call; its stop is over, and the stub resumes it at once.
  Any stop of a thread GDB did not resume is held as it arrives, a breakpoint hit set back, as GDB
  holds the thread: the upcall of one held in a call, and any stop of one the all-stop could not
  hold (**Resuming** below). A thread the upcall finds
  blocked in any other interruptible syscall returns from it with `Interrupted`
  ([docs/fault-handling.md](../../docs/fault-handling.md) § Asynchronous Upcalls, Blocking
  syscalls), so each all-stop can end a sleep or a wait of the target early, as any stop can. A
  thread that masks upcalls takes its upcall when it unmasks, and one still masked past
  `STOP_WAIT` runs on, unheld.
- **Crediting a stop.** A thread the target spawns after the attach copies its spawner's bindings,
  the stub's badge among them, so its stops arrive under its spawner's badge. The stub credits a
  stop to the thread its badge names only when that thread is not already held and its register
  file reads at the pointer the message carries. Any other stop makes it refresh its table: it
  pages procmgr's thread list (`ATTACH_PROCESS`) from the index of the first thread the table
  does not hold, one past the main thread and the table's live registered threads, since procmgr
  lists the main thread at index 0 whether or not it has exited, then each registered thread still
  alive in registration order
  ([procmgr IPC Interface](../procmgr/docs/ipc-interface.md) § Label 20: `ATTACH_PROCESS`). It
  takes the list again, `REFRESH_TRIES` walks in all, when a thread of the table exits meanwhile,
  or one taken from a reply of the walk before its last does: procmgr pages the list in replies of
  `ATTACH_THREADS_PAGE` caps and drops an exited thread before each, so such an exit moves every
  later thread an index down and the walk skips one. It binds each new thread under its own badge,
  in the slot of an exited thread or after the last. A bind to a new badge delivers the new
  thread's stop again under it
  ([docs/fault-handling.md](../../docs/fault-handling.md) § Delivery, Resume, and Kill, Rebind),
  and cancels the first delivery, which ignores the stub's answer. A new thread
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
  `Hg` of a thread GDB cannot select is answered `E04` when its bind failed, `E05` when it has
  exited, and `E01` when the table has no such slot, and the stub logs the refusal, so the cause
  reaches the host even when the line cannot, as when the target held is logd. `g` and `p` of a
  thread still held in a call read the registers the kernel reads of a thread blocked in a
  syscall: the frame of the call's entry, at the instruction past the `syscall` on x86-64 and at
  the `ecall` on riscv64, with result registers that hold the call's arguments until it returns
  (core/kernel/docs/syscalls.md § `SYS_THREAD_READ_REGS`); `G` and `P` of it are answered
  `E06`, since the kernel writes only a stopped or fault-blocked thread's registers, the call's
  return still writing them. A read the kernel refuses because the thread left its call after the
  stub found it there, or a write's read that finds the upcall the call's return takes queued for
  the stub's receive, is made again once the stub has waited for that upcall. `qThreadExtraInfo`
  shows such a thread as `held in a call`.
- **Memory.** `m` reads and `M` and `X` write the target's memory through a live thread of it, in
  the chunks the kernel copies at once. A chunk on a page memmgr evicted, into its compressed store
  or to disk, is not present to the kernel's copy, so the stub asks procmgr, through its debug
  authority, to make the chunk resident (`MAKE_RESIDENT`,
  [memmgr Memory Pool](../memmgr/docs/memory-pool.md#eviction) § Eviction) and copies it again; for
  a chunk on disk it asks again after a pause while the swap service restores it
  (`ipc::make_resident`), and passes the chunk over after about a second; a page procmgr cannot
  make resident ends a read there, and fails a write.
- **Breakpoints.** `Z0` plants `int3` (kind 1) on x86-64, `c.ebreak` (kind 2) or `ebreak` (kind 4)
  on riscv64, through the kernel's text route (`THREAD_MEM_TEXT`) with every thread held, and keeps
  the bytes it replaced, read as **Memory** reads them; `z0` writes them back. Text the target
  shares with the other instances of its binary ([procmgr](../procmgr/README.md#image-sharing) §
  Image Sharing) refuses the write, a page the target has run because another mapping holds its
  frame and one it has not because it is not present; the stub then asks procmgr, through its debug
  authority, to give the page a copy of the target's own (`MAKE_PRIVATE`), and writes again, so the
  breakpoint patches the target alone. GDB itself sets the pointer back to the breakpoint after an
  x86-64 stop it is told of, and steps over a breakpoint it resumes from by removing it for the
  step. A breakpoint another thread hits during an all-stop is held unreported; on x86-64, whose
  `int3` leaves the pointer past it, the stub sets that thread's pointer back to the breakpoint, so
  its resume runs the breakpoint again and the hit is reported then.
- **Single-step.** `s`, or a `vCont` step action, runs one instruction of one thread, the others
  held, those a continue action of the same packet names among them, since another thread could take
  the riscv64 step's planted `c.ebreak` (GDB's own software step resumes only the stepped thread for
  that reason): on x86-64 by the trap flag, on riscv64 by a `c.ebreak` planted at the successor the
  instruction's decode gives, through the text write of **Breakpoints** (a page the target shares
  becomes its own first), and removed at the step's stop, with the hazards
  [docs/fault-handling.md](../../docs/fault-handling.md) § Debugging lists for that route. An
  all-stop that ends otherwise (GDB's interrupt, another thread's stop) undoes the step once its
  thread is held, and the planted `c.ebreak` is written back through any live thread once the
  stepped one has exited. A detach whose stepped thread an all-stop left running stops the target
  once more and writes the `c.ebreak` back whatever comes; a trap flag on an x86-64 thread that
  never stopped stays set, which the stub logs, and the thread's next instruction then traps to
  the crash endpoint.
- **Resuming.** A `vCont` resumes only the threads its actions name, as the remote protocol has
  it: each thread takes the leftmost action that names it, an action with no thread id or with `-1`
  naming every thread and one with `0` the current thread, and a thread no action names stays held;
  a step runs alone, as above. `c`, `C`, `s`, and `S` act on the thread `Hc` selected, alone, or,
  after `Hc0` or `Hc-1`, on the current thread with every other thread continuing; an address the
  packet gives becomes that thread's pointer first. `Hc` of a thread id `Hg` would refuse is refused
  as `Hg` is, with no target attached too; `Hc0` and `Hc-1` name no thread and are accepted. A
  signal passed to a thread stopped on a fault declines the fault (`FAULT_REPLY_KILL`), so a step
  that passes one is a continue passing it. A thread GDB did not
  resume stays held while the target runs, one the all-stop could not hold from its next stop on,
  and a stop is reported only for a thread GDB resumed, or one spawned while the target ran: a stop
  GDB did not ask for would break its own run control, as a software step's breakpoint taken by
  another thread does. GDB's interrupt reports the current thread when GDB resumed it, and
  otherwise the first thread it resumed, held or else in a call; when every thread GDB resumed has
  exited, it reports the first live thread, held or else in a call, since its stop names a thread
  GDB then selects. A `vCont` whose actions name no
  live thread is answered `E01`; a resume with no target, or after which every thread has exited,
  is answered `W00`, as is a target whose threads all exit while it runs, but only when the stub's
  table holds every thread of the target, since threads it could not take may run on. Once no
  thread GDB resumed runs on, each having exited, while others are held, the stub stops the target
  and answers `N` when GDB's `qSupported` offered `no-resumed+`; otherwise the target waits for
  GDB's interrupt.
- **Memory.** `m`, `M`, and `X` read and write the target's address space through any held
  thread's cap; a write that a read-only page refuses goes through the text route, which reaches
  text, mapped through a capability that carries Execute, but not read-only data such as `.rodata`
  or RELRO, mapped through a Map-only one, so such a write is answered `E01`. A text-route write,
  a breakpoint's included, that the kernel refuses because another leaf maps the page's frame, as
  memmgr's own view does every page of a memory-object attachment, asks procmgr, through the debug
  authority, to give the range pages of their own (`MAKE_PRIVATE`, `ipc::make_private`;
  [memmgr Memory Pool](../memmgr/docs/memory-pool.md#memory-objects) § Memory objects) and writes
  again, so the write patches the target alone. Only pages present in
  the space are reached, so a demand-paged page the target has not touched reads as an error.

---

## Protocol Coverage

| Packet | Answer |
|---|---|
| `qSupported` | `PacketSize`, `QStartNoAckMode+`, `qXfer:features:read+`, `vContSupported+`; attaches first when detached, and notes whether GDB offered `no-resumed+` |
| `QStartNoAckMode` | `OK`, then no acknowledgements |
| `?` | `T05` for the current thread; `W00` when detached |
| `qAttached` | `1`: GDB detaches on quit rather than killing the target |
| `qOffsets` | the image's load bias, so GDB relocates the host binary's symbols |
| `qXfer:features:read:target.xml` | the architecture's target description |
| `qfThreadInfo`, `qsThreadInfo`, `qC`, `Hg`, `Hc`, `T` | the live threads, the current one, its selection |
| `qThreadExtraInfo` | what the thread does: `stopped`, `held in a call`, or `running` ([Stop Model](#stop-model)) |
| `g`, `G`, `p`, `P` | the current thread's registers, read and written through its register file; a thread held in a call reads, and `G` and `P` of it are answered `E06` |
| `m`, `M`, `X` | target memory |
| `Z0`, `z0` | software breakpoints |
| `c`, `C`, `s`, `S`, `vCont?`, `vCont` | resume and step, as above; `N` once no resumed thread runs on |
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
| `STOP_WAIT` | 2 s per all-stop, and from the post to a thread its creator starts during it | a thread whose upcall has not arrived runs on; an attach whose target is unstarted at the all-stop's last read detaches |
| `START_POLL` | 10 ms | the all-stop's interval between reads of a thread its creator has not started, and of a posted thread's upcall state |
| `FIND_ATTEMPTS` × `FIND_INTERVAL` | 600 × 100 ms, for the target at startup | the stub serves detached (no target) |
| `REATTACH_ATTEMPTS` × `FIND_INTERVAL` | 50 × 100 ms, for the target at a `qSupported` that finds the stub detached | the stub stays detached; `?` reports the target exited |
| `REFRESH_TRIES` | 3 walks of the thread list per refresh or attach | a refresh's stop is settled as no new thread's, and the next stop that is not its thread's own refreshes again; the attach keeps its last list and refreshes no more |
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
resume plans of `c`, `s`, and `vCont`: each thread takes its leftmost action, a thread no action
names stays held, a step runs alone, and `c` and `s` resume the thread `Hc` selected alone. They
drive the stop state machine against a simulated kernel through the interleavings that can break
it: a spawner and a thread it spawned after the attach at one breakpoint, in either order and with
the spawner's stop late; a fault of a thread the stub cannot bind; a new thread in its exited
spawner's slot; stops during a step; a repeat of a stop GDB knows of, and the kernel's second
delivery of one; a restart at a breakpoint built into the target; a thread's own upcall beside a
stop that was not its; stops racing a resume or an all-stop, and an all-stop that holds no thread;
an attach before the target's start, holding its main thread once started, and one whose target is
not started within the all-stop, or starts after its last read; a start late in the all-stop, alone
or beside a thread a refresh adds unstarted; a continue that ends every thread, or whose threads all
exit while the target runs; a continue of one thread with another held at the same breakpoint,
whose stop alone is reported, a held thread's call returning meanwhile, an interrupt meanwhile, the
restart of the resumed thread's stop, and a continue or step whose one thread exits; and a detach
with a stop pending, with every thread exited, and
with the step's thread exited or never stopped. The `debug-port` case's second boot boots the
`gdb-target` fixture (`programs/debugger --gdb-target`,
[programs/debugger/README.md](../../programs/debugger/README.md)) with the stub and runs a batch
GDB session over the debug port: it lists two threads, single-steps the main thread from where the
attach stopped it, on text the fixture attaches shared, breaks on the fixture's tick function and
continues to it, rewrites and reads back a variable and a register, single-steps again, selects the
second thread and reads its registers, and detaches, and the stub's detach line reports the crash
bindings restored; it then has the port's driver killed under the stub and requires the stub to
answer through the restarted driver ([docs/testing.md](../../docs/testing.md) § GDB stub
(`debug-port` case)). svctest's `debug_authority_refused` phase checks that `LIST_PROCESSES` and
`DETACH_PROCESS` refuse a caller without the authority, and its `crash_endpoint` phase drives both
for a holder of it, with the restore after a watch thread's exit.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/fault-handling.md](../../docs/fault-handling.md) | § Debugging, § Asynchronous Upcalls, § Liveness |
| [services/procmgr/docs/ipc-interface.md](../procmgr/docs/ipc-interface.md) | `LIST_PROCESSES`, `ATTACH_PROCESS`, `DETACH_PROCESS`, `DECLARE_NO_DEBUG`, `REGISTER_THREAD` |
| [services/drivers/virtio/console/README.md](../drivers/virtio/console/README.md) | The debug port's driver and the serial protocol it serves |
| [docs/device-management.md](../../docs/device-management.md) | The debug port and `QUERY_DEVICE` |

---

## Summarized By

[Fault Handling](../../docs/fault-handling.md), [Testing](../../docs/testing.md),
[services/README.md](../README.md),
[procmgr IPC Interface](../procmgr/docs/ipc-interface.md),
[xtask/README.md](../../xtask/README.md)
