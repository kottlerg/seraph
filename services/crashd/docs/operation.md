# crashd Operation

How crashd registers as the crash service, handles each fault, bounds that handling, and what it
cannot report.

---

## Startup

1. crashd declares itself undebuggable to procmgr (`DECLARE_NO_DEBUG`), so no debug-authority
   holder stops it and its own threads are not bound to the endpoint it receives on.
2. Its bootstrap round delivers one cap, a `DEBUG_AUTHORITY`-badged `SEND|GRANT` on procmgr, which
   its recipe's `debug_authority = yes` has svcmgr mint
   ([`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md) § `debug_authority`).
3. It binds its main thread's upcall class to an endpoint its watchdog thread receives on, and
   starts that thread ([Bounds](#bounds)).
4. It sends `REGISTER_CRASH_SERVICE` with a Thread cap of its main thread, and receives a `RECV` cap
   on procmgr's crash endpoint, which every process procmgr creates has its exception class bound
   to ([procmgr IPC Interface](../../procmgr/docs/ipc-interface.md) § Crash Endpoint and Debug
   Authority).

When crashd dies, procmgr declines the faults on the endpoint until a respawned crashd registers.

---

## Per Fault

The fault message carries the badge the faulting thread's exception class is bound under, the
fault's kind and words, and the instruction pointer. The badge names the thread: the process badge
names its main thread (or a thread that never registered, which kept its spawner's binding), and a
thread crash badge the registered thread procmgr bound under it
([procmgr IPC Interface](../../procmgr/docs/ipc-interface.md) § Crash Endpoint and Debug
Authority). crashd:

1. sends `ATTACH_PROCESS` for the badge, which returns the Thread caps of the process's threads
   from the first, its main thread, then each registered one, at most four a reply; the image's
   load bias and text bounds; the process badge; and the index of the thread the badge names;
2. takes the named thread's cap, from that reply, or from a second attach whose page starts at the
   index when the index lies past the first page, and reads its registers. The read succeeds only
   for a thread that is stopped or fault-blocked, and crashd takes the thread as the faulting one
   when it does and the register file's instruction pointer is the message's; the check catches a
   thread that never registered, whose spawner's badge named another thread. The block's `thread`
   is then `main` or `spawned`, and the block carries the registers and the stack walk; otherwise it
   is `unidentified`. Another thread of the process blocked on a fault at the same instruction,
   whose fault some other handler holds, is not taken for the faulting one: its badge is not the
   message's;
3. reads the bytes at the instruction pointer through the same cap, since every thread of the
   process shares its address space;
4. logs the block ([block-format.md](block-format.md)), then declines the fault with the block's id
   as the decline reason, which the kernel prints on its `fault unhandled` line.

The block is logged before the decline, so the kernel's diagnostic of the kill does not land among
its lines on the serial console.

A fault of a restartable syscall's user copy never reaches crashd: its pager's forward is a decline
([docs/fault-handling.md](../../../docs/fault-handling.md) § Reply), so the syscall fails and the
process, which lives on, leaves no report.

---

## Bounds

Handling one fault, its reading and its block's logging, is bounded by a watchdog, 2 s per fault
(`FAULT_BOUND`, checked every 100 ms, `WATCHDOG_TICK`). The attach request can wait on procmgr, and
procmgr can be waiting on the faulting process (an fs driver serving a `CREATE_FROM_FILE` read); a
log write can wait on a driver logd writes through before that driver has declared itself
undebuggable. When the bound passes, the watchdog posts the receiving thread an upcall
([docs/fault-handling.md](../../../docs/fault-handling.md) § Asynchronous Upcalls), which cancels
the blocking request it waits in (`Interrupted`) and is then served by the watchdog. An upcall never
cancels a fault of the receiving thread's own, a page fault on its pager included, so the bound
cannot end crashd. Each fault takes a generation, which the watchdog re-reads just before the post,
and an attach cancelled for an earlier generation is sent again, so a late cancellation does not cut
the next fault's handling short. On the cancellation crashd declines the fault at once, marking the
block `status=timeout` when the attach was the request cancelled, and logs the rest of the block
after the decline, when nothing waits on the faulting thread any more. The stack scan reads at most
8 KiB (`STACK_SCAN_BYTES`).

---

## Limits

- **Threads that never registered.** A thread the runtime spawns registers itself with procmgr
  before it runs its code ([runtime/ruststd/README.md](../../../runtime/ruststd/README.md) § Thread
  registration). A thread that did not (procmgr refused it at the per-process bound, or the call
  failed, or the process does not use the runtime's spawn) is not in the attach list, and its
  faults carry its spawner's badge. crashd cannot read its registers, so its block carries
  `thread=unidentified`, the fault, the image placement, and the bytes at the instruction pointer,
  and no registers and no stack walk. When its spawner was a registered thread that has since exited
  and been dropped from the registry, the spawner's crash badge names no thread any more: the attach
  is refused, and the block is `status=unattached`, with the fault message's fields alone.
- **Uncovered processes.** init, memmgr, and procmgr are not created by procmgr. logd, the serial
  driver, and the framebuffer driver, through which logd writes every line, and crashd declare
  themselves undebuggable at startup, as svctest and the GDB stub, debug-authority holders, do in a
  boot that stages them;
  before the declaration, a fault of one of them reaches crashd and is declined once the bound
  passes. A fault of any of these takes the outcome it has with no handler bound; the kernel's
  `fault unhandled` and `USERSPACE FAULT` lines are its only report.
- **Pinned processes' page faults.** A process created `CREATE_PINNED`, or whose pager binding
  failed, has no virtual-memory handler: its page faults kill it with no forward and no report. Its
  exceptions are reported.
- **Debugged threads.** A debugger that binds a thread's exception class takes its faults; crashd
  sees none of them.

Persistence of the reports through logd's disk and network sinks, core dumps after the log report,
and holding a crashed process stopped for a debugger are design intent; not yet implemented
([docs/fault-handling.md](../../../docs/fault-handling.md) § Crash Reports).

---

## Summarized By

[Fault Handling](../../../docs/fault-handling.md), [Testing](../../../docs/testing.md),
[services/crashd/README.md](../README.md),
[services/drivers/framebuffer/README.md](../../drivers/framebuffer/README.md),
[services/drivers/serial/README.md](../../drivers/serial/README.md),
[services/logd/README.md](../../logd/README.md),
[procmgr IPC Interface](../../procmgr/docs/ipc-interface.md)
