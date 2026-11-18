# crashd Operation

How crashd registers as the crash service, handles each fault, holds a fault declined for want of
memory, writes a core of a process its policy names, bounds that handling, and what it cannot
report.

---

## Startup

1. crashd declares itself undebuggable to procmgr (`DECLARE_NO_DEBUG`), so no debug-authority
   holder stops it and its own threads are not bound to the endpoint it receives on.
2. Its bootstrap round delivers one cap, a `DEBUG_AUTHORITY`-badged `SEND|GRANT` on procmgr, which
   its recipe's `debug_authority = yes` has svcmgr mint
   ([`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md) § `debug_authority`).
3. It reads its core-dump policy from the `CORE_DUMP` entry of its environment and logs it
   ([Core Dump](#core-dump)), and its stall from `CRASHD_OOM_STALL_MS` ([Hold](#hold)).
4. It starts its watchdog thread, then binds its main thread's upcall class to an endpoint the
   watchdog receives on, so the watchdog does not copy that binding onto itself
   ([Bounds](#bounds)).
5. It sends `REGISTER_CRASH_SERVICE` with a Thread cap of its main thread, and receives a `RECV` cap
   on procmgr's crash endpoint, which every process procmgr creates has its exception class bound
   to ([procmgr IPC Interface](../../procmgr/docs/ipc-interface.md) § Crash Endpoint and Debug
   Authority).
6. With a stall set, it makes its hold endpoints and wait set and touches its stack and heap
   ([Hold](#hold)), and logs `holding faults declined for want of memory up to <stall> ms`. It
   logs `reporting crashes` and receives faults.

When crashd dies, procmgr declines the faults on the endpoint until a respawned crashd registers.

---

## Per Fault

The fault message carries the badge the faulting thread's exception class is bound under, the
fault's kind and words, and the instruction pointer. The badge names the thread: the process badge
names its main thread (or a thread that never registered, which kept its spawner's binding or, when
that was a debugger's, was bound back under the process badge at its refused registration), and a
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
4. logs the block ([block-format.md](block-format.md));
5. writes a core of the process when its policy names it ([Core Dump](#core-dump)), and logs the
   dump's line;
6. declines the fault with the block's id as the decline reason, which the kernel prints on its
   `fault unhandled` line.

The block and the dump's line are logged before the decline, so the kernel's diagnostic of the
kill does not land among them on the serial console.

A fault of a restartable syscall's user copy never reaches crashd: its pager's forward is a decline
([docs/fault-handling.md](../../../docs/fault-handling.md) § Reply), so the syscall fails and the
process, which lives on, leaves no report.

A page fault memmgr declined for want of memory is first held, when crashd's stall is set
([Hold](#hold)).

---

## Hold

`CRASHD_OOM_STALL_MS` in crashd's environment, a decimal number of milliseconds, sets the stall:
how long crashd holds a page fault memmgr declined for want of memory before it reports and
declines it. No entry, or `0`, holds none, and crashd handles every fault as
[Per Fault](#per-fault) says. A value that is not decimal digits is logged as a warning and holds
none; one past 600 000 ms (`STALL_MAX_MS`, ten minutes) is clamped to it, logged. The shipped
recipe sets 10 000 ms, longer than oomd's grace and cooldown together; the usertest boot's sets
3000 ms
([docs/testing.md](../../../docs/testing.md) § Crash reports).

With a stall set, crashd makes 16 hold endpoints at start (`SLOTS`), each the queue of one held
fault, and a wait set of procmgr's crash endpoint and the Notification on which the runtime
receives memmgr's pressure-level changes. It waits on the wait set with a timeout of the earliest
hold's deadline, and receives from the crash endpoint without blocking when the wait set names it.
When the endpoints or the wait set cannot be made, or the process has no pressure registration, it
logs a warning and runs with no hold. It reads memmgr's level when the Notification has signalled
a change since its last read, and takes the level as `CRITICAL` while memmgr does not answer.

A fault is holdable when it is a VM fault memmgr forwarded with decline code 7 (no free page can
back it), 6 (the metadata arena cannot grow) or 8 (the region's chunk table cannot record the run)
([memmgr IPC Interface](../../memmgr/docs/ipc-interface.md) § Kernel-origin fault message). Code
10, a budget node's max, is the process's own limit, and a holdable fault is never one of an
exception class; crashd handles each such fault at once. A holdable fault that arrives:

- at `CRITICAL` with a slot free is redirected (`FAULT_REPLY_REDIRECT`,
  [docs/fault-handling.md](../../../docs/fault-handling.md) § Reply) to that slot's endpoint, with
  the slot as its reason word. crashd keeps the fault's message as it arrived and logs
  `fault badge=<badge> addr=<addr> held: memory critical (reason=<code>), up to <stall> ms`. The
  thread stays fault-blocked, and its fault reaches that endpoint when the thread next runs, to
  wait there queued; no thread of crashd waits on it, so crashd goes on receiving and reporting
  other faults. The endpoint is in crashd's wait set from the redirect until the fault arrives;
- at `CRITICAL` with every slot taken is logged `not held: no free hold slot` as a warning, then
  reported and declined;
- below `CRITICAL`, the level having fallen between memmgr's decline and crashd's receive, is
  resumed at once (`FAULT_REPLY_RESUME`), logged `resumed at once: memory no longer critical`.

When the level falls below `CRITICAL`, crashd receives each held fault that has arrived from its
endpoint without blocking and resumes it, logging `resumed after <ms> ms: memory no longer
critical`; the thread retries its access, which faults into memmgr again. A fault that has not
arrived yet stays held, and is resumed when it arrives. When a hold's deadline passes first,
crashd receives that fault, logs `hold timed out after <ms> ms` as a warning, and reports and
declines it as [Per Fault](#per-fault) does, from the message it kept. A receive that finds
nothing after the fault arrived frees the slot with no answer, logged `withdrawn after <ms> ms
held`: the fault left the endpoint while held, when a debugger's attach stopped the thread, which
cancels its fault, the process was destroyed, or the thread's exception class was rebound, which
delivers the fault again under the new binding
([docs/fault-handling.md](../../../docs/fault-handling.md) § Delivery, Resume, and Kill). A
fault that has not arrived when its deadline passes (its thread was stopped or destroyed before
it ran) is logged `not delivered to its hold in <ms> ms` as a warning, and crashd replaces the
slot's endpoint with a new one, so a slot's endpoint only ever queues the fault crashd holds
there. Should that fault reach the old endpoint later, its delivery holds the endpoint's last
reference, and the fault is released unhandled, its thread killed with no report
([docs/fault-handling.md](../../../docs/fault-handling.md) § Liveness, rule 1). A slot whose new
endpoint cannot be made is retired, logged, and holds no fault again until crashd restarts.

crashd remembers each fault it resumed, by its badge and faulting page, until that fault's hold
deadline, in 16 entries, the one that expires first replaced when they are full. A fault of the
same badge and page before then repeats it: at `CRITICAL` it is held only until that deadline;
below `CRITICAL` it is logged `not held: repeats a resumed fault` as a warning, then reported and
declined. So an access memmgr cannot back once memory is freed is not resumed into a loop, and the
holds of one fault total at most the stall.

**While memory is critical.** crashd runs inside memmgr's system reserve: its recipe's
`reserve = yes` has svcmgr create it with a reserve budget node
([`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md) § `reserve`), so a page
it touches for the first time while the level reads `CRITICAL` is backed from the reserve, which
the processes outside it cannot take
([services/memmgr/docs/memory-pool.md](../../memmgr/docs/memory-pool.md) § Distribution policy).
Only a reserve that is itself spent declines such a page, and crashd, undebuggable and with no
handler of its own faults, then dies of it. Its held faults are then released unhandled, as a
decline would end them, with no report
([docs/fault-handling.md](../../../docs/fault-handling.md) § Liveness, rule 3), and procmgr
declines new faults until the respawned crashd registers. The reserve is shared with the core
services, so crashd draws on it as little as it can: with a stall set, crashd touches
64 KiB of its heap at start (`HEAP_TOUCH_BYTES`), which the allocator reuses for a report's
buffers, and 32 KiB of the stacks of its main and watchdog threads (`STACK_TOUCH_BYTES`); its log
writes format on the stack. A report allocates its block's lines, its stack scan (at most 8 KiB),
its registers, the bytes at the instruction pointer and its frames, all within that heap. While the
level reads `CRITICAL` it writes no core, since a core's buffers and the file system's writes need
pages a report does not: the dump's line is `not written: memory is critical`
([Core Dump](#core-dump)). A report that needs a page past those takes it from the reserve.

---

## Core Dump

`CORE_DUMP` in crashd's environment, which its recipe's `env` key sets, names the processes
crashd writes a core of. `no`, the recipe's value, or no entry, writes none. Otherwise the value is
a comma-separated list of names, each matched against a process's name, the first string of its
argv, or that name's last path component, so `crashme` names a process started as
`/programs/crashme`. A process with an empty name is never named. crashd logs the setting at
startup, `core dumps off` or `core dumps for <list>`; a list holding an empty name is logged as a
warning and writes no core. The usertest boot stages a recipe that names `crashme`
([docs/testing.md](../../../docs/testing.md) § Crash reports).

A dump follows the block when the report attached and read the process within its bound, its
`status` `complete`, and the policy is not off. Its steps, in order, each under the dump's bound
([Bounds](#bounds)):

1. It reads the process's name from `LIST_PROCESSES`, and ends, with no line, when the policy
   does not name it.
2. It writes no core while memory is critical, when crashd holds faults and memmgr's level reads
   `CRITICAL` ([Hold](#hold)).
3. It writes no core of a process that declared itself on the core path (`DECLARE_NO_CORE`, which
   the attach reply's flags word reports): vfsd, the FAT driver, the block driver, devmgr and the
   IOMMU driver, through which the core would be written, and logd, which the outcome line below
   and every process's log output wait on while step 4 holds its threads, so the dump never waits
   on the process that died
   ([procmgr IPC Interface](../../procmgr/docs/ipc-interface.md) § Label 26: `DECLARE_NO_CORE`).
4. It attaches the process again, page by page, and stops each listed thread but the faulting one
   (`SYS_THREAD_STOP`): the fault holds that one already, and a stop would cancel its fault. It
   reads the registers and extended state of each, the faulting thread first, at most 256 threads
   (`CORE_THREADS_MAX`); a thread past them is stopped and not recorded. When the faulting thread
   is not listed (one that never registered), it writes no core.
5. It lists the address space's pages (`SYS_THREAD_LIST_PAGES`), reads the image's ELF header at
   the load bias for the core's `NT_AUXV`, and lays the core out within the per-core budget.
6. It deletes the `.part` files earlier dumps left, and the oldest cores until the new one fits
   the directory budget.
7. It writes the core under its `.part` name, reading the pages through the faulting thread's
   cap, and renames it.

The threads it stopped stay stopped: the decline that follows ends the process, whose teardown ends
every thread. The core's names, budgets and contents are in [core-format.md](core-format.md).

After the block, before the decline, crashd logs one line of the dump's outcome, carrying the
block's `id`:

```
core id=<id> written /crash/<name> bytes=<size>
core id=<id> not written: <reason>
```

A process the policy does not name gets no line.

---

## Bounds

Handling one fault, its reading and its block's logging, is bounded by a watchdog, 2 s per fault
(`FAULT_BOUND`, checked every 100 ms, `WATCHDOG_TICK`). The attach request can wait on procmgr, and
procmgr can be waiting on the faulting process (an fs driver serving a `CREATE_FROM_FILE` read); a
log write can wait on a driver logd writes through before that driver has declared itself
undebuggable. When the bound passes, the watchdog posts the receiving thread an upcall
([docs/fault-handling.md](../../../docs/fault-handling.md) § Asynchronous Upcalls), which cancels
the blocking request it waits in (`Interrupted`) and is then served by the watchdog. It posts
another each tick until crashd ends that step, so a request a runtime call sends after the first
cancellation (the close a file sends as it is dropped) is cancelled in its turn. An upcall never
cancels a fault of the receiving thread's own, a page fault on its pager included, so the bound
cannot end crashd. Each fault takes a generation, and the watchdog commits to cancel one only while
it is still being handled ([`fault-bound/`](../fault-bound/src/lib.rs), host-tested). Once it has,
crashd starts no further request of that fault's handling, and one a runtime call still sends waits
at most a tick, wherever the upcall was delivered. On the cancellation crashd declines the fault at
once, marking the block `status=timeout` when an attach was the request cancelled, waits for the
watchdog to have served its last upcall, and logs the rest of the block after the decline, when
nothing waits on the faulting thread any more. So no cancellation of one fault reaches the next
fault's handling, unless the watchdog has not served it within another 2 s; crashd then logs that
and goes on, and the late upcall can cut one request of the next fault's handling short. The stack
scan reads at most 8 KiB (`STACK_SCAN_BYTES`).

A dump runs under a bound of its own, 60 s (`DUMP_BOUND`), after the report's and outside it, as
a new generation of the same watchdog. A request it waits in, an attach or a file-system call, is
cancelled as the report's is, and the runtime's file calls return an error for it; crashd then
starts no further request, the runtime's close of the core file cancelled in its turn, writes no
core, logs `not written: the dump passed its bound`, and
declines. The faulting thread is held while the dump runs, so the bound is the most a dump delays
the process's teardown and crashd's next fault. It covers a core of the per-core budget, 2 MiB
(`CORE_BYTES_MAX`), at half the slowest rate measured writing through the FAT driver, about
75 KB/s on a riscv64 debug build under QEMU, where each 4 KiB write allocates a cluster: the 0.9 MiB
core of crashme's `worker` mode took 8 s to 12 s on debug builds of both architectures.

---

## Limits

- **Threads that never registered.** A thread the runtime spawns registers itself with procmgr
  before it runs its code ([runtime/ruststd/README.md](../../../runtime/ruststd/README.md) § Thread
  registration). A thread that did not (procmgr refused it at the per-process bound, or the call
  failed, or the process does not use the runtime's spawn) is not in the attach list, and its
  faults carry its spawner's badge, or the process badge when procmgr refused it at the bound or
  for its heap while it carried a debugger's binding and bound it back under that badge. crashd
  cannot read its registers, so its block carries `thread=unidentified`, the fault, the image
  placement, and the bytes at the instruction pointer, and no registers and no stack walk. When its
  spawner was a registered thread that has since exited and been dropped from the registry, the
  spawner's crash badge names no thread any more: the attach is refused, and the block is
  `status=unattached`, with the fault message's fields alone.
- **Uncovered processes.** init, memmgr, and procmgr are not created by procmgr. The serial
  driver and the framebuffer driver, through which logd writes every line, the debug port's
  virtio-console driver, which the GDB stub waits on, and crashd declare themselves undebuggable at
  startup, as svctest and the GDB stub, debug-authority holders, do in a boot that stages them;
  before the declaration, a fault of one of them reaches crashd and is declined once the bound
  passes. A fault of any of these takes the outcome it has with no handler bound; the kernel's
  `fault unhandled` and `USERSPACE FAULT` lines are its only report.
- **Pinned processes' page faults.** A process created `CREATE_PINNED`, or whose pager binding
  failed, has no virtual-memory handler: its page faults kill it with no forward and no report. Its
  exceptions are reported.
- **Debugged threads.** A debugger that binds a thread's exception class takes its faults; crashd
  sees none of them.
- **Cores.** A process whose faulting thread never registered gets no core, and a core records at
  most 256 threads ([Core Dump](#core-dump)). A file write the dump's bound cancels leaves its page
  frame mapped in crashd until crashd exits, since the FAT driver may still be copying from it
  (`write_memory_chunks` in
  [`runtime/ruststd/src/sys/fs/seraph.rs`](../../../runtime/ruststd/src/sys/fs/seraph.rs)); each
  cancelled dump costs one page so.

Persistence of the reports through logd's disk and network sinks, and holding a crashed process
stopped for a debugger, are design intent; not yet implemented
([docs/fault-handling.md](../../../docs/fault-handling.md) § Crash Reports).

---

## Summarized By

[Fault Handling](../../../docs/fault-handling.md),
[Supervision](../../../docs/supervision.md), [Testing](../../../docs/testing.md),
[services/crashd/README.md](../README.md),
[services/drivers/framebuffer/README.md](../../drivers/framebuffer/README.md),
[services/drivers/serial/README.md](../../drivers/serial/README.md),
[procmgr IPC Interface](../../procmgr/docs/ipc-interface.md)
