# crashd Operation

How crashd registers as the crash service, handles each fault, holds a fault declined for want of
memory, writes a core of a process its policy names, writes a live core of a running process on
request, bounds that handling, and what it cannot report.

---

## Startup

1. crashd declares itself undebuggable to procmgr (`DECLARE_NO_DEBUG`), so no debug-authority
   holder stops it and its own threads are not bound to the endpoint it receives on.
2. Its bootstrap round delivers three caps: the `RECV` on its live-core endpoint, which its
   recipe's `provides = crashd.core:grant` has svcmgr create ([Live Core](#live-core)); the
   `logd.flush` seed of its recipe's `seed = logd.flush`, a `LOG_FLUSH_AUTHORITY`-badged `SEND`
   on logd's master log endpoint that carries logd's flush barrier and no other authority
   ([logd IPC interface](../../logd/docs/ipc-interface.md#flush-barrier) § Flush barrier), which
   step 6 of [Per Fault](#per-fault) waits on; and a `DEBUG_AUTHORITY`-badged `SEND|GRANT` on
   procmgr, which its recipe's `debug_authority = yes` has svcmgr mint
   ([`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md) § `provides`, § `seed`,
   § `debug_authority`). Without the authority it reports nothing and exits; without the endpoint
   it logs a warning and writes no live core; without the seed it declines each fault without
   waiting for the log.
3. It reads its core-dump policy from the `CORE_DUMP` entry of its environment and logs it
   ([Core Dump](#core-dump)), and its stall from `CRASHD_OOM_STALL_MS` ([Hold](#hold)).
4. It sends `REGISTER_CRASH_SERVICE` with a Thread cap of its main thread, and receives a `RECV` cap
   on procmgr's crash endpoint, which every process procmgr creates has its exception class bound
   to ([procmgr IPC Interface](../../procmgr/docs/ipc-interface.md) § Crash Endpoint and Debug
   Authority).
5. With a stall set, it makes its hold endpoints and wait set and touches its stack and heap
   ([Hold](#hold)), and logs `holding faults declined for want of memory up to <stall> ms`. It
   logs `reporting crashes` and receives faults, and live-core requests, one at a time from a wait
   set of both endpoints.

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
   index when the index lies past the first page, and reads its registers. The read succeeds for a
   thread that is not running, and crashd takes the thread as the faulting one when it reads as
   stopped or fault-blocked, not as blocked in a syscall, and the register file's instruction
   pointer is the message's; the check catches a thread that never registered, whose spawner's
   badge named another thread. The block's `thread` is then `main` or `spawned`, and the block
   carries the registers and the stack walk; otherwise it is `unidentified`. Another thread of the
   process blocked on a fault at the same instruction, whose fault some other handler holds, is not
   taken for the faulting one: its badge is not the message's;
3. reads the bytes at the instruction pointer through the same cap, since every thread of the
   process shares its address space;
4. logs the block ([block-format.md](block-format.md));
5. writes a core of the process when its policy names it ([Core Dump](#core-dump)), and logs the
   dump's line;
6. waits on logd's flush barrier until logd has written the lines it took before the wait to the
   sinks that hold the log, within what is left of the report's 2 s bound ([Bounds](#bounds)),
   asking again after each retry hint (`ipc::log_flush::wait`); logd answers at once when no sink
   holds the log or the one that does is stalled
   ([logd IPC interface](../../logd/docs/ipc-interface.md#flush-barrier) § Flush barrier);
7. declines the fault with the block's id as the decline reason, which the kernel prints on its
   `fault unhandled` line. It declines whatever step 6 ended on: flushed, refused, not answered,
   or out of time.

The block and the dump's line are logged before the decline, so the kernel's diagnostic of the
kill does not land among them on the serial console. logd answers a log call once it holds the
line and writes it later, and the lines it holds unwritten die with it; the wait of step 6 is
what lets the block of a fault of logd's own, which the decline ends, reach the serial console.

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
recipe sets 10 000 ms, and svctest's test recipe sets 5000 ms
([docs/testing.md](../../../docs/testing.md) § Crash reports).

**The stall and oomd's ladder.** oomd stops one candidate once the level has read `CRITICAL` for
its grace (2000 ms), and another each cooldown (5000 ms) while it still reads `CRITICAL`
([services/oomd/docs/operation.md](../../oomd/docs/operation.md) § Ladder). The shipped stall is
longer than the grace and the cooldown together, so a fault held from the level's rise outlasts
oomd's first two acts, at 2000 ms and 7000 ms, and the 3000 ms after the second in which its
stopped candidate's memory comes back; a fault held later in the episode outlasts the act that
falls due next. When the stops within the stall give back too little to lift the level, the act
that does falls after the stall: the hold times out, and crashd reports and declines the fault. The
stall is not sized to the ladder, whose length is the number of candidates oomd stops before the
one whose memory lifts the level, and which no fixed bound covers; it bounds how long a thread
waits on the policy, and a stop that frees memory within it resumes the thread rather than ending
it.

With a stall set, crashd makes 16 hold endpoints at start (`SLOTS`), each the queue of one held
fault, and a wait set of procmgr's crash endpoint and the Notification on which the runtime receives
memmgr's pressure-level changes and draw-room openings. It waits on the wait set with a timeout of
the earliest hold's deadline, and receives from the crash endpoint without blocking when the wait
set names it. When the endpoints or the wait set cannot be made, or the process has no pressure
registration, it logs a warning and runs with no hold. It reads memmgr's level and draw room when
the Notification has signalled since its last read, and the draw room again for each fault of code
7 or 11 that reaches it, since memmgr signals the draw room's opening and not its closing. It takes
the level as `CRITICAL`, and the draw room as short, while memmgr does not answer. Every receive it
makes, from the crash endpoint, the live-core endpoint and the slots' endpoints, goes through one
receive guard ([docs/ipc-design.md](../../../docs/ipc-design.md) § Receive-Failure Policy): a
receive that fails leaves its message queued and the wait set names the source again at once, so a
failure that keeps repeating ends crashd with `EXIT_RECV_WEDGE` for svcmgr's restart, and one on a
slot's endpoint leaves that hold as it was.

A fault is holdable when it is a VM fault memmgr forwarded with decline code 7 (no free page can
back it), 11 (a commit overrun: no free frame for a committed page), 6 (the metadata arena cannot
grow) or 8 (the region's chunk table cannot record the run)
([memmgr IPC Interface](../../memmgr/docs/ipc-interface.md) § Kernel-origin fault message). Code
10, a budget node's max, is the process's own limit, and a holdable fault is never one of an
exception class; crashd handles each such fault at once. A fault of code 6 or 8 waits on the
level: its memory is short while the level reads `CRITICAL`. A commit overrun waits on memmgr's
draw room, the free frames a fault on a committed page may take (`QUERY_POOL_STATUS` `data[16]`;
[memmgr Memory Pool](../../memmgr/docs/memory-pool.md#commit) § Commit, Overcommit): its memory
is short while the draw room is below a demand chunk's 64 KiB, the most one committed draw takes,
and the draw room opens at that, which memmgr signals. Write-out to swap brings the draw room back
while the level stays `CRITICAL`, so a commit overrun waits on the draw room and not on the level.
A fault of code 7 waits on either, its memory short while both are: the code is a demand page no
free page outside `promised` and the growth floor can back, which the level tracks, or the restore
of an evicted chunk the free frames do not cover while swap slots are registered, which the
evictions that free frames admit while the level stays `CRITICAL`
([memmgr Memory Pool](../../memmgr/docs/memory-pool.md#eviction) § Eviction, Restore headroom),
and an open draw room has room for a chunk's restore. The decline word does not tell the two apart.
A holdable fault that arrives:

- while its memory is short, with a slot free, is redirected (`FAULT_REPLY_REDIRECT`,
  [docs/fault-handling.md](../../../docs/fault-handling.md) § Reply) to that slot's endpoint, with
  the slot as its reason word. crashd keeps the fault's message as it arrived and logs
  `fault badge=<badge> addr=<addr> held: <short> (reason=<code>), up to <stall> ms`, `<short>`
  being `memory critical` for the level, `no commit draw room` for the draw room, and
  `memory critical and no commit draw room` for either. The
  thread stays fault-blocked, and its fault reaches that endpoint when the thread next runs, to
  wait there queued; no thread of crashd waits on it, so crashd goes on receiving and reporting
  other faults. The endpoint is in crashd's wait set from the redirect until the fault arrives;
- while its memory is short, with every slot taken, is logged `not held: no free hold slot` as a
  warning, then reported and declined;
- with its memory there, the level having fallen below `CRITICAL`, or the draw room having
  opened, between memmgr's decline and crashd's receive, is resumed at once (`FAULT_REPLY_RESUME`),
  logged `resumed at once: <back>`, `<back>` being `memory no longer critical` for the level,
  `commit draw room open` for the draw room, and `memory no longer critical or commit draw room
  open` for either.
When the memory a held fault waits for is there, the level below `CRITICAL` or the draw room open,
crashd receives each such held fault that has arrived from its endpoint without blocking and resumes
it, logging `resumed after <ms> ms: <back>`; the thread retries its access, which faults into memmgr
again. A fault that has not arrived yet stays held, and is resumed when it arrives. When a hold's
deadline passes first, crashd receives that fault, logs `hold timed out after <ms> ms` as a warning,
and reports and declines it as [Per Fault](#per-fault) does, from the message it kept. A receive
that finds nothing after the fault arrived frees the slot with no answer, logged `withdrawn after
<ms> ms held`: the fault left the endpoint while held, when a debugger's attach stopped the thread,
which cancels its fault, the process was destroyed, or the thread's exception class was rebound,
which delivers the fault again under the new binding
([docs/fault-handling.md](../../../docs/fault-handling.md) § Delivery, Resume, and Kill). A fault
that has not arrived when its deadline passes (its thread was stopped or destroyed before it ran) is
logged `not delivered to its hold in <ms> ms` as a warning, and crashd replaces the slot's endpoint
with a new one, so a slot's endpoint only ever queues the fault crashd holds there. Should that
fault reach the old endpoint later, its delivery holds the endpoint's last reference, and the fault
is released unhandled, its thread killed with no report
([docs/fault-handling.md](../../../docs/fault-handling.md) § Liveness, rule 1). A slot whose new
endpoint cannot be made is retired, logged, and holds no fault again until crashd restarts.

crashd remembers each fault it resumed, by its badge and faulting page, until that fault's hold
deadline, in 16 entries, the one that expires first replaced when they are full. A fault of the same
badge and page before then repeats it: while its memory is short it is held only until that
deadline. With its memory there, a repeat of a fault that waits on the level is logged `not held:
repeats a resumed fault` as a warning, then reported and declined, so an access memmgr cannot back
once memory is freed is not resumed into a loop. A repeat of a commit overrun with the draw room
open is resumed again, logged `resumed at once: commit draw room open`, and remembered until the
same deadline: one opening of the draw room backs one committed draw, and another may have taken
it between the resume and the retry. A repeat of a fault of code 7 waits on the level alone, so a
demand page that the draw room's opening resumed and memmgr declines again is resumed into that
decline at most once per hold. The holds of one fault total at most the stall.

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
buffers, and 32 KiB of its thread's stack (`STACK_TOUCH_BYTES`); its log
writes format on the stack. A report allocates its block's lines, its stack scan (at most 8 KiB),
its registers, the bytes at the instruction pointer and its frames, all within that heap. While the
level reads `CRITICAL`, while memmgr's draw room is short, and while it holds a fault, it writes no
core, since a core's buffers and the file system's writes need pages a report does not, and a fault
of the file system's threads that memmgr declines for want of them would wait on crashd, which
serves nothing while it dumps, past its stall: the dump's line is `not written: memory is short`
([Core Dump](#core-dump)). A report that needs a page past those takes it from the reserve.

---

## Core Dump

`CORE_DUMP` in crashd's environment, which its recipe's `env` key sets, names the processes crashd
writes a core of. `no`, the recipe's value, or no entry, writes none. Otherwise the value is a
comma-separated list of names, each matched against a process's name, the first string of its argv,
or that name's last path component, so `crashme` names a process started as
`/tests/fixtures/programs/crashme`. A process with an empty name is never named. crashd logs the
setting at startup, `core dumps off` or `core dumps for <list>`; a list holding an empty name is
logged as a warning and writes no core. The svctest sets other than `crash-endpoint` stage a recipe
that names `crashme` ([docs/testing.md](../../../docs/testing.md) § Crash reports).

A dump follows the block when the report attached and read the process within its bound, its
`status` `complete`, and the policy is not off. Its steps, in order, each under the dump's bound
([Bounds](#bounds)):

1. It reads the process's name from `LIST_PROCESSES`, and ends, with no line, when the policy
   does not name it.
2. It writes no core while memory is short, when crashd runs with a stall and holds a fault, or
   memmgr's level reads `CRITICAL` or its draw room is short, read as the report ends
   ([Hold](#hold)).
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
5. It asks procmgr to make resident (`MAKE_RESIDENT`) the range from the page of the fault's
   instruction and of each thread's stack pointer up, an equal share of the per-core budget each, so
   memmgr restores each chunk it evicted there, the ones the layout keeps first (a chunk on disk the
   swap service restores, crashd pausing and asking again after each pending reply, at most
   `ipc::PENDING_TRIES` pauses, about a second, over the whole dump), then
   lists the address space's pages (`SYS_THREAD_LIST_PAGES`), reads the image's ELF header at the
   load bias for the core's `NT_AUXV`, and lays the core out within the per-core budget.
6. It deletes the `.part` files earlier dumps left, and the oldest cores until the new one fits
   the directory budget.
7. It writes the core under its `.part` name, reading the pages through the faulting thread's
   cap, and renames it. A page the read finds not present, one memmgr evicted since the list, is
   made resident through procmgr and read again, under the dump's bound of step 5: its pauses count
   against the same `ipc::PENDING_TRIES`, and once the dump's deadline has passed no page is asked
   for (`ipc::read_mem_resident_bounded`).

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

## Live Core

A holder of the `crashd.core` name asks crashd for an ELF core of a process that keeps running
(`LIVE_CORE`, [`shared/ipc/src/crashd_labels.rs`](../../../shared/ipc/src/crashd_labels.rs)).
svcmgr publishes the name seed-only, as a `:grant` entry, badged `LIVE_CORE_AUTHORITY`: a live
core copies the process's memory, and the request moves the account the capture is charged to. The
request names the process in a name block, matched as `CORE_DUMP` matches a name
([Core Dump](#core-dump)), and carries as `caps[0]` the requester's own memmgr `SEND`, the
account. `CORE_DUMP` does not apply: the authority is the policy. crashd serves one request at a
time, between faults, and deletes every cap the request carried before it replies.

Its steps, in order, under the dump's bound ([Bounds](#bounds)):

1. It refuses an unknown label (`UNKNOWN_OPCODE`), a badge without the authority
   (`UNAUTHORIZED`), a missing, empty or too long name, or a `caps[0]` that is not an endpoint
   `SEND` (`INVALID_ARGUMENT`), and any request while memory is short, as for a crash core, or
   while memmgr's level reads `CRITICAL` (`MEMORY_CRITICAL`).
2. It finds the first live process, in badge order, that the name names (`LIST_PROCESSES`), or
   replies `NOT_FOUND`.
3. It attaches the process (`ATTACH_PROCESS`), asking for no thread from an index past every
   list, so procmgr derives no thread cap, and sending no debugger watch, so the attach leaves
   nothing held in procmgr or in crashd. A process that declared itself on the core path
   (`DECLARE_NO_CORE`) before the request gets no core: crashd replies `NO_CORE` at once, sends
   no snapshot and charges nothing to the account, the declaration being one-way. Every other
   answer of the attach, a refusal or a failed call, leaves the reply to step 4, whose refusal
   procmgr gives as it would without this step; a request past its bound is `TIMED_OUT`.
4. It asks procmgr, through its debug authority, for a snapshot of the process charged to the
   account ([procmgr IPC Interface](../../procmgr/docs/ipc-interface.md) § Label 33: `SNAPSHOT`).
   procmgr holds the process for the capture alone and records each thread's registers as the
   hold left them; crashd stops no thread and copies none of the process's pages itself. A refusal
   is replied `SNAPSHOT_REFUSED`, with procmgr's label in `data[0]`, and `NOT_FOUND` when the
   process ended first.
5. It attaches the object's layout pages read-only and checks the layout.
6. It attaches the process (`ATTACH_PROCESS`) again to read its declarations as they stand after
   the capture, so a declaration the process made before the capture's hold is always seen, one
   made since step 3 among them. A process that declared itself on the core path
   (`DECLARE_NO_CORE`) gets no core: crashd replies `NO_CORE`. A process that ended before the
   attach gets `NOT_FOUND`, its declarations unknown.
   One that declared itself undebuggable since the capture is refused as at step 4,
   `SNAPSHOT_REFUSED` with procmgr's `NOT_ATTACHABLE` in `data[0]`, and any other refusal of the
   attach, with its label, the same way; a failed call is `NOT_WRITTEN`.
   Through the process's main thread crashd then reads the image's ELF header at the load bias the
   snapshot's header records, for the core's `NT_AUXV` (`ipc::read_mem_resident_bounded`); a
   read that fails, the process having ended since the attach among the causes, leaves the core
   without `NT_AUXV`, as it leaves a crash core.
7. It lays the core out within the per-core budget from the snapshot's runs and thread records
   ([core-format.md](core-format.md) § Live cores), deletes the `.part` files and the oldest
   cores as step 6 of [Core Dump](#core-dump) does, and writes the core under its `.part` name
   from the object's pages, a window of 64 pages (`WINDOW_PAGES`) attached at a time, and renames
   it.
8. It releases the object (`OBJECT_RELEASE`). Every path after a snapshot was taken releases it
   before the reply, a refusal and a request past its bound included, the release not bounded by
   it, so no live core leaves the capture charged to the account.

crashd replies `SUCCESS` with `data[0]` the process badge, `data[1]` the core's sequence number,
`data[2]` its bytes, and `data[3]` `LIVE_CORE_COMPLETE` when the snapshot holds every page it
listed. A core it could not write is `NOT_WRITTEN`, a `.part` file then perhaps remaining until
the next core, and a request that passed its bound `TIMED_OUT`
([`shared/ipc/src/crashd_errors.rs`](../../../shared/ipc/src/crashd_errors.rs)). It logs one line
of the outcome:

```
live core of <name> badge=<badge> written /crash/<file> bytes=<size>[ (incomplete)]
live core of <name> not written: <reason>
```

The capture's pages are the requester's. crashd's own cost is the layout and the window, attached
in its address space, which count against its budget node's max while attached
([memmgr IPC Interface](../../memmgr/docs/ipc-interface.md) § Label 28: `ATTACH_OBJECT`).

---

## Bounds

Handling one fault, its reading and its block's logging, runs under a call deadline 2 s ahead
(`FAULT_BOUND`; `std::os::seraph::with_call_deadline`,
[runtime/ruststd/README.md](../../../runtime/ruststd/README.md) § Call deadline), and so does the
wait for the log before the decline (step 6 of [Per Fault](#per-fault)), with what is left of the
same deadline, after a dump when one ran: one deadline over the block and the wait. The attach
request can wait on procmgr, and procmgr can be waiting on the faulting process (an fs driver
serving a `CREATE_FROM_FILE` read); a log write is refused while a sink that holds the log has not
written enough of crashd's earlier lines, and is sent again after logd's retry hint ([logd IPC
interface](../../logd/docs/ipc-interface.md#hold-window) § Hold window); the wait for the log lasts
until the sink holding the log has written the block, or that sink stalls (`SINK_STALL_MS`). A fault
in a thread of logd that holds logd's state lock leaves logd unable to answer the wait: it ends at
the deadline, the fault is declined, and the block's lines logd had not written are lost with logd.
Every call of the step carries the time left as its `SYS_IPC_CALL` timeout, so the kernel ends the
one waiting at the deadline (`WouldBlock`): crashd's own requests, the attach and the stack walk's
resident requests (`ipc::ipc_call_within`, `ipc::ResidentBound`), and the runtime's, the log writes
among them. None is sent once the deadline has passed. The deadline bounds only calls: a page fault
of crashd's own, a page fault on its pager included, is not cut, so the bound cannot end crashd.
When the deadline passes, crashd declines the fault at once, marking the block `status=timeout` when
an attach was the call it ended, and logs the rest of the block after the decline, when nothing
waits on the faulting thread any more. The deadline ends with the step, so nothing of one fault's
bound reaches the next fault's handling. The stack scan reads at most 8 KiB (`STACK_SCAN_BYTES`); a
stack page it asks procmgr to make resident waits on the swap service for at most
`ipc::PENDING_TRIES` pauses, about a second, over the whole scan, and none is asked for once the
deadline has passed. The log lines crashd writes about its holds ([Hold](#hold)) each run under a
deadline of the same 2 s, so a write that waits on a stuck driver does not stop crashd serving
faults and ending holds.

A dump runs under a call deadline of its own, 60 s (`DUMP_BOUND`), after the report's and outside
it, and so does a live core ([Live Core](#live-core)), which delays the faults that arrive meanwhile
by at most that bound. Its calls, the attach, the process list, the resident requests, and the
runtime's file-system calls, each carry the time left, and the one it waits in ends at the deadline:
crashd's own end `WouldBlock`, and the runtime's file calls fail `TimedOut`. crashd then starts no
further request, writes no core, logs `not written: the dump passed its bound`, and declines. What
the dump leaves: a request the driver had received before the deadline may still be carried out (a
write lands, a file is created); the core file's close, as it is dropped, is not sent past the
deadline: the runtime keeps the open and sends its close at crashd's next file open or at its exit
([runtime/ruststd](../../../runtime/ruststd/README.md) § Call deadline), and until then that open
stays in crashd's session with the driver, its records charged to crashd's own node
([fs driver protocol](../../fs/docs/fs-driver-protocol.md) § Label 23: `FS_SESSION`); the
`.part` file stays, and the next dump deletes it (step 6 of [Core Dump](#core-dump)); and the
threads it stopped stay stopped until the decline ends the process. The faulting thread is held
while the dump runs, so the bound is the most a dump delays the process's teardown and crashd's next
fault, which crashd then handles with no deadline left set. It covers a core of the per-core budget,
2 MiB (`CORE_BYTES_MAX`), at half the slowest rate measured writing through the FAT driver, about 75
KB/s on a riscv64 debug build under QEMU, where each 4 KiB write allocates a cluster: the 0.9 MiB
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
- **Uncovered processes.** init, memmgr, and procmgr are not created by procmgr. The debug port's
  virtio-console driver, which the GDB stub waits on, and crashd declare themselves undebuggable at
  startup, as svctest and the GDB stub, debug-authority holders, do in a boot that stages them;
  before the declaration, a fault of one of them reaches crashd and is declined once the bound
  passes. The serial and framebuffer drivers, through which logd writes the log lines, are covered:
  crashd's log lines reach them through logd's sink writers, so no thread crashd waits on waits on
  either driver for longer than logd's `SINK_STALL_MS`. A fault of any of these takes the outcome it
  has with no handler bound; the kernel's `fault unhandled` and `USERSPACE FAULT` lines are its only
  report.
- **Pinned processes' page faults.** A process created `CREATE_PINNED`, or whose pager binding
  failed, has no virtual-memory handler: its page faults kill it with no forward and no report. Its
  exceptions are reported.
- **Debugged threads.** A debugger that binds a thread's exception class takes its faults; crashd
  sees none of them.
- **Cores.** A process whose faulting thread never registered gets no core, and a core records at
  most 256 threads ([Core Dump](#core-dump)). A file write the dump's bound ends after the FAT
  driver received it leaves its page frame mapped in crashd until crashd exits, since the driver may
  still be copying from it; one the bound ends before then returns the frame (`write_memory_chunks`
  in [`runtime/ruststd/src/sys/fs/seraph.rs`](../../../runtime/ruststd/src/sys/fs/seraph.rs)). An
  abandoned dump costs at most one page so.

Persistence of the reports through logd's disk and network sinks, and holding a crashed process
stopped for a debugger, are design intent; not yet implemented
([docs/fault-handling.md](../../../docs/fault-handling.md) § Crash Reports).

---

## Summarized By

[Fault Handling](../../../docs/fault-handling.md),
[Supervision](../../../docs/supervision.md), [Testing](../../../docs/testing.md),
[services/crashd/README.md](../README.md),
[procmgr IPC Interface](../../procmgr/docs/ipc-interface.md)
