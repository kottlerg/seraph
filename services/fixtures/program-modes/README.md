# program-modes

svctest's shared program-role fixture: the processes svctest's phases spawn in the program role
whose checks need no image of their own. One binary serves every mode, chosen by the first
argument, with the mode's own arguments after it. It installs at
`/tests/fixtures/programs/program-modes`, whose `programs` path component gives it the program
signing role ([docs/signing.md](../../../docs/signing.md)); see
[docs/testing.md](../../../docs/testing.md#sysroot-layout) for where test fixtures install.

Each mode is a module under `src/` named for it (`src/<mode>.rs`); `src/main.rs` dispatches on the
first argument.

| Mode | Argv | svctest phase |
|---|---|---|
| [`capexhaust`](#capexhaust) | `program-modes capexhaust` | `recv_wedge`, `console_whole_lines` |
| [`deadline`](#deadline) | `program-modes deadline`; `program-modes deadline idle` for its idle child | `deadline` |
| [`demandpaged`](#demandpaged) | `program-modes demandpaged [oor\|ptdrain\|teardown]` | `demand_paging`, `demand_paging_segfault`, `demand_paging_pinned`, `demand_paging_pt_drain`, `demand_paging_teardown` |
| [`narrow`](#narrow) | `program-modes narrow` | `procmgr_program_narrowing` |
| [`pipefault`](#pipefault) | `program-modes pipefault` | `pipe_fault_eof` |
| [`pipestress`](#pipestress) | `program-modes pipestress <token>`; `program-modes pipestress sink` | `pipestress` |
| [`relrofault`](#relrofault) | `program-modes relrofault` | `relro_write`, `console_whole_lines` |
| [`stackoverflow`](#stackoverflow) | `program-modes stackoverflow` | `stack_overflow` |
| [`threadchurn`](#threadchurn) | `program-modes threadchurn` | `threadchurn` |
| [`threadstack`](#threadstack) | `program-modes threadstack <mode>` | `threadstack` |

Unknown mode: with no first argument or one that names no mode above, it prints
`program-modes: no mode <argument>` on stderr, the argument in Rust's debug form (`Some("x")`, or
`None` when there is none), and exits with code 2 (`src/main.rs`).

---

## capexhaust

Exhausts the process's own `CSpace` general slots, spends its IPC receive reserve on memmgr grants,
checks memmgr's undo of a grant and a sub-node whose replies fail, and then runs a guarded blocking receive loop. The
`recv_wedge` phase of [`svctest`](../../svctest/README.md)
(`services/svctest/src/phases/recv_guard.rs`) spawns `program-modes capexhaust`, waits for it to
exit, and checks that it died with `EXIT_RECV_WEDGE`. It is not a general-purpose program. Source:
`src/capexhaust.rs`.

---

### Behavior

The fixture runs these steps in order:

1. **Endpoint.** It creates a private endpoint from its object slab. If that fails, it logs
   `cap_create_endpoint failed` and exits with code 1.
2. **Exhaustion.** It derives `RIGHTS_EP_SEND` caps from the endpoint until `cap_derive`
   fails, and panics unless that failure is `OutOfMemory`. The fixture never augments its
   `CSpace`'s slot-page pool, so the loop ends at pool exhaustion with only the IPC receive
   reserve (`CSPACE_IPC_RECV_RESERVE` slots) still free (see
   [docs/capability-model.md](../../../docs/capability-model.md#address-space-and-cspace-growth-budgets)).
3. **Reserve.** It sends one-page `REQUEST_MEMORY_CAPS` calls until one is refused. The
   cap-bearing replies land in the IPC receive reserve until it is spent, so at least one
   grant lands and no more than `CSPACE_IPC_RECV_RESERVE` do; the fixture panics otherwise.
   Nothing between the derive loop and this one allocates, so no heap growth takes reserved
   slots first.
4. **Failed-reply undo.** It reads its own charge (`QUERY_MEMORY_USAGE` `data[0]`), and
   memmgr's pool `free_bytes` and the used slots of memmgr's own `CSpace`
   (`QUERY_POOL_STATUS` `data[3]` and `data[19]`), sends eight one-page
   `REQUEST_MEMORY_CAPS` calls and eight `CREATE_SUB_NODE` calls, and reads all three again.
   With its reserve spent, the `CSpace` cannot take a cap-bearing reply, so every reply MUST
   carry the `IPC_REPLY_TRANSFER_FAILED` label (see
   [docs/ipc-design.md](../../../docs/ipc-design.md#message-format)), and memmgr MUST undo each
   request ([memory-pool.md](../../memmgr/docs/memory-pool.md#receive-loop) § Receive loop):
   the grant's frames go back to the pool uncharged and its caps are deleted, and the
   sub-node's handle state is dropped and its handle cap deleted, so the two readings MUST
   match. `free_bytes` and memmgr's slots are system-wide, so another process that allocates
   or dies in the window (`crasher` shares the `svctest` boot, per
   [docs/testing.md](../../../docs/testing.md#gating)) can move them, and a first touch of a
   stack page can move the charge. The fixture therefore retries the window up to
   `ROLLBACK_WINDOW_TRIES` (8) times and panics if no window matches. If a query fails, it
   exits with code 1.
5. **Wedged receive.** It enters a blocking `ipc_recv` loop on the endpoint, routing every
   outcome through `ipc::recv_guard::RecvGuard` as services do. With its reserve spent and no
   headroom for the kernel's `MSG_CAP_SLOTS_MAX` pre-allocate, every receive fails before
   blocking, so the
   guard escalates and the process exits with `EXIT_RECV_WEDGE`, per
   [docs/ipc-design.md](../../../docs/ipc-design.md#receive-failure-policy).

---

### Log Lines

The fixture registers the log name `capexhaust` and logs these lines:

| Line | When |
|---|---|
| `cap_create_endpoint failed` | Endpoint creation failed, before the exit with code 1 |
| `general slots exhausted after <n> derives` | The reserve loop has ended (logged after it, so the log cannot take reserved slots) |
| `<n> grants landed in the IPC receive reserve; reserve spent` | The reserve loop has ended |
| `REQUEST_MEMORY_CAPS unexpected reply label <l>` | memmgr answered a grant with neither a grant nor a failed transfer, before the exit with code 1 |
| `REQUEST_MEMORY_CAPS call failed (err=<e>)` | A grant call failed, before the exit with code 1 |
| `CREATE_SUB_NODE unexpected reply label <l>` | memmgr answered a sub-node request with other than a failed transfer, before the exit with code 1 |
| `CREATE_SUB_NODE call failed (err=<e>)` | A sub-node call failed, before the exit with code 1 |
| `QUERY_MEMORY_USAGE failed` | A query of the fixture's charge failed, before the exit with code 1 |
| `QUERY_POOL_STATUS failed` | A pool query failed, before the exit with code 1 |
| `undo window moved, retrying: attempt=<i> charge=<a>-><b> free_bytes=<a>-><b> memmgr_slots=<a>-><b>` | The fixture's charge, the pool's `free_bytes` or memmgr's used `CSpace` slots differ across one window |
| `failed-reply undo verified` | A window's readings match |
| `ipc_recv failing (err=<e>); backing off` | `RecvGuard` reports the first failure of a streak |
| `ipc_recv wedged (err=<e>); exiting` | `RecvGuard` reports the fatal failure, before the exit |

The `ipc_recv failing` line also shows that logging still works from a fully exhausted
`CSpace`: log messages and their replies carry no caps.

`svctest`'s `recv_wedge` phase asserts only the exit code. The `OutOfMemory`, reserve, and
undo checks above are the fixture's own panics, which exit with a fault code instead of
`EXIT_RECV_WEDGE` and so fail the phase.

---

### Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../../docs/testing.md) | Where test fixtures install and how `svctest` and `crasher` are staged |
| [docs/ipc-design.md](../../../docs/ipc-design.md) | Reply-side transfer failure and the receive-failure policy (`RecvGuard`, `EXIT_RECV_WEDGE`) |
| [docs/capability-model.md](../../../docs/capability-model.md) | `CSpace` slot-page pool, its exhaustion, and the IPC receive reserve |
| [memmgr IPC Interface](../../memmgr/docs/ipc-interface.md) | `REQUEST_MEMORY_CAPS` and `QUERY_POOL_STATUS` |
| [shared/ipc/README.md](../../../shared/ipc/README.md) | The `recv_guard` module the fixture uses |

---

## deadline

Deadlines: a supervisor bounds a worker's computation by a deadline and cancels it with an
asynchronous upcall, and a call deadline bounds the calls of a thread that waits on a server that
never answers. Source: `src/deadline.rs`.

---

### Cancellation Under Test

The worker is a `std` thread that publishes its own Thread capability
(`std::os::seraph::thread::current_thread_cap`) and then spins in a computation that makes no
syscall and never ends. The supervisor, the main thread:

1. binds the worker's upcall class (`FAULT_CLASS_UPCALL`) to an endpoint it creates;
2. lets the worker compute past the deadline, then posts it an upcall with `UPCALL_ANY_INSTRUCTION`,
   which reaches a thread that makes no syscall at an interrupt's return ([fault-handling.md §
   Asynchronous Upcalls](../../../docs/fault-handling.md#asynchronous-upcalls));
3. receives the upcall (`FAULT_KIND_UPCALL`, its cookie, the interrupt delivery point), rewrites
   the worker's instruction and stack pointers to enter the cancellation routine, and replies to
   resume it;
4. waits for the routine to mark the computation cancelled, checks that the worker computes no
   further, and prints `PASS`.

The cancellation routine ends the worker thread with `SYS_THREAD_EXIT`.

---

### Call Deadline Under Test

The main thread then makes an endpoint nobody receives on, so a call on it waits until its
timeout ends it, and bounds calls on it with a call deadline (`std::os::seraph::with_call_deadline`,
[runtime/ruststd/README.md](../../../runtime/ruststd/README.md)):

1. a runtime call (`std::os::seraph::namespace_lookup_file`) under a deadline 100 ms ahead, inside
   which a later deadline is nested, fails `io::ErrorKind::TimedOut` after 50 ms or more and
   under 5 s: the earlier deadline holds, and the call waits for it and no longer;
2. no deadline is left once the scope returns (`std::os::seraph::call_time_left` is `None`);
3. a call of the fixture's own (`ipc::ipc_call_within` with the time left) ends `WouldBlock`
   within the same window;
4. a runtime call under a deadline already passed fails `TimedOut` without waiting, and so does
   `Child::kill` of a child the fixture spawned idle (`program-modes deadline idle`), which it then
   kills and waits for outside the deadline;
5. a spawn of the idle child given one bootstrap cap (`CommandExt::bootstrap_caps`, a copy of
   the endpoint), which it never asks for, under a deadline 2 s ahead fails `TimedOut` after 1 s
   or more and under 5 s, and the cap it did not deliver is deleted
   ([runtime/ruststd/README.md](../../../runtime/ruststd/README.md) § Bootstrap caps).

Before either part, the fixture checks that it holds no creator endpoint: svctest spawns it with no
bootstrap caps.

The fixture handles Seraph capabilities directly. It prints `PASS` and exits cleanly when every
step holds; a failed step panics it, a non-clean exit.

---

### Driven By

The `deadline` phase of svctest (`services/svctest/src/phases/deadline.rs`) spawns
`program-modes deadline` once, with stdout piped and no bootstrap caps, reads its stdout
to the end, and waits for it. It asserts:

- a stdout line, trimmed, is `PASS`; otherwise the phase logs the stdout and panics with
  `deadline: PASS marker missing`;
- the exit status is a success; otherwise it panics with `deadline: exited non-clean` and the exit
  code.

---

### Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../../docs/testing.md) | Where test fixtures install and how `svctest` stages them |
| [docs/fault-handling.md](../../../docs/fault-handling.md) | Asynchronous upcalls |
| [runtime/ruststd/README.md](../../../runtime/ruststd/README.md) | Call deadlines and bootstrap caps |
| [services/svctest/README.md](../../svctest/README.md) | The harness that runs the `deadline` phase |

---

## demandpaged

Exercises the demand-paging pager surface. The [`svctest`](../../svctest/README.md) pager phases
spawn `program-modes demandpaged`. It prints no marker lines and reports through its exit status,
which the spawning phase checks. Source: `src/demandpaged.rs`.

---

### Modes

Demand paging is the system-wide default: procmgr binds memmgr as the pager of each process it
creates unless the creator opts out with `CREATE_PINNED`
([fault-handling.md](../../../docs/fault-handling.md#demand-paging-and-the-default-system-pager)).
memmgr backs faults inside a region the process registered and kills the thread on any other fault
([memmgr IPC Interface](../../memmgr/docs/ipc-interface.md)). The mode is selected by the
arguments after the mode name: any argument equal to `oor` selects the out-of-region mode, any
equal to `ptdrain` the page-table drain mode, and any equal to `teardown` the teardown mode.

| Mode | Behaviour | Exit status |
|---|---|---|
| default | `register_demand_paged(4)` reserves four pages and registers them read-write with the pager; the program writes a per-(page, byte) pattern across all four, then reads it back | `0` on a full match; `2` if registration fails; `3` on a mismatch |
| `oor` | `reserve_pages(1)` reserves one page ([page reservations](../../../docs/userspace-memory-model.md#page-reservations)) that is never registered; the program writes to it | Expected to be killed; `0` if the write survives, so the harness's must-be-killed assertion fails; `2` if the reservation fails |
| `ptdrain` | `register_demand_paged(1024)` registers a region holding a whole 2 MiB block that nothing has mapped, so its first touch needs a fresh page table. The program then maps one page of a `REQUEST_MEMORY_CAPS` frame in each 2 MiB block of a second reservation, with no funding, until `mem_map` returns `OutOfMemory` and the address space's page-table pool (`CAP_INFO_ASPACE_PT_BUDGET`) is empty. It then writes a pattern to the block's first page and reads it back, so the pager must fund the pool itself ([memmgr Memory Pool § Client page-table funding](../../memmgr/docs/memory-pool.md#client-page-table-funding)) | `0` on a full match; `2` if a reservation or the registration fails; `3` on a mismatch; `4` if the frame request or a drain mapping fails for a reason other than an empty pool; `5` if the drain does not empty the pool; killed if the pager declines the fault |
| `teardown` | `register_demand_paged(4)` registers a region, and the program fills and reads it back as the default mode does, then tears it down with `unregister_demand_paged`, which unregisters it with the pager and releases the reservation. It then registers four pages again, which the lowest-address first-fit reservation places on the same VA, so the pager accepts the registration only if the teardown removed the first one, and fills, reads back and tears down the second region the same way | `0` when both rounds pass; `2` if a registration fails; `3` on a mismatch; `4` if a teardown gets no answer from the pager; `5` if the second region lands at another VA |

---

### Harness Phases

| Phase | Spawn | Expected outcome |
|---|---|---|
| `demand_paging` | Default mode | Clean exit; memmgr's all-RAM-accounted identity still holds |
| `demand_paging_segfault` | `oor` argument | Killed with an exit reason at or above `EXIT_FAULT_BASE` |
| `demand_paging_pinned` | Default mode, `pinned(true)` | Killed with an exit reason at or above `EXIT_FAULT_BASE`, since no pager is bound; the RAM identity still holds |
| `demand_paging_pt_drain` | `ptdrain` argument | Clean exit; the RAM identity still holds |
| `demand_paging_teardown` | `teardown` argument | Clean exit; the RAM identity still holds |

---

### Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../../docs/testing.md) | Harness model and the sysroot layout of test fixtures |
| [docs/fault-handling.md](../../../docs/fault-handling.md) | Default system pager and the pinned opt-out |
| [docs/userspace-memory-model.md](../../../docs/userspace-memory-model.md) | Page-reservation surface |
| [memmgr IPC Interface](../../memmgr/docs/ipc-interface.md) | `REGISTER_REGION` and the fault arm |

---

## narrow

Checks the creator policy of the program signing role: a program may start programs only
([docs/signing.md](../../../docs/signing.md) § Signature Policy in procmgr), so its start of a
service image must be refused. Source: `src/narrow.rs`.

---

### Behaviour

The mode takes no further argument.

| Output | Exit |
|---|---|
| `refused: <error>` when starting `/tests/fixtures/service-modes` fails `PermissionDenied` | `0` |
| `starting /tests/fixtures/service-modes: <error>, not PermissionDenied` when the start fails another way | `3` |
| `started the service /tests/fixtures/service-modes` when the start succeeds; the mode kills the started process first | `4` |

`/tests/fixtures/service-modes` is a service-role image
([docs/signing.md](../../../docs/signing.md) § Signature Policy in procmgr).

---

### Driven By

The `procmgr_program_narrowing` phase of svctest (`services/svctest/src/phases/procmgr.rs`) runs
`program-modes narrow`; the exit `0` is the check that starting a service image is refused.

---

### Relevant Design Documents

| Document | Content |
|---|---|
| [docs/signing.md](../../../docs/signing.md) | Signing roles and the creator policy `narrow` checks |
| [services/svctest/README.md](../../svctest/README.md) | The harness that runs the phase |
| [services/procmgr/README.md](../../procmgr/README.md) | The process creation the phase drives |

---

## pipefault

The pipe death-bridge regression test's fixture. It writes a known prefix to a piped stdout, then
faults on purpose before its stdio pipes are closed, so the parent can see EOF only through the
spawner-side death bridge. `svctest`'s `pipe_fault_eof` phase spawns `program-modes pipefault`.
Source: `src/pipefault.rs`.

---

### Behavior

1. Writes `prefix\n` to stdout and flushes it.
2. Writes through a NULL pointer. The fault kills the process inside `main`, so the
   [ruststd](../../../runtime/ruststd/README.md) `_start` never reaches `close_all`, and the
   child's side of the pipe never sets the ring's `closed` flag.

The program prints nothing else and returns no exit code of its own; its exit reason is the
kernel's fault reason (the `EXIT_FAULT_BASE` range in
[docs/process-lifecycle.md § Exit reason](../../../docs/process-lifecycle.md#exit-reason)).

The `pipe_fault_eof` phase in
[`services/svctest/src/phases/pipes.rs`](../../svctest/src/phases/pipes.rs) spawns
it with `Stdio::piped()` stdout and checks four things: `read_to_end` returns data that starts
with `prefix\n` and then reaches EOF without hanging; the `ExitStatus` code lies in the fault
range; procmgr's `QUERY_PROCESS` reports the process `EXITED`; and procmgr's exit reason matches
the one the spawner saw.

---

### Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../../docs/testing.md) | How harnesses and the fixtures they spawn are staged |
| [docs/process-lifecycle.md](../../../docs/process-lifecycle.md) | Process death and the exit-reason ranges |
| [runtime/ruststd/README.md](../../../runtime/ruststd/README.md) | The std backend that supplies `_start`, stdio pipes, and `Command::spawn` |

---

## pipestress

Pipe fixture in two forms. By default it is the spawn-exit-drain stress fixture for the pipe
EOF-drain regression test: it writes one stdout line and exits at once, so the gap between the write
and process death is as short as the runtime allows, the window in which a parent draining the pipe
races the pipe's peer-death signal. Its `sink` argument makes it the reader of the doorbell trial.
It is plain std Rust and uses no Seraph capabilities. Source: `src/pipestress.rs`.

---

### Fixture Output

The fixture prints exactly one line, built from its argument after the mode name (empty when
absent), and exits `0`:

```
pipestress: <token> ok
```

Given `sink` as that argument, it prints `pipestress: sink ready`, reads its stdin to EOF,
then prints the bytes it read and the pipe notification sends and waits its thread made meanwhile
(`std::os::seraph::pipe`, [runtime/ruststd/README.md](../../../runtime/ruststd/README.md) § Pipes),
and exits `0`:

```
pipestress: sink <bytes> bytes <sends> sends <waits> waits
```

---

### Driven By

The `pipestress` phase of svctest (`services/svctest/src/phases/pipestress.rs`) spawns a fresh
child, `/tests/svctest pipestress-spawner`, with a piped stdout, so the slot bound measures that
process's own growth. It logs each line the child prints with a `pipestress-spawner:` prefix, waits
for it, and asserts that it exited successfully; otherwise it panics with `pipestress: spawner
exited non-zero`, the exit code, and the captured stdout. The child prints `pipestress: FAIL
<reason>` and the captured output of the failing trial, then exits `1`, on the first failed check
below, which it makes in this order:

- Spawn-drain loop: `ITERATIONS` (250) trials, each spawning
  `program-modes pipestress` with the iteration index as its argument and a piped stdout,
  reading stdout to EOF, and waiting for the child. A trial fails when the child exits non-zero or
  when the captured output lacks the line `pipestress: <index> ok`; a missing line means the reader
  saw EOF with bytes still in the pipe.
- CSpace-slot growth bound: each trial creates and destroys several kernel objects in the
  spawner's own process (the regression guard for ruststd's pooled object-slab recycling, see
  [docs/userspace-memory-model.md](../../../docs/userspace-memory-model.md)). The spawner reads the
  populated slot count with `cap_info(self_cspace, CAP_INFO_CSPACE_USED)`, takes a baseline after
  `WARMUP` (10) trials, and samples a peak every 50 trials and once after the last. Growth from
  baseline to peak above `SLOT_SLACK` (8) fails the run.
- Doorbell trial: it spawns the fixture's `sink` argument with piped stdin and stdout, waits for its
  `pipestress: sink ready` line, makes `DOORBELL_WRITES` (10000) writes of `DOORBELL_WRITE_BYTES`
  (16) bytes into its stdin, reads its own counters, closes the stdin, and reads the sink's report.
  The trial fails when the sink does not report ready, exits non-zero, or has no well-formed
  report, when it read other than every byte written, or when either end sent more notifications
  than the other announced waits, since a pipe end rings its peer only for a wait the peer
  announced ([shared/shmem/README.md](../../../shared/shmem/README.md) § Doorbell protocol). It
  logs the time from the first write to the sink's report, the throughput, and both ends' sends and
  waits.

After the child exits successfully the phase logs `pipestress phase passed`.

---

### Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../../docs/testing.md) | Sysroot layout and harness gating |
| [docs/userspace-memory-model.md](../../../docs/userspace-memory-model.md) | memmgr grants and ruststd's pooled object-slab recycling |
| [services/svctest/README.md](../../svctest/README.md) | The service that runs the phase |

---

## relrofault

The `PT_GNU_RELRO` enforcement test's fixture: it writes into its own `.data.rel.ro` and is
expected to fault. [`svctest`](../../svctest/README.md)'s `relro_write` phase spawns
`program-modes relrofault`. Source: `src/relrofault.rs`.

---

### Behavior

`MESSAGE` is an immutable `&'static str` static. Its initializer carries a relocated pointer,
so the linker places it in `.data.rel.ro`, inside the image's `PT_GNU_RELRO` region, which the
loader maps read-only once relocations are applied (see
[docs/userspace-memory-model.md](../../../docs/userspace-memory-model.md#image-placement)).
`main` keeps the static live with `std::hint::black_box`, logs
`relrofault: writing to <address>`, and performs a volatile 64-bit write of `0xDEAD` to the
static's address.

The write is expected to fault, so nothing after it runs. If it does not fault, the fixture
logs `relrofault: WRITE SUCCEEDED (RELRO not enforced)` and returns from `main`, exiting
cleanly.

The `relro_write` phase in
[`services/svctest/src/phases/process_faults.rs`](../../svctest/src/phases/process_faults.rs)
waits for the child and fails on a clean exit. It also fails unless the exit reason falls in
the fault range `EXIT_FAULT_BASE..EXIT_KILLED` (`0x1000..0x2000`), as defined in
[docs/process-lifecycle.md](../../../docs/process-lifecycle.md#exit-reason).

---

### Relevant Design Documents

| Document | Content |
|---|---|
| [docs/userspace-memory-model.md](../../../docs/userspace-memory-model.md) | Image placement, relocation, and RELRO sealing |
| [docs/process-lifecycle.md](../../../docs/process-lifecycle.md) | Exit-reason ranges the harness checks |
| [docs/fault-handling.md](../../../docs/fault-handling.md) | How a userspace fault is handled or ends the thread |
| [docs/testing.md](../../../docs/testing.md) | How harnesses and fixtures are staged |

---

## stackoverflow

Test of the main-thread stack guard. [`svctest`](../../svctest/README.md)'s `stack_overflow`
phase (`services/svctest/src/phases/process_faults.rs`) spawns `program-modes stackoverflow` and
waits for it to die. The mode is pure `std` with no Seraph cap awareness and prints nothing.
Source: `src/stackoverflow.rs`.

`overflow` (called from `main`) recurses without bound, and each of its frames holds a
page-sized local buffer, so the stack pointer descends at least one page per call. The stack
descends through its committed pages and then through the demand-growth range below them, which
memmgr backs on first touch; once that range is exhausted, the next write lands in the
unregistered guard below it, per
[docs/userspace-memory-model.md § Bootstrap Cross-Boundary VAs](../../../docs/userspace-memory-model.md#bootstrap-cross-boundary-vas).
procmgr binds memmgr as the process's pager, per
[docs/fault-handling.md § Default System Pager](../../../docs/fault-handling.md#default-system-pager),
so the fault is delivered to memmgr. The guard lies outside every registered region, so
memmgr declines it with `FAULT_REPLY_FORWARD`, per
[memmgr IPC Interface § Kernel-origin fault message](../../memmgr/docs/ipc-interface.md#kernel-origin-fault-message-fault_label);
the crash service reports it and declines it in turn, or, with none staged, procmgr declines it,
and the kernel kills the thread as an unhandled fault with a fault exit reason
(`EXIT_FAULT_BASE + <fault code>`), per
[docs/fault-handling.md § Delivery, Resume, and Kill](../../../docs/fault-handling.md#delivery-resume-and-kill),
[docs/fault-handling.md § Reply](../../../docs/fault-handling.md#reply), and
[docs/process-lifecycle.md § Exit reason](../../../docs/process-lifecycle.md#exit-reason).

---

### What the Harness Checks

The `stack_overflow` phase passes when all of the following hold:

- The child does not exit cleanly.
- Its exit code lies in `EXIT_FAULT_BASE..EXIT_KILLED`, the fault range.
- procmgr's `QUERY_PROCESS` on the child reports `EXITED`, with the same exit reason the
  spawner saw.



---

### Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../../docs/testing.md) | Harness model and where test fixtures install |
| [docs/userspace-memory-model.md](../../../docs/userspace-memory-model.md) | Main-thread stack placement, its demand-growth range, and the guard below it |
| [docs/fault-handling.md](../../../docs/fault-handling.md) | Pager fault delivery, `FAULT_REPLY_FORWARD` and `FAULT_REPLY_KILL`, and the fault exit reason |
| [services/memmgr/docs/ipc-interface.md](../../memmgr/docs/ipc-interface.md) | memmgr's fault reply: `FAULT_REPLY_FORWARD` for an address outside every registered region |
| [docs/process-lifecycle.md](../../../docs/process-lifecycle.md) | Exit-reason ranges and process death |

---

## threadchurn

Thread-churn reclaim test for the CSpace-slot leak regression (#240) and the memmgr-pool footprint
regression (#274). It spawns and joins, then spawns and detaches, batches of `std` threads, and
asserts that neither its populated CSpace-slot count nor memmgr's free pool drifts across the churn.
The threading is plain `std`, and only the sampling reaches Seraph surfaces. Source:
`src/threadchurn.rs`.

---

### Fixture Run

The fixture samples two quantities: its populated slot count, read with
`cap_info(self_cspace, CAP_INFO_CSPACE_USED)`, and memmgr's free-pool size, read with
`std::os::seraph::memmgr_pool_free_bytes()`, which wraps memmgr's
[`QUERY_POOL_STATUS`](../../memmgr/docs/ipc-interface.md#label-6-query_pool_status)
free-bytes word and returns `None` when memmgr is unreachable. It runs in three phases:

1. **Warm-up.** Eight spawn-and-join iterations bring the reaper's first death queue, the
   pooled object slabs, and the page-table budget to steady state. A held burst follows:
   `HELD_BURST` (128) detached threads each wait on one barrier until all are spawned, so all
   are bound at once, past the reaper's first 71-node death queue and past 64 slots. The
   fixture does not fund its `CSpace` first: the burst's caps outgrow the `CSpace` procmgr
   seeds, so a spawn is refused unless thread spawn tops the `CSpace` up itself
   ([runtime/ruststd/README.md](../../../runtime/ruststd/README.md) § CSpace slot headroom).
   Once released, a 100 ms sleep and 16 spawn-and-join iterations reap them, and the slot
   count must be within `BURST_SLACK` (8) of its value before the burst. Then the baseline
   slot count and free pool are sampled.
2. **Join churn.** `JOIN_CHURN` (600) spawn-and-join iterations, logging a progress line every
   25, then a slot sample.
3. **Detach churn.** `DETACH_BATCH` (128) threads are spawned and their handles dropped at once,
   a 100 ms sleep lets them die, and `REAP_CHURN` (50) spawn-and-join iterations drive the
   reaper sweeps that reclaim them. A 50 ms sleep and 16 more iterations drain stragglers, then
   the slot count and free pool are sampled again.

Flat results depend on ruststd returning each reclaimed thread's slab to memmgr mid-life and
recycling pooled object-slab bytes in place, per the
[memory allocation contract](../../../docs/userspace-memory-model.md#memory-allocation-contract).

The fixture then checks three bounds:

| Bound | Constant | Fails when |
|---|---|---|
| Held-burst growth | `BURST_SLACK` (8) | The slot count after the held burst is reaped exceeds its value before the burst by more than 8 (the second death queue and its slab, and the heap's growth for the slot table) |
| Slot growth | `SLACK` (4) | The larger of the two post-churn slot samples exceeds the baseline by more than 4 |
| Pool drop | `POOL_SLACK_BYTES` (1 MiB) | The final free pool is more than 1 MiB below the baseline; skipped when either sample is `None` |

A per-spawn slot leak grows the slot count by a few slots per spawn, and a per-spawn slab leak
drops the free pool by several pages per spawn, so either trips its bound. `JOIN_CHURN` also
runs past the roughly 250 spawns at which an unbounded memmgr tracking-anchor footprint
live-locks memmgr (#274), so that regression shows as a hang; the progress lines keep a hang
distinguishable from slow progress.

---

### Fixture Output

The fixture prints exactly one stdout line on a completed run and exits `0` on pass, `1` on a
failed bound or a refused burst:

| Line | When |
|---|---|
| `threadchurn: PASS slot growth <g> within slack 4` | Every bound held |
| `threadchurn: FAIL held-burst spawn <n> refused` | The held burst's `n`th spawn failed; no bound is checked |
| `threadchurn: FAIL held-burst slot growth <g> exceeds 8` | The held-burst bound failed; the later bounds are not checked |
| `threadchurn: FAIL slot growth <g> exceeds slack 4` | The held-burst bound held and the slot bound failed; the pool bound is not checked |
| `threadchurn: FAIL pool free dropped <d> exceeds slack 1048576` | The slot bound held and the pool bound failed |

It also logs through `log!` under the `[threadchurn]` name: the held burst's slot counts, the
baseline, a `join-churn progress <n>/600` line every 25 iterations, the post-churn samples, the
measured pool drop when the pool bound is checked, and a `PASS` or `FAIL` line (a refused
held-burst spawn logs its count, the slot count and the headroom). A failed `cap_info` call or a
panicked worker panics the fixture, so it exits non-zero with no stdout marker.

---

### Driven By

The `threadchurn` phase of svctest (`services/svctest/src/phases/threadchurn.rs`) runs
`program-modes threadchurn` twice: demand-paged, the system default, and then pinned
(`std::os::seraph::process::CommandExt::pinned`), with no pager. In the pinned run each thread's
stack is mapped at spawn from a memmgr grant
([runtime/ruststd/README.md](../../../runtime/ruststd/README.md) § Spawned-thread stacks), so a
stack that a join or the reaper does not return trips the pool bound. For each run it spawns the
fixture with a piped stdout, reads stdout to EOF, and waits for the child. It asserts, in this
order, and a run's panic message names it with ` (pinned)` for the pinned run:

- no stdout line contains `threadchurn: FAIL`; otherwise it panics with `threadchurn: fixture
  reported FAIL`;
- some stdout line contains `threadchurn: PASS`; otherwise it panics with `threadchurn: fixture PASS
  marker missing`;
- the child's exit status is a success; otherwise it panics with `threadchurn: fixture exited
  non-zero` and the exit code.

A failed spawn, read, or wait panics the phase as well. After both runs it logs `threadchurn phase
passed`.

---

### Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../../docs/testing.md) | Sysroot layout and harness gating |
| [docs/userspace-memory-model.md](../../../docs/userspace-memory-model.md) | memmgr grants, mid-life release, and ruststd's pooled object-slab recycling |
| [memmgr IPC Interface](../../memmgr/docs/ipc-interface.md) | `QUERY_POOL_STATUS` and `RELEASE_MEMORY_CAPS` wire shapes |
| [Syscall Interface Specification](../../../core/kernel/docs/syscalls.md) | `SYS_CAP_INFO` field reads |
| [services/svctest/README.md](../../svctest/README.md) | The service that runs the phase |

---

## threadstack

Test of the guarded stack that a spawned thread gets, demand-paged or, in a process with no pager,
mapped at spawn, and of the demand growth of the main thread's stack. Source:
`src/threadstack.rs`.

---

### Stack Under Test

Every process procmgr creates is demand-paged by default
([Fault Handling § Default System Pager](../../../docs/fault-handling.md#default-system-pager)),
so the fixture needs no opt-in: each thread it spawns gets the stack that
[ruststd § Spawned-thread stacks](../../../runtime/ruststd/README.md#spawned-thread-stacks)
specifies, a demand-paged region above an unregistered guard of four pages
(`process_abi::STACK_GUARD_PAGES`) that `join` frees through
memmgr's
[`UNREGISTER_REGION`](../../memmgr/docs/ipc-interface.md#label-9-unregister_region).
Its main thread's stack is the 8 pages the loader commits (the fixture declares no stack note)
above a demand-growth range that reaches 512 pages, with an unregistered guard of at least four
pages below it, as
[docs/userspace-memory-model.md § Bootstrap Cross-Boundary VAs](../../../docs/userspace-memory-model.md#bootstrap-cross-boundary-vas)
specifies.

The `threadstack` phase also spawns the fixture pinned
(`std::os::seraph::process::CommandExt::pinned`), with no pager. Each thread it spawns then gets the
eager stack that the same section specifies: the pages the spawn asks for, mapped at spawn, above an
unmapped guard of the same four pages, all of which `join` returns. The `guard`, `bigframe`,
`eager-grow`, and `eager-bigframe` workers ask for 16 pages (`EAGER_STACK_PAGES`, std's default
minimum); a demand-paged process raises that to its 512-page demand stack, and a pinned one maps
exactly those 16 pages.

In `grow`, `nested-grow`, `eager-grow`, and `guard`, the worker thread recurses through `recurse`,
and each level fills and sums a 4096-byte stack buffer, so the stack grows by about one page per
level. The recursive call goes through a `black_box`'d function pointer so the optimiser cannot
fold the recursion into a loop. `main-grow` and `main-guard` run the same recursion on the main
thread. `bigframe` and `eager-bigframe` use one oversized frame instead, and `splitframe` and
`span` a descent to the bottom of the stack, as § Modes describes.

---

### Modes

The mode is the first of `main-guard`, `main-grow`, `guard`, `eager-bigframe`, `eager-grow`,
`bigframe`, `splitframe`, `span`, and `nested-grow` that an argument after the mode name equals;
otherwise it is `grow`. A worker spawn that std refuses fails every mode's verdict: the workers of
`guard`, `bigframe`, `eager-grow`, and `eager-bigframe` print `spawn failed: <error>` and exit with
code 4, and any other refused spawn panics, which aborts the process before it prints `PASS` or
`about to overflow`.

| Mode | Behavior | Stdout and exit |
|---|---|---|
| `grow` | A worker recurses `GROW_DEPTH` (200) levels, inside the default 2 MiB usable stack, and is joined | `grow checksum <n>`, then `PASS`; exits `ExitCode::SUCCESS`. A panicked worker prints `grow worker panicked` and exits with code 3 |
| `nested-grow` | A worker spawns a second worker, which recurses `GROW_DEPTH` (200) levels and is joined by the first, which is joined in turn. The second worker's spawn copies the first worker's bindings ([Fault Handling § Inheritance is userspace policy](../../../docs/fault-handling.md#inheritance-is-userspace-policy)), so the mode runs the copy from a spawned thread; both workers and the main thread carry the same pager binding, so a pass shows the second worker's demand stack is served, not which thread's binding was copied | `nested-grow checksum <n>`, then `PASS`; exits `ExitCode::SUCCESS`. A panicked worker prints `nested-grow worker panicked` and exits with code 3 |
| `guard` | The main thread prints and flushes `about to overflow`, then a worker recurses without bound into the guard | No clean exit: the guard fault is terminal and procmgr tears down the whole process. If `join` returns, prints `SURVIVED (BUG)` and exits `ExitCode::SUCCESS` so the phase fails |
| `main-grow` | The main thread recurses `GROW_DEPTH` (200) levels, 25 times its 8 committed pages and inside its 512-page stack | `main-grow checksum <n>`, then `PASS`; exits `ExitCode::SUCCESS` |
| `main-guard` | The main thread prints and flushes `about to overflow`, then recurses without bound through its demand-growth range into the guard below it | No clean exit: the guard fault is terminal and procmgr tears down the whole process. If the recursion returns, prints `SURVIVED (BUG)` and exits `ExitCode::SUCCESS` so the phase fails |
| `bigframe` | The main thread prints and flushes `about to overflow`, spawns a worker that signals it is running and then blocks on a channel, and waits for that signal, so the top of the worker's stack and the page table covering it are mapped. A second worker, whose stack the reservation arena places directly above the first worker's one-page IPC buffer, itself directly above the first worker's stack, calls a function with one frame of 519 pages (the 512-page default usable stack, its 4-page guard, and 3 pages) and writes only the frame's lowest byte, which lies past the guard and that IPC buffer, near the top of the first worker's registered stack. Only the stack probes that [ruststd § Spawned-thread stacks](../../../runtime/ruststd/README.md#spawned-thread-stacks) describes reach the guard | No clean exit: the probe faults on the guard and procmgr tears down the whole process. If `join` returns, prints `SURVIVED (BUG)` and exits `ExitCode::SUCCESS` so the phase fails |
| `splitframe` | The same two workers as `bigframe`. The second takes its usable base as the page boundary above its first frame less 512 pages, and descends its stack in written frames, of a page and then of 256 bytes, until its frame lies within 1024 bytes of that base. A dry run makes the descent, writes 64 bytes below it, and returns, which shows that the descent and the overflow's first write lie in the usable stack. The worker then prints and flushes `about to overflow` and descends again to call `split_frame`, a 6128-byte frame that saves its return address and calls `page_leaf`, a leaf with 4080 bytes of locals that writes only its lowest byte. On riscv64 the frame is allocated as 2032 bytes and then 4096 unprobed, so the leaf's byte lies about 10 KiB below the save with nothing written between them ([docs/build-system.md § Custom Targets](../../../docs/build-system.md#custom-targets)): past a guard of two pages or fewer, on a mapped page of the first worker: its IPC buffer, or its stack below | As `bigframe`. A dry run that faults, which a misjudged base causes, prints no `about to overflow`, and the phase fails |
| `span` | As `splitframe`, but the overflow is two stores 14312 bytes apart with nothing written between them, the std target's bound on the distance between two consecutive stack stores, which `process_abi::STACK_GUARD_PAGES` covers: past a guard of three pages or fewer, on a mapped page of the first worker: its IPC buffer, or its stack below | As `splitframe` |
| `eager-grow` | For a pinned run. A worker recurses `EAGER_GROW_DEPTH` (10) levels, about 41 KiB, inside its 16-page eager stack, and is joined | `eager-grow checksum <n>`, then `PASS`; exits `ExitCode::SUCCESS`. A panicked worker prints `eager-grow worker panicked` and exits with code 3 |
| `eager-bigframe` | For a pinned run. As `bigframe`, but the frame is 23 pages (the 16-page eager stack, its 4-page guard, and 3 pages), so its lowest byte lies past the guard and the parked worker's IPC buffer, near the top of the parked worker's mapped eager stack. Waiting for the parked worker changes nothing here, since an eager stack is mapped whole at spawn. A stack with no unmapped guard below it, over mapped memory, lets the frame return | As `bigframe` |

A terminal fault on a worker thread brings down the whole process because procmgr observes the
address space's death, as
[Capability Model § "Kill process" pattern](../../../docs/capability-model.md#kill-process-pattern)
describes.

---

### Driven By

The `threadstack` phase of svctest (`services/svctest/src/phases/threadstack.rs`) runs
`program-modes threadstack` demand-paged in the modes `grow`, `guard`, `bigframe`,
`splitframe`, `span`, `nested-grow`, `main-grow`, and `main-guard`, then pinned
(`CommandExt::pinned`, no pager) in `eager-grow`, `guard`, and `eager-bigframe`, in that order. For
each run it passes the mode as the second argument, pipes stdout, reads it to the end, and waits
for the exit status. A pinned run's panic message names its mode with ` (pinned)`. Each run asserts:

- `grow`, `nested-grow`, `main-grow`, and `eager-grow`: no stdout line is `SURVIVED (BUG)`
  (otherwise it panics with `unexpectedly reported SURVIVED`); some line is `PASS` (otherwise
  `PASS marker missing`); the exit is a success (otherwise `exited non-clean`).
- `guard`, `bigframe`, `splitframe`, `span`, `main-guard`, and `eager-bigframe`: no stdout line is
  `SURVIVED (BUG)` (otherwise `guard did not fault`); some line contains `about to overflow`
  (otherwise `fixture never reached the overflow point`); the exit is not a success (otherwise
  `overflow exited cleanly`); the exit code is at least `EXIT_FAULT_BASE` (`0x1000`), the base of
  the Fault range in
  [Process Lifecycle § Exit reason](../../../docs/process-lifecycle.md#exit-reason) (otherwise
  `death reason is not a fault class`), so a Fault or Killed reason passes.

After the eleven runs it logs `threadstack phase passed`.

---

### Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../../docs/testing.md) | Sysroot layout and harness gating |
| [docs/build-system.md](../../../docs/build-system.md) | The std targets' inline stack probes, and the span between two stack stores they leave on riscv64 |
| [docs/fault-handling.md](../../../docs/fault-handling.md) | Demand paging as the system default; memmgr as the pager; the fatal fault of a process with no pager |
| [docs/userspace-memory-model.md](../../../docs/userspace-memory-model.md) | The main-thread stack's committed pages, demand-growth range, and guard |
| [docs/capability-model.md](../../../docs/capability-model.md) | Address-space death observers and process teardown on a terminal fault |
| [docs/process-lifecycle.md](../../../docs/process-lifecycle.md) | Exit-reason ranges, including `EXIT_FAULT_BASE` |
| [runtime/ruststd/README.md](../../../runtime/ruststd/README.md) | Spawned-thread stack geometry, demand and eager, and release at `join`; the main-thread growth range `_start` registers |
| [memmgr IPC Interface](../../memmgr/docs/ipc-interface.md) | `UNREGISTER_REGION`, which frees a joined thread's guarded stack |

---

## Summarized By

None
