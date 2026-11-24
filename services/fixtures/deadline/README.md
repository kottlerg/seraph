# deadline

Test fixture for deadlines: a supervisor bounds a worker's computation by a deadline and cancels
it with an asynchronous upcall, and a call deadline bounds the calls of a thread that waits on a
server that never answers.

---

## Source Layout

```
deadline/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Supervisor, spinning worker, cancellation routine; call deadline
```

---

## Cancellation Under Test

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

## Call Deadline Under Test

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
   `Child::kill` of a child the fixture spawned idle (`deadline idle`), which it then kills and
   waits for outside the deadline;
5. a spawn of the idle child given one bootstrap cap (`CommandExt::bootstrap_caps`, a copy of
   the endpoint), which it never asks for, under a deadline 2 s ahead fails `TimedOut` after 1 s
   or more and under 5 s, and the cap it did not deliver is deleted
   ([runtime/ruststd/README.md](../../../runtime/ruststd/README.md) § Bootstrap caps).

Before either part, the fixture checks that it holds no creator endpoint: svctest spawns it with no
bootstrap caps.

The fixture handles Seraph capabilities directly. It prints `PASS` and exits cleanly when every
step holds; a failed step panics it, a non-clean exit.

---

## Driven By

The `deadline` phase of svctest (`services/svctest/src/phases/deadline.rs`) spawns
`/tests/fixtures/programs/deadline` once, with stdout piped and no bootstrap caps, reads its stdout
to the end, and waits for it. It asserts:

- a stdout line, trimmed, is `PASS`; otherwise the phase logs the stdout and panics with
  `deadline: PASS marker missing`;
- the exit status is a success; otherwise it panics with `deadline: exited non-clean` and the exit
  code.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../../docs/testing.md) | Where test fixtures install and how `svctest` stages them |
| [docs/fault-handling.md](../../../docs/fault-handling.md) | Asynchronous upcalls |
| [runtime/ruststd/README.md](../../../runtime/ruststd/README.md) | Call deadlines and bootstrap caps |
| [services/svctest/README.md](../../svctest/README.md) | The harness that runs the `deadline` phase |

---

## Summarized By

None