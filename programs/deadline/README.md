# deadline

Test fixture for deadlines: a supervisor bounds a worker's computation by a deadline and cancels
it with an asynchronous upcall, and a call deadline bounds the calls of a thread that waits on a
server that never answers.

---

## Role

The fixture's per-program tester, `deadline-tester`, runs it once, and the `usertest`
orchestrator discovers and runs that tester. The fixture installs at `/programs/deadline` and the
tester at `/tests/programs/deadline`, per
[docs/testing.md § Per-program tester protocol](../../docs/testing.md#per-program-tester-protocol).
The fixture handles Seraph capabilities directly; the tester uses idiomatic `std` only.

---

## Source Layout

```
deadline/
├── Cargo.toml
├── README.md
├── src/
│   └── main.rs            # Supervisor, spinning worker, cancellation routine; call deadline
└── tester/
    ├── Cargo.toml
    └── src/
        └── main.rs        # Spawns the fixture and checks stdout and exit status
```

---

## Cancellation Under Test

The worker is a `std` thread that publishes its own Thread capability
(`std::os::seraph::thread::current_thread_cap`) and then spins in a computation that makes no
syscall and never ends. The supervisor, the main thread:

1. binds the worker's upcall class (`FAULT_CLASS_UPCALL`) to an endpoint it creates;
2. lets the worker compute past the deadline, then posts it an upcall with `UPCALL_ANY_INSTRUCTION`,
   which reaches a thread that makes no syscall at an interrupt's return
   ([fault-handling.md § Asynchronous Upcalls](../../docs/fault-handling.md#asynchronous-upcalls));
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
[runtime/ruststd/README.md](../../runtime/ruststd/README.md)):

1. a runtime call (`std::os::seraph::namespace_lookup_file`) under a deadline 100 ms ahead, inside
   which a later deadline is nested, fails `io::ErrorKind::TimedOut` after 50 ms or more and
   under 5 s: the earlier deadline holds, and the call waits for it and no longer;
2. no deadline is left once the scope returns (`std::os::seraph::call_time_left` is `None`);
3. a call of the fixture's own (`ipc::ipc_call_within` with the time left) ends `WouldBlock`
   within the same window;
4. a runtime call under a deadline already passed fails `TimedOut` without waiting, and so does
   `Child::kill` of a child the fixture spawned idle (`deadline idle`), which it then kills and
   waits for outside the deadline.

The tester passes when the fixture prints `PASS` and exits cleanly; any failed step panics the
fixture, a non-clean exit.

---

## Summarized By

None
