# deadline

Test fixture for the asynchronous upcall: a supervisor bounds a worker's computation by a
deadline and cancels it with an upcall.

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
│   └── main.rs            # Supervisor and spinning worker; the cancellation routine
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

The cancellation routine ends the worker thread with `SYS_THREAD_EXIT`. The tester passes when
the fixture prints `PASS` and exits cleanly; any failed step panics the fixture, a non-clean exit.

---

## Summarized By

None
