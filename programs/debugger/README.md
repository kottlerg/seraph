# debugger

Test fixture for debugging through the fault and upcall handlers: a debugger thread takes a
debuggee thread's breakpoint, inspects and modifies its memory, single-steps it, and breaks into it
while it runs; then it debugs a debuggee process, reading and writing its memory
and planting a breakpoint in its text.

---

## Role

The fixture's per-program tester, `debugger-tester`, runs it once, and the `usertest`
orchestrator discovers and runs that tester. The fixture installs at `/programs/debugger` and the
tester at `/tests/programs/debugger`, per
[docs/testing.md § Per-program tester protocol](../../docs/testing.md#per-program-tester-protocol).
The fixture handles Seraph capabilities directly; the tester uses idiomatic `std` only.

---

## Source Layout

```
debugger/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs            # Debugger and debuggee threads, and the debuggee process
│   │                      #   (`--debuggee`)
│   └── arch/
│       ├── mod.rs         # Architecture-dispatch surface
│       ├── x86_64.rs      # `int3`; single-step by the trap flag
│       └── riscv64.rs     # `ebreak`; single-step by `c.ebreak` at the successor
└── tester/
    ├── Cargo.toml
    └── src/
        └── main.rs        # Spawns the fixture and checks stdout and exit status
```

---

## Debugging Under Test

The debuggee is a `std` thread that publishes its own Thread capability
(`std::os::seraph::thread::current_thread_cap`) and waits until the debugger, the main thread, has
bound its exception and upcall classes (`FAULT_CLASS_EXCEPTION | FAULT_CLASS_UPCALL`) to an
endpoint of the debugger's
([fault-handling.md § Debugging](../../docs/fault-handling.md#debugging)). The debugger then:

1. receives the debuggee's software breakpoint (`int3` on x86-64, a 4-byte `ebreak` on riscv64)
   as `FAULT_EXC_BREAKPOINT`; checks that the register file's instruction pointer is the one the
   message reports; reads and rewrites a word of the debuggee's memory while it is stopped; and
   resumes it past the breakpoint, setting the trap flag on x86-64, or, on riscv64, planting
   `c.ebreak` at the successor of the instruction it resumes at;
2. single-steps the three `nop`s after the breakpoint, one fault each reporting the next
   instruction: on x86-64 a `FAULT_EXC_DEBUG`, the trap flag cleared at the last; on riscv64 a
   `FAULT_EXC_BREAKPOINT` at the `c.ebreak` it planted, whose bytes it writes back before planting
   the next step's (the successor from `riscv_step`,
   [shared/riscv-step/README.md](../../shared/riscv-step/README.md); the plant through
   `SYS_THREAD_WRITE_MEM` with `THREAD_MEM_TEXT`);
3. waits for the debuggee to spin in a loop that makes no syscall, async-breaks it with an
   `UPCALL_ANY_INSTRUCTION` upcall, checks that it does not run while broken in, sets the flag
   that ends its loop, and resumes it;
4. checks that the breakpoint's reported pointer matches its address on the architecture (past
   `int3`, at `ebreak`) and that the debuggee read back the rewritten word;
5. spawns itself with `--debuggee` as a debuggee process, which prints the addresses of a data
   word, a go flag, and a function, and waits on the flag. Through the child's main-thread cap
   (`std::os::seraph::process::ChildExt::main_thread_cap`) the debugger binds the child's exception
   class, reads and rewrites the data word (`SYS_THREAD_READ_MEM`, `SYS_THREAD_WRITE_MEM`), writes
   a breakpoint over the function's first instruction (`THREAD_MEM_TEXT`), and sets the flag. The
   child calls the function and stops at the breakpoint; the debugger restores the instruction,
   moves the pointer back to it, and resumes the child, which prints the rewritten word and exits.
   The debugger then prints `PASS`.

The text writes, of step 5 and of the riscv64 steps of step 2, succeed only because procmgr's
loader gives each process its own text frames: the kernel refuses a text write to a frame mapped
more than once.

The tester passes when the fixture prints `PASS` and exits cleanly; a failed step panics the
fixture, a non-clean exit.

---

## Relevant Design Documents

| Document | Covers |
|---|---|
| [docs/fault-handling.md](../../docs/fault-handling.md) | § Debugging, § Asynchronous Upcalls, § Fault Message |
| [docs/capability-model.md](../../docs/capability-model.md) | § Thread: the Observe, Control, and Upcall rights |
| [shared/riscv-step/README.md](../../shared/riscv-step/README.md) | The successor decoder of the riscv64 step |
| [core/kernel/docs/syscalls.md](../../core/kernel/docs/syscalls.md) | `SYS_THREAD_READ_REGS`, `SYS_THREAD_WRITE_REGS`, `SYS_THREAD_POST_UPCALL`, `SYS_THREAD_READ_MEM`, `SYS_THREAD_WRITE_MEM` |
| [runtime/ruststd/README.md](../../runtime/ruststd/README.md) | § Child process handles: `ChildExt::main_thread_cap` |
| [docs/testing.md](../../docs/testing.md) | § Per-program tester protocol |

---

## Summarized By

None
