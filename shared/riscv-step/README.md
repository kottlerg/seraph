# shared/riscv-step

The successor-address decoder a debugger single-steps a riscv64 thread with.

---

## Source Layout

```
riscv-step/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs              # successor, instruction_len, C_EBREAK, StepError
```

`no_std`, no allocation, no dependencies. Pure logic, host-tested by `cargo xtask test`.

---

## Surface

| Item | Purpose |
|---|---|
| `successor(pc, insn, reg)` | The address the thread runs next after the instruction `insn` at `pc`, reading `xN` through `reg(N)`: the fall-through, a conditional branch's taken or not-taken target, or a jump's target. |
| `instruction_len(parcel)` | 2 or 4: how many bytes of the instruction to read from its first 16-bit parcel. |
| `C_EBREAK` | The 2-byte `c.ebreak` a debugger plants at the successor. |
| `StepError` | Why no successor is given: an illegal or over-long encoding, a breakpoint (which traps at itself), or a jump to itself (which a planted breakpoint would trap before it runs). |

## Scope

RISC-V has no user-mode single-step without a debug trigger, and the kernel programs none. A
debugger steps a stopped thread by reading its registers and the instruction at its pointer,
planting `C_EBREAK` at the successor with `SYS_THREAD_WRITE_MEM` and `THREAD_MEM_TEXT`, resuming
the thread, taking the breakpoint, and writing the saved bytes back. This crate is the decode step
of that route; the route itself, and its hazards, are in
[docs/fault-handling.md](../../docs/fault-handling.md) § Debugging. The decoder covers RV64GC: every
32-bit and compressed instruction falls through by its length except `jal`, `jalr`, the six
conditional branches, `c.j`, `c.jr`, `c.jalr`, `c.beqz`, and `c.bnez`. `ecall` falls through, since
the syscall returns to the instruction after it.

Consumers: ktest's riscv64 `integration::single_step`
([core/ktest/README.md](../../core/ktest/README.md)) and the `debugger` fixture
([programs/debugger/README.md](../../programs/debugger/README.md)).

---

## Summarized By

None
