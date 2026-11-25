# seraph-path-account-plugin

The QEMU TCG plugin `cargo xtask path-account trace` loads into the guest's QEMU, and the format
of the record it writes. The plugin counts every instruction the guest executes between two
user-mode counter reads, and records each read's value; xtask reads the record back through this
crate's `record` module and accounts the benchmarks' windows
([xtask/README.md](../README.md#cargo-xtask-path-account)).

---

## Scope

A host-only crate, built only by `cargo xtask`: a `cdylib`, the plugin, which `trace` builds
for the host in the release profile and passes to QEMU as `-plugin`, and an `rlib`, which
xtask links for the record's format and the instruction classes; `cargo xtask test` tests and
lints it with xtask's other sub-crates. Neither is part of an image. It links nothing
of QEMU's: QEMU exports its plugin API from its own binary, so the plugin resolves each function
it calls, and `GLib`'s, in the process that loads it, and refuses to install when one is missing.

## Source Layout

```
path-account-plugin/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs        The crate's modules
    ├── class.rs      The instruction classes: counter reads, traps, lazy units' and rep strings
    ├── record.rs     The record's events, written and parsed
    ├── recorder.rs   The recorder: slots, segments, histograms, attempts (host-tested)
    └── qemu.rs       The plugin API's side: install, and the callbacks that drive the recorder
```

## Behavior

The plugin installs into a system emulation of one vCPU, with one argument, `out=<file>`, the
record's path, and needs QEMU's plugin API at version 7 or later.

**Segments.** A segment is the instructions executed from one user-mode counter read, itself
included, to the next, excluded, in every privilege mode and address space. A counter read is
`rdtsc` on x86_64 and `csrr rd, cycle` on riscv64, the reads `shared/bench` makes; it is a
user-mode read when its address lies in the user half. Each translated instruction gets a slot,
shared by every translation of the same bytes at the same address, and three callbacks in this
order: the value callback (only while a read's value is due), the read callback (on a user-mode
counter read), and the execution callback, which counts the slot in the open segment. QEMU calls
an instruction's callbacks before it executes, so a read closes the segment before it is counted.

**Values.** A read's value is in its destination register when the next instruction begins: the
value callback, conditional on a scoreboard flag the read sets and registered with register
access, reads EDX:EAX or `x<rd>`.

**Attempts.** Under icount an instruction that an exception ends has been counted by its
execution callback but did not retire, and the counter did not count it. The plugin notes such an
attempt from QEMU's discontinuity callback: a discontinuity from the address of the instruction
executed last, when that instruction does not trap by design (`syscall`, `ecall`, `ebreak`),
is an attempt. An interrupt comes between two instructions, from the address of the next one,
except between two iterations of an x86 `rep` string instruction, which runs once per
iteration: the plugin watches its memory accesses, which QEMU reports once each completed, and
an iteration whose accesses all completed retired. (The discontinuity's kind does not tell them
apart: x86_64 reports a page fault as an interrupt.) An instruction of a unit that is off
(x86_64's FPU and vector state while `CR0.TS` or `CR0.EM` is set, which the kernel never sets;
riscv64's floating-point and vector units until a thread's first use of them) is the other
exception: while the unit is off, QEMU's translator raises the trap when it decodes the
instruction, and icount has counted it, so the counter counted it too. The plugin defers such
an attempt to the next instruction and reads the unit's state register there (`CR0.TS` and
`CR0.EM`, `sstatus.FS` and `sstatus.VS`): with the unit off the attempt is not one, with it
on (a fault of the instruction's memory access) it is. A counter read that runs more than once
before its value is read (its first execution interrupted) retired once; its other executions
are attempts, which the record writes after the read, in the segment the read opens and that ran
them. xtask subtracts the attempts from the window that holds them.

**Record.** One event per line, in the order the guest ran them:

```text
seraph-path-account 1 <arch>       the header: the format's version, the guest's architecture
H <id> <pc>:<count> ...            a segment's instructions, by address, the first time a
                                   segment held them
R <pc> <id> <value>                a user-mode counter read at <pc>, the segment before it
                                   (histogram <id>), its value
A <pc>                             an attempt at <pc> that a trap ended before it retired
```

A histogram is written once, keyed by a 128-bit FNV-1a hash of its entries, and a later segment
with the same entries names it, so a benchmark's repeated iterations cost one line each. The
record is flushed after each read, since xtask kills QEMU once the benchmark program has ended; a
last line without its newline is one QEMU was killed in the middle of writing, which the reader
leaves out.

---

## Summarized By

[xtask/README.md](../README.md)
