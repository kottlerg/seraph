# Kernel Hot-Path Instruction Account

Where the instructions of each kernel benchmark's measured path go, function by function, on
x86_64 and riscv64 in the dev and release profiles, and the ranked cuts drawn from it.

---

## What the Account Measures

Each row of ktest's bench-only image (`--ktest-bench-only`) measures one path from user mode
back to user mode: a counter read in ktest, the syscalls, traps and switches the benchmark
makes, and the closing counter read. Under QEMU's icount the counter advances by one per
instruction, so the benchmark's sample is that path's instruction count, and the benchmark
cell gates it ([docs/testing.md](../../../docs/testing.md) § Gating).

The account steps one CPU through eight consecutive iterations of each benchmark under QEMU's
gdbstub and attributes every instruction between the two counter reads to a function. An
iteration whose stepped count differs from the sample it recorded, or a benchmark whose p50
differs from the reference boot's, fails the run, so each table below sums to the count the
benchmark cell sees for that tree and profile. The method, its checks and its limits are in
[xtask/README.md](../../../xtask/README.md) § `cargo xtask path-account`.

An x86_64 `rep` string instruction counts once per iteration under icount, in the benchmark
and in the account alike. A `memset` or `memcpy` row on x86_64 is therefore the iterations
of one `rep stos` or `rep movs` (about one per 8 bytes): hardware retires it as a few
instructions but performs the same stores. riscv64 runs `compiler_builtins`' word loops,
whose rows are instructions on hardware too.

## Regenerating It

The generated block below is written by `cargo xtask path-account write` from the result files
of `cargo xtask path-account trace`, one per architecture and profile; the commands that
regenerate one configuration are in [xtask/README.md](../../../xtask/README.md)
§ `cargo xtask path-account`. The block's first table names, for each configuration, the head
of the tree it was taken at, the date, the QEMU version, and the reference it was checked
against. A change to a kernel path regenerates the four configurations, rewrites the block,
and revises the prose below where its numbers moved.

## Reading the Tables

- **Totals** gives each path's p50, split into the instructions run in ktest (user mode: the
  benchmark loop, the syscall stubs and the counter reads) and in the kernel.
- Each path's table lists its functions by their largest count in any configuration. A
  function is the innermost one the instruction's line tables name, inlined frames included,
  outside `core`, `alloc` and `compiler_builtins` and outside a primitive's methods, so a
  bounds check inlined from `core` counts in the kernel function that made it. Code no line
  table covers is named by its symbol: the assembly entry stubs (`syscall_entry`,
  `trap_entry`, `seraph_enter_from_user`, `__copy_user`), and `memcpy` and `memset`.
- The smallest rows of each path, below 3 instructions or below 1/200 of the path's largest
  row, fold into one closing row.
- An empty cell means the function ran no instruction in that configuration: inlined into its
  caller, or not on that architecture's path.

## Where the Instructions Go

The figures in this section are release, x86_64 / riscv64, unless marked dev.

### The Null Syscall

The null syscall (`SYS_SYSTEM_INFO` on a cheap query) is 275 / 374 instructions, 268 / 371 in
the kernel:

| Part | x86_64 | riscv64 | Functions |
|---|---:|---:|---|
| Entry and exit stubs | 70 | 145 | `syscall_entry`, `seraph_enter_from_user`; `trap_entry`, `trap_dispatch` |
| Finding this CPU's scheduler and thread | 60 | 95 | `scheduler_for`, `scheduler_ptr`, `current_cpu`, `PerCpuScheduler::current`, `current_tcb` |
| Dispatch and result | 68 | 42 | `dispatch`, `dispatch_in_range`, `index_mask`, `mask_index`, `syscall_nr`, `finish_syscall` |
| Return-to-user work checks | 36 | 56 | `running_thread_stopped`, `reclaim_deferred_stack`, `drain_deferred_reclaim`, `sole_reference::drain`, `deliver_at_syscall`, `upcall::take`, `upcall::deliver` |
| Diagnostic stamps | 13 | 12 | `cpu_diag`, `stamp_syscall_entry`, `note_cpu_syscall` |
| The handler | 19 | 20 | `sys_system_info`, `TrapFrame::arg` |

The current-thread lookup goes through the scheduler table on every access, several times per
syscall; reading it through one per-CPU pointer saved 32 / 53 per syscall (dev) in the
prototype for PR #1507. The sole-reference drain that #1528 found is the 3 instructions per
syscall left after PR #1530. Each return-work check reaches its own per-CPU or per-thread
state, so the checks cost 36 / 56 before any work is pending.

### Context Switch and IPC

On x86_64, every context switch rewrites the TSS I/O permission bitmap
(`gdt::load_iopb`): an 8 KiB fill for a thread without port bindings and an 8 KiB copy for a
thread with them, 2121 instructions of each row that switches twice (`ktest.ipc_round_trip`,
`ktest.notification_roundtrip`, `ktest.context_switch_pair`): 42 % of the IPC round trip and
65 % of the context-switch pair. riscv64 has no bitmap, which is most of why its context-switch
pair is 1411 against x86_64's 3278.

An IPC call and its reply each zero a whole 576-byte `Message` and move it by value between
the endpoint and the receiver whatever its `data_count`: 442 / 1605 instructions of the round
trip with no data words.

On riscv64 `__copy_user` copies one byte per seven instructions: about 28700 of the 32250 of
`ktest.thread_read_mem_page`, against 5411 on x86_64, and about 1590 of the IPC round trip
with seven words, the one whose payload passes the register words.

### Other Rows

- `ktest.aspace_harvest_*`: the leaf walker calls its visitor through `dyn FnMut` once per
  slot; on x86_64 the retpoline thunk alone is 640 of 4402 (all accessed) and 480 of 3410
  (none).
- `ktest.thread_lifecycle`: two kernel entropy draws (the TCB's random field, and the CSpace-id
  epoch redraw on free) run Keccak-f[1600] four times, 25256 of 61599 / 25060 of 84691; the
  kernel-stack paint at creation and the depth scan at teardown are 8204 / 15765 more, and the
  zeroing of new and freed memory 8218 / 21400.

## Profile

The benchmark cell is decided to gate the release profile (opt-level 2, LTO, one codegen unit),
for its ktest rows, ubench and fsbench alike, so one rule states what the cell measures: the
build that runs on hardware. Dev (opt-level 2 with debug assertions and overflow checks, without LTO) adds
9 % to 58 % to a path on x86_64, unevenly, so a dev count does not predict the release count
and a cut ranked on dev is mis-ranked:

| Path (x86_64) | Dev | Release | Dev / release |
|---|---:|---:|---:|
| `ktest.null_syscall_roundtrip` | 358 | 275 | 1.30 |
| `ktest.ipc_round_trip words=0` | 6583 | 5015 | 1.31 |
| `ktest.notification_roundtrip` | 6127 | 4944 | 1.24 |
| `ktest.cap_info_lookup` | 571 | 392 | 1.46 |
| `ktest.mem_map_unmap` | 2690 | 1896 | 1.42 |
| `ktest.aspace_harvest_all_accessed pages=32` | 4786 | 4402 | 1.09 |
| `ktest.thread_lifecycle` | 97213 | 61599 | 1.58 |
| `ktest.context_switch_pair` | 3800 | 3278 | 1.16 |
| `ktest.tlb_shootdown_unmap` | 1045 | 700 | 1.49 |

Dev's excess is debug assertions (`debug_assert_kernel_entry_flags`, `read_rflags`), overflow
checks, and calls that LTO inlines in release: the current-thread lookup alone is 96 (dev) and 38
(release) of the x86_64 null syscall. The accepted cost is that a regression only dev runs (a
debug assertion added to a hot path) is not gated; it costs nothing on hardware, and the
functional cells still build and boot dev. The cell builds dev until the change that moves it
to release, with its baselines and its host-mode bands re-taken on the release build.

## Ranked Cuts

Ranked on the release account by the instructions each removes from the gated rows. Each cut is
its own Issue, under #1531. A design change goes to the maintainer as a pick before it is built,
and its Issue is filed once approved; a local cut does not wait. Each reports the host-mode figure under KVM beside its counts, and a cut
that saves instructions but costs time is not taken.

| Rank | Cut | Kind | Expected saving (release, x86_64 / riscv64) |
|---:|---|---|---|
| 1 | #1539: skip the I/O bitmap reload when the TSS already holds it | local | about 2100 per row that switches twice / none |
| 2 | #1540: copy user memory a word at a time on riscv64 | local | none / about 24000 on `thread_read_mem_page`, 1300 on IPC with 7 words |
| 3 | #1541: build IPC messages in place, copying only the valid words | local | about 440 / 1600 per IPC round trip |
| 4 | Read the current thread and per-CPU state through one per-CPU pointer (after PR #1507) | design, awaiting approval | about 45 / 75 per kernel entry |
| 5 | Test the return-to-user work with one per-CPU word (after PR #1507) | design, awaiting approval | about 30 / 50 per return to user |
| 6 | Dispatch syscalls through one masked table index | design, awaiting approval | about 50 / 30 per syscall |
| 7 | #1542: monomorphise the page-table leaf walker's visitor | local | about 700 / not estimated (no thunk) per harvest of 32 pages |
| 8 | Serve small kernel entropy draws from one squeezed block | design, awaiting approval | about 24000 / 24000 per thread lifecycle |
| 9 | #1543: scan kernel stacks a line at a time, and paint them with wider stores | local | about 4700 / 12000 per thread lifecycle |

Not taken:

- The zeroing of memory on retype and free (most of `ktest.thread_lifecycle`'s `memset`):
  it is what keeps one owner's data from the next, and the account shows no excess in it.
- The entry and exit stubs (70 / 145 per syscall): they save and restore the full trap frame,
  which faults, upcalls and the debugger read; a syscall-only frame changes that contract for a
  saving the account does not yet bound, and is not on this list.

## Account

<!-- path-account: begin; generated by cargo xtask path-account write -->
<!-- path-account: end -->

---

## Summarized By

[core/kernel/README.md](../README.md)
