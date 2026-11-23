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

The benchmark cell gates the release profile (opt-level 2, LTO, one codegen
unit), for its ktest rows, ubench and fsbench alike, so one rule states what the cell measures:
the build that runs on hardware. Dev (opt-level 2 with debug assertions and overflow checks,
without LTO) adds 9 % to 58 % to a path on x86_64, unevenly, so a dev count does not predict
the release count and a cut ranked on dev is mis-ranked:

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
functional cells still build and boot dev. The cell's icount baselines and the host-mode bands
are taken on the release build ([docs/testing.md](../../../docs/testing.md) § Benchmarks).

## Ranked Cuts

Ranked on the release account by the instructions each removes from the gated rows. Each cut is
its own Issue, under #1531. A design change went to the maintainer as a pick before its Issue
was filed, and each of the four here is approved; a local cut needs no pick. Each reports the
host-mode figure under KVM beside its counts, and a cut that saves instructions but costs time
is not taken.

| Rank | Cut | Kind | Expected saving (release, x86_64 / riscv64) |
|---:|---|---|---|
| 1 | #1539: skip the I/O bitmap reload when the TSS already holds it | local | about 2100 per row that switches twice / none |
| 2 | #1540: copy user memory a word at a time on riscv64 | local | none / about 24000 on `thread_read_mem_page`, 1300 on IPC with 7 words |
| 3 | #1541: build IPC messages in place, copying only the valid words | local | about 440 / 1600 per IPC round trip |
| 4 | #1547: read the current thread and per-CPU state through one per-CPU pointer (after PR #1507) | design | about 45 / 75 per kernel entry |
| 5 | #1548: test the return-to-user work with one per-CPU word (after PR #1507) | design | about 30 / 50 per return to user |
| 6 | #1549: dispatch syscalls through one masked table index | design | about 50 / 30 per syscall |
| 7 | #1542: monomorphise the page-table leaf walker's visitor | local | about 700 / not estimated (no thunk) per harvest of 32 pages |
| 8 | #1550: serve small kernel entropy draws from one squeezed block | design | about 24000 / 24000 per thread lifecycle |
| 9 | #1543: scan kernel stacks a line at a time, and paint them with wider stores | local | about 4700 / 12000 per thread lifecycle |

Not taken:

- The zeroing of memory on retype and free (most of `ktest.thread_lifecycle`'s `memset`):
  it is what keeps one owner's data from the next, and the account shows no excess in it.
- The entry and exit stubs (70 / 145 per syscall): they save and restore the full trap frame,
  which faults, upcalls and the debugger read; a syscall-only frame changes that contract for a
  saving the account does not yet bound, and is not on this list.

## Account

<!-- path-account: begin; generated by cargo xtask path-account write -->

| Configuration | Head | Taken | QEMU | Checked against |
|---|---|---|---|---|
| x86_64 dev | `356733b5c6ed` | 2026-11-23 | QEMU emulator version 11.1.3 | 1 icount boot(s) of the image without debuginfo |
| x86_64 release | `356733b5c6ed` | 2026-11-23 | QEMU emulator version 11.1.3 | 1 icount boot(s) of the image without debuginfo |
| riscv64 dev | `356733b5c6ed` | 2026-11-23 | QEMU emulator version 11.1.3 | 1 icount boot(s) of the image without debuginfo |
| riscv64 release | `356733b5c6ed` | 2026-11-23 | QEMU emulator version 11.1.3 | 1 icount boot(s) of the image without debuginfo |

#### Totals

| Path | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `ktest.null_syscall_roundtrip cpus=1` | all | 358 | 275 | 496 | 374 |
| `ktest.null_syscall_roundtrip cpus=1` | ktest | 14 | 7 | 9 | 3 |
| `ktest.null_syscall_roundtrip cpus=1` | kernel | 344 | 268 | 487 | 371 |
| `ktest.ipc_round_trip words=0 cpus=1` | all | 6583 | 5015 | 6889 | 4693 |
| `ktest.ipc_round_trip words=0 cpus=1` | ktest | 635 | 97 | 1420 | 79 |
| `ktest.ipc_round_trip words=0 cpus=1` | kernel | 5948 | 4918 | 5469 | 4614 |
| `ktest.ipc_round_trip words=6 cpus=1` | all | 6878 | 5213 | 7296 | 5044 |
| `ktest.ipc_round_trip words=6 cpus=1` | ktest | 745 | 153 | 1620 | 222 |
| `ktest.ipc_round_trip words=6 cpus=1` | kernel | 6133 | 5060 | 5676 | 4822 |
| `ktest.ipc_round_trip words=7 cpus=1` | all | 7180 | 5500 | 8810 | 6490 |
| `ktest.ipc_round_trip words=7 cpus=1` | ktest | 903 | 273 | 1672 | 234 |
| `ktest.ipc_round_trip words=7 cpus=1` | kernel | 6277 | 5227 | 7138 | 6256 |
| `ktest.notification_roundtrip cpus=1` | all | 6127 | 4944 | 4579 | 3584 |
| `ktest.notification_roundtrip cpus=1` | ktest | 43 | 42 | 34 | 32 |
| `ktest.notification_roundtrip cpus=1` | kernel | 6084 | 4902 | 4545 | 3552 |
| `ktest.cap_create_delete cpus=1` | all | 2354 | 1715 | 2887 | 2307 |
| `ktest.cap_create_delete cpus=1` | ktest | 20 | 18 | 15 | 13 |
| `ktest.cap_create_delete cpus=1` | kernel | 2334 | 1697 | 2872 | 2294 |
| `ktest.cap_info_lookup cpus=1` | all | 571 | 392 | 714 | 576 |
| `ktest.cap_info_lookup cpus=1` | ktest | 16 | 9 | 9 | 3 |
| `ktest.cap_info_lookup cpus=1` | kernel | 555 | 383 | 705 | 573 |
| `ktest.mem_map_unmap cpus=1` | all | 2690 | 1896 | 3069 | 2478 |
| `ktest.mem_map_unmap cpus=1` | ktest | 28 | 27 | 23 | 21 |
| `ktest.mem_map_unmap cpus=1` | kernel | 2662 | 1869 | 3046 | 2457 |
| `ktest.mem_protect_pair cpus=1` | all | 2133 | 1627 | 2501 | 1967 |
| `ktest.mem_protect_pair cpus=1` | ktest | 27 | 27 | 23 | 19 |
| `ktest.mem_protect_pair cpus=1` | kernel | 2106 | 1600 | 2478 | 1948 |
| `ktest.aspace_harvest_all_accessed pages=32 cpus=1` | all | 4786 | 4402 | 4976 | 4659 |
| `ktest.aspace_harvest_all_accessed pages=32 cpus=1` | ktest | 17 | 10 | 11 | 7 |
| `ktest.aspace_harvest_all_accessed pages=32 cpus=1` | kernel | 4769 | 4392 | 4965 | 4652 |
| `ktest.aspace_harvest_none_accessed pages=32 cpus=1` | all | 3794 | 3410 | 4016 | 3699 |
| `ktest.aspace_harvest_none_accessed pages=32 cpus=1` | ktest | 17 | 10 | 11 | 7 |
| `ktest.aspace_harvest_none_accessed pages=32 cpus=1` | kernel | 3777 | 3400 | 4005 | 3692 |
| `ktest.thread_lifecycle cpus=1` | all | 97213 | 61599 | 110772 | 84691 |
| `ktest.thread_lifecycle cpus=1` | ktest | 85 | 83 | 73 | 71 |
| `ktest.thread_lifecycle cpus=1` | kernel | 97128 | 61516 | 110699 | 84620 |
| `ktest.context_switch_pair cpus=1` | all | 3800 | 3278 | 1873 | 1411 |
| `ktest.context_switch_pair cpus=1` | ktest | 20 | 13 | 13 | 7 |
| `ktest.context_switch_pair cpus=1` | kernel | 3780 | 3265 | 1860 | 1404 |
| `ktest.thread_read_mem_page cpus=1` | all | 5764 | 5411 | 32507 | 32250 |
| `ktest.thread_read_mem_page cpus=1` | ktest | 20 | 15 | 11 | 8 |
| `ktest.thread_read_mem_page cpus=1` | kernel | 5744 | 5396 | 32496 | 32242 |
| `ktest.event_post_recv cpus=1` | all | 1208 | 926 | 1508 | 1218 |
| `ktest.event_post_recv cpus=1` | ktest | 23 | 22 | 18 | 16 |
| `ktest.event_post_recv cpus=1` | kernel | 1185 | 904 | 1490 | 1202 |
| `ktest.wait_set_cycle cpus=1` | all | 5442 | 3906 | 6500 | 5168 |
| `ktest.wait_set_cycle cpus=1` | ktest | 35 | 34 | 34 | 29 |
| `ktest.wait_set_cycle cpus=1` | kernel | 5407 | 3872 | 6466 | 5139 |
| `ktest.tlb_shootdown_unmap cpus=1` | all | 1045 | 700 | 1213 | 961 |
| `ktest.tlb_shootdown_unmap cpus=1` | ktest | 17 | 10 | 10 | 7 |
| `ktest.tlb_shootdown_unmap cpus=1` | kernel | 1028 | 690 | 1203 | 954 |

#### `ktest.null_syscall_roundtrip cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 93 | 93 |
| `kernel::sched::scheduler_for` | kernel | 60 | 26 | 72 | 34 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 62 | 62 | | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 45 | 52 |
| `kernel::sched::scheduler_ptr` | kernel | 36 | 12 | 48 | 36 |
| `kernel::ipc::upcall::deliver` | kernel | 14 | | 27 | 22 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 5 | 11 | 25 | 12 |
| `kernel::syscall::dispatch` | kernel | 18 | 16 | 23 | 8 |
| `kernel::syscall::sysinfo::sys_system_info` | kernel | 15 | 14 | 22 | 19 |
| `kernel::syscall::dispatch_in_range` | kernel | 19 | 19 | 16 | 16 |
| `kernel::syscall::finish_syscall` | kernel | 8 | 18 | 8 | 8 |
| `kernel::cap::object::reclaim_deferred_stack` | kernel | 7 | 10 | 16 | 5 |
| `kernel::sched::cpu_diag` | kernel | 12 | 6 | 14 | 6 |
| `kernel::sched::running_thread_stopped` | kernel | 14 | 10 | 14 | 8 |
| `kernel::ipc::upcall::deliver_at_syscall` | kernel | 9 | 5 | 12 | 6 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 9 | | | |
| `kernel::cap::object::drain_deferred_reclaim` | kernel | | 5 | 3 | 9 |
| `kernel::syscall::current_tcb` | kernel | 6 | 6 | 6 | 8 |
| `kernel::syscall::stamp_syscall_entry` | kernel | 6 | 4 | 8 | 3 |
| `seraph_enter_from_user` | kernel | 8 | 8 | | |
| `<kernel::arch::current::trap_frame::TrapFrame>::syscall_nr` | kernel | 1 | 7 | 1 | 1 |
| `kernel::arch::current::speculation::index_mask` | kernel | 6 | 6 | 6 | 6 |
| `<bench::counters::Counters>::read` | ktest | 6 | | 6 | |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 3 | 5 | 1 | 1 |
| `<kernel::sched::run_queue::PerCpuScheduler>::current` | kernel | 5 | 5 | 5 | 5 |
| `kernel::ipc::upcall::take` | kernel | 5 | 3 | 5 | 3 |
| `bench::arch::current::cycles` | ktest | 4 | 3 | 1 | 1 |
| `syscall::arch::current::syscall2` | ktest | 4 | 4 | 2 | 2 |
| `kernel::arch::nospec::mask_index` | kernel | 2 | 2 | 3 | 3 |
| `kernel::cap::sole_reference::drain` | kernel | 3 | 3 | 3 | 3 |
| `kernel::sched::note_cpu_syscall` | kernel | 1 | 3 | 2 | 3 |
| 6 functions below 3 each |  | 10 | 2 | 9 | 1 |

#### `ktest.ipc_round_trip words=0 cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `memcpy` | kernel | 1320 | 1320 | 6 | 4 |
| `memset` | kernel | 1223 | 1223 | 452 | 452 |
| `compiler_builtins::mem::memcpy` | kernel | | | 1149 | 762 |
| `compiler_builtins::mem::memcpy` | ktest | | | 686 | |
| `memset` | ktest | 170 | | 428 | |
| `compiler_builtins::mem::memmove` | kernel | | | | 385 |
| `kernel::sched::schedule` | kernel | 296 | 190 | 268 | 234 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 279 | 279 |
| `kernel::sched::scheduler_for` | kernel | 230 | 98 | 276 | 137 |
| `kernel::sched::scheduler_ptr` | kernel | 162 | 58 | 213 | 159 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | 186 | | |
| `memcpy` | ktest | 160 | | 4 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 135 | 156 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 153 | 100 | 68 | 68 |
| `<ipc::IpcMessage>::from_delivery` | ktest | 128 | | 134 | |
| `kernel::arch::current::cpu::current_cpu` | kernel | 42 | 58 | 130 | 54 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 52 | 32 | 114 | 92 |
| `kernel::syscall::pin_checked` | kernel | 94 | 84 | 104 | 90 |
| `kernel::sched::enqueue_and_wake` | kernel | 88 | 58 | 102 | 76 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 91 | 70 | 98 | 86 |
| `kernel::arch::current::context::switch` | kernel | 92 | 92 | 74 | 74 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 88 | 32 | 64 | 40 |
| `kernel::sched::select_target_cpu_excluding` | kernel | 56 | 31 | 87 | 47 |
| `kernel::ipc::upcall::deliver` | kernel | 42 | | 81 | 66 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 76 | 53 | 81 | 72 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 61 | 40 | 76 | 69 |
| `<ipc::IpcMessage>::stage_send` | ktest | 74 | | 70 | |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 72 | 24 | 63 | 22 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 59 | 31 | 69 | 53 |
| `kernel::syscall::dispatch` | kernel | 54 | 48 | 69 | 24 |
| `<kernel::sched::run_queue::RunQueue>::enqueue` | kernel | 58 | 14 | 56 | 16 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 57 | 48 | 48 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 33 | 36 | 56 | 54 |
| `kernel::arch::current::gdt::load_iopb` | kernel | 56 | 17 | | |
| `kernel::syscall::finish_syscall` | kernel | 24 | 54 | 24 | 24 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 51 | 51 | 30 | 28 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 36 | 24 | 50 | 50 |
| `kernel::cap::object::reclaim_deferred_stack` | kernel | 21 | 30 | 48 | 15 |
| `kernel::ipc::endpoint::endpoint_recv` | kernel | 42 | 11 | 45 | 17 |
| `kernel::arch::current::fpu::switch_out_save` | kernel | 10 | 10 | 42 | 38 |
| `kernel::sched::cpu_diag` | kernel | 36 | 18 | 42 | 18 |
| `kernel::sched::running_thread_stopped` | kernel | 42 | 30 | 42 | 24 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 15 | 13 | 35 | 39 |
| `kernel::ipc::upcall::deliver_at_syscall` | kernel | 27 | 15 | 36 | 18 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | | 34 | 34 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 34 | 24 | 34 | 34 |
| 124 functions below 34 each |  | 972 | 783 | 887 | 735 |

#### `ktest.ipc_round_trip words=6 cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `memcpy` | kernel | 1320 | 1364 | 6 | 8 |
| `memset` | kernel | 1223 | 1223 | 452 | 452 |
| `compiler_builtins::mem::memcpy` | kernel | | | 1149 | 864 |
| `compiler_builtins::mem::memcpy` | ktest | | | 792 | 102 |
| `memset` | ktest | 170 | | 428 | |
| `compiler_builtins::mem::memmove` | kernel | | | | 385 |
| `kernel::sched::schedule` | kernel | 296 | 190 | 268 | 234 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 279 | 279 |
| `kernel::sched::scheduler_for` | kernel | 230 | 98 | 276 | 137 |
| `kernel::sched::scheduler_ptr` | kernel | 162 | 58 | 213 | 159 |
| `memcpy` | ktest | 204 | 44 | 8 | 4 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | 186 | | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 135 | 156 |
| `<ipc::IpcMessage>::from_delivery` | ktest | 148 | | 156 | |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 153 | 100 | 68 | 68 |
| `<ipc::IpcMessage>::stage_send` | ktest | 120 | | 138 | |
| `kernel::arch::current::cpu::current_cpu` | kernel | 42 | 58 | 130 | 54 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 52 | 32 | 114 | 92 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 106 | 75 | 112 | 92 |
| `kernel::syscall::pin_checked` | kernel | 94 | 84 | 104 | 90 |
| `kernel::sched::enqueue_and_wake` | kernel | 88 | 58 | 102 | 76 |
| `kernel::arch::current::context::switch` | kernel | 92 | 92 | 74 | 74 |
| `kernel::syscall::ipc::read_data_words` | kernel | 68 | 14 | 92 | 14 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 88 | 32 | 64 | 40 |
| `kernel::sched::select_target_cpu_excluding` | kernel | 56 | 31 | 87 | 47 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 66 | 45 | 82 | 75 |
| `kernel::ipc::upcall::deliver` | kernel | 42 | | 81 | 66 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 76 | 53 | 81 | 72 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 72 | 24 | 63 | 22 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 59 | 31 | 69 | 53 |
| `kernel::syscall::dispatch` | kernel | 54 | 48 | 69 | 24 |
| `<kernel::sched::run_queue::RunQueue>::enqueue` | kernel | 58 | 14 | 56 | 16 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 57 | 48 | 48 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 33 | 36 | 56 | 54 |
| `kernel::arch::current::gdt::load_iopb` | kernel | 56 | 17 | | |
| `kernel::syscall::finish_syscall` | kernel | 24 | 54 | 24 | 24 |
| `<kernel::arch::current::trap_frame::TrapFrame>::set_msg_regs` | kernel | 50 | 44 | 52 | 46 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 51 | 51 | 30 | 28 |
| `ipc::ipc_reply` | ktest | 4 | 29 | 6 | 51 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 36 | 24 | 50 | 50 |
| `kernel::cap::object::reclaim_deferred_stack` | kernel | 21 | 30 | 48 | 15 |
| `kernel::ipc::endpoint::endpoint_recv` | kernel | 42 | 11 | 45 | 17 |
| `kernel::arch::current::fpu::switch_out_save` | kernel | 10 | 10 | 42 | 38 |
| `kernel::sched::cpu_diag` | kernel | 36 | 18 | 42 | 18 |
| `kernel::sched::running_thread_stopped` | kernel | 42 | 30 | 42 | 24 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 15 | 13 | 35 | 39 |
| `kernel::ipc::upcall::deliver_at_syscall` | kernel | 27 | 15 | 36 | 18 |
| 129 functions below 36 each |  | 1049 | 820 | 992 | 819 |

#### `ktest.ipc_round_trip words=7 cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `memcpy` | kernel | 1320 | 1320 | 6 | 4 |
| `memset` | kernel | 1223 | 1223 | 452 | 452 |
| `compiler_builtins::mem::memcpy` | kernel | | | 1149 | 762 |
| `__copy_user_fault_end` | kernel | 8 | 8 | 908 | 908 |
| `compiler_builtins::mem::memcpy` | ktest | | | 686 | |
| `__copy_user_fault_start` | kernel | 228 | 228 | 448 | 448 |
| `memset` | ktest | 170 | | 428 | |
| `compiler_builtins::mem::memmove` | kernel | | | | 385 |
| `kernel::sched::schedule` | kernel | 296 | 190 | 268 | 234 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 279 | 279 |
| `kernel::sched::scheduler_for` | kernel | 230 | 98 | 276 | 137 |
| `<ipc::IpcMessage>::from_delivery` | ktest | 256 | | 262 | |
| `__copy_user` | kernel | 12 | 12 | 236 | 236 |
| `<ipc::IpcMessage>::stage_send` | ktest | 214 | | 194 | |
| `kernel::sched::scheduler_ptr` | kernel | 162 | 58 | 213 | 159 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | 186 | | |
| `memcpy` | ktest | 160 | | 4 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 135 | 156 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 153 | 100 | 68 | 68 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 42 | 58 | 130 | 54 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 52 | 32 | 114 | 92 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 106 | 77 | 112 | 93 |
| `ipc::ipc_call_timeout` | ktest | 18 | 105 | 20 | 90 |
| `kernel::syscall::pin_checked` | kernel | 94 | 84 | 104 | 90 |
| `kernel::sched::enqueue_and_wake` | kernel | 88 | 58 | 102 | 76 |
| `kernel::arch::current::context::switch` | kernel | 92 | 92 | 74 | 74 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 88 | 32 | 64 | 40 |
| `kernel::sched::select_target_cpu_excluding` | kernel | 56 | 31 | 87 | 47 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 66 | 45 | 82 | 75 |
| `kernel::ipc::upcall::deliver` | kernel | 42 | | 81 | 66 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 76 | 53 | 81 | 72 |
| `ipc::ipc_reply` | ktest | 4 | 70 | 6 | 74 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 72 | 24 | 63 | 22 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 59 | 31 | 69 | 53 |
| `kernel::syscall::dispatch` | kernel | 54 | 48 | 69 | 24 |
| `<kernel::sched::run_queue::RunQueue>::enqueue` | kernel | 58 | 14 | 56 | 16 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 57 | 48 | 48 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 33 | 36 | 56 | 54 |
| `kernel::arch::current::gdt::load_iopb` | kernel | 56 | 17 | | |
| `kernel::syscall::finish_syscall` | kernel | 24 | 54 | 24 | 24 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 51 | 51 | 30 | 28 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 36 | 24 | 50 | 50 |
| `kernel::cap::object::reclaim_deferred_stack` | kernel | 21 | 30 | 48 | 15 |
| `ipc::ipc_recv_timeout` | ktest | 16 | 48 | 16 | 32 |
| `kernel::ipc::endpoint::endpoint_recv` | kernel | 42 | 11 | 45 | 17 |
| 135 functions below 44 each |  | 1159 | 895 | 1167 | 936 |

#### `ktest.notification_roundtrip cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `memcpy` | kernel | 1056 | 1056 | | |
| `memset` | kernel | 1045 | 1045 | | |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 372 | 372 |
| `kernel::sched::scheduler_for` | kernel | 300 | 128 | 360 | 178 |
| `kernel::sched::schedule` | kernel | 296 | 190 | 268 | 234 |
| `kernel::sched::scheduler_ptr` | kernel | 204 | 72 | 269 | 201 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 248 | 248 | | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 180 | 208 |
| `kernel::syscall::pin_checked` | kernel | 188 | 168 | 208 | 180 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 180 | 118 | 80 | 80 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 48 | 70 | 160 | 68 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 52 | 32 | 114 | 92 |
| `kernel::ipc::upcall::deliver` | kernel | 56 | | 108 | 88 |
| `kernel::sched::enqueue_and_wake` | kernel | 88 | 58 | 102 | 76 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 72 | 48 | 100 | 100 |
| `kernel::syscall::ipc::sys_notification_wait` | kernel | 88 | 66 | 98 | 100 |
| `kernel::syscall::ipc::sys_notification_send` | kernel | 94 | 68 | 94 | 70 |
| `kernel::arch::current::context::switch` | kernel | 92 | 92 | 74 | 74 |
| `kernel::syscall::dispatch` | kernel | 72 | 64 | 92 | 32 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 88 | 36 | 64 | 40 |
| `kernel::sched::select_target_cpu_excluding` | kernel | 56 | 31 | 87 | 47 |
| `kernel::ipc::notification::notification_send` | kernel | 78 | 48 | 78 | 56 |
| `kernel::syscall::dispatch_in_range` | kernel | 76 | 78 | 64 | 66 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 72 | 24 | 63 | 22 |
| `kernel::syscall::finish_syscall` | kernel | 32 | 72 | 32 | 32 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 68 | 48 | 68 | 68 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 38 | 40 | 66 | 64 |
| `kernel::cap::object::reclaim_deferred_stack` | kernel | 28 | 40 | 64 | 20 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 60 | 60 | 36 | 34 |
| `<kernel::sched::run_queue::RunQueue>::enqueue` | kernel | 58 | 14 | 56 | 16 |
| `kernel::arch::current::gdt::load_iopb` | kernel | 56 | 17 | | |
| `kernel::sched::cpu_diag` | kernel | 48 | 24 | 56 | 24 |
| `kernel::sched::running_thread_stopped` | kernel | 56 | 40 | 56 | 32 |
| `kernel::ipc::notification::notification_wait` | kernel | 50 | 20 | 42 | 30 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 22 | 16 | 44 | 48 |
| `kernel::ipc::upcall::deliver_at_syscall` | kernel | 36 | 20 | 48 | 24 |
| `kernel::arch::current::fpu::switch_out_save` | kernel | 10 | 10 | 42 | 38 |
| `kernel::syscall::current_tcb` | kernel | 32 | 32 | 32 | 42 |
| `<kernel::ipc::WaitQueue>::push` | kernel | 40 | 18 | 32 | 20 |
| `<kernel::sched::run_queue::PerCpuScheduler>::current` | kernel | 32 | 32 | 36 | 32 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 36 | | | |
| `kernel::cap::object::drain_deferred_reclaim` | kernel | | 20 | 12 | 36 |
| `kernel::cap::object::release_ref` | kernel | 36 | 32 | 28 | 28 |
| `<kernel::ipc::WaitQueue>::unlink` | kernel | 34 | 20 | 26 | 16 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | | 34 | 34 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 32 | 12 | 24 | 24 |
| `kernel::arch::current::speculation::index_mask` | kernel | 32 | 32 | 32 | 32 |
| `kernel::syscall::stamp_syscall_entry` | kernel | 24 | 16 | 32 | 12 |
| `seraph_enter_from_user` | kernel | 32 | 32 | | |
| `<kernel::sched::run_queue::RunQueue>::dequeue` | kernel | 30 | 22 | 26 | 20 |
| 82 functions below 30 each |  | 656 | 515 | 620 | 474 |

#### `ktest.cap_create_delete cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 186 | 186 |
| `kernel::sched::scheduler_for` | kernel | 140 | 60 | 168 | 84 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 114 | 84 | 138 | 124 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 124 | 124 | | |
| `kernel::sched::scheduler_ptr` | kernel | 84 | 28 | 112 | 84 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 90 | 104 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 88 | 33 | 66 | 66 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 72 | 48 | 88 | 69 |
| `kernel::syscall::cap::sys_cap_delete` | kernel | 58 | 36 | 75 | 60 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 14 | 40 | 70 | 32 |
| `memset` | kernel | 37 | 37 | 70 | 70 |
| `kernel::syscall::cap::sys_cap_create_notification` | kernel | 67 | 40 | 68 | 66 |
| `kernel::cap::retype::retype_allocate` | kernel | 57 | 33 | 67 | 36 |
| `kernel::cap::object::dealloc_object_one` | kernel | 58 | 32 | 66 | 39 |
| `kernel::sched::check_lock_hold_preemptible` | kernel | 40 | 10 | 60 | 10 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 44 | 44 | 55 | 55 |
| `<kernel::cap::registry::CSpaceRegistry>::entry` | kernel | 54 | 19 | 48 | 23 |
| `kernel::ipc::upcall::deliver` | kernel | 28 | | 54 | 44 |
| `<kernel::cap::registry::CSpaceRegistry>::slot` | kernel | 36 | 29 | 33 | 52 |
| `kernel::syscall::pin_checked` | kernel | 47 | 13 | 52 | 45 |
| `<kernel::cap::registry::CSpaceRegistry>::lookup` | kernel | 39 | 18 | 48 | 16 |
| `kernel::cap::retype::retype_free` | kernel | 41 | 24 | 46 | 39 |
| `kernel::syscall::dispatch` | kernel | 36 | 32 | 46 | 16 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 45 | 29 | 24 | 24 |
| `kernel::cap::derivation::unlink_node` | kernel | 37 | 23 | 42 | 45 |
| `<kernel::cap::cspace::CSpace>::pop_free_slot` | kernel | 37 | 42 | 41 | 41 |
| `<kernel::cap::cspace::CSpace>::free_slot` | kernel | 36 | 33 | 38 | 41 |
| `kernel::arch::current::speculation::index_mask` | kernel | 41 | 41 | 41 | 41 |
| `kernel::cap::derivation::reparent_children` | kernel | 27 | 21 | 40 | 32 |
| `kernel::syscall::dispatch_in_range` | kernel | 40 | 40 | 32 | 32 |
| `kernel::syscall::finish_syscall` | kernel | 16 | 36 | 16 | 16 |
| `<kernel::cap::cspace::CSpace>::insert_cap` | kernel | 30 | 3 | 33 | 4 |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>` | kernel | | | 22 | 33 |
| `kernel::cap::object::reclaim_deferred_stack` | kernel | 14 | 20 | 32 | 10 |
| `<kernel::cap::derivation::DerivationLock>::write_lock` | kernel | 20 | 16 | 31 | 27 |
| `kernel::cap::object::dealloc_object::{closure#0}` | kernel | 1 | 17 | 3 | 31 |
| `kernel::sched::cpu_diag` | kernel | 24 | 12 | 28 | 12 |
| `kernel::sched::running_thread_stopped` | kernel | 28 | 20 | 28 | 16 |
| `<kernel::cap::object::MemoryObject>::read_lock` | kernel | 18 | 21 | 27 | 26 |
| `kernel::ipc::interrupt_all_waiters` | kernel | 6 | 12 | 21 | 24 |
| `kernel::ipc::upcall::deliver_at_syscall` | kernel | 18 | 10 | 24 | 12 |
| `kernel::cap::derivation::resolve_slot_mut` | kernel | 11 | 23 | 11 | 7 |
| `<kernel::cap::retype::FreedClear>::clear` | kernel | 19 | 22 | 17 | 22 |
| `<kernel::cap::slot::CapTag as core::cmp::PartialEq>::eq` | kernel | 22 | 9 | 16 | 7 |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>::{closure#0}` | kernel | 11 | 22 | 11 | |
| `<kernel::cap::cspace::CSpace>::insert_cap_handle` | kernel | 3 | 2 | 20 | 1 |
| `<kernel::cap::retype::RetypeAllocator>::lock` | kernel | 14 | 15 | 20 | 20 |
| `<kernel::cap::slot::SlotId>::with_epoch` | kernel | 16 | 7 | 20 | 18 |
| `kernel::cap::retype::round_to_class` | kernel | 11 | 20 | 10 | 20 |
| `kernel::sched::holder_info` | kernel | 14 | 8 | 20 | 8 |
| `kernel::syscall::current_tcb` | kernel | 16 | 16 | 16 | 20 |
| `<kernel::cap::object::KernelObjectHeader>::dec_ref_in` | kernel | 11 | 8 | 19 | 12 |
| `kernel::syscall::cap::resolve_delete_target` | kernel | 13 | 19 | 8 | 10 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 18 | | | |
| `kernel::cap::object::drain_deferred_reclaim` | kernel | | 10 | 6 | 18 |
| `kernel::cap::retype::credit_freed` | kernel | 14 | 10 | 18 | 15 |
| `<kernel::sched::run_queue::PerCpuScheduler>::current` | kernel | 17 | 17 | 17 | 17 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 12 | 11 | 17 | 17 |
| `kernel::sched::running_tcb_raw` | kernel | 14 | 9 | 17 | 10 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 17 | 9 | 17 | 17 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 16 | 8 | 14 | 9 |
| `kernel::syscall::stamp_syscall_entry` | kernel | 12 | 8 | 16 | 6 |
| `seraph_enter_from_user` | kernel | 16 | 16 | | |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 15 | 15 | 9 | 9 |
| `kernel::arch::current::interrupts::are_enabled` | kernel | 15 | 15 | 10 | 10 |
| `kernel::sched::sleep_wakeups_quiesce` | kernel | 8 | 6 | 15 | 5 |
| `<kernel::arch::current::trap_frame::TrapFrame>::syscall_nr` | kernel | 2 | 14 | 2 | 2 |
| `<kernel::cap::cspace::CSpace>::fill_slot` | kernel | 11 | 14 | 8 | 9 |
| `<kernel::cap::object::MemoryObject>::read_unlock` | kernel | 2 | 9 | 4 | 14 |
| 79 functions below 14 each |  | 288 | 193 | 300 | 217 |

#### `ktest.cap_info_lookup cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 93 | 93 |
| `kernel::sched::scheduler_for` | kernel | 70 | 30 | 84 | 41 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 62 | 62 | | |
| `kernel::sched::scheduler_ptr` | kernel | 42 | 14 | 56 | 42 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 45 | 52 |
| `kernel::syscall::cap::sys_cap_info` | kernel | 52 | 31 | 44 | 44 |
| `kernel::syscall::pin_checked` | kernel | 47 | 11 | 52 | 45 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 6 | 12 | 30 | 14 |
| `kernel::ipc::upcall::deliver` | kernel | 14 | | 27 | 22 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 18 | 12 | 25 | 25 |
| `kernel::syscall::dispatch` | kernel | 18 | 16 | 23 | 8 |
| `kernel::syscall::dispatch_in_range` | kernel | 21 | 21 | 16 | 16 |
| `kernel::syscall::finish_syscall` | kernel | 8 | 18 | 8 | 8 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 17 | 8 | 17 | 17 |
| `kernel::cap::object::reclaim_deferred_stack` | kernel | 7 | 10 | 16 | 5 |
| `kernel::arch::current::speculation::index_mask` | kernel | 11 | 11 | 14 | 14 |
| `kernel::sched::cpu_diag` | kernel | 12 | 6 | 14 | 6 |
| `kernel::sched::running_thread_stopped` | kernel | 14 | 10 | 14 | 8 |
| `kernel::ipc::upcall::deliver_at_syscall` | kernel | 9 | 5 | 12 | 6 |
| `kernel::syscall::current_tcb` | kernel | 8 | 8 | 8 | 11 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 2 | 9 | 2 | 2 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 9 | 6 | 4 | 4 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 9 | | | |
| `kernel::cap::object::drain_deferred_reclaim` | kernel | | 5 | 3 | 9 |
| `kernel::cap::object::release_ref` | kernel | 9 | 8 | 7 | 7 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 8 | 3 | 6 | 6 |
| `<kernel::sched::run_queue::PerCpuScheduler>::current` | kernel | 8 | 8 | 8 | 8 |
| `kernel::syscall::pin_slot` | kernel | 5 | | 8 | 8 |
| `kernel::syscall::stamp_syscall_entry` | kernel | 6 | 4 | 8 | 3 |
| `seraph_enter_from_user` | kernel | 8 | 8 | | |
| `<kernel::arch::current::trap_frame::TrapFrame>::syscall_nr` | kernel | 1 | 7 | 1 | 1 |
| `<bench::counters::Counters>::read` | ktest | 6 | | 6 | |
| `syscall::arch::current::syscall4` | ktest | 6 | 6 | 2 | 2 |
| `<kernel::cap::object::KernelObjectHeader>::dec_ref_in` | kernel | 3 | 3 | 5 | 4 |
| `<kernel::cap::object::KernelObjectHeader>::inc_ref` | kernel | 5 | 1 | 2 | 3 |
| `<kernel::cap::slot::Rights>::contains` | kernel | 5 | | 3 | 3 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 4 | 4 | 5 | 5 |
| `kernel::ipc::upcall::take` | kernel | 5 | 3 | 5 | 3 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 2 | 4 | 3 | 3 |
| `kernel::arch::nospec::mask_index` | kernel | 2 | 2 | 4 | 4 |
| `bench::arch::current::cycles` | ktest | 4 | 3 | 1 | 1 |
| `<kernel::cap::slot::CapTag as core::cmp::PartialEq>::eq` | kernel | 3 | 3 | 2 | 2 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 2 | 1 | 3 | 3 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 3 | 3 | 2 | 2 |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>` | kernel | | | 2 | 3 |
| `kernel::cap::object::references_in` | kernel | | | 3 | |
| `kernel::cap::sole_reference::drain` | kernel | 3 | 3 | 3 | 3 |
| `kernel::sched::note_cpu_syscall` | kernel | 1 | 3 | 2 | 3 |
| 12 functions below 3 each |  | 16 | 10 | 16 | 7 |

#### `ktest.mem_map_unmap cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::syscall::pin_checked` | kernel | 188 | 114 | 208 | 180 |
| `kernel::syscall::mem::sys_mem_map` | kernel | 190 | 156 | 167 | 155 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 186 | 186 |
| `kernel::sched::scheduler_for` | kernel | 140 | 60 | 168 | 84 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 124 | 124 | | |
| `kernel::sched::scheduler_ptr` | kernel | 84 | 28 | 112 | 84 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 90 | 104 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 72 | 48 | 100 | 100 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | | 98 | 90 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 22 | 29 | 85 | 38 |
| `kernel::arch::current::paging::read_entry` | kernel | 80 | 21 | | |
| `kernel::syscall::mem::sys_mem_unmap` | kernel | 59 | 42 | 61 | 77 |
| `boot_protocol::x86_paging::table_index` | kernel | 69 | 39 | | |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 68 | 45 | 68 | 68 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 64 | 32 | 56 | 42 |
| `kernel::arch::current::paging::descend_existing::<kernel::mm::paging::phys_to_virt>` | kernel | 14 | 3 | 60 | 31 |
| `kernel::ipc::upcall::deliver` | kernel | 28 | | 54 | 44 |
| `kernel::arch::current::paging::entry` | kernel | 3 | 3 | 53 | 50 |
| `<kernel::mm::address_space::AddressSpace>::map_page_pooled` | kernel | 43 | 18 | 49 | 46 |
| `<kernel::mm::frame_map::FrameMap>::slot` | kernel | 48 | 25 | 44 | 28 |
| `kernel::arch::current::paging::table_at` | kernel | 35 | | 48 | |
| `boot_protocol::x86_paging::level_shift` | kernel | 47 | 45 | | |
| `kernel::syscall::dispatch` | kernel | 36 | 32 | 46 | 16 |
| `kernel::arch::current::paging::names_table` | kernel | 22 | 45 | | |
| `kernel::syscall::dispatch_in_range` | kernel | 42 | 42 | 32 | 32 |
| `kernel::mm::tlb_shootdown::shootdown_range` | kernel | 23 | 26 | 32 | 40 |
| `kernel::arch::current::paging::map_user_page_pooled` | kernel | 20 | 6 | 39 | 8 |
| `<kernel::mm::frame_map::FrameMap>::lower` | kernel | 22 | 10 | 31 | 38 |
| `kernel::arch::current::paging::install_user_leaf` | kernel | | | 12 | 38 |
| `kernel::arch::current::speculation::index_mask` | kernel | 36 | 35 | 37 | 37 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 36 | 24 | 16 | 16 |
| `boot_protocol::riscv_paging::vpn_index` | kernel | | | 36 | 24 |
| `kernel::cap::object::release_ref` | kernel | 36 | 32 | 28 | 28 |
| `kernel::percpu::per_cpu_ptr` | kernel | 28 | 8 | 36 | 22 |
| `kernel::syscall::finish_syscall` | kernel | 16 | 36 | 16 | 16 |
| `<kernel::syscall::mem::FramePins as core::ops::drop::Drop>::drop` | kernel | 26 | 25 | 34 | 17 |
| `kernel::arch::current::paging::walk_to_4k_leaf::<kernel::mm::paging::phys_to_virt>` | kernel | 34 | 23 | | |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 32 | 12 | 24 | 24 |
| `kernel::cap::object::reclaim_deferred_stack` | kernel | 14 | 20 | 32 | 10 |
| `<kernel::mm::frame_map::FrameMap>::raise` | kernel | 21 | 9 | 30 | 20 |
| `core::ptr::drop_glue::<kernel::syscall::mem::FramePins>` | kernel | 6 | 8 | 29 | 13 |
| `kernel::sched::cpu_diag` | kernel | 24 | 12 | 28 | 12 |
| `kernel::sched::running_thread_stopped` | kernel | 28 | 20 | 28 | 16 |
| `kernel::arch::current::paging::translate_user_page` | kernel | 27 | 6 | 14 | 3 |
| `<kernel::arch::current::paging::PageTableEntry>::phys_addr` | kernel | 16 | 15 | 25 | 25 |
| `<kernel::mm::address_space::AddressSpace>::unmap_page` | kernel | 16 | 3 | 25 | 5 |
| `kernel::ipc::upcall::deliver_at_syscall` | kernel | 18 | 10 | 24 | 12 |
| `<kernel::syscall::mem::FramePins>::pin` | kernel | 18 | 22 | 17 | 15 |
| `kernel::percpu::preempt_enable` | kernel | 22 | 4 | 22 | 8 |
| `<kernel::cap::slot::Rights>::contains` | kernel | 21 | 11 | 13 | 13 |
| `<boot_protocol::riscv_paging::PagingMode>::levels` | kernel | | | 4 | 20 |
| `<kernel::arch::current::paging::PageTableEntry>::new_page` | kernel | 17 | 11 | 20 | 12 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 6 | 20 | 2 | 2 |
| `<kernel::cap::object::KernelObjectHeader>::dec_ref_in` | kernel | 12 | 12 | 20 | 16 |
| `<kernel::cap::object::KernelObjectHeader>::inc_ref` | kernel | 20 | 4 | 8 | 12 |
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 6 | 6 | 20 | 15 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 16 | 16 | 20 | 20 |
| `kernel::syscall::current_tcb` | kernel | 16 | 16 | 16 | 20 |
| `<kernel::arch::current::paging::PageTableEntry>::is_present` | kernel | 18 | 9 | 9 | 5 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 18 | | | |
| `kernel::arch::current::paging::descend_alloc::<kernel::arch::current::paging::map_user_page_pooled::{closure#0}>` | kernel | 14 | 6 | 18 | 6 |
| `kernel::arch::current::paging::root_level` | kernel | 10 | 18 | 2 | |
| `kernel::cap::object::drain_deferred_reclaim` | kernel | | 10 | 6 | 18 |
| `kernel::mm::user_page_range` | kernel | 17 | 17 | 10 | 10 |
| `kernel::percpu::preempt_disable` | kernel | 17 | 6 | 13 | 6 |
| `<boot_protocol::x86_paging::PagingDepth>::from_levels` | kernel | 16 | | | |
| `<kernel::syscall::PinnedCap as core::ops::drop::Drop>::drop` | kernel | 13 | 12 | 16 | 16 |
| `kernel::syscall::mem::map_permissions` | kernel | 16 | 16 | 8 | 8 |
| `kernel::syscall::stamp_syscall_entry` | kernel | 12 | 8 | 16 | 6 |
| `seraph_enter_from_user` | kernel | 16 | 16 | | |
| `<kernel::cpu_mask::MaskSource>::word_except` | kernel | 15 | 14 | 15 | 14 |
| `kernel::arch::current::paging::unmap_user_page` | kernel | 6 | 3 | 15 | 3 |
| `kernel::arch::current::paging::user_va_top` | kernel | 15 | 15 | 10 | 12 |
| `kernel::arch::nospec::mask_span_u64` | kernel | 15 | 15 | 11 | 11 |
| 75 functions below 15 each |  | 361 | 318 | 397 | 331 |

#### `ktest.mem_protect_pair cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::syscall::pin_checked` | kernel | 188 | 168 | 208 | 180 |
| `kernel::syscall::mem::sys_mem_protect` | kernel | 196 | 168 | 174 | 195 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 186 | 186 |
| `kernel::sched::scheduler_for` | kernel | 140 | 60 | 168 | 84 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 124 | 124 | | |
| `kernel::sched::scheduler_ptr` | kernel | 84 | 28 | 112 | 84 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 90 | 104 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 72 | 48 | 100 | 100 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 23 | 29 | 85 | 38 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 68 | 48 | 68 | 68 |
| `kernel::ipc::upcall::deliver` | kernel | 28 | | 54 | 44 |
| `<kernel::mm::address_space::AddressSpace>::protect_page` | kernel | 22 | 2 | 50 | 5 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | | 48 | 48 |
| `kernel::arch::current::paging::protect_user_page` | kernel | 31 | 18 | 46 | 6 |
| `kernel::syscall::dispatch` | kernel | 36 | 32 | 46 | 16 |
| `kernel::arch::current::speculation::index_mask` | kernel | 42 | 42 | 36 | 36 |
| `boot_protocol::x86_paging::table_index` | kernel | 40 | 30 | | |
| `kernel::arch::current::paging::descend_existing::<kernel::mm::paging::phys_to_virt>` | kernel | 28 | 6 | 40 | 20 |
| `kernel::mm::tlb_shootdown::shootdown_range` | kernel | 23 | 26 | 32 | 40 |
| `kernel::syscall::dispatch_in_range` | kernel | 38 | 38 | 32 | 32 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 36 | 24 | 16 | 16 |
| `kernel::arch::current::paging::entry` | kernel | 6 | 6 | 30 | 36 |
| `kernel::cap::object::release_ref` | kernel | 36 | 32 | 28 | 28 |
| `kernel::percpu::per_cpu_ptr` | kernel | 28 | 8 | 36 | 16 |
| `kernel::syscall::finish_syscall` | kernel | 16 | 36 | 16 | 16 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 32 | 12 | 24 | 24 |
| `kernel::arch::current::paging::table_at` | kernel | 32 | | 24 | |
| `kernel::cap::object::reclaim_deferred_stack` | kernel | 14 | 20 | 32 | 10 |
| `boot_protocol::x86_paging::level_shift` | kernel | 28 | 30 | | |
| `kernel::arch::current::paging::names_table` | kernel | 20 | 30 | | |
| `kernel::sched::cpu_diag` | kernel | 24 | 12 | 28 | 12 |
| `kernel::sched::running_thread_stopped` | kernel | 28 | 20 | 28 | 16 |
| `kernel::arch::current::encoding::protected_leaf` | kernel | | | 24 | 14 |
| `kernel::arch::current::paging::map_rights_superset` | kernel | 13 | 13 | 24 | 5 |
| `kernel::ipc::upcall::deliver_at_syscall` | kernel | 18 | 10 | 24 | 12 |
| `kernel::percpu::preempt_enable` | kernel | 24 | 4 | 22 | 6 |
| `kernel::arch::current::paging::protected_leaf` | kernel | 21 | 16 | | |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 6 | 20 | 2 | 2 |
| `<kernel::cap::object::KernelObjectHeader>::dec_ref_in` | kernel | 12 | 12 | 20 | 16 |
| `<kernel::cap::object::KernelObjectHeader>::inc_ref` | kernel | 20 | 4 | 8 | 12 |
| `<kernel::cap::slot::Rights>::contains` | kernel | 20 | 20 | 12 | 12 |
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 6 | 6 | 20 | 8 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 16 | 16 | 20 | 20 |
| `kernel::syscall::current_tcb` | kernel | 16 | 16 | 16 | 20 |
| `<kernel::syscall::PinnedCap as core::ops::drop::Drop>::drop` | kernel | 12 | 12 | 18 | 18 |
| `boot_protocol::riscv_paging::vpn_index` | kernel | | | 18 | 12 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 18 | | | |
| `kernel::cap::object::drain_deferred_reclaim` | kernel | | 10 | 6 | 18 |
| `kernel::mm::user_page_range` | kernel | 16 | 18 | 10 | 10 |
| `kernel::percpu::preempt_disable` | kernel | 18 | 4 | 14 | 6 |
| `<kernel::arch::current::paging::PageTableEntry>::new_page` | kernel | 16 | 8 | 16 | |
| `kernel::syscall::stamp_syscall_entry` | kernel | 12 | 8 | 16 | 6 |
| `seraph_enter_from_user` | kernel | 16 | 16 | | |
| `<kernel::cpu_mask::MaskSource>::word_except` | kernel | 15 | 14 | 15 | 14 |
| `<kernel::arch::current::paging::PageTableEntry>::is_present` | kernel | 14 | 8 | 6 | 2 |
| `<kernel::arch::current::paging::PageTableEntry>::phys_addr` | kernel | 10 | 12 | 14 | 12 |
| `<kernel::arch::current::trap_frame::TrapFrame>::syscall_nr` | kernel | 2 | 14 | 2 | 2 |
| `<kernel::mm::paging::LeafGrant>::admits` | kernel | 14 | 6 | | |
| `<kernel::sched::run_queue::PerCpuScheduler>::current` | kernel | 14 | 14 | 14 | 14 |
| `kernel::mm::tlb_shootdown::shootdown` | kernel | 3 | 4 | 6 | 14 |
| `kernel::syscall::lookup_cap::<kernel::cap::slot::AddressSpaceCap>` | kernel | 8 | 10 | 14 | 14 |
| `kernel::syscall::lookup_cap::<kernel::cap::slot::MemoryCap>` | kernel | 8 | 10 | 14 | 12 |
| `syscall::arch::current::syscall5` | ktest | 13 | 13 | 14 | 13 |
| `<kernel::cap::slot::CapTag as core::cmp::PartialEq>::eq` | kernel | 12 | 4 | 8 | 8 |
| `<kernel::cpu_mask::AtomicCpuMask>::fill_would_be_nonempty` | kernel | 12 | 9 | 9 | 6 |
| `<kernel::cpu_mask::AtomicCpuMask>::words` | kernel | 12 | 2 | 8 | 3 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 8 | 4 | 12 | 12 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 8 | 8 | 12 | 12 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 12 | 12 | 8 | 8 |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>` | kernel | | | 8 | 12 |
| `kernel::cap::object::references_in` | kernel | | | 12 | |
| `kernel::mm::check_user_base` | kernel | 10 | 10 | 12 | 12 |
| 47 functions below 12 each |  | 195 | 163 | 186 | 140 |

#### `ktest.aspace_harvest_all_accessed pages=32 cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::arch::current::paging::walk_leaf_tables` | kernel | | | 912 | 846 |
| `kernel::arch::current::paging::walk_leaf_slots` | kernel | 816 | 746 | | |
| `kernel::arch::current::paging::clear_user_accessed::{closure#0}` | kernel | 448 | 448 | 768 | 800 |
| `__x86_indirect_thunk_r11` | kernel | 640 | 640 | | |
| `<kernel::mm::address_space::AddressSpace>::read_accessed::{closure#0}` | kernel | 384 | 384 | 544 | 544 |
| `kernel::mm::address_space::harvest_bit` | kernel | 416 | 416 | 256 | 256 |
| `kernel::arch::current::paging::entry_mut` | kernel | 320 | 320 | 160 | 160 |
| `kernel::arch::current::paging::read_user_accessed::{closure#0}` | kernel | 320 | 320 | 288 | 288 |
| `memset` | kernel | 85 | 85 | 214 | 214 |
| `kernel::arch::current::paging::entry` | kernel | 6 | 6 | 210 | 210 |
| `<kernel::mm::address_space::AddressSpace>::clear_accessed::{closure#0}` | kernel | 128 | 128 | 192 | 192 |
| `<kernel::mm::address_space::AddressSpace>::clear_accessed::{closure#0}::{closure#0}` | kernel | 160 | 160 | 192 | 192 |
| `<kernel::arch::current::paging::PageTableEntry>::is_present` | kernel | 70 | 70 | 96 | 96 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 93 | 93 |
| `kernel::sched::scheduler_for` | kernel | 70 | 31 | 84 | 43 |
| `kernel::syscall::mem::sys_aspace_harvest` | kernel | 72 | 58 | 74 | 67 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 62 | 62 | | |
| `boot_protocol::riscv_paging::level_shift` | kernel | | | 60 | |
| `kernel::sched::scheduler_ptr` | kernel | 42 | 14 | 56 | 42 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 45 | 52 |
| `kernel::syscall::pin_checked` | kernel | 47 | 42 | 52 | 45 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 10 | 16 | 50 | 22 |
| `boot_protocol::x86_paging::level_shift` | kernel | 48 | | | |
| `boot_protocol::x86_paging::next_level_boundary` | kernel | 36 | 30 | | |
| `kernel::percpu::per_cpu_ptr` | kernel | 28 | 8 | 36 | 20 |
| `kernel::arch::current::paging::names_table` | kernel | 30 | 34 | | |
| `kernel::arch::current::paging::table_at` | kernel | 32 | | 12 | |
| `boot_protocol::riscv_paging::next_level_boundary` | kernel | | | 30 | 30 |
| `boot_protocol::x86_paging::table_index` | kernel | 30 | 6 | | |
| `kernel::ipc::upcall::deliver` | kernel | 14 | | 27 | 22 |
| `kernel::arch::current::paging::for_each_leaf_slot` | kernel | 26 | 16 | 26 | 22 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 18 | 12 | 25 | 25 |
| `<kernel::mm::address_space::AddressSpace>::read_accessed` | kernel | 19 | 18 | 21 | 24 |
| 79 functions below 24 each |  | 409 | 332 | 453 | 354 |

#### `ktest.aspace_harvest_none_accessed pages=32 cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::arch::current::paging::walk_leaf_tables` | kernel | | | 912 | 846 |
| `kernel::arch::current::paging::walk_leaf_slots` | kernel | 816 | 746 | | |
| `kernel::arch::current::paging::clear_user_accessed::{closure#0}` | kernel | 416 | 416 | 672 | 704 |
| `__x86_indirect_thunk_r11` | kernel | 480 | 480 | | |
| `kernel::arch::current::paging::entry_mut` | kernel | 320 | 320 | 160 | 160 |
| `memset` | kernel | 85 | 85 | 214 | 214 |
| `kernel::arch::current::paging::entry` | kernel | 6 | 6 | 210 | 210 |
| `<kernel::mm::address_space::AddressSpace>::clear_accessed::{closure#0}` | kernel | 128 | 128 | 192 | 192 |
| `<kernel::mm::address_space::AddressSpace>::clear_accessed::{closure#0}::{closure#0}` | kernel | 160 | 160 | 192 | 192 |
| `kernel::arch::current::paging::read_user_accessed::{closure#0}` | kernel | 160 | 160 | 160 | 160 |
| `kernel::mm::address_space::harvest_bit` | kernel | 160 | 160 | 64 | 64 |
| `<kernel::arch::current::paging::PageTableEntry>::is_present` | kernel | 70 | 70 | 96 | 96 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 93 | 93 |
| `kernel::sched::scheduler_for` | kernel | 70 | 31 | 84 | 43 |
| `kernel::syscall::mem::sys_aspace_harvest` | kernel | 72 | 58 | 74 | 67 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 62 | 62 | | |
| `boot_protocol::riscv_paging::level_shift` | kernel | | | 60 | |
| `kernel::sched::scheduler_ptr` | kernel | 42 | 14 | 56 | 42 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 45 | 52 |
| `kernel::syscall::pin_checked` | kernel | 47 | 42 | 52 | 45 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 10 | 16 | 50 | 22 |
| `boot_protocol::x86_paging::level_shift` | kernel | 48 | | | |
| `boot_protocol::x86_paging::next_level_boundary` | kernel | 36 | 30 | | |
| `kernel::percpu::per_cpu_ptr` | kernel | 28 | 8 | 36 | 20 |
| `kernel::arch::current::paging::names_table` | kernel | 30 | 34 | | |
| `kernel::arch::current::paging::table_at` | kernel | 32 | | 12 | |
| `boot_protocol::riscv_paging::next_level_boundary` | kernel | | | 30 | 30 |
| `boot_protocol::x86_paging::table_index` | kernel | 30 | 6 | | |
| `kernel::ipc::upcall::deliver` | kernel | 14 | | 27 | 22 |
| `kernel::arch::current::paging::for_each_leaf_slot` | kernel | 26 | 16 | 26 | 22 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 18 | 12 | 25 | 25 |
| `<kernel::mm::address_space::AddressSpace>::read_accessed` | kernel | 19 | 18 | 21 | 24 |
| `kernel::syscall::dispatch` | kernel | 18 | 16 | 23 | 8 |
| `kernel::percpu::preempt_enable` | kernel | 22 | 4 | 22 | 6 |
| `<kernel::mm::address_space::AddressSpace>::clear_accessed` | kernel | 15 | 14 | 17 | 20 |
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 6 | 6 | 20 | 18 |
| 75 functions below 20 each |  | 348 | 292 | 371 | 302 |

#### `ktest.thread_lifecycle cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `crypto::keccak::keccak_f1600` | kernel | 24212 | 25256 | 27004 | 25060 |
| `memset` | kernel | 8260 | 8218 | 21400 | 21400 |
| `kernel::stack_depth::paint` | kernel | 20495 | 2818 | 16397 | 6151 |
| `kernel::stack_depth::used_bytes::{closure#0}` | kernel | 7825 | | 9650 | 3844 |
| `kernel::stack_depth::used_bytes_with::<kernel::stack_depth::used_bytes::{closure#0}>` | kernel | 5870 | 2940 | 5805 | 5770 |
| `kernel::stack_depth::used_bytes_with::<kernel::stack_depth::used_bytes::{closure#0}>::{closure#0}` | kernel | 1956 | 2446 | | |
| `<kernel::cap::cspace::CSpace>::grow` | kernel | 2281 | 1672 | 2351 | 1788 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 1460 | 948 | 1826 | 1776 |
| `<kernel::cap::registry::CSpaceRegistry>::entry` | kernel | 1386 | 421 | 1232 | 456 |
| `kernel::cap::derivation::resolve_slot_mut` | kernel | 966 | 665 | 1138 | 145 |
| `memcpy` | kernel | 1056 | 1056 | | |
| `kernel::sched::scheduler_for` | kernel | 830 | 364 | 996 | 488 |
| `<kernel::cap::registry::CSpaceRegistry>::slot` | kernel | 924 | 494 | 847 | 476 |
| `<kernel::cap::registry::CSpaceRegistry>::lookup` | kernel | 826 | 594 | 906 | 529 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 888 | 888 |
| `<kernel::cap::slot::CapabilitySlot>::set_next_free` | kernel | 460 | 460 | 845 | 845 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 816 | 310 | 612 | 612 |
| `kernel::sched::scheduler_ptr` | kernel | 522 | 183 | 693 | 500 |
| `kernel::syscall::pin_checked` | kernel | 611 | 347 | 676 | 585 |
| `kernel::cap::drain::drain_batch` | kernel | 658 | 654 | 606 | 541 |
| `kernel::cap::cspace::fill_sentinel::<kernel::cap::cspace::CSpacePage, 128>` | kernel | 448 | 176 | 641 | 385 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 592 | 592 | | |
| 423 functions below 553 each |  | 14759 | 10985 | 16259 | 12452 |

#### `ktest.context_switch_pair cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `memcpy` | kernel | 1056 | 1056 | | |
| `memset` | kernel | 1045 | 1045 | | |
| `kernel::sched::schedule` | kernel | 332 | 220 | 306 | 270 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 186 | 186 |
| `kernel::sched::scheduler_for` | kernel | 120 | 52 | 144 | 68 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 124 | 124 | | |
| `kernel::sched::scheduler_ptr` | kernel | 84 | 30 | 112 | 84 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 90 | 104 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 40 | 24 | 102 | 82 |
| `kernel::arch::current::context::switch` | kernel | 92 | 92 | 74 | 74 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 32 | 42 | 80 | 32 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 72 | 24 | 62 | 20 |
| `<kernel::sched::run_queue::RunQueue>::enqueue` | kernel | 66 | 18 | 64 | 20 |
| `kernel::arch::current::gdt::load_iopb` | kernel | 56 | 17 | | |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 54 | 36 | 24 | 24 |
| `kernel::ipc::upcall::deliver` | kernel | 28 | | 54 | 44 |
| `kernel::syscall::dispatch` | kernel | 36 | 32 | 46 | 16 |
| `kernel::arch::current::fpu::switch_out_save` | kernel | 10 | 10 | 42 | 38 |
| `kernel::syscall::finish_syscall` | kernel | 16 | 36 | 16 | 16 |
| `kernel::cap::object::reclaim_deferred_stack` | kernel | 14 | 20 | 32 | 10 |
| `kernel::syscall::dispatch_in_range` | kernel | 32 | 32 | 20 | 20 |
| `<kernel::sched::run_queue::RunQueue>::dequeue` | kernel | 28 | 20 | 24 | 18 |
| `kernel::sched::cpu_diag` | kernel | 24 | 12 | 28 | 12 |
| `kernel::sched::running_thread_stopped` | kernel | 28 | 20 | 28 | 16 |
| `kernel::ipc::upcall::deliver_at_syscall` | kernel | 18 | 10 | 24 | 12 |
| `kernel::percpu::per_cpu_ptr` | kernel | 24 | 8 | 18 | 10 |
| `kernel::sched::last_non_idle_tick` | kernel | 24 | 12 | 22 | 10 |
| `<kernel::sched::run_queue::PerCpuScheduler>::idle` | kernel | 16 | 14 | 22 | 16 |
| `<kernel::sched::Outgoing>::owned_by_another_cpu` | kernel | 20 | 20 | 12 | 6 |
| `kernel::sched::run_queue::queue_index` | kernel | 18 | 20 | 12 | 14 |
| 48 functions below 19 each |  | 291 | 232 | 229 | 189 |

#### `ktest.thread_read_mem_page cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `__copy_user_fault_end` | kernel | 2 | 2 | 16387 | 16387 |
| `__copy_user_fault_start` | kernel | 4097 | 4097 | 8192 | 8192 |
| `__copy_user` | kernel | 3 | 3 | 4099 | 4099 |
| `compiler_builtins::mem::memcpy` | kernel | | | 2583 | 2581 |
| `memcpy` | kernel | 528 | 528 | 2 | 2 |
| 114 functions below 162 each |  | 1134 | 781 | 1244 | 989 |

#### `ktest.event_post_recv cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 186 | 186 |
| `kernel::sched::scheduler_for` | kernel | 140 | 60 | 168 | 82 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 124 | 124 | | |
| `kernel::sched::scheduler_ptr` | kernel | 84 | 28 | 112 | 84 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 90 | 104 |
| `kernel::syscall::pin_checked` | kernel | 94 | 84 | 104 | 90 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 12 | 24 | 60 | 28 |
| `kernel::ipc::upcall::deliver` | kernel | 28 | | 54 | 44 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 36 | 24 | 50 | 50 |
| `kernel::ipc::event_queue::event_queue_post` | kernel | 43 | 22 | 49 | 40 |
| `kernel::syscall::dispatch` | kernel | 36 | 32 | 46 | 16 |
| `kernel::syscall::ipc::sys_event_recv` | kernel | 40 | 29 | 42 | 41 |
| `kernel::syscall::dispatch_in_range` | kernel | 38 | 38 | 32 | 32 |
| `kernel::syscall::ipc::sys_event_post` | kernel | 37 | 27 | 37 | 32 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 36 | 23 | 16 | 16 |
| `kernel::syscall::finish_syscall` | kernel | 16 | 36 | 16 | 16 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 34 | 24 | 34 | 34 |
| `kernel::cap::object::reclaim_deferred_stack` | kernel | 14 | 20 | 32 | 10 |
| `kernel::sched::cpu_diag` | kernel | 24 | 12 | 28 | 12 |
| `kernel::sched::running_thread_stopped` | kernel | 28 | 20 | 28 | 16 |
| `kernel::ipc::upcall::deliver_at_syscall` | kernel | 18 | 10 | 24 | 12 |
| `kernel::syscall::current_tcb` | kernel | 16 | 16 | 16 | 22 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 5 | 18 | 5 | 5 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 18 | | | |
| `kernel::cap::object::drain_deferred_reclaim` | kernel | | 10 | 6 | 18 |
| `kernel::cap::object::release_ref` | kernel | 18 | 16 | 14 | 14 |
| `kernel::ipc::event_queue::pop_entry_locked` | kernel | 17 | 13 | 18 | 13 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 12 | 17 | 8 | 7 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 16 | 6 | 12 | 12 |
| `<kernel::sched::run_queue::PerCpuScheduler>::current` | kernel | 16 | 16 | 15 | 15 |
| `kernel::arch::current::speculation::index_mask` | kernel | 16 | 16 | 16 | 16 |
| `kernel::syscall::stamp_syscall_entry` | kernel | 12 | 8 | 16 | 6 |
| `seraph_enter_from_user` | kernel | 16 | 16 | | |
| `<kernel::arch::current::trap_frame::TrapFrame>::syscall_nr` | kernel | 2 | 14 | 2 | 2 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 9 | 9 | 14 | 14 |
| `kernel::syscall::lookup_cap::<kernel::cap::slot::EventQueueCap>` | kernel | 8 | 6 | 13 | 11 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 6 | 4 | 11 | 12 |
| `<kernel::cap::object::KernelObjectHeader>::dec_ref_in` | kernel | 6 | 6 | 10 | 8 |
| `<kernel::cap::object::KernelObjectHeader>::inc_ref` | kernel | 10 | 2 | 4 | 6 |
| `<kernel::cap::slot::Rights>::contains` | kernel | 10 | 10 | 6 | 6 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 8 | 8 | 10 | 10 |
| `kernel::ipc::event_queue::ring_step` | kernel | 10 | 9 | 5 | 6 |
| `kernel::ipc::upcall::take` | kernel | 10 | 6 | 10 | 6 |
| 30 functions below 7 each |  | 85 | 63 | 89 | 64 |

#### `ktest.wait_set_cycle cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 465 | 465 |
| `kernel::sched::scheduler_for` | kernel | 350 | 150 | 420 | 208 |
| `kernel::syscall::pin_checked` | kernel | 282 | 170 | 312 | 270 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 310 | 310 | | |
| `kernel::sched::scheduler_ptr` | kernel | 210 | 70 | 280 | 210 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 225 | 260 |
| `memset` | kernel | 112 | 112 | 255 | 255 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 160 | 108 | 213 | 194 |
| `kernel::ipc::wait_set::wait_set_drop::<kernel::cap::object::dealloc_object_one::{closure#7}>` | kernel | 172 | 172 | 202 | 198 |
| `<kernel::ipc::wait_set::WaitSetState>::new` | kernel | 171 | 71 | 157 | 87 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 32 | 76 | 160 | 74 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 114 | 84 | 138 | 124 |
| `kernel::ipc::upcall::deliver` | kernel | 70 | | 135 | 110 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 128 | 48 | 96 | 96 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 126 | 79 | 56 | 56 |
| `kernel::syscall::dispatch` | kernel | 90 | 80 | 115 | 40 |
| `kernel::syscall::ipc::sys_wait_set_add` | kernel | 101 | 64 | 108 | 65 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 102 | 65 | 102 | 102 |
| `kernel::syscall::dispatch_in_range` | kernel | 99 | 101 | 80 | 82 |
| `kernel::syscall::ipc::sys_wait_set_remove` | kernel | 88 | 53 | 91 | 53 |
| `kernel::syscall::finish_syscall` | kernel | 40 | 90 | 40 | 40 |
| `kernel::arch::current::speculation::index_mask` | kernel | 85 | 87 | 87 | 88 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 64 | 64 | 80 | 80 |
| `kernel::cap::object::reclaim_deferred_stack` | kernel | 35 | 50 | 80 | 25 |
| `kernel::syscall::cap::sys_cap_create_wait_set` | kernel | 68 | 42 | 78 | 71 |
| `kernel::syscall::cap::sys_cap_delete` | kernel | 58 | 36 | 75 | 60 |
| `kernel::sched::cpu_diag` | kernel | 60 | 30 | 70 | 30 |
| `kernel::sched::running_thread_stopped` | kernel | 70 | 50 | 70 | 40 |
| `kernel::cap::retype::retype_allocate` | kernel | 58 | 34 | 68 | 37 |
| `kernel::cap::object::dealloc_object_one` | kernel | 55 | 30 | 66 | 43 |
| `kernel::ipc::upcall::deliver_at_syscall` | kernel | 45 | 25 | 60 | 30 |
| `kernel::sched::check_lock_hold_preemptible` | kernel | 40 | 10 | 60 | 10 |
| `syscall_abi::wait_set_retype_bytes` | kernel | 52 | 19 | 56 | 26 |
| `<kernel::cap::registry::CSpaceRegistry>::entry` | kernel | 54 | 19 | 48 | 23 |
| `kernel::cap::object::release_ref` | kernel | 54 | 48 | 42 | 42 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 42 | 53 | 28 | 26 |
| `<kernel::cap::registry::CSpaceRegistry>::slot` | kernel | 36 | 29 | 33 | 52 |
| `kernel::syscall::current_tcb` | kernel | 40 | 40 | 40 | 52 |
| `<kernel::cap::object::KernelObjectHeader>::dec_ref_in` | kernel | 30 | 30 | 51 | 36 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 34 | 33 | 47 | 49 |
| `<kernel::cap::registry::CSpaceRegistry>::lookup` | kernel | 39 | 18 | 48 | 16 |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>` | kernel | | | 32 | 48 |
| `kernel::syscall::ipc::wait_set_source` | kernel | 48 | 30 | 46 | 24 |
| `kernel::cap::retype::retype_free` | kernel | 41 | 24 | 46 | 39 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 45 | | | |
| `kernel::cap::derivation::unlink_node` | kernel | 37 | 23 | 42 | 45 |
| `kernel::cap::object::drain_deferred_reclaim` | kernel | | 25 | 15 | 45 |
| `kernel::syscall::ipc::sys_wait_set_wait` | kernel | 42 | 27 | 44 | 40 |
| `<kernel::cap::object::KernelObjectHeader>::inc_ref` | kernel | 43 | 8 | 21 | 21 |
| `<kernel::cap::cspace::CSpace>::pop_free_slot` | kernel | 37 | 42 | 41 | 41 |
| `<kernel::ipc::wait_set::WaitSetMember>::is_occupied` | kernel | 41 | 42 | 23 | 23 |
| `<kernel::cap::cspace::CSpace>::free_slot` | kernel | 36 | 33 | 38 | 41 |
| `<kernel::sched::run_queue::PerCpuScheduler>::current` | kernel | 40 | 40 | 38 | 38 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 21 | 16 | 40 | 40 |
| `kernel::cap::derivation::reparent_children` | kernel | 27 | 21 | 40 | 32 |
| `kernel::ipc::wait_set::waitset_remove` | kernel | 40 | 18 | 18 | 13 |
| `kernel::syscall::stamp_syscall_entry` | kernel | 30 | 20 | 40 | 15 |
| `seraph_enter_from_user` | kernel | 40 | 40 | | |
| `<kernel::cap::slot::CapTag as core::cmp::PartialEq>::eq` | kernel | 37 | 18 | 26 | 17 |
| `<kernel::ipc::wait_set::WaitSetState>::install::<kernel::ipc::wait_set::waitset_add::{closure#0}>` | kernel | 37 | 23 | 31 | 27 |
| `<kernel::ipc::wait_set::WaitSetState>::pop_ready::<&kernel::ipc::wait_set::next_ready_member::{closure#0}>` | kernel | 36 | 21 | 37 | 23 |
| `<kernel::arch::current::trap_frame::TrapFrame>::syscall_nr` | kernel | 5 | 35 | 5 | 5 |
| `<kernel::cap::cspace::CSpace>::insert_cap` | kernel | 30 | 3 | 33 | 4 |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>::{closure#0}` | kernel | 16 | 32 | 16 | |
| `kernel::ipc::wait_set::waitset_add` | kernel | 30 | 12 | 32 | 29 |
| 129 functions below 32 each |  | 907 | 703 | 959 | 733 |

#### `ktest.tlb_shootdown_unmap cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 93 | 93 |
| `kernel::sched::scheduler_for` | kernel | 70 | 30 | 84 | 42 |
| `kernel::syscall::mem::sys_mem_unmap` | kernel | 59 | 42 | 61 | 77 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 62 | 62 | | |
| `kernel::sched::scheduler_ptr` | kernel | 42 | 14 | 56 | 42 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 45 | 52 |
| `kernel::syscall::pin_checked` | kernel | 47 | 15 | 52 | 45 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | | 48 | 48 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 14 | 15 | 45 | 20 |
| `kernel::arch::current::paging::descend_existing::<kernel::mm::paging::phys_to_virt>` | kernel | 14 | 3 | 40 | 20 |
| `kernel::arch::current::paging::read_entry` | kernel | 40 | 10 | | |
| `kernel::mm::tlb_shootdown::shootdown_range` | kernel | 23 | 26 | 32 | 40 |
| `boot_protocol::x86_paging::table_index` | kernel | 34 | 21 | | |
| `kernel::arch::current::paging::entry` | kernel | 3 | 3 | 30 | 28 |
| `kernel::arch::current::paging::names_table` | kernel | 16 | 30 | | |
| `kernel::ipc::upcall::deliver` | kernel | 14 | | 27 | 22 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 18 | 12 | 25 | 25 |
| `<kernel::mm::address_space::AddressSpace>::unmap_page` | kernel | 16 | 3 | 25 | 5 |
| `boot_protocol::x86_paging::level_shift` | kernel | 23 | 24 | | |
| `kernel::arch::current::paging::table_at` | kernel | 16 | | 24 | |
| `kernel::syscall::dispatch` | kernel | 18 | 16 | 23 | 8 |
| `kernel::syscall::dispatch_in_range` | kernel | 21 | 21 | 16 | 16 |
| `<kernel::mm::frame_map::FrameMap>::lower` | kernel | 11 | 5 | 16 | 19 |
| `boot_protocol::riscv_paging::vpn_index` | kernel | | | 18 | 12 |
| `kernel::percpu::per_cpu_ptr` | kernel | 14 | 4 | 18 | 10 |
| `kernel::syscall::finish_syscall` | kernel | 8 | 18 | 8 | 8 |
| `kernel::arch::current::paging::walk_to_4k_leaf::<kernel::mm::paging::phys_to_virt>` | kernel | 17 | 11 | | |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 17 | 10 | 17 | 17 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 16 | 8 | 14 | 11 |
| `kernel::cap::object::reclaim_deferred_stack` | kernel | 7 | 10 | 16 | 5 |
| `<kernel::cpu_mask::MaskSource>::word_except` | kernel | 15 | 14 | 15 | 14 |
| `kernel::arch::current::paging::translate_user_page` | kernel | 15 | 3 | 6 | 1 |
| `kernel::arch::current::paging::unmap_user_page` | kernel | 6 | 3 | 15 | 3 |
| `kernel::sched::cpu_diag` | kernel | 12 | 6 | 14 | 6 |
| `kernel::sched::running_thread_stopped` | kernel | 14 | 10 | 14 | 8 |
| `<kernel::arch::current::paging::PageTableEntry>::phys_addr` | kernel | 7 | 6 | 13 | 13 |
| `<kernel::arch::current::paging::PageTableEntry>::is_present` | kernel | 12 | 6 | 1 | 1 |
| `<kernel::cpu_mask::AtomicCpuMask>::fill_would_be_nonempty` | kernel | 12 | 9 | 9 | 6 |
| `<kernel::cpu_mask::AtomicCpuMask>::words` | kernel | 12 | 2 | 8 | 3 |
| `<kernel::mm::frame_map::FrameMap>::slot` | kernel | 12 | 6 | 11 | 7 |
| `kernel::ipc::upcall::deliver_at_syscall` | kernel | 9 | 5 | 12 | 6 |
| `kernel::percpu::preempt_enable` | kernel | 11 | 2 | 11 | 3 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 3 | 10 | 1 | 1 |
| `<kernel::cpu_mask::MaskSource>::word_except::{closure#0}` | kernel | 6 | 6 | 10 | 10 |
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 3 | 3 | 10 | 5 |
| `<kernel::mm::address_space::AddressSpace>::shootdown_remote` | kernel | 6 | 5 | 10 | 9 |
| `kernel::arch::current::speculation::index_mask` | kernel | 10 | 10 | 10 | 10 |
| `kernel::syscall::current_tcb` | kernel | 8 | 8 | 8 | 10 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 9 | 6 | 4 | 4 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 9 | | | |
| `kernel::cap::object::drain_deferred_reclaim` | kernel | | 5 | 3 | 9 |
| `kernel::cap::object::release_ref` | kernel | 9 | 8 | 7 | 7 |
| `kernel::mm::user_page_range` | kernel | 8 | 9 | 5 | 5 |
| `kernel::percpu::preempt_disable` | kernel | 9 | 3 | 7 | 3 |
| `<boot_protocol::x86_paging::PagingDepth>::from_levels` | kernel | 8 | | | |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 8 | 3 | 6 | 6 |
| `kernel::mm::tlb_shootdown::requests` | kernel | 7 | 5 | 8 | 6 |
| `kernel::syscall::stamp_syscall_entry` | kernel | 6 | 4 | 8 | 3 |
| `seraph_enter_from_user` | kernel | 8 | 8 | | |
| `<kernel::arch::current::trap_frame::TrapFrame>::syscall_nr` | kernel | 1 | 7 | 1 | 1 |
| `<kernel::sched::run_queue::PerCpuScheduler>::current` | kernel | 7 | 7 | 7 | 7 |
| `kernel::syscall::lookup_cap::<kernel::cap::slot::AddressSpaceCap>` | kernel | 4 | | 7 | 6 |
| `syscall::arch::current::syscall4` | ktest | 7 | 7 | 3 | 6 |
| `<boot_protocol::riscv_paging::PagingMode>::from_satp_mode` | kernel | | | 6 | |
| `<kernel::syscall::PinnedCap as core::ops::drop::Drop>::drop` | kernel | 5 | 4 | 6 | 5 |
| `kernel::arch::current::paging::direct_map_base` | kernel | 6 | 6 | 6 | 6 |
| `kernel::arch::current::paging::levels_above::{closure#0}` | kernel | 3 | 3 | | 6 |
| `kernel::arch::current::paging::root_level` | kernel | 6 | 3 | | |
| `kernel::mm::check_user_base` | kernel | 5 | 5 | 6 | 6 |
| `kernel::mm::frame_map::lower` | kernel | 6 | | | 3 |
| `kernel::mm::paging::phys_to_virt` | kernel | 6 | 6 | 6 | 6 |
| `kernel::mm::tlb_shootdown::shootdown` | kernel | 3 | 4 | 6 | 5 |
| `<bench::counters::Counters>::read` | ktest | 6 | | 6 | |
| 42 functions below 6 each |  | 86 | 70 | 94 | 80 |

<!-- path-account: end -->

---

## Summarized By

[core/kernel/README.md](../README.md)
