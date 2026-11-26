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

The account boots the image at one CPU under icount with a QEMU plugin that counts every
instruction the guest runs, and attributes every instruction between each pair of counter reads
to a function. A window whose instructions differ from the sample the benchmark recorded, or a
p50 outside the gate's band of the reference boot's, fails the run, so each table below sums to
the count the benchmark cell sees for that tree and profile. The method, its checks and its
limits are in [xtask/README.md](../../../xtask/README.md) § `cargo xtask path-account`. The
ubench and fsbench rows, whose paths cross the kernel and several processes, are accounted the
same way in [hot-path-account-userspace.md](hot-path-account-userspace.md).

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
and revises the prose below where its numbers moved. A kernel path the ubench or fsbench rows
also run owes their account too, as
[hot-path-account-userspace.md](hot-path-account-userspace.md) § Regenerating It says.

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

The null syscall (`SYS_SYSTEM_INFO` on a cheap query) is 160 / 217 instructions, 153 / 214 in
the kernel:

| Part | x86_64 | riscv64 | Functions |
|---|---:|---:|---|
| Entry and exit stubs | 70 | 150 | `syscall_entry`, `seraph_enter_from_user`; `trap_entry`, `trap_dispatch`, `handle_trap` |
| Finding this CPU's thread and diagnostic record | 3 | 3 | `read_percpu_ptr` of `PerCpuData::current` and `PerCpuData::diag` |
| Dispatch and result | 54 | 33 | `dispatch`, `dispatch_in_range`, `index_mask`, `mask_index`, `finish_syscall` |
| Return-to-user work test | 4 | 4 | `leave_syscall`, `read_percpu_u32` of `PerCpuData::return_work` |
| Diagnostic stamps | 4 | 2 | `stamp_syscall_entry` |
| The handler | 15 | 18 | `sys_system_info`, `TrapFrame::arg` |
| Functions below 3 each | 3 | 4 | `syscall_nr`, `note_cpu_syscall`, `TrapFrame::set_return` |

The current thread and this CPU's diagnostic record are each one load relative to the per-CPU
pointer ([scheduling-internals.md](scheduling-internals.md#per-cpu-current-thread) § Per-CPU
Current Thread). The return to user mode tests this CPU's return-work word with one load and one
branch, 4 / 4 instructions when no work is pending; the stopped check, the reclaim and
sole-reference drains, upcall delivery and the wake-preemption decision run only when a producer
has set their bit ([scheduling-internals.md](scheduling-internals.md#return-work) § Return Work).

### Context Switch and IPC

On x86_64, a switch to a thread without port bindings stores the TSS I/O-bitmap offset past the
segment limit and writes no bitmap byte, and a switch to a bound thread copies its 8 KiB bitmap
only when the CPU's TSS does not already hold it at its generation (`gdt::load_iopb`;
[capability-internals.md](capability-internals.md) § IoPort Bindings). Once the TSS holds the
bound bench thread's bitmap, a row that switches twice (`ktest.ipc_round_trip`,
`ktest.notification_roundtrip`, `ktest.context_switch_pair`) spends 5 instructions in
`load_iopb` and copies nothing, so x86_64's context-switch pair, 1011, is below riscv64's 1289,
which has no bitmap.

A switch-in of a user thread makes its floating-point and vector state live
([scheduler.md](scheduler.md#what-gets-saved-and-restored) § What Gets Saved and Restored). On
x86_64 a switch between two user threads saves one and loads the other, the `fpu` rows of
`ktest.context_switch_pair` 52 instructions. On riscv64 a thread that has not used F, D or V has
the registers zeroed at its switch-in when they hold another thread's state (`fpu::scrub`, 39).
`ktest.context_switch_pair` and `ktest.notification_roundtrip` pair such a thread with one that
has used them, so each round trip zeroes the registers for the one and loads the other's area
(`restore_fp_from` 34, `restore_v_from` 17): the pair's `fpu` rows are 184 instructions.

A call finds the receiver its CPU parked on the endpoint by comparing the queue words of all four
slots of the CPU's parked-receiver table, and a receiver's park finds the slot naming its endpoint
the same way ([ipc-internals.md](ipc-internals.md) § Wait Queues), so the search costs the same
whichever slot names the endpoint. The slot follows the order of the CPU's earlier parks on other
endpoints, which the machine's timing decides, and a search that stopped at the match gave one
image's round trip a different count from one boot to the next.

An IPC message is built in place in each thread's `ipc_msg`, and a rendezvous, a reply or a
fault delivery copies only its counted data words and capability slots, so no row zeroes or
moves a whole 576-byte `Message`. A server that replies and receives in one
`SYS_IPC_REPLY_RECV` (`ktest.ipc_round_trip words=0 server=reply_recv`) serves the empty round
trip in 2352 / 2825, against 2445 / 2904 for `SYS_IPC_REPLY` and then `SYS_IPC_RECV`: one kernel
entry and exit fewer per round trip.

On riscv64 `__copy_user` copies a run whose user and kernel pointers are both 8-byte aligned
in 64-byte blocks of eight loads and eight stores, then single words, and any other run in
bytes ([arch-interface.md](arch-interface.md) § `cpu` — `arch::current::cpu`). The page of
`ktest.thread_read_mem_page` takes 1280 of its 4659 in `__copy_user`, against 4097 of 5271 in
x86_64's `rep movsb`, which counts once per byte under icount; the IPC round trip with seven
words, the one whose payload passes the register words, copies it in 180.

### Other Rows

- `ktest.aspace_harvest_*`: the leaf walkers take their visitors as generic parameters, so
  the per-slot visit is a direct call, or inlined, with no retpoline thunk; the walk and its
  visitors are most of the 2685 / 3140 with all 32 pages accessed and the 2013 / 2372 with
  none.
- `ktest.thread_lifecycle`: 28412 / 46450. Its two kernel entropy draws (the TCB's random
  field, and the CSpace-id epoch redraw on free) take their bytes from the CPU's squeezed block
  ([entropy.md](entropy.md) § Draw API and consumers), 334 / 286 for both; the block's refill,
  three Keccak-f[1600] permutations, falls in one iteration of 17 and so outside the p50
  window. The kernel-stack paint at creation and the depth scan at teardown are 3667 / 4323:
  the paint's `fill_words` 2051 / 2566 (`rep stosq` counts once per word under icount; riscv64
  stores a line per iteration), and the scan, which reads one word per 64-byte line of the
  untouched span ([memory-internals.md](memory-internals.md) § Kernel Stack Depth), 1616 / 1757;
  and the zeroing of new and freed memory 7097 / 21309.

## Profile

The benchmark cell gates the release profile (opt-level 2, LTO, one codegen
unit), for its ktest rows, ubench and fsbench alike, so one rule states what the cell measures:
the build that runs on hardware. Dev (opt-level 2 with debug assertions and overflow checks,
without LTO) adds 5 % to 61 % to a path on x86_64, unevenly, so a dev count does not predict
the release count and a cut ranked on dev is mis-ranked:

| Path (x86_64) | Dev | Release | Dev / release |
|---|---:|---:|---:|
| `ktest.null_syscall_roundtrip` | 190 | 160 | 1.19 |
| `ktest.ipc_round_trip words=0` | 3907 | 2445 | 1.60 |
| `ktest.notification_roundtrip` | 3264 | 2370 | 1.38 |
| `ktest.cap_info_lookup` | 373 | 260 | 1.43 |
| `ktest.mem_map_unmap` | 2228 | 1626 | 1.37 |
| `ktest.aspace_harvest_all_accessed pages=32` | 2957 | 2685 | 1.10 |
| `ktest.thread_lifecycle` | 38849 | 28412 | 1.37 |
| `ktest.context_switch_pair` | 1452 | 1011 | 1.44 |
| `ktest.tlb_shootdown_unmap` | 827 | 565 | 1.46 |

Dev's excess is debug assertions (`debug_assert_kernel_entry_flags`, `read_rflags`), overflow
checks, and calls that LTO inlines in release. The accepted cost is that a
regression only dev runs (a debug assertion added to a hot path) is not gated; it costs nothing
on hardware, and the functional cells still build and boot dev. The cell's icount baselines and
the host-mode bands are taken on the release build
([docs/testing.md](../../../docs/testing.md) § Benchmarks).

## Ranked Cuts

Ranked on the release account by the instructions each removes from the gated rows. Each cut is
its own Issue, under #1531. A design change goes to the maintainer as a pick: the three taken or
declined here were approved before their Issues were filed, and #1695's goes before it is built;
a local cut needs no pick. Each reports the
host-mode figure under KVM beside its counts, and a cut that saves instructions but costs time
is not taken.

| Rank | Cut | Kind | Expected saving (release, x86_64 / riscv64) |
|---:|---|---|---|
| 1 | #1540: copy user memory a word at a time on riscv64 (taken: PR #1657) | local | none / 27404 on `thread_read_mem_page`, 1381 on IPC with 7 words, measured; no riscv64 KVM host or hardware for a host-mode figure |
| 2 | #1541: build IPC messages in place, copying only the valid words (taken: PR #1567) | local | 384 / 1570 per IPC round trip, measured |
| 3 | #1548: test the return-to-user work with one per-CPU word (taken: PR #1574) | design | 51 / 65 per null syscall, measured |
| 4 | #1549: dispatch syscalls through one masked table index (not taken: PR #1576 kept the `match`, built from one list) | design | about 50 / 30 per syscall; measured 7 / 6 per null syscall, and about 10 cycles slower on x86_64 under KVM |
| 5 | #1542: monomorphise the page-table leaf walker's visitor (taken: PR #1657) | local | 1585 / 1314 per harvest of 32 pages, measured; 4334 to 1239 cycles on x86_64 under KVM |
| 6 | #1550: serve small kernel entropy draws from one squeezed block (taken: PR #1656) | design | 25618 / 25185 per thread lifecycle, measured; 17479 to 14321 cycles on x86_64 under KVM |
| 7 | #1543: scan kernel stacks a line at a time, and paint them with wider stores (taken: PR #1660) | local | 4632 / 11391 per thread lifecycle, measured; 14284 to 13498 cycles on x86_64 under KVM |
| 8 | #1695: find a parked receiver's slot through a per-CPU hint in the receive queue, with no scan (open) | design | about 18 / 30 per IPC round trip that passes the parked-receiver table, estimated from the search's instructions |

Not taken:

- The zeroing of memory on retype and free (most of `ktest.thread_lifecycle`'s `memset`):
  it is what keeps one owner's data from the next, and the account shows no excess in it.
- The entry and exit stubs (70 / 150 per syscall): they save and restore the full trap frame,
  which faults, upcalls and the debugger read; a syscall-only frame changes that contract for a
  saving the account does not yet bound, and is not on this list.

## Account

<!-- path-account: begin; generated by cargo xtask path-account write -->

| Configuration | Head | Taken | QEMU | Checked against |
|---|---|---|---|---|
| x86_64 dev | `bda9b5ff0364` | 2026-11-26 | QEMU emulator version 11.1.3 | 1 icount boot(s) of the image without debuginfo |
| x86_64 release | `bda9b5ff0364` | 2026-11-26 | QEMU emulator version 11.1.3 | 1 icount boot(s) of the image without debuginfo |
| riscv64 dev | `bda9b5ff0364` | 2026-11-26 | QEMU emulator version 11.1.3 | 1 icount boot(s) of the image without debuginfo |
| riscv64 release | `bda9b5ff0364` | 2026-11-26 | QEMU emulator version 11.1.3 | 1 icount boot(s) of the image without debuginfo |

#### Totals

| Path | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `ktest.null_syscall_roundtrip cpus=1` | all | 190 | 160 | 253 | 217 |
| `ktest.null_syscall_roundtrip cpus=1` | ktest | 14 | 7 | 9 | 3 |
| `ktest.null_syscall_roundtrip cpus=1` | kernel | 176 | 153 | 244 | 214 |
| `ktest.ipc_round_trip words=0 cpus=1` | all | 3907 | 2445 | 5087 | 2904 |
| `ktest.ipc_round_trip words=0 cpus=1` | ktest | 640 | 101 | 1420 | 78 |
| `ktest.ipc_round_trip words=0 cpus=1` | kernel | 3267 | 2344 | 3667 | 2826 |
| `ktest.ipc_round_trip words=6 cpus=1` | all | 4225 | 2647 | 5560 | 3295 |
| `ktest.ipc_round_trip words=6 cpus=1` | ktest | 750 | 158 | 1620 | 227 |
| `ktest.ipc_round_trip words=6 cpus=1` | kernel | 3475 | 2489 | 3940 | 3068 |
| `ktest.ipc_round_trip words=7 cpus=1` | all | 4508 | 2928 | 5693 | 3375 |
| `ktest.ipc_round_trip words=7 cpus=1` | ktest | 908 | 277 | 1672 | 234 |
| `ktest.ipc_round_trip words=7 cpus=1` | kernel | 3600 | 2651 | 4021 | 3141 |
| `ktest.ipc_round_trip words=0 fpu=both cpus=1` | all | 3912 | 2450 | 5277 | 3076 |
| `ktest.ipc_round_trip words=0 fpu=both cpus=1` | ktest | 645 | 106 | 1426 | 84 |
| `ktest.ipc_round_trip words=0 fpu=both cpus=1` | kernel | 3267 | 2344 | 3851 | 2992 |
| `ktest.ipc_round_trip words=0 server=reply_recv cpus=1` | all | 3798 | 2352 | 5013 | 2825 |
| `ktest.ipc_round_trip words=0 server=reply_recv cpus=1` | ktest | 636 | 98 | 1418 | 77 |
| `ktest.ipc_round_trip words=0 server=reply_recv cpus=1` | kernel | 3162 | 2254 | 3595 | 2748 |
| `ktest.notification_roundtrip cpus=1` | all | 3264 | 2370 | 3759 | 3007 |
| `ktest.notification_roundtrip cpus=1` | ktest | 43 | 41 | 34 | 32 |
| `ktest.notification_roundtrip cpus=1` | kernel | 3221 | 2329 | 3725 | 2975 |
| `ktest.cap_create_delete cpus=1` | all | 1928 | 1461 | 2322 | 1944 |
| `ktest.cap_create_delete cpus=1` | ktest | 20 | 18 | 15 | 13 |
| `ktest.cap_create_delete cpus=1` | kernel | 1908 | 1443 | 2307 | 1931 |
| `ktest.cap_info_lookup cpus=1` | all | 373 | 260 | 444 | 392 |
| `ktest.cap_info_lookup cpus=1` | ktest | 16 | 9 | 9 | 3 |
| `ktest.cap_info_lookup cpus=1` | kernel | 357 | 251 | 435 | 389 |
| `ktest.mem_map_unmap cpus=1` | all | 2228 | 1626 | 2426 | 2086 |
| `ktest.mem_map_unmap cpus=1` | ktest | 28 | 27 | 23 | 21 |
| `ktest.mem_map_unmap cpus=1` | kernel | 2200 | 1599 | 2403 | 2065 |
| `ktest.mem_protect_pair cpus=1` | all | 1695 | 1375 | 1887 | 1607 |
| `ktest.mem_protect_pair cpus=1` | ktest | 27 | 25 | 23 | 19 |
| `ktest.mem_protect_pair cpus=1` | kernel | 1668 | 1350 | 1864 | 1588 |
| `ktest.aspace_harvest_all_accessed pages=32 cpus=1` | all | 2957 | 2685 | 3396 | 3140 |
| `ktest.aspace_harvest_all_accessed pages=32 cpus=1` | ktest | 17 | 10 | 11 | 7 |
| `ktest.aspace_harvest_all_accessed pages=32 cpus=1` | kernel | 2940 | 2675 | 3385 | 3133 |
| `ktest.aspace_harvest_none_accessed pages=32 cpus=1` | all | 2285 | 2013 | 2628 | 2372 |
| `ktest.aspace_harvest_none_accessed pages=32 cpus=1` | ktest | 17 | 10 | 11 | 7 |
| `ktest.aspace_harvest_none_accessed pages=32 cpus=1` | kernel | 2268 | 2003 | 2617 | 2365 |
| `ktest.thread_lifecycle cpus=1` | all | 38849 | 28412 | 54759 | 46450 |
| `ktest.thread_lifecycle cpus=1` | ktest | 81 | 79 | 69 | 67 |
| `ktest.thread_lifecycle cpus=1` | kernel | 38768 | 28333 | 54690 | 46383 |
| `ktest.context_switch_pair cpus=1` | all | 1452 | 1011 | 1677 | 1289 |
| `ktest.context_switch_pair cpus=1` | ktest | 20 | 13 | 13 | 7 |
| `ktest.context_switch_pair cpus=1` | kernel | 1432 | 998 | 1664 | 1282 |
| `ktest.thread_read_mem_page cpus=1` | all | 5541 | 5271 | 4826 | 4659 |
| `ktest.thread_read_mem_page cpus=1` | ktest | 20 | 15 | 11 | 8 |
| `ktest.thread_read_mem_page cpus=1` | kernel | 5521 | 5256 | 4815 | 4651 |
| `ktest.event_post_recv cpus=1` | all | 805 | 669 | 1000 | 854 |
| `ktest.event_post_recv cpus=1` | ktest | 23 | 23 | 18 | 16 |
| `ktest.event_post_recv cpus=1` | kernel | 782 | 646 | 982 | 838 |
| `ktest.wait_set_cycle cpus=1` | all | 4366 | 3247 | 5130 | 4226 |
| `ktest.wait_set_cycle cpus=1` | ktest | 35 | 33 | 34 | 29 |
| `ktest.wait_set_cycle cpus=1` | kernel | 4331 | 3214 | 5096 | 4197 |
| `ktest.tlb_shootdown_unmap cpus=1` | all | 827 | 565 | 904 | 761 |
| `ktest.tlb_shootdown_unmap cpus=1` | ktest | 17 | 10 | 10 | 7 |
| `ktest.tlb_shootdown_unmap cpus=1` | kernel | 810 | 555 | 894 | 754 |

#### `ktest.null_syscall_roundtrip cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 93 | 93 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 62 | 62 | | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 32 | 38 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | | 24 | 19 |
| `kernel::syscall::dispatch` | kernel | 18 | 23 | 17 | 7 |
| `kernel::syscall::sysinfo::sys_system_info` | kernel | 15 | 12 | 22 | 17 |
| `kernel::syscall::dispatch_in_range` | kernel | 21 | 21 | 15 | 15 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 9 | | | |
| `seraph_enter_from_user` | kernel | 8 | 8 | | |
| `kernel::arch::current::speculation::index_mask` | kernel | 6 | 6 | 6 | 6 |
| `kernel::syscall::leave_syscall` | kernel | 5 | 3 | 6 | 3 |
| `kernel::syscall::stamp_syscall_entry` | kernel | 6 | 4 | 5 | 2 |
| `<bench::counters::Counters>::read` | ktest | 6 | | 6 | |
| `kernel::sched::this_cpu_diag` | kernel | 4 | | 3 | |
| `bench::arch::current::cycles` | ktest | 4 | 3 | 1 | 1 |
| `syscall::arch::current::syscall2` | ktest | 4 | 4 | 2 | 2 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 3 | 3 | 1 | 1 |
| `kernel::arch::nospec::mask_index` | kernel | 2 | 2 | 3 | 3 |
| 12 functions below 3 each |  | 17 | 9 | 17 | 10 |

#### `ktest.ipc_round_trip words=0 cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `compiler_builtins::mem::memcpy` | ktest | | | 686 | |
| `memset` | ktest | 170 | | 428 | |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 279 | 279 |
| `kernel::sched::schedule` | kernel | 260 | 172 | 260 | 228 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | 186 | | |
| `memcpy` | ktest | 160 | | 4 | |
| `<ipc::IpcMessage>::from_delivery` | ktest | 128 | | 134 | |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 122 | 44 | 121 | 40 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 52 | 32 | 114 | 92 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 96 | 114 |
| `kernel::syscall::pin_checked` | kernel | 84 | 84 | 104 | 90 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 102 | 101 | 68 | 68 |
| `kernel::sched::enqueue_and_wake` | kernel | 76 | 46 | 102 | 70 |
| `kernel::arch::current::context::switch` | kernel | 92 | 92 | 74 | 74 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 60 | 35 | 90 | 40 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 72 | 61 | 87 | 74 |
| `<kernel::sched::run_queue::RunQueue>::enqueue` | kernel | 74 | 14 | 68 | 16 |
| `<ipc::IpcMessage>::stage_send` | ktest | 74 | | 70 | |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | | 72 | 57 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 59 | 40 | 72 | 55 |
| `kernel::syscall::dispatch` | kernel | 54 | 69 | 52 | 21 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 57 | 45 | 45 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 30 | 34 | 56 | 54 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 53 | 51 | 30 | 26 |
| `<kernel::ipc::recv_park::RecvParkTable>::named` | kernel | 46 | 44 | 48 | 52 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 26 | 24 | 52 | 12 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 40 | 24 | 50 | 50 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 28 | 24 | 45 | 39 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 42 | 22 | 45 | 36 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 16 | 13 | 37 | 39 |
| `kernel::arch::current::fpu::set_frame_units` | kernel | | | 36 | 28 |
| `kernel::syscall::finish_syscall_work` | kernel | 17 | 20 | 18 | 36 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | | 34 | 34 |
| `kernel::ipc::endpoint::bind_next_sender` | kernel | 21 | 18 | 33 | 34 |
| `kernel::syscall::ipc::deliver_message` | kernel | 16 | 32 | 24 | 34 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 34 | 24 | 34 | 34 |
| `<kernel::ipc::message::Message>::caps` | kernel | 33 | 28 | 32 | 26 |
| `kernel::sched::place_unpinned::<kernel::sched::KernelWake>` | kernel | 10 | 18 | 33 | 31 |
| `kernel::sched::scheduler_ptr` | kernel | 24 | 10 | 32 | 26 |
| `memcpy` | kernel | 32 | 32 | 4 | 4 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 9 | 30 | 7 | 7 |
| `<kernel::ipc::message::Message>::data` | kernel | 30 | 18 | 19 | 20 |
| `<kernel::sched::run_queue::RunQueue>::dequeue` | kernel | 30 | 22 | 26 | 20 |
| `kernel::arch::current::fpu::switch_in_restore` | kernel | 16 | 18 | 30 | 30 |
| `kernel::ipc::endpoint::endpoint_recv` | kernel | 24 | 15 | 30 | 23 |
| `kernel::sched::mark_dispatched` | kernel | 28 | 14 | 26 | 16 |
| `kernel::sched::run_return_work::<kernel::syscall::finish_syscall_work::{closure#0}, kernel::syscall::finish_syscall_work::{closure#1}>` | kernel | 20 | 5 | 28 | 1 |
| `kernel::syscall::ipc::deposit_reply` | kernel | 28 | 14 | 26 | 15 |
| `kernel::syscall::ipc::stage_reply_payload` | kernel | 27 | 22 | 28 | 22 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 27 | | | |
| `kernel::ipc::upcall::deliver` | kernel | 7 | | 27 | 22 |
| `kernel::sched::run_queue::queue_index` | kernel | 26 | 24 | 17 | 17 |
| `ipc::ipc_call_timeout` | ktest | 18 | 26 | 20 | 18 |
| 174 functions below 25 each |  | 1267 | 786 | 1134 | 735 |

#### `ktest.ipc_round_trip words=6 cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `compiler_builtins::mem::memcpy` | ktest | | | 792 | 102 |
| `memset` | ktest | 170 | | 428 | |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 279 | 279 |
| `kernel::sched::schedule` | kernel | 260 | 172 | 260 | 228 |
| `memcpy` | ktest | 204 | 44 | 8 | 4 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | 186 | | |
| `compiler_builtins::mem::memcpy` | kernel | | | 61 | 162 |
| `<ipc::IpcMessage>::from_delivery` | ktest | 148 | | 156 | |
| `<ipc::IpcMessage>::stage_send` | ktest | 120 | | 138 | |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 122 | 44 | 121 | 40 |
| `kernel::syscall::ipc::read_data_words` | kernel | 92 | 13 | 120 | 14 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 52 | 32 | 114 | 92 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 96 | 114 |
| `kernel::syscall::pin_checked` | kernel | 84 | 84 | 104 | 90 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 102 | 101 | 68 | 68 |
| `kernel::sched::enqueue_and_wake` | kernel | 76 | 46 | 102 | 70 |
| `kernel::arch::current::context::switch` | kernel | 92 | 92 | 74 | 74 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 60 | 35 | 90 | 40 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 76 | 63 | 87 | 74 |
| `memcpy` | kernel | 38 | 82 | 4 | 8 |
| `<kernel::sched::run_queue::RunQueue>::enqueue` | kernel | 74 | 14 | 68 | 16 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | | 72 | 57 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 59 | 40 | 72 | 55 |
| `kernel::syscall::dispatch` | kernel | 54 | 69 | 52 | 21 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 57 | 45 | 45 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 30 | 34 | 56 | 54 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 53 | 51 | 30 | 26 |
| `<kernel::arch::current::trap_frame::TrapFrame>::set_msg_regs` | kernel | 52 | 46 | 52 | 46 |
| `<kernel::ipc::recv_park::RecvParkTable>::named` | kernel | 46 | 44 | 48 | 52 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 26 | 24 | 52 | 12 |
| `ipc::ipc_reply` | ktest | 5 | 30 | 6 | 52 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 40 | 24 | 50 | 50 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 28 | 24 | 45 | 39 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 42 | 22 | 45 | 36 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 16 | 13 | 37 | 39 |
| `kernel::arch::current::fpu::set_frame_units` | kernel | | | 36 | 28 |
| `kernel::syscall::finish_syscall_work` | kernel | 17 | 20 | 18 | 36 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | | 34 | 34 |
| `kernel::ipc::endpoint::bind_next_sender` | kernel | 21 | 18 | 33 | 34 |
| `kernel::syscall::ipc::deliver_message` | kernel | 16 | 32 | 24 | 34 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 34 | 24 | 34 | 34 |
| `<kernel::ipc::message::Message>::caps` | kernel | 33 | 28 | 32 | 26 |
| `kernel::sched::place_unpinned::<kernel::sched::KernelWake>` | kernel | 10 | 18 | 33 | 31 |
| `kernel::sched::scheduler_ptr` | kernel | 24 | 10 | 32 | 26 |
| `ipc::ipc_call_timeout` | ktest | 18 | 32 | 20 | 27 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 9 | 30 | 7 | 7 |
| `<kernel::ipc::message::Message>::data` | kernel | 30 | 18 | 19 | 20 |
| `<kernel::sched::run_queue::RunQueue>::dequeue` | kernel | 30 | 22 | 26 | 20 |
| `kernel::arch::current::fpu::switch_in_restore` | kernel | 16 | 18 | 30 | 30 |
| `kernel::ipc::endpoint::endpoint_recv` | kernel | 24 | 15 | 30 | 23 |
| `kernel::syscall::ipc::stage_reply_payload` | kernel | 28 | 25 | 29 | 25 |
| `kernel::sched::mark_dispatched` | kernel | 28 | 14 | 26 | 16 |
| `kernel::sched::run_return_work::<kernel::syscall::finish_syscall_work::{closure#0}, kernel::syscall::finish_syscall_work::{closure#1}>` | kernel | 20 | 5 | 28 | 1 |
| `kernel::syscall::ipc::deposit_reply` | kernel | 28 | 14 | 26 | 15 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 27 | | | |
| `kernel::ipc::upcall::deliver` | kernel | 7 | | 27 | 22 |
| 181 functions below 27 each |  | 1341 | 818 | 1184 | 747 |

#### `ktest.ipc_round_trip words=7 cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `compiler_builtins::mem::memcpy` | ktest | | | 686 | |
| `memset` | ktest | 170 | | 428 | |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 279 | 279 |
| `<ipc::IpcMessage>::from_delivery` | ktest | 256 | | 262 | |
| `kernel::sched::schedule` | kernel | 260 | 172 | 260 | 228 |
| `__copy_user_fault_start` | kernel | 228 | 228 | | |
| `<ipc::IpcMessage>::stage_send` | ktest | 214 | | 194 | |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | 186 | | |
| `__copy_user_words` | kernel | | | 180 | 180 |
| `memcpy` | ktest | 160 | | 4 | |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 122 | 44 | 121 | 40 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 52 | 32 | 114 | 92 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 96 | 114 |
| `ipc::ipc_call_timeout` | ktest | 18 | 106 | 20 | 91 |
| `kernel::syscall::pin_checked` | kernel | 84 | 84 | 104 | 90 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 102 | 101 | 68 | 68 |
| `kernel::sched::enqueue_and_wake` | kernel | 76 | 46 | 102 | 70 |
| `kernel::arch::current::context::switch` | kernel | 92 | 92 | 74 | 74 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 60 | 35 | 90 | 40 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 76 | 63 | 87 | 74 |
| `<kernel::sched::run_queue::RunQueue>::enqueue` | kernel | 74 | 14 | 68 | 16 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | | 72 | 57 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 59 | 40 | 72 | 55 |
| `ipc::ipc_reply` | ktest | 5 | 70 | 6 | 72 |
| `kernel::syscall::dispatch` | kernel | 54 | 69 | 52 | 21 |
| `compiler_builtins::mem::memcpy` | kernel | | | 66 | 65 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 57 | 45 | 45 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 30 | 34 | 56 | 54 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 53 | 51 | 30 | 26 |
| `<kernel::ipc::recv_park::RecvParkTable>::named` | kernel | 46 | 44 | 48 | 52 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 26 | 24 | 52 | 12 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 40 | 24 | 50 | 50 |
| `ipc::ipc_recv_timeout` | ktest | 14 | 47 | 15 | 31 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 28 | 24 | 45 | 39 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 42 | 22 | 45 | 36 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 16 | 13 | 37 | 39 |
| `memcpy` | kernel | 39 | 39 | 4 | 4 |
| `kernel::arch::current::fpu::set_frame_units` | kernel | | | 36 | 28 |
| `kernel::syscall::finish_syscall_work` | kernel | 17 | 20 | 18 | 36 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | | 34 | 34 |
| `kernel::ipc::endpoint::bind_next_sender` | kernel | 21 | 18 | 33 | 34 |
| `kernel::syscall::ipc::deliver_message` | kernel | 16 | 32 | 24 | 34 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 34 | 24 | 34 | 34 |
| `<kernel::ipc::message::Message>::caps` | kernel | 33 | 28 | 32 | 26 |
| `kernel::sched::place_unpinned::<kernel::sched::KernelWake>` | kernel | 10 | 18 | 33 | 31 |
| `__copy_user` | kernel | 12 | 12 | 32 | 32 |
| `kernel::sched::scheduler_ptr` | kernel | 24 | 10 | 32 | 26 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 9 | 30 | 7 | 7 |
| `<kernel::ipc::message::Message>::data` | kernel | 30 | 18 | 19 | 20 |
| `<kernel::sched::run_queue::RunQueue>::dequeue` | kernel | 30 | 22 | 26 | 20 |
| `kernel::arch::current::fpu::switch_in_restore` | kernel | 16 | 18 | 30 | 30 |
| `kernel::ipc::endpoint::endpoint_recv` | kernel | 24 | 15 | 30 | 23 |
| `kernel::syscall::ipc::stage_reply_payload` | kernel | 28 | 25 | 29 | 25 |
| `kernel::sched::mark_dispatched` | kernel | 28 | 14 | 26 | 16 |
| `kernel::sched::run_return_work::<kernel::syscall::finish_syscall_work::{closure#0}, kernel::syscall::finish_syscall_work::{closure#1}>` | kernel | 20 | 5 | 28 | 1 |
| `kernel::syscall::ipc::deposit_reply` | kernel | 28 | 14 | 26 | 15 |
| 185 functions below 28 each |  | 1389 | 844 | 1232 | 789 |

#### `ktest.ipc_round_trip words=0 fpu=both cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `compiler_builtins::mem::memcpy` | ktest | | | 686 | |
| `memset` | ktest | 170 | | 428 | |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 279 | 279 |
| `kernel::sched::schedule` | kernel | 260 | 172 | 260 | 228 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | 186 | | |
| `memcpy` | ktest | 160 | | 4 | |
| `<ipc::IpcMessage>::from_delivery` | ktest | 128 | | 134 | |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 122 | 44 | 121 | 40 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 52 | 32 | 114 | 92 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 96 | 114 |
| `kernel::syscall::pin_checked` | kernel | 84 | 84 | 104 | 90 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 102 | 101 | 68 | 68 |
| `kernel::sched::enqueue_and_wake` | kernel | 76 | 46 | 102 | 70 |
| `kernel::arch::current::context::switch` | kernel | 92 | 92 | 74 | 74 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 60 | 35 | 90 | 40 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 72 | 61 | 87 | 74 |
| `<kernel::sched::run_queue::RunQueue>::enqueue` | kernel | 74 | 14 | 68 | 16 |
| `<ipc::IpcMessage>::stage_send` | ktest | 74 | | 70 | |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | | 72 | 57 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 59 | 40 | 72 | 55 |
| `kernel::syscall::dispatch` | kernel | 54 | 69 | 52 | 21 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | | 68 | 68 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 57 | 45 | 45 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 30 | 34 | 56 | 54 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 53 | 51 | 30 | 26 |
| `<kernel::ipc::recv_park::RecvParkTable>::named` | kernel | 46 | 44 | 48 | 52 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 26 | 24 | 52 | 12 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 40 | 24 | 50 | 50 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 28 | 24 | 45 | 39 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 42 | 22 | 45 | 36 |
| `kernel::arch::current::fpu::set_frame_units` | kernel | | | 44 | 34 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 16 | 13 | 37 | 39 |
| `kernel::arch::current::fpu::save_v_to` | kernel | | | 36 | 36 |
| `kernel::syscall::finish_syscall_work` | kernel | 17 | 20 | 18 | 36 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | | 34 | 34 |
| `kernel::arch::current::fpu::restore_v_from` | kernel | | | 34 | 34 |
| `kernel::arch::current::fpu::switch_in_restore` | kernel | 16 | 18 | 34 | 30 |
| `kernel::ipc::endpoint::bind_next_sender` | kernel | 21 | 18 | 33 | 34 |
| `kernel::syscall::ipc::deliver_message` | kernel | 16 | 32 | 24 | 34 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 34 | 24 | 34 | 34 |
| `<kernel::ipc::message::Message>::caps` | kernel | 33 | 28 | 32 | 26 |
| `kernel::sched::place_unpinned::<kernel::sched::KernelWake>` | kernel | 10 | 18 | 33 | 31 |
| `kernel::sched::scheduler_ptr` | kernel | 24 | 10 | 32 | 26 |
| `memcpy` | kernel | 32 | 32 | 4 | 4 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 9 | 30 | 7 | 7 |
| `<kernel::ipc::message::Message>::data` | kernel | 30 | 18 | 19 | 20 |
| `<kernel::sched::run_queue::RunQueue>::dequeue` | kernel | 30 | 22 | 26 | 20 |
| `kernel::ipc::endpoint::endpoint_recv` | kernel | 24 | 15 | 30 | 23 |
| `kernel::sched::mark_dispatched` | kernel | 28 | 14 | 26 | 16 |
| `kernel::sched::run_return_work::<kernel::syscall::finish_syscall_work::{closure#0}, kernel::syscall::finish_syscall_work::{closure#1}>` | kernel | 20 | 5 | 28 | 1 |
| `kernel::syscall::ipc::deposit_reply` | kernel | 28 | 14 | 26 | 15 |
| `kernel::syscall::ipc::stage_reply_payload` | kernel | 27 | 22 | 28 | 22 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 27 | | | |
| `kernel::ipc::upcall::deliver` | kernel | 7 | | 27 | 22 |
| `kernel::sched::run_queue::queue_index` | kernel | 26 | 24 | 17 | 17 |
| `ipc::ipc_call_timeout` | ktest | 18 | 26 | 20 | 18 |
| 179 functions below 26 each |  | 1272 | 791 | 1174 | 763 |

#### `ktest.ipc_round_trip words=0 server=reply_recv cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `compiler_builtins::mem::memcpy` | ktest | | | 686 | |
| `memset` | ktest | 170 | | 428 | |
| `kernel::sched::schedule` | kernel | 260 | 172 | 260 | 228 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 186 | 186 |
| `memcpy` | ktest | 160 | | 4 | |
| `<ipc::IpcMessage>::from_delivery` | ktest | 128 | | 134 | |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 124 | 124 | | |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 122 | 44 | 121 | 40 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 52 | 32 | 114 | 92 |
| `kernel::syscall::pin_checked` | kernel | 84 | 84 | 104 | 90 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 102 | 100 | 68 | 68 |
| `kernel::sched::enqueue_and_wake` | kernel | 76 | 46 | 102 | 70 |
| `kernel::arch::current::context::switch` | kernel | 92 | 92 | 74 | 74 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 60 | 40 | 90 | 40 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 72 | 61 | 87 | 74 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 64 | 76 |
| `<kernel::sched::run_queue::RunQueue>::enqueue` | kernel | 74 | 14 | 68 | 16 |
| `<ipc::IpcMessage>::stage_send` | ktest | 74 | | 70 | |
| `kernel::arch::current::cpu::current_cpu` | kernel | 32 | 28 | 72 | 19 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 59 | 40 | 72 | 55 |
| `kernel::syscall::ipc::sys_ipc_reply_recv` | kernel | 55 | 41 | 64 | 61 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 33 | 39 | 56 | 54 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 53 | 51 | 30 | 25 |
| `<kernel::ipc::recv_park::RecvParkTable>::named` | kernel | 46 | 44 | 48 | 52 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 40 | 24 | 50 | 50 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | | 48 | 38 |
| `kernel::syscall::dispatch` | kernel | 36 | 46 | 35 | 14 |
| `kernel::sched::place_unpinned::<kernel::sched::KernelWake>` | kernel | 30 | 25 | 41 | 38 |
| `kernel::arch::current::fpu::scrub` | kernel | | | 40 | 39 |
| `kernel::arch::current::fpu::set_frame_units` | kernel | | | 40 | 31 |
| `kernel::sched::run_queue::queue_index` | kernel | 40 | 37 | 26 | 26 |
| `kernel::syscall::dispatch_in_range` | kernel | 40 | 40 | 30 | 30 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 16 | 13 | 37 | 39 |
| `kernel::sched::scheduler_ptr` | kernel | 24 | 10 | 37 | 26 |
| `kernel::syscall::finish_syscall_work` | kernel | 17 | 20 | 18 | 36 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | | 34 | 34 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | | 34 | 34 |
| `kernel::ipc::endpoint::bind_next_sender` | kernel | 21 | 18 | 33 | 34 |
| `kernel::syscall::ipc::deliver_message` | kernel | 16 | 32 | 24 | 34 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 34 | 24 | 34 | 34 |
| `<kernel::ipc::message::Message>::caps` | kernel | 33 | 28 | 32 | 26 |
| `kernel::arch::current::fpu::switch_in_restore` | kernel | 16 | 18 | 33 | 31 |
| `memcpy` | kernel | 32 | 32 | 4 | 4 |
| `<kernel::ipc::message::Message>::data` | kernel | 30 | 18 | 19 | 20 |
| `<kernel::sched::run_queue::RunQueue>::dequeue` | kernel | 30 | 22 | 26 | 20 |
| `kernel::ipc::endpoint::endpoint_recv` | kernel | 29 | 22 | 30 | 25 |
| `kernel::sched::mark_dispatched` | kernel | 28 | 14 | 26 | 16 |
| `kernel::sched::run_return_work::<kernel::syscall::finish_syscall_work::{closure#0}, kernel::syscall::finish_syscall_work::{closure#1}>` | kernel | 20 | 5 | 28 | 1 |
| `kernel::syscall::ipc::deposit_reply` | kernel | 26 | 21 | 28 | 18 |
| `kernel::syscall::ipc::stage_reply_payload` | kernel | 27 | 22 | 28 | 22 |
| `kernel::ipc::upcall::deliver` | kernel | 7 | | 27 | 22 |
| `ipc::ipc_call_timeout` | ktest | 18 | 26 | 20 | 18 |
| 183 functions below 25 each |  | 1260 | 783 | 1149 | 745 |

#### `ktest.notification_roundtrip cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 372 | 372 |
| `kernel::sched::schedule` | kernel | 276 | 185 | 278 | 245 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 248 | 248 | | |
| `kernel::syscall::pin_checked` | kernel | 168 | 168 | 208 | 180 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 128 | 152 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 117 | 31 | 114 | 33 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 52 | 32 | 114 | 92 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 80 | 48 | 100 | 100 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 96 | 95 | 64 | 64 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | | 96 | 76 |
| `kernel::arch::current::context::switch` | kernel | 92 | 92 | 74 | 74 |
| `kernel::syscall::dispatch` | kernel | 72 | 92 | 70 | 28 |
| `kernel::syscall::ipc::sys_notification_wait` | kernel | 80 | 60 | 92 | 91 |
| `kernel::syscall::ipc::sys_notification_send` | kernel | 78 | 68 | 80 | 68 |
| `kernel::syscall::dispatch_in_range` | kernel | 76 | 78 | 60 | 62 |
| `kernel::syscall::finish_syscall_work` | kernel | 34 | 40 | 36 | 72 |
| `kernel::ipc::notification::notification_send` | kernel | 60 | 43 | 68 | 52 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 68 | 48 | 68 | 68 |
| `kernel::sched::run_return_work::<kernel::syscall::finish_syscall_work::{closure#0}, kernel::syscall::finish_syscall_work::{closure#1}>` | kernel | 42 | 12 | 57 | 3 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 54 | 48 | 29 | 26 |
| `kernel::ipc::upcall::deliver` | kernel | 14 | | 54 | 44 |
| `kernel::sched::enqueue_and_wake` | kernel | 38 | 23 | 52 | 36 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 29 | 33 | 50 | 49 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 30 | 18 | 45 | 20 |
| `kernel::ipc::notification::notification_wait` | kernel | 43 | 21 | 35 | 22 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 24 | 22 | 42 | 8 |
| `<kernel::ipc::WaitQueue>::push` | kernel | 40 | 18 | 32 | 20 |
| `kernel::arch::current::fpu::scrub` | kernel | | | 40 | 39 |
| `kernel::arch::current::fpu::set_frame_units` | kernel | | | 40 | 31 |
| `<kernel::sched::run_queue::RunQueue>::enqueue` | kernel | 37 | 7 | 34 | 8 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 36 | | | |
| `kernel::sched::running_thread_stopped` | kernel | 36 | 22 | 24 | 12 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 18 | 12 | 34 | 35 |
| `<kernel::ipc::WaitQueue>::unlink` | kernel | 34 | 20 | 26 | 16 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | | 34 | 34 |
| `kernel::arch::current::fpu::switch_in_restore` | kernel | 16 | 18 | 33 | 31 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 32 | 12 | 24 | 24 |
| `kernel::arch::current::speculation::index_mask` | kernel | 32 | 32 | 32 | 32 |
| `seraph_enter_from_user` | kernel | 32 | 32 | | |
| `<kernel::sched::run_queue::RunQueue>::dequeue` | kernel | 30 | 22 | 26 | 20 |
| `kernel::percpu::take_return_work` | kernel | 30 | 18 | 18 | 9 |
| `kernel::cap::object::release_ref` | kernel | 28 | | 28 | |
| `kernel::sched::mark_dispatched` | kernel | 28 | 14 | 26 | 16 |
| `kernel::sched::run_queue::queue_index` | kernel | 26 | 24 | 17 | 17 |
| `kernel::syscall::finish_syscall_work::{closure#1}` | kernel | 26 | 10 | 24 | 12 |
| `kernel::arch::current::cpu::read_percpu_ptr::<kernel::sched::thread::ThreadControlBlock, 104>` | kernel | 24 | 24 | 24 | 24 |
| `kernel::cap::object::reclaim_deferred_stack` | kernel | 14 | 6 | 24 | 6 |
| `kernel::percpu::current_scheduler` | kernel | 24 | | 18 | |
| `kernel::percpu::per_cpu_ptr` | kernel | 24 | 8 | 18 | |
| `kernel::sched::last_non_idle_tick` | kernel | 24 | 12 | 22 | 10 |
| `kernel::syscall::stamp_syscall_entry` | kernel | 24 | 16 | 20 | 8 |
| `kernel::arch::current::gdt::load_iopb` | kernel | 22 | 5 | | |
| `kernel::syscall::leave_syscall` | kernel | 22 | 14 | 20 | 12 |
| `kernel::syscall::lookup_cap::<kernel::cap::slot::NotificationCap>` | kernel | 14 | 14 | 22 | 22 |
| `<kernel::sched::run_queue::PerCpuScheduler>::idle` | kernel | 19 | 15 | 21 | 17 |
| `<kernel::sched::run_queue::RunQueue>::enqueue_head` | kernel | 21 | 10 | 18 | 10 |
| `<kernel::cap::object::KernelObjectHeader>::dec_ref_in` | kernel | 12 | 12 | 20 | 14 |
| `<kernel::cap::object::KernelObjectHeader>::inc_ref` | kernel | 20 | 4 | 8 | 12 |
| `<kernel::cap::slot::Rights>::contains` | kernel | 20 | 20 | 12 | 12 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 16 | 16 | 20 | 20 |
| `kernel::sched::requeue_local` | kernel | 3 | 19 | 3 | 13 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 8 | 18 | 8 | 4 |
| `<kernel::syscall::PinnedCap as core::ops::drop::Drop>::drop` | kernel | 13 | | 18 | |
| `kernel::arch::current::fpu::switch_out_save` | kernel | 14 | 14 | 18 | 18 |
| `kernel::ipc::upcall::deliver_at_syscall` | kernel | 18 | 10 | 18 | 12 |
| `kernel::ipc::upcall::take` | kernel | 18 | 6 | 10 | 6 |
| 102 functions below 18 each |  | 538 | 361 | 539 | 394 |

#### `ktest.cap_create_delete cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 186 | 186 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 114 | 84 | 138 | 124 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 124 | 124 | | |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 83 | 48 | 109 | 70 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 88 | 33 | 66 | 66 |
| `kernel::syscall::cap::sys_cap_delete` | kernel | 59 | 36 | 79 | 60 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 64 | 76 |
| `kernel::cap::retype::retype_allocate` | kernel | 57 | 33 | 70 | 36 |
| `memset` | kernel | 37 | 37 | 70 | 70 |
| `kernel::cap::object::dealloc_object_one` | kernel | 60 | 33 | 69 | 40 |
| `kernel::syscall::cap::sys_cap_create_notification` | kernel | 64 | 42 | 68 | 68 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 44 | 44 | 55 | 55 |
| `<kernel::cap::registry::CSpaceRegistry>::entry` | kernel | 54 | 19 | 48 | 23 |
| `<kernel::cap::registry::CSpaceRegistry>::slot` | kernel | 36 | 29 | 33 | 53 |
| `kernel::syscall::pin_checked` | kernel | 42 | 13 | 52 | 45 |
| `kernel::cap::retype::retype_free` | kernel | 41 | 24 | 50 | 35 |
| `<kernel::cap::registry::CSpaceRegistry>::lookup` | kernel | 39 | 18 | 48 | 16 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | | 48 | 38 |
| `kernel::syscall::dispatch` | kernel | 36 | 46 | 34 | 14 |
| `kernel::cap::derivation::unlink_node` | kernel | 37 | 23 | 42 | 45 |
| `<kernel::cap::cspace::CSpace>::pop_free_slot` | kernel | 37 | 42 | 41 | 41 |
| `<kernel::cap::cspace::CSpace>::free_slot` | kernel | 36 | 33 | 36 | 41 |
| `kernel::arch::current::speculation::index_mask` | kernel | 41 | 41 | 41 | 41 |
| `kernel::cap::derivation::reparent_children` | kernel | 27 | 21 | 40 | 32 |
| `kernel::syscall::dispatch_in_range` | kernel | 40 | 40 | 30 | 30 |
| `<kernel::cap::cspace::CSpace>::insert_cap` | kernel | 30 | 3 | 33 | 4 |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>` | kernel | | | 22 | 33 |
| `kernel::cap::object::dealloc_object::{closure#0}` | kernel | 1 | 17 | 3 | 31 |
| `kernel::ipc::interrupt_all_waiters` | kernel | 18 | 16 | 31 | 30 |
| `kernel::sched::check_lock_hold_preemptible` | kernel | 20 | 10 | 30 | 10 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 29 | 27 | 24 | 22 |
| `<kernel::cap::object::MemoryObject>::read_lock` | kernel | 18 | 21 | 24 | 28 |
| `<kernel::cap::slot::SlotId>::with_epoch` | kernel | 3 | 9 | 3 | 27 |
| `kernel::arch::current::cpu::read_percpu_ptr::<kernel::sched::thread::ThreadControlBlock, 104>` | kernel | 12 | 27 | 11 | 12 |
| `<kernel::cap::derivation::DerivationLock>::write_lock` | kernel | 20 | 11 | 25 | 13 |
| `kernel::cap::derivation::resolve_slot_mut` | kernel | 11 | 23 | 11 | 7 |
| `<kernel::cap::retype::FreedClear>::clear` | kernel | 19 | 22 | 17 | 19 |
| `<kernel::cap::retype::RetypeAllocator>::lock` | kernel | 14 | 15 | 20 | 22 |
| `<kernel::cap::slot::CapTag as core::cmp::PartialEq>::eq` | kernel | 22 | 9 | 16 | 7 |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>::{closure#0}` | kernel | 11 | 22 | 11 | |
| `<kernel::cap::cspace::CSpace>::insert_cap_handle` | kernel | 3 | 2 | 20 | 1 |
| `kernel::cap::retype::round_to_class` | kernel | 11 | 20 | 10 | 17 |
| `kernel::syscall::cap::resolve_delete_target` | kernel | 14 | 20 | 8 | 10 |
| `<kernel::cap::object::KernelObjectHeader>::dec_ref_in` | kernel | 11 | 8 | 19 | 12 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 12 | 11 | 17 | 19 |
| `<kernel::cap::object::MemoryReadGuard>::acquire` | kernel | 10 | | 18 | |
| `kernel::arch::current::cpu::read_rflags` | kernel | 18 | | | |
| `kernel::cap::retype::credit_freed` | kernel | 14 | 10 | 18 | 15 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 17 | 9 | 17 | 17 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 16 | 8 | 14 | 9 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 16 | 15 | 10 | 9 |
| `seraph_enter_from_user` | kernel | 16 | 16 | | |
| `kernel::arch::current::interrupts::are_enabled` | kernel | 15 | 15 | 10 | 10 |
| `<kernel::cap::cspace::CSpace>::fill_slot` | kernel | 11 | 14 | 8 | 9 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 7 | 6 | 13 | 13 |
| `<kernel::cap::slot::CapabilitySlot>::is_on_free_list` | kernel | 9 | 1 | 12 | 1 |
| `<kernel::mm::frame_map::FrameMap>::slot` | kernel | 12 | 8 | 11 | 10 |
| `kernel::mm::frame_map::frames_of` | kernel | 10 | 10 | 11 | 12 |
| `kernel::syscall::leave_syscall` | kernel | 10 | 6 | 12 | 6 |
| `kernel::syscall::stamp_syscall_entry` | kernel | 12 | 8 | 10 | 4 |
| `<kernel::cap::object::MemoryObject>::read_unlock` | kernel | 2 | 9 | 6 | 11 |
| `kernel::sched::holder_info` | kernel | 11 | 8 | 11 | 7 |
| `syscall::arch::current::syscall2` | ktest | 7 | 7 | 7 | 11 |
| 80 functions below 11 each |  | 240 | 155 | 262 | 171 |

#### `ktest.cap_info_lookup cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 93 | 93 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 62 | 62 | | |
| `kernel::syscall::pin_checked` | kernel | 42 | 11 | 52 | 45 |
| `kernel::syscall::cap::sys_cap_info` | kernel | 45 | 34 | 44 | 42 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 32 | 38 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 20 | 12 | 25 | 25 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | | 24 | 19 |
| `kernel::syscall::dispatch` | kernel | 18 | 23 | 17 | 7 |
| `kernel::syscall::dispatch_in_range` | kernel | 19 | 19 | 15 | 15 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 17 | 8 | 17 | 17 |
| `kernel::arch::current::speculation::index_mask` | kernel | 11 | 11 | 14 | 14 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 2 | 9 | 2 | 2 |
| `<kernel::syscall::UserFrame>::arg` | kernel | 9 | | 2 | |
| `kernel::arch::current::cpu::read_rflags` | kernel | 9 | | | |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 8 | 3 | 6 | 6 |
| `kernel::syscall::pin_slot` | kernel | 5 | | 8 | 8 |
| `seraph_enter_from_user` | kernel | 8 | 8 | | |
| `kernel::cap::object::release_ref` | kernel | 7 | | 7 | |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 6 | 6 | 4 | 4 |
| `kernel::syscall::leave_syscall` | kernel | 5 | 3 | 6 | 3 |
| `kernel::syscall::stamp_syscall_entry` | kernel | 6 | 4 | 5 | 2 |
| `<bench::counters::Counters>::read` | ktest | 6 | | 6 | |
| `syscall::arch::current::syscall4` | ktest | 6 | 6 | 2 | 2 |
| `<kernel::cap::object::KernelObjectHeader>::dec_ref_in` | kernel | 3 | 3 | 5 | 4 |
| `<kernel::cap::object::KernelObjectHeader>::inc_ref` | kernel | 5 | 1 | 2 | 3 |
| `<kernel::cap::slot::Rights>::contains` | kernel | 5 | | 3 | 3 |
| `kernel::arch::current::cpu::read_percpu_ptr::<kernel::sched::thread::ThreadControlBlock, 104>` | kernel | 5 | 5 | 5 | 5 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 4 | 4 | 5 | 5 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 4 | 3 | 2 | 2 |
| `kernel::arch::nospec::mask_index` | kernel | 2 | 2 | 4 | 4 |
| `kernel::sched::this_cpu_diag` | kernel | 4 | | 3 | |
| `bench::arch::current::cycles` | ktest | 4 | 3 | 1 | 1 |
| `<kernel::cap::slot::CapTag as core::cmp::PartialEq>::eq` | kernel | 3 | 3 | 2 | 2 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 2 | 1 | 3 | 3 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 2 | 3 | 3 | 3 |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>` | kernel | | | 2 | 3 |
| `kernel::cap::object::references_in` | kernel | | | 3 | |
| 16 functions below 3 each |  | 19 | 13 | 20 | 12 |

#### `ktest.mem_map_unmap cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::syscall::pin_checked` | kernel | 168 | 114 | 208 | 180 |
| `kernel::syscall::mem::sys_mem_map` | kernel | 191 | 168 | 158 | 172 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 186 | 186 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 124 | 124 | | |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 80 | 48 | 100 | 100 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | | 98 | 90 |
| `kernel::syscall::mem::sys_mem_unmap` | kernel | 59 | 44 | 60 | 82 |
| `kernel::arch::current::paging::read_entry` | kernel | 80 | 21 | | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 64 | 76 |
| `boot_protocol::x86_paging::table_index` | kernel | 69 | 39 | | |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 68 | 45 | 68 | 68 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 64 | 32 | 56 | 42 |
| `kernel::arch::current::paging::descend_existing::<kernel::mm::paging::phys_to_virt>` | kernel | 14 | 3 | 60 | 31 |
| `kernel::arch::current::paging::entry` | kernel | 3 | 3 | 53 | 50 |
| `<kernel::mm::address_space::AddressSpace>::map_page_pooled` | kernel | 42 | 19 | 48 | 42 |
| `<kernel::mm::frame_map::FrameMap>::slot` | kernel | 48 | 25 | 44 | 22 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | | 48 | 38 |
| `kernel::arch::current::paging::table_at` | kernel | 35 | | 48 | |
| `boot_protocol::x86_paging::level_shift` | kernel | 47 | 45 | | |
| `kernel::syscall::dispatch` | kernel | 36 | 46 | 34 | 14 |
| `kernel::arch::current::paging::names_table` | kernel | 22 | 45 | | |
| `kernel::mm::tlb_shootdown::shootdown_range` | kernel | 23 | 26 | 32 | 40 |
| `kernel::syscall::dispatch_in_range` | kernel | 40 | 40 | 30 | 30 |
| `kernel::arch::current::paging::map_user_page_pooled` | kernel | 20 | 6 | 39 | 8 |
| `kernel::arch::current::paging::install_user_leaf` | kernel | | | 12 | 38 |
| `kernel::arch::current::speculation::index_mask` | kernel | 36 | 37 | 37 | 37 |
| `boot_protocol::riscv_paging::vpn_index` | kernel | | | 36 | 24 |
| `kernel::arch::current::paging::walk_to_4k_leaf::<kernel::mm::paging::phys_to_virt>` | kernel | 34 | 23 | | |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 32 | 12 | 24 | 24 |
| `<kernel::mm::frame_map::FrameMap>::lower` | kernel | 21 | 9 | 29 | 18 |
| `kernel::cap::object::release_ref` | kernel | 28 | 3 | 28 | 3 |
| `<kernel::mm::frame_map::FrameMap>::raise` | kernel | 21 | 9 | 27 | 17 |
| `kernel::arch::current::paging::translate_user_page` | kernel | 27 | 6 | 14 | 3 |
| `<kernel::arch::current::paging::PageTableEntry>::phys_addr` | kernel | 16 | 15 | 25 | 25 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 24 | 24 | 16 | 16 |
| `<kernel::mm::address_space::AddressSpace>::unmap_page` | kernel | 23 | 3 | 21 | 4 |
| `<kernel::syscall::mem::FramePins as core::ops::drop::Drop>::drop` | kernel | 22 | 20 | 21 | 19 |
| `<kernel::cap::slot::Rights>::contains` | kernel | 21 | 11 | 13 | 13 |
| `core::ptr::drop_glue::<kernel::syscall::PinnedCap>` | kernel | | 12 | | 21 |
| `<boot_protocol::riscv_paging::PagingMode>::levels` | kernel | | | 4 | 20 |
| `<kernel::arch::current::paging::PageTableEntry>::new_page` | kernel | 17 | 11 | 20 | 12 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 6 | 20 | 2 | 2 |
| `<kernel::cap::object::KernelObjectHeader>::dec_ref_in` | kernel | 12 | 12 | 20 | 17 |
| `<kernel::cap::object::KernelObjectHeader>::inc_ref` | kernel | 20 | 4 | 8 | 12 |
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 6 | 6 | 20 | 16 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 16 | 16 | 20 | 20 |
| `<kernel::arch::current::paging::PageTableEntry>::is_present` | kernel | 18 | 9 | 9 | 5 |
| `<kernel::syscall::PinnedCap as core::ops::drop::Drop>::drop` | kernel | 13 | 18 | 17 | 3 |
| `<kernel::syscall::mem::FramePins>::pin` | kernel | 17 | 15 | 18 | 15 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 18 | | | |
| `kernel::arch::current::paging::descend_alloc::<kernel::arch::current::paging::map_user_page_pooled::{closure#0}>` | kernel | 14 | 6 | 18 | 6 |
| `kernel::arch::current::paging::root_level` | kernel | 11 | 18 | 2 | |
| `core::ptr::drop_glue::<kernel::syscall::mem::FramePins>` | kernel | 6 | 4 | 15 | 17 |
| `kernel::mm::user_page_range` | kernel | 16 | 17 | 10 | 10 |
| `kernel::percpu::preempt_enable` | kernel | 17 | 2 | 14 | 8 |
| `<boot_protocol::x86_paging::PagingDepth>::from_levels` | kernel | 16 | | | |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 16 | 14 | 8 | 8 |
| `kernel::arch::nospec::mask_span_u64` | kernel | 16 | 16 | 12 | 12 |
| `kernel::syscall::mem::map_permissions` | kernel | 16 | 16 | 8 | 8 |
| `seraph_enter_from_user` | kernel | 16 | 16 | | |
| `<kernel::cap::object::MemoryObject>::read_lock` | kernel | 9 | 13 | 12 | 15 |
| `<kernel::cpu_mask::MaskSource>::word_except` | kernel | 15 | 14 | 15 | 14 |
| `kernel::arch::current::paging::unmap_user_page` | kernel | 7 | 3 | 15 | 3 |
| `kernel::arch::current::paging::user_va_top` | kernel | 15 | 15 | 10 | 12 |
| `kernel::syscall::lookup_cap::<kernel::cap::slot::MemoryCap>` | kernel | 8 | 5 | 14 | 14 |
| `kernel::percpu::preempt_disable` | kernel | 12 | 4 | 13 | 6 |
| `kernel::syscall::lookup_cap::<kernel::cap::slot::AddressSpaceCap>` | kernel | 7 | 5 | 13 | 13 |
| `<boot_protocol::riscv_paging::PagingMode>::from_satp_mode` | kernel | | | 12 | |
| `<kernel::cap::slot::CapTag as core::cmp::PartialEq>::eq` | kernel | 12 | 8 | 8 | 8 |
| `<kernel::cpu_mask::AtomicCpuMask>::fill_would_be_nonempty` | kernel | 12 | 9 | 9 | 6 |
| `<kernel::cpu_mask::AtomicCpuMask>::words` | kernel | 12 | 2 | 8 | 3 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 8 | 6 | 12 | 12 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 8 | 8 | 12 | 12 |
| `kernel::arch::current::paging::direct_map_base` | kernel | 12 | 12 | 12 | 12 |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>` | kernel | | | 8 | 12 |
| `kernel::cap::object::references_in` | kernel | | | 12 | |
| `kernel::mm::check_user_base` | kernel | 10 | 10 | 12 | 12 |
| `kernel::mm::paging::phys_to_virt` | kernel | 12 | 12 | 12 | 12 |
| `kernel::syscall::leave_syscall` | kernel | 10 | 6 | 12 | 6 |
| `kernel::syscall::stamp_syscall_entry` | kernel | 12 | 8 | 10 | 4 |
| 63 functions below 12 each |  | 222 | 189 | 233 | 186 |

#### `ktest.mem_protect_pair cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::syscall::mem::sys_mem_protect` | kernel | 192 | 178 | 172 | 215 |
| `kernel::syscall::pin_checked` | kernel | 168 | 168 | 208 | 180 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 186 | 186 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 124 | 124 | | |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 80 | 48 | 100 | 100 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 64 | 76 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 68 | 48 | 68 | 68 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | | 48 | 48 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | | 48 | 38 |
| `kernel::arch::current::paging::protect_user_page` | kernel | 31 | 16 | 46 | 6 |
| `kernel::syscall::dispatch` | kernel | 36 | 46 | 34 | 14 |
| `kernel::arch::current::speculation::index_mask` | kernel | 42 | 40 | 36 | 36 |
| `kernel::syscall::dispatch_in_range` | kernel | 42 | 42 | 30 | 30 |
| `<kernel::mm::address_space::AddressSpace>::protect_page` | kernel | 30 | 2 | 40 | 6 |
| `boot_protocol::x86_paging::table_index` | kernel | 40 | 30 | | |
| `kernel::arch::current::paging::descend_existing::<kernel::mm::paging::phys_to_virt>` | kernel | 28 | 6 | 40 | 20 |
| `kernel::mm::tlb_shootdown::shootdown_range` | kernel | 23 | 26 | 32 | 40 |
| `kernel::arch::current::paging::entry` | kernel | 6 | 6 | 30 | 36 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 32 | 12 | 24 | 24 |
| `kernel::arch::current::paging::table_at` | kernel | 32 | | 24 | |
| `boot_protocol::x86_paging::level_shift` | kernel | 28 | 30 | | |
| `kernel::arch::current::paging::names_table` | kernel | 20 | 30 | | |
| `core::ptr::drop_glue::<kernel::syscall::PinnedCap>` | kernel | | 16 | | 28 |
| `kernel::cap::object::release_ref` | kernel | 28 | | 28 | |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 24 | 24 | 16 | 16 |
| `<kernel::syscall::PinnedCap as core::ops::drop::Drop>::drop` | kernel | 14 | 24 | 18 | 4 |
| `kernel::arch::current::encoding::protected_leaf` | kernel | | | 24 | 14 |
| `kernel::arch::current::paging::map_rights_superset` | kernel | 13 | 13 | 24 | 5 |
| `kernel::arch::current::paging::protected_leaf` | kernel | 21 | 16 | | |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 6 | 20 | 2 | 2 |
| `<kernel::cap::object::KernelObjectHeader>::dec_ref_in` | kernel | 12 | 12 | 20 | 16 |
| `<kernel::cap::object::KernelObjectHeader>::inc_ref` | kernel | 20 | 4 | 8 | 12 |
| `<kernel::cap::slot::Rights>::contains` | kernel | 20 | 20 | 12 | 12 |
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 6 | 6 | 20 | 8 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 16 | 16 | 20 | 20 |
| `boot_protocol::riscv_paging::vpn_index` | kernel | | | 18 | 12 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 18 | | | |
| `kernel::mm::user_page_range` | kernel | 16 | 18 | 10 | 10 |
| `kernel::percpu::preempt_enable` | kernel | 18 | 2 | 16 | 6 |
| `<kernel::arch::current::paging::PageTableEntry>::new_page` | kernel | 16 | 8 | 16 | |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 16 | 12 | 8 | 8 |
| `seraph_enter_from_user` | kernel | 16 | 16 | | |
| `<kernel::cpu_mask::MaskSource>::word_except` | kernel | 15 | 14 | 15 | 14 |
| `<kernel::arch::current::paging::PageTableEntry>::is_present` | kernel | 14 | 8 | 6 | 2 |
| `<kernel::arch::current::paging::PageTableEntry>::phys_addr` | kernel | 10 | 12 | 14 | 12 |
| `<kernel::mm::paging::LeafGrant>::admits` | kernel | 14 | 6 | | |
| `kernel::percpu::preempt_disable` | kernel | 12 | 2 | 14 | 6 |
| `kernel::syscall::lookup_cap::<kernel::cap::slot::AddressSpaceCap>` | kernel | 10 | 10 | 14 | 14 |
| `syscall::arch::current::syscall5` | ktest | 13 | 13 | 14 | 13 |
| `kernel::mm::tlb_shootdown::shootdown` | kernel | 3 | 4 | 6 | 13 |
| `<kernel::cap::slot::CapTag as core::cmp::PartialEq>::eq` | kernel | 12 | 4 | 8 | 8 |
| `<kernel::cpu_mask::AtomicCpuMask>::fill_would_be_nonempty` | kernel | 12 | 9 | 9 | 6 |
| `<kernel::cpu_mask::AtomicCpuMask>::words` | kernel | 12 | 2 | 8 | 3 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 8 | 4 | 12 | 12 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 8 | 8 | 12 | 12 |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>` | kernel | | | 8 | 12 |
| `kernel::cap::object::references_in` | kernel | | | 12 | |
| `kernel::mm::check_user_base` | kernel | 10 | 10 | 12 | 12 |
| `kernel::syscall::leave_syscall` | kernel | 10 | 6 | 12 | 6 |
| `kernel::syscall::lookup_cap::<kernel::cap::slot::MemoryCap>` | kernel | 10 | 10 | 12 | 12 |
| `kernel::syscall::stamp_syscall_entry` | kernel | 12 | 8 | 10 | 4 |
| `<kernel::cpu_mask::MaskSource>::word_except::{closure#0}` | kernel | 6 | 6 | 10 | 10 |
| `<kernel::mm::address_space::AddressSpace>::shootdown_remote` | kernel | 6 | 5 | 10 | 9 |
| `kernel::arch::current::paging::classify_user_map` | kernel | 8 | 8 | 10 | |
| `kernel::arch::current::paging::user_leaf_grant` | kernel | 6 | 10 | | |
| `kernel::arch::current::paging::user_va_top` | kernel | 6 | 6 | 8 | 10 |
| `kernel::syscall::held_rights_mask` | kernel | 10 | 10 | 6 | 6 |
| 47 functions below 9 each |  | 166 | 121 | 155 | 115 |

#### `ktest.aspace_harvest_all_accessed pages=32 cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `<kernel::mm::address_space::AddressSpace>::read_accessed::{closure#0}` | kernel | 352 | 352 | 512 | 544 |
| `kernel::mm::address_space::harvest_bit` | kernel | 416 | 416 | 288 | 224 |
| `kernel::arch::current::paging::walk_leaf_tables::<kernel::arch::current::paging::clear_user_accessed<<kernel::mm::address_space::AddressSpace>::clear_accessed::{closure#0}>::{closure#0}>` | kernel | | | 347 | 283 |
| `kernel::arch::current::paging::walk_leaf_tables::<kernel::arch::current::paging::read_user_accessed<<kernel::mm::address_space::AddressSpace>::read_accessed::{closure#0}>::{closure#0}>` | kernel | | | 323 | 283 |
| `kernel::arch::current::paging::walk_leaf_slots::<kernel::arch::current::paging::read_user_accessed<<kernel::mm::address_space::AddressSpace>::read_accessed::{closure#0}>::{closure#0}>` | kernel | 304 | 271 | | |
| `kernel::arch::current::paging::walk_leaf_slots::<kernel::arch::current::paging::clear_user_accessed<<kernel::mm::address_space::AddressSpace>::clear_accessed::{closure#0}>::{closure#0}>` | kernel | 303 | 270 | | |
| `kernel::arch::current::paging::clear_user_accessed::<<kernel::mm::address_space::AddressSpace>::clear_accessed::{closure#0}>::{closure#0}` | kernel | 224 | 224 | 64 | 128 |
| `boot_protocol::x86_paging::table_index` | kernel | 222 | 198 | | |
| `memset` | kernel | 85 | 85 | 214 | 214 |
| `<kernel::mm::address_space::AddressSpace>::clear_accessed::{closure#0}` | kernel | 64 | 64 | 192 | 160 |
| `<kernel::mm::address_space::AddressSpace>::clear_accessed::{closure#0}::{closure#0}` | kernel | 64 | 64 | 160 | 192 |
| `<kernel::arch::current::paging::PageTableEntry>::is_present` | kernel | 70 | 70 | 160 | 96 |
| `kernel::arch::current::paging::entry` | kernel | 6 | 6 | 146 | 146 |
| `kernel::arch::current::paging::read_user_accessed::<<kernel::mm::address_space::AddressSpace>::read_accessed::{closure#0}>::{closure#0}` | kernel | 128 | 128 | 96 | 128 |
| `kernel::arch::current::paging::entry_mut` | kernel | | | 96 | 96 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 93 | 93 |
| `kernel::syscall::mem::sys_aspace_harvest` | kernel | 72 | 62 | 74 | 71 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 62 | 62 | | |
| `boot_protocol::riscv_paging::level_shift` | kernel | | | 60 | |
| `kernel::syscall::pin_checked` | kernel | 42 | 42 | 52 | 45 |
| `boot_protocol::x86_paging::level_shift` | kernel | 48 | | | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 32 | 38 |
| `boot_protocol::x86_paging::next_level_boundary` | kernel | 36 | 30 | | |
| `kernel::arch::current::paging::names_table` | kernel | 30 | 34 | | |
| `kernel::arch::current::paging::table_at` | kernel | 32 | | 12 | |
| `boot_protocol::riscv_paging::next_level_boundary` | kernel | | | 30 | 30 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 20 | 12 | 25 | 25 |
| `__copy_user_words` | kernel | | | 25 | 25 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | | 24 | 19 |
| `kernel::syscall::dispatch` | kernel | 18 | 23 | 17 | 7 |
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 6 | 6 | 20 | 18 |
| `<kernel::mm::address_space::AddressSpace>::read_accessed` | kernel | 16 | 17 | 18 | 19 |
| `kernel::syscall::dispatch_in_range` | kernel | 18 | 18 | 11 | 11 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 17 | 12 | 17 | 17 |
| `kernel::percpu::preempt_enable` | kernel | 16 | 2 | 14 | 6 |
| 74 functions below 16 each |  | 286 | 217 | 274 | 222 |

#### `ktest.aspace_harvest_none_accessed pages=32 cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::arch::current::paging::walk_leaf_tables::<kernel::arch::current::paging::clear_user_accessed<<kernel::mm::address_space::AddressSpace>::clear_accessed::{closure#0}>::{closure#0}>` | kernel | | | 347 | 283 |
| `kernel::arch::current::paging::walk_leaf_tables::<kernel::arch::current::paging::read_user_accessed<<kernel::mm::address_space::AddressSpace>::read_accessed::{closure#0}>::{closure#0}>` | kernel | | | 323 | 283 |
| `kernel::arch::current::paging::walk_leaf_slots::<kernel::arch::current::paging::read_user_accessed<<kernel::mm::address_space::AddressSpace>::read_accessed::{closure#0}>::{closure#0}>` | kernel | 304 | 271 | | |
| `kernel::arch::current::paging::walk_leaf_slots::<kernel::arch::current::paging::clear_user_accessed<<kernel::mm::address_space::AddressSpace>::clear_accessed::{closure#0}>::{closure#0}>` | kernel | 303 | 270 | | |
| `boot_protocol::x86_paging::table_index` | kernel | 222 | 198 | | |
| `memset` | kernel | 85 | 85 | 214 | 214 |
| `<kernel::mm::address_space::AddressSpace>::clear_accessed::{closure#0}` | kernel | 64 | 64 | 192 | 160 |
| `<kernel::mm::address_space::AddressSpace>::clear_accessed::{closure#0}::{closure#0}` | kernel | 64 | 64 | 160 | 192 |
| `<kernel::arch::current::paging::PageTableEntry>::is_present` | kernel | 70 | 70 | 160 | 96 |
| `kernel::arch::current::paging::clear_user_accessed::<<kernel::mm::address_space::AddressSpace>::clear_accessed::{closure#0}>::{closure#0}` | kernel | 160 | 160 | | 64 |
| `kernel::mm::address_space::harvest_bit` | kernel | 160 | 160 | 96 | 64 |
| `kernel::arch::current::paging::entry` | kernel | 6 | 6 | 146 | 146 |
| `kernel::arch::current::paging::read_user_accessed::<<kernel::mm::address_space::AddressSpace>::read_accessed::{closure#0}>::{closure#0}` | kernel | 128 | 128 | 96 | 128 |
| `kernel::arch::current::paging::entry_mut` | kernel | | | 96 | 96 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 93 | 93 |
| `kernel::syscall::mem::sys_aspace_harvest` | kernel | 72 | 62 | 74 | 71 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 62 | 62 | | |
| `boot_protocol::riscv_paging::level_shift` | kernel | | | 60 | |
| `kernel::syscall::pin_checked` | kernel | 42 | 42 | 52 | 45 |
| `boot_protocol::x86_paging::level_shift` | kernel | 48 | | | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 32 | 38 |
| `boot_protocol::x86_paging::next_level_boundary` | kernel | 36 | 30 | | |
| `kernel::arch::current::paging::names_table` | kernel | 30 | 34 | | |
| `kernel::arch::current::paging::table_at` | kernel | 32 | | 12 | |
| `boot_protocol::riscv_paging::next_level_boundary` | kernel | | | 30 | 30 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 20 | 12 | 25 | 25 |
| `__copy_user_words` | kernel | | | 25 | 25 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | | 24 | 19 |
| `kernel::syscall::dispatch` | kernel | 18 | 23 | 17 | 7 |
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 6 | 6 | 20 | 18 |
| `<kernel::mm::address_space::AddressSpace>::read_accessed` | kernel | 16 | 17 | 18 | 19 |
| `kernel::syscall::dispatch_in_range` | kernel | 18 | 18 | 11 | 11 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 17 | 12 | 17 | 17 |
| `kernel::percpu::preempt_enable` | kernel | 16 | 2 | 14 | 6 |
| `<kernel::mm::address_space::AddressSpace>::clear_accessed` | kernel | 12 | 13 | 14 | 15 |
| `kernel::arch::current::speculation::index_mask` | kernel | 14 | 14 | 14 | 14 |
| 72 functions below 13 each |  | 260 | 190 | 246 | 193 |

#### `ktest.thread_lifecycle cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `memset` | kernel | 7139 | 7097 | 21257 | 21257 |
| `kernel::arch::current::cpu::fill_words` | kernel | 2051 | 2051 | 2584 | 2566 |
| `<kernel::cap::cspace::CSpace>::grow` | kernel | 2280 | 1671 | 2350 | 1787 |
| `kernel::stack_depth::lowest_written::<kernel::stack_depth::used_bytes::{closure#0}>` | kernel | 1827 | 1129 | 1218 | 1559 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 1460 | 948 | 1826 | 1720 |
| `kernel::stack_depth::used_bytes::{closure#0}` | kernel | 1624 | | 1567 | 320 |
| `<kernel::cap::registry::CSpaceRegistry>::entry` | kernel | 1386 | 420 | 1232 | 457 |
| `kernel::cap::derivation::resolve_slot_mut` | kernel | 966 | 665 | 1138 | 145 |
| `<kernel::cap::registry::CSpaceRegistry>::slot` | kernel | 924 | 495 | 847 | 478 |
| `<kernel::cap::registry::CSpaceRegistry>::lookup` | kernel | 826 | 594 | 906 | 529 |
| `<kernel::cap::slot::CapabilitySlot>::set_next_free` | kernel | 460 | 460 | 845 | 845 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 816 | 310 | 612 | 612 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 795 | 795 |
| `kernel::syscall::pin_checked` | kernel | 546 | 350 | 676 | 585 |
| `kernel::cap::drain::drain_batch` | kernel | 659 | 650 | 606 | 538 |
| `kernel::cap::cspace::fill_sentinel::<kernel::cap::cspace::CSpacePage, 128>` | kernel | 448 | 176 | 641 | 385 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 443 | 264 | 566 | 477 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 530 | 530 | | |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 408 | 407 | 510 | 510 |
| `kernel::cap::drain::examine` | kernel | 456 | 344 | 455 | 399 |
| `kernel::cap::drain::examine::{closure#0}` | kernel | 448 | | 224 | |
| `kernel::cap::arena::sort_list::<kernel::cap::object::ArenaPage, kernel::cap::object::free_donation_group::{closure#1}, kernel::cap::object::free_donation_group::{closure#2}, kernel::cap::object::free_donation_group::{closure#3}, kernel::cap::object::free_donation_group::{closure#0}>` | kernel | 417 | 392 | 298 | 325 |
| `kernel::arch::current::speculation::index_mask` | kernel | 359 | 359 | 359 | 359 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 272 | 321 |
| `<kernel::cap::slot::CapTag as core::cmp::PartialEq>::eq` | kernel | 320 | 223 | 238 | 160 |
| `kernel::cap::cspace::fill_sentinel::<kernel::cap::cspace::DirPage<kernel::cap::cspace::CSpacePage>, 64>` | kernel | 224 | 88 | 320 | 194 |
| `kernel::cap::cspace::fill_sentinel::<kernel::cap::cspace::DirPage<kernel::cap::cspace::DirPage<kernel::cap::cspace::CSpacePage>>, 63>` | kernel | 256 | 90 | 315 | 191 |
| `kernel::stack_depth::lowest_written::<kernel::stack_depth::used_bytes::{closure#0}>::{closure#0}` | kernel | 245 | 312 | | |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 311 | 299 | 235 | 224 |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>` | kernel | | | 204 | 306 |
| `<kernel::cap::cspace::CSpace>::for_each_object_by_leaf::<kernel::cap::object::dealloc_object_one::{closure#5}, kernel::cap::object::dealloc_object_one::{closure#4}>` | kernel | 271 | 263 | 295 | 284 |
| 481 functions below 273 each |  | 10749 | 7825 | 11368 | 8122 |

#### `ktest.context_switch_pair cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::sched::schedule` | kernel | 296 | 202 | 298 | 264 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 186 | 186 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 124 | 124 | | |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 114 | 16 | 112 | 24 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 40 | 24 | 102 | 82 |
| `kernel::arch::current::context::switch` | kernel | 92 | 92 | 74 | 74 |
| `<kernel::sched::run_queue::RunQueue>::enqueue` | kernel | 82 | 18 | 76 | 20 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 64 | 76 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | | 48 | 38 |
| `kernel::syscall::dispatch` | kernel | 36 | 46 | 34 | 14 |
| `kernel::arch::current::fpu::scrub` | kernel | | | 40 | 39 |
| `kernel::arch::current::fpu::set_frame_units` | kernel | | | 40 | 31 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 36 | 36 | 24 | 24 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | | 34 | 34 |
| `kernel::arch::current::fpu::switch_in_restore` | kernel | 16 | 18 | 33 | 31 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 22 | 20 | 32 | 4 |
| `kernel::sched::run_queue::queue_index` | kernel | 32 | 30 | 22 | 22 |
| `kernel::sched::requeue_local` | kernel | 6 | 30 | 6 | 14 |
| `kernel::syscall::dispatch_in_range` | kernel | 30 | 30 | 20 | 22 |
| `<kernel::sched::run_queue::RunQueue>::dequeue` | kernel | 28 | 20 | 24 | 18 |
| `kernel::sched::mark_dispatched` | kernel | 28 | 14 | 26 | 16 |
| `kernel::percpu::per_cpu_ptr` | kernel | 24 | 8 | 18 | |
| `kernel::sched::last_non_idle_tick` | kernel | 24 | 12 | 22 | 10 |
| `kernel::arch::current::gdt::load_iopb` | kernel | 22 | 5 | | |
| `<kernel::sched::Outgoing>::owned_by_another_cpu` | kernel | 20 | 20 | 12 | 6 |
| `<kernel::sched::run_queue::PerCpuScheduler>::idle` | kernel | 18 | 14 | 20 | 16 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 18 | | | |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 18 | 18 | 10 | 8 |
| `kernel::arch::current::fpu::switch_out_save` | kernel | 14 | 14 | 18 | 18 |
| `kernel::arch::current::fpu::restore_v_from` | kernel | | | 17 | 17 |
| `seraph_enter_from_user` | kernel | 16 | 16 | | |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 8 | 12 | 14 | 14 |
| `kernel::ipc::upcall::return_work_of` | kernel | 14 | 8 | 10 | 6 |
| `kernel::sched::run_queue::queues_above` | kernel | 14 | 12 | 12 | 12 |
| `kernel::arch::current::gdt::current_tss` | kernel | 12 | 2 | | |
| `kernel::syscall::leave_syscall` | kernel | 10 | 6 | 12 | 6 |
| `kernel::syscall::stamp_syscall_entry` | kernel | 12 | 8 | 10 | 4 |
| `<kernel::sched::Outgoing>::requeue` | kernel | 10 | 10 | 6 | 6 |
| `<kernel::sched::run_queue::PerCpuScheduler>::enqueue` | kernel | 8 | | 10 | |
| `<kernel::sync::Spinlock>::release_lock_only` | kernel | 4 | 4 | 10 | 10 |
| `__x86_indirect_thunk_r11` | kernel | 10 | 10 | | |
| `kernel::percpu::set_current_thread` | kernel | 10 | 2 | 8 | 2 |
| `kernel::sched::watchdog_mark_non_idle` | kernel | 6 | 4 | 6 | 10 |
| `kernel::arch::current::fpu::make_live` | kernel | | | 9 | 4 |
| `<kernel::sched::fpu_switch::Owner>::of::<kernel::sched::thread::ThreadControlBlock>` | kernel | 8 | 8 | 2 | 2 |
| `kernel::arch::current::fpu::restore_from` | kernel | 8 | 6 | | |
| `kernel::arch::current::fpu::save_to` | kernel | 8 | 6 | | |
| `kernel::arch::current::fpu::units_off` | kernel | | | 8 | 8 |
| `kernel::arch::current::gdt::set_rsp0` | kernel | 8 | 4 | | |
| `kernel::mm::stack_guard::live::flush_before_run` | kernel | 8 | 4 | 2 | 2 |
| `kernel::percpu::current_scheduler` | kernel | 8 | | 6 | |
| `kernel::percpu::fpu_owner_for` | kernel | 8 | | 4 | |
| `kernel::percpu::guard_epoch_flushed` | kernel | 8 | | 8 | 2 |
| `kernel::sched::this_cpu_diag` | kernel | 8 | | 6 | |
| `syscall::arch::current::syscall2` | ktest | 8 | 8 | 4 | 4 |
| 37 functions below 8 each |  | 98 | 70 | 118 | 89 |

#### `ktest.thread_read_mem_page cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `__copy_user_fault_start` | kernel | 4097 | 4097 | | |
| `compiler_builtins::mem::memcpy` | kernel | | | 2583 | 2581 |
| `__copy_user_block_start` | kernel | | | 1280 | 1280 |
| `memcpy` | kernel | 528 | 528 | 2 | 2 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 93 | 93 |
| `kernel::arch::current::paging::read_entry` | kernel | 80 | 15 | | |
| `<kernel::mm::address_space::AddressSpace>::copy_user_bytes` | kernel | 66 | 34 | 68 | 62 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 62 | 62 | | |
| `kernel::syscall::pin_checked` | kernel | 42 | 42 | 52 | 45 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | | 48 | 48 |
| `kernel::syscall::thread::sys_thread_read_mem` | kernel | 29 | 33 | 44 | 42 |
| `kernel::arch::current::paging::descend_existing::<kernel::mm::paging::phys_to_virt>` | kernel | | | 40 | 23 |
| `kernel::mm::address_space::page_spans::{closure#0}` | kernel | 25 | 38 | 37 | 39 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 32 | 38 |
| `boot_protocol::x86_paging::table_index` | kernel | 34 | 18 | | |
| `kernel::arch::current::paging::walk_to_4k_leaf::<kernel::mm::paging::phys_to_virt>` | kernel | 34 | 22 | | |
| `<kernel::mm::address_space::AddressSpace>::copy_user_bytes::{closure#0}` | kernel | 32 | 6 | 7 | 5 |
| `<kernel::syscall::thread::AspacePin>::of_thread` | kernel | 30 | 27 | 32 | 24 |
| `kernel::arch::current::paging::names_table` | kernel | 12 | 30 | | |
| `kernel::arch::current::paging::translate_user_page` | kernel | 30 | 12 | 12 | 2 |
| `kernel::arch::current::paging::entry` | kernel | | | 28 | 26 |
| 94 functions below 27 each |  | 440 | 307 | 468 | 349 |

#### `ktest.event_post_recv cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 186 | 186 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 124 | 124 | | |
| `kernel::syscall::pin_checked` | kernel | 84 | 84 | 104 | 90 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 64 | 76 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 40 | 24 | 50 | 50 |
| `kernel::syscall::ipc::sys_event_recv` | kernel | 40 | 31 | 49 | 42 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | | 48 | 38 |
| `kernel::ipc::event_queue::event_queue_post` | kernel | 40 | 22 | 47 | 40 |
| `kernel::syscall::dispatch` | kernel | 36 | 46 | 34 | 14 |
| `kernel::syscall::dispatch_in_range` | kernel | 38 | 38 | 30 | 30 |
| `kernel::syscall::ipc::sys_event_post` | kernel | 37 | 27 | 37 | 32 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 34 | 24 | 34 | 34 |
| `kernel::ipc::event_queue::event_queue_recv` | kernel | 5 | | 31 | |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 24 | 24 | 16 | 16 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 5 | 18 | 5 | 5 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 18 | | | |
| `kernel::ipc::event_queue::pop_entry_locked` | kernel | 18 | 13 | 18 | 13 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 14 | 17 | 8 | 7 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 16 | 6 | 12 | 12 |
| `kernel::arch::current::speculation::index_mask` | kernel | 16 | 16 | 16 | 16 |
| `seraph_enter_from_user` | kernel | 16 | 16 | | |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 9 | 9 | 14 | 14 |
| `kernel::cap::object::release_ref` | kernel | 14 | 1 | 14 | |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 6 | 4 | 11 | 12 |
| `kernel::syscall::leave_syscall` | kernel | 10 | 6 | 12 | 6 |
| `kernel::syscall::stamp_syscall_entry` | kernel | 12 | 8 | 10 | 4 |
| `kernel::syscall::lookup_cap::<kernel::cap::slot::EventQueueCap>` | kernel | 6 | 6 | 11 | 11 |
| `<kernel::cap::object::KernelObjectHeader>::dec_ref_in` | kernel | 6 | 7 | 10 | 8 |
| `<kernel::cap::object::KernelObjectHeader>::inc_ref` | kernel | 10 | 2 | 4 | 6 |
| `<kernel::cap::slot::Rights>::contains` | kernel | 10 | 10 | 6 | 6 |
| `kernel::arch::current::cpu::read_percpu_ptr::<kernel::sched::thread::ThreadControlBlock, 104>` | kernel | 10 | 10 | 9 | 9 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 8 | 8 | 10 | 10 |
| `kernel::ipc::event_queue::ring_step` | kernel | 10 | 9 | 5 | 6 |
| `kernel::sched::this_cpu_diag` | kernel | 8 | | 6 | |
| `<kernel::cap::slot::CapTag as core::cmp::PartialEq>::eq` | kernel | 6 | 2 | 4 | 4 |
| `<kernel::syscall::PinnedCap as core::ops::drop::Drop>::drop` | kernel | 4 | | 6 | |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>` | kernel | | | 4 | 6 |
| `kernel::cap::object::references_in` | kernel | | | 6 | |
| `<bench::counters::Counters>::read` | ktest | 6 | | 6 | |
| `ktest::bench::event::bench_event_post_recv` | ktest | | 6 | | 4 |
| `syscall::arch::current::syscall3` | ktest | 5 | 5 | 5 | 6 |
| `syscall::arch::current::syscall2_ret3` | ktest | 4 | 5 | 4 | 4 |
| 24 functions below 5 each |  | 56 | 41 | 54 | 37 |

#### `ktest.wait_set_cycle cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 465 | 465 |
| `kernel::syscall::pin_checked` | kernel | 252 | 168 | 312 | 270 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 310 | 310 | | |
| `memset` | kernel | 112 | 112 | 255 | 255 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 181 | 108 | 234 | 195 |
| `kernel::ipc::wait_set::wait_set_drop::<kernel::cap::object::dealloc_object_one::{closure#8}>` | kernel | 172 | 176 | 209 | 202 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 160 | 190 |
| `<kernel::ipc::wait_set::WaitSetState>::new` | kernel | 171 | 71 | 157 | 87 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 114 | 84 | 138 | 124 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 128 | 48 | 96 | 96 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | | 120 | 95 |
| `kernel::syscall::dispatch` | kernel | 90 | 115 | 85 | 35 |
| `kernel::syscall::ipc::sys_wait_set_add` | kernel | 96 | 68 | 108 | 66 |
| `kernel::syscall::dispatch_in_range` | kernel | 101 | 103 | 75 | 77 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 102 | 65 | 102 | 102 |
| `kernel::syscall::ipc::sys_wait_set_remove` | kernel | 84 | 57 | 91 | 54 |
| `kernel::arch::current::speculation::index_mask` | kernel | 85 | 87 | 87 | 87 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 84 | 80 | 56 | 56 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 64 | 64 | 80 | 80 |
| `kernel::syscall::cap::sys_cap_delete` | kernel | 59 | 36 | 79 | 60 |
| `kernel::syscall::cap::sys_cap_create_wait_set` | kernel | 65 | 43 | 77 | 72 |
| `kernel::cap::retype::retype_allocate` | kernel | 58 | 34 | 71 | 37 |
| `kernel::cap::object::dealloc_object_one` | kernel | 55 | 29 | 66 | 42 |
| `syscall_abi::wait_set_retype_bytes` | kernel | 52 | 19 | 56 | 26 |
| `<kernel::cap::registry::CSpaceRegistry>::entry` | kernel | 54 | 19 | 48 | 23 |
| `<kernel::cap::registry::CSpaceRegistry>::slot` | kernel | 36 | 29 | 33 | 53 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 49 | 53 | 29 | 26 |
| `<kernel::cap::object::KernelObjectHeader>::dec_ref_in` | kernel | 30 | 30 | 50 | 32 |
| `kernel::cap::retype::retype_free` | kernel | 41 | 24 | 50 | 35 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 35 | 33 | 47 | 49 |
| `<kernel::cap::registry::CSpaceRegistry>::lookup` | kernel | 39 | 18 | 48 | 16 |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>` | kernel | | | 32 | 48 |
| `kernel::syscall::ipc::wait_set_source` | kernel | 48 | 30 | 46 | 24 |
| `kernel::syscall::ipc::sys_wait_set_wait` | kernel | 42 | 28 | 46 | 41 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 45 | | | |
| `kernel::cap::derivation::unlink_node` | kernel | 37 | 23 | 42 | 45 |
| `<kernel::cap::object::KernelObjectHeader>::inc_ref` | kernel | 43 | 8 | 21 | 21 |
| `<kernel::cap::cspace::CSpace>::pop_free_slot` | kernel | 37 | 42 | 41 | 41 |
| `<kernel::ipc::wait_set::WaitSetMember>::is_occupied` | kernel | 41 | 42 | 23 | 23 |
| `kernel::cap::object::release_ref` | kernel | 42 | 1 | 42 | |
| `<kernel::cap::cspace::CSpace>::free_slot` | kernel | 36 | 33 | 36 | 41 |
| `kernel::arch::current::cpu::read_percpu_ptr::<kernel::sched::thread::ThreadControlBlock, 104>` | kernel | 26 | 41 | 23 | 24 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 21 | 16 | 40 | 40 |
| `kernel::cap::derivation::reparent_children` | kernel | 27 | 21 | 40 | 32 |
| `seraph_enter_from_user` | kernel | 40 | 40 | | |
| `<kernel::cap::slot::CapTag as core::cmp::PartialEq>::eq` | kernel | 37 | 18 | 26 | 17 |
| `<kernel::ipc::wait_set::WaitSetState>::pop_ready::<&kernel::ipc::wait_set::next_ready_member::{closure#0}>` | kernel | 36 | 21 | 37 | 23 |
| `kernel::ipc::wait_set::waitset_remove` | kernel | 36 | 18 | 18 | 13 |
| `<kernel::cap::cspace::CSpace>::insert_cap` | kernel | 30 | 3 | 33 | 4 |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>::{closure#0}` | kernel | 16 | 32 | 16 | |
| `kernel::ipc::wait_set::waitset_add` | kernel | 23 | 12 | 32 | 29 |
| `<kernel::cap::slot::Rights>::contains` | kernel | 31 | 24 | 19 | 19 |
| `<kernel::ipc::wait_set::WaitSetState>::install::<kernel::ipc::wait_set::waitset_add::{closure#0}>` | kernel | 30 | 24 | 31 | 27 |
| `kernel::cap::object::dealloc_object::{closure#0}` | kernel | 1 | 17 | 3 | 31 |
| `kernel::ipc::interrupt_all_waiters` | kernel | 18 | 16 | 31 | 30 |
| `kernel::sched::check_lock_hold_preemptible` | kernel | 20 | 10 | 30 | 10 |
| `kernel::syscall::leave_syscall` | kernel | 25 | 15 | 30 | 15 |
| `kernel::syscall::stamp_syscall_entry` | kernel | 30 | 20 | 25 | 10 |
| `<kernel::syscall::PinnedCap as core::ops::drop::Drop>::drop` | kernel | 24 | 6 | 29 | |
| `<kernel::cap::object::MemoryObject>::read_lock` | kernel | 18 | 21 | 24 | 28 |
| `kernel::ipc::wait_set::waitset_wait` | kernel | 26 | 4 | 28 | 4 |
| `<kernel::cap::slot::SlotId>::with_epoch` | kernel | 3 | 9 | 3 | 27 |
| `<kernel::ipc::wait_set::WaitSetState>::push_ready` | kernel | 27 | 16 | 26 | 27 |
| `<kernel::ipc::wait_set::WaitSetState>::vacate_member` | kernel | 27 | 18 | 18 | 18 |
| `kernel::cap::retype::round_to_class` | kernel | 17 | 26 | 14 | 23 |
| `<kernel::cap::derivation::DerivationLock>::write_lock` | kernel | 20 | 11 | 25 | 13 |
| 121 functions below 25 each |  | 667 | 498 | 716 | 471 |

#### `ktest.tlb_shootdown_unmap cpus=1`

| Function | Image | x86_64 dev | x86_64 release | riscv64 dev | riscv64 release |
|---|---|---:|---:|---:|---:|
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | | 93 | 93 |
| `kernel::syscall::mem::sys_mem_unmap` | kernel | 59 | 44 | 60 | 82 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 62 | 62 | | |
| `kernel::syscall::pin_checked` | kernel | 42 | 15 | 52 | 45 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | | 48 | 48 |
| `kernel::arch::current::paging::descend_existing::<kernel::mm::paging::phys_to_virt>` | kernel | 14 | 3 | 40 | 20 |
| `kernel::arch::current::paging::read_entry` | kernel | 40 | 10 | | |
| `kernel::mm::tlb_shootdown::shootdown_range` | kernel | 23 | 26 | 32 | 40 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | | 32 | 38 |
| `boot_protocol::x86_paging::table_index` | kernel | 34 | 21 | | |
| `kernel::arch::current::paging::entry` | kernel | 3 | 3 | 30 | 28 |
| `kernel::arch::current::paging::names_table` | kernel | 16 | 30 | | |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 20 | 12 | 25 | 25 |
| `boot_protocol::x86_paging::level_shift` | kernel | 23 | 24 | | |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | | 24 | 19 |
| `kernel::arch::current::paging::table_at` | kernel | 16 | | 24 | |
| `<kernel::mm::address_space::AddressSpace>::unmap_page` | kernel | 23 | 3 | 21 | 4 |
| `kernel::syscall::dispatch` | kernel | 18 | 23 | 17 | 7 |
| `kernel::syscall::dispatch_in_range` | kernel | 21 | 21 | 15 | 15 |
| `boot_protocol::riscv_paging::vpn_index` | kernel | | | 18 | 12 |
| `kernel::arch::current::paging::walk_to_4k_leaf::<kernel::mm::paging::phys_to_virt>` | kernel | 17 | 11 | | |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 17 | 10 | 17 | 17 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 16 | 8 | 14 | 12 |
| `<kernel::cpu_mask::MaskSource>::word_except` | kernel | 15 | 14 | 15 | 14 |
| `kernel::arch::current::paging::translate_user_page` | kernel | 15 | 3 | 6 | 1 |
| `kernel::arch::current::paging::unmap_user_page` | kernel | 7 | 3 | 15 | 3 |
| `<kernel::mm::frame_map::FrameMap>::lower` | kernel | 10 | 5 | 14 | 10 |
| `<kernel::arch::current::paging::PageTableEntry>::phys_addr` | kernel | 7 | 6 | 13 | 13 |
| `<kernel::arch::current::paging::PageTableEntry>::is_present` | kernel | 12 | 6 | 1 | 1 |
| `<kernel::cpu_mask::AtomicCpuMask>::fill_would_be_nonempty` | kernel | 12 | 9 | 9 | 6 |
| `<kernel::cpu_mask::AtomicCpuMask>::words` | kernel | 12 | 2 | 8 | 3 |
| `<kernel::mm::frame_map::FrameMap>::slot` | kernel | 12 | 6 | 11 | 6 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 3 | 10 | 1 | 1 |
| `<kernel::cpu_mask::MaskSource>::word_except::{closure#0}` | kernel | 6 | 6 | 10 | 10 |
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 3 | 3 | 10 | 6 |
| `<kernel::mm::address_space::AddressSpace>::shootdown_remote` | kernel | 6 | 5 | 10 | 9 |
| `kernel::arch::current::speculation::index_mask` | kernel | 10 | 10 | 10 | 10 |
| `kernel::arch::current::cpu::read_rflags` | kernel | 9 | | | |
| `kernel::mm::user_page_range` | kernel | 8 | 9 | 5 | 5 |
| `<boot_protocol::x86_paging::PagingDepth>::from_levels` | kernel | 8 | | | |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 8 | 3 | 6 | 6 |
| `kernel::mm::tlb_shootdown::requests` | kernel | 7 | 5 | 8 | 6 |
| `kernel::percpu::preempt_enable` | kernel | 8 | 1 | 7 | 3 |
| `seraph_enter_from_user` | kernel | 8 | 8 | | |
| `kernel::arch::current::paging::root_level` | kernel | 7 | 3 | | |
| `kernel::cap::object::release_ref` | kernel | 7 | 3 | 7 | 3 |
| `kernel::percpu::preempt_disable` | kernel | 6 | 2 | 7 | 3 |
| `syscall::arch::current::syscall4` | ktest | 7 | 7 | 3 | 6 |
| `<boot_protocol::riscv_paging::PagingMode>::from_satp_mode` | kernel | | | 6 | |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 6 | 6 | 4 | 4 |
| `<kernel::syscall::PinnedCap as core::ops::drop::Drop>::drop` | kernel | 5 | | 6 | |
| `kernel::arch::current::paging::direct_map_base` | kernel | 6 | 6 | 6 | 6 |
| `kernel::arch::current::paging::levels_above::{closure#0}` | kernel | 3 | 3 | | 6 |
| `kernel::mm::check_user_base` | kernel | 5 | 5 | 6 | 6 |
| `kernel::mm::paging::phys_to_virt` | kernel | 6 | 6 | 6 | 6 |
| `kernel::mm::tlb_shootdown::shootdown` | kernel | 3 | 4 | 6 | 5 |
| `kernel::syscall::leave_syscall` | kernel | 5 | 3 | 6 | 3 |
| `kernel::syscall::lookup_cap::<kernel::cap::slot::AddressSpaceCap>` | kernel | 4 | | 6 | 6 |
| `kernel::syscall::stamp_syscall_entry` | kernel | 6 | 4 | 5 | 2 |
| `<bench::counters::Counters>::read` | ktest | 6 | | 6 | |
| `<boot_protocol::riscv_paging::PagingMode>::levels` | kernel | | | 2 | 5 |
| `<kernel::cap::object::KernelObjectHeader>::dec_ref_in` | kernel | 3 | 3 | 5 | 5 |
| `<kernel::cap::object::KernelObjectHeader>::inc_ref` | kernel | 5 | 1 | 2 | 3 |
| `<kernel::cap::slot::Rights>::contains` | kernel | 5 | | 3 | 3 |
| `<kernel::cpu_mask::AtomicCpuMask>::fill_would_be_nonempty::{closure#0}` | kernel | 5 | 5 | 5 | 5 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 1 | 1 | 5 | 2 |
| `kernel::arch::current::paging::leaf_phys` | kernel | | | 5 | 3 |
| `kernel::arch::current::paging::user_va_top` | kernel | 3 | 3 | 4 | 5 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 4 | 4 | 5 | 5 |
| `kernel::arch::current::cpu::read_percpu_ptr::<kernel::sched::thread::ThreadControlBlock, 104>` | kernel | 4 | 4 | 4 | 4 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 4 | 4 | 2 | 2 |
| `kernel::arch::current::paging::flush_page` | kernel | 2 | 2 | 2 | 4 |
| `kernel::arch::current::paging::paging_depth` | kernel | 4 | 2 | | |
| `kernel::arch::current::paging::paging_mode` | kernel | | | 4 | |
| `kernel::arch::nospec::mask_span_u64` | kernel | 4 | 4 | 3 | 3 |
| `kernel::sched::this_cpu_diag` | kernel | 4 | | 3 | |
| `bench::arch::current::cycles` | ktest | 4 | 3 | 1 | 1 |
| 31 functions below 4 each |  | 43 | 37 | 48 | 37 |

<!-- path-account: end -->

---

## Summarized By

[core/kernel/README.md](../README.md)
