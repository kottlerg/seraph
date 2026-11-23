# Userspace Hot-Path Instruction Account

Where the instructions of each gated ubench and fsbench path go, function by function and
process by process, on x86_64 and riscv64 in the release profile the benchmark cell gates.

---

## What the Account Measures

Each gated row of ubench and fsbench measures one path between two counter reads in a
benchmark program: under QEMU's icount the counter advances by one per instruction, so the
sample is the path's instruction count, whatever ran in it: the program, the kernel, the
services the path calls (memmgr, vfsd, a fatfs instance, a driver), and the firmware the kernel
calls. The benchmark cell gates the rows in the release profile
([docs/testing.md](../../../docs/testing.md) § Benchmarks).

The account is taken as the kernel paths' account is
([hot-path-account.md](hot-path-account.md)): one boot of the image at one CPU under icount,
with ubench staged as the benchmark cell stages it and a QEMU plugin counting every instruction
the guest runs. Every counted window of a gated row retires exactly its sample, and each row's
p50 lies within the gate's band of a boot of the image without debuginfo, so each table below
sums to the count the cell sees. The method, its checks and its limits are in
[xtask/README.md](../../../xtask/README.md) § `cargo xtask path-account`.

## Regenerating It

The generated block below is written by `cargo xtask path-account write` from the userspace
result files of `cargo xtask path-account trace`, one per architecture; the commands that
regenerate one are in [xtask/README.md](../../../xtask/README.md) § `cargo xtask path-account`.
The block's first table names, for each configuration, the head of the tree it was taken at,
the date, the QEMU version, and the reference it was checked against. A change to the code of a
function a gated window runs regenerates both architectures, rewrites the block, and revises
the prose below where its numbers moved. Beside ubench's and fsbench's own code, the windows
run the kernel's syscall, IPC, page-fault and scheduling paths, memmgr, vfsd, both fatfs
instances, the framebuffer driver and the IOMMU driver (the Totals table gives each image's
share), so a kernel change on those paths owes this account as well as the four configurations
of [hot-path-account.md](hot-path-account.md). The commands and their host time are in
[xtask/README.md](../../../xtask/README.md) § `cargo xtask path-account`.

## Reading the Tables

- **Totals** gives each path's p50 split by the image its instructions ran in: the benchmark
  program, the kernel, and each service, named as procmgr logged it when it spawned the process
  (`fatfs:/` and `fatfs:/data` are two instances of fatfs).
- An instruction in no placed image counts against the page it ran in, `<page …>`: on riscv64
  the firmware (OpenSBI, from `0x80000000`) the kernel calls through the SBI. **Totals** sums
  those pages as `other`. No x86_64 path runs outside a placed image.
- Each path's table lists its functions by their largest count in either architecture, a
  function being named as in the kernel account (§ Reading the Tables there), so `memset` and
  `memcpy` are named in the image that ran them.
- The smallest rows of each path fold into one closing row, and an empty cell means the
  function ran no instruction on that architecture.

## Where the Instructions Go

The figures are release, x86_64 / riscv64. Each heading's cut, where one is named, is an Issue
under #1531; the kernel account's ranked list ([hot-path-account.md](hot-path-account.md)
§ Ranked Cuts) orders them.

### IPC Round Trip

`ubench.ipc_rt words=0` is 3172 / 5911, 2516 / 3207 of it in the kernel. The kernel copies and
zeroes no whole `Message` on either side: its largest functions are the entries
(`syscall_entry` 186 on x86_64; `trap_entry` and `trap_dispatch`, 372 and 153, on riscv64) and
`schedule` (178 / 236). On riscv64 ubench moves the message through `compiler_builtins`' word
loops (`memcpy` 1448, `memset` 667), and the firmware's pages take 353 (`other`). On x86_64
each round trip also takes the lazy FPU switch's `#NM` trap once a thread is switched back in
(`isr_nm` and its handler, 114).

### Page Faults

`ubench.fault_fill path=fault pages=16` is 34918 / 60002: memmgr 13917 / 31714, of which its
`memset` zeroing the 16 frames is 8298 / 24812 (x86_64's `rep stos` is about one iteration per 8
bytes, riscv64's loop about one instruction per 2.6 bytes), and the kernel 20990 / 28280, spread
over the page-table walk and install (`level_shift`, `table_index`, `names_table`, `read_entry`,
`install_user_leaf`), the frame map's counters, and `sys_mem_map`. `fault_scaling threads=1` runs
the same path. `path=grant` adds the grant's capability operations, 35262 / 63557.

### Shared-Memory Ring

`ubench.shmem_ring` runs in ubench alone: `shmem_ring::transfer` is 49342 / 57448 of the
4096-byte transfer, about 12 / 14 instructions per byte.

### Console Writes

`ubench.console_write bytes=4096` is 48944510 / 177121983, all but 0.2 % in the framebuffer
driver. Its scroll moves the whole framebuffer up a text row at each line it fills
(`memmove` 28673472 / 143361728 and `FramebufferWriter::scroll` 9013440 / 19662656), and
drawing the glyphs is 7156800 / 12820888.

### File Reads and Opens

A read through the inline path (`fsbench.read path=inline`) is fatfs's copy and zeroing of the reply
and the kernel's copy to and from user memory. A read through granted frames (`path=frame`) spends
12628 / 12530 in the kernel's Keccak permutation (`keccak_f1600`, a kernel entropy draw) per 4 KiB
frame the grant names, 202048 / 200480 of 709727 / 1109064 at 64 KiB; #1550 serves such small draws
from one squeezed block. `fsbench.open depth=3` is 70149 / 106866, one such draw (12628 / 12530) and
fatfs's long-name parsing (`LfnAccum`, 8370 / 7071) among it.

## Account

<!-- path-account: begin; generated by cargo xtask path-account write -->

| Configuration | Head | Taken | QEMU | Checked against |
|---|---|---|---|---|
| x86_64 release | `499f0fea8b4d` | 2026-11-23 | QEMU emulator version 11.1.3 | 1 icount boot(s) of the image without debuginfo |
| riscv64 release | `499f0fea8b4d` | 2026-11-23 | QEMU emulator version 11.1.3 | 1 icount boot(s) of the image without debuginfo |

#### Totals

| Path | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `ubench.ipc_rt words=0 cpus=1` | all | 3172 | 5911 |
| `ubench.ipc_rt words=0 cpus=1` | ubench | 656 | 2351 |
| `ubench.ipc_rt words=0 cpus=1` | kernel | 2516 | 3207 |
| `ubench.ipc_rt words=0 cpus=1` | other | 0 | 353 |
| `ubench.ipc_rt words=6 cpus=1` | all | 3417 | 6973 |
| `ubench.ipc_rt words=6 cpus=1` | ubench | 757 | 2573 |
| `ubench.ipc_rt words=6 cpus=1` | kernel | 2660 | 3694 |
| `ubench.ipc_rt words=6 cpus=1` | other | 0 | 706 |
| `ubench.ipc_rt words=7 cpus=1` | all | 3666 | 7801 |
| `ubench.ipc_rt words=7 cpus=1` | ubench | 842 | 2558 |
| `ubench.ipc_rt words=7 cpus=1` | kernel | 2824 | 4890 |
| `ubench.ipc_rt words=7 cpus=1` | other | 0 | 353 |
| `ubench.ipc_rt words=64 cpus=1` | all | 6644 | 22395 |
| `ubench.ipc_rt words=64 cpus=1` | ubench | 1939 | 4097 |
| `ubench.ipc_rt words=64 cpus=1` | kernel | 4705 | 17945 |
| `ubench.ipc_rt words=64 cpus=1` | other | 0 | 353 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | all | 34918 | 60002 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | ubench | 11 | 8 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | memmgr | 13917 | 31714 |
| `ubench.fault_fill path=fault pages=16 cpus=1` | kernel | 20990 | 28280 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | all | 35262 | 63557 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | ubench | 115 | 353 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | memmgr | 11111 | 30247 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | kernel | 24036 | 32604 |
| `ubench.fault_fill path=grant pages=16 cpus=1` | other | 0 | 353 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | all | 34850 | 59883 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | ubench | 11 | 8 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | memmgr | 13849 | 31586 |
| `ubench.fault_scaling threads=1 pages=16 cpus=1` | kernel | 20990 | 28289 |
| `ubench.shmem_ring bytes=64 cpus=1` | all | 219 | 103 |
| `ubench.shmem_ring bytes=64 cpus=1` | ubench | 219 | 103 |
| `ubench.shmem_ring bytes=512 cpus=1` | all | 207 | 383 |
| `ubench.shmem_ring bytes=512 cpus=1` | ubench | 207 | 383 |
| `ubench.shmem_ring bytes=4096 cpus=1` | all | 49353 | 57455 |
| `ubench.shmem_ring bytes=4096 cpus=1` | ubench | 49353 | 57455 |
| `ubench.shmem_ring bytes=65536 cpus=1` | all | 789862 | 919564 |
| `ubench.shmem_ring bytes=65536 cpus=1` | ubench | 789423 | 919115 |
| `ubench.shmem_ring bytes=65536 cpus=1` | kernel | 439 | 449 |
| `ubench.console_write bytes=64 cpus=1` | all | 768010 | 2774432 |
| `ubench.console_write bytes=64 cpus=1` | ubench | 989 | 3099 |
| `ubench.console_write bytes=64 cpus=1` | /services/drivers/framebuffer | 763764 | 2764543 |
| `ubench.console_write bytes=64 cpus=1` | kernel | 3257 | 6084 |
| `ubench.console_write bytes=64 cpus=1` | other | 0 | 706 |
| `ubench.console_write bytes=4096 cpus=1` | all | 48944510 | 177121983 |
| `ubench.console_write bytes=4096 cpus=1` | ubench | 25251 | 60079 |
| `ubench.console_write bytes=4096 cpus=1` | /services/drivers/framebuffer | 48865048 | 176873272 |
| `ubench.console_write bytes=4096 cpus=1` | /services/drivers/iommu-riscv | 0 | 113 |
| `ubench.console_write bytes=4096 cpus=1` | /services/drivers/iommu-vtd | 63 | 0 |
| `ubench.console_write bytes=4096 cpus=1` | kernel | 54148 | 182871 |
| `ubench.console_write bytes=4096 cpus=1` | other | 0 | 5648 |
| `fsbench.read size=16 path=inline cpus=1` | all | 6212 | 12935 |
| `fsbench.read size=16 path=inline cpus=1` | /programs/fsbench | 577 | 1541 |
| `fsbench.read size=16 path=inline cpus=1` | fatfs:/ | 2344 | 5967 |
| `fsbench.read size=16 path=inline cpus=1` | fatfs:/data | 1 | 1 |
| `fsbench.read size=16 path=inline cpus=1` | kernel | 3290 | 4659 |
| `fsbench.read size=16 path=inline cpus=1` | other | 0 | 767 |
| `fsbench.read size=16 path=frame cpus=1` | all | 44062 | 68973 |
| `fsbench.read size=16 path=frame cpus=1` | /programs/fsbench | 11322 | 27036 |
| `fsbench.read size=16 path=frame cpus=1` | fatfs:/ | 4226 | 5986 |
| `fsbench.read size=16 path=frame cpus=1` | fatfs:/data | 27 | 27 |
| `fsbench.read size=16 path=frame cpus=1` | kernel | 28487 | 34390 |
| `fsbench.read size=16 path=frame cpus=1` | other | 0 | 1534 |
| `fsbench.read size=1024 path=inline cpus=1` | all | 32113 | 76893 |
| `fsbench.read size=1024 path=inline cpus=1` | /programs/fsbench | 2643 | 7249 |
| `fsbench.read size=1024 path=inline cpus=1` | fatfs:/ | 14300 | 33852 |
| `fsbench.read size=1024 path=inline cpus=1` | fatfs:/data | 4 | 4 |
| `fsbench.read size=1024 path=inline cpus=1` | kernel | 15166 | 32842 |
| `fsbench.read size=1024 path=inline cpus=1` | other | 0 | 2946 |
| `fsbench.read size=1024 path=frame cpus=1` | all | 44062 | 68973 |
| `fsbench.read size=1024 path=frame cpus=1` | /programs/fsbench | 11322 | 27036 |
| `fsbench.read size=1024 path=frame cpus=1` | fatfs:/ | 4226 | 5986 |
| `fsbench.read size=1024 path=frame cpus=1` | fatfs:/data | 27 | 27 |
| `fsbench.read size=1024 path=frame cpus=1` | kernel | 28487 | 34390 |
| `fsbench.read size=1024 path=frame cpus=1` | other | 0 | 1534 |
| `fsbench.read size=4096 path=inline cpus=1` | all | 128317 | 307431 |
| `fsbench.read size=4096 path=inline cpus=1` | /programs/fsbench | 10437 | 28855 |
| `fsbench.read size=4096 path=inline cpus=1` | fatfs:/ | 57200 | 135408 |
| `fsbench.read size=4096 path=inline cpus=1` | fatfs:/data | 16 | 16 |
| `fsbench.read size=4096 path=inline cpus=1` | kernel | 60664 | 131368 |
| `fsbench.read size=4096 path=inline cpus=1` | other | 0 | 11784 |
| `fsbench.read size=4096 path=frame cpus=1` | all | 44062 | 68973 |
| `fsbench.read size=4096 path=frame cpus=1` | /programs/fsbench | 11322 | 27036 |
| `fsbench.read size=4096 path=frame cpus=1` | fatfs:/ | 4226 | 5986 |
| `fsbench.read size=4096 path=frame cpus=1` | fatfs:/data | 27 | 27 |
| `fsbench.read size=4096 path=frame cpus=1` | kernel | 28487 | 34390 |
| `fsbench.read size=4096 path=frame cpus=1` | other | 0 | 1534 |
| `fsbench.read size=16384 path=inline cpus=1` | all | 525718 | 1244097 |
| `fsbench.read size=16384 path=inline cpus=1` | /programs/fsbench | 41613 | 115279 |
| `fsbench.read size=16384 path=inline cpus=1` | fatfs:/ | 240930 | 555690 |
| `fsbench.read size=16384 path=inline cpus=1` | fatfs:/data | 78 | 70 |
| `fsbench.read size=16384 path=inline cpus=1` | kernel | 243097 | 525922 |
| `fsbench.read size=16384 path=inline cpus=1` | other | 0 | 47136 |
| `fsbench.read size=16384 path=frame cpus=1` | all | 176732 | 276457 |
| `fsbench.read size=16384 path=frame cpus=1` | /programs/fsbench | 45153 | 108003 |
| `fsbench.read size=16384 path=frame cpus=1` | fatfs:/ | 17523 | 24638 |
| `fsbench.read size=16384 path=frame cpus=1` | fatfs:/data | 108 | 120 |
| `fsbench.read size=16384 path=frame cpus=1` | kernel | 113948 | 137560 |
| `fsbench.read size=16384 path=frame cpus=1` | other | 0 | 6136 |
| `fsbench.read size=65536 path=inline cpus=1` | all | 2285359 | 5191188 |
| `fsbench.read size=65536 path=inline cpus=1` | /programs/fsbench | 166317 | 460975 |
| `fsbench.read size=65536 path=inline cpus=1` | fatfs:/ | 1147152 | 2436993 |
| `fsbench.read size=65536 path=inline cpus=1` | fatfs:/data | 384 | 271 |
| `fsbench.read size=65536 path=inline cpus=1` | kernel | 971506 | 2104405 |
| `fsbench.read size=65536 path=inline cpus=1` | other | 0 | 188544 |
| `fsbench.read size=65536 path=frame cpus=1` | all | 709727 | 1109064 |
| `fsbench.read size=65536 path=frame cpus=1` | /programs/fsbench | 180477 | 431871 |
| `fsbench.read size=65536 path=frame cpus=1` | fatfs:/ | 72585 | 101516 |
| `fsbench.read size=65536 path=frame cpus=1` | fatfs:/data | 432 | 444 |
| `fsbench.read size=65536 path=frame cpus=1` | kernel | 456233 | 550689 |
| `fsbench.read size=65536 path=frame cpus=1` | other | 0 | 24544 |
| `fsbench.open depth=3 cpus=1` | all | 70149 | 106866 |
| `fsbench.open depth=3 cpus=1` | /programs/fsbench | 3274 | 7055 |
| `fsbench.open depth=3 cpus=1` | fatfs:/ | 25067 | 42882 |
| `fsbench.open depth=3 cpus=1` | fatfs:/data | 19 | 83 |
| `fsbench.open depth=3 cpus=1` | vfsd | 1182 | 3579 |
| `fsbench.open depth=3 cpus=1` | kernel | 40607 | 50966 |
| `fsbench.open depth=3 cpus=1` | other | 0 | 2301 |

#### `ubench.ipc_rt words=0 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | ubench | | 1448 |
| `memset` | ubench | 93 | 667 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 372 |
| `memcpy` | ubench | 347 | 10 |
| `kernel::sched::schedule` | kernel | 178 | 236 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 153 |
| `<page 0x8000c000>` | other | | 134 |
| `<page 0x80000000>` | other | | 104 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 99 | 68 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::sched::scheduler_ptr` | kernel | 30 | 91 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `kernel::arch::current::idt::isr_nm` | kernel | 80 | |
| `kernel::sched::enqueue_and_wake` | kernel | 58 | 78 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 76 |
| `kernel::syscall::dispatch` | kernel | 69 | 24 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 58 | 69 |
| `kernel::arch::current::fpu::save_fp_to` | kernel | | 68 |
| `kernel::ipc::upcall::deliver` | kernel | | 66 |
| `ipc::ipc_call_timeout` | ubench | 48 | 61 |
| `kernel::sched::scheduler_for` | kernel | 47 | 60 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 59 | 34 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 58 | 26 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 51 |
| `ubench::ipc_rt::serve` | ubench | 57 | 52 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 32 | 54 |
| `ipc::ipc_recv_timeout` | ubench | 36 | 51 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 24 | 50 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 30 | 50 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 26 | 49 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 19 | 45 |
| `<page 0x80017000>` | other | | 45 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 42 | 38 |
| `kernel::syscall::finish_syscall` | kernel | 42 | 12 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 31 | 40 |
| `seraph_enter_from_user` | kernel | 40 | |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 13 | 39 |
| `kernel::arch::current::fpu::switch_out_save` | kernel | 18 | 38 |
| `kernel::arch::current::fpu::save_v_to` | kernel | | 36 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | 34 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 34 |
| `kernel::arch::current::idt::nm_handler` | kernel | 34 | |
| `kernel::syscall::ipc::deliver_message` | kernel | 32 | 34 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 24 | 34 |
| `kernel::ipc::endpoint::bind_next_sender` | kernel | 17 | 33 |
| `kernel::percpu::per_cpu_ptr` | kernel | 32 | 12 |
| `memcpy` | kernel | 32 | 4 |
| `<kernel::arch::current::trap_frame::TrapFrame>::arg` | kernel | 30 | 6 |
| `kernel::cap::object::reclaim_deferred_stack` | kernel | 30 | 15 |
| `kernel::sched::running_thread_stopped` | kernel | 30 | 24 |
| `<kernel::sched::run_queue::PerCpuScheduler>::current` | kernel | 29 | 28 |
| 126 functions below 29 each |  | 797 | 902 |

#### `ubench.ipc_rt words=6 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | ubench | | 1592 |
| `memset` | ubench | 93 | 667 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 465 |
| `memcpy` | ubench | 397 | 14 |
| `<page 0x8000c000>` | other | | 268 |
| `kernel::sched::schedule` | kernel | 178 | 236 |
| `<page 0x80000000>` | other | | 208 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 192 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | |
| `compiler_builtins::mem::memcpy` | kernel | | 162 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 99 | 68 |
| `ipc::ipc_call_timeout` | ubench | 72 | 99 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 92 |
| `kernel::sched::scheduler_ptr` | kernel | 30 | 91 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `<page 0x80017000>` | other | | 90 |
| `memcpy` | kernel | 82 | 8 |
| `kernel::arch::current::idt::isr_nm` | kernel | 80 | |
| `kernel::sched::enqueue_and_wake` | kernel | 58 | 78 |
| `ipc::ipc_recv_timeout` | ubench | 53 | 78 |
| `kernel::syscall::dispatch` | kernel | 69 | 24 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 60 | 69 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 68 |
| `kernel::arch::current::fpu::save_fp_to` | kernel | | 68 |
| `kernel::ipc::upcall::deliver` | kernel | | 66 |
| `kernel::sched::scheduler_for` | kernel | 47 | 60 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 59 | 34 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 58 | 26 |
| `ubench::ipc_rt::serve` | ubench | 58 | 53 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 51 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 32 | 54 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 24 | 50 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 30 | 50 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 26 | 49 |
| `<page 0x80010000>` | other | | 48 |
| `<kernel::arch::current::trap_frame::TrapFrame>::set_msg_regs` | kernel | 46 | 46 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 19 | 45 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 42 | 38 |
| `kernel::syscall::finish_syscall` | kernel | 42 | 12 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 31 | 40 |
| `seraph_enter_from_user` | kernel | 40 | |
| `<page 0x80003000>` | other | | 40 |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 13 | 39 |
| `kernel::arch::current::fpu::switch_out_save` | kernel | 18 | 38 |
| `kernel::arch::current::fpu::restore_v_from` | kernel | | 36 |
| `kernel::arch::current::fpu::save_v_to` | kernel | | 36 |
| `<page 0x80008000>` | other | | 36 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | 34 |
| `kernel::arch::current::idt::nm_handler` | kernel | 34 | |
| `kernel::syscall::ipc::deliver_message` | kernel | 32 | 34 |
| `kernel::syscall::pin_checked::{closure#0}` | kernel | 24 | 34 |
| 132 functions below 34 each |  | 1020 | 1031 |

#### `ubench.ipc_rt words=7 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memcpy` | ubench | | 1495 |
| `__copy_user_fault_end` | kernel | 8 | 908 |
| `memset` | ubench | 93 | 667 |
| `__copy_user_fault_start` | kernel | 228 | 448 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 372 |
| `memcpy` | ubench | 354 | 10 |
| `__copy_user` | kernel | 12 | 236 |
| `kernel::sched::schedule` | kernel | 178 | 236 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 153 |
| `ipc::ipc_call_timeout` | ubench | 134 | 138 |
| `<page 0x8000c000>` | other | | 134 |
| `<page 0x80000000>` | other | | 104 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 99 | 68 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::sched::scheduler_ptr` | kernel | 30 | 91 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `ipc::ipc_recv_timeout` | ubench | 77 | 83 |
| `kernel::arch::current::idt::isr_nm` | kernel | 80 | |
| `kernel::sched::enqueue_and_wake` | kernel | 58 | 78 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 76 |
| `ipc::ipc_reply` | ubench | 74 | 73 |
| `kernel::syscall::dispatch` | kernel | 69 | 24 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 60 | 69 |
| `kernel::arch::current::fpu::save_fp_to` | kernel | | 68 |
| `kernel::ipc::upcall::deliver` | kernel | | 66 |
| `compiler_builtins::mem::memcpy` | kernel | | 65 |
| `kernel::sched::scheduler_for` | kernel | 47 | 60 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 59 | 34 |
| `kernel::arch::current::cpu::save_and_disable_interrupts` | kernel | 58 | 26 |
| `ubench::ipc_rt::serve` | ubench | 58 | 53 |
| `kernel::syscall::dispatch_in_range` | kernel | 57 | 51 |
| `kernel::arch::current::cpu::restore_interrupts` | kernel | 32 | 54 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 24 | 50 |
| `kernel::syscall::ipc::sys_ipc_reply` | kernel | 30 | 50 |
| `kernel::syscall::ipc::sys_ipc_recv` | kernel | 26 | 49 |
| `kernel::ipc::endpoint::endpoint_call` | kernel | 19 | 45 |
| `<page 0x80017000>` | other | | 45 |
| `<kernel::sched::run_queue::PerCpuScheduler>::link` | kernel | 42 | 38 |
| `kernel::syscall::finish_syscall` | kernel | 42 | 12 |
| `kernel::sched::commit_blocked_under_local_lock` | kernel | 31 | 40 |
| `seraph_enter_from_user` | kernel | 40 | |
| `<kernel::sync::Spinlock>::unlock_raw` | kernel | 13 | 39 |
| `memcpy` | kernel | 39 | 4 |
| 145 functions below 39 each |  | 1101 | 1233 |

#### `ubench.ipc_rt words=64 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `__copy_user_fault_end` | kernel | 8 | 8204 |
| `__copy_user_fault_start` | kernel | 2052 | 4096 |
| `__copy_user` | kernel | 12 | 2060 |
| `compiler_builtins::mem::memcpy` | ubench | | 1780 |
| `ipc::ipc_call_timeout` | ubench | 654 | 765 |
| `memset` | ubench | 93 | 667 |
| `ipc::ipc_reply` | ubench | 416 | 415 |
| `memcpy` | ubench | 411 | 10 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 372 |
| `ipc::ipc_recv_timeout` | ubench | 255 | 368 |
| `compiler_builtins::mem::memcpy` | kernel | | 350 |
| `kernel::sched::schedule` | kernel | 178 | 236 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 186 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 153 |
| `<page 0x8000c000>` | other | | 134 |
| 175 functions below 111 each |  | 2379 | 2785 |

#### `ubench.fault_fill path=fault pages=16 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | memmgr | 8298 | 24812 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | 2136 |
| `<memmgr::MappedSlots as memmgr_free_pool::arena::SlotStore>::read` | memmgr | 1272 | 1528 |
| `<kernel::mm::address_space::AddressSpace>::map_page_pooled` | kernel | 576 | 1472 |
| `kernel::arch::current::paging::install_user_leaf` | kernel | | 1216 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 896 | 1168 |
| `kernel::arch::current::paging::entry` | kernel | 48 | 1161 |
| `compiler_builtins::mem::memcpy` | memmgr | | 1119 |
| `boot_protocol::x86_paging::level_shift` | kernel | 1065 | |
| `kernel::arch::current::paging::names_table` | kernel | 975 | |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 930 |
| `boot_protocol::x86_paging::table_index` | kernel | 921 | |
| `<kernel::mm::frame_map::FrameMap>::lower` | kernel | 240 | 912 |
| `kernel::syscall::mem::sys_mem_map` | kernel | 852 | 818 |
| `<kernel::mm::frame_map::FrameMap>::slot` | kernel | 674 | 784 |
| `kernel::arch::current::paging::descend_existing::<kernel::mm::paging::phys_to_virt>` | kernel | 48 | 682 |
| `<kernel::mm::frame_map::FrameMap>::raise` | kernel | 288 | 640 |
| `kernel::mm::tlb_shootdown::shootdown_range` | kernel | 416 | 640 |
| `kernel::percpu::per_cpu_ptr` | kernel | 300 | 600 |
| `<kernel::arch::current::paging::PageTableEntry>::phys_addr` | kernel | 387 | 598 |
| `boot_protocol::riscv_paging::vpn_index` | kernel | | 582 |
| `kernel::arch::current::paging::walk_to_4k_leaf::<kernel::mm::paging::phys_to_virt>` | kernel | 571 | |
| `<boot_protocol::riscv_paging::PagingMode>::levels` | kernel | | 565 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 558 | |
| `kernel::syscall::pin_checked` | kernel | 304 | 540 |
| `kernel::arch::current::paging::root_level` | kernel | 531 | |
| `kernel::arch::current::paging::read_entry` | kernel | 521 | |
| `<memmgr_free_pool::arena::ArenaLayout>::slot_va` | memmgr | 414 | 450 |
| `compiler_builtins::mem::memcpy` | kernel | | 401 |
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 144 | 400 |
| `<kernel::arch::current::paging::PageTableEntry>::new_page` | kernel | 352 | 384 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 381 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 223 | 378 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 192 | 374 |
| `memmgr_free_pool::chunk::child::<memmgr::MappedSlots>` | memmgr | 369 | 363 |
| `memmgr_free_pool::chunk::leaf::<memmgr::MappedSlots>` | memmgr | 369 | 225 |
| 419 functions below 300 each |  | 13114 | 13743 |

#### `ubench.fault_fill path=grant pages=16 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | memmgr | 8388 | 25041 |
| `compiler_builtins::mem::memcpy` | memmgr | | 2846 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | 2112 |
| `<kernel::mm::address_space::AddressSpace>::map_page_pooled` | kernel | 576 | 1472 |
| `kernel::arch::current::paging::install_user_leaf` | kernel | | 1216 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 896 | 1168 |
| `kernel::arch::current::paging::entry` | kernel | 48 | 1152 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 1116 |
| `boot_protocol::x86_paging::level_shift` | kernel | 1056 | |
| `kernel::arch::current::paging::names_table` | kernel | 960 | |
| `<kernel::mm::frame_map::FrameMap>::lower` | kernel | 240 | 912 |
| `boot_protocol::x86_paging::table_index` | kernel | 912 | |
| `kernel::syscall::mem::sys_mem_map` | kernel | 852 | 818 |
| `<kernel::mm::frame_map::FrameMap>::slot` | kernel | 674 | 784 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 682 | |
| `kernel::arch::current::paging::descend_existing::<kernel::mm::paging::phys_to_virt>` | kernel | 48 | 672 |
| `<memmgr::MappedSlots as memmgr_free_pool::arena::SlotStore>::read` | memmgr | 498 | 666 |
| `<kernel::mm::frame_map::FrameMap>::raise` | kernel | 288 | 640 |
| `kernel::mm::tlb_shootdown::shootdown_range` | kernel | 416 | 640 |
| `compiler_builtins::mem::memcpy` | kernel | | 635 |
| `kernel::syscall::pin_checked` | kernel | 360 | 630 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 348 | 629 |
| `memcpy` | memmgr | 609 | 22 |
| `kernel::percpu::per_cpu_ptr` | kernel | 310 | 600 |
| `<kernel::arch::current::paging::PageTableEntry>::phys_addr` | kernel | 384 | 592 |
| `boot_protocol::riscv_paging::vpn_index` | kernel | | 576 |
| `<boot_protocol::riscv_paging::PagingMode>::levels` | kernel | | 560 |
| `kernel::arch::current::paging::walk_to_4k_leaf::<kernel::mm::paging::phys_to_virt>` | kernel | 560 | |
| `kernel::arch::current::paging::root_level` | kernel | 528 | |
| `kernel::arch::current::paging::read_entry` | kernel | 512 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 457 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 252 | 414 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 251 | 402 |
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 144 | 400 |
| `<kernel::arch::current::paging::PageTableEntry>::new_page` | kernel | 352 | 384 |
| 449 functions below 317 each |  | 14118 | 16001 |

#### `ubench.fault_scaling threads=1 pages=16 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | memmgr | 8298 | 24812 |
| `boot_protocol::riscv_paging::level_shift` | kernel | | 2136 |
| `<kernel::mm::address_space::AddressSpace>::map_page_pooled` | kernel | 576 | 1472 |
| `<memmgr::MappedSlots as memmgr_free_pool::arena::SlotStore>::read` | memmgr | 1224 | 1420 |
| `kernel::arch::current::paging::install_user_leaf` | kernel | | 1216 |
| `<kernel::mm::frame_map::FrameMap>::counter` | kernel | 896 | 1168 |
| `kernel::arch::current::paging::entry` | kernel | 48 | 1161 |
| `compiler_builtins::mem::memcpy` | memmgr | | 1119 |
| `boot_protocol::x86_paging::level_shift` | kernel | 1065 | |
| `kernel::arch::current::paging::names_table` | kernel | 975 | |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 930 |
| `boot_protocol::x86_paging::table_index` | kernel | 921 | |
| `<kernel::mm::frame_map::FrameMap>::lower` | kernel | 240 | 912 |
| `kernel::syscall::mem::sys_mem_map` | kernel | 852 | 818 |
| `<kernel::mm::frame_map::FrameMap>::slot` | kernel | 674 | 784 |
| `kernel::arch::current::paging::descend_existing::<kernel::mm::paging::phys_to_virt>` | kernel | 48 | 682 |
| `<kernel::mm::frame_map::FrameMap>::raise` | kernel | 288 | 640 |
| `kernel::mm::tlb_shootdown::shootdown_range` | kernel | 416 | 640 |
| `kernel::percpu::per_cpu_ptr` | kernel | 300 | 600 |
| `<kernel::arch::current::paging::PageTableEntry>::phys_addr` | kernel | 387 | 598 |
| `boot_protocol::riscv_paging::vpn_index` | kernel | | 582 |
| `kernel::arch::current::paging::walk_to_4k_leaf::<kernel::mm::paging::phys_to_virt>` | kernel | 571 | |
| `<boot_protocol::riscv_paging::PagingMode>::levels` | kernel | | 565 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 558 | |
| `kernel::syscall::pin_checked` | kernel | 304 | 540 |
| `kernel::arch::current::paging::root_level` | kernel | 531 | |
| `kernel::arch::current::paging::read_entry` | kernel | 521 | |
| `<memmgr_free_pool::arena::ArenaLayout>::slot_va` | memmgr | 414 | 450 |
| `compiler_builtins::mem::memcpy` | kernel | | 401 |
| `<kernel::mm::address_space::AddressSpace>::pt_lock` | kernel | 144 | 400 |
| `<kernel::arch::current::paging::PageTableEntry>::new_page` | kernel | 352 | 384 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 381 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 223 | 378 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 192 | 374 |
| `memmgr_free_pool::chunk::child::<memmgr::MappedSlots>` | memmgr | 369 | 363 |
| `memmgr_free_pool::chunk::leaf::<memmgr::MappedSlots>` | memmgr | 369 | 225 |
| 421 functions below 299 each |  | 13094 | 13732 |

#### `ubench.shmem_ring bytes=64 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `ubench::shmem_ring::transfer` | ubench | 208 | 96 |
| `<bench::counters::Counters>::read` | ubench | 7 | 6 |
| `bench::arch::current::cycles` | ubench | 4 | 1 |

#### `ubench.shmem_ring bytes=512 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `ubench::shmem_ring::transfer` | ubench | 196 | 376 |
| `<bench::counters::Counters>::read` | ubench | 7 | 6 |
| `bench::arch::current::cycles` | ubench | 4 | 1 |

#### `ubench.shmem_ring bytes=4096 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `ubench::shmem_ring::transfer` | ubench | 49342 | 57448 |
| 2 functions below 287 each |  | 11 | 7 |

#### `ubench.shmem_ring bytes=65536 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `ubench::shmem_ring::transfer` | ubench | 789412 | 919108 |
| 57 functions below 4597 each |  | 450 | 456 |

#### `ubench.console_write bytes=64 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memmove` | /services/drivers/framebuffer | | 2240025 |
| `memmove` | /services/drivers/framebuffer | 448023 | 2 |
| `<framebuffer::render::FramebufferWriter>::scroll` | /services/drivers/framebuffer | 140835 | 307229 |
| `<framebuffer::render::FramebufferWriter>::draw_glyph_bitmap` | /services/drivers/framebuffer | 111825 | 200332 |
| `<framebuffer::render::FramebufferWriter>::pixel_bytes` | /services/drivers/framebuffer | 57960 | 11340 |
| 253 functions below 13872 each |  | 9367 | 15504 |

#### `ubench.console_write bytes=4096 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `compiler_builtins::mem::memmove` | /services/drivers/framebuffer | | 143361600 |
| `memmove` | /services/drivers/framebuffer | 28673472 | 128 |
| `<framebuffer::render::FramebufferWriter>::scroll` | /services/drivers/framebuffer | 9013440 | 19662656 |
| `<framebuffer::render::FramebufferWriter>::draw_glyph_bitmap` | /services/drivers/framebuffer | 7156800 | 12820888 |
| `<framebuffer::render::FramebufferWriter>::pixel_bytes` | /services/drivers/framebuffer | 3709440 | 725760 |
| 313 functions below 885609 each |  | 391358 | 550951 |

#### `fsbench.read size=16 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 1154 | 3553 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1598 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 759 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 651 |
| `memset` | /programs/fsbench | 87 | 434 |
| `memcpy` | fatfs:/ | 398 | 16 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 310 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 268 |
| `<page 0x8000c000>` | other | | 268 |
| `kernel::sched::schedule` | kernel | 180 | 240 |
| `<page 0x80000000>` | other | | 208 |
| `memcpy` | /programs/fsbench | 199 | 8 |
| `std::os::seraph::memmgr_call` | /programs/fsbench | 126 | 151 |
| `kernel::sched::scheduler_ptr` | kernel | 46 | 145 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 132 |
| `<page 0x80017000>` | other | | 125 |
| `<std::fs::File as alloc::io::read::Read>::read` | /programs/fsbench | 96 | 124 |
| `fatfs::service_loop` | fatfs:/ | 116 | 112 |
| `kernel::syscall::dispatch` | kernel | 115 | 40 |
| `kernel::ipc::upcall::deliver` | kernel | | 110 |
| `compiler_builtins::mem::memcpy` | kernel | | 107 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 99 | 68 |
| `kernel::syscall::dispatch_in_range` | kernel | 95 | 85 |
| `<kernel::sched::run_queue::PerCpuScheduler>::dequeue_highest` | kernel | 32 | 92 |
| `kernel::arch::current::context::switch` | kernel | 92 | 74 |
| `kernel::sched::scheduler_for` | kernel | 73 | 92 |
| `kernel::syscall::pin_checked` | kernel | 84 | 90 |
| `<kernel::mm::address_space::AddressSpace>::activate` | kernel | 4 | 88 |
| `kernel::arch::current::cpu::current_cpu` | kernel | 81 | 62 |
| `kernel::arch::current::idt::isr_nm` | kernel | 80 | |
| `kernel::sched::enqueue_and_wake` | kernel | 58 | 78 |
| `fatfs::handle_read` | fatfs:/ | 66 | 75 |
| `memcpy` | kernel | 71 | 8 |
| `kernel::arch::current::encoding::ticks_to_us` | kernel | | 70 |
| `kernel::syscall::finish_syscall` | kernel | 70 | 20 |
| `kernel::syscall::ipc::sys_ipc_call` | kernel | 60 | 69 |
| `kernel::arch::current::fpu::restore_fp_from` | kernel | | 68 |
| `kernel::arch::current::fpu::save_fp_to` | kernel | | 68 |
| `ipc::ipc_recv_timeout` | fatfs:/ | 43 | 64 |
| 226 functions below 64 each |  | 2377 | 2715 |

#### `fsbench.read size=16 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /programs/fsbench | 10407 | 24744 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 2325 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1816 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1302 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 954 |
| `memset` | /programs/fsbench | 175 | 871 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 769 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 456 | 690 |
| `memset` | fatfs:/ | | 651 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 360 | 616 |
| `kernel::syscall::pin_checked` | kernel | 343 | 585 |
| `<page 0x8000c000>` | other | | 536 |
| `kernel::sched::scheduler_ptr` | kernel | 158 | 521 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 484 |
| `kernel::syscall::dispatch` | kernel | 483 | 168 |
| `kernel::sched::schedule` | kernel | 360 | 480 |
| `kernel::ipc::upcall::deliver` | kernel | | 462 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 436 | 356 |
| `memcpy` | fatfs:/ | 416 | 12 |
| `<page 0x80000000>` | other | | 416 |
| `kernel::syscall::dispatch_in_range` | kernel | 411 | 355 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 204 | 408 |
| `compiler_builtins::mem::memcpy` | kernel | | 396 |
| `kernel::sched::scheduler_for` | kernel | 289 | 360 |
| 463 functions below 344 each |  | 15634 | 17468 |

#### `fsbench.read size=1024 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 4616 | 14212 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 13690 |
| `__copy_user_fault_end` | kernel | 8 | 8204 |
| `__copy_user_fault_start` | kernel | 2052 | 4096 |
| `memcpy` | fatfs:/ | 3712 | 300 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 3696 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 2604 |
| `fatfs::handle_read` | fatfs:/ | 2304 | 1980 |
| `__copy_user` | kernel | 12 | 2060 |
| `memset` | /programs/fsbench | 348 | 1736 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1240 | |
| `std::os::seraph::memmgr_call` | /programs/fsbench | 854 | 1170 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 1072 |
| `<page 0x8000c000>` | other | | 1072 |
| `kernel::sched::schedule` | kernel | 720 | 960 |
| `ipc::ipc_reply` | fatfs:/ | 900 | 924 |
| `memcpy` | /programs/fsbench | 916 | 32 |
| `<page 0x80000000>` | other | | 832 |
| `kernel::sched::scheduler_ptr` | kernel | 184 | 580 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 528 |
| `<std::fs::File as alloc::io::read::Read>::read` | /programs/fsbench | 384 | 496 |
| `fatfs::service_loop` | fatfs:/ | 464 | 454 |
| `kernel::syscall::dispatch` | kernel | 460 | 160 |
| `kernel::ipc::upcall::deliver` | kernel | | 440 |
| `<page 0x80017000>` | other | | 430 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 396 | 272 |
| 246 functions below 384 each |  | 12543 | 14893 |

#### `fsbench.read size=1024 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /programs/fsbench | 10407 | 24744 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 2325 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1816 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1302 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 954 |
| `memset` | /programs/fsbench | 175 | 871 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 769 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 456 | 690 |
| `memset` | fatfs:/ | | 651 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 360 | 616 |
| `kernel::syscall::pin_checked` | kernel | 343 | 585 |
| `<page 0x8000c000>` | other | | 536 |
| `kernel::sched::scheduler_ptr` | kernel | 158 | 521 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 484 |
| `kernel::syscall::dispatch` | kernel | 483 | 168 |
| `kernel::sched::schedule` | kernel | 360 | 480 |
| `kernel::ipc::upcall::deliver` | kernel | | 462 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 436 | 356 |
| `memcpy` | fatfs:/ | 416 | 12 |
| `<page 0x80000000>` | other | | 416 |
| `kernel::syscall::dispatch_in_range` | kernel | 411 | 355 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 204 | 408 |
| `compiler_builtins::mem::memcpy` | kernel | | 396 |
| `kernel::sched::scheduler_for` | kernel | 289 | 360 |
| 463 functions below 344 each |  | 15634 | 17468 |

#### `fsbench.read size=4096 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 18464 | 56848 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 54760 |
| `__copy_user_fault_end` | kernel | 32 | 32816 |
| `__copy_user_fault_start` | kernel | 8208 | 16384 |
| `memcpy` | fatfs:/ | 14848 | 1200 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 14784 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 10416 |
| `fatfs::handle_read` | fatfs:/ | 9216 | 7920 |
| `__copy_user` | kernel | 48 | 8240 |
| `memset` | /programs/fsbench | 1392 | 6944 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 4960 | |
| `std::os::seraph::memmgr_call` | /programs/fsbench | 3416 | 4680 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 4288 |
| `<page 0x8000c000>` | other | | 4288 |
| `kernel::sched::schedule` | kernel | 2880 | 3840 |
| `ipc::ipc_reply` | fatfs:/ | 3600 | 3696 |
| `memcpy` | /programs/fsbench | 3664 | 128 |
| `<page 0x80000000>` | other | | 3328 |
| `kernel::sched::scheduler_ptr` | kernel | 736 | 2320 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 2112 |
| `<std::fs::File as alloc::io::read::Read>::read` | /programs/fsbench | 1536 | 1984 |
| `fatfs::service_loop` | fatfs:/ | 1856 | 1816 |
| `kernel::syscall::dispatch` | kernel | 1840 | 640 |
| `kernel::ipc::upcall::deliver` | kernel | | 1760 |
| `<page 0x80017000>` | other | | 1720 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 1584 | 1088 |
| 246 functions below 1537 each |  | 50037 | 59431 |

#### `fsbench.read size=4096 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /programs/fsbench | 10407 | 24744 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 2325 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 1816 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1302 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 954 |
| `memset` | /programs/fsbench | 175 | 871 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 769 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 456 | 690 |
| `memset` | fatfs:/ | | 651 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 360 | 616 |
| `kernel::syscall::pin_checked` | kernel | 343 | 585 |
| `<page 0x8000c000>` | other | | 536 |
| `kernel::sched::scheduler_ptr` | kernel | 158 | 521 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 484 |
| `kernel::syscall::dispatch` | kernel | 483 | 168 |
| `kernel::sched::schedule` | kernel | 360 | 480 |
| `kernel::ipc::upcall::deliver` | kernel | | 462 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 436 | 356 |
| `memcpy` | fatfs:/ | 416 | 12 |
| `<page 0x80000000>` | other | | 416 |
| `kernel::syscall::dispatch_in_range` | kernel | 411 | 355 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 204 | 408 |
| `compiler_builtins::mem::memcpy` | kernel | | 396 |
| `kernel::sched::scheduler_for` | kernel | 289 | 360 |
| 463 functions below 344 each |  | 15634 | 17468 |

#### `fsbench.read size=16384 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 73856 | 227392 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 219034 |
| `__copy_user_fault_end` | kernel | 128 | 131264 |
| `__copy_user_fault_start` | kernel | 32832 | 65536 |
| `memcpy` | fatfs:/ | 59392 | 4800 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 59136 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 41757 |
| `fatfs::handle_read` | fatfs:/ | 36864 | 31680 |
| `__copy_user` | kernel | 192 | 32960 |
| `memset` | /programs/fsbench | 5568 | 27776 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 19840 | |
| `std::os::seraph::memmgr_call` | /programs/fsbench | 13664 | 18720 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 17192 |
| `<page 0x8000c000>` | other | | 17152 |
| `kernel::sched::schedule` | kernel | 11520 | 15360 |
| `ipc::ipc_reply` | fatfs:/ | 14400 | 14784 |
| `memcpy` | /programs/fsbench | 14656 | 512 |
| `<page 0x80000000>` | other | | 13312 |
| `kernel::sched::scheduler_ptr` | kernel | 2948 | 9288 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 8462 |
| `<std::fs::File as alloc::io::read::Read>::read` | /programs/fsbench | 6144 | 7936 |
| `fatfs::service_loop` | fatfs:/ | 7472 | 7312 |
| `kernel::syscall::dispatch` | kernel | 7360 | 2560 |
| `kernel::ipc::upcall::deliver` | kernel | 6 | 7062 |
| `<page 0x80017000>` | other | | 6880 |
| `<kernel::sync::Spinlock>::lock_raw` | kernel | 6356 | 4371 |
| 283 functions below 6220 each |  | 212520 | 251859 |

#### `fsbench.read size=16384 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /programs/fsbench | 41628 | 98976 |
| `crypto::keccak::keccak_f1600` | kernel | 50512 | 50120 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 9300 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 7264 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 5208 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 3816 |
| `memset` | /programs/fsbench | 700 | 3484 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 3076 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 1824 | 2760 |
| `memset` | fatfs:/ | | 2604 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 1440 | 2464 |
| `kernel::syscall::pin_checked` | kernel | 1372 | 2340 |
| `<page 0x8000c000>` | other | | 2144 |
| `kernel::sched::scheduler_ptr` | kernel | 632 | 2084 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 1936 |
| `kernel::syscall::dispatch` | kernel | 1932 | 672 |
| `kernel::sched::schedule` | kernel | 1440 | 1920 |
| `kernel::ipc::upcall::deliver` | kernel | | 1848 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 1744 | 1424 |
| `memcpy` | fatfs:/ | 1664 | 48 |
| `<page 0x80000000>` | other | | 1664 |
| `kernel::syscall::dispatch_in_range` | kernel | 1644 | 1420 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 816 | 1632 |
| `compiler_builtins::mem::memcpy` | kernel | | 1584 |
| `kernel::sched::scheduler_for` | kernel | 1156 | 1440 |
| 471 functions below 1382 each |  | 63020 | 70437 |

#### `fsbench.read size=65536 path=inline cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 295424 | 909558 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 876155 |
| `__copy_user_fault_end` | kernel | 512 | 525056 |
| `__copy_user_fault_start` | kernel | 131328 | 262144 |
| `memcpy` | fatfs:/ | 237568 | 19200 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 236544 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 167121 |
| `fatfs::handle_read` | fatfs:/ | 147456 | 126720 |
| `__copy_user` | kernel | 768 | 131840 |
| `memset` | /programs/fsbench | 22272 | 111104 |
| `fatfs::fat::chain_next` | fatfs:/ | 99836 | 96000 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 79360 | |
| `fatfs::alloc::read_fat_entry` | fatfs:/ | 36480 | 76800 |
| `std::os::seraph::memmgr_call` | /programs/fsbench | 54656 | 74880 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 68808 |
| `<page 0x8000c000>` | other | | 68608 |
| `kernel::sched::schedule` | kernel | 46080 | 61541 |
| `ipc::ipc_reply` | fatfs:/ | 57587 | 59136 |
| `memcpy` | /programs/fsbench | 58624 | 2048 |
| `<page 0x80000000>` | other | | 53248 |
| `fatfs::fat::read_file_data` | fatfs:/ | 40849 | 44800 |
| `kernel::sched::scheduler_ptr` | kernel | 11784 | 37167 |
| `<fatfs::bpb::FatState>::fat_entry_location` | fatfs:/ | 30720 | 34560 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 33862 |
| `<std::fs::File as alloc::io::read::Read>::read` | /programs/fsbench | 24576 | 31744 |
| `fatfs::service_loop` | fatfs:/ | 29935 | 29296 |
| `kernel::syscall::dispatch` | kernel | 29440 | 10240 |
| `kernel::ipc::upcall::deliver` | kernel | 12 | 28270 |
| `<page 0x80017000>` | other | | 27520 |
| 287 functions below 25955 each |  | 850092 | 987218 |

#### `fsbench.read size=65536 path=frame cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `<std::fs::File as alloc::io::read::Read>::read` | /programs/fsbench | 166512 | 395904 |
| `crypto::keccak::keccak_f1600` | kernel | 202048 | 200480 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 37293 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 29056 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 20832 | |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 15304 |
| `memset` | /programs/fsbench | 2800 | 13936 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 12304 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 7296 | 11040 |
| `memset` | fatfs:/ | | 10416 |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 5760 | 9856 |
| `kernel::syscall::pin_checked` | kernel | 5488 | 9360 |
| `<page 0x8000c000>` | other | | 8576 |
| `kernel::sched::scheduler_ptr` | kernel | 2532 | 8344 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 7758 |
| `kernel::syscall::dispatch` | kernel | 7728 | 2688 |
| `kernel::sched::schedule` | kernel | 5760 | 7680 |
| `kernel::ipc::upcall::deliver` | kernel | 6 | 7414 |
| `<fatfs::session::SessionPages>::va` | fatfs:/ | 6976 | 5696 |
| `memcpy` | fatfs:/ | 6656 | 192 |
| `<page 0x80000000>` | other | | 6656 |
| `kernel::syscall::dispatch_in_range` | kernel | 6576 | 5680 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 3264 | 6528 |
| `compiler_builtins::mem::memcpy` | kernel | | 6336 |
| `kernel::sched::scheduler_for` | kernel | 4624 | 5760 |
| 500 functions below 5545 each |  | 254869 | 284807 |

#### `fsbench.open depth=3 cpus=1`

| Function | Image | x86_64 release | riscv64 release |
|---|---|---:|---:|
| `memset` | fatfs:/ | 5251 | 15155 |
| `crypto::keccak::keccak_f1600` | kernel | 12628 | 12530 |
| `compiler_builtins::mem::memcpy` | fatfs:/ | | 8746 |
| `<fatfs_parse::LfnAccum>::add_lfn_entry` | fatfs:/ | 4528 | 4736 |
| `fatfs::dir::scan_sector_for_name` | fatfs:/ | 3303 | 4025 |
| `compiler_builtins::mem::memcpy` | /programs/fsbench | | 3420 |
| `kernel::arch::current::interrupts::entry::trap_entry` | kernel | | 3162 |
| `<fatfs_parse::LfnAccum>::assemble_utf8` | fatfs:/ | 3065 | 2335 |
| `compiler_builtins::mem::memcpy` | vfsd | | 2359 |
| `<kernel::cap::cspace::CSpace>::slot_mut` | kernel | 1248 | 2092 |
| `kernel::arch::current::syscall::syscall_entry` | kernel | 1736 | |
| `<kernel::cap::cspace::CSpace>::slot` | kernel | 924 | 1516 |
| `memcpy` | fatfs:/ | 1364 | 62 |
| `memset` | /programs/fsbench | 260 | 1299 |
| `kernel::arch::current::interrupts::trap_dispatch` | kernel | | 1298 |
| `<fatfs::cache::PageCache>::lookup_cached` | fatfs:/ | 618 | 1283 |
| `<kernel::cap::cspace::CSpace>::leaf_ptr` | kernel | 543 | 1086 |
| `std::sys::fs::seraph::walk_components` | /programs/fsbench | 958 | 891 |
| `std::sys::alloc::seraph::alloc` | fatfs:/ | 948 | 666 |
| `kernel::syscall::pin_checked` | kernel | 535 | 945 |
| `kernel::arch::nospec::select_ptr::<kernel::cap::cspace::CSpacePage>` | kernel | 724 | 905 |
| `compiler_builtins::mem::memcpy` | kernel | | 891 |
| `memcpy` | /programs/fsbench | 861 | 32 |
| `<page 0x8000c000>` | other | | 804 |
| `<fatfs::cache::PageCache>::pages_held` | fatfs:/ | 781 | 775 |
| `<fatfs_parse::LfnAccum>::matches` | fatfs:/ | 777 | |
| `<kernel::cap::registry::CSpaceRegistry>::entry` | kernel | 596 | 771 |
| `<fatfs::cache::PageCache>::pages_held::{closure#0}` | fatfs:/ | 256 | 768 |
| `<kernel::cap::registry::CSpaceRegistry>::slot` | kernel | 636 | 754 |
| `kernel::sched::schedule` | kernel | 540 | 720 |
| `kernel::sched::scheduler_ptr` | kernel | 220 | 720 |
| `kernel::arch::current::speculation::index_mask` | kernel | 700 | 708 |
| `kernel::arch::current::interrupts::handle_trap` | kernel | | 656 |
| `memset` | vfsd | 88 | 651 |
| `kernel::syscall::dispatch` | kernel | 646 | 226 |
| `<page 0x80000000>` | other | | 624 |
| `kernel::ipc::upcall::deliver` | kernel | | 616 |
| `<kernel::cap::registry::CSpaceRegistry>::lookup` | kernel | 589 | 552 |
| `memcpy` | vfsd | 584 | 22 |
| `kernel::syscall::dispatch_in_range` | kernel | 544 | 470 |
| `kernel::cap::cspace::load_at::<kernel::cap::cspace::CSpacePage>` | kernel | | 543 |
| 442 functions below 534 each |  | 23698 | 27052 |

<!-- path-account: end -->

---

## Summarized By

[core/kernel/README.md](../README.md), [Kernel Hot-Path Instruction Account](hot-path-account.md)
